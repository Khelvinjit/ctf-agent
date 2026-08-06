#!/usr/bin/env python3
"""Classify and solve the local material in challenge_materials/."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path

# Support the documented `python scripts/solve_manual.py` invocation before installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctf_agent.classifier import (
    MaterialItem,
    ThemeClassifier,
    challenge_urls,
    inventory_materials,
)
from ctf_agent.config import get_settings
from ctf_agent.handoff import load_transcript, write_handoff
from ctf_agent.models.client import ChatClient
from ctf_agent.sandbox.manager import SandboxManager
from ctf_agent.sandbox.planner import SandboxPlanner
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.loop import SolverLoop
from ctf_agent.types import ChallengeDetail, SolveResult
from ctf_agent.writeup import write_writeup

ROOT_DIR = Path(__file__).resolve().parents[1]
MATERIALS_DIR = ROOT_DIR / "challenge_materials"
DESCRIPTION_FILE = MATERIALS_DIR / "CHALLENGE_DESCRIPTION.md"


def metadata(description: str) -> tuple[str, str]:
    """Derive display-only metadata from arbitrary pasted challenge text."""
    first_line = next(
        (line.strip() for line in description.splitlines() if line.strip()), ""
    )
    title = first_line.lstrip("# ").strip()[:120] or "pasted challenge"
    # Theme classification receives the entire text and must not depend on a label.
    return title, "unknown"


def material_record(item: MaterialItem) -> dict[str, object]:
    """Convert inventory entries into the JSON shape used by logs and fingerprints."""
    return {
        "path": item.path,
        "size_bytes": item.size_bytes,
        "sha256": item.sha256,
        "file_type": item.file_type,
        "archive_members": item.archive_members,
    }


def write_json(path: Path, data: object) -> None:
    """Write an inspectable JSON artefact with a trailing newline."""
    path.write_text(json.dumps(data, indent=2, default=list) + "\n", encoding="utf-8")


def session_fingerprint(description: str, inventory: Sequence[MaterialItem]) -> str:
    """Bind persisted evidence to the exact challenge text and material inventory."""
    payload = json.dumps(
        {
            "description": description,
            "materials": [material_record(item) for item in inventory],
        },
        sort_keys=True,
        default=list,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def resumable_transcript(
    logs: Path, fingerprint: str
) -> tuple[list[dict[str, object]], bool]:
    """Return prior evidence only when it belongs to the current challenge."""
    session_path = logs / "session.json"
    transcript_path = logs / "transcript.jsonl"
    try:
        saved = json.loads(session_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        saved = {}
    if saved.get("fingerprint") == fingerprint:
        events = load_transcript(transcript_path)
        if events:
            return events, True
    session_path.write_text(
        json.dumps({"fingerprint": fingerprint}, indent=2) + "\n", encoding="utf-8"
    )
    return [], False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flag-format")
    args = parser.parse_args()
    settings = get_settings()
    if args.flag_format:
        settings.flag_format_regex = args.flag_format
    if not DESCRIPTION_FILE.is_file():
        parser.error(f"required description file not found: {DESCRIPTION_FILE}")
    print("Inventorying challenge materials…", flush=True)
    try:
        inventory = inventory_materials(MATERIALS_DIR)
    except ValueError as exc:
        parser.error(str(exc))
    description = DESCRIPTION_FILE.read_text(encoding="utf-8")
    title, declared_category = metadata(description)
    logs = settings.logs_dir / "manual"
    logs.mkdir(parents=True, exist_ok=True)
    client = ChatClient(settings)
    decision = ThemeClassifier(
        client,
        settings.model_provider,
        settings.model_name,
        progress=lambda message: print(message, flush=True),
    ).classify(description, declared_category, inventory)
    write_json(
        logs / "theme-decision.json",
        {
            "declared_category": declared_category,
            "inventory": [material_record(item) for item in inventory],
            "decision": decision.to_dict(),
        },
    )
    planner = SandboxPlanner()
    targets = challenge_urls(description)
    plan = planner.create(decision, targets)
    files = [
        Path(item.path) for item in inventory if item.path != DESCRIPTION_FILE.name
    ]
    challenge = ChallengeDetail(
        id="manual",
        title=title,
        category=decision.theme,
        description=description,
        files=files,
    )
    transcript_path = logs / "transcript.jsonl"
    handoff_path = logs / "handoff.md"
    prior_transcript, resumed = resumable_transcript(
        logs, session_fingerprint(description, inventory)
    )
    if resumed:
        print(f"Resuming from {len(prior_transcript)} recorded events.", flush=True)
    else:
        write_handoff(handoff_path, challenge, plan, [], reason="new challenge session")
    manager = SandboxManager(settings)
    transcript: list[dict[str, object]] = []
    result = None
    for expansion in range(settings.max_sandbox_expansions + 1):
        active_plan = plan
        print(f"Sandbox plan: {', '.join(plan.capabilities)}", flush=True)
        write_json(logs / "sandbox-plan.json", active_plan.to_dict())
        try:
            executor = manager.start(MATERIALS_DIR, active_plan)
        except RuntimeError as exc:
            print(f"\nCould not start sandbox: {exc}", file=sys.stderr)
            return 2
        try:
            solver = SolverLoop(settings, client, SkillRouter(settings.skill_index))
            # Keep evidence across expansions and only resume when the content
            # fingerprint proves it belongs to the current challenge.
            transcript_mode = "a" if resumed or expansion > 0 else "w"
            with transcript_path.open(transcript_mode, encoding="utf-8") as stream:

                def log(event: dict[str, object]) -> None:
                    stream.write(json.dumps(event, default=str) + "\n")
                    stream.flush()
                    write_handoff(
                        handoff_path,
                        challenge,
                        active_plan,
                        load_transcript(transcript_path),
                    )
                    if event["event"] == "model":
                        print(
                            "Agent response received; processing requested tools…",
                            flush=True,
                        )
                    elif event["event"] == "model_rotation":
                        print(
                            f"Iteration budget reached; switching to {event['to_provider']}:{event['to_model']}…",
                            flush=True,
                        )
                    elif event["event"] == "tool":
                        if event["tool"] == "run_command":
                            command = str(event.get("command", ""))
                            print("Sandbox command:", flush=True)
                            print(
                                "\n".join(f"$ {line}" for line in command.splitlines())
                                or "$",
                                flush=True,
                            )
                            print("Sandbox command completed.", flush=True)
                        else:
                            print(f"Agent tool completed: {event['tool']}", flush=True)

                preflight_events: list[dict[str, object]] = []
                preflight_failure: SolveResult | None = None
                for target in active_plan.network_targets:
                    print(f"Preflighting authorised target: {target}", flush=True)
                    preflight = executor.preflight_target(target)
                    event = {
                        "event": "target_preflight",
                        "target": preflight.target,
                        "command": preflight.command,
                        "exit_code": preflight.result.exit_code,
                        "timed_out": preflight.result.timed_out,
                        "stdout": preflight.result.stdout,
                        "stderr": preflight.result.stderr,
                        "reachable": preflight.reachable,
                        "reason": preflight.reason,
                    }
                    preflight_events.append(event)
                    log(event)
                    if not preflight.reachable:
                        reason = (
                            preflight.reason
                            or f"authorised challenge target is unavailable: {target}"
                        )
                        print(
                            f"Target preflight failed; the solver will not start: {reason}",
                            file=sys.stderr,
                        )
                        preflight_failure = SolveResult(
                            None, None, reason, transcript=preflight_events
                        )
                        break
                if preflight_failure:
                    result = preflight_failure
                else:
                    print("Solving challenge…", flush=True)
                    result = solver.solve(
                        challenge,
                        executor,
                        active_plan,
                        prior_transcript + transcript,
                        log=log,
                    )
        finally:
            manager.stop(executor)
        transcript.extend(result.transcript)
        write_handoff(
            handoff_path,
            challenge,
            plan,
            load_transcript(transcript_path),
            reason=result.reason,
        )
        if (
            result.flag
            or not result.requested_capabilities
            or expansion >= settings.max_sandbox_expansions
        ):
            break
        expanded = planner.expand(
            plan, result.requested_capabilities, result.reason or "no reason supplied"
        )
        if expanded is None:
            requested = ", ".join(result.requested_capabilities)
            result.reason = (
                f"sandbox expansion denied ({requested}). The requested capability is not "
                "compatible with the classified challenge theme."
            )
            break
        plan = expanded
    assert result is not None
    if result.flag:
        print(f"\nFLAG: {result.flag}")
        try:
            import pyperclip

            pyperclip.copy(result.flag)
            print("Copied to clipboard.")
        except ImportError:
            pass
        write_writeup(
            settings.logs_dir / "writeups",
            challenge,
            result,
            decision.to_dict(),
            plan.to_dict(),
        )
        return 0
    print(
        f"\nNo flag found: {result.reason}. Transcript: {transcript_path}. Handoff: {handoff_path}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
