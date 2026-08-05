#!/usr/bin/env python3
"""Classify and solve the local material in challenge_materials/."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Support the documented `python scripts/solve_manual.py` invocation before installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctf_agent.classifier import ThemeClassifier, challenge_urls, inventory_materials
from ctf_agent.config import get_settings
from ctf_agent.models.client import ChatClient
from ctf_agent.sandbox.manager import SandboxManager
from ctf_agent.sandbox.planner import SandboxPlanner
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.loop import SolverLoop
from ctf_agent.types import ChallengeDetail
from ctf_agent.writeup import write_writeup


ROOT_DIR = Path(__file__).resolve().parents[1]
MATERIALS_DIR = ROOT_DIR / "challenge_materials"
DESCRIPTION_FILE = MATERIALS_DIR / "CHALLENGE_DESCRIPTION.md"


def metadata(description: str) -> tuple[str, str]:
    """Derive display-only metadata from arbitrary pasted challenge text."""
    first_line = next((line.strip() for line in description.splitlines() if line.strip()), "")
    title = first_line.lstrip("# ").strip()[:120] or "pasted challenge"
    # Theme classification receives the entire text and must not depend on a label.
    return title, "unknown"


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
    decision = ThemeClassifier(client, settings.model_provider, settings.model_name,
                               progress=lambda message: print(message, flush=True)).classify(
        description, declared_category, inventory)
    (logs / "theme-decision.json").write_text(
        json.dumps({"declared_category": declared_category, "inventory": [item.__dict__ if hasattr(item, "__dict__") else {
            "path": item.path, "size_bytes": item.size_bytes, "sha256": item.sha256,
            "file_type": item.file_type, "archive_members": item.archive_members,
        } for item in inventory], "decision": decision.to_dict()}, indent=2, default=list) + "\n", encoding="utf-8")
    planner = SandboxPlanner()
    targets = challenge_urls(description)
    plan = planner.create(decision, targets)
    files = [Path(item.path) for item in inventory if item.path != DESCRIPTION_FILE.name]
    challenge = ChallengeDetail(id="manual", title=title, category=decision.theme, description=description, files=files)
    manager = SandboxManager(settings)
    transcript: list[dict[str, object]] = []
    result = None
    for expansion in range(settings.max_sandbox_expansions + 1):
        print(f"Sandbox plan: {', '.join(plan.capabilities)}", flush=True)
        (logs / "sandbox-plan.json").write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
        try:
            executor = manager.start(MATERIALS_DIR, plan)
        except RuntimeError as exc:
            print(f"\nCould not start sandbox: {exc}", file=sys.stderr)
            return 2
        try:
            solver = SolverLoop(settings, client, SkillRouter(settings.skill_index))
            with (logs / "transcript.jsonl").open("a", encoding="utf-8") as stream:
                def log(event: dict[str, object]) -> None:
                    stream.write(json.dumps(event, default=str) + "\n")
                    stream.flush()
                    if event["event"] == "model":
                        print("Agent response received; processing requested tools…", flush=True)
                    elif event["event"] == "tool":
                        if event["tool"] == "run_command":
                            command = str(event.get("command", ""))
                            print("Sandbox command:", flush=True)
                            print("\n".join(f"$ {line}" for line in command.splitlines()) or "$", flush=True)
                            print("Sandbox command completed.", flush=True)
                        else:
                            print(f"Agent tool completed: {event['tool']}", flush=True)
                print("Solving challenge…", flush=True)
                result = solver.solve(challenge, executor, plan, transcript, log=log)
        finally:
            manager.stop(executor)
        transcript.extend(result.transcript)
        if result.flag or not result.requested_capabilities or expansion >= settings.max_sandbox_expansions:
            break
        expanded = planner.expand(plan, result.requested_capabilities, result.reason or "no reason supplied")
        if expanded is None:
            requested = ", ".join(result.requested_capabilities)
            result.reason = (f"sandbox expansion denied ({requested}). The requested capability is not "
                             "compatible with the classified challenge theme.")
            break
        plan = expanded
    assert result is not None
    if result.flag:
        print(f"\nFLAG: {result.flag}")
        try:
            import pyperclip
            pyperclip.copy(result.flag); print("Copied to clipboard.")
        except ImportError:
            pass
        write_writeup(settings.logs_dir / "writeups", challenge, result, decision.to_dict(), plan.to_dict())
        return 0
    print(f"\nNo flag found: {result.reason}. Transcript: {logs / 'transcript.jsonl'}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
