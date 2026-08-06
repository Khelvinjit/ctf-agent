"""Compact, durable evidence handoffs for model rotations and resumed solves."""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from ctf_agent.sandbox.planner import SandboxPlan
from ctf_agent.types import ChallengeDetail


HANDOFF_CHARACTER_BUDGET = 6_000
EVENT_OUTPUT_CHARACTER_BUDGET = 900
MODEL_TEXT_CHARACTER_BUDGET = 700


def _excerpt(value: object, limit: int) -> str:
    """Keep the beginning and end of evidence without silently losing either."""
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return f"{text[:head]}\n… [{len(text) - limit} characters omitted] …\n{text[-tail:]}"


def load_transcript(path: Path) -> list[dict[str, object]]:
    """Read a JSONL transcript while tolerating a partially written final line."""
    if not path.is_file():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def format_handoff(
    challenge: ChallengeDetail,
    plan: SandboxPlan,
    events: Iterable[dict[str, object]],
    *,
    reason: str | None = None,
) -> str:
    """Summarise evidence an incoming model needs to continue without repetition."""
    recorded = list(events)
    lines = [
        "# CTF solver handoff",
        f"Challenge: {challenge.title} ({challenge.category})",
        f"Sandbox capabilities: {', '.join(plan.capabilities)}",
        f"Approved network targets: {', '.join(plan.network_targets) or 'none'}",
    ]
    if reason:
        lines.append(f"Current stop reason: {reason}")

    model_events = [event for event in recorded if event.get("event") == "model" and event.get("text")]
    if model_events:
        lines.extend(["", "## Latest model assessments"])
        for event in model_events[-2:]:
            route = f"{event.get('provider', 'unknown')}:{event.get('model', 'unknown')}"
            lines.append(f"- {route}: {_excerpt(event.get('text'), MODEL_TEXT_CHARACTER_BUDGET)}")

    tool_events = [event for event in recorded if event.get("event") == "tool"]
    if tool_events:
        lines.extend(["", "## Completed commands and evidence"])
        for event in tool_events[-5:]:
            arguments = event.get("arguments")
            command = event.get("command")
            if not command and isinstance(arguments, dict):
                command = arguments.get("command", "")
            command = _excerpt(command, 300)
            exit_code = event.get("exit_code", "unknown")
            output = _excerpt(event.get("output"), EVENT_OUTPUT_CHARACTER_BUDGET)
            lines.append(f"- `$ {command}` (exit {exit_code})\n  {output or 'No output recorded.'}")

    rotations = [event for event in recorded if event.get("event") == "model_rotation"]
    if rotations:
        latest = rotations[-1]
        lines.extend(["", "## Route change", (
            f"Previous route: {latest.get('from_provider', 'unknown')}:{latest.get('from_model', 'unknown')}; "
            f"incoming route: {latest.get('to_provider', 'unknown')}:{latest.get('to_model', 'unknown')}; "
            f"reason: {latest.get('reason', 'unknown')}."
        )])

    lines.extend(["", "## Continue from here", (
        "Treat the completed commands as evidence. Do not rerun them unless a new hypothesis requires a narrower or "
        "changed query. Choose one new, testable next step and verify any flag from tool output or derived evidence."
    )])
    return _excerpt("\n".join(lines), HANDOFF_CHARACTER_BUDGET)


def write_handoff(
    path: Path,
    challenge: ChallengeDetail,
    plan: SandboxPlan,
    events: Iterable[dict[str, object]],
    *,
    reason: str | None = None,
) -> None:
    """Atomically refresh the human- and model-readable continuation brief."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(format_handoff(challenge, plan, events, reason=reason) + "\n", encoding="utf-8")
    temporary.replace(path)
