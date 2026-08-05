from __future__ import annotations

import json
from pathlib import Path

from ctf_agent.types import ChallengeDetail, SolveResult


def write_writeup(directory: Path, challenge: ChallengeDetail, result: SolveResult,
                  decision: dict[str, object] | None = None,
                  sandbox_plan: dict[str, object] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{challenge.id}.md"
    commands = [str(event.get("arguments", {}).get("command")) for event in result.transcript
                if event.get("event") == "tool" and event.get("tool") == "run_command"]
    decision_section = f"\n## Theme decision\n\n```json\n{json.dumps(decision, indent=2)}\n```\n" if decision else ""
    plan_section = f"\n## Sandbox plan\n\n```json\n{json.dumps(sandbox_plan, indent=2)}\n```\n" if sandbox_plan else ""
    target.write_text(f"# {challenge.title}\n\n- Category: {challenge.category}\n- Model: {result.model or 'unknown'}\n- Flag: `{result.flag or 'not found'}`\n" +
                      decision_section + plan_section + "\n## Commands used\n\n" +
                      "\n".join(f"```sh\n{command}\n```" for command in commands) + "\n", encoding="utf-8")
    return target
