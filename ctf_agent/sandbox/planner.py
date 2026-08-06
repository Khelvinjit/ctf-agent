"""Constrain the agent's requested tooling to a small, reproducible sandbox plan."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from ctf_agent.classifier import CAPABILITIES, ThemeDecision

THEME_CAPABILITIES: dict[str, frozenset[str]] = {
    "web": frozenset({"web"}), "crypto": frozenset({"crypto"}),
    "forensics": frozenset({"forensics", "stego"}), "reverse": frozenset({"reverse"}),
    "pwn": frozenset({"pwn", "reverse"}), "stego": frozenset({"stego", "forensics"}),
    "misc": frozenset(),
}
TOOL_SUMMARIES: dict[str, tuple[str, ...]] = {
    "base": ("python3", "file", "strings", "xxd", "unzip", "tar", "jq"),
    "web": ("curl", "python requests"), "crypto": ("pycryptodome", "gmpy2"),
    "forensics": ("exiftool", "binwalk", "foremost", "tshark"),
    "reverse": ("binutils", "gdb", "radare2"), "pwn": ("pwntools", "ROPgadget", "gcc"),
    "stego": ("steghide", "zsteg"),
}


@dataclass(frozen=True, slots=True)
class SandboxPlan:
    theme: str
    capabilities: tuple[str, ...]
    tools: tuple[str, ...]
    rationale: tuple[str, ...]
    network_targets: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "fingerprint": self.fingerprint}

    @property
    def network_enabled(self) -> bool:
        return bool(self.network_targets)


class SandboxPlanner:
    def create(self, decision: ThemeDecision, network_targets: tuple[str, ...] = ()) -> SandboxPlan:
        allowed = self._allowed_capabilities(decision.theme, network_targets)
        selected = tuple(capability for capability in decision.initial_capabilities if capability in allowed)
        if not selected and decision.theme != "misc":
            selected = (decision.theme,)
        rationale = decision.evidence
        if network_targets and "web" not in selected:
            # An explicit challenge URL is sufficient, auditable evidence for
            # the narrowly allow-listed web capability—even for a primarily
            # crypto, reverse, or misc challenge.
            selected = tuple((*selected, "web"))
            rationale = tuple((*rationale, "explicit HTTP(S) challenge target"))
        targets = network_targets if "web" in selected else ()
        return self._plan(decision.theme, selected, rationale, targets)

    def expand(self, plan: SandboxPlan, requested: list[str], reason: str) -> SandboxPlan | None:
        allowed = self._allowed_capabilities(plan.theme, plan.network_targets)
        additions = tuple(capability for capability in requested
                          if capability in CAPABILITIES and capability in allowed and capability not in plan.capabilities)
        if not additions:
            return None
        return self._plan(plan.theme, tuple((*plan.capabilities, *additions)),
                          tuple((*plan.rationale, f"approved expansion: {reason}")), plan.network_targets)

    @staticmethod
    def _allowed_capabilities(theme: str, network_targets: tuple[str, ...]) -> frozenset[str]:
        allowed = THEME_CAPABILITIES[theme]
        return allowed | frozenset({"web"}) if network_targets else allowed

    @staticmethod
    def _plan(theme: str, capabilities: tuple[str, ...], rationale: tuple[str, ...],
              network_targets: tuple[str, ...] = ()) -> SandboxPlan:
        all_capabilities = tuple(dict.fromkeys(("base", *capabilities)))
        tools = tuple(tool for capability in all_capabilities for tool in TOOL_SUMMARIES[capability])
        return SandboxPlan(theme, all_capabilities, tools, rationale, network_targets)
