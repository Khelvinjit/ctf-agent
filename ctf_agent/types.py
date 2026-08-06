"""Shared domain objects for the local-materials solve flow."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ChallengeDetail:
    id: str
    title: str
    category: str
    description: str = ""
    files: list[Path | str] = field(default_factory=list)


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, object]
    id: str | None = None
    # Gemini thinking models require this opaque value to be replayed with the
    # original function call on the next turn.
    thought_signature: str | None = None


@dataclass(slots=True)
class ModelResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: object | None = None
    provider: str | None = None
    model: str | None = None
    rate_limited_routes: tuple[str, ...] = ()
    unavailable_routes: tuple[str, ...] = ()


@dataclass(slots=True)
class SolveResult:
    flag: str | None
    model: str | None = None
    reason: str | None = None
    requested_capabilities: list[str] = field(default_factory=list)
    transcript: list[dict[str, object]] = field(default_factory=list)
