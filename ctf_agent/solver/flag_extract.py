from __future__ import annotations

import re


def _is_placeholder(candidate: str) -> bool:
    """Reject templates such as ``picoCTF{...}`` embedded in challenge source."""
    try:
        body = candidate[candidate.index("{") + 1:candidate.rindex("}")].strip()
    except ValueError:
        return False
    normalized = body.casefold().replace("-", "_").replace(" ", "_")
    template_values = {"...", "…", "flag", "flag_here", "your_flag", "your_flag_here", "insert_flag"}
    return not any(character.isalnum() for character in body) or normalized in template_values


def extract_flag(text: str, pattern: str) -> str | None:
    try:
        matches = re.finditer(pattern, text)
    except re.error as exc:
        raise ValueError(f"invalid FLAG_FORMAT_REGEX: {exc}") from exc
    return next((match.group(0) for match in matches if not _is_placeholder(match.group(0))), None)
