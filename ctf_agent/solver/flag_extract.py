from __future__ import annotations

import re


def extract_flag(text: str, pattern: str) -> str | None:
    try:
        match = re.search(pattern, text)
    except re.error as exc:
        raise ValueError(f"invalid FLAG_FORMAT_REGEX: {exc}") from exc
    return match.group(0) if match else None

