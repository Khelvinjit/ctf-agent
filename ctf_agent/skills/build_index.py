"""Build a compact, offline FTS technique index from a local ctf-skills checkout."""

from __future__ import annotations

import argparse
import re
import sqlite3
from pathlib import Path


def _entries(markdown: str) -> list[tuple[str, str]]:
    """Extract useful headings/bullets without copying long source material into the DB."""
    found: list[tuple[str, str]] = []
    lines = [line.strip() for line in markdown.splitlines()]
    for i, line in enumerate(lines):
        match = re.match(r"^(?:#{1,6}\s+|[-*]\s+|\d+[.)]\s+)(.+)$", line)
        if not match:
            continue
        name = re.sub(r"[`*_]", "", match.group(1)).strip()
        if len(name) < 4 or len(name) > 180:
            continue
        context = next(
            (
                candidate
                for candidate in lines[i + 1 : i + 4]
                if candidate and not candidate.startswith(("#", "-", "*"))
            ),
            "",
        )
        found.append((name, context[:400]))
    return found


def build_index(source: Path, destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(destination)
    connection.executescript("""
      DROP TABLE IF EXISTS techniques;
      CREATE VIRTUAL TABLE techniques USING fts5(category, name, snippet);
    """)
    total = 0
    for skill_file in source.rglob("SKILL.md"):
        category = skill_file.parent.name.removeprefix("ctf-").replace("_", " ")
        for name, snippet in _entries(
            skill_file.read_text(encoding="utf-8", errors="ignore")
        ):
            connection.execute(
                "INSERT INTO techniques(category,name,snippet) VALUES (?,?,?)",
                (category, name, snippet),
            )
            total += 1
    connection.commit()
    connection.close()
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source", type=Path, help="local checkout of ljagiello/ctf-skills"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("ctf_agent/skills/index.sqlite")
    )
    args = parser.parse_args()
    print(
        f"Indexed {build_index(args.source, args.output)} techniques in {args.output}"
    )
