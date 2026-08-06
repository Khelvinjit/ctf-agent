"""Cheap category + keyword retrieval over the local skill FTS index."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

_ALIASES = {
    "crypto": "crypto",
    "cryptography": "crypto",
    "cryptographic": "crypto",
    "pwn": "pwn",
    "binary exploitation": "pwn",
    "binary": "pwn",
    "rev": "reverse",
    "reverse engineering": "reverse",
    "reversing": "reverse",
    "web": "web",
    "web exploitation": "web",
    "forensics": "forensics",
    "misc": "misc",
    "osint": "osint",
}


class SkillRouter:
    def __init__(self, index_path: Path) -> None:
        self.index_path = index_path

    @staticmethod
    def normalize_category(category: str) -> str:
        lowered = category.lower().strip()
        return _ALIASES.get(
            lowered,
            next((value for key, value in _ALIASES.items() if key in lowered), lowered),
        )

    @staticmethod
    def _terms(text: str) -> list[str]:
        words = re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text.lower())
        stop = {
            "the",
            "and",
            "with",
            "this",
            "that",
            "from",
            "your",
            "have",
            "for",
            "into",
            "challenge",
        }
        return [word for word in words if word not in stop][:20]

    def retrieve(
        self, category: str, title: str, description: str, limit: int = 20
    ) -> list[dict[str, str]]:
        if not self.index_path.exists():
            return []
        normalized = self.normalize_category(category)
        connection = sqlite3.connect(self.index_path)
        terms = self._terms(f"{title} {description}")
        query = " OR ".join(f'"{term}"' for term in terms) or "*"
        try:
            rows = connection.execute(
                """
              SELECT category,name,snippet FROM techniques WHERE techniques MATCH ? AND category = ?
              ORDER BY bm25(techniques) LIMIT ?
            """,
                (query, normalized, limit),
            ).fetchall()
            if not rows:
                rows = connection.execute(
                    "SELECT category,name,snippet FROM techniques WHERE category = ? LIMIT ?",
                    (normalized, limit),
                ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        finally:
            connection.close()
        return [{"category": r[0], "name": r[1], "snippet": r[2]} for r in rows]

    def format_retrieval(self, *args: str, limit: int = 20) -> str:
        results = self.retrieve(*args, limit=limit)
        if not results:
            return "No local techniques were retrieved. Reason from the challenge evidence."
        return "\n".join(
            f"- {item['name']}: {item['snippet']}".strip() for item in results
        )
