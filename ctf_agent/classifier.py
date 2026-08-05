"""Safe challenge-material inventory and AI-assisted theme classification."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import subprocess
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlparse

from ctf_agent.models.client import ModelError
from ctf_agent.types import ModelResponse

THEMES = frozenset({"web", "crypto", "forensics", "reverse", "pwn", "stego", "misc"})
CAPABILITIES = frozenset({"web", "crypto", "forensics", "reverse", "pwn", "stego"})


@dataclass(frozen=True, slots=True)
class MaterialItem:
    path: str
    size_bytes: int
    sha256: str
    file_type: str
    archive_members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ThemeDecision:
    theme: str
    confidence: float
    evidence: tuple[str, ...]
    initial_capabilities: tuple[str, ...]
    unknowns: tuple[str, ...] = ()
    source: str = "agent"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ChatModel(Protocol):
    def chat(self, messages: list[dict[str, object]], *, provider: str, model: str,
             tools: list[dict[str, object]] | None = None) -> ModelResponse: ...


def assert_safe_materials(root: Path) -> None:
    """Reject symlinks so a bind mount cannot expose files outside the input root."""
    if root.is_symlink():
        raise ValueError(f"challenge materials directory must not be a symlink: {root}")
    if not root.is_dir():
        raise ValueError(f"challenge materials directory does not exist: {root}")
    for item in root.rglob("*"):
        if item.is_symlink():
            raise ValueError(f"symlinks are not allowed in challenge materials: {item.relative_to(root)}")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_members(path: Path, limit: int = 100) -> tuple[str, ...]:
    """List archive names only; never extract or execute an attachment on the host."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                return tuple(member.filename for member in archive.infolist()[:limit])
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                return tuple(member.name for member in archive.getmembers()[:limit])
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        return ("<archive listing unavailable>",)
    return ()


def inventory_materials(root: Path) -> list[MaterialItem]:
    assert_safe_materials(root)
    result: list[MaterialItem] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        # `file` only identifies bytes; it does not execute the attachment.
        try:
            identified = subprocess.run(["file", "--brief", "--no-dereference", str(path)], text=True,
                                        capture_output=True, timeout=5, check=False)
            file_type = identified.stdout.strip() if identified.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            file_type = ""
        file_type = file_type or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        result.append(MaterialItem(relative, path.stat().st_size, _hash_file(path), file_type,
                                   _archive_members(path)))
    return result


def challenge_urls(description: str) -> tuple[str, ...]:
    """Return explicitly supplied HTTP(S) targets, preserving their first occurrence."""
    urls = re.findall(r"https?://[^\s<>\]\[\"')]+", description, flags=re.IGNORECASE)
    return tuple(dict.fromkeys(url.rstrip(".,;:") for url in urls if urlparse(url).netloc))


def _json_object(text: str) -> dict[str, object]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("classification response did not contain JSON")
    value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("classification response was not an object")
    return value


def _fallback_theme(description: str, declared_category: str, items: list[MaterialItem]) -> ThemeDecision:
    haystack = " ".join([description, declared_category, *(item.path for item in items)]).lower()
    keywords = {
        "crypto": ("crypto", "cipher", "vigen", "rsa", "aes", "base64"),
        "forensics": ("forensic", "pcap", "disk", "memory", "metadata"),
        "reverse": ("reverse", "decompile", "binary", ".elf", ".exe", ".wasm"),
        "pwn": ("pwn", "buffer overflow", "rop", "format string"),
        "stego": ("stego", "stegan", "hidden image", "lsb"),
        "web": ("web", "html", "javascript", "http", "cookie"),
    }
    theme = next((name for name, words in keywords.items() if any(word in haystack for word in words)), "misc")
    capabilities = () if theme == "misc" else (theme,)
    return ThemeDecision(theme, 0.2, ("fallback keyword classification",), capabilities,
                         ("AI classification was unavailable",), "fallback")


class ThemeClassifier:
    def __init__(self, model: ChatModel, provider: str, model_name: str,
                 progress: Callable[[str], None] | None = None) -> None:
        self.model, self.provider, self.model_name = model, provider, model_name
        self.progress = progress

    def classify(self, description: str, declared_category: str, items: list[MaterialItem]) -> ThemeDecision:
        inventory = [asdict(item) for item in items]
        if self.progress:
            self.progress("Asking the agent to classify the challenge theme…")
        classification_prompt = f"""Classify this authorised, local CTF challenge before any attachment is executed.
Use the description and non-executing inventory below. Return JSON only with keys:
theme (one of {sorted(THEMES)}), confidence (0 to 1), evidence (short string list), and unknowns (string list).
Do not choose tools yet. A claimed category is evidence only.

Claimed category: {declared_category}
Description:
{description}
Inventory:
{json.dumps(inventory, ensure_ascii=False)}"""
        try:
            response = self.model.chat([{"role": "system", "content": "You are a cautious CTF triage agent."},
                                         {"role": "user", "content": classification_prompt}],
                                       provider=self.provider, model=self.model_name)
            data = _json_object(response.text)
            theme = str(data.get("theme", "")).lower()
            if theme not in THEMES:
                raise ValueError("classification contained unsupported values")
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
            evidence = tuple(str(value) for value in data.get("evidence", [])[:8])
            unknowns = tuple(str(value) for value in data.get("unknowns", [])[:8])
            if not evidence:
                raise ValueError("classification omitted evidence")
            planning_prompt = f"""You classified an authorised local CTF challenge as {theme}.
Now choose the smallest sandbox capability set for its first investigation. Return JSON only with
the key initial_capabilities: a list containing zero to two values from {sorted(CAPABILITIES)}.
The base utilities are always present. Do not choose unrelated tools.

Classification evidence: {json.dumps(evidence)}
Description: {description}
Inventory: {json.dumps(inventory, ensure_ascii=False)}"""
            if self.progress:
                self.progress("Asking the agent to select the minimal sandbox capabilities…")
            planning_response = self.model.chat([{"role": "system", "content": "You are a cautious CTF sandbox planner."},
                                                  {"role": "user", "content": planning_prompt}],
                                                provider=self.provider, model=self.model_name)
            planning = _json_object(planning_response.text)
            capabilities = tuple(dict.fromkeys(str(value).lower() for value in planning.get("initial_capabilities", [])
                                                if str(value).lower() in CAPABILITIES))
            if len(capabilities) > 2:
                raise ValueError("sandbox plan requested too many capabilities")
            return ThemeDecision(theme, confidence, evidence, capabilities, unknowns)
        except (ModelError, ValueError, TypeError, json.JSONDecodeError):
            return _fallback_theme(description, declared_category, items)
