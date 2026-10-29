"""Description-hash pinning: the rug-pull defence.

`pin` records a SHA-256 of each tool's normalised description.
`verify` re-hashes the current descriptions: a tool whose description
changed after it was approved is exactly the MCP rug-pull shape
(benign at install, weaponised in a later update).
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

from .model import Finding
from .rules import RULES_META

PIN_FORMAT = "sentinel-scan/pins@1"


def normalise(description: str) -> str:
    text = unicodedata.normalize("NFC", description or "")
    return " ".join(text.split()).strip()


def description_hash(description: str) -> str:
    return hashlib.sha256(normalise(description).encode("utf-8")).hexdigest()


def build_pins(tools: list[dict]) -> dict:
    return {
        "format": PIN_FORMAT,
        "tools": {t["name"]: description_hash(t.get("description", ""))
                  for t in tools},
    }


def verify_pins(tools: list[dict], pins: dict,
                origin: str = "") -> list[Finding]:
    findings: list[Finding] = []
    recorded = pins.get("tools") or {}
    current = {t["name"]: t for t in tools}
    sev = RULES_META["rugpull.description-changed"]["severity"]
    for name, old_hash in recorded.items():
        tool = current.get(name)
        if tool is None:
            findings.append(Finding(
                rule_id="rugpull.description-changed", severity="medium",
                unit=name, origin=origin,
                message="Pinned tool is missing from the current tool "
                        "list (removed or renamed after approval)."))
        elif description_hash(tool.get("description", "")) != old_hash:
            findings.append(Finding(
                rule_id="rugpull.description-changed", severity=sev,
                unit=name, origin=origin,
                message="Tool description changed after it was pinned. "
                        "Review the new description before trusting this "
                        "tool again.",
                evidence=normalise(tool.get("description", ""))[:300]))
    return findings


def load_tools_manifest(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "tools" in data:
        return data["tools"]
    if isinstance(data, list):
        return data
    raise ValueError(f"{path}: expected a tool list or {{'tools': [...]}}")
