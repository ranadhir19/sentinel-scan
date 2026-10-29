"""Input adapters: turn files/directories into Units and run the rules."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import rules
from .model import Finding, Unit

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash",
                   ".ps1", ".rb", ".pl"}


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Minimal YAML-subset frontmatter parser (name/description/allowed-tools)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    block, body = text[3:end], text[end + 4:]
    fm: dict = {}
    current_key = None
    for line in block.splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            current_key = m.group(1)
            fm[current_key] = m.group(2).strip()
        elif line.strip().startswith("- ") and current_key:
            prev = fm.get(current_key)
            items = prev if isinstance(prev, list) else (
                [prev] if prev else [])
            items.append(line.strip()[2:].strip())
            fm[current_key] = items
    return fm, body


def units_from_tools_manifest(path: Path) -> list[Unit]:
    from .pin import load_tools_manifest
    units = []
    for t in load_tools_manifest(path):
        units.append(Unit(kind="tool", name=str(t.get("name", "?")),
                          origin=str(path),
                          description=str(t.get("description", "")),
                          source=str(t.get("source", ""))))
    return units


def units_from_mcp_config(path: Path) -> list[Unit]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    units = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        units.append(Unit(kind="config", name=name, origin=str(path),
                          config=entry,
                          description=str(entry.get("description", ""))))
    return units


def unit_from_source_file(path: Path) -> Unit:
    return Unit(kind="source", name=path.name, origin=str(path),
                source=path.read_text(encoding="utf-8", errors="replace"))


def units_from_skill(path: Path) -> list[Unit]:
    skill_md = path / "SKILL.md" if path.is_dir() else path
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    fm, body = parse_frontmatter(text)
    scripts = ""
    if path.is_dir():
        for sub in sorted(path.rglob("*")):
            if sub.is_file() and sub.suffix in SOURCE_SUFFIXES:
                scripts += "\n" + sub.read_text(
                    encoding="utf-8", errors="replace")
    return [Unit(kind="skill", name=str(fm.get("name") or skill_md.parent.name),
                 origin=str(skill_md),
                 description=str(fm.get("description", "")),
                 source=(body + scripts), frontmatter=fm)]


def looks_like_mcp_config(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(data, dict) and (
        "mcpServers" in data or "servers" in data)


def looks_like_tools_manifest(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if isinstance(data, list):
        return all(isinstance(t, dict) and "name" in t for t in data)
    return isinstance(data, dict) and isinstance(data.get("tools"), list)


def collect_units(path: Path) -> list[Unit]:
    """Auto-detect what a path is and produce its Units."""
    if path.is_dir():
        if (path / "SKILL.md").exists():
            return units_from_skill(path)
        units: list[Unit] = []
        for sub in sorted(path.rglob("*")):
            if not sub.is_file():
                continue
            if sub.name == "SKILL.md":
                units += units_from_skill(sub.parent)
            elif sub.suffix in SOURCE_SUFFIXES:
                units.append(unit_from_source_file(sub))
            elif sub.suffix == ".json" and looks_like_mcp_config(sub):
                units += units_from_mcp_config(sub)
            elif sub.suffix == ".json" and looks_like_tools_manifest(sub):
                units += units_from_tools_manifest(sub)
        return units
    if path.name == "SKILL.md":
        return units_from_skill(path)
    if path.suffix in SOURCE_SUFFIXES:
        return [unit_from_source_file(path)]
    if path.suffix == ".json":
        if looks_like_mcp_config(path):
            return units_from_mcp_config(path)
        if looks_like_tools_manifest(path):
            return units_from_tools_manifest(path)
    if path.suffix == ".md":
        return units_from_skill(path)
    return []


def run_rules(units: list[Unit],
              rule_fns=None) -> list[Finding]:
    findings: list[Finding] = []
    for unit in units:
        for fn in (rule_fns or rules.ALL_RULES):
            findings.extend(fn(unit))
    return findings


def scan_path(path: str | Path) -> tuple[list[Unit], list[Finding]]:
    units = collect_units(Path(path))
    return units, run_rules(units)
