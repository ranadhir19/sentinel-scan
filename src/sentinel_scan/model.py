"""Core data model: scan units and findings."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Unit:
    """One scannable thing: a tool, a source file, a skill, a config entry."""

    kind: str  # "tool" | "source" | "skill" | "config"
    name: str
    origin: str  # file path or manifest the unit came from
    description: str = ""
    source: str = ""  # source code text (server code, skill body+scripts)
    config: dict = field(default_factory=dict)  # parsed config entry, if any
    frontmatter: dict = field(default_factory=dict)  # skill frontmatter


@dataclass
class Finding:
    rule_id: str
    severity: str
    unit: str  # unit name
    origin: str
    message: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "unit": self.unit,
            "origin": self.origin,
            "message": self.message,
            "evidence": self.evidence,
        }
