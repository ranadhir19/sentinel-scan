"""Report renderers: terminal text, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .model import Finding, SEVERITY_RANK
from .rules import RULES_META

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def render_text(findings: list[Finding], n_units: int) -> str:
    lines = [f"sentinel-scan {__version__} — scanned {n_units} unit(s), "
             f"{len(findings)} finding(s)"]
    if not findings:
        lines.append("OK: no findings.")
        return "\n".join(lines)
    ordered = sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity])
    for f in ordered:
        lines.append(f"\n[{f.severity.upper()}] {f.rule_id} — "
                     f"{RULES_META.get(f.rule_id, {}).get('title', '')}")
        lines.append(f"  unit: {f.unit}  ({f.origin})")
        lines.append(f"  {f.message}")
        if f.evidence:
            lines.append(f"  evidence: {f.evidence}")
    return "\n".join(lines)


def render_json(findings: list[Finding], n_units: int) -> str:
    return json.dumps({
        "tool": "sentinel-scan",
        "version": __version__,
        "units_scanned": n_units,
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def render_sarif(findings: list[Finding], artifact_root: str = ".") -> str:
    sarif_rules = []
    for rule_id, meta in RULES_META.items():
        sarif_rules.append({
            "id": rule_id,
            "name": rule_id.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": meta["title"]},
            "fullDescription": {"text": meta["title"] + " — mapped to "
                                       + meta["owasp"]},
            "defaultConfiguration": {"level": _SARIF_LEVEL[meta["severity"]]},
            "properties": {"severity": meta["severity"],
                           "owasp": meta["owasp"]},
        })
    results = []
    for f in findings:
        uri = f.origin
        try:
            uri = str(Path(f.origin).relative_to(Path(artifact_root).resolve())) \
                if Path(f.origin).is_absolute() else f.origin
        except Exception:
            uri = f.origin
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.unit}: {f.message}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri.replace("\\", "/")},
                }
            }],
            "partialFingerprints": {
                "sentinelScan/v1": f"{f.rule_id}:{f.unit}:{f.origin}"
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sentinel-scan",
                    "version": __version__,
                    "informationUri":
                        "https://github.com/ranadhir19/sentinel-scan",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
