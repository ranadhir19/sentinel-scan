#!/usr/bin/env python3
"""Measure per-rule precision on the labelled fixture corpus.

Runs the real scanner over fixtures/corpus/*, compares fired rules
against each case's labels, and writes data/precision.json plus the
README precision table (between the PRECISION markers). With --check,
exits 1 if the committed artifacts differ from a fresh measurement.

Run: python3 scripts/measure.py [--check]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel_scan import pin as pin_mod  # noqa: E402
from sentinel_scan.model import Unit  # noqa: E402
from sentinel_scan.rules import RULES_META  # noqa: E402
from sentinel_scan.scan import (run_rules, unit_from_source_file,  # noqa: E402
                                units_from_mcp_config, units_from_skill)

CORPUS = ROOT / "fixtures" / "corpus"
BEGIN = "<!-- PRECISION:BEGIN -->"
END = "<!-- PRECISION:END -->"


def case_findings(case_dir: Path, meta: dict):
    kind = meta["kind"]
    if kind == "tool":
        desc = (case_dir / "desc.txt").read_text(encoding="utf-8")
        source = ""
        if (case_dir / "source.txt").exists():
            source = (case_dir / "source.txt").read_text(encoding="utf-8")
        unit = Unit(kind="tool", name=meta["id"], origin=str(case_dir),
                    description=desc, source=source)
        return run_rules([unit]), None
    if kind == "source":
        payload = next(p for p in case_dir.iterdir()
                       if p.suffix in (".py", ".js"))
        return run_rules([unit_from_source_file(payload)]), None
    if kind == "config":
        return run_rules(units_from_mcp_config(case_dir / "config.json")), None
    if kind == "skill":
        return run_rules(units_from_skill(case_dir)), None
    if kind == "pinverify":
        v1 = pin_mod.load_tools_manifest(case_dir / "tools_v1.json")
        v2 = pin_mod.load_tools_manifest(case_dir / "tools_v2.json")
        pins = pin_mod.build_pins(v1)
        findings = pin_mod.verify_pins(v2, pins, origin=str(case_dir))
        return findings, {f.rule_id: sorted({x.unit for x in findings
                                             if x.rule_id == f.rule_id})
                          for f in findings}
    raise ValueError(kind)


def measure() -> dict:
    per_rule = {r: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "cases": 0}
                for r in RULES_META}
    surprises = []
    n_cases = 0
    for case_dir in sorted(CORPUS.iterdir()):
        meta_file = case_dir / "case.json"
        if not meta_file.exists():
            continue
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        findings, unit_map = case_findings(case_dir, meta)
        fired = {f.rule_id for f in findings}
        scoped = meta.get("rules_scoped") or list(RULES_META)
        expected = set(meta.get("fires") or [])
        n_cases += 1
        for rule in scoped:
            per_rule[rule]["cases"] += 1
            want, got = rule in expected, rule in fired
            key = ("tp" if want and got else "fp" if got else
                   "fn" if want else "tn")
            per_rule[rule][key] += 1
            if key in ("fp", "fn"):
                surprises.append(f"{meta['id']}: {rule} -> {key}")
        for rule, want_units in (meta.get("expect_units") or {}).items():
            got_units = (unit_map or {}).get(rule, [])
            if sorted(want_units) != got_units:
                surprises.append(
                    f"{meta['id']}: {rule} units {got_units} "
                    f"!= expected {sorted(want_units)}")
    for blob in per_rule.values():
        fp_d = blob["fp"] + blob["tn"]
        fn_d = blob["fn"] + blob["tp"]
        blob["fp_rate"] = round(blob["fp"] / fp_d, 4) if fp_d else 0.0
        blob["fn_rate"] = round(blob["fn"] / fn_d, 4) if fn_d else 0.0
    totals = {k: sum(b[k] for b in per_rule.values())
              for k in ("tp", "fp", "fn", "tn")}
    return {"corpus_cases": n_cases, "per_rule": per_rule,
            "totals": totals, "surprises": surprises}


def table_md(result: dict) -> str:
    lines = ["| Rule | Cases | TP | FP | FN | FP rate | FN rate |",
             "|------|------:|---:|---:|---:|--------:|--------:|"]
    for rule, b in result["per_rule"].items():
        lines.append(f"| {rule} | {b['cases']} | {b['tp']} | {b['fp']} | "
                     f"{b['fn']} | {b['fp_rate']:.2%} | {b['fn_rate']:.2%} |")
    t = result["totals"]
    lines.append(f"| **All rules** | {result['corpus_cases']} cases | "
                 f"{t['tp']} | {t['fp']} | {t['fn']} | – | – |")
    return "\n".join(lines)


def splice_readme(table: str) -> str:
    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    block = f"{BEGIN}\n{table}\n{END}"
    if BEGIN in readme:
        pre, rest = readme.split(BEGIN, 1)
        _, post = rest.split(END, 1)
        return pre + block + post
    return readme + "\n" + block + "\n"


def main() -> int:
    check = "--check" in sys.argv
    result = measure()
    payload = json.dumps(result, indent=2) + "\n"
    table = table_md(result)
    if check:
        ok = True
        committed = (ROOT / "data" / "precision.json")
        if not committed.exists() or committed.read_text() != payload:
            print("precision.json is stale")
            ok = False
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        if BEGIN in readme:
            current = readme.split(BEGIN, 1)[1].split(END, 1)[0].strip()
            if current != table.strip():
                print("README precision table is stale")
                ok = False
        else:
            print("README precision table missing")
            ok = False
        if result["surprises"]:
            print("surprises:", *result["surprises"], sep="\n  ")
            ok = False
        print("MEASURE CHECK:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    (ROOT / "data" / "precision.json").write_text(payload, encoding="utf-8")
    (ROOT / "README.md").write_text(splice_readme(table), encoding="utf-8")
    print(f"measured {result['corpus_cases']} cases; "
          f"totals TP={result['totals']['tp']} FP={result['totals']['fp']} "
          f"FN={result['totals']['fn']}")
    if result["surprises"]:
        print("surprises:", *result["surprises"], sep="\n  ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
