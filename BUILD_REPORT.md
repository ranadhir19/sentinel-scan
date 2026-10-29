# Sentinel Scan — Build Report

**Built:** 2026-10-29, per the Sentinel Scan spec in
`~/workspace/your_files/Developer_Tools_Plan_2026-10-29.md` (§3, first
build). Staged locally at `~/workspace/sentinel-scan/`; **not pushed** —
the parent verifies and pushes, per the standing pattern.

## What was built

- **Package** `sentinel-scan` 0.1.0, src layout (`src/sentinel_scan/`),
  pure stdlib, zero runtime dependencies, Python ≥ 3.10. Console
  script `sentinel-scan` with `scan` / `pin` / `verify` / `demo`.
- **Scan surfaces:** MCP config JSON (mcpServers), tool manifests
  (registry-style `{tools: [...]}` or list), server/skill source files
  (.py/.js/.ts/.sh/…), SKILL.md folders (frontmatter + body + bundled
  scripts), and whole directories (auto-detected, recursive).
- **11 rules** (see README catalogue): 3 description-poisoning rules,
  description-hash pinning (rug pull), 3 source-sink rules, hardcoded
  secrets, 2 skill rules, filesystem-scope overreach. Findings carry
  severity + an OWASP (LLM / Agentic 2026) mapping per rule.
- **Outputs:** terminal text, JSON, SARIF 2.1.0 (GitHub Security tab);
  CI exit codes via `--fail-on` (default high for scan, critical for
  verify).
- **Rug-pull pinning:** `pin` writes SHA-256 hashes of normalised
  descriptions (whitespace-only edits do not trip it); `verify` flags
  changed or removed tools.
- **GitHub Action** (`action.yml`, composite): setup-python → pip
  install → scan → upload SARIF via codeql-action.
- **Labelled corpus:** `fixtures/corpus/` — 32 cases; every rule has
  planted positives AND benign near-miss negatives (quoted-injection
  detector tool, "ignores previous cached results", AWS documentation
  example key, `ast.literal_eval`, fixed-argv `shell=False`
  subprocess, comment-only danger mentions, project-scoped filesystem
  server, training skill quoting an example in a fence, …).
- **Demo corpus:** 12 tools exactly as specced (6 benign incl. the two
  traps, 6 planted) behind `sentinel-scan demo`, including a live
  pin→tamper→verify rug-pull demonstration. The corpus is also bundled
  as package data so the demo works from a real pip install (verified
  from a clean `--target` install — see Deviations).
- **Local web demo** (`demo/`): FastAPI backend + single-page React
  front end (paste → verdict), per the portfolio demo standard;
  deployment is a separate later step.
- **Examples** (`examples/`): a clean MCP config, a tools manifest with
  one planted poisoned tool, a sample undeclared-capability skill.

## Measured precision (the product's differentiator)

`scripts/measure.py` over the 32-case labelled corpus
(`data/precision.json`, spliced into the README by the script):

- **Totals: TP 18, FP 0, FN 0, TN 314 — FP rate 0.00% and FN rate
  0.00% for every rule on this corpus.**
- Honest scope: these are rates on a curated 32-case corpus built to
  include the known trap shapes, not a claim about arbitrary
  third-party servers. The corpus is versioned so the measurement is
  reproducible and extendable; the README says exactly this.

Measurement caught three real defects during the build, all fixed and
re-measured: (1) a JS destructured `child_process` `exec` was missed
by the command rule and misfiled under dynamic-code; (2) bare "files"
as an exfiltration object (a covert sync tool) was missed — now fires
only with a literal external destination; (3) the demo corpus was not
reachable from an installed layout — now bundled as package data.

## Gates

- `python3 validate.py` — **OVERALL: PASS**, all six stages:
  import/compile; test suite (**35 passed**); precision consistency
  (fresh re-measurement == committed `data/precision.json` == README
  table, zero surprises); demo smoke test (7 scan findings + 1
  rug-pull finding); reference-integrity scan of the exact repo
  content (**0 candidate hits**, confirmed again by a direct scan of
  the finished tree); banned-name check (absent, also confirmed by a
  case-insensitive grep: 0 matches).
- Install story verified end-to-end: `pip install --target` from the
  repo, then the installed `sentinel-scan` console script ran `demo`
  (12 units, 7 + 1 findings) and `scan` (exit 1 on the planted
  example, exit 0 on the clean corpus config at default threshold).
- Size: ~508 KB total repo, 107 files; all fixtures are hand-written
  text (KB-scale). No third-party servers were downloaded; no model
  weights; no API keys or GPU anywhere.

## Deviations from the spec

1. **Reality-check scans of public servers: not performed.** The spec
   allowed a small number of individually fetched public examples; the
   build instead validated against the hand-built labelled corpus only,
   keeping the no-big-download constraint absolute and the precision
   numbers fully reproducible offline. A public-server scan run is a
   good first post-launch step (it is also the planned YouTube demo).
2. **Demo UI is local-only** (as the task specified): FastAPI + React
   single page in `demo/`; Render deployment not attempted.
3. **governed-agents reuse is conceptual, not code.** The mirror was
   mined first; its transferable assets were the hash-pinning idea
   (sentinel-ledger) and the measured FP/FN discipline
   (injection-containment). Its agent-behaviour scoring code does not
   transfer to static MCP/skill analysis, so the scanner is new code;
   the README's lineage note says so plainly.

## Push-readiness verdict

**READY.** validate.py green in the final state, reference-integrity
scan clean (0 candidates), precision artifacts consistent, install
story verified from a clean target install. Suggested repo:
`ranadhir19/sentinel-scan`; suggested PyPI release follows the repo
push. The plan's 90-day success gate (≥5k downloads/mo run-rate,
≥300 stars, ≥10 external issues/PRs, ≥1 registry listing; fold-in
decision at day 60) starts at first publication.
