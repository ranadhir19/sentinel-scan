"""Detection rules.

Every rule is a function Unit -> list[Finding]. Rules are deliberately
narrow: each fires on a specific, explainable signal shape, because the
product's claim is precision (a published, measured false-positive rate
per rule), not recall theatre.
"""

from __future__ import annotations

import re

from . import patterns
from .model import Finding, Unit

RULES_META = {
    "poison.hidden-instruction": {
        "severity": "critical",
        "title": "Hidden instruction to the model in a tool description",
        "owasp": "LLM01 / Agentic ASI01 (tool poisoning)",
    },
    "poison.data-exfiltration": {
        "severity": "high",
        "title": "Description directs exfiltration of sensitive data",
        "owasp": "LLM02 / Agentic ASI03",
    },
    "poison.covert-action": {
        "severity": "high",
        "title": "Description directs action concealed from the user",
        "owasp": "Agentic ASI01 / ASI07",
    },
    "rugpull.description-changed": {
        "severity": "critical",
        "title": "Tool description changed after pinning (rug pull)",
        "owasp": "Agentic ASI04 (supply chain)",
    },
    "sink.command-execution": {
        "severity": "high",
        "title": "Shell / string command execution in server or skill code",
        "owasp": "Agentic ASI05 (code execution)",
    },
    "sink.dynamic-code": {
        "severity": "high",
        "title": "Dynamic code evaluation (eval/exec/Function) in code",
        "owasp": "Agentic ASI05 (code execution)",
    },
    "sink.sensitive-file-access": {
        "severity": "high",
        "title": "Access to credential stores or full environment dump",
        "owasp": "LLM02 / Agentic ASI03",
    },
    "secret.hardcoded": {
        "severity": "critical",
        "title": "Hardcoded credential in scanned content",
        "owasp": "LLM02 / Agentic ASI03",
    },
    "skill.instruction-malware": {
        "severity": "critical",
        "title": "Hidden instruction malware in a SKILL.md body",
        "owasp": "Agentic ASI01 / ASI04",
    },
    "skill.undeclared-capability": {
        "severity": "high",
        "title": "Skill uses shell/network capabilities it does not declare",
        "owasp": "Agentic ASI02 (tool misuse) / ASI07",
    },
    "perm.filesystem-overreach": {
        "severity": "medium",
        "title": "Filesystem server scoped to root or home directory",
        "owasp": "Agentic ASI03 (privilege abuse)",
    },
}


def _f(rule_id: str, unit: Unit, message: str, evidence: str = "") -> Finding:
    return Finding(rule_id=rule_id, severity=RULES_META[rule_id]["severity"],
                   unit=unit.name, origin=unit.origin, message=message,
                   evidence=evidence[:300])


# ---------------------------------------------------------------------------
# description poisoning (MCP tools + skill bodies)
# ---------------------------------------------------------------------------

def rule_hidden_instruction(u: Unit) -> list[Finding]:
    text = u.description
    if not text:
        return []
    strong, weak = patterns.count_signals(text)
    comments = patterns.html_comment_directives(text)
    if strong or len(set(weak)) >= 2 or comments:
        why = []
        if strong:
            why.append("strong signal: " + ", ".join(sorted(set(strong))))
        if len(set(weak)) >= 2:
            why.append("weak signals: " + ", ".join(sorted(set(weak))))
        if comments:
            why.append("directive-bearing HTML comment")
        return [_f("poison.hidden-instruction", u,
                   "Tool description carries an instruction aimed at the "
                   "model, not at describing the tool (" + "; ".join(why) + ")",
                   text[:300])]
    return []


_URL_EXTERNALITY = re.compile(
    r"https?://|[\w.-]+\.(com|net|io|org|dev|xyz|site)\b|"
    r"to\s+[\w.+-]+@[\w-]+\.[\w.]+", re.I)
_FILES_OBJECT = re.compile(r"\bfiles?\b", re.I)


def rule_data_exfiltration(u: Unit) -> list[Finding]:
    text = u.description
    if not text or not patterns.TRANSFER_VERB.search(text):
        return []
    strong = (patterns.SENSITIVE_OBJECT.search(text)
              and patterns.EXTERNALITY.search(text))
    # bare "files" counts as an object only with a literal external
    # destination (a URL/domain/email), not a parameter siphon.
    weak = (_FILES_OBJECT.search(text)
            and _URL_EXTERNALITY.search(text))
    if strong or weak:
        return [_f("poison.data-exfiltration", u,
                   "Description directs sensitive data (credentials, files, "
                   "conversation contents) to be transferred out or smuggled "
                   "through a parameter.", text[:300])]
    return []


def rule_covert_action(u: Unit) -> list[Finding]:
    text = u.description
    if not text:
        return []
    m = patterns.CONCEALMENT.search(text)
    if m:
        return [_f("poison.covert-action", u,
                   "Description directs an action while concealing it from "
                   "the user.", m.group(0)[:160])]
    return []


# ---------------------------------------------------------------------------
# source-code sinks
# ---------------------------------------------------------------------------

def _strip_comments(text: str) -> str:
    """Remove comments only (string contents kept, positions preserved)."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            quote = c
            triple = text[i:i + 3] == quote * 3
            j = i + (3 if triple else 1)
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if triple and text[j:j + 3] == quote * 3:
                    j += 3
                    break
                if not triple and text[j] == quote:
                    j += 1
                    break
                if not triple and text[j] == "\n":
                    break
                j += 1
            i = j
        elif c == "#" or (c == "/" and i + 1 < n and text[i + 1] in "/*"):
            if c == "/" and text[i + 1] == "*":
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
            else:
                j = text.find("\n", i)
                j = n if j < 0 else j
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _strip_code(text: str) -> str:
    """Remove comments and string-literal contents (positions preserved).

    Sink rules match on code shape, so a string that merely *mentions*
    subprocess, or a comment describing eval, must not fire.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'`":
            quote = c
            triple = text[i:i + 3] == quote * 3
            j = i + (3 if triple else 1)
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if triple and text[j:j + 3] == quote * 3:
                    j += 3
                    break
                if not triple and text[j] == quote:
                    j += 1
                    break
                if not triple and text[j] == "\n":
                    break
                j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


_CMD_CODE_PATTERNS = [  # matched on fully stripped code
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bos\.popen\s*\("),
    re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True"),
]
_CMD_STRING_PATTERNS = [  # matched on comment-stripped text (strings kept)
    re.compile(r"\bsubprocess\.\w+\s*\(\s*[\"'][^\"']*\s[^\"']*[\"']"),
    re.compile(r"\bchild_process\.(exec|execSync)\s*\([^)]*(\$\{|\+)"),
    re.compile(r"\bchild_process\.exec\s*\(\s*`[^`]*\$\{"),
]
_JS_SUFFIXES = (".js", ".ts", ".mjs", ".cjs")
_CMD_JS_PATTERNS = [  # destructured child_process usage in JS/TS sources
    re.compile(r"(?<![\w.])(exec|execSync)\s*\(\s*`[^`]*\$\{"),
    re.compile(r"(?<![\w.])(exec|execSync)\s*\([^)]*(\+|\$\{)"),
]


def rule_command_execution(u: Unit) -> list[Finding]:
    if not u.source:
        return []
    raw = u.source
    views = [(_CMD_CODE_PATTERNS, _strip_code(raw)),
             (_CMD_STRING_PATTERNS, _strip_comments(raw))]
    if u.origin.endswith(_JS_SUFFIXES):
        views.append((_CMD_JS_PATTERNS, _strip_comments(raw)))
    for patterns, view in views:
        for rx in patterns:
            m = rx.search(view)
            if m:
                return [_f("sink.command-execution", u,
                           "Code executes commands through a shell or a "
                           "string command (injection-prone shape).",
                           raw[max(0, m.start() - 20):
                               m.start() + 80].strip())]
    return []


_DYNAMIC = re.compile(
    r"(?<![\w.])eval\s*\(|__import__\s*\(|(?<![\w.])Function\s*\(")
_DYNAMIC_PY_EXEC = re.compile(r"(?<![\w.])exec\s*\(")


def rule_dynamic_code(u: Unit) -> list[Finding]:
    if not u.source:
        return []
    stripped = _strip_code(u.source)
    m = _DYNAMIC.search(stripped)
    if m is None and not u.origin.endswith(_JS_SUFFIXES):
        # bare exec() is the Python builtin; in JS sources a bare exec(
        # is the destructured child_process call, which is the
        # command-execution rule's territory, not this rule's.
        m = _DYNAMIC_PY_EXEC.search(stripped)
    if m:
        return [_f("sink.dynamic-code", u,
                   "Code evaluates dynamically supplied code "
                   "(eval/exec/Function/__import__).",
                   u.source[max(0, m.start() - 20):m.start() + 60].strip())]
    return []


_SENSITIVE_PATH = re.compile(
    r"(~|\$HOME|\bhome\b)[^\s\"']*(\.ssh|\.aws|\.gnupg)|"
    r"id_(rsa|ed25519|ecdsa)|/etc/(passwd|shadow)|"
    r"\.aws[/\\]credentials|\.ssh[/\\]id_", re.I)
_ENV_DUMP = re.compile(
    r"dict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(|"
    r"\{\s*\*\*\s*os\.environ|\{\s*\.\.\.\s*process\.env|"
    r"JSON\.stringify\s*\(\s*process\.env\s*\)")


def rule_sensitive_file_access(u: Unit) -> list[Finding]:
    if not u.source:
        return []
    raw = u.source
    # comments stripped (a comment *mentioning* ~/.ssh is not access);
    # string contents kept (a literal path argument IS the access).
    view = _strip_comments(raw)
    m = _SENSITIVE_PATH.search(view) or _ENV_DUMP.search(view)
    if m:
        return [_f("sink.sensitive-file-access", u,
                   "Code reaches for credential stores (ssh/aws/gnupg, "
                   "shadow files) or dumps the full process environment.",
                   raw[max(0, m.start() - 20):m.start() + 80].strip())]
    return []


# ---------------------------------------------------------------------------
# hardcoded secrets (raw text: secrets live inside string literals)
# ---------------------------------------------------------------------------

_PLACEHOLDER = re.compile(
    r"example|your[-_ ]|xxx|placeholder|changeme|sample|dummy|"
    r"redacted|insert[-_ ]|replace[-_ ]", re.I)
_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("OpenAI-style API key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("assigned credential literal", re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*"
        r"[\"'][A-Za-z0-9_\-/+]{16,}[\"']")),
]


def rule_hardcoded_secret(u: Unit) -> list[Finding]:
    texts = [u.source or "", u.description or ""]
    env_blob = ""
    if u.config:
        env_blob = " ".join(str(v) for v in
                            (u.config.get("env") or {}).values())
        texts.append(env_blob)
        texts.append(" ".join(str(a) for a in u.config.get("args") or []))
    for text in texts:
        if not text:
            continue
        for label, rx in _SECRET_PATTERNS:
            for m in rx.finditer(text):
                if _PLACEHOLDER.search(m.group(0)):
                    continue
                return [_f("secret.hardcoded", u,
                           f"Hardcoded credential in scanned content "
                           f"({label}).", m.group(0)[:24] + "…")]
    return []


# ---------------------------------------------------------------------------
# skill rules
# ---------------------------------------------------------------------------

_CAPABILITY_EVIDENCE = re.compile(
    r"(```|\`)\s*[^`\n]{0,80}?\b(curl|wget|bash|sh|python3?|node|pip3?\s+install|npm\s+)\b|"
    r"\b(execute|run|invoke)\s+(the\s+)?(downloaded|attached|bundled|following)\s+"
    r"(script|file|command|binary)\b|"
    r"\bcurl\s+https?://|\bwget\s+https?://", re.I)
_SHELL_TOKENS = {"bash", "shell", "terminal", "execute", "command", "sh",
                 "powershell", "cmd"}


def _declared_tools(u: Unit) -> set[str]:
    raw = u.frontmatter.get("allowed-tools") or u.frontmatter.get(
        "allowed_tools") or []
    if isinstance(raw, str):
        raw = [t.strip() for t in re.split(r"[,\[\]]", raw) if t.strip()]
    out = set()
    for t in raw:
        out.add(str(t).strip().lower().strip("[]'\" "))
    return out


def rule_skill_undeclared_capability(u: Unit) -> list[Finding]:
    if u.kind != "skill":
        return []
    body = u.source
    if not body or not _CAPABILITY_EVIDENCE.search(body):
        return []
    declared = _declared_tools(u)
    if declared & _SHELL_TOKENS:
        return []
    return [_f("skill.undeclared-capability", u,
               "Skill body invokes shell/network commands but its "
               "frontmatter declares no shell capability "
               f"(declared: {sorted(declared) or 'none'}).")]


def rule_skill_instruction_malware(u: Unit) -> list[Finding]:
    if u.kind != "skill":
        return []
    body = u.source
    if not body:
        return []
    comments = patterns.html_comment_directives(body)
    strong, weak = patterns.count_signals(body)
    if comments or strong or len(set(weak)) >= 2:
        why = []
        if comments:
            why.append("directive-bearing HTML comment")
        if strong:
            why.append("strong signal: " + ", ".join(sorted(set(strong))))
        if len(set(weak)) >= 2:
            why.append("weak signals: " + ", ".join(sorted(set(weak))))
        return [_f("skill.instruction-malware", u,
                   "SKILL.md body carries hidden instructions aimed at "
                   "the agent (" + "; ".join(why) + ")", body[:200])]
    return []


# ---------------------------------------------------------------------------
# config rules
# ---------------------------------------------------------------------------

_FS_SERVER = re.compile(r"server-filesystem|mcp-server-filesystem|"
                        r"filesystem", re.I)
_ROOT_ARGS = {"/", "~", "$HOME", "/home", "/Users", "C:\\", "C:/"}


def rule_filesystem_overreach(u: Unit) -> list[Finding]:
    if u.kind != "config" or not u.config:
        return []
    cmd = str(u.config.get("command") or "")
    args = [str(a) for a in u.config.get("args") or []]
    blob = cmd + " " + " ".join(args)
    if not _FS_SERVER.search(blob):
        return []
    for a in args:
        if a in _ROOT_ARGS or re.fullmatch(r"/home/[^/]+", a) \
                or re.fullmatch(r"/Users/[^/]+", a):
            return [_f("perm.filesystem-overreach", u,
                       "Filesystem server is scoped to a root or home "
                       f"directory ('{a}'), not a project directory.")]
    return []


DESCRIPTION_RULES = [rule_hidden_instruction, rule_data_exfiltration,
                     rule_covert_action]
SOURCE_RULES = [rule_command_execution, rule_dynamic_code,
                rule_sensitive_file_access]
ALL_RULES = DESCRIPTION_RULES + SOURCE_RULES + [
    rule_hardcoded_secret,
    rule_skill_undeclared_capability,
    rule_skill_instruction_malware,
    rule_filesystem_overreach,
]
