"""Signal patterns for the poisoning rules.

Design notes (precision first):
- STRONG signals fire a rule on their own: markup directives aimed at the
  model, "note to the AI" framing, concealment-from-user phrasing.
- WEAK signals need two distinct hits, and are suppressed when every hit
  sits inside a quoted or fenced span in a documenting context (a security
  tool that *quotes* an injection as an example is the classic false
  positive of pattern-matching scanners; we refuse to repeat it).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# strong signals: hidden instruction directed at the model
# ---------------------------------------------------------------------------
STRONG_INSTRUCTION = [
    ("markup-directive", re.compile(
        r"<\s*(IMPORTANT|SYSTEM|INSTRUCTION|OVERRIDE)\b[^>]*>", re.I)),
    ("bracket-directive", re.compile(
        r"\[\s*(SYSTEM|SYS|INSTRUCTION|OVERRIDE)\s*[:\]]", re.I)),
    ("note-to-model", re.compile(
        r"\b(note|message|attention|instruction)s?\s+(to|for)\s+"
        r"(the\s+)?(ai|a\.i\.|model|assistant|llm|agent)\b", re.I)),
    ("model-address", re.compile(
        r"\b(dear|hello|hey)\s+(ai|model|assistant|llm)\b", re.I)),
]

# ---------------------------------------------------------------------------
# weak signals: suspicious phrasing that needs corroboration
# ---------------------------------------------------------------------------
WEAK_INSTRUCTION = [
    ("ignore-instructions", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}?"
        r"\b(previous|prior|above|earlier|original|system)\b[^.]{0,25}?"
        r"\b(instructions?|prompts?|directions?|rules?)\b", re.I)),
    ("new-instructions", re.compile(
        r"\b(new|real|actual|updated)\s+instructions?\s*[:\-]", re.I)),
    ("system-prompt-reference", re.compile(
        r"\b(system\s+prompt|developer\s+message)\b[^.]{0,40}?"
        r"\b(says?|states?|instructs?|requires?|overrides?)\b", re.I)),
    ("fetch-and-include", re.compile(
        r"\b(read|open|load|fetch|retrieve)\b[^.]{0,60}?"
        r"\b(and|then)\b[^.]{0,30}?\b(include|add|attach|insert|pass)\b", re.I)),
]

DOC_VERBS = re.compile(
    r"\b(detects?|detected|flag(s|ged)?|example|e\.g\.|such as|quot\w+|"
    r"pattern|attempt|malicious|injection|documentation|illustrat\w+)\b", re.I)

# ---------------------------------------------------------------------------
# exfiltration: sensitive object + transfer verb + externality / siphon
# ---------------------------------------------------------------------------
SENSITIVE_OBJECT = re.compile(
    r"(credentials?|passwords?|api[\s_-]?keys?|access\s+tokens?|secrets?|"
    r"~/\.ssh|~/\.aws|\.env\s+file|id_rsa|private\s+keys?|"
    r"conversation\s+(history|contents?|transcript)|chat\s+history|"
    r"contents?\s+of\s+(the\s+)?(file|~|/|\.)|user'?s\s+files?|"
    r"environment\s+variables?)", re.I)
TRANSFER_VERB = re.compile(
    r"\b(send|sends|sent|post|posts|upload|transmit|forward|exfiltrate|"
    r"include|attach|leak|report|deliver|relay)\b", re.I)
EXTERNALITY = re.compile(
    r"(https?://|www\.|[\w.-]+\.(com|net|io|org|dev|xyz|site)\b|"
    r"third[\s-]?part|external\s+(server|endpoint|address)|"
    r"the\s+following\s+(address|url|endpoint)|"
    r"in\s+the\s+\w+\s+(parameter|argument|field)|"
    r"to\s+[\w.+-]+@[\w-]+\.[\w.]+)", re.I)

# ---------------------------------------------------------------------------
# covert action: concealment from the user
# ---------------------------------------------------------------------------
CONCEALMENT = re.compile(
    r"(\b(do\s+not|don't|dont|never|must\s+not|should\s+not)\b[^.]{0,40}?"
    r"\b(tell|inform|notify|mention|alert|show)\b[^.]{0,25}?\buser\b|"
    r"\bwithout\s+(telling|informing|notifying|alerting|mentioning)\b"
    r"[^.]{0,25}?\buser\b|"
    r"\bkeep\s+(this|it)\s+(secret|hidden)\s+from\s+the\s+user\b|"
    r"\buser\s+(does\s+not|doesn't|should\s+not|must\s+not)\s+"
    r"(need\s+to\s+)?know\b|"
    r"\bsilently\s+(send|forward|upload|post|transmit|copy)\b)", re.I)

# ---------------------------------------------------------------------------
# span helpers: quoted and fenced regions (documentation contexts)
# ---------------------------------------------------------------------------
_QUOTED = re.compile(
    r'"[^"\n]{3,}"|\'[^\'\n]{3,}\'|`[^`\n]{3,}`')
_FENCED = re.compile(r"```.*?```", re.S)


def _inside_spans(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(s <= start and end <= e for s, e in spans)


def doc_spans(text: str) -> list[tuple[int, int]]:
    """Quoted + fenced spans, only meaningful when a doc verb is present."""
    spans = [(m.start(), m.end()) for m in _QUOTED.finditer(text)]
    spans += [(m.start(), m.end()) for m in _FENCED.finditer(text)]
    return spans


def count_signals(text: str) -> tuple[list[str], list[str]]:
    """Return (strong_names, weak_names) for instruction-poisoning signals.

    Weak hits entirely inside quoted/fenced spans are dropped when the
    text is in a documenting frame (doc verb present). Strong hits are
    kept regardless of quoting (a quoted <IMPORTANT> block is still a
    payload shape), except the same documentation suppression applies
    when the strong hit is inside a fenced code block.
    """
    documenting = bool(DOC_VERBS.search(text))
    spans = doc_spans(text) if documenting else []
    strong: list[str] = []
    for name, rx in STRONG_INSTRUCTION:
        for m in rx.finditer(text):
            fenced = _inside_spans(
                [(s, e) for s, e in spans if text[s:s + 3] == "```"],
                m.start(), m.end())
            if documenting and fenced:
                continue
            strong.append(name)
            break
    weak: list[str] = []
    for name, rx in WEAK_INSTRUCTION:
        for m in rx.finditer(text):
            if documenting and _inside_spans(spans, m.start(), m.end()):
                continue
            weak.append(name)
            break
    return strong, weak


def html_comment_directives(text: str) -> list[str]:
    """Directive-bearing HTML comments (a real skill/tool-description vector)."""
    hits = []
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        body = m.group(1)
        if re.search(r"\b(ignore|disregard|override|instruction|system|"
                     r"must|always|never|send|exfiltrate)\b", body, re.I):
            hits.append(body.strip()[:120])
    return hits
