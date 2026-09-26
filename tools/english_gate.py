#!/usr/bin/env python3
"""English gate: fail if any text line outside docs/internal-hu/ looks Hungarian.

A line is flagged when, after the literal allowlist tokens are removed, it contains
a Hungarian accented character or a common Hungarian stop-word (whole word,
case-insensitive).

Deterministic: files are visited in sorted path order and the report is stable.
Skipped: the .git directory, binary files (NUL byte or not valid UTF-8),
docs/internal-hu/ (historical internal notes, intentionally Hungarian), and this
script itself (it has to spell out the stop-words it looks for).

Usage:  python3 tools/english_gate.py [ROOT] [--quiet]
Exit:   0 = clean, 1 = Hungarian lines found.
"""
import os
import re
import sys

ACCENTED = re.compile("[áéíóöőúüűÁÉÍÓÖŐÚÜŰ]")

STOPWORDS = (
    "és", "vagy", "nem", "csak", "minden", "kell", "van", "nincs", "ha",
    "akkor", "mert", "hogy", "lehet", "már", "még",
)
# \w is Unicode-aware for str patterns, so "ha" does not match inside "hash".
STOPWORD_RE = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(w) for w in STOPWORDS) + r")(?!\w)",
    re.IGNORECASE,
)

# Identifiers and product names that are allowed verbatim. Removed from a line
# (exact, case-sensitive, longest first) before the checks run.
ALLOWLIST = ("Zynko", "zafire", "korpusz_sema", "parositas", "pr_gomb")
# Non-ASCII test vectors that must stay byte-identical: the signed conformance
# vector in docs/AGENT_BUS_SCHEMA.md (its sha256 and signatures cover these bytes)
# and a UTF-8 round-trip input in test_poke_hardening_20260916.py.
TEST_VECTORS = ("árvíztűrő tükörfúrógép\\tvége", "árvíztűrő")
_REMOVE = tuple(sorted(ALLOWLIST + TEST_VECTORS, key=len, reverse=True))

EXCLUDED_DIRS = ("docs/internal-hu",)
SELF = "tools/english_gate.py"


def is_excluded(rel):
    if rel == SELF:
        return True
    return any(rel == d or rel.startswith(d + "/") for d in EXCLUDED_DIRS)


def read_text(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def line_hits(line):
    stripped = line
    for token in _REMOVE:
        stripped = stripped.replace(token, "")
    return bool(ACCENTED.search(stripped) or STOPWORD_RE.search(stripped))


def scan(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if is_excluded(rel):
                continue
            text = read_text(path)
            if text is None:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if line_hits(line):
                    findings.append((rel, lineno, line.strip()))
    return findings


def main(argv):
    quiet = "--quiet" in argv
    args = [a for a in argv if a != "--quiet"]
    root = args[0] if args else "."
    findings = scan(root)
    if not quiet:
        for rel, lineno, text in findings:
            print(f"{rel}:{lineno}: {text[:160]}")
    files = len({f[0] for f in findings})
    if findings:
        print(f"english_gate: FAIL — {len(findings)} Hungarian line(s) in {files} file(s)")
        return 1
    print("english_gate: PASS — 0 Hungarian lines")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
