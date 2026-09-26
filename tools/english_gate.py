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

# Identifiers and product names allowed verbatim everywhere (exact, case-sensitive).
ALLOWLIST = ("Zynko", "zafire", "korpusz_sema", "parositas", "pr_gomb")

# Byte-identical Hungarian literals, allowed ONLY in the named file: test vectors the test (or a
# signature/hash) depends on, and match strings that read the Hungarian internal notes. Translating
# any of them would change test logic or behaviour.
FILE_VECTORS = {
    # the leak scanner's own Hungarian regex alternatives (a pattern holder; code, not prose)
    "product/release_preflight.py": (
        "t[áa]mad[óo]k[öo]r", "k[óo]dn[ée]v",
        "t[óo]l|t[őo]l|r[óo]l|r[őo]l", "n[áa]l|n[ée]l|ra|re|[ée]k|[ée]",
    ),
    # row keywords of docs/internal-hu/TAMADASI_MATRIX_v1.5.md (closed / refuted / open)
    "docs_bind_probe.py": ("ZÁRVA", "CÁFOLVA", "NYITVA"),
    # signed conformance vector: the doc's sha256, byte length and Ed25519 signatures cover it
    "docs/AGENT_BUS_SCHEMA.md": ("árvíztűrő",),
    "test_schema_doc_signed_shape.py": ("árvíztűrő",),
    # UTF-8 round-trip input for bus_poke._safe
    "test_poke_hardening_20260916.py": ("árvíztűrő tükörfúrógép\\tvége",),
    # leak-scanner regex inputs: Hungarian case endings, protocol vocabulary, invalid version
    "product/test_product_packaging.py": (
        "Licensor:  Examplesoft (Ödönyi Elek and Kovács Elek Pál)",
        "a kör-bejegyzés round_seq mezője", "round2 az ack-ablakban",
        # three of the leak-scanner inputs (a cross-reference, a ticket number and a severity label)
        # are allowlisted by their Hungarian fragment only, so this file carries no leak shape itself
        "a mérés hiánya", "lásd", "Válasz Ödönnek", "Kovács Elek", "Ödönyi",
        "Ödönnek", "Ödöntől", "Ödönnel", "Ödön_key", "Ödön", "nem-verzio",
    ),
}


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


def line_hits(line, rel=""):
    stripped = line
    tokens = ALLOWLIST + FILE_VECTORS.get(rel, ())
    for token in sorted(tokens, key=len, reverse=True):
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
                if line_hits(line, rel):
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
