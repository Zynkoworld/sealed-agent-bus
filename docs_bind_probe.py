#!/usr/bin/env python3
"""docs_bind_probe.py — binds the ATTACK MATRIX's claims to the code.

WHY: every row of the matrix is a CLAIM (closed, refuted, open — ZÁRVA / CÁFOLVA / NYITVA in the matrix), and the partner rounds
keep citing the matrix. Measured 2026-09-16: of the 60 rows, **20 closed/refuted rows stood on prose** — they did not name a single
identifier that exists in the code. A "closed" that nothing binds to the code is exactly the kind of claim
our partner measured against us three times in the corpus: it looks like a claim, but it is not.

The rule from now on: EVERY closed/refuted row must name at least one backticked identifier that
EXISTS — as a code symbol or as a file. This does not apply to "open" rows: there the point is precisely that there is no
mechanism.

rc=0 green · rc=1 unbound row · rc=2 usage error.
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "docs")


def main(argv=None) -> int:
    src = {}
    for f in os.listdir(HERE):
        if f.endswith(".py"):
            try:
                src[f] = open(os.path.join(HERE, f), encoding="utf-8").read()
            except OSError:
                pass
    allsrc = "\n".join(src.values())
    path = os.path.join(DOCS, "internal-hu", "TAMADASI_MATRIX_v1.5.md")
    if not os.path.exists(path):
        print("docs_bind_probe: no attack matrix (%s)" % path)
        return 2
    doc = open(path, encoding="utf-8").read()
    rows, unbound = 0, []
    for line in doc.splitlines():
        if not line.startswith("|") or not ("ZÁRVA" in line or "CÁFOLVA" in line):
            continue
        rows += 1
        ids = re.findall(r"`([A-Za-z_][A-Za-z0-9_.]{3,})`", line)
        if not [i for i in ids if i in allsrc or i in src or os.path.exists(os.path.join(HERE, i))]:
            unbound.append(line.split("|")[1].strip() + " — " + line.split("|")[2].strip()[:60])
    # …and the SCHEMA doc: every backticked identifier is either in the code, or the line states that it is
    # INFORMATIVE. Measured 2026-09-16: `proposal` was listed as a "known value", but the code knows it nowhere —
    # whoever builds from the doc could believe it is handled.
    schema = os.path.join(DOCS, "AGENT_BUS_SCHEMA.md")
    if os.path.exists(schema):
        txt = open(schema, encoding="utf-8").read()
        # A LINE-level rule (the paragraph was too coarse a unit: one explanatory sentence took the whole paragraph
        # out of the measurement — my own mutant probe caught it). A LINE marked INFORMATIVE is exempt;
        # its neighbours are not.
        _lines = txt.splitlines()
        for _i, _line in enumerate(_lines):
            if "INFORMATIVE" in _line or "informative" in _line:
                continue
            para = _line
            for ident in set(re.findall(r"`([a-z_]{4,30})`", para)):
                if ident not in allsrc and not os.path.exists(os.path.join(HERE, ident)):
                    unbound.append("AGENT_BUS_SCHEMA.md — `%s` (not in the code, and the line does not call it "
                                   "informative)" % ident)
    print("docs_bind_probe: %d closed/refuted rows | unbound=%d" % (rows, len(unbound)))
    for u in unbound[:10]:
        # the diagnosis says WHAT is wrong — the matrix row and the schema doc are two different errors
        if u.startswith("AGENT_BUS_SCHEMA.md"):
            print("  - the schema doc names an identifier the code does not have: %s" % u)
        else:
            print("  - a row claims CLOSED with nothing that exists in the code: %s" % u)
    if unbound:
        return 1
    print("ALL PASS — every closed/refuted matrix row names something that exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
