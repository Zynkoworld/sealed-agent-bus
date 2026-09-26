#!/usr/bin/env python3
"""docs_bind_probe.py — a TÁMADÁSI MÁTRIX állításait a kódhoz köti.

MIÉRT: a mátrix minden sora egy ÁLLÍTÁS („ZÁRVA", „CÁFOLVA", „NYITVA"), és a partner-körök rendre a mátrixra
hivatkoznak. Mérés 2026-09-16: a 60 sorból **20 ZÁRVA/CÁFOLVA sor prózán állt** — egyetlen olyan azonosítót
sem nevezett meg, ami a kódban létezik. Egy „zárva", amit semmi nem köt a kódhoz, pontosan az a fajta állítás,
amit a partnerünk a korpuszban háromszor is kimért nálunk: állításnak látszik, de nem az.

A szabály innentől: MINDEN „ZÁRVA"/„CÁFOLVA" sor nevezzen meg legalább egy backtickes azonosítót, ami
LÉTEZIK — kód-szimbólumként vagy fájlként. A „NYITVA" sorokra ez nem áll: ott épp az a lényeg, hogy nincs
mechanizmus.

rc=0 zöld · rc=1 kötetlen sor · rc=2 használati hiba.
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
        print("docs_bind_probe: nincs támadási mátrix (%s)" % path)
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
    # …és a SÉMA-doksi: minden backtickes azonosító vagy a kódban van, vagy a bekezdés kimondja, hogy
    # TÁJÉKOZTATÓ. Mérve 2026-09-16: a `proposal` „ismert értékként" szerepelt, de a kód sehol nem ismeri —
    # aki a doksiból épít, azt hihette, hogy kezelve van.
    schema = os.path.join(DOCS, "AGENT_BUS_SCHEMA.md")
    if os.path.exists(schema):
        txt = open(schema, encoding="utf-8").read()
        # SOR-szintű szabály (a bekezdés túl durva egység volt: egy magyarázó mondat az egész bekezdést
        # kivonta a mérés alól — a saját mutáns-próbám fogta meg). Egy TÁJÉKOZTATÓ-nak jelölt SOR kivétel;
        # a szomszédai nem.
        _lines = txt.splitlines()
        for _i, _line in enumerate(_lines):
            if "TÁJÉKOZTATÓ" in _line or "tájékoztató" in _line:
                continue
            para = _line
            for ident in set(re.findall(r"`([a-z_]{4,30})`", para)):
                if ident not in allsrc and not os.path.exists(os.path.join(HERE, ident)):
                    unbound.append("AGENT_BUS_SCHEMA.md — `%s` (a kódban nincs, és a bekezdés nem mondja "
                                   "tájékoztatónak)" % ident)
    print("docs_bind_probe: %d closed/refuted rows | unbound=%d" % (rows, len(unbound)))
    for u in unbound[:10]:
        # a diagnózis mondja meg, MI a baj — a mátrix-sor és a séma-doksi két különböző hiba
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
