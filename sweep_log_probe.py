#!/usr/bin/env python3
"""sweep_log_probe.py — a KÖZJEGYZŐI NAPLÓ mező-söprése állandó őrszemként.

MIÉRT: a capsule2-oldalon a söprés (minden mező törlése / `null` / üres / típus-csere) sorra hozott olyan
leleteket, amiket kézzel írt szonda nem talált volna; a busz-oldalon ugyanez a módszer két tracebacket mutatott
ki a `reconcile`-ban (`envelope_sha256` törölve -> `KeyError`, `reason: null` -> `TypeError`). Egy ilyen mérés
viszont csak addig ér valamit, amíg valaki lefuttatja — ezért ez a fájl a CI-ben fut minden push-ra.

Amit mér: felépít egy VALÓDI kört (posta -> kiadás -> ack) a közjegyzővel és a busz audit-táblájával, majd
minden bejegyzés-mezőre végigmegy a hamisításokon, és megköveteli, hogy

  * a hamisítás NE maradjon némán zöld (a hash-lánc vagy az alak-kapu mondja ki), és
  * SOHA ne legyen traceback — a MÁSIK fél exportja megbízhatatlan bemenet, a traceback nem diagnózis.

rc=0 zöld · rc=1 néma vagy traceback · rc=2 használati hiba.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


# A KONZISZTENS ÍRÓ modelljében (hamisítás UTÁN újraláncolás) mérten NEM ellenőrzött `cursor` almezők.
# „ahol a némaság rendben van, ott egy kimondott, nevesített lista mondja ki,
# hogy az a mező nem ellenőrzött." Ez az a lista. Amelyik almező NINCS benne és mégis néma marad, az LELET.
# FONTOS, amit a mérés mutatott: ezek a mezők NEM attól kötöttek, hogy bárki olvassa őket, hanem az ALÁÍRÁSTÓL
# — ugyanez a söprés egy ALÁÍRT ellenőrzőpontot tartalmazó exporton 0 némát ad, mert az író újraláncolhat, de
# a közjegyző checkpointját nem tudja újra aláírni.
CURSOR_UNCHECKED = {
    "at":             "a kurzor állása — a busz audit-sorának from/to párja köti, a kör-bejegyzésé nem",
    "id":             "a KIADOTT üzenet azonosítója a `delivered` soron — a nyugtákkal vetjük össze, nem magában",
    "ack":            "a kör ack-célja — az audit-sor `to_id`-ja köti",
    "from":           "az ack kiinduló kurzora — az audit-sor `from_id`-ja köti",
    "to":             "az ack cél-kurzora — az audit-sor `to_id`-ja köti",
    "pending":        "csak a `replies`-hoz VISZONYÍTVA jelent állítást (`_claims_no_skip`)",
    "replies":        "ugyanaz a viszony a másik oldalról",
    "next_id":        "az első kiadatlan — csak az ack-célhoz viszonyítva állítás",
    "round_seq":      "a záró horgony visszamutatása a körre — a SORREND köti, nem az érték",
    "audit_hash":     "a nyitó horgony hash-e — a `by_seq` összevetés köti, ha az export elér odáig",
    "audit_end_hash": "a záró horgony hash-e — ugyanaz",
}


def _hex(x):
    return x.hex() if isinstance(x, (bytes, bytearray)) else str(x)


def build_round(t, mode="dev"):
    """Egy valódi kör: 3 üzenet, kiadás, ack — a napló és a busz audit-tábla is megszületik.

    (2026-09-17): a kör eddig CSAK dev módban épült (a szonda saját env-je), és product módban nem
    pirosat adott, hanem elszállt (`max()` üres listán: a kikényszerítés az aláíratlan sorokat eldobta) — a CI-ben
    futó őrszem a TERMÉK-konfigurációt nem mérte, és ezt nem mondta ki. Most a kör MINDKÉT módban felépül: product
    módban a `hub` feladó a registryben pinelt kulccsal (root, 0600) auto-aláír, tehát a kikényszerítés átengedi.
    A módok EGY tmp-könyvtárban, külön DB/napló/tár úttal élnek (az `agent_bus.KEYS_DIR` importkor rögzül)."""
    keys = os.path.join(t, "keys")
    os.environ.update({"AGENT_BUS_DB": os.path.join(t, "bus_%s.db" % mode), "AGENT_BRIDGE_DIR": t,
                       "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": mode, "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
                       "AGENT_BUS_KEYS_DIR": keys, "AGENT_WAKE_DIR": os.path.join(t, "wake"),
                       "AGENT_BUS_AUTO_SIGN": "1" if mode == "product" else "0"})
    import agent_bus as ab
    import bus_notary as bn
    import bus_ssh_exchange as ex
    db, log = os.environ["AGENT_BUS_DB"], os.path.join(t, "n_%s.jsonl" % mode)
    if mode == "product":
        # a `hub` pinelt kulcsa: registry pub + guard-olt seed (root-tulajdon, 0600, a könyvtár nem csoport/világ-írható)
        os.makedirs(keys, mode=0o700, exist_ok=True)
        os.chmod(keys, 0o700)
        hseed, hpub = bn.keypair()
        with open(os.path.join(keys, "hub.pub"), "w", encoding="utf-8") as f:
            f.write(_hex(hpub))
        kp = os.path.join(keys, "hub.ed25519.key")
        with open(kp, "w", encoding="utf-8") as f:
            f.write(_hex(hseed))
        os.chmod(kp, 0o600)
    seed, _pub = bn.keypair()
    # SŰRŰ checkpoint: a korábbi `checkpoint_every=50` mellett a 3 üzenetes körbe EGYETLEN checkpoint sem
    # került, tehát a söprés az ALÁÍRT sort meg sem látta. A saját őrszemem vakfoltja volt (2026-09-16).
    notary = bn.Notary(log, seed=seed, checkpoint_every=2, db=db)
    for i in range(3):
        ab.send("hub", "remote1", "ki-%d" % i, db=db, mirror=False)
    r1 = ex.exchange("remote1", json.dumps({}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    if mode == "product":
        # a product-kör CSAK akkor mér product-ot, ha a kikényszerítés tényleg élt ÉS a válaszok aláírva jöttek át —
        # különben a „zöld" egy dev-kör lenne product címkével (pont a hibaosztálya, egy réteggel beljebb)
        import bus_enforce as enf
        if enf.mode(db=db) != "product":
            raise RuntimeError("a product-kör nem product módban futott (mode=%r)" % enf.mode(db=db))
        # a válasz-vetület (_REPLY_KEYS) nem hordoz sig-et — a BUSZ sorait mérjük, nem a vetületet
        rows_p = ab.recv("remote1", mark=False, db=db)
        auth = [ab.verify_sender(r) for r in rows_p]
        if not r1["replies"] or not rows_p or any(a != "signed" for a in auth):
            raise RuntimeError("a product-kör sorai nem 'signed' (replies=%d, auth=%s) — a kikényszerítés nem mérhető"
                               % (len(r1["replies"]), auth))
    top = max(m["id"] for m in r1["replies"])
    ex.exchange("remote1", json.dumps({"ack": top}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    if mode == "product":
        # a valódi oka: az exchange PROCESS-GLOBÁLISAN kapcsolta ki az auto-signt — egy KÉSŐBBI küldés ugyanabban a
        # folyamatban aláíratlan maradt. Ezért egy exchange UTÁNI küldésnek is 'signed'-nek kell lennie (mutáns-érzékeny).
        ab.send("hub", "remote1", "post-exchange", db=db, mirror=False)
        after = ab.recv("remote1", mark=False, db=db)
        if not after:
            raise RuntimeError("az exchange UTÁNI küldést a termék-mód ELDOBTA (aláíratlan) — az exchange folyamat-"
                               "állapotot rontott (AGENT_BUS_AUTO_SIGN globálisan kikapcsolva)")
        last = after[-1]
        if ab.verify_sender(last) != "signed":
            raise RuntimeError("egy exchange UTÁNI küldés nem 'signed' (%s) — az exchange folyamat-állapotot rontott"
                               % ab.verify_sender(last))
    exp = bn.export(log, 1)
    c = ab._conn(db)
    try:
        rows = [dict(x) for x in c.execute(
            "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
            "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
    finally:
        c.close()
    receipts = [{"phase": "request", "sent": [], "ack": top, "received": r1["replies"], "round": "r1"},
                {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
    return bn, exp, rows, receipts


def sweep(t, probe_mode) -> int:
    """A teljes söprés EGY módban (dev | product). rc=0 zöld, rc=1 néma/traceback."""
    with contextlib.nullcontext():
        bn, exp, rows, receipts = build_round(t, probe_mode)

        def run(entries):
            try:
                rep = bn.reconcile(copy.deepcopy(entries), "remote1", copy.deepcopy(receipts),
                                   strict=True, bus_audit=copy.deepcopy(rows))
                return rep["ok"]
            except Exception as e:                      # a traceback maga a lelet
                return "CRASH:%s" % e.__class__.__name__

        if run(exp) is not True:
            print("sweep_log_probe: az ÉRINTETLEN export nem zöld — a szonda nem tud mérni")
            return 1
        # MINDEN sortípus, nem csak az `entry`: a `checkpoint` hordozza a közjegyző ALÁÍRÁSÁT, és eddig
        # semmilyen alak-kapu nem futott rá. A söprés ezért típusonként megy végig a mezőkön.
        keys_by_type = {}
        for e in exp:
            ty = e.get("type")
            if ty:
                keys_by_type.setdefault(ty, set()).update(e)
        if "checkpoint" not in keys_by_type:
            print("sweep_log_probe: a korpuszban NINCS checkpoint sor — a szonda az aláírt sort nem méri")
            return 1
        # a `claimed_ts_ms` a legtöbb bejegyzésen VALÓBAN None: a `null` ott nem változtat semmit
        noop = {("entry", "claimed_ts_ms", "null"),   # (sortípus, mező, MÓD) — a lista-érték nem lehet kulcs
                ("entry", "type", "str"), ("checkpoint", "type", "str")}   # a `type` átírása MÁS sortípus
        silent, crashed, n = [], [], 0
        for ty in sorted(keys_by_type):
          for k in sorted(keys_by_type[ty]):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(exp), 0
                for e in ents:
                    if e.get("type") != ty or k not in e:
                        continue
                    if mode == "delete":
                        e.pop(k)
                        touched += 1
                    elif e[k] != val:
                        e[k] = val
                        touched += 1
                if not touched or (ty, k, mode) in noop:
                    continue
                n += 1
                res = run(ents)
                if res is True:
                    silent.append((ty, k, mode, touched))
                elif isinstance(res, str):
                    crashed.append((ty, k, mode, res))
        print("sweep_log_probe: %d tamper | silent=%d crash=%d" % (n, len(silent), len(crashed)))
        for ty, k, mode, c in silent[:10]:
            print("  - SILENT: %s.%s mode=%s (%d sor) — the report stayed green" % (ty, k, mode, c))
        for ty, k, mode, e in crashed[:10]:
            print("  - CRASH:  %s.%s mode=%s -> %s — a traceback is not a diagnosis" % (ty, k, mode, e))
        if silent or crashed:
            return 1
        # ── 2. fázis: a `cursor` ALMEZŐI, a KONZISZTENS ÍRÓ modelljében ────────────────────────────────
        # MEDIUM (a)+(b): a fenti söprés a bejegyzés TOP-LEVEL mezőire megy, és a
        # diagnózist sokszor a hash-guard adja — aki viszont a naplót ÍRJA, a láncot is maga számolja.
        import bus_notary as _bn

        def _rechain(ents):
            prev, seq = "0" * 64, 0
            for e in ents:
                if e.get("type") != "entry":
                    continue
                seq += 1
                e["seq"], e["prev_hash"] = seq, prev
                e["entry_hash"] = _bn.entry_hash({k: v for k, v in e.items()
                                                  if k not in ("type", "entry_hash")})
                prev = e["entry_hash"]
            return ents

        subs = set()
        for e in exp:
            if e.get("type") == "entry" and isinstance(e.get("cursor"), dict):
                subs |= set(e["cursor"])
        # KÉT szeletet mérünk, mert a különbségük MAGA a lelet:
        #   (a) TELJES export — van benne ALÁÍRT ellenőrzőpont: az író újraláncolhat, de újra ALÁÍRNI nem tud;
        #   (b) ALÁÍRÁS NÉLKÜLI szelet (a checkpoint sorokat kivéve) — ez az egyik kar korpusza, és itt látszik,
        #       mi az, amit VALÓBAN olvas valaki, és mi az, ami csak az aláírástól volt kötve.
        # Ha csak (a)-t mérnénk, a kimondott lista sosem szólalna meg — épp a veszélyes esetet hagynánk ki.
        slices = [("aláírt ellenőrzőponttal", list(exp)),
                  ("ALÁÍRÁS NÉLKÜLI szelet", [e for e in exp if e.get("type") != "checkpoint"])]
        for _label, _base in slices:
          if run(_rechain(copy.deepcopy(_base))) is not True:
            print("sweep_log_probe: az ÚJRALÁNCOLT, érintetlen %s nem zöld — a 2. fázis nem tud mérni" % _label)
            return 1
        c_silent, c_crash, c_n = [], [], 0
        _base = slices[1][1]                     # a mérés az ALÁÍRÁS NÉLKÜLI szeleten dönt (a szigorúbb eset)
        for k in sorted(subs):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(_base), 0
                for e in ents:
                    cur = e.get("cursor")
                    if e.get("type") != "entry" or not isinstance(cur, dict) or k not in cur:
                        continue
                    if mode == "delete":
                        cur.pop(k)
                        touched += 1
                    elif cur[k] != val:
                        cur[k] = val
                        touched += 1
                if not touched:
                    continue
                c_n += 1
                res = run(_rechain(ents))
                if res is True:
                    c_silent.append((k, mode))
                elif isinstance(res, str):
                    c_crash.append((k, mode, res))
        undeclared = sorted({k for k, _ in c_silent} - set(CURSOR_UNCHECKED))
        # …és ugyanez a söprés az ALÁÍRT szeleten: itt 0 némát várunk, mert a checkpointot nem lehet újra aláírni
        s_silent, s_n = [], 0
        for k in sorted(subs):
            for mode, val in (("delete", None), ("null", None), ("zero", 0), ("str", "X"), ("empty", [])):
                ents, touched = copy.deepcopy(exp), 0
                for e in ents:
                    cur = e.get("cursor")
                    if e.get("type") != "entry" or not isinstance(cur, dict) or k not in cur:
                        continue
                    if mode == "delete":
                        cur.pop(k)
                        touched += 1
                    elif cur[k] != val:
                        cur[k] = val
                        touched += 1
                if not touched:
                    continue
                s_n += 1
                if run(_rechain(ents)) is True:
                    s_silent.append((k, mode))
        print("sweep_log_probe/cursor (konzisztens író):")
        print("   ALÁÍRT ellenőrzőponttal:  %d hamisítás | néma=%d   <- a fedezet az ALÁÍRÁS, nem az ellenőrzés"
              % (s_n, len(s_silent)))
        print("   ALÁÍRÁS NÉLKÜLI szeleten: %d hamisítás | néma=%d (%d mező) crash=%d"
              % (c_n, len(c_silent), len({k for k, _ in c_silent}), len(c_crash)))
        if s_silent:
            for k, mode in s_silent[:8]:
                print("  - SILENT: cursor.%s mode=%s ALÁÍRT szeleten — az aláírás sem köti" % (k, mode))
            return 1
        for k, mode, e in c_crash[:8]:
            print("  - CRASH:  cursor.%s mode=%s -> %s — a traceback is not a diagnosis" % (k, mode, e))
        for k in undeclared:
            print("  - SILENT: cursor.%s — NINCS a kimondott (nem ellenőrzött) listán" % k)
        if undeclared or c_crash:
            return 1
        for k in sorted({k for k, _ in c_silent}):
            print("      nem ellenőrzött (kimondva): cursor.%-16s %s" % (k, CURSOR_UNCHECKED[k]))
        print("PASS (mode=%s) — no notary entry field can be dropped or mistyped without a diagnosis, and every "
              "silent cursor sub-field is DECLARED as unchecked (not hidden)." % probe_mode)
        return 0


MODES = ("dev", "product")


def main(argv=None) -> int:
    """a verdikt csak a MÉRT módokra áll. Mindkét mód fut; ha egy kör fel sem épül, az PIROS és kimondott
    (nem traceback, nem csendes 'csak dev'). Az 'ALL PASS' csak akkor, ha dev ÉS product is zöld."""
    rc = 0
    with tempfile.TemporaryDirectory() as t:
        for mode in MODES:
            print("=== sweep_log_probe: mode=%s ===" % mode)
            try:
                r = sweep(t, mode)
            except Exception as e:                      # a kör felépülése maga is mérés: a bukása lelet, nem traceback
                print("sweep_log_probe: a(z) %s módú kör NEM ÉPÜLT FEL (%s: %s) — a verdikt ezt a módot NEM fedi"
                      % (mode, e.__class__.__name__, e))
                r = 1
            rc = max(rc, r)
    if rc == 0:
        print("ALL PASS — measured in BOTH modes: %s" % ", ".join(MODES))
    else:
        print("FAIL — at least one mode is red or unmeasured (see above); the verdict covers only the green modes")
    return rc


if __name__ == "__main__":
    sys.exit(main())
