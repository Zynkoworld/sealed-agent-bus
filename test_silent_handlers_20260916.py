"""A NÉMA kivétel-ágak rendszeres felmérése — saját kör.

A capsule2-oldalon a B-kar háromszor mondta ki ugyanazt az osztályt: *a mérés HIÁNYA harmadik állapot, nem
zöld*. Ugyanez a busz-oldalon egy `except …: pass` alakjában él. Nem vártuk meg, hogy megtalálják: AST-vel
végigmértük mind a 28 néma ágat, és megnéztük, melyik ül BIZONYÍTÉK-hordozó úton.

Három javítva:

  1. `bus_notary._audit_cross` — a busz audit-láncának ÖNELLENŐRZÉSE `except Exception: pass`-ban ült. Ha a
     lánc-verifikáló bármiért dob (hiányzó mező, rossz típus a MÁSIK fél exportjában), a `audit_chain_broken`
     eltérés NÉMÁN eltűnt, és a jelentés zöld maradt. Innentől `audit_chain_unverifiable` (soft) — a mérés
     hiánya látszik.
  2. `agent_duty._notify` — a riasztás-hook hibája elnyelte a riasztást. Innentől stderr-re kiírja, hogy a
     riasztás NEM ment ki.
  3. `agent_bus.replay_lifeboat` — a végleges elutasítás szűrője `pass`-szal bukott, tehát a VÉGLEGESEN
     elutasított sor is visszakerülhetett a mentőcsónakba, csendben. Innentől a válasz `warning` mezője
     kimondja, hogy a szűrés nem futott.

A többi néma ág mérten ártalmatlan (`FileExistsError` mkdir-nél, `BrokenPipeError` lezárt SSE-nél stb.) — a
teszt ezért NEM tiltja az összeset, hanem a hármat köti, plusz kimondja a felmérés tényét.

stdlib unittest.
"""
import ast
import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad     # noqa: E402
import bus_notary as bn     # noqa: E402


class ChainSelfCheckIsNotSilent(unittest.TestCase):
    def test_a_throwing_chain_verify_becomes_a_discrepancy(self):
        """Ha a lánc-önellenőrzés dob, az a jelentésben LÁTSZIK (nem tűnik el)."""
        rows = [{"seq": 0, "agent": "peer", "op": "ack", "from_id": 0, "to_id": 1,
                 "skipped_undelivered": 0, "prev_row_hash": "0" * 64, "row_hash": "a" * 64, "ts": 1}]
        entries = [{"type": "entry", "seq": 1, "recipient": "peer", "kind": "pickup", "decision": "accepted",
                    "cursor": {"at": 0, "pending": 0, "replies": 0, "next_id": 0}}]
        with mock.patch("agent_bus.audit_chain_verify", side_effect=RuntimeError("boom")):
            out = bn._audit_cross(entries, "peer", rows)
        types = {d["type"] for d in out}
        self.assertIn("audit_chain_unverifiable", types,
                      "a dobó lánc-ellenőrzés némán eltűnt: %r" % sorted(types))
        self.assertTrue(all(d.get("soft") for d in out if d["type"] == "audit_chain_unverifiable"),
                        "ez HARMADIK ÁLLAPOT (nem vád): soft")

    def test_control_a_working_chain_verify_still_reports_breakage(self):
        rows = [{"seq": 5, "agent": "peer", "op": "ack", "from_id": 0, "to_id": 1,
                 "skipped_undelivered": 0, "prev_row_hash": "0" * 64, "row_hash": "a" * 64, "ts": 1}]
        entries = [{"type": "entry", "seq": 1, "recipient": "peer", "kind": "pickup", "decision": "accepted",
                    "cursor": {"at": 0, "pending": 0, "replies": 0, "next_id": 0}}]
        out = bn._audit_cross(entries, "peer", rows)
        self.assertIn("audit_chain_broken", {d["type"] for d in out})


class DutyNotifyFailureIsLoud(unittest.TestCase):
    def test_a_failing_notify_hook_is_named(self):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"AGENT_DUTY_NOTIFY": "nincs_ilyen_modul:fn"}, clear=False), \
                redirect_stderr(buf):
            ad._notify("ügyeleti riasztás")
        self.assertIn("NEM ment ki", buf.getvalue(),
                      "a riasztás elveszett, és ez néma maradt: %r" % buf.getvalue())


class TheSweepItself(unittest.TestCase):
    def test_no_new_silent_handler_on_the_evidence_paths(self):
        """A bizonyíték-hordozó modulokban ne jelenjen meg ÚJ, csupasz `except: pass`."""
        # (mérve): a keret HÁROM modulra szólt, és épp a napló MÁSIK határpontja
        # (`bus_ssh_exchange.py`) maradt ki — ott ült a menekülő ajtó néma ága. A keret ezért bővül.
        watched = {"bus_notary.py": 3, "agent_bus.py": 3, "bus_enforce.py": 1, "bus_ssh_exchange.py": 0,
                   "bus_singleflight.py": 4, "agent_duty.py": 0}
        for fname, budget in watched.items():
            path = os.path.join(HERE, fname)
            if not os.path.exists(path):
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            silent = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                      and all(isinstance(st, ast.Pass) for st in n.body)]
            self.assertLessEqual(len(silent), budget,
                                 "%s: %d néma except-ág (keret: %d) — soronként: %s"
                                 % (fname, len(silent), budget, silent))


class EveryVerdictHasACaller(unittest.TestCase):
    """egy verdikt, amit senki nem kérdez meg, nem jelzés.

    Az ő leletének magja az volt, hogy a `state_dir_warnings()` a saját unit-tesztjén kívül SEHOL nem futott,
    tehát a mátrix „jelzett" minősítése nem volt mérhető. A szabály általánosítva: minden VERDIKT-jellegű
    publikus függvénynek (warn/check/verify/audit/state/doctor/status/guard nevűek) legyen legalább egy
    TERMELÉSI hívója — a teszt-hívás nem számít, mert a tesztet mi írjuk.
    """

    def test_no_orphan_verdict_function(self):
        import collections
        defs, calls = {}, collections.Counter()
        trees = {}
        for f in sorted(os.listdir(HERE)):
            if not f.endswith(".py") or f.startswith("test_"):
                continue
            try:
                trees[f] = ast.parse(open(os.path.join(HERE, f), encoding="utf-8").read())
            except SyntaxError:
                continue
        for f, t in trees.items():
            for n in t.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"):
                    defs[(f, n.name)] = n.lineno
            for n in ast.walk(t):
                if isinstance(n, ast.Call):
                    nm = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                    if nm:
                        calls[nm] += 1
        verdictish = ("warn", "check", "verify", "audit", "doctor", "status", "guard", "health")
        orphans = ["%s:%s (%d. sor)" % (f, nm, ln) for (f, nm), ln in sorted(defs.items())
                   if any(v in nm.lower() for v in verdictish) and calls[nm] == 0]
        self.assertEqual(orphans, [],
                         "verdikt termelési hívó nélkül — a jelzés senkihez nem jut el: %s" % orphans)


if __name__ == "__main__":
    unittest.main()
