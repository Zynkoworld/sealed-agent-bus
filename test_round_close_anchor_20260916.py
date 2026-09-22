"""A kör ZÁRÓ horgonya — a támadási mátrix 2.7-es NYITOTT sora.

A nyitott sor szövege volt: „egykörös szeleten a második nyilvántartás következetes újraláncolása — a horgony
a kör ELEJÉN íródik, a saját köre ack-sorát nem köti."

Mérve: a kör NYITÓ horgonya a busz audit-láncának AKKORI fejére köt. A kör SAJÁT sorai (a `mark_delivered`
és az `ack` audit-sorai) ez UTÁN keletkeznek — tehát egy egykörös exportot a támadó a horgony fölött
következetesen újraláncolhatott (a lánc belsőleg ép marad, a horgony a szelet ELEJÉT köti, nem a végét).

A javítás: a kör VÉGÉN, minden mellékhatás után egy `round_close` bejegyzés, amibe a horgonyt — a nyitó
horgony mintájára — a KÖZJEGYZŐ számolja bele (`audit_end_seq` + `audit_end_hash`), nem az író fél. A nyitó
bejegyzés `closes: 1`-gyel VÁLLALJA a zárást; a vállalás a hash-láncolt bejegyzésben utazik, tehát a záró
horgony utólagos levágása bizonyíték (`audit_close_missing`), a régi, vállalás nélküli körök pedig
változatlanul zöldek (nincs visszamenőleges pirosítás).

KIMONDOTT korlát: a záró írás fail-OPEN (a posta ekkor már kiment, fail-closed nem lehet) — a hibát a válasz
`round_close: "failed"` mezője és a reconcile `audit_close_missing` eltérése mondja ki. A teljes zárás
továbbra is külső tanú (v1.7, az üzemeltető döntése).

stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab            # noqa: E402
import bus_notary as bn           # noqa: E402
import bus_ssh_exchange as ex     # noqa: E402


class RoundCloseAnchor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.log = os.path.join(t, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50, db=self.db)
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── a kör: két üzenet kiadva, majd ack ──────────────────────────────────
    def round_trip(self):
        for i in range(2):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        res = ex.exchange("remote1", json.dumps({}), db=self.db,
                          attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        top = max(m["id"] for m in res["replies"])
        ex.exchange("remote1", json.dumps({"ack": top}), db=self.db,
                    attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        return res, top

    def audit_rows(self):
        c = ab._conn(self.db)
        try:
            return [dict(r) for r in c.execute(
                "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
                "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
        finally:
            c.close()

    def rechain(self, rows, *, drop_last=True):
        """A támadó KÖVETKEZETESEN újraláncol: a kör saját (utolsó) sorát elhagyja, és a maradékot úgy számolja
        újra, hogy a lánc belsőleg ép maradjon. Ez a 2.7-es sor pontos alakja."""
        keep = rows[:-1] if drop_last else list(rows)
        out, prev = [], ab._GENESIS
        for r in keep:
            n = dict(r, prev_row_hash=prev)
            n["row_hash"] = ab._audit_row_hash(n["seq"], n["ts"], n["agent"], n["op"], n["from_id"],
                                               n["to_id"], n["skipped_undelivered"], prev)
            prev = n["row_hash"]
            out.append(n)
        return out

    def reconcile(self, bus_audit, entries=None):
        res, top = getattr(self, "_rt", (None, None))
        receipts = [{"phase": "request", "sent": [], "ack": top, "received": res["replies"], "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = entries if entries is not None else bn.export(self.log, 1)
        return bn.reconcile(exp, "remote1", receipts, strict=True, bus_audit=bus_audit)

    # ── kontroll: a becsületes kör a záró horgonnyal is zöld ─────────────────
    def test_control_honest_round_with_close_is_green(self):
        self._rt = self.round_trip()
        r = self.reconcile(self.audit_rows())
        self.assertTrue(r["ok"], "a becsületes kör nem zöld: %r / %r" % (r["discrepancies"], r["unresolved"]))

    # ── a záró horgony TÉNYLEG megvan, és a közjegyző írta bele ──────────────
    def test_close_entry_carries_a_notary_computed_anchor(self):
        self._rt = self.round_trip()
        ents = [e for e in bn.read_lines(self.log) if e.get("type") == "entry"]
        closes = [e for e in ents if e["kind"] == "round_close"]
        self.assertTrue(closes, "nincs kör-záró bejegyzés")
        c = closes[-1]["cursor"]
        self.assertIn("audit_end_seq", c)
        self.assertRegex(str(c.get("audit_end_hash")), r"^[0-9a-f]{64}$")
        rows = self.audit_rows()
        self.assertEqual(c["audit_end_seq"], rows[-1]["seq"] if rows else 0,
                         "a záró horgony nem a kör UTÁNI láncfejre mutat")
        opens = [e for e in ents if e["kind"] == "pickup" and e["decision"] == "accepted"]
        self.assertEqual(opens[0]["cursor"].get("closes"), 1, "a nyitó bejegyzés nem VÁLLALTA a zárást")
        # a záró bejegyzés a kör MINDEN mellékhatása után áll
        self.assertGreater(closes[0]["seq"], max(e["seq"] for e in ents if e["kind"] == "pickup"
                                                 and e["decision"] == "delivered"))

    # ── A LELET: az egykörös szelet következetes újraláncolása ───────────────
    def test_consistently_rechained_single_round_slice_is_caught(self):
        # FONTOS: EGYETLEN kör. A kétkörös változatot már a KÖVETKEZŐ kör nyitó horgonya is megfogja — az volt
        # a mátrixban a részleges enyhítés. A 2.7-es sor pont az egykörös szeletről szólt, ahol a nyitó horgony
        # a kör ELEJÉT köti, és a kör saját sorai után nincs semmi. Itt csak a ZÁRÓ horgony maradhat tanú.
        for i in range(2):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        res = ex.exchange("remote1", json.dumps({}), db=self.db,
                          attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        self._rt = (res, max(m["id"] for m in res["replies"]))
        rows = self.audit_rows()
        self.assertGreaterEqual(len(rows), 2, "előfeltétel: a körnek van saját audit-sora")
        faked = self.rechain(rows)                     # a kör SAJÁT sora eltüntetve, a lánc belsőleg ép
        chk = ab.audit_chain_verify(faked)
        self.assertTrue(chk["ok"], "előfeltétel: a hamisított lánc BELSŐLEG ép (különben nem ez a lelet)")
        r = self.reconcile(faked)
        self.assertFalse(r["ok"], "a következetesen újraláncolt egykörös szelet zöldet kapott")
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertTrue({"audit_close_not_covered", "audit_close_hash_mismatch"} & types,
                        "nem a ZÁRÓ horgony fogta meg, hanem valami más: %r" % sorted(types))

    # ── a záró bejegyzés levágása: a VÁLLALÁS miatt bizonyíték ───────────────
    def test_stripping_the_close_entry_is_evidence(self):
        self._rt = self.round_trip()
        ents = [e for e in bn.export(self.log, 1) if not (e.get("type") == "entry" and e.get("kind") == "round_close")]
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertIn("audit_close_missing", types,
                      "a vállalt, mégis hiányzó zárás némán átment: %r" % sorted(types))
        self.assertFalse(r["ok"])

    # ── a nem-Claude kar köre EZEN a javításon  ──────────
    def test_close_anchor_may_not_point_at_an_older_head(self):
        """(1) Ha a zárás a mellékhatások ELŐTT íródna, a horgony a kör ELŐTTI láncfejre mutatna — a kör saját
        sorai megint kötetlenek lennének. A horgony MONOTON: a kör végi fej nem lehet a kör eleji előtt."""
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if (e.get("type") == "entry" and e.get("kind") == "round_close"
                    and isinstance(e.get("cursor"), dict) and e["cursor"].get("audit_end_seq", 0) > 0):
                e = dict(e, cursor=dict(e["cursor"], audit_end_seq=0))     # „a kör ELEJI fej"
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]}
        self.assertIn("audit_close_before_open", types,
                      "a kör ELEJÉRE mutató záró horgony átment: %r" % sorted(types))

    def test_a_close_that_names_another_round_does_not_count(self):
        """(2) A sorrend csak visszatartó; a zárás MEGNEVEZI a körét. Egy máshová tartozó zárás nem tehet
        egy záratlan kört lezárttá."""
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if (e.get("type") == "entry" and e.get("kind") == "round_close"
                    and isinstance(e.get("cursor"), dict) and "round_seq" in e["cursor"]):
                e = dict(e, cursor=dict(e["cursor"], round_seq=e["cursor"]["round_seq"] + 100))
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {u["type"] for u in r["unresolved"]}
        self.assertIn("audit_close_missing", types,
                      "egy MÁSIK kört megnevező zárás lezártnak mutatta ezt a kört: %r" % sorted(types))

    def test_unclosed_rounds_are_counted_not_just_soft(self):
        """(3) „Minden kör záratlan" nem tűnhet el a soft-zajban: a jelentés SZÁMOT ad róla."""
        self._rt = self.round_trip()
        ok = self.reconcile(self.audit_rows())
        self.assertGreaterEqual(ok["counts"]["rounds_pledged"], 1)
        self.assertEqual(ok["counts"]["rounds_unclosed"], 0, "a becsületes körök záratlannak számítottak")
        ents = [e for e in bn.export(self.log, 1)
                if not (e.get("type") == "entry" and e.get("kind") == "round_close")]
        bad = self.reconcile(self.audit_rows(), entries=ents)
        self.assertEqual(bad["counts"]["rounds_unclosed"], bad["counts"]["rounds_pledged"],
                         "a záratlan körök száma nem mérhető a jelentésből")

    # ── a RÉGI, zárást nem vállaló kör nem lesz visszamenőleg piros ──────────
    def test_old_round_without_the_pledge_is_not_accused(self):
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if e.get("type") == "entry" and e.get("kind") == "round_close":
                continue                                # a régi verzió nem írt zárást…
            if (e.get("type") == "entry" and e.get("kind") == "pickup" and e.get("decision") == "accepted"
                    and isinstance(e.get("cursor"), dict)):
                e = dict(e, cursor={k: v for k, v in e["cursor"].items() if k != "closes"})   # …és nem is vállalta
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertNotIn("audit_close_missing", types, "a régi körre is számon kértük a zárást")


if __name__ == "__main__":
    unittest.main()
