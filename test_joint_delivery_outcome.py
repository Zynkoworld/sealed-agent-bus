"""(2026-09-16, ) — a `cursor_skips_undelivered` clamp HAZUG (nem hiányzó) mezővel.

Az `e8d9370` a KIHAGYÁST lezárta (`round_pending_unknown` / `round_next_id_contradicts_pending`). A doksi
kimondott korlátja a HAZUG értékre szól: „a busz saját, hash-láncolt `cursor_audit` sorával kerül
ellentmondásba". Ez a szonda megméri, MENNYIBE kerül a hazugság, és hogy a megnevezett ellenréteg
elérhető-e a SÉRTETTNEK.

Mind a három sorban ugyanaz a kár: 6 üzenetből csak az id 5,6 megy ki, a kurzor 0->6, az 1..4 véglegesen
elfogy. A különbség csak a kör-bejegyzés EGYETLEN száma.
stdlib unittest + cryptography. Hálózat nincs, minden út /tmp alá.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402

N_MAIL, N_GIVEN = 6, 2


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ClampLiedFields(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def report(self, lie=None):
        """A VALÓDI kiadási út (bus_ssh_exchange.py:161-196) — csak a kör-bejegyzés EGY száma hazudik."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        self.assertEqual(len(allr), N_MAIL)
        out = allr[N_MAIL - N_GIVEN:]                       # a vádlott csak a LEGFELSŐ kettőt adja ki
        cur = ab.cursor_of("peer", db=self.db)
        given = {x["id"] for x in out}
        left = [x["id"] for x in allr if x["id"] not in given]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if lie == "next_id_up":                             # „az első kiadatlan a kiadottak FÖLÖTT van"
            c["next_id"] = max(given) + 1
        if lie == "pending_down":                           # „nem is maradt kiadatlan"
            c["pending"], c["next_id"] = len(out), 0
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)), cursor=c)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(given)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = bn.export(self.log, 1)
        r = bn.reconcile(exp, "peer", receipts, strict=True)     # strict = termék-mód szigora
        v = bn.verify(exp, trusted_pub=self.pub)
        cc = ab._conn(self.db)
        try:
            aud = [(a["op"], a["skipped_undelivered"]) for a in cc.execute(
                "SELECT op, skipped_undelivered FROM cursor_audit WHERE agent='peer' ORDER BY id")]
        finally:
            cc.close()
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}), "trusted": v["trusted"],
                "still_reachable": [m["id"] for m in ab.recv("peer", mark=False, limit=99, db=self.db)],
                "bus_audit": aud}

    # ── kontroll: a clamp ÉL, a becsületes csonkolt kör lelepleződik ──────────
    def test_control_honest_truncated_round_is_caught(self):
        r = self.report(None)
        self.assertIn("cursor_skips_undelivered", r["hard"])
        self.assertFalse(r["ok"])

    # ── kontroll: a busz MINDHÁROM esetben pontosan tudja az igazságot ────────
    def test_control_bus_measures_the_truth_in_all_three(self):
        for lie in (None, "next_id_up", "pending_down"):
            with self.subTest(lie=lie):
                r = self.report(lie)
                self.assertIn(("ack", N_MAIL - N_GIVEN), r["bus_audit"],
                              "a busz cursor_audit sora tudja, hogy 4 üzenet elveszett")
                self.assertEqual(r["still_reachable"], [], "a posta mindhárom esetben elfogy")
            self.tearDown()
            self.setUp()

    # ── LELET: egyetlen hazug szám betűre becsületessé teszi a jelentést ──────
    def test_lied_next_id_must_not_defeat_the_clamp(self):
        r = self.report("next_id_up")
        self.assertTrue(r["hard"] or r["soft"],
                        "hazug next_id: a jelentés ok=%s, hard=[], soft=[] — 4 üzenet nyomtalanul elveszett" % r["ok"])

    def test_lied_pending_must_not_defeat_the_clamp(self):
        r = self.report("pending_down")
        self.assertTrue(r["hard"] or r["soft"],
                        "hazug pending: a jelentés ok=%s, hard=[], soft=[] — 4 üzenet nyomtalanul elveszett" % r["ok"])


if __name__ == "__main__":
    unittest.main()
