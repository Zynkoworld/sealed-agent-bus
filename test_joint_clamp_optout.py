"""(2026-09-16, ) — az 52ad412 `cursor_skips_undelivered` clamp-jének támadása.

A BLOCKER javítása a kör-bejegyzés GÉPI mezőjére épül (`pending`, `next_id`), amit a VÁDLOTT ír.
A kimondott korlát az volt, hogy a HAZUG érték a busz saját `cursor_audit` sorával ütközik. Ez a szonda
nem a hazugságot méri, hanem a KIHAGYÁST: mit ér a clamp, ha a mező egyszerűen NINCS ott — ami a régi
formátumú (52ad412 előtti) becsületes bejegyzéstől MEGKÜLÖNBÖZTETHETETLEN.

Mind a négy változatban UGYANAZ a kár: 6 üzenetből 2 megy ki, a kurzor 0->6, az 1..4 véglegesen elvész.
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

N_MAIL = 6
N_GIVEN = 2          # a vádlott csak a LEGFELSŐ kettőt (id 5,6) adja ki — a maradék 1..4 elvész


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ClampOptOut(unittest.TestCase):
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

    def round(self, *, given=N_MAIL, drop_pending=False, drop_next_id=False, next_id_zero=False,
              no_cursor_field=False, mark_all=False):
        """A VALÓDI kiadási út (bus_ssh_exchange.py:161-192) — csak a kör-bejegyzés gépi mezője változik."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        self.assertEqual(len(allr), N_MAIL)
        out = allr[N_MAIL - given:]
        cur = ab.cursor_of("peer", db=self.db)
        given_ids = {x.get("id") for x in out}
        left = [x.get("id") for x in allr if x.get("id") not in given_ids]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if drop_pending:
            c.pop("pending")
        if drop_next_id:
            c.pop("next_id")
        if next_id_zero:
            c["next_id"] = 0
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)),
            cursor=None if no_cursor_field else c)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x.get("id"),
                cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x.get("id") for x in (allr if mark_all else out)], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        return bn.export(self.log, 1), receipts

    def report(self, **kw):
        exp, receipts = self.round(**kw)
        r = bn.reconcile(exp, "peer", receipts, strict=True)          # strict = termék-mód szigora
        v = bn.verify(exp, trusted_pub=self.pub)
        lost = [m["id"] for m in ab.recv("peer", mark=False, limit=99, db=self.db)]
        return {"ok": r["ok"], "hard": [d["type"] for d in r["discrepancies"]],
                "soft": [u["type"] for u in r["unresolved"]], "verify_ok": v["ok"], "trusted": v["trusted"],
                "local_skipped": len(ab.reconcile("peer", db=self.db)), "still_reachable": lost}

    # ── KONTROLLOK ────────────────────────────────────────────────────────────────────────
    def test_control_honest_round_is_not_accused(self):
        r = self.report(given=N_MAIL)
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["hard"], r["soft"]), ([], []), r)

    def test_control_todays_writer_catches_the_swallow(self):
        r = self.report(given=N_GIVEN)
        self.assertIn("cursor_skips_undelivered", r["hard"], r)
        self.assertFalse(r["ok"], r)

    # ── TÁMADÁSOK: a mező KIHAGYÁSA (nem hazugság) ────────────────────────────────────────
    def test_attack_drop_pending_field(self):
        r = self.report(given=N_GIVEN, drop_pending=True)
        self.assertFalse(r["ok"], "a `pending` kihagyása némán kikapcsolja a clampet: %r" % (r,))

    def test_attack_drop_next_id_field(self):
        r = self.report(given=N_GIVEN, drop_next_id=True)
        self.assertFalse(r["ok"], "a `next_id` kihagyása -> a korlát a LEGUTOLSÓ KIADOTT id, "
                                  "amit az 52ad412 commit-üzenete maga nevez elégtelennek: %r" % (r,))

    def test_attack_next_id_zero(self):
        r = self.report(given=N_GIVEN, next_id_zero=True)
        self.assertFalse(r["ok"], "a `next_id=0` (a becsületes író 'nincs kiadatlan' értéke) kikapcsolja: %r" % (r,))

    def test_attack_no_machine_cursor_at_all(self):
        r = self.report(given=N_GIVEN, no_cursor_field=True)
        self.assertFalse(r["ok"], "gépi mező nélkül (régi formátum) a clamp néma: %r" % (r,))

    # ── a kár mindegyik ágon VALÓDI ───────────────────────────────────────────────────────
    def test_the_loss_is_real_in_every_variant(self):
        for kw in ({"drop_pending": True}, {"drop_next_id": True}, {"next_id_zero": True},
                   {"no_cursor_field": True}):
            with self.subTest(**kw):
                r = self.report(given=N_GIVEN, **kw)
                self.assertEqual(r["still_reachable"], [], r)         # az 1..4 véglegesen elveszett

    # ── KONTROLL: a helyi mentőöv nem pótolja a naplót (a vak mentőövet a másik szonda méri) ──
    def test_control_local_lifeboat_does_not_cover_the_gap(self):
        """az egyik kar 2026-09-16: a kontroll ÁTÍRVA a mai viselkedésre. A `mark_delivered` high-water javítása
         óta a HELYI réteg IS lát: a kihagyott postát a `cursor_audit.skipped_undelivered`
        jelzi (itt 6). A szonda állítása („a napló önmagában néma") a `soft` listán változatlanul mérve van."""
        r = self.report(given=N_GIVEN, drop_next_id=True)
        self.assertGreater(r["local_skipped"], 0,
                           "a helyi mentőövnek látnia kell a kihagyott postát: %r" % (r,))
        self.assertIn("round_pending_unknown", r["soft"],
                      "a hiányzó next_id nem lehet néma (harmadik állapot): %r" % (r,))


if __name__ == "__main__":
    unittest.main(verbosity=2)

