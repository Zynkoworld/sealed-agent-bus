"""(2026-09-16, ) — a per-kör kvantor SORREND-ÉRZÉKENY.

A 9. körben mért BLOCKER javítása (`b66bac3`) a kihagyást ahhoz a körhöz rendeli, amelyiknek az ACK-je hozta
a `skipped_undelivered > 0`-t; a kört az ack ELŐTTI UTOLSÓ `pickup` adja (`_cand[-1]`). Ez a szonda azt méri,
mi történik, ha a támadó az önmagában BECSÜLETES extra kör-bejegyzést nem az ack UTÁN, hanem a hazug kör és a
SAJÁT ack-je KÖZÉ írja.

A fixtúra az ő `test_joint_pledge_optout_20260916.py::SkippedContradictionQuantifier` harness-e, egyetlen
változtatással: az extra bejegyzés helye.
"""
import os, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab            # noqa: E402
import bus_notary as bn           # noqa: E402
import bus_ssh_exchange as ex     # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class SkipAccusationIsOrderSensitive(unittest.TestCase):
    N_MAIL, N_GIVEN = 6, 2

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log, self.db = os.path.join(t, "notary.jsonl"), os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        import unittest.mock as mock
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_WAKE_STATE_DIR": os.path.join(t, "wstate"),
            "AGENT_BUS_NOTARY_LOG": self.log, "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"),
            "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def report(self, extra_round=None, where="after", strict=True):
        """6 üzenetből 2 megy ki, a kurzor 6-ra ugrik → 4 VÉGLEGESEN elvész; a kör hazudik, és le van zárva."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, self.N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[self.N_MAIL - self.N_GIVEN:]
        cur = ab.cursor_of("peer", db=self.db)
        given = {x["id"] for x in out}
        e1 = rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
                 kind="pickup", decision="accepted", reason="cursor=%d" % cur,
                 cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})   # HAZUG
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"],
                cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(given)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        extra_seq = None
        if extra_round is not None and where == "before":
            e2 = rec(envelope={"identity": "peer", "cursor": cur, "note": "round-extra"}, kind="pickup",
                     decision="accepted", reason="extra", cursor=extra_round)
            extra_seq = e2["seq"]
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d" % (base, tgt), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        rec(envelope={"identity": "peer", "round_close": 1, "cursor": ab.cursor_of("peer", db=self.db)},
            kind="round_close", decision="accepted", reason="zarva", cursor={"round_seq": e1["seq"]})
        if extra_seq is not None:
            rec(envelope={"identity": "peer", "round_close": 1, "cursor": ab.cursor_of("peer", db=self.db)},
                kind="round_close", decision="accepted", reason="zarva-extra", cursor={"round_seq": extra_seq})
        if extra_round is not None and where == "after":
            e2 = rec(envelope={"identity": "peer", "cursor": tgt, "note": "round2"}, kind="pickup",
                     decision="accepted", reason="round2", cursor=extra_round)
            rec(envelope={"identity": "peer", "round_close": 1, "cursor": ab.cursor_of("peer", db=self.db)},
                kind="round_close", decision="accepted", reason="zarva2", cursor={"round_seq": e2["seq"]})
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = bn.export(self.log, 1)
        audit = ab.audit_export("peer", db=self.db)
        r = bn.reconcile(exp, "peer", receipts, strict=strict, bus_audit=audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "notes": sorted({str(x.get("type")) for x in (r.get("notes") or [])}),
                "trusted": bn.verify(exp, trusted_pub=self.pub).get("trusted"),
                "skipped": sum(int(a.get("skipped_undelivered") or 0) for a in audit),
                "still_reachable": [m["id"] for m in ab.recv("peer", mark=False, limit=99, db=self.db)]}

    HONEST = {"at": 6, "pending": 1, "replies": 0, "next_id": 1}
    NO_PENDING = {"at": 0, "replies": 0, "next_id": 1}        # a `pending` KIMARAD — ez az egyetlen lépés

    # ── kontroll: a hazug kör egyedül lelepleződik, és a kár valódi ─────────────
    def test_control_the_lie_alone_is_caught(self):
        r = self.report(None)
        self.assertEqual(r["skipped"], self.N_MAIL - self.N_GIVEN, "a busz audit-sora tudja, hány posta veszett el")
        self.assertEqual(r["still_reachable"], [], "a posta tényleg elfogyott")
        self.assertIn("audit_skipped_contradicts_log", r["hard"], "a kontroll-vád nem jött ki: %r" % r)

    # ── kontroll: az extra kör az ack UTÁN — a `b66bac3` javítása megtartja a vádat ─
    def test_control_the_extra_round_after_the_ack_keeps_the_accusation(self):
        r = self.report(self.HONEST, where="after")
        self.assertIn("audit_skipped_contradicts_log", r["hard"],
                      "a per-kör kvantor kontrollja megbukott: %r" % r)

    # ── kontroll (CÁFOLT megkerülés): `pending`-gel ELŐTTE a MÁSIK réteg fogja meg ─
    def test_control_an_extra_round_with_pending_is_caught_by_the_other_layer(self):
        r = self.report({"at": 0, "pending": 1, "replies": 0, "next_id": 1}, where="before")
        self.assertIn("cursor_skips_undelivered", r["hard"],
                      "a napló-belső réteg sem fogta meg: %r" % r)

    # ── LELET: a `pending` KIHAGYÁSA + a HELY kioltja a kemény vádat ────────────
    def test_a_pending_less_round_before_the_ack_must_not_erase_the_accusation(self):
        r = self.report(self.NO_PENDING, where="before")
        self.assertIn("audit_skipped_contradicts_log", r["hard"],
                      "egyetlen `pending` NÉLKÜLI kör-bejegyzés a hazug kör és a SAJÁT ack-je KÖZÉ írva "
                      "kioltotta az EGYETLEN kemény bizonyítékot: hard=%r soft=%r trusted=%s — közben %d "
                      "üzenet véglegesen elveszett, és a busz hash-láncolt audit-sora ezt tudja"
                      % (r["hard"], r["soft"], r["trusted"], r["skipped"]))

    # ── LELET (a súlyosabb fele): dev-módban ZÖLD bizonyítvány ─────────────────
    def test_the_same_log_must_not_be_green_without_strict(self):
        r = self.report(self.NO_PENDING, where="before", strict=False)
        self.assertFalse(r["ok"],
                         "a napló strict nélkül (a CLI ALAPÉRTELMEZÉSE dev-módban) ZÖLD: ok=True, hard=[], "
                         "soft=%r — négy elveszett üzenet fölött" % r["soft"])


if __name__ == "__main__":
    unittest.main()
