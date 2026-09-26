"""CLOSING the stated limit of `ClampLiedFields`.

One arm's two `test_joint_delivery_outcome.py::ClampLiedFields` probes fail DELIBERATELY today: the
round entry's `pending`/`next_id` field is the accused's SELF-REPORT, and the notary log alone does not
refute it. We stated this limit — but we do not let it stand.

This file runs THE SAME scenario (taking over the probe's structure), with a single difference:
`reconcile` gets the bus's OWN hash-chained `cursor_audit` export (`bus_audit=`). The contradiction between the two
records is the evidence:
  - `pending_down` ("nothing undelivered remained")  -> the bus audit row records a step over 4 undelivered rows;
  - `next_id_up`  ("the first undelivered is ABOVE the ack") -> the same claim in other words.
Both are `audit_skipped_contradicts_log` (hard) — the clamp CANNOT be defeated with a single lying number
if the comparison runs.

A LIMIT this does not solve either: if the same party writes BOTH records, a simultaneous lie cannot
be ruled out — but it now has to lie in two places, and the contradiction between the two chains is evidence.

stdlib unittest. No network, every path under /tmp.
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

N_MAIL = 6          # this many messages wait
N_GIVEN = 2         # the accused delivers this many (4 would be lost)


@unittest.skipUnless(hasattr(ab, "audit_export"), "audit_export (67b050e+) required")
class ClampLieMeetsBusAudit(unittest.TestCase):
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

    def report(self, lie=None, *, cross=True, round_cursor=True, ack_target=True):
        """The real delivery path; with `cross=True` the bus audit export also goes before reconcile.

        `round_cursor=False` — the round entry has NO machine field.
        `ack_target=False`  — the ack entry's cursor field lacks `to`.
        """
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[N_MAIL - N_GIVEN:]                       # the accused delivers only the TOP two
        cur = ab.cursor_of("peer", db=self.db)
        given = {x["id"] for x in out}
        left = [x["id"] for x in allr if x["id"] not in given]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if lie == "next_id_up":
            c["next_id"] = max(given) + 1
        if lie == "pending_down":
            c["pending"], c["next_id"] = len(out), 0
        if lie == "next_id_at_ack":                         # admits the skip, but pushes it BELOW the ack TARGET
            c["next_id"] = max(given)
        kw = {"cursor": c} if round_cursor else {}
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)), **kw)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(given)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        ac = {"from": base, "to": tgt, "ack": ack_to} if ack_target else {"from": base, "ack": ack_to}
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor=ac)
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = bn.export(self.log, 1)
        audit = ab.audit_export("peer", db=self.db) if cross else None
        r = bn.reconcile(exp, "peer", receipts, strict=True, bus_audit=audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "skipped": sum(int(a.get("skipped_undelivered") or 0) for a in (audit or []))}

    # ── control: the comparison's input is intact (the bus's own chain is self-checked) ──
    def test_control_bus_audit_chain_verifies(self):
        self.report(None)
        rows = ab.audit_export("peer", db=self.db)
        self.assertTrue(ab.audit_chain_verify(rows)["ok"], "the bus audit chain passes its self-check")

    # ── control: an honest truncated round fails even WITH the comparison ────
    def test_control_honest_truncated_round_still_caught(self):
        r = self.report(None, cross=True)
        self.assertIn("cursor_skips_undelivered", r["hard"])
        self.assertFalse(r["ok"])

    # ── control: WITHOUT the comparison the lie really passes (this is the stated limit) ──
    def test_control_without_cross_check_the_lie_wins(self):
        for lie in ("pending_down", "next_id_up"):
            with self.subTest(lie=lie):
                r = self.report(lie, cross=False)
                self.assertEqual(r["hard"], [], "without the comparison the lying number launders the report")
            self.tearDown()
            self.setUp()

    # ── CLOSURE: compared with the bus's own log BOTH lies fail ──
    def test_lied_fields_are_contradicted_by_the_bus_audit(self):
        for lie in ("pending_down", "next_id_up"):
            with self.subTest(lie=lie):
                r = self.report(lie, cross=True)
                self.assertEqual(r["skipped"], N_MAIL - N_GIVEN,
                                 "precondition: the bus audit row knows how many undelivered rows the cursor stepped over")
                self.assertIn("audit_skipped_contradicts_log", r["hard"],
                              "the lying %s field did not come into contradiction with the bus's own log" % lie)
                self.assertFalse(r["ok"])
            self.tearDown()
            self.setUp()


    # ── 8: three bypass attempts against the comparison ──────
    def test_glm8_admitted_skip_below_the_ack_is_already_hard(self):
        """REFUTED finding: "admit a skip, but push next_id below the ack" — the OLD rule catches this."""
        r = self.report("next_id_at_ack", cross=True)
        self.assertIn("cursor_skips_undelivered", r["hard"],
                      "the admitted skip below the ack: the ack could have moved the cursor only up to next_id-1")
        self.assertFalse(r["ok"])

    def test_glm8_missing_cursor_field_is_not_silent(self):
        """REFUTED finding: "write no machine field" — a missing measurement is a third state, not green."""
        r = self.report(None, cross=True, round_cursor=False)
        self.assertIn("round_pending_unknown", r["soft"], "the absence of the machine field cannot fall back silently")
        self.assertFalse(r["ok"])

    def test_glm8_missing_ack_target_must_not_manufacture_a_contradiction(self):
        """REAL finding fixed: without a logged ack target (`ack_top == 0`) we must not manufacture a contradiction.

        Silence is not evidence: the `next_id > ack_top` branch may only speak if we really saw an ack target —
        otherwise every HONEST truncated round would get a false `audit_skipped_contradicts_log` accusation.
        """
        r = self.report(None, cross=True, ack_target=False)
        self.assertNotIn("audit_skipped_contradicts_log", r["hard"],
                         "without an ack target the honest round got a FALSE contradiction accusation")
        self.assertIn("cursor_skips_undelivered", r["hard"], "but the real skip is still stated")


class CliRefusesGreenWithoutTheSecondRegister(ClampLieMeetsBusAudit):
    """The limit turned into POLICY: a round is not accused just because the other record is not beside it
    (that would be a false accusation) — but in strict/product mode the CLI gives no GREEN light without it."""

    def files(self):
        """Runs an HONEST, complete round, and writes out the slice + receipts + bus-audit files."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, 3):
            ab.send("hub", "peer", "level-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        out = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        cur = ab.cursor_of("peer", db=self.db)
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)),
            cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        # The round's CLOSING anchor (attack matrix 2.7, 2026-09-16): the real writer writes it AFTER every side effect
        # — the fixture imitates this, otherwise it would model not the honest round but an interrupted one.
        rec(envelope={"identity": "peer", "round_close": 1}, kind="round_close", decision="accepted",
            reason="close replies=%d" % len(out), cursor={"at": ab.cursor_of("peer", db=self.db),
                                                          "replies": len(out)})
        t = self.tmp.name
        exp, rp, au = os.path.join(t, "exp.jsonl"), os.path.join(t, "r.jsonl"), os.path.join(t, "audit.jsonl")
        with open(exp, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 1):
                f.write(bn.json.dumps(e, ensure_ascii=False) + "\n")
        with open(rp, "w", encoding="utf-8") as f:
            for r in ({"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                      {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}):
                f.write(bn.json.dumps(r, ensure_ascii=False) + "\n")
        with open(au, "w", encoding="utf-8") as f:
            for a in ab.audit_export("peer", db=self.db):
                f.write(bn.json.dumps(a, ensure_ascii=False) + "\n")
        return exp, rp, au

    def test_strict_cli_needs_the_bus_audit(self):
        exp, rp, au = self.files()
        args = ["reconcile", exp, "--identity", "peer", "--receipts", rp, "--pub", self.pub]
        self.assertEqual(bn.main(args), 0, "in dev mode (not strict) the honest round is green")
        self.assertEqual(bn.main(args + ["--strict"]), 1,
                         "in strict mode there can be no green light WITHOUT the bus audit export (incomplete evidence)")
        self.assertEqual(bn.main(args + ["--strict", "--bus-audit", au]), 0,
                         "with the second record the honest round is green in strict mode too")


if __name__ == "__main__":
    unittest.main()
