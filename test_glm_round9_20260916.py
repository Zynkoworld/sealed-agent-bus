"""A hostile re-measurement of the partner arm's blocking fix.

The fix: the NOTARY writes the head of the bus audit chain into the round entry (`audit_seq` + `audit_hash`), and the
comparison requires the export of the SECOND RECORD to reach that far. The non-Claude arm found four ways
in which a shorter/forged export would STILL have given green:

  9/1  WRITING the anchor is fail-open (skipped on an exception) -> without an anchor there is nothing to hold to account.
       Fix: a missing anchor is a THIRD STATE (`audit_anchor_absent`, unresolved -> ok:false in strict mode).
  9/2  the library path did not run the chain self-check (only the CLI) -> an export with a seq GAP passed.
       Fix: `audit_chain_broken`.
  9/3  of the anchor we asked only for the seq, not the HASH -> the rows' content could be swapped by re-chaining.
       Fix: `audit_head_hash_mismatch` (for a genesis anchor: the export must start from row 0).
  9/4  an export passed EMPTY silently narrowed to 0 rows to examine on the library path.
       Fix: `audit_evidence_absent`.

The scenario is one arm's `test_joint_audit_anchor_20260916.py`: 2 of 6 messages go out, the round denies the
skip (`pending_down`), but the bus audit row knows the truth.

stdlib unittest + cryptography. No network, every path under /tmp.
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


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography required")
class AnchorUnderAttack(unittest.TestCase):
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
        self.out, self.ack_to = self._round()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def _round(self):
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(N_MAIL):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[len(allr) - N_GIVEN:]
        cur = ab.cursor_of("peer", db=self.db)
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)),
            cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})   # the LIE
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        return out, ack_to

    def verdict(self, bus_audit):
        receipts = [{"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=True, trusted_pub=self.pub,
                         bus_audit=bus_audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]})}

    # ── control: the full export catches the lie, and the anchor is there ──
    def test_control_full_export_contradicts_the_lie(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertIn("audit_skipped_contradicts_log", self.verdict(rows)["hard"])
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]]
        self.assertIn("audit_hash", rounds[-1]["cursor"], "the notary wrote in the chain head")

    # ── 9/4: empty export ───────────────────────────────────────────────────
    def test_empty_export_is_absent_evidence(self):
        v = self.verdict([])
        self.assertIn("audit_evidence_absent", v["hard"], "the export passed empty silently narrowed to 0 rows")
        self.assertFalse(v["ok"])

    # ── 9/2: export with a seq gap ──────────────────────────────────────────
    def test_seq_gap_export_is_caught_on_the_library_path(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertGreaterEqual(len(rows), 3, "precondition: there are at least 3 audit rows")
        gapped = [rows[0]] + rows[2:]                    # the MIDDLE row left out: the chain has a gap
        v = self.verdict(gapped)
        self.assertIn("audit_chain_broken", v["hard"], "the gapped export passed on the library path")
        self.assertFalse(v["ok"])

    # ── 9/3: re-chained, SWAPPED content — bound by a LATER round's anchor ──
    def test_rechained_content_is_caught_by_a_later_round_anchor(self):
        """The anchor is written at the START of the round, so it does not yet bind its own round's ack row — the NEXT round's does.

        MEASURED LIMIT (stated): in a SINGLE-ROUND slice, consistent re-chaining of the second record does not
        get caught — this is the same stated limit that the same party writes both records. As soon as there is a
        LATER round entry, its anchor (`audit_seq` + `audit_hash`) also binds the content of the earlier rows.
        """
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)   # a second, honest round
        cur = ab.cursor_of("peer", db=self.db)
        n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                 envelope={"identity": "peer", "cursor": cur, "reply_sha256": []}, kind="pickup",
                 decision="accepted", reason="cursor=%d replies=0" % cur,
                 cursor={"at": cur, "replies": 0, "pending": 0, "next_id": 0})
        rows = [dict(r) for r in ab.audit_export("peer", db=self.db)]
        anchored = [e for e in bn.export(self.log, 1) if e.get("kind") == "pickup"
                    and isinstance(e.get("cursor"), dict) and "audit_seq" in e["cursor"]]
        want = anchored[-1]["cursor"]["audit_seq"]
        self.assertTrue(any(r["seq"] == want for r in rows), "precondition: the anchor points to an EXISTING row")
        rows[-1]["skipped_undelivered"] = 0               # removing the EVIDENCE
        prev = rows[0]["prev_row_hash"]
        for r in rows:                                    # re-chaining: the chain becomes internally INTACT
            r["prev_row_hash"] = prev
            r["row_hash"] = ab._audit_row_hash(r["seq"], r["ts"], r["agent"], r["op"], r["from_id"], r["to_id"],
                                               r["skipped_undelivered"], prev)
            prev = r["row_hash"]
        self.assertTrue(ab.audit_chain_verify(rows)["ok"], "precondition: the re-chained export is internally INTACT")
        v = self.verdict(rows)
        self.assertIn("audit_head_hash_mismatch", v["hard"],
                      "the re-chained export did not contradict even the LATER round's anchor: %r" % (v,))
        self.assertFalse(v["ok"])

    # ── 9/1: OMITTING the anchor is a third state ───────────────────────────
    def test_missing_anchor_is_a_third_state(self):
        entries = []
        for e in bn.export(self.log, 1):
            if (e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]):
                c = {k: v for k, v in e["cursor"].items() if k not in ("audit_seq", "audit_hash")}
                e = dict(e, cursor=c)                     # the anchor "was skipped" (fail-open write)
            entries.append(e)
        receipts = [{"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(entries, "peer", receipts, strict=True, bus_audit=ab.audit_export("peer", db=self.db))
        self.assertIn("audit_anchor_absent", {u["type"] for u in r["unresolved"]},
                      "without an anchor there is nothing to hold to account, and this did not show")
        self.assertFalse(r["ok"], "in strict mode a missing anchor cannot be green")


if __name__ == "__main__":
    unittest.main()
