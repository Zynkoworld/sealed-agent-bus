"""`_audit_cross`: pairing by key and a two-way coverage gate — (2026-09-17, LOW-MEDIUM).

The two parts of the finding, both measured on a real bus:
  (a) the length gate was ONE-WAY: only "the log says more than the audit" (audit_row_missing) fired; the reverse
      direction — 2 log acks / 3 audit rows, even 0 / 3 — stayed SILENT. Yet that is exactly the direction of HIDING: the independent
      record knows more than the self-report.
  (b) it paired the two records BY POSITION (`zip`): if an ack drops out of the log, every further pair
      slides, and the accusation (audit_cursor_mismatch) points at an HONEST entry — the accused party rightly shows
      that its row is fine, and the cross-check's credibility suffers, although the system was right that something was wrong.

Fix: pairing BY KEY (audit from_id/to_id ↔ log cursor.from/to, in log order, each row once), and the
reverse direction's own name: `audit_row_unlogged`, with the seqs of the missing audit rows. One arm's strong refutation still stands
(the skipped signal cannot be made to disappear), we do not re-measure that here.

Mutant probe: with position pairing `test_dropped_middle_ack_does_not_accuse_the_honest_third` fails; without the reverse gate
`test_audit_rows_without_log_ack_are_named` fails. stdlib unittest; a real bus + a real audit export, /tmp.
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


class KeyPairedAuditCross(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, _ = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()
        # THREE honest rounds: 2 messages → delivery → ack, every ack in the log AND in the bus audit table
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        self.steps = []
        for r in range(3):
            for i in range(2):
                ab.send("hub", "peer", "m-%d-%d" % (r, i), db=self.db, mirror=False)
            rows = ab.recv("peer", mark=False, db=self.db)
            cur = ab.cursor_of("peer", db=self.db)
            rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": []}, kind="pickup", decision="accepted",
                reason="cursor=%d replies=%d" % (cur, len(rows)),
                cursor={"at": cur, "replies": len(rows), "pending": len(rows), "next_id": 0})
            ack_to = max(x["id"] for x in rows)
            base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
            rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
                reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
            ab.ack("peer", ack_to, db=self.db)
            self.steps.append((base, tgt))
        self.entries = bn.export(self.log, 1)
        self.audit = ab.audit_export("peer", db=self.db)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def cross(self, entries):
        out = bn._audit_cross(entries, "peer", self.audit, entries_all=entries)
        return {d["type"]: d for d in out}

    def _without_ack(self, which):
        """The `which`-th (0-based) ack entry drops out of the log — everything else stays."""
        drop_to = self.steps[which][1]
        return [e for e in self.entries
                if not (e.get("kind") == "ack" and isinstance(e.get("cursor"), dict) and e["cursor"].get("to") == drop_to)]

    def test_precondition_three_audit_ack_rows(self):
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(len(acks), 3)
        self.assertEqual([(a["from_id"], a["to_id"]) for a in acks], self.steps)

    def test_control_honest_export_is_silent_on_pairing_and_coverage(self):
        r = self.cross(self.entries)
        for t in ("audit_cursor_mismatch", "audit_row_missing", "audit_row_unlogged"):
            self.assertNotIn(t, r, r)

    def test_dropped_middle_ack_does_not_accuse_the_honest_third(self):
        # one arm's (b): the 2nd log ack drops out; the 3rd log ack's step (e.g. 20→30) matches the 3rd audit row BYTE for byte
        r = self.cross(self._without_ack(1))
        self.assertNotIn("audit_cursor_mismatch", r, r)          # the honest 3rd ack is NOT accused
        self.assertIn("audit_row_unlogged", r, r)
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(r["audit_row_unlogged"]["audit_seq"], [acks[1]["seq"]])   # the MISSING row named
        self.assertEqual(r["audit_row_unlogged"]["steps"], [list(self.steps[1])])

    def test_audit_rows_without_log_ack_are_named(self):
        # one arm's (a): 2/3, 1/3 and 0/3 — all were silent
        for drop in ([1], [0, 1], [0, 1, 2]):
            ents = self.entries
            for w in drop:
                to = self.steps[w][1]
                ents = [e for e in ents if not (e.get("kind") == "ack" and isinstance(e.get("cursor"), dict)
                                                and e["cursor"].get("to") == to)]
            r = self.cross(ents)
            self.assertIn("audit_row_unlogged", r, (drop, r))
            self.assertEqual(r["audit_row_unlogged"]["audit_ack_rows"], 3)
            self.assertEqual(r["audit_row_unlogged"]["logged_acks"], 3 - len(drop))
            self.assertEqual(len(r["audit_row_unlogged"]["audit_seq"]), len(drop))

    def test_control_the_other_direction_still_fires(self):
        # the log says MORE: a fourth, lying ack entry → audit_row_missing (the old gate unchanged)
        extra = dict(self.entries[-1]); extra = {**extra, "kind": "ack", "decision": "accepted",
                                                "cursor": {"from": 99, "to": 120, "ack": 120}, "recipient": "peer"}
        r = self.cross(self.entries + [extra])
        self.assertIn("audit_row_missing", r, r)
        self.assertIn("audit_cursor_mismatch", r, r)              # there is no audit row for the lying step: the ACCUSATION points at it
        self.assertEqual(r["audit_cursor_mismatch"]["log"], [99, 120])

    def test_lying_step_is_accused_by_its_own_entry_not_by_position(self):
        # we rewrite the 2nd log ack's step: the accusation points at the 2nd, the 3rd stays untouched
        ents = []
        for e in self.entries:
            if e.get("kind") == "ack" and isinstance(e.get("cursor"), dict) and e["cursor"].get("to") == self.steps[1][1]:
                e = {**e, "cursor": {**e["cursor"], "to": e["cursor"]["to"] + 7}}
            ents.append(e)
        r = self.cross(ents)
        self.assertIn("audit_cursor_mismatch", r, r)
        self.assertEqual(r["audit_cursor_mismatch"]["log"], [self.steps[1][0], self.steps[1][1] + 7])
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(r["audit_cursor_mismatch"]["audit_seq"], [acks[1]["seq"]])   # the unpaired audit row
        self.assertNotIn("audit_row_unlogged", r, r)              # the counts match: this is a discrepancy, not hiding


if __name__ == "__main__":
    unittest.main()
