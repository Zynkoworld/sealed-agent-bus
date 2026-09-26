"""A TRUNCATED `pending` measurement is a third state — our own.

The round entry's `pending` field is the number of mail items awaiting delivery. The measurement goes up to a limit
(`MAX_REPLIES * 50 + 1`), and the `+1` was made precisely as a truncation detector — but no one read it.
So a measurement that hit the limit, i.e. a TRUNCATED one, looked exactly like a clean round.

The fix per the house rule: a truncated measurement is the same third state as a missing one
(`pending_truncated` in the round entry -> the next ack gets a `round_pending_unknown` unresolved
item, `ok:false` in strict/product mode).

stdlib unittest + cryptography.
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


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography required")
class TruncatedPendingIsNotACleanRound(unittest.TestCase):
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

    def round_cursor(self, n_mail, *, max_replies):
        """Runs a round with a `max_replies` delivery limit, and returns the round entry's machine field."""
        for i in range(1, n_mail + 1):
            ab.send("hub", "peer", "m%d" % i, db=self.db, mirror=False)
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)     # an explicit notary (in dev mode there is no env key)
        with mock.patch.object(ex, "MAX_REPLIES", max_replies):
            ex.exchange("peer", bn.json.dumps({"messages": []}).encode(), db=self.db, notary=n)
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("type") == "entry" and e.get("kind") == "pickup" and e.get("decision") == "accepted"
                  and isinstance(e.get("cursor"), dict) and "at" in e["cursor"]]
        self.assertTrue(rounds, "precondition: there is a round entry with a machine field")
        return rounds[-1]["cursor"]

    # ── control: a measurement below the limit is COMPLETE, no truncation flag ────────
    def test_control_complete_measurement_has_no_flag(self):
        c = self.round_cursor(5, max_replies=1)
        self.assertEqual(c["pending"], 5, "below the limit the measurement is exact")
        self.assertNotIn("pending_truncated", c)

    # ── FINDING: a measurement hitting the limit is TRUNCATED, and that must be stated ─────────
    def test_truncated_measurement_is_flagged(self):
        c = self.round_cursor(55, max_replies=1)             # the measurement's limit: 1*50 -> 55 does not fit
        self.assertEqual(c.get("pending_truncated"), 1,
                         "the truncated `pending` measurement (%s) looked like a clean round" % c.get("pending"))

    # ── and on the notary side the same third state as a missing measurement ──
    def test_truncated_measurement_blocks_a_clean_report(self):
        cur = ab.cursor_of("peer", db=self.db)
        c = self.round_cursor(55, max_replies=1)
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        ack_to = 1
        n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                 envelope={"ack": ack_to, "cursor_from": cur, "cursor_to": ack_to}, kind="ack", decision="accepted",
                 reason="cursor %d->%d (ack %d)" % (cur, ack_to, ack_to),
                 cursor={"from": cur, "to": ack_to, "ack": ack_to})
        rep = bn.reconcile(bn.export(self.log, 1), "peer",
                           [{"phase": "request", "sent": [], "ack": ack_to, "received": [], "round": "r1"},
                            {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}], strict=True)
        self.assertIn("round_pending_unknown", {u["type"] for u in rep["unresolved"]},
                      "after the truncated measurement the cursor step was silently accepted (%r)" % (c,))
        self.assertFalse(rep["ok"])


if __name__ == "__main__":
    unittest.main()
