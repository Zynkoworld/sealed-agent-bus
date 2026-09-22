"""BLOCKER + NIT — a kurzor-detektorok nem kapcsolhatók ki a szabad szöveges `reason`-nel."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_notary as bn


class ReasonOptOut(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "n.jsonl")
        self.n = bn.Notary(self.log, seed=None, checkpoint_every=50)

    def tearDown(self):
        self.tmp.cleanup()

    def rec(self, **kw):
        base = dict(envelope={"x": kw.pop("x", 0)}, sender_identity="peer", sender_auth="ssh-key", recipient="peer")
        base.update(kw)
        return self.n.record(**base)

    def recs(self):
        return [json.loads(l) for l in open(self.log) if l.strip()]

    def hard(self, receipts=None, strict=True):
        rep = bn.reconcile(self.recs(), "peer", receipts or [], strict=strict)
        return rep, [d["type"] for d in rep["discrepancies"]]

    def test_structured_cursor_survives_trailing_space(self):
        self.rec(kind="pickup", decision="accepted", reason="cursor=4 replies=0 ", cursor={"at": 4, "replies": 0})
        rep, h = self.hard()
        self.assertIn("cursor_moved_without_logged_ack", h)
        self.assertFalse(rep["ok"])

    def test_unparsable_round_without_structured_field_is_hard(self):
        self.rec(kind="pickup", decision="accepted", reason="cursor=4 replies=2 ")
        rep, h = self.hard(strict=True)
        self.assertIn("unparsable_cursor_entry", h)
        self.assertFalse(rep["ok"])
        rep2, h2 = self.hard(strict=False)
        self.assertIn("unparsable_cursor_entry", [u["type"] for u in rep2["unresolved"]])

    def test_unparsable_ack_without_structured_field_is_hard(self):
        self.rec(kind="ack", decision="accepted", reason="cursor 0->4 (ack 4).")
        rep, h = self.hard(strict=True)
        self.assertIn("unparsable_cursor_entry", h)

    def test_delivered_without_round_is_hard(self):
        self.rec(kind="pickup", decision="delivered", reason="id=1", x=1)
        rep, h = self.hard(strict=True)
        self.assertIn("delivered_without_round", h)

    def test_control_honest_round_then_delivered_is_clean(self):
        self.rec(kind="pickup", decision="accepted", reason="cursor=0 replies=1", cursor={"at": 0, "replies": 1})
        self.rec(kind="pickup", decision="delivered", reason="id=1", x=1)
        rep, h = self.hard(strict=False)
        self.assertNotIn("delivered_without_round", h)
        self.assertNotIn("unparsable_cursor_entry", h)
        self.assertNotIn("cursor_moved_without_logged_ack", h)

    def test_cursor_field_is_hash_bound(self):
        self.rec(kind="ack", decision="accepted", reason="cursor 0->4 (ack 4)", cursor={"from": 0, "to": 4, "ack": 4})
        rows = self.recs()
        rows[0]["cursor"]["to"] = 9
        self.assertFalse(bn.verify(rows)["ok"])


    def test_glm_a3_reason_contradicts_cursor(self):
        self.rec(kind="ack", decision="accepted", reason="cursor 0->999 (ack 999)", cursor={"from": 0, "to": 0, "ack": 0})
        rep, h = self.hard(strict=False)
        self.assertIn("cursor_reason_mismatch", h)

    def test_glm_a4_bool_cursor_rejected(self):
        with self.assertRaises(bn.NotaryError):
            self.rec(kind="ack", decision="accepted", reason="x", cursor={"from": True, "to": 1, "ack": 1})

    def test_glm_a2_round_replies_mismatch(self):
        self.rec(kind="pickup", decision="accepted", reason="cursor=0 replies=2", cursor={"at": 0, "replies": 2})
        self.rec(kind="pickup", decision="delivered", reason="id=1", x=1)
        rep, h = self.hard(strict=True)
        self.assertIn("round_replies_mismatch", h)


if __name__ == "__main__":
    unittest.main()
