"""54Z's open item: a lying pending/next_id comes into contradiction with the bus's OWN audit chain."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class AuditCross(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.env = {"AGENT_BUS_DB": os.path.join(t, "b.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_MODE": "dev",
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": os.path.join(t, "n.jsonl"),
                    "AGENT_BUS_AUTO_SIGN": "0"}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        global ab, bn, ex
        import agent_bus as ab, bus_notary as bn, bus_ssh_exchange as ex   # noqa: E402
        self.db = self.env["AGENT_BUS_DB"]
        self.seed, self.pub = bn.keypair()
        self.n = bn.Notary(self.env["AGENT_BUS_NOTARY_LOG"], seed=self.seed, checkpoint_every=1)

    def tearDown(self):
        for k, v in self.old.items():
            os.environ.pop(k, None) if v is None else os.environ.update({k: v})
        self.tmp.cleanup()

    def swallow(self, lie):
        """2/6 delivered, the cursor jumps to 6; the log LIES (the round looks "complete")."""
        for i in range(1, 7):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        out = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows][4:]
        rec = lambda **kw: self.n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        rec(envelope={"i": 1}, kind="pickup", decision="accepted", reason="cursor=0 replies=2", cursor=lie)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id", cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        base, tgt = ab.ack_preview("peer", 6, db=self.db)
        rec(envelope={"a": 1}, kind="ack", decision="accepted", reason="a", cursor={"from": base, "to": tgt, "ack": 6})
        ab.ack("peer", 6, db=self.db)
        rcpts = [{"phase": "request", "sent": [], "ack": 6, "received": out, "round": "r1"},
                 {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        return bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1), rcpts

    def test_lied_pending_is_caught_against_the_bus_audit(self):
        recs, rcpts = self.swallow({"at": 0, "replies": 2, "pending": 2, "next_id": 0})   # the lie: "nothing undelivered"
        audit = ab.audit_export("peer", db=self.db)
        self.assertTrue(ab.audit_chain_verify(audit)["ok"])
        without = bn.reconcile(recs, "peer", rcpts, trusted_pub=self.pub, strict=True)
        with_audit = bn.reconcile(recs, "peer", rcpts, trusted_pub=self.pub, strict=True, bus_audit=audit)
        self.assertNotIn("audit_skipped_contradicts_log", [d["type"] for d in without["discrepancies"]])
        self.assertIn("audit_skipped_contradicts_log", [d["type"] for d in with_audit["discrepancies"]])
        self.assertFalse(with_audit["ok"])

    def test_honest_round_with_audit_is_clean(self):
        for i in range(1, 4):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        out = ex._exchange("peer", json.dumps({"messages": [], "ack": 0}), db=self.db,
                           attach_root=os.path.join(self.tmp.name, "att"), notary=self.n)
        ids = [r["id"] for r in out["replies"]]
        rec = lambda **kw: self.n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        base, tgt = ab.ack_preview("peer", max(ids), db=self.db)
        rec(envelope={"a": 1}, kind="ack", decision="accepted", reason="a",
            cursor={"from": base, "to": tgt, "ack": max(ids)})
        ab.ack("peer", max(ids), db=self.db)
        rcpts = [{"phase": "request", "sent": [], "ack": max(ids), "received": out["replies"], "round": "r1"},
                 {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        rep = bn.reconcile(bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1), "peer", rcpts, trusted_pub=self.pub,
                           strict=True, bus_audit=ab.audit_export("peer", db=self.db))
        self.assertEqual([d["type"] for d in rep["discrepancies"]], [])

    def test_audit_chain_tamper_is_caught(self):
        for i in range(1, 3):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        ab.recv("peer", mark=True, db=self.db)
        audit = ab.audit_export("peer", db=self.db)
        self.assertTrue(ab.audit_chain_verify(audit)["ok"])
        audit[0]["to_id"] = 99
        self.assertFalse(ab.audit_chain_verify(audit)["ok"])


if __name__ == "__main__":
    unittest.main()
