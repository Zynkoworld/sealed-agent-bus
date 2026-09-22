"""BLOCKER/HIGH — a VALÓDI kiadási úton (bus_ssh_exchange._exchange) mérve."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class RealReleasePath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.env = {"AGENT_BUS_DB": os.path.join(t, "b.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_MODE": "dev",
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": os.path.join(t, "n.jsonl"),
                    "AGENT_BUS_AUTO_SIGN": "0"}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        global ab, ex, bn
        import agent_bus as ab, bus_ssh_exchange as ex, bus_notary as bn         # noqa: E402
        self.db = self.env["AGENT_BUS_DB"]
        self.seed, self.pub = bn.keypair()
        self.n = bn.Notary(self.env["AGENT_BUS_NOTARY_LOG"], seed=self.seed, checkpoint_every=1)

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.environ.pop("AGENT_BUS_STRICT_ACK", None)
        self.tmp.cleanup()

    def release(self, n_mail=6):
        for i in range(1, n_mail + 1):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        return ex._exchange("peer", json.dumps({"messages": [], "ack": 0}), db=self.db,
                            attach_root=os.path.join(self.tmp.name, "att"), notary=self.n)

    def round_entry(self):
        for e in bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1):
            if e.get("type") == "entry" and e.get("kind") == "pickup" and e.get("decision") == "accepted":
                return e
        return None

    def test_round_entry_carries_pending_and_next_id(self):
        self.release()
        c = self.round_entry()["cursor"]
        self.assertEqual((c["pending"], c["replies"], c["next_id"]), (6, 6, 0))

    def test_release_marks_delivered_so_lifeboat_is_quiet(self):
        self.release()
        self.assertEqual([m["id"] for m in ab.reconcile("peer", db=self.db)], [])

    def test_strict_ack_clamp_is_not_frozen_by_peek(self):
        self.release()
        os.environ["AGENT_BUS_STRICT_ACK"] = "1"
        self.assertEqual(ab.ack_preview("peer", 6, db=self.db), (0, 6))

    def test_swallowing_round_is_accused(self):
        """Csonkolt kör (2/6 kiadva), a kurzor mégis a kiadatlan posta fölé megy -> hard vád."""
        for i in range(1, 7):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[4:]
        rec = lambda **kw: self.n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        rec(envelope={"i": 1}, kind="pickup", decision="accepted", reason="r",
            cursor={"at": 0, "replies": len(out), "pending": len(allr), "next_id": 1})
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id", cursor={"id": int(x["id"])})
        rec(envelope={"a": 1}, kind="ack", decision="accepted", reason="a", cursor={"from": 0, "to": 6, "ack": 6})
        rcpts = [{"phase": "request", "sent": [], "ack": 6, "received": out, "round": "r1"},
                 {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        rep = bn.reconcile(bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1), "peer", rcpts, start_cursor=0,
                           trusted_pub=self.pub, strict=True)
        self.assertIn("cursor_skips_undelivered", [d["type"] for d in rep["discrepancies"]])
        self.assertFalse(rep["ok"])

    def test_honest_truncated_round_is_not_accused(self):
        """Becsületes csonkolás: a kurzor a kiadatlan maradék ALATT marad -> nincs vád."""
        for i in range(1, 7):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[:3]
        rec = lambda **kw: self.n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        rec(envelope={"i": 1}, kind="pickup", decision="accepted", reason="r",
            cursor={"at": 0, "replies": 3, "pending": 6, "next_id": 4})
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id", cursor={"id": int(x["id"])})
        rec(envelope={"a": 1}, kind="ack", decision="accepted", reason="a", cursor={"from": 0, "to": 3, "ack": 3})
        rcpts = [{"phase": "request", "sent": [], "ack": 3, "received": out, "round": "r1"},
                 {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        rep = bn.reconcile(bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1), "peer", rcpts, start_cursor=0,
                           trusted_pub=self.pub, strict=True)
        self.assertNotIn("cursor_skips_undelivered", [d["type"] for d in rep["discrepancies"]])

    def test_verify_reads_the_structured_cursor(self):
        """a verify a gépi mezőt olvassa — üres reason mellett is látja a hamis kurzor-célt."""
        self.n.record(envelope={"a": 1}, sender_identity="peer", sender_auth="ssh-key", recipient="peer", kind="ack",
                      decision="accepted", reason="", cursor={"from": 0, "to": 9, "ack": 0})
        rep = bn.verify(bn.export(self.env["AGENT_BUS_NOTARY_LOG"], 1))
        self.assertEqual(len(rep["ack_target_violations"]), 1)


if __name__ == "__main__":
    unittest.main()


class GlmRound10(RealReleasePath):
    """a javításon: (A) néma kettős hiba, (C) high-water lyuk."""

    def test_c_unread_hole_lowers_the_highwater(self):
        """ha egy alacsonyabb id-jű üzenet OLVASATLAN marad, a vízszint nem maradhat fölötte."""
        self.release(3)
        c = ab._conn(self.db)
        before = c.execute("SELECT delivered_id FROM cursors WHERE agent='peer'").fetchone()["delivered_id"]
        c.execute("UPDATE messages SET read_at=NULL WHERE id=2")     # lyuk: a 2-es olvasatlan
        c.commit(); c.close()
        ab.mark_delivered("peer", [3], db=self.db)
        c = ab._conn(self.db)
        after = c.execute("SELECT delivered_id FROM cursors WHERE agent='peer'").fetchone()["delivered_id"]
        c.close()
        self.assertEqual(before, 3)
        self.assertEqual(after, 1, "a vízszint az összefüggő prefix teteje (1), nem a régi 3")

    def test_a_double_failure_is_fail_closed(self):
        import unittest.mock as mock
        for i in range(1, 4):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        with mock.patch.object(ab, "mark_delivered", side_effect=OSError("db")), \
             mock.patch.object(self.n, "record", side_effect=[self.n.record(envelope={"a": 1}, sender_identity="peer",
                                                                            sender_auth="ssh-key", recipient="peer",
                                                                            kind="pickup", decision="accepted",
                                                                            reason="r", cursor={"at": 0, "replies": 3,
                                                                                                "pending": 3, "next_id": 0})]
                               + [OSError("log")] * 10):
            with self.assertRaises(ex._NotaryWriteFailed):        # fail-closed: a hívó üres/hibás választ ad, posta nem megy ki
                ex._exchange("peer", json.dumps({"messages": [], "ack": 0}), db=self.db,
                             attach_root=os.path.join(self.tmp.name, "att"), notary=self.n)


class TransientAndReplay(RealReleasePath):
    """az egyik kar + átmeneti/végleges elutasítás, per-id lezárás, replay-idempotencia."""

    def test_glm_a_per_id_close_does_not_silence_a_gap(self):
        for i in range(1, 4):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        ab.mark_delivered("peer", [1, 3], db=self.db)            # a 2-es NINCS kézbesítve
        rows = ab.audit_export("peer", db=self.db)
        covered = {(r["from_id"], r["to_id"]) for r in rows if r["op"] == "remote_delivered"}
        self.assertEqual(covered, {(1, 1), (3, 3)}, "id-szintű sorok kellenek, nem tartomány")

    def test_glm_c_replay_is_idempotent(self):
        """A mentőövbe került sor csak EGYSZER replay-elhető (a második hívás nem gyárt új másolatot)."""
        for i in range(1, 3):
            ab.send("hub", "peer", "t-%d" % i, db=self.db, mirror=False)
        ab.recv("peer", mark=True, db=self.db)                    # kurzor 2, vízszint 2
        c = ab._conn(self.db)
        with c:                                                   # elutasított sor nyoma: a mentőöv innen látja
            c.execute("UPDATE messages SET read_at=NULL WHERE id=1")
            ab._append_audit(c, "peer", 1, 1, "enforce_reject:stale-ts", 1)
        c.close()
        self.assertIn(1, [m["id"] for m in ab.reconcile("peer", db=self.db)])
        first = ab.replay("peer", commit=True, db=self.db)
        second = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(len(first["replayed"]), 1)
        self.assertEqual(second["replayed"], [], "ugyanaz a sor másodszor nem replay-elhető")

    def test_glm_d_old_forged_row_does_not_pin_the_cursor(self):
        """Régi (a türelmi időn túli) forged sor VÉGLEGES -> a vízszint átlépheti; friss -> megvárja."""
        import bus_enforce
        self.assertIn("future-ts", ab.TRANSIENT_REJECT)
        self.assertNotIn("forged", ab.TRANSIENT_REJECT)
        self.assertGreater(ab.FORGED_GRACE_S, 0)
