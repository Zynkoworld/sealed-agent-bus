"""7 (2026-09-16) — a HOSTILE re-measurement of the 52Z fix.

The fixes (transient/permanent rejection, per-id `remote_delivered`, signed-copy replay) were attacked by a
NON-Claude-based arm before upload. Five findings came back; this file is the
regression for each — so that the fix of the fix does not slide back either.

  7/1  the `forged` grace period was computed from the SENDER's `ts` -> a future ts = eternal grace = the water level
       stuck forever (DoS). Fix: a future/unparseable ts -> NOT fresh (permanent).
  7/2  an `enf.check` exception -> the fail-closed branch treated EVERY row as blocking, the permanent ones too ->
       a single unparseable row could stop the water level forever. Fix: per-row handling.
  7/3  the replay's signed COPY itself remained a lifeboat candidate -> a copy of a copy (flood), and a
       TOCTOU between the candidate read + the insert. Fix: `to_id` also excludes + an IMMEDIATE txn +
       the `ux_replay_once` unique index.
  7/4  `mark_delivered` wrote `remote_delivered` for any id -> the remote side's lying ack
       COULD CLOSE the open `enforce_reject` trace (false silence). Fix: a permanently
       rejected id is left out, and goes into a separate `remote_delivered_refused` row.
  7/5  `got[sha]` -> KeyError on a missing envelope (audit DoS). Fix: `got.get(sha, 0)`.

stdlib unittest + cryptography. No network, every path under /tmp.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402


@unittest.skipUnless(ab._A2_HAVE, "cryptography required")
class Glm7Round(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(t, "bus.db")
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.kp = os.path.join(self.keys, "hub.ed25519.key")
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(pub)
        with open(self.kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        self.p = [
            mock.patch.dict(os.environ, {
                "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": self.keys,
                "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
                "AGENT_BUS_MODE": "product"}, clear=False),
            mock.patch.object(ab, "KEYS_DIR", self.keys),
            mock.patch.object(ab, "_a2_guarded_read",
                              lambda p: (open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None)),
        ]
        for x in self.p:
            x.start()
        os.environ.pop("AGENT_BUS_STRICT_ACK", None)

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    # ── helpers ─────────────────────────────────────────────────────────────
    def unknown_key(self, name="idegen"):
        """A signed message with a key that is NOT in the registry -> `forged`."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        kp = os.path.join(self.keys, "%s.ed25519.key" % name)
        with open(kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        return kp

    def fresh(self, tag="a"):
        return ab.send("hub", "peer", "friss-%s" % tag, db=self.db, mirror=False, sign_key=self.kp)

    def delivered_id(self):
        c = ab._conn(self.db)
        try:
            r = c.execute("SELECT delivered_id FROM cursors WHERE agent='peer'").fetchone()
            return r["delivered_id"] if r else 0
        finally:
            c.close()

    def audit_ops(self):
        c = ab._conn(self.db)
        try:
            return [(a["op"], a["from_id"]) for a in c.execute(
                "SELECT op, from_id FROM cursor_audit WHERE agent='peer' ORDER BY id")]
        finally:
            c.close()

    # ── 7/1 ──────────────────────────────────────────────────────────────────
    def test_future_dated_forged_row_gets_no_endless_grace(self):
        """A forged row with a future `ts` does NOT get endless grace (otherwise it pins the water level forever)."""
        kp = self.unknown_key()
        far = int((time.time() + 10 * 365 * 24 * 3600) * 1e9)         # 10 years in the future
        with mock.patch.object(ab.time, "time_ns", lambda: far):
            ab.send("idegen", "peer", "10-ev-mulva-hamis", db=self.db, mirror=False, sign_key=kp)
        good = self.fresh("a")
        self.assertNotIn(1, ab.pending_blocking_ids("peer", db=self.db),
                         "a `forged` row dated in the future counts as blocking -> the attacker stops the water level")
        ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), good, "the water level stands on the fresh row, it does not stick below the garbage row")

    def test_fresh_forged_row_is_still_transient(self):
        """Control: a FRESH `forged` row is still transient (key rollout stays protected)."""
        kp = self.unknown_key("ops")
        ab.send("ops", "peer", "most-erkezett-bejegyzes-elott", db=self.db, mirror=False, sign_key=kp)
        good = self.fresh("a")
        self.assertIn(1, ab.pending_blocking_ids("peer", db=self.db), "a fresh `forged` row blocks (rollout window)")
        ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), 0, "the water level cannot step over a row that can still be resolved")

    # ── 7/2 ──────────────────────────────────────────────────────────────────
    def test_unparseable_row_must_not_block_forever(self):
        """If `enf.check` RAISES on a row, that row can never be delivered -> it cannot block."""
        self.fresh("a")
        good = self.fresh("b")
        real = enf.check

        def boom(m, **kw):
            if m["id"] == 1:
                raise ValueError("ertelmezhetetlen fejlec")
            return real(m, **kw)

        with mock.patch.object(enf, "check", boom):
            self.assertNotIn(1, ab.pending_blocking_ids("peer", db=self.db))
            ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), good,
                         "a single unparseable row can stop the water level (lasting muting)")

    # ── 7/4 ──────────────────────────────────────────────────────────────────
    def test_remote_ack_cannot_close_a_permanent_reject(self):
        """The remote side's ack CANNOT close the trace of a permanent rejection (false silence)."""
        old = int((time.time() - 30 * 24 * 3600) * 1e9)               # 30 days old -> `stale-ts` (PERMANENT)
        with mock.patch.object(ab.time, "time_ns", lambda: old):
            ab.send("hub", "peer", "regi-sor", db=self.db, mirror=False, sign_key=self.kp)
        n = ab.mark_delivered("peer", [1], db=self.db)
        self.assertEqual(n, 0, "a permanently rejected id cannot be marked as delivered")
        ops = self.audit_ops()
        self.assertIn(("remote_delivered_refused", 1), ops, "the refused ack goes into a separate, hash-chained row")
        self.assertNotIn(("remote_delivered", 1), ops, "a lying ack CANNOT manufacture a `remote_delivered` row")
        c = ab._conn(self.db)
        try:
            self.assertIsNone(c.execute("SELECT read_at FROM messages WHERE id=1").fetchone()["read_at"],
                              "the row stays unread (`read_at` is the truth)")
        finally:
            c.close()

    def test_honest_ack_still_closes(self):
        """Control: an honest ack still works."""
        good = self.fresh("a")
        self.assertEqual(ab.mark_delivered("peer", [good], db=self.db), 1)
        self.assertIn(("remote_delivered", good), self.audit_ops())

    # ── 7/3 ──────────────────────────────────────────────────────────────────
    def test_signed_copy_is_not_replayed_again(self):
        """The replay's signed COPY cannot be the basis of another replay (otherwise a copy avalanche).

        MEASURED LIMIT: right after the replay the copy is ABOVE the cursor, so it is not even a candidate
        (`reconcile`'s range: delivered < id <= cursor). The avalanche would start if a LATER
        cursor jump stepped over the copy without delivery — the test produces this situation.
        """
        self.fresh("a")
        self.fresh("b")
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 2, db=self.db)                              # the cursor jumps WITHOUT delivery: 2 skipped rows
        first = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(len(first["replayed"]), 2, "precondition: the copies of the two skipped rows are made")
        self.assertTrue(all(r.get("mode") == "signed-copy" for r in first["replayed"]))
        copies = {r["new"] for r in first["replayed"]}
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", max(copies), db=self.db)                    # the cursor also jumps above the COPIES without delivery
        life = {m["id"] for m in ab.reconcile("peer", db=self.db)}
        self.assertTrue(copies & life, "precondition: now the copies themselves are lifeboat candidates")
        second = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(second["replayed"], [],
                         "a copy spawned a copy (%s): replay avalanche" % (second["replayed"],))

    def test_unique_index_blocks_a_second_replay_row(self):
        """For the race case: the `ux_replay_once` index in the DB forbids a second replay row for the same original."""
        self.fresh("a")
        # 2026-09-16: the strict ack clamp became the DEFAULT IN PRODUCT MODE — the cursor cannot step over
        # undelivered mail. This probe produces exactly the DAMAGE the clamp prevents, so for the
        # damage scenario the escape hatch MUST BE STATED here.
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 1, db=self.db)
        ab.replay("peer", commit=True, db=self.db)
        c = ab._conn(self.db)
        try:
            with self.assertRaises(ab.sqlite3.IntegrityError):
                with c:
                    ab._append_audit(c, "peer", 1, 99, "replay", 0)
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
