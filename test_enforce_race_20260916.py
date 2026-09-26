"""The race condition and silent branches of enforcement — our own.

Three findings from the non-Claude arm, all three around `bus_enforce.check()`:
  1. there is a RACE between `seen()` and `add()`: both of two concurrent recvs measure "not seen",
     and both deliver. `add()` returning FALSE (INSERT OR IGNORE, "was already in") is the only
     atomic signal — we used to throw it away.
  2. `record=True` WITHOUT a seen-store: replay protection is silently skipped. The consuming path can never call like this.
  3. if product mode rests SOLELY on the marker next to the bus, then whoever can write to the bus can also delete
     the marker -> the gate silently falls to dev. This is an operational risk: doctor states it LOUDLY.

A fourth claim (the `seen` key contains the signature, so it can be bypassed by re-signing)
REFUTED BY MEASUREMENT: Ed25519 is deterministic, the same key + the same content = the same signature.

stdlib unittest + cryptography.
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
class EnforceRaceAndSilentPaths(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(t, "bus.db")
        priv = ed25519.Ed25519PrivateKey.generate()
        self.priv = priv
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

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def signed(self):
        ab.send("hub", "peer", "egy-uzenet", db=self.db, mirror=False, sign_key=self.kp)
        return ab.recv("peer", mark=False, limit=5, db=self.db)[0]

    # ── control: an honest row passes ────────────────────────────────────
    def test_control_signed_message_passes(self):
        self.assertEqual(enf.check(self.signed(), keys_dir=self.keys), (True, "ok"))

    # ── 1. race: `add()` returning FALSE = replay, not a silent delivery ─────────
    def test_lost_race_is_a_replay_not_a_delivery(self):
        m = self.signed()

        class RacyStore:
            """The other process wrote the same key BETWEEN `seen()` AND `add()`."""
            def seen(self, key):
                return False                      # we have not seen it yet...

            def add(self, key, ts_s):
                return False                      # ...but the insert says: it was already in

        ok, why = enf.check(m, seen=RacyStore(), record=True, keys_dir=self.keys)
        self.assertFalse(ok, "the party losing the race would also have delivered (double delivery)")
        self.assertEqual(why, "replay")

    def test_control_won_race_still_delivers(self):
        m = self.signed()

        class WinningStore:
            def seen(self, key):
                return False

            def add(self, key, ts_s):
                return True                       # we wrote it in first

        self.assertEqual(enf.check(m, seen=WinningStore(), record=True, keys_dir=self.keys), (True, "ok"))

    # ── 2. consuming without a seen-store: a programming error, not a silent pass ──
    def test_consuming_without_a_seen_store_is_an_error(self):
        with self.assertRaises(ValueError):
            enf.check(self.signed(), seen=None, record=True, keys_dir=self.keys)

    def test_classifying_without_a_seen_store_is_allowed(self):
        self.assertEqual(enf.check(self.signed(), seen=None, record=False, keys_dir=self.keys), (True, "ok"))

    # ── 3. doctor states it if product mode rests on a bus-writable marker ───────
    def test_doctor_warns_when_product_mode_rests_on_a_bus_writable_marker(self):
        open(os.path.join(self.tmp.name, enf.MARKER), "w").close()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_BUS_MODE", None)
            with mock.patch.object(enf.os.path, "exists",
                                   lambda p: False if p == enf.SYSTEM_MARKER else os.path.lexists(p)):
                ok, lines = enf.doctor()
        self.assertFalse(ok)
        self.assertTrue(any("silently falls to dev" in l for l in lines),
                        "doctor does not state the silent-downgrade risk: %r" % (lines,))

    # ── 4. REFUTED finding: re-signing does not give a new seen key ────────────
    def test_resigning_the_same_content_yields_the_same_key(self):
        m = self.signed()
        again = self.priv.sign(ab._a2_content_bytes(m)).hex()
        self.assertEqual(again, m["sig"], "Ed25519 is deterministic: the same content = the same signature")
        self.assertEqual(enf.content_key(m), enf.content_key({**m, "sig": again}),
                         "the re-signed copy gets the same replay key")


if __name__ == "__main__":
    unittest.main()
