"""The relay's archive and the limit on SSE connections — our own.

Two findings from the non-Claude arm, both in the shadow of the "no deletion" principle:
  1. a PICKED-UP envelope goes under `.picked/`, and on a notary write error it stays under the name `.unnotarized`
     — neither was counted by the spool limit (another directory, and a hidden name respectively). An
     authenticated party could fill the disk with repeated send+pickup rounds.
  2. an authenticated party could open unlimited `/events` (SSE) connections, each holding a thread and
     an fd for up to an hour -> the relay would also be paralysed for `/deliver`.

Fix per the house rule: QUOTA and LIMIT, without deletion — cleaning up the archive stays an operator
decision, `archive_total()` shows how much lies there.

stdlib unittest + cryptography.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_relay as br  # noqa: E402


@unittest.skipUnless(br.HAVE_CRYPTO if hasattr(br, "HAVE_CRYPTO") else True, "cryptography required")
class RelayArchiveAndSse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a_sign, a_pub = br.ed25519_keypair()
        self.b_sign, b_pub = br.ed25519_keypair()
        self.a_x, a_xpub = br.x25519_keypair()
        self.b_x, b_xpub = br.x25519_keypair()
        self.relay = br.Relay(os.path.join(self.tmp.name, "spool"), {"alice": a_pub, "bob": b_pub},
                              sse_interval=0.05, notary=False).start()
        peers = {"alice": a_xpub, "bob": b_xpub}
        self.alice = br.RelayClient(self.relay.url, "alice", self.a_sign, self.a_x, peers)
        self.bob = br.RelayClient(self.relay.url, "bob", self.b_sign, self.b_x, peers)

    def tearDown(self):
        self.relay.stop()
        self.tmp.cleanup()

    # ── control: a normal round works, and the picked-up envelope goes into the archive ──
    def test_control_delivery_and_pickup(self):
        self.alice.deliver("bob", "hi bob")
        self.assertEqual(self.relay.archive_total(), 0, "no archived item before pickup")
        got = self.bob.pickup()
        self.assertEqual([m["body"] for m in got], ["hi bob"])
        self.assertEqual(self.relay.archive_total(), 1, "the picked-up envelope is in the archive (we do not delete)")

    # ── FINDING: the archive grew without limit — from now on a quota closes the gate ──
    def test_archive_quota_closes_the_gate(self):
        self.alice.deliver("bob", "elso")
        self.bob.pickup()
        self.relay.max_archive_total = 1                       # the quota is reached (1 archived item)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.alice.deliver("bob", "masodik")
        self.assertEqual(cm.exception.code, 429)
        self.assertIn("archive full", cm.exception.read().decode())

    # ── the quota deletes nothing: the evidence stays there ────────────────────────
    def test_quota_does_not_delete_anything(self):
        self.alice.deliver("bob", "elso")
        self.bob.pickup()
        self.relay.max_archive_total = 1
        try:
            self.alice.deliver("bob", "masodik")
        except urllib.error.HTTPError:
            pass
        self.assertEqual(self.relay.archive_total(), 1, "the quota closes the gate, it does not clean up")

    # ── FINDING: the number of SSE connections is limited per agent ────────────────
    def test_sse_connection_cap(self):
        self.relay.max_sse_per_agent = 1
        q = br.sign_request("events", "bob", self.b_sign)
        url = self.relay.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in
                                                     list(q.items()) + [("max_seconds", "3")])
        first = urllib.request.urlopen(url, timeout=5)          # the first connection is alive
        try:
            q2 = br.sign_request("events", "bob", self.b_sign)  # a fresh nonce: not a replay, just a SECOND connection
            url2 = self.relay.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in
                                                          list(q2.items()) + [("max_seconds", "3")])
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(url2, timeout=5)
            self.assertEqual(cm.exception.code, 429)
        finally:
            first.close()

    # ── and the slot is FREED when the connection closes ───────────────────────
    def test_sse_slot_is_released(self):
        self.relay.max_sse_per_agent = 1
        self.assertTrue(self.relay.sse_slot("bob", True))
        self.assertFalse(self.relay.sse_slot("bob", True), "the second reservation does not fit")
        self.relay.sse_slot("bob", False)
        self.assertTrue(self.relay.sse_slot("bob", True), "after closing there is room again")


if __name__ == "__main__":
    unittest.main()
