"""A relay archívuma és az SSE-kapcsolatok korlátja — saját.

Két lelet a nem-Claude kartól, mindkettő a „nincs törlés" elv árnyékában:
  1. a LEHÚZOTT boríték a `.picked/` alá kerül, a közjegyzői írás hibájánál pedig `.unnotarized`
     néven marad — egyiket sem számolta a spool-limit (más könyvtár, illetve rejtett név). Egy
     hitelesített fél ismételt küldés+lehúzás körrel megtöltheti a lemezt.
  2. egy hitelesített fél korlátlan `/events` (SSE) kapcsolatot nyithatott, mindegyik egy szálat és
     egy fd-t tart akár egy órán át -> a relay a `/deliver`-re is megbénul.

Javítás a ház szabálya szerint: KVÓTA és KORLÁT, törlés nélkül — az archívum takarítása operátori
döntés marad, a `archive_total()` megmutatja, mennyi fekszik ott.

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


@unittest.skipUnless(br.HAVE_CRYPTO if hasattr(br, "HAVE_CRYPTO") else True, "cryptography szükséges")
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

    # ── kontroll: a rendes kör megy, és a lehúzott boríték az archívumba kerül ──
    def test_control_delivery_and_pickup(self):
        self.alice.deliver("bob", "szia bob")
        self.assertEqual(self.relay.archive_total(), 0, "lehúzás előtt nincs archív darab")
        got = self.bob.pickup()
        self.assertEqual([m["body"] for m in got], ["szia bob"])
        self.assertEqual(self.relay.archive_total(), 1, "a lehúzott boríték az archívumban van (nem törlünk)")

    # ── LELET: az archívum korlátlanul nőtt — mostantól kvóta zárja a kaput ──
    def test_archive_quota_closes_the_gate(self):
        self.alice.deliver("bob", "elso")
        self.bob.pickup()
        self.relay.max_archive_total = 1                       # a kvótát elértük (1 archív darab)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.alice.deliver("bob", "masodik")
        self.assertEqual(cm.exception.code, 429)
        self.assertIn("archive full", cm.exception.read().decode())

    # ── a kvóta nem töröl semmit: a bűnjel ott marad ────────────────────────
    def test_quota_does_not_delete_anything(self):
        self.alice.deliver("bob", "elso")
        self.bob.pickup()
        self.relay.max_archive_total = 1
        try:
            self.alice.deliver("bob", "masodik")
        except urllib.error.HTTPError:
            pass
        self.assertEqual(self.relay.archive_total(), 1, "a kvóta kaput zár, nem takarít")

    # ── LELET: az SSE-kapcsolatok száma agentenként korlátos ────────────────
    def test_sse_connection_cap(self):
        self.relay.max_sse_per_agent = 1
        q = br.sign_request("events", "bob", self.b_sign)
        url = self.relay.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in
                                                     list(q.items()) + [("max_seconds", "3")])
        first = urllib.request.urlopen(url, timeout=5)          # az első kapcsolat él
        try:
            q2 = br.sign_request("events", "bob", self.b_sign)  # friss nonce: nem replay, csak MÁSODIK kapcsolat
            url2 = self.relay.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in
                                                          list(q2.items()) + [("max_seconds", "3")])
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(url2, timeout=5)
            self.assertEqual(cm.exception.code, 429)
        finally:
            first.close()

    # ── és a hely FELSZABADUL, ha a kapcsolat lezárul ───────────────────────
    def test_sse_slot_is_released(self):
        self.relay.max_sse_per_agent = 1
        self.assertTrue(self.relay.sse_slot("bob", True))
        self.assertFalse(self.relay.sse_slot("bob", True), "a második foglalás nem fér be")
        self.relay.sse_slot("bob", False)
        self.assertTrue(self.relay.sse_slot("bob", True), "lezárás után újra van hely")


if __name__ == "__main__":
    unittest.main()
