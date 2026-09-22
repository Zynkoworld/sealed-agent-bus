"""bus_relay: vak store-and-forward (E2E), aláírt lehúzás (hamis/aláíratlan/replay → 401), SSE-értesítés tartalom
nélkül, csatolmány darabokban, fail-closed indulás. Csak 127.0.0.1. stdlib unittest (+cryptography)."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_attach  # noqa: E402
import bus_relay as br  # noqa: E402


@unittest.skipUnless(br.HAVE_CRYPTO, "cryptography missing")
class RelayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a_sign, a_pub = br.ed25519_keypair()
        self.b_sign, b_pub = br.ed25519_keypair()
        self.a_x, a_xpub = br.x25519_keypair()
        self.b_x, b_xpub = br.x25519_keypair()
        self.relay = br.Relay(os.path.join(self.tmp.name, "spool"), {"alice": a_pub, "bob": b_pub},
                              sse_interval=0.05).start()
        peers = {"alice": a_xpub, "bob": b_xpub}
        self.alice = br.RelayClient(self.relay.url, "alice", self.a_sign, self.a_x, peers)
        self.bob = br.RelayClient(self.relay.url, "bob", self.b_sign, self.b_x, peers)

    def tearDown(self):
        self.relay.stop()
        self.tmp.cleanup()

    def _post(self, path, obj):
        req = urllib.request.Request(self.relay.url + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_e2e_roundtrip_relay_blind(self):
        secret = "top-secret-plaintext-42"
        self.alice.deliver("bob", secret)
        spooled = ""
        for root, _, files in os.walk(self.relay.spool):
            for f in files:
                spooled += open(os.path.join(root, f)).read()
        self.assertTrue(spooled)
        self.assertNotIn(secret, spooled)                        # a relay csak titkosított borítékot lát
        got = self.bob.pickup()
        self.assertEqual([g["body"] for g in got], [secret])
        self.assertEqual(self.bob.pickup(), [])                 # lehúzva (a .picked alá mozgatva, nem törölve)
        picked = os.listdir(os.path.join(self.relay.spool, "bob", ".picked"))
        self.assertEqual(len(picked), 1)

    def _fake_env(self, to="bob", i=0):
        return {"v": br.V, "from": "mallory", "to": to, "ts": int(time.time()), "nonce": "%024x" % i,
                "ct": "00" * 16, "alg": "x25519-hkdf-chacha20poly1305"}

    def test_H_deliver_flood_is_capped_per_recipient(self):
        """500 formailag érvényes boríték egy címzettnek, hitelesítés nélkül → korábban
        mind az 500 bekerült; most a címzettenkénti várakozó-plafon felett 429, a spoolban legfeljebb a plafon."""
        codes = [self._post("/deliver", self._fake_env("bob", i))[0] for i in range(500)]
        spool_files = [n for n in os.listdir(os.path.join(self.relay.spool, "bob")) if n.endswith(".json")]
        self.assertLessEqual(len(spool_files), self.relay.max_pending_per_recipient)
        self.assertIn(429, codes)
        self.assertEqual(codes.count(200), len(spool_files))

    def test_H_deliver_unknown_recipient_refused(self):
        code, body = self._post("/deliver", self._fake_env("nobody-registered"))
        self.assertEqual(code, 404)
        self.assertFalse(os.path.isdir(os.path.join(self.relay.spool, "nobody-registered")))

    def test_H_deliver_total_spool_cap(self):
        self.relay.max_spool_total = 30
        codes = [self._post("/deliver", self._fake_env("bob" if i % 2 else "alice", i))[0] for i in range(60)]
        total = sum(1 for r, _, fs in os.walk(self.relay.spool) for f in fs if f.endswith(".json") and ".picked" not in r)
        self.assertLessEqual(total, 30)
        self.assertIn(429, codes)

    def test_plaintext_deliver_refused(self):
        code, _ = self._post("/deliver", {"from": "alice", "to": "bob", "body": "plain"})
        self.assertEqual(code, 400)

    def test_unsigned_forged_and_replayed_pickup_rejected(self):
        self.alice.deliver("bob", "m1")
        self.assertEqual(self._post("/pickup", {"agent": "bob"})[0], 401)                       # aláíratlan
        forged = br.sign_request("pickup", "bob", self.a_sign)                                   # alice kulcsával bobként
        self.assertEqual(self._post("/pickup", forged)[0], 401)
        stale = br.sign_request("pickup", "bob", self.b_sign, ts=int(time.time()) - 10 * br.WINDOW)
        self.assertEqual(self._post("/pickup", stale)[0], 401)
        wrong_purpose = br.sign_request("events", "bob", self.b_sign)
        self.assertEqual(self._post("/pickup", wrong_purpose)[0], 401)
        good = br.sign_request("pickup", "bob", self.b_sign)
        code, res = self._post("/pickup", good)
        self.assertEqual((code, len(res["envelopes"])), (200, 1))
        self.assertEqual(self._post("/pickup", good)[0], 401)                                    # REPLAY
        self.assertEqual(len(os.listdir(os.path.join(self.relay.spool, "bob", ".picked"))), 1)

    def test_replay_rejected_after_relay_restart(self):
        """v1.4: a nonce-tár tartós — újraindított relay ugyanazt az aláírt lehúzást sem fogadja el."""
        self.alice.deliver("bob", "m1")
        good = br.sign_request("pickup", "bob", self.b_sign)
        self.assertEqual(self._post("/pickup", good)[0], 200)
        spool, reg = self.relay.spool, dict(self.relay.auth.registry)
        self.relay.stop()
        self.relay = br.Relay(spool, reg, sse_interval=0.05).start()           # "újraindítás": új folyamat-állapot, ugyanaz a spool
        self.assertEqual(self._post("/pickup", good)[0], 401)
        fresh = br.sign_request("pickup", "bob", self.b_sign)
        self.assertEqual(self._post("/pickup", fresh)[0], 200)                  # friss kérés továbbra is megy

    def test_H2_deleted_nonce_store_does_not_reopen_replay(self):
        """a nonce-fájl törlése + relay-újraindítás ne nyissa meg ugyanazt az aláírt lehúzást."""
        self.alice.deliver("bob", "m1")
        good = br.sign_request("pickup", "bob", self.b_sign)
        self.assertEqual(self._post("/pickup", good)[0], 200)
        spool, reg = self.relay.spool, dict(self.relay.auth.registry)
        self.relay.stop()
        os.unlink(os.path.join(spool, ".pickup_nonces.jsonl"))
        time.sleep(1.1)                                                        # az újraindítás a lehúzás UTÁNI másodpercben
        self.relay = br.Relay(spool, reg, sse_interval=0.05).start()
        self.assertEqual(self._post("/pickup", good)[0], 401)
        fresh = br.sign_request("pickup", "bob", self.b_sign)
        self.assertEqual(self._post("/pickup", fresh)[0], 200)

    def test_nonce_store_compaction_keeps_unexpired(self):
        a = br._Auth({"bob": "00" * 32}, window=100, nonce_path=os.path.join(self.tmp.name, "n.jsonl"))
        now = time.time()
        a._seen = {("pickup", "bob", "fresh-nonce"): now - 10, ("pickup", "bob", "old-nonce"): now - 1000}
        with a._lock:
            for k in [k for k, v in a._seen.items() if now - v > 2 * a.window]:
                del a._seen[k]
            a._compact_locked()
        b = br._Auth({"bob": "00" * 32}, window=100, nonce_path=os.path.join(self.tmp.name, "n.jsonl"))
        self.assertIn(("pickup", "bob", "fresh-nonce"), b._seen)
        self.assertNotIn(("pickup", "bob", "old-nonce"), b._seen)

    def test_tampered_envelope_not_delivered_to_app(self):
        env = br.seal("hello", "alice", "bob", self.a_x, self.bob.peers["bob"])
        env["ct"] = env["ct"][:-4] + ("AAAA" if not env["ct"].endswith("AAAA") else "BBBB")
        self.assertEqual(self.relay.deliver(env)[0], 200)
        self.assertEqual(self.bob.pickup(), [])                 # AEAD-hiba → kimarad (fail-closed)

    def test_sse_notifies_without_content(self):
        result = {}
        th = threading.Thread(target=lambda: result.setdefault("n", self.bob.wait_pending(timeout=5)))
        th.start()
        time.sleep(0.3)
        self.alice.deliver("bob", "wake-content-should-not-leak")
        th.join(8)
        self.assertEqual(result.get("n"), 1)
        q = br.sign_request("events", "bob", self.b_sign)
        q["max_seconds"] = "0.2"
        url = self.relay.url + "/events?" + "&".join("%s=%s" % kv for kv in q.items())
        with urllib.request.urlopen(url, timeout=5) as r:
            stream = r.read().decode()
        self.assertIn('"count": 1', stream)
        self.assertNotIn("wake-content", stream)

    def test_sse_unauthenticated_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.relay.url + "/events?agent=bob", timeout=5)
        self.assertEqual(cm.exception.code, 401)

    def test_attachment_over_relay(self):
        src = bus_attach.Store(os.path.join(self.tmp.name, "a_att"))
        dst = bus_attach.Store(os.path.join(self.tmp.name, "b_att"))
        data = os.urandom(600 * 1024)
        d = src.put(data)
        n = self.alice.deliver_attachment("bob", src, d)
        self.assertGreaterEqual(n, 3)
        self.alice.deliver("bob", "normal message")
        rest, done, errors = br.RelayClient.take_attachments(self.bob.pickup(), dst)
        self.assertEqual((done, errors), ([d], []))
        self.assertEqual([r["body"] for r in rest], ["normal message"])
        self.assertEqual(dst.get(d), data)


class FailClosedTest(unittest.TestCase):
    def test_no_crypto_refuses(self):
        with mock.patch.object(br, "HAVE_CRYPTO", False):
            with self.assertRaises(RuntimeError):
                br.Relay(tempfile.gettempdir(), {"x": "00" * 32})

    @unittest.skipUnless(br.HAVE_CRYPTO, "cryptography missing")
    def test_empty_registry_refuses(self):
        with self.assertRaises(RuntimeError):
            br.Relay(tempfile.gettempdir(), {})


if __name__ == "__main__":
    unittest.main()
