"""Matesensei (2026-09-15, 3. kör) — a v1.5 napló az SSH-határon CSAK a bejövő irányt fogja.

A relay mindkét irányt naplózza (`/deliver` + `/pickup`, bus_relay.py:257-263), az SSH-csere viszont a
kiadott válaszokról (`replies`) és a kurzort mozgató `ack`-ról egyetlen bejegyzést sem ír. Következmény: ha a
busz-gép a távoli félnek szánt postát visszatartja vagy a kurzort előreugratja, a napló változatlan és a
`verify` ok:true / errors:[] — a fenyegetés-modell „a kihagyás látszik" állítása erre az irányra nem áll.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class MateOutboundNotary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        self.env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log}

    def tearDown(self):
        self.tmp.cleanup()

    def _entries(self):
        return [r for r in bn.read_lines(self.log) if r.get("type") == "entry"]

    def _exchange(self, payload):
        import bus_ssh_exchange as ex
        with mock.patch.dict(os.environ, self.env, clear=False):
            return ex.exchange("remote1", json.dumps(payload), db=self.db,
                               attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)

    def _queue(self, n, prefix="ki"):
        import agent_bus as ab
        with mock.patch.dict(os.environ, self.env, clear=False):
            for i in range(n):
                ab.send("hub", "remote1", "%s-%d" % (prefix, i), db=self.db, mirror=False)

    def test_outbound_replies_are_notarized(self):
        """A távoli félnek KIADOTT posta is határ-esemény: kell róla bejegyzés."""
        self._queue(3)
        res = self._exchange({})
        self.assertEqual(len(res["replies"]), 3)
        out = [e for e in self._entries() if e["recipient"] == "remote1" or "repl" in e["kind"]]
        self.assertTrue(out, "3 válasz ment ki a határon, és NULLA közjegyzői bejegyzés lett róla: %r"
                             % (self._entries(),))

    def test_ack_moving_the_cursor_is_notarized(self):
        """Az `ack` véglegesen elfogyasztja a postát (előre-only kurzor) — nyom nélkül ma."""
        self._queue(2)
        res = self._exchange({})
        top = max(m["id"] for m in res["replies"])
        before = len(self._entries())
        self._exchange({"ack": top})
        self.assertGreater(len(self._entries()), before,
                           "az ack a kurzort %d-ig elmozdította, a napló mégis változatlan (%d bejegyzés)"
                           % (top, before))

    def test_withheld_outbound_leaves_a_trace(self):
        """A busz-gép előreugratja a kurzort: a távoli fél 4 üzenetet soha nem kap meg. Lássa a napló."""
        import agent_bus as ab
        self._queue(4, "soha")
        with mock.patch.dict(os.environ, self.env, clear=False):
            last = max(m["id"] for m in ab.recv("remote1", mark=False, db=self.db))
            ab.ack("remote1", last, db=self.db)                     # a posta „elnyelve”
        res = self._exchange({})
        self.assertEqual(res["replies"], [])
        rep = bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)
        self.assertTrue(self._entries() or rep["errors"],
                        "4 üzenet veszett el a határon: napló üres ÉS verify ok=%s errors=%r"
                        % (rep["ok"], rep["errors"]))


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ControlRelayOutboundIsNotarized(unittest.TestCase):
    """KONTROLL: a MÁSIK határpont ugyanezt a kimenő irányt naplózza — nem elvi korlát, hanem hiány."""

    def test_relay_pickup_is_notarized(self):
        import bus_relay as br
        with tempfile.TemporaryDirectory() as t:
            log = os.path.join(t, "notary.jsonl")
            seed, pub = bn.keypair()
            notary = bn.Notary(log, seed=seed, checkpoint_every=50)
            sign, agent_pub = br.ed25519_keypair()
            relay = br.Relay(os.path.join(t, "spool"), {"remote1": agent_pub}, sse_interval=0.05,
                             notary=notary).start()
            try:
                client = br.RelayClient(relay.url, "remote1", sign, br.x25519_keypair()[0], {})
                client.pickup()
            finally:
                relay.stop()
            entries = [r for r in bn.read_lines(log) if r.get("type") == "entry"]
            self.assertEqual([(e["kind"], e["decision"], e["sender_auth"]) for e in entries],
                             [("pickup", "accepted", "pickup-sig")])


if __name__ == "__main__":
    unittest.main()
