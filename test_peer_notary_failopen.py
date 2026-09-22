"""Matesensei (2026-09-15) — a közjegyzői napló írási hibája NEM fail-closed az SSH-határon.
A relay-úton van visszavonás (`Relay._unwrite`), az SSH-úton nincs: az `ab.send()` már commitolt,
mire a `note()` dob."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class MateNotaryFailOpen(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=2)
        self.db = os.path.join(self.tmp.name, "bus.db")
        self.env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": self.tmp.name,
                    "AGENT_BUS_DIR": self.tmp.name, "AGENT_WAKE_DIR": os.path.join(self.tmp.name, "wake"),
                    "AGENT_BUS_NOTARY_LOG": self.log}

    def tearDown(self):
        self.tmp.cleanup()

    def _exchange(self, bodies, record_side_effect):
        import bus_ssh_exchange as ex
        raw = json.dumps({"messages": [{"to": "hub", "body": b} for b in bodies]})
        with mock.patch.dict(os.environ, self.env, clear=False), \
                mock.patch.object(self.notary, "record", side_effect=record_side_effect):
            return ex.exchange("remote1", raw, db=self.db, attach_root=os.path.join(self.tmp.name, "att"),
                               notary=self.notary)

    def _delivered(self):
        import agent_bus as ab
        with mock.patch.dict(os.environ, self.env, clear=False):
            return [m["body"] for m in ab.recv("hub", db=self.db)]

    def _entries(self):
        return [r for r in bn.read_lines(self.log) if r.get("type") == "entry"]

    def test_write_failure_does_not_deliver_unnotarized_mail(self):
        """A napló nem írható → a határon SEMMI nem mehet át naplózatlanul."""
        res = self._exchange(["a", "b", "c"], OSError("disk full"))
        self.assertEqual(res["error"], "notary write failed (fail-closed)")
        self.assertEqual(self._entries(), [])
        self.assertEqual(self._delivered(), [],
                         "naplózatlan posta a címzett postaládájában: %r" % (self._delivered(),))

    def test_partial_write_failure_leaves_no_unnotarized_mail(self):
        """Az első tétel naplózódik, a másodiké bukik → a második sem kézbesülhet."""
        calls = {"n": 0}
        real = bn.Notary.record

        def flaky(**kw):
            calls["n"] += 1
            if calls["n"] > 1:
                raise OSError("disk full")
            return real(self.notary, **kw)
        res = self._exchange(["a", "b", "c"], flaky)
        self.assertEqual(res["error"], "notary write failed (fail-closed)")
        self.assertEqual(len(self._delivered()), len(self._entries()),
                         "kézbesítve %r, naplózva %d" % (self._delivered(), len(self._entries())))

    def test_client_retry_does_not_amplify_unnotarized_delivery(self):
        """A hívó hibát kap és újraküld — de az előző próbálkozás postája már bent van."""
        for _ in range(5):
            self._exchange(["SURGOS"], OSError("disk full"))
        self.assertEqual(self._delivered(), [],
                         "5 'fail-closed' válasz után %d másolat a postaládában" % len(self._delivered()))

    def test_omission_leaves_a_visible_gap_in_the_log(self):
        """A fenyegetés-modell állítása: 'megtagadhat/kihagyhat → rés látszik'."""
        real = self.notary.record                       # az "ép" hívások VALÓDI bejegyzést írnak
        self._exchange(["normal-1"], lambda **kw: real(**kw))
        self._exchange(["KIHAGYOTT"], OSError("disk full"))
        self._exchange(["normal-2"], lambda **kw: real(**kw))
        delivered, ents = self._delivered(), self._entries()
        rep = bn.verify(bn.read_lines(self.log), trusted_pub=self.pub)
        self.assertEqual(len(delivered), len(ents),
                         "kézbesítve %d, naplózva %d, verify.ok=%s errors=%r — rés NEM látszik"
                         % (len(delivered), len(ents), rep["ok"], rep["errors"]))


if __name__ == "__main__":
    unittest.main()
