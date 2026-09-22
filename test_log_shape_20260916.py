"""A KÖZJEGYZŐI NAPLÓ alakja — rendszeres söprés (2026-09-16, saját kör).

Ugyanaz a módszer, amit a konformancia-korpuszon futtattunk: minden bejegyzés-mezőt egyenként törölni,
`null`-ra, `0`-ra és `"X"`-re állítani, és megnézni, mit mond a `reconcile`.

Mérés a javítás ELŐTT: 2 TRACEBACK (`envelope_sha256` törölve -> `KeyError` az összevetés közepén;
`reason: null` -> `TypeError`). A hash-lánc minden ÉRTÉK-változást elkap (a `claimed_ts_ms` valódi számra
írása is `verify_ok: false`) — a hiányzó/rossz TÍPUSÚ mező viszont összeomlasztotta a vizsgálatot.

A MÁSIK fél exportja megbízhatatlan bemenet: egy összeomlott `reconcile` semmit nem mond arról, hogy a napló
hazudott-e. A traceback nem diagnózis — ezt a szabályt a B-kar mondta ki a korpusz-oldalon, és ugyanúgy áll
itt. Innentől alak-kapu: a hiányzó vagy rossz típusú bejegyzés-mező `malformed_entry` eltérés.

stdlib unittest.
"""
import copy
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab            # noqa: E402
import bus_notary as bn           # noqa: E402
import bus_ssh_exchange as ex     # noqa: E402


class LogShapeGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.log = os.path.join(t, "n.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50, db=self.db)
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()
        for i in range(3):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        self.r1 = ex.exchange("remote1", json.dumps({}), db=self.db,
                              attach_root=os.path.join(t, "att"), notary=self.notary)
        self.top = max(m["id"] for m in self.r1["replies"])
        ex.exchange("remote1", json.dumps({"ack": self.top}), db=self.db,
                    attach_root=os.path.join(t, "att"), notary=self.notary)
        self.exp = bn.export(self.log, 1)
        self.receipts = [{"phase": "request", "sent": [], "ack": self.top, "received": self.r1["replies"],
                          "round": "r1"},
                         {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def rec(self, entries):
        return bn.reconcile(copy.deepcopy(entries), "remote1", copy.deepcopy(self.receipts), strict=True)

    def test_control_the_untouched_export_is_green(self):
        self.assertTrue(self.rec(self.exp)["ok"])

    def test_a_missing_field_is_a_diagnosis_not_a_traceback(self):
        for field in ("envelope_sha256", "reason", "recipient", "kind", "decision", "entry_hash"):
            with self.subTest(field=field):
                e = copy.deepcopy(self.exp)
                for x in e:
                    if x.get("type") == "entry":
                        x.pop(field, None)
                r = self.rec(e)                      # nem dobhat
                self.assertFalse(r["ok"])
                self.assertIn("malformed_entry", {d["type"] for d in r["discrepancies"]})

    def test_a_mistyped_field_is_a_diagnosis_too(self):
        for field, val in (("reason", None), ("seq", "X"), ("received_at_ms", None), ("kind", 0),
                           ("envelope_sha256", 0)):
            with self.subTest(field=field, val=val):
                e = copy.deepcopy(self.exp)
                for x in e:
                    if x.get("type") == "entry":
                        x[field] = val
                r = self.rec(e)
                self.assertFalse(r["ok"])
                self.assertIn("malformed_entry", {d["type"] for d in r["discrepancies"]})

    def test_malformed_garbage_must_not_hide_a_chain_break(self):
        """A nem-Claude kar köre (2026-09-16): az alak-kapu korai `return`-je „ne nézz ide" gombbá vált.

        Egy szándékos `seq: []` szeméttel a MÉLYEBB ellenőrzés (aláírás, backdate, hash-lánc) soha nem futott
        le, és a válasz ártatlan formai hibának látszott. Mostantól mindkettő fut: a rossz alakú sorokat
        kimondjuk, és a MARADÉKON lefut a `verify` — a szennyezés nem takarhatja el a lánc-törést.
        """
        e = copy.deepcopy(self.exp)
        ents = [x for x in e if x.get("type") == "entry"]
        self.assertGreaterEqual(len(ents), 2, "előfeltétel: van mit elrontani")
        ents[1]["entry_hash"] = "ab" * 32          # VALÓDI lánc-törés
        ents[0]["seq"] = []                        # …és egy formai szemét EGY MÁSIK sorban
        r = self.rec(e)
        types = {d["type"] for d in r["discrepancies"]}
        self.assertIn("malformed_entry", types)
        self.assertIn("chain_error_behind_the_malformed", types,
                      "a formai szemét elrejtette a lánc-törést: %r" % sorted(types))
        self.assertFalse(r["ok"])

    def test_the_chain_still_catches_every_value_change(self):
        """A kontroll: az alak-kapu NEM helyettesíti a hash-láncot — az érték-változást az fogja."""
        e = copy.deepcopy(self.exp)
        for x in e:
            if x.get("type") == "entry":
                x["claimed_ts_ms"] = 1_700_000_000_000
        r = self.rec(e)
        self.assertFalse(r["verify_ok"], "a hash-lánc nem vette észre a mezőváltozást")


if __name__ == "__main__":
    unittest.main()
