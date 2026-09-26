"""The SHAPE of the NOTARY LOG — a routine sweep (2026-09-16, our own round).

The same method we ran on the conformance corpus: delete every entry field one by one, set it to
`null`, `0` and `"X"`, and see what `reconcile` says.

Measurement BEFORE the fix: 2 TRACEBACKS (`envelope_sha256` deleted -> `KeyError` in the middle of the comparison;
`reason: null` -> `TypeError`). The hash chain catches every VALUE change (writing a real number into `claimed_ts_ms`
also gives `verify_ok: false`) — but a missing/wrongly TYPED field crashed the examination.

The OTHER party's export is untrusted input: a crashed `reconcile` says nothing about whether the log
lied. A traceback is not a diagnosis — the B arm stated this rule on the corpus side, and it holds here
just the same. From now on a shape gate: a missing or wrongly typed entry field is a `malformed_entry` discrepancy.

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
                r = self.rec(e)                      # must not raise
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
        """The non-Claude arm's round (2026-09-16): the shape gate's early `return` became a "don't look here" button.

        With deliberate `seq: []` garbage the DEEPER check (signature, backdate, hash chain) never ran,
        and the answer looked like an innocent formatting error. From now on both run: the malformed rows are
        stated, and `verify` runs on the REST — the pollution cannot hide a chain break.
        """
        e = copy.deepcopy(self.exp)
        ents = [x for x in e if x.get("type") == "entry"]
        self.assertGreaterEqual(len(ents), 2, "precondition: there is something to spoil")
        ents[1]["entry_hash"] = "ab" * 32          # a REAL chain break
        ents[0]["seq"] = []                        # …and formal garbage in ANOTHER row
        r = self.rec(e)
        types = {d["type"] for d in r["discrepancies"]}
        self.assertIn("malformed_entry", types)
        self.assertIn("chain_error_behind_the_malformed", types,
                      "the formal garbage hid the chain break: %r" % sorted(types))
        self.assertFalse(r["ok"])

    def test_the_chain_still_catches_every_value_change(self):
        """The control: the shape gate does NOT replace the hash chain — the value change is caught by that."""
        e = copy.deepcopy(self.exp)
        for x in e:
            if x.get("type") == "entry":
                x["claimed_ts_ms"] = 1_700_000_000_000
        r = self.rec(e)
        self.assertFalse(r["verify_ok"], "the hash chain did not notice the field change")


if __name__ == "__main__":
    unittest.main()
