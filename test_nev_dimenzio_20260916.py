"""The NAME dimension on the notary log — our own round with the non-Claude arm.

On the capsule2 side the B arm reopened the same finding FIVE times, each time one dimension further:
missing field -> empty string -> `null` -> wrong TYPE -> unknown field NAME. On the bus side we did not
wait for the fifth, we measured it:

  * an arbitrary `operator_note` field added to an entry -> `ok=true`, 0 discrepancies, and
    `entry_hash(e) == entry_hash(e + unknown field)` — the hash covers the FIXED `ENTRY_KEYS`, so it is
    content carried in a hash-CHAINED log that the chain does NOT authenticate;
  * the same on the SIGNED `checkpoint` row, on which until then NO shape gate ran;
  * deleting the checkpoint's `type` field makes the row stop looking like a checkpoint -> the notary's signed anchor
    SILENTLY disappears from the report, `ok` stays green;
  * deleting its `seq` or its signature gave `ok=false`, but `discrepancies: []` and `errors: null` —
    a red verdict WITHOUT A NAMED REASON.

The shape of the fix was set by the non-Claude arm's round, and its main objection was CORRECT: a whitelist
REJECTION would turn an upgraded partner's log red AS A WHOLE (forward compatibility, rolling
version upgrades, external correlation ids), and then no one would dare raise a version. So:

  NEW, well-formed field name      -> `unauthenticated_field` NOTE + report column, the verdict does NOT change
  a name SHADOWING a chained key   -> `shadowing_field`, ACCUSATION (`entry_hash ` with a trailing space is aimed at the reader's eye)
  a row without a type / wrong type -> `row_type_missing`, ACCUSATION
  `verify()`'s errors              -> in the report as `verify_error` (the verdict does not change from this either)

stdlib unittest.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _round(t):
    os.environ.update({"AGENT_BUS_DB": os.path.join(t, "bus.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                       "AGENT_BUS_MODE": "dev", "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
                       "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_WAKE_DIR": os.path.join(t, "wake"),
                       "AGENT_BUS_AUTO_SIGN": "0"})
    import agent_bus as ab
    import bus_notary as bn
    import bus_ssh_exchange as ex
    db, log = os.environ["AGENT_BUS_DB"], os.path.join(t, "n.jsonl")
    seed, pub = bn.keypair()
    notary = bn.Notary(log, seed=seed, checkpoint_every=2, db=db)   # DENSE: there should be a signed row too
    for i in range(3):
        ab.send("hub", "remote1", "ki-%d" % i, db=db, mirror=False)
    r1 = ex.exchange("remote1", json.dumps({}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    top = max(m["id"] for m in r1["replies"])
    ex.exchange("remote1", json.dumps({"ack": top}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    exp = bn.export(log, 1)
    c = ab._conn(db)
    try:
        rows = [dict(x) for x in c.execute(
            "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
            "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
    finally:
        c.close()
    receipts = [{"phase": "request", "sent": [], "ack": top, "received": r1["replies"], "round": "r1"},
                {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]

    def run(ents):
        return bn.reconcile(copy.deepcopy(ents), "remote1", copy.deepcopy(receipts), strict=True,
                            bus_audit=copy.deepcopy(rows), trusted_pub=pub)
    return bn, exp, run


class NameDimension(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.bn, self.exp, self.run = _round(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def _tamper(self, row_type, fn):
        ents = copy.deepcopy(self.exp)
        for e in ents:
            if e.get("type") == row_type:
                fn(e)
        return self.run(ents)

    def test_control_an_untouched_export_is_green_and_quiet(self):
        """The HONEST partner's round stays green, and does NOT get a single new note."""
        rep = self.run(self.exp)
        self.assertTrue(rep["ok"], rep["discrepancies"])
        self.assertEqual(rep.get("notes"), [])
        self.assertEqual(rep["counts"]["unauthenticated_fields"], 0)
        self.assertEqual(rep["counts"]["shadowing_fields"], 0)
        self.assertEqual(rep["counts"]["rows_without_type"], 0)

    def test_the_chain_does_not_cover_an_unknown_field(self):
        """The PREMISE that makes the whole thing finding-grade — measured, not assumed."""
        e = [x for x in self.exp if x.get("type") == "entry"][0]
        before = self.bn.entry_hash(e)
        e2 = dict(e)
        e2["operator_note"] = "4200 capsules received, sorted"
        self.assertEqual(before, self.bn.entry_hash(e2),
                         "if the hash COVERED the unknown field, this test class would be moot")

    def test_a_new_field_name_is_named_but_does_not_flip_the_verdict(self):
        """Forward compatibility: a field from a NEWER notary version does not turn the partner's log red…"""
        rep = self._tamper("entry", lambda e: e.__setitem__("operator_note", "4200 capsules sorted"))
        self.assertTrue(rep["ok"], "a new field name turned the log red AS A WHOLE: %r" % rep["discrepancies"])
        # …but it does not stay SILENT either: the chain does not cover it, and that must be stated
        self.assertGreater(rep["counts"]["unauthenticated_fields"], 0)
        self.assertTrue(any(n["type"] == "unauthenticated_field" for n in rep["notes"]),
                        "the unauthenticated field is not named: %r" % rep["notes"])

    def test_a_shadowing_field_name_is_an_accusation(self):
        """`entry_hash ` (with a trailing space) and `Entry_hash`: not forward compatibility, aimed at the reader's eye."""
        for nm in ("entry_hash ", "Entry_hash", "prev_HASH", "cursor."):
            rep = self._tamper("entry", lambda e, nm=nm: e.__setitem__(nm, "a" * 64))
            self.assertFalse(rep["ok"], "the shadowing %r passed silently" % nm)
            self.assertTrue(any(d["type"] == "shadowing_field" for d in rep["discrepancies"]),
                            "%r is not named: %r" % (nm, rep["discrepancies"]))

    def test_the_signed_checkpoint_row_is_measured_too(self):
        """Until then NO shape gate at all ran on the SIGNED row."""
        rep = self._tamper("checkpoint", lambda e: e.__setitem__("parancs_szeru", "IGNORE_PREVIOUS"))
        self.assertTrue(any(n["type"] == "unauthenticated_field" and n.get("row_type") == "checkpoint"
                            for n in rep["notes"]), rep["notes"])
        for field in ("seq", "sig", "head_hash", "notary_pub"):
            rep = self._tamper("checkpoint", lambda e, f=field: e.pop(f, None))
            self.assertFalse(rep["ok"], "deleting the checkpoint's %s left the report green" % field)
            self.assertTrue(rep["discrepancies"],
                            "A RED VERDICT WITHOUT A NAMED REASON for deleting %s" % field)

    def test_a_row_that_does_not_say_what_it_is(self):
        """Deleting `type` on the checkpoint makes the SIGNED ANCHOR disappear — this cannot stay silent."""
        for val in (None, 0, [], ""):
            def f(e, v=val):
                if v is None:
                    e.pop("type", None)
                else:
                    e["type"] = v
            ents = copy.deepcopy(self.exp)
            for e in ents:
                if e.get("type") == "checkpoint":
                    f(e)
            rep = self.run(ents)                      # there must NEVER be a traceback
            self.assertFalse(rep["ok"], "with type=%r the report stayed green" % (val,))
            self.assertTrue(any(d["type"] == "row_type_missing" for d in rep["discrepancies"]),
                            "type=%r is not named: %r" % (val, rep["discrepancies"]))

    def test_a_red_verdict_always_names_a_reason(self):
        """THE CLOSING RULE: if `ok=false`, there must be at least one named discrepancy. No red without a reason."""
        cases = {
            "entry_hash forged": ("entry", lambda e: e.__setitem__("entry_hash", "b" * 64)),
            "prev_hash forged": ("entry", lambda e: e.__setitem__("prev_hash", "c" * 64)),
            "checkpoint signature deleted": ("checkpoint", lambda e: e.pop("sig", None)),
            "checkpoint seq deleted": ("checkpoint", lambda e: e.pop("seq", None)),
        }
        for nm, (ty, fn) in cases.items():
            rep = self._tamper(ty, fn)
            if rep["ok"]:
                continue
            self.assertTrue(rep["discrepancies"],
                            "%s: ok=false, but the report does NOT say why" % nm)


if __name__ == "__main__":
    unittest.main()
