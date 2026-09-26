"""The round's CLOSING anchor — the OPEN row 2.7 of the attack matrix.

The open row's text was: "consistent re-chaining of the second record on a single-round slice — the anchor
is written at the START of the round, it does not bind its own round's ack row."

Measured: the round's OPENING anchor binds to the head of the bus audit chain AT THAT TIME. The round's OWN rows (the audit rows of
`mark_delivered` and `ack`) arise AFTER that — so an attacker could consistently re-chain a single-round export above the
anchor (the chain stays internally intact, the anchor binds the START of the slice, not its end).

The fix: at the END of the round, after every side effect, a `round_close` entry, into which the anchor — like the opening
anchor — is computed by the NOTARY (`audit_end_seq` + `audit_end_hash`), not by the writer. The opening
entry COMMITS to the close with `closes: 1`; the commitment travels in the hash-chained entry, so cutting off the closing
anchor afterwards is evidence (`audit_close_missing`), while old rounds without the commitment
stay green (no retroactive reddening).

STATED limit: the closing write is fail-OPEN (the mail has already gone out by then, it cannot be fail-closed) — the error is stated by the response's
`round_close: "failed"` field and reconcile's `audit_close_missing` discrepancy. Full closure
is still an external witness (v1.7, the operator's decision).

stdlib unittest.
"""
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


class RoundCloseAnchor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.log = os.path.join(t, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50, db=self.db)
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── the round: two messages delivered, then ack ─────────────────────────────
    def round_trip(self):
        for i in range(2):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        res = ex.exchange("remote1", json.dumps({}), db=self.db,
                          attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        top = max(m["id"] for m in res["replies"])
        ex.exchange("remote1", json.dumps({"ack": top}), db=self.db,
                    attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        return res, top

    def audit_rows(self):
        c = ab._conn(self.db)
        try:
            return [dict(r) for r in c.execute(
                "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
                "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
        finally:
            c.close()

    def rechain(self, rows, *, drop_last=True):
        """The attacker CONSISTENTLY re-chains: drops the round's own (last) row, and recomputes the rest so
        that the chain stays internally intact. This is the exact shape of row 2.7."""
        keep = rows[:-1] if drop_last else list(rows)
        out, prev = [], ab._GENESIS
        for r in keep:
            n = dict(r, prev_row_hash=prev)
            n["row_hash"] = ab._audit_row_hash(n["seq"], n["ts"], n["agent"], n["op"], n["from_id"],
                                               n["to_id"], n["skipped_undelivered"], prev)
            prev = n["row_hash"]
            out.append(n)
        return out

    def reconcile(self, bus_audit, entries=None):
        res, top = getattr(self, "_rt", (None, None))
        receipts = [{"phase": "request", "sent": [], "ack": top, "received": res["replies"], "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = entries if entries is not None else bn.export(self.log, 1)
        return bn.reconcile(exp, "remote1", receipts, strict=True, bus_audit=bus_audit)

    # ── control: an honest round is green with the closing anchor too ─────────────────
    def test_control_honest_round_with_close_is_green(self):
        self._rt = self.round_trip()
        r = self.reconcile(self.audit_rows())
        self.assertTrue(r["ok"], "the honest round is not green: %r / %r" % (r["discrepancies"], r["unresolved"]))

    # ── the closing anchor REALLY exists, and the notary wrote it ──────────────
    def test_close_entry_carries_a_notary_computed_anchor(self):
        self._rt = self.round_trip()
        ents = [e for e in bn.read_lines(self.log) if e.get("type") == "entry"]
        closes = [e for e in ents if e["kind"] == "round_close"]
        self.assertTrue(closes, "there is no round-close entry")
        c = closes[-1]["cursor"]
        self.assertIn("audit_end_seq", c)
        self.assertRegex(str(c.get("audit_end_hash")), r"^[0-9a-f]{64}$")
        rows = self.audit_rows()
        self.assertEqual(c["audit_end_seq"], rows[-1]["seq"] if rows else 0,
                         "the closing anchor does not point to the chain head AFTER the round")
        opens = [e for e in ents if e["kind"] == "pickup" and e["decision"] == "accepted"]
        self.assertEqual(opens[0]["cursor"].get("closes"), 1, "the opening entry did not COMMIT to the close")
        # the closing entry stands after EVERY side effect of the round
        self.assertGreater(closes[0]["seq"], max(e["seq"] for e in ents if e["kind"] == "pickup"
                                                 and e["decision"] == "delivered"))

    # ── THE FINDING: consistent re-chaining of a single-round slice ───────────────
    def test_consistently_rechained_single_round_slice_is_caught(self):
        # IMPORTANT: a SINGLE round. The two-round variant is already caught by the NEXT round's opening anchor — that was
        # the partial mitigation in the matrix. Row 2.7 was exactly about the single-round slice, where the opening anchor
        # binds the START of the round, and there is nothing after the round's own rows. Here only the CLOSING anchor can remain a witness.
        for i in range(2):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        res = ex.exchange("remote1", json.dumps({}), db=self.db,
                          attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        self._rt = (res, max(m["id"] for m in res["replies"]))
        rows = self.audit_rows()
        self.assertGreaterEqual(len(rows), 2, "precondition: the round has its own audit row")
        faked = self.rechain(rows)                     # the round's OWN row removed, the chain internally intact
        chk = ab.audit_chain_verify(faked)
        self.assertTrue(chk["ok"], "precondition: the forged chain is INTERNALLY intact (otherwise this is not the finding)")
        r = self.reconcile(faked)
        self.assertFalse(r["ok"], "the consistently re-chained single-round slice got green")
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertTrue({"audit_close_not_covered", "audit_close_hash_mismatch"} & types,
                        "it was not the CLOSING anchor that caught it, but something else: %r" % sorted(types))

    # ── cutting off the closing entry: evidence because of the COMMITMENT ───────────────
    def test_stripping_the_close_entry_is_evidence(self):
        self._rt = self.round_trip()
        ents = [e for e in bn.export(self.log, 1) if not (e.get("type") == "entry" and e.get("kind") == "round_close")]
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertIn("audit_close_missing", types,
                      "a committed yet missing close passed silently: %r" % sorted(types))
        self.assertFalse(r["ok"])

    # ── the non-Claude arm's round ON this fix  ──────────
    def test_close_anchor_may_not_point_at_an_older_head(self):
        """(1) If the close were written BEFORE the side effects, the anchor would point to the chain head BEFORE the round — the round's own
        rows would be unbound again. The anchor is MONOTONIC: the head at the end of the round cannot be before the one at its start."""
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if (e.get("type") == "entry" and e.get("kind") == "round_close"
                    and isinstance(e.get("cursor"), dict) and e["cursor"].get("audit_end_seq", 0) > 0):
                e = dict(e, cursor=dict(e["cursor"], audit_end_seq=0))     # "the head at the start of the round"
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]}
        self.assertIn("audit_close_before_open", types,
                      "a closing anchor pointing to the START of the round passed: %r" % sorted(types))

    def test_a_close_that_names_another_round_does_not_count(self):
        """(2) Order only restrains; the close NAMES its round. A close belonging elsewhere cannot make
        an unclosed round closed."""
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if (e.get("type") == "entry" and e.get("kind") == "round_close"
                    and isinstance(e.get("cursor"), dict) and "round_seq" in e["cursor"]):
                e = dict(e, cursor=dict(e["cursor"], round_seq=e["cursor"]["round_seq"] + 100))
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {u["type"] for u in r["unresolved"]}
        self.assertIn("audit_close_missing", types,
                      "a close naming ANOTHER round showed this round as closed: %r" % sorted(types))

    def test_unclosed_rounds_are_counted_not_just_soft(self):
        """(3) "Every round unclosed" cannot disappear in the soft noise: the report gives a NUMBER for it."""
        self._rt = self.round_trip()
        ok = self.reconcile(self.audit_rows())
        self.assertGreaterEqual(ok["counts"]["rounds_pledged"], 1)
        self.assertEqual(ok["counts"]["rounds_unclosed"], 0, "honest rounds counted as unclosed")
        ents = [e for e in bn.export(self.log, 1)
                if not (e.get("type") == "entry" and e.get("kind") == "round_close")]
        bad = self.reconcile(self.audit_rows(), entries=ents)
        self.assertEqual(bad["counts"]["rounds_unclosed"], bad["counts"]["rounds_pledged"],
                         "the number of unclosed rounds cannot be measured from the report")

    # ── an OLD round that did not commit to closing does not turn red retroactively ──────────
    def test_old_round_without_the_pledge_is_not_accused(self):
        self._rt = self.round_trip()
        ents = []
        for e in bn.export(self.log, 1):
            if e.get("type") == "entry" and e.get("kind") == "round_close":
                continue                                # the old version wrote no close…
            if (e.get("type") == "entry" and e.get("kind") == "pickup" and e.get("decision") == "accepted"
                    and isinstance(e.get("cursor"), dict)):
                e = dict(e, cursor={k: v for k, v in e["cursor"].items() if k != "closes"})   # …and did not commit either
            ents.append(e)
        r = self.reconcile(self.audit_rows(), entries=ents)
        types = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertNotIn("audit_close_missing", types, "we demanded the close from the old round too")


if __name__ == "__main__":
    unittest.main()
