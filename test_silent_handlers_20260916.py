"""A routine survey of SILENT exception branches — our own round.

On the capsule2 side the B arm stated the same class three times: *the ABSENCE of measurement is a third state, not
green*. On the bus side the same lives in the shape of an `except …: pass`. We did not wait for them to find it: with the AST
we measured all 28 silent branches, and looked at which one sits on an EVIDENCE-carrying path.

Three fixed:

  1. `bus_notary._audit_cross` — the SELF-CHECK of the bus audit chain sat in `except Exception: pass`. If the
     chain verifier throws for any reason (a missing field, a wrong type in the OTHER party's export), the `audit_chain_broken`
     discrepancy vanished SILENTLY, and the report stayed green. From now on `audit_chain_unverifiable` (soft) — the absence
     of measurement shows.
  2. `agent_duty._notify` — a failure of the alert hook swallowed the alert. From now on it writes to stderr that the
     alert did NOT go out.
  3. `agent_bus.replay_lifeboat` — the filter for permanent rejections failed with `pass`, so a PERMANENTLY
     rejected row could also get back into the lifeboat, silently. From now on the response's `warning` field
     states that the filtering did not run.

The other silent branches are measurably harmless (`FileExistsError` on mkdir, `BrokenPipeError` on a closed SSE etc.) — so the
test does NOT forbid all of them, but pins the three, plus states the fact of the survey.

stdlib unittest.
"""
import ast
import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad     # noqa: E402
import bus_notary as bn     # noqa: E402


class ChainSelfCheckIsNotSilent(unittest.TestCase):
    def test_a_throwing_chain_verify_becomes_a_discrepancy(self):
        """If the chain self-check throws, it SHOWS in the report (it does not vanish)."""
        rows = [{"seq": 0, "agent": "peer", "op": "ack", "from_id": 0, "to_id": 1,
                 "skipped_undelivered": 0, "prev_row_hash": "0" * 64, "row_hash": "a" * 64, "ts": 1}]
        entries = [{"type": "entry", "seq": 1, "recipient": "peer", "kind": "pickup", "decision": "accepted",
                    "cursor": {"at": 0, "pending": 0, "replies": 0, "next_id": 0}}]
        with mock.patch("agent_bus.audit_chain_verify", side_effect=RuntimeError("boom")):
            out = bn._audit_cross(entries, "peer", rows)
        types = {d["type"] for d in out}
        self.assertIn("audit_chain_unverifiable", types,
                      "the throwing chain check vanished silently: %r" % sorted(types))
        self.assertTrue(all(d.get("soft") for d in out if d["type"] == "audit_chain_unverifiable"),
                        "this is a THIRD STATE (not an accusation): soft")

    def test_control_a_working_chain_verify_still_reports_breakage(self):
        rows = [{"seq": 5, "agent": "peer", "op": "ack", "from_id": 0, "to_id": 1,
                 "skipped_undelivered": 0, "prev_row_hash": "0" * 64, "row_hash": "a" * 64, "ts": 1}]
        entries = [{"type": "entry", "seq": 1, "recipient": "peer", "kind": "pickup", "decision": "accepted",
                    "cursor": {"at": 0, "pending": 0, "replies": 0, "next_id": 0}}]
        out = bn._audit_cross(entries, "peer", rows)
        self.assertIn("audit_chain_broken", {d["type"] for d in out})


class DutyNotifyFailureIsLoud(unittest.TestCase):
    def test_a_failing_notify_hook_is_named(self):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"AGENT_DUTY_NOTIFY": "nincs_ilyen_modul:fn"}, clear=False), \
                redirect_stderr(buf):
            ad._notify("duty alert")
        self.assertIn("did NOT go out", buf.getvalue(),
                      "the alert was lost, and it stayed silent: %r" % buf.getvalue())


class TheSweepItself(unittest.TestCase):
    def test_no_new_silent_handler_on_the_evidence_paths(self):
        """No NEW bare `except: pass` may appear in the evidence-carrying modules."""
        # (measured): the budget covered THREE modules, and exactly the log's OTHER boundary point
        # (`bus_ssh_exchange.py`) was left out — the escape hatch's silent branch sat there. So the budget grows.
        watched = {"bus_notary.py": 3, "agent_bus.py": 3, "bus_enforce.py": 1, "bus_ssh_exchange.py": 0,
                   "bus_singleflight.py": 4, "agent_duty.py": 0}
        for fname, budget in watched.items():
            path = os.path.join(HERE, fname)
            if not os.path.exists(path):
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            silent = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                      and all(isinstance(st, ast.Pass) for st in n.body)]
            self.assertLessEqual(len(silent), budget,
                                 "%s: %d silent except branch(es) (budget: %d) — per line: %s"
                                 % (fname, len(silent), budget, silent))


class EveryVerdictHasACaller(unittest.TestCase):
    """a verdict no one asks for is not a signal.

    The core of their finding was that `state_dir_warnings()` ran NOWHERE outside its own unit test,
    so the matrix's "signalled" rating was not measurable. The rule generalized: every VERDICT-like
    public function (named warn/check/verify/audit/state/doctor/status/guard) must have at least one
    PRODUCTION caller — a test call does not count, because we write the tests.
    """

    def test_no_orphan_verdict_function(self):
        import collections
        defs, calls = {}, collections.Counter()
        trees = {}
        for f in sorted(os.listdir(HERE)):
            if not f.endswith(".py") or f.startswith("test_"):
                continue
            try:
                trees[f] = ast.parse(open(os.path.join(HERE, f), encoding="utf-8").read())
            except SyntaxError:
                continue
        for f, t in trees.items():
            for n in t.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"):
                    defs[(f, n.name)] = n.lineno
            for n in ast.walk(t):
                if isinstance(n, ast.Call):
                    nm = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                    if nm:
                        calls[nm] += 1
        verdictish = ("warn", "check", "verify", "audit", "doctor", "status", "guard", "health")
        orphans = ["%s:%s (line %d)" % (f, nm, ln) for (f, nm), ln in sorted(defs.items())
                   if any(v in nm.lower() for v in verdictish) and calls[nm] == 0]
        self.assertEqual(orphans, [],
                         "a verdict without a production caller — the signal reaches no one: %s" % orphans)


if __name__ == "__main__":
    unittest.main()
