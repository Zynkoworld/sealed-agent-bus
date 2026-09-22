"""(nem-Claude kar, 2026-09-15 este) leletei a javításon — regressziós tesztek."""
import json, os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_notary


def _rows(outcome_rows, sent=None, ack=0, rnd="r1"):
    rows = [{"phase": "request", "round": rnd, "sent": sent or [], "ack": ack, "received": []}]
    rows += [dict(o, phase="outcome", round=rnd) for o in outcome_rows]
    return rows


class GlmAttackRound(unittest.TestCase):
    def test_c2_first_outcome_wins_and_conflict_is_flagged(self):
        rep = bus_notary.reconcile([], "alice", _rows([{"outcome": "delivered"}, {"outcome": "unknown"}]), strict=False)
        self.assertIn("outcome_conflict", [u["type"] for u in rep["unresolved"]])

    def test_c2_conflict_fails_in_strict(self):
        rep = bus_notary.reconcile([], "alice", _rows([{"outcome": "not-sent"}, {"outcome": "delivered"}]), strict=True)
        self.assertFalse(rep["ok"])


import test_joint_error_reply_outcome as _m


class ClientOutcome(_m.ErrorReplyOutcome):
    """a partner-kar hamis-ssh keretét használja (setUp/run_round); csak a leletek esetei."""
    def test_c1_empty_stdout_is_not_delivered(self):
        self.assertNotEqual(self.run_round("", 0)["outcome"], "delivered")

    def test_b1_error_before_processing_is_not_reached(self):
        self.assertEqual(self.run_round('{"error": "oversize", "processed": false}', 0)["outcome"], "unknown")

    def test_error_reply_without_flag_is_reached(self):
        self.assertEqual(self.run_round('{"error": "busy"}', 0)["outcome"], "reached")


if __name__ == "__main__":
    unittest.main()
