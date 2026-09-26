"""The waiting branch was blind to being stuck — (2026-09-17, MEDIUM-HIGH).

The finding: on the busy branch of `decide` the developers had already recognized that the "working" pattern is a self-reported state (it may be on the last frame
of a frozen pane), and alert after an hour on a byte-identical pane. One line below, the
WAITING branch had THE SAME class of error unfixed: the approval pattern unconditionally gave `none` — no clock, counter,
hash. The same byte-identical pane — busy branch 61 minutes → alert, waiting branch 61 minutes AND ten
years → none. And the pattern reads from the pane's OWN output: five innocent lines (an installer [Y/n], help output, a Hungarian log
with y/n, a python print in the source, a menu frame "Enter to select") all silenced duty.

The fix carries over the busy branch's recipe: a pane byte-identical together with the pattern above `waiting_stuck_min` =
stuck → alert (a per-type key: alerted_waiting, repeats every remind_s). A CHANGING pane with the pattern
is still waiting (none). Mutant probe: without the hash counting `test_waiting_pane_unchanged_for_an_hour_alerts`
and `test_innocent_lines_cannot_silence_the_watch_forever` fail.

stdlib unittest; `is_busy` is mocked to False (the pane is not "working").
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad  # noqa: E402

ASKING = "$ valami\nDo you want to proceed?\n❯ 1. Yes\n  2. No\n"
INNOCENT = ["Install now? (y/n)", "usage: tool --yes   do you want to skip prompts",
            "2026-09-17 log: folytassam? (y/n)", 'print("Do you want to proceed?")', "┌ Enter to select ┐"]


def _decide(st, now, pane, **kw):
    with mock.patch.object(ad.aw, "is_busy", lambda pane: False):
        return ad.decide(st, now=now, pane=pane, asleep=False, reported=0, own_prefix="x", **kw)


class WaitingIsSelfDeclaredToo(unittest.TestCase):
    def test_control_a_fresh_waiting_pane_is_none(self):
        act, st = _decide({}, 1000.0, ASKING)
        self.assertEqual(act, "none")
        self.assertIn("waiting_hash", st)

    def test_waiting_pane_unchanged_for_an_hour_alerts(self):
        # 61 minutes byte-identical → the busy branch alerts, the waiting branch did not until now
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 30 * 60, ASKING)
        self.assertEqual(act, "none")                                            # half an hour: still waiting
        act, st = _decide(st, 1000.0 + 61 * 60, ASKING)
        self.assertEqual(act, "alert")
        self.assertTrue(st.get("stuck_waiting"))
        self.assertIn("alerted_waiting", st)
        # repeats only every remind_s (a per-type key — it does not suppress the other alerts, nor they it)
        act, st = _decide(st, 1000.0 + 62 * 60, ASKING)
        self.assertEqual(act, "none")
        act, st = _decide(st, 1000.0 + 61 * 60 + 3600, ASKING)
        self.assertEqual(act, "alert")

    def test_ten_years_later_is_not_none(self):
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 10 * 365 * 86400, ASKING)
        self.assertEqual(act, "alert")

    def test_control_a_changing_waiting_pane_is_waiting_not_stuck(self):
        act, st = _decide({}, 1000.0, ASKING)
        for k in range(1, 5):
            act, st = _decide(st, 1000.0 + k * 30 * 60, ASKING + ("." * k))       # the pane changes (within two hours)
            self.assertEqual(act, "none", k)
        self.assertNotIn("stuck_waiting", st)

    def test_innocent_lines_cannot_silence_the_watch_forever(self):
        # one arm's five innocent lines: all match the pattern; after an hour unchanged it still alerts
        for line in INNOCENT:
            pane = "$ cat README\n" + line + "\n$ "
            self.assertIsNotNone(ad.WAITING.search(line), line)
            act, st = _decide({}, 1000.0, pane)
            self.assertEqual(act, "none", line)
            act, st = _decide(st, 1000.0 + 61 * 60, pane)
            self.assertEqual(act, "alert", line)

    def test_leaving_the_waiting_state_clears_its_clock(self):
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 10, "$ ")                                 # the question disappeared
        self.assertNotIn("waiting_hash", st)
        self.assertNotIn("waiting_same_since", st)
        act, st = _decide(st, 1000.0 + 61 * 60, ASKING)                          # a new question: the clock restarts
        self.assertEqual(act, "none")

    def test_threshold_is_a_parameter(self):
        t0 = 100000.0                                                            # > remind_s: the first alert does not fall into the window measured from 0
        act, st = _decide({}, t0, ASKING, waiting_stuck_min=0)                   # threshold 0: even the first frame is stuck
        self.assertEqual(act, "alert")
        act, st = _decide(st, t0 + 1, ASKING, waiting_stuck_min=0)               # within remind_s it does not repeat
        self.assertEqual(act, "none")


if __name__ == "__main__":
    unittest.main()
