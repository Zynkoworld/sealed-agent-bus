"""The trust state of the wake markers — our own.

Two fixes and two STATED limits.

  CLOSED 1 — the trust state of the marker directory showed NOWHERE until now: whoever can write there can SILENTLY
            mute an agent by creating a foreign `X.sleep_safe`, and wake it by deleting the marker
            — and they also write the audit `by` field. `state_dir_warnings()` states this, and the
            marker directory is created in strict mode (0700).
  CLOSED 2 — `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1` allows waking without a signature. It may exist (an operator
            decision), but its USE cannot be silent: the caller gets a warning.

  STATED 1 — a TOCTOU between `may_poke` and `send-keys`: the operator may type between the decision and the send.
            The "sacred typing" rule narrows it (no C-u, no blind retry), but the window exists.
  STATED 2 — "working"/"typing" detection comes from the pane's TEXT, which the agent writes itself: with a lasting fake-busy
            state an agent can be made unwakeable. The same class as for the
            duty watcher; the module is our own machine's supervision helper, NOT a trust boundary.

stdlib unittest.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_wake as aw  # noqa: E402


class WakeMarkers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state")
        self.p = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.state}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── 1: the marker directory is created in strict mode ───────────────────────
    def test_marker_dir_is_created_strict(self):
        aw.enter_sleep_safe("peer", by="operator")
        self.assertTrue(os.path.isdir(self.state))
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o700,
                         "the marker directory was not created in strict mode")
        self.assertTrue(aw.is_asleep("peer"))

    # ── 1b: a broadly permissioned directory is STATED ─────────────────────────────────
    def test_loose_marker_dir_is_named(self):
        os.makedirs(self.state, mode=0o777)
        os.chmod(self.state, 0o777)
        w = aw.state_dir_warnings()
        self.assertTrue(any("writable" in x for x in w), "the world-writable marker directory was not stated: %r" % w)

    def test_control_strict_dir_has_no_warning(self):
        os.makedirs(self.state, mode=0o700)
        if os.geteuid() == 0:
            self.assertEqual(aw.state_dir_warnings(), [], "no objection to a strict, root-owned directory")
        else:
            self.assertTrue(all("root" in x for x in aw.state_dir_warnings()))

    # ── 2: using the keyless operator switch is not silent ────────────
    def test_keyless_operator_switch_is_loud(self):
        import io
        from contextlib import redirect_stderr
        msg = {"sender": "operator", "kind": aw.KIND_WAKE, "body": "peer"}
        buf = io.StringIO()
        env = {"AGENT_WAKE_ALLOW_KEYLESS_OPERATOR": "1", "AGENT_WAKE_OPERATORS": "operator"}
        with mock.patch.dict(os.environ, env, clear=False), redirect_stderr(buf):
            aw.handle_operator_message(msg, verify=lambda m: "unsigned", has_key=False)
        self.assertIn("WITHOUT A SIGNATURE", buf.getvalue(),
                      "the keyless acceptance stayed silent: %r" % buf.getvalue())

    def test_control_without_the_switch_the_message_is_ignored(self):
        msg = {"sender": "operator", "kind": aw.KIND_WAKE, "body": "peer"}
        with mock.patch.dict(os.environ, {"AGENT_WAKE_OPERATORS": "operator"}, clear=False):
            os.environ.pop("AGENT_WAKE_ALLOW_KEYLESS_OPERATOR", None)
            self.assertEqual(aw.handle_operator_message(msg, verify=lambda m: "unsigned", has_key=False),
                             "ignored:operator-no-key")


if __name__ == "__main__":
    unittest.main()
