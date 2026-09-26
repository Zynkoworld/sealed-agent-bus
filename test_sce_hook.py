"""sce_hook: only a hook point — no decider → no decision; a faulty decider → ABORT. stdlib unittest."""
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sce_hook  # noqa: E402

ENVS = [{"id": 1, "sender": "armA", "body": "{}", "sds": "valid"},
        {"id": 2, "sender": "armB", "body": "{}", "sds": "valid"},
        {"id": 3, "sender": "armC", "body": "{}", "sds": "valid"}]


def fake_decider(envs):
    ok = len(envs) == 3 and all(e["sds"] == "valid" for e in envs)
    return {"verdict": "ACCEPT" if ok else "ABORT", "n": len(envs)}


class SceHookTest(unittest.TestCase):
    def test_no_decider_no_decision(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(sce_hook.ENV, None)
            self.assertIsNone(sce_hook.decide(ENVS))

    def test_env_loaded_fake_decider(self):
        mod = types.ModuleType("fake_sce_mod")
        mod.decide = fake_decider
        with mock.patch.dict(sys.modules, {"fake_sce_mod": mod}), \
             mock.patch.dict(os.environ, {sce_hook.ENV: "fake_sce_mod:decide"}):
            self.assertEqual(sce_hook.decide(ENVS), {"verdict": "ACCEPT", "n": 3})
            self.assertEqual(sce_hook.decide(ENVS[:2])["verdict"], "ABORT")

    def test_bad_decider_fail_closed(self):
        self.assertEqual(sce_hook.decide(ENVS, decider=lambda e: 1 / 0)["verdict"], "ABORT")
        self.assertEqual(sce_hook.decide(ENVS, decider=lambda e: {"verdict": "MAYBE"})["verdict"], "ABORT")
        self.assertEqual(sce_hook.decide(ENVS, decider=lambda e: {"strength": 0.9})["verdict"], "ABORT")
        self.assertEqual(sce_hook.decide(ENVS, spec="no_such_module_xyz:decide")["verdict"], "ABORT")

    def test_envelopes_from_rows(self):
        rows = [{"id": 1, "kind": "msg", "body": "x"}, {"id": 2, "kind": "sds-envelope", "sender": "s", "body": "b", "sds": "valid"}]
        self.assertEqual(sce_hook.envelopes_from_rows(rows), [{"id": 2, "sender": "s", "body": "b", "sds": "valid"}])


if __name__ == "__main__":
    unittest.main()
