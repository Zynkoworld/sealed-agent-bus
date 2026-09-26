"""The CI closure pins ITSELF — the open row 7.2 of the attack matrix (2026-09-16).

The row's text until now: "`requirements-ci.txt` does not pin itself — OPEN (stated)".

`--require-hashes` binds the PACKAGES, not the list itself: whoever swaps the closure also rewrites the hashes
in it, and pip happily installs the NEW list. So the file's digest lives in the WORKFLOW (`CLOSURE_SHA256`),
so the swap takes TWO simultaneous edits, and both show in the PR diff.

This test measures in the repo the same thing as the CI step: if someone modifies the closure but not the workflow pin
(or vice versa), it goes red HERE too, not only on the runner.

STATED: this closes 7.2, NOT 7.1 — the workflow file itself lives at HEAD, which a repo setting (a required
status check) closes, an owner decision.

stdlib unittest.
"""
import hashlib
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WF = os.path.join(HERE, ".github", "workflows", "tests.yml")
CLOSURE = os.path.join(HERE, "requirements-ci.txt")


def _pins(text):
    return re.findall(r"CLOSURE_SHA256:\s*([0-9a-f]{64})", text)


class ClosurePinsItself(unittest.TestCase):
    def setUp(self):
        for p in (WF, CLOSURE):
            if not os.path.exists(p):
                self.skipTest("missing: %s" % p)
        self.wf = open(WF, encoding="utf-8").read()

    def test_the_workflow_pins_the_closure_digest(self):
        self.assertTrue(_pins(self.wf), "the workflow does not pin the closure digest (7.2 would stay open)")

    def test_the_pin_matches_the_file(self):
        got = hashlib.sha256(open(CLOSURE, "rb").read()).hexdigest()
        for want in _pins(self.wf):
            self.assertEqual(want, got,
                             "the workflow's CLOSURE_SHA256 pin (%s…) does not match the digest of requirements-ci.txt "
                             "(%s…) — the closure changed, the pin did not" % (want[:12], got[:12]))

    def test_the_check_runs_before_the_install(self):
        i_pin = self.wf.find("CLOSURE_SHA256")
        m = re.search(r"pip install [^\n]*--require-hashes", self.wf)   # the REAL install line, not the header comment
        i_install = m.start() if m else -1
        self.assertNotEqual(i_pin, -1)
        self.assertNotEqual(i_install, -1, "there is no real `pip install --require-hashes` line in the workflow")
        self.assertLess(i_pin, i_install, "the pin check runs AFTER the install — by then it is too late")

    def test_the_install_stays_fail_closed(self):
        self.assertIn("--require-hashes", self.wf, "the hash enforcement disappeared from the install")
        self.assertIn("--no-deps", self.wf, "--no-deps disappeared: the closure is no longer closed")


if __name__ == "__main__":
    unittest.main()
