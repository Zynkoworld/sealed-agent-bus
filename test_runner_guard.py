"""Runner guard: `python3 -m unittest discover` SILENTLY skips pytest-style (bare `def test_*`) tests
and prints "OK" — so the full suite runs ONLY with `python3 -m pytest -q`. This test fails LOUDLY under
unittest, so that no one believes the truncated run is green."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _bare_pytest_files():
    out = []
    for fn in sorted(os.listdir(HERE)):
        if fn.startswith("test_") and fn.endswith(".py"):
            with open(os.path.join(HERE, fn), encoding="utf-8") as f:
                if re.search(r"^def test_", f.read(), re.M):
                    out.append(fn)
    return out


class RunnerGuard(unittest.TestCase):
    def test_full_suite_needs_pytest(self):
        bare = _bare_pytest_files()
        if bare and "_pytest" not in sys.modules:
            self.fail("The full test suite runs ONLY with `python3 -m pytest -q` — under unittest these files "
                      "are silently left out: %s" % ", ".join(bare))


if __name__ == "__main__":
    unittest.main()
