"""Futtató-őr: a `python3 -m unittest discover` a pytest-stílusú (bare `def test_*`) teszteket
CSENDBEN kihagyja, és „OK"-t ír — ezért a teljes készlet CSAK `python3 -m pytest -q`-val fut le. Ez a teszt unittest
alatt HANGOSAN bukik, hogy senki ne higgye zöldnek a csonka futást."""
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
            self.fail("A teljes tesztkészlet CSAK `python3 -m pytest -q`-val fut le — unittest alatt ezek a fájlok "
                      "csendben kimaradnak: %s" % ", ".join(bare))


if __name__ == "__main__":
    unittest.main()
