"""A CI zárványa pinelje ÖNMAGÁT — a támadási mátrix 7.2-es nyitott sora (2026-09-16).

A sor szövege eddig: „a `requirements-ci.txt` nem pineli önmagát — NYITVA (kimondva)".

A `--require-hashes` a CSOMAGOKAT köti, a listát magát nem: aki a closure-t kicseréli, a benne lévő hash-eket
is átírja, és a pip boldogan telepíti az ÚJ listát. A fájl digestje ezért a WORKFLOW-ban áll (`CLOSURE_SHA256`),
tehát a cseréhez KÉT egyidejű szerkesztés kell, és mindkettő látszik a PR diffjében.

Ez a teszt a repóban méri ugyanazt, amit a CI lépése: ha valaki a closure-t módosítja és a workflow pinjét nem
(vagy fordítva), az NÁLUNK is piros lesz, nem csak a runneren.

KIMONDVA: ez a 7.2-t zárja, NEM a 7.1-et — a workflow-fájl maga a HEAD-en él, azt repó-beállítás (required
status check) zárja, ami tulajdonosi döntés.

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
                self.skipTest("nincs meg: %s" % p)
        self.wf = open(WF, encoding="utf-8").read()

    def test_the_workflow_pins_the_closure_digest(self):
        self.assertTrue(_pins(self.wf), "a workflow nem pineli a closure digestjét (7.2 nyitva maradna)")

    def test_the_pin_matches_the_file(self):
        got = hashlib.sha256(open(CLOSURE, "rb").read()).hexdigest()
        for want in _pins(self.wf):
            self.assertEqual(want, got,
                             "a workflow CLOSURE_SHA256 pinje (%s…) nem egyezik a requirements-ci.txt "
                             "digestjével (%s…) — a closure megváltozott, a pin nem" % (want[:12], got[:12]))

    def test_the_check_runs_before_the_install(self):
        i_pin = self.wf.find("CLOSURE_SHA256")
        m = re.search(r"pip install [^\n]*--require-hashes", self.wf)   # a VALÓDI telepítő sor, nem a fejléc-komment
        i_install = m.start() if m else -1
        self.assertNotEqual(i_pin, -1)
        self.assertNotEqual(i_install, -1, "nincs valódi `pip install --require-hashes` sor a workflow-ban")
        self.assertLess(i_pin, i_install, "a pin-ellenőrzés a telepítés UTÁN fut — akkor már késő")

    def test_the_install_stays_fail_closed(self):
        self.assertIn("--require-hashes", self.wf, "a hash-kényszer eltűnt a telepítésből")
        self.assertIn("--no-deps", self.wf, "a --no-deps eltűnt: a closure már nem zárt")


if __name__ == "__main__":
    unittest.main()
