"""A terjesztési oldal GENERÁTORÁNAK tesztjei — az oldal nem állíthat többet, mint amit a build bizonyít.

A kézzel írt letöltő-oldal elcsúszik: régi verziót, korábbi build hash-ét, vagy egy olyan fejezetet hirdet, amit a
boríték PENDING-nek mér. Ezért generált, és ezért van rajta három kapu, amit itt MÉRÜNK, nem feltételezünk:
piros suite -> nincs oldal; a borítékhoz nem illő artefaktum -> nincs oldal; hiányzó bemenet -> nincs oldal.
stdlib unittest."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from version import RELEASE_VERSION  # noqa: E402 — egy forrás; a teszt ne hordozzon saját verzió-literált

VERSION = RELEASE_VERSION
NAME = "sealed-bus-" + VERSION
import evidence as ev  # noqa: E402


@unittest.skipUnless(os.path.isfile(os.path.join(HERE, "evidence", "MANIFEST.json")), "a boríték még nincs megépítve")
class ReleasePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dist = os.path.join(cls.tmp.name, "dist")
        p = subprocess.run([sys.executable, os.path.join(HERE, "make_release.py"), "--version", VERSION,
                            "--commit", "HEAD", "--repo", TREE, "--out", cls.dist], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        cls.rel = json.load(open(os.path.join(cls.dist, "%s.release.json" % NAME)))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def gen(self, dist=None, tree=None):
        script = os.path.join(tree or TREE, "product", "make_release_page.py")
        return subprocess.run([sys.executable, script, "--dist", dist or self.dist, "--version", VERSION],
                              capture_output=True, text=True)

    def tree_with_suite(self, line, into):
        """A generátor a SAJÁT fája manifestjét olvassa. Ezek a tesztek nem függhetnek attól, hogy a repóban épp
        milyen suite-sor áll (különben körkörös: a manifest tartalmazza ezeknek a teszteknek az eredményét is),
        ezért másolt fán, RÖGZÍTETT suite-sorral mérünk."""
        copy = os.path.join(into, "tree")
        shutil.copytree(TREE, copy, ignore=shutil.ignore_patterns(*ev.SKIP_DIRS))
        mp = os.path.join(copy, "product", "evidence", "MANIFEST.json")
        man = json.load(open(mp, encoding="utf-8"))
        man["suite"] = line
        json.dump(man, open(mp, "w", encoding="utf-8"))
        dist = os.path.join(into, "dist")
        shutil.copytree(self.dist, dist)
        for f in ("index.md", "index.html"):
            if os.path.exists(os.path.join(dist, f)):
                os.remove(os.path.join(dist, f))
        return copy, dist

    def test_page_carries_the_artifact_identity_and_regenerates_identically(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        tree, dist = self.tree_with_suite("280 passed, 1 skipped in 34.68s", t.name)
        p = self.gen(dist=dist, tree=tree)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        md = open(os.path.join(dist, "index.md"), encoding="utf-8").read()
        self.assertIn(self.rel["artifact_sha256"], md)                      # a hash, amit a telepítő is ellenőriz
        self.assertIn(self.rel["source_commit"], md)
        self.assertIn("--expect-sha256 " + self.rel["artifact_sha256"], md)  # a csatornán kívüli pin készen, másolhatóan
        self.assertIn("never count as a pass", md)                           # a PENDING/REFERENCE jelentése kiírva
        first = (md, open(os.path.join(dist, "index.html"), encoding="utf-8").read())
        self.gen(dist=dist, tree=tree)
        self.assertEqual(first, (open(os.path.join(dist, "index.md"), encoding="utf-8").read(),
                                 open(os.path.join(dist, "index.html"), encoding="utf-8").read()))

    def test_no_page_for_a_red_suite(self):
        with tempfile.TemporaryDirectory() as t:
            copy, dist = self.tree_with_suite("1 failed, 274 passed, 1 skipped in 36.45s", t)
            p = self.gen(dist=dist, tree=copy)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("not green", p.stdout + p.stderr)
            self.assertFalse(os.path.exists(os.path.join(dist, "index.md")))

    def test_no_page_when_the_envelope_does_not_describe_the_shipped_tree(self):
        """Egyetlen módosított szállított fájl -> a boríték már nem erről a fáról szól -> nincs oldal."""
        with tempfile.TemporaryDirectory() as t:
            tree, dist = self.tree_with_suite("280 passed, 1 skipped in 34.68s", t)
            with open(os.path.join(tree, "bus_notary.py"), "a", encoding="utf-8") as f:
                f.write("# egy sor, amit a manifest nem ismer\n")
            p = self.gen(dist=dist, tree=tree)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("does not describe the shipped tree", p.stdout + p.stderr)
            self.assertIn("bus_notary.py", p.stdout + p.stderr)
            self.assertFalse(os.path.exists(os.path.join(dist, "index.md")))

    def test_no_page_without_an_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            p = self.gen(dist=t)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("missing input", p.stdout + p.stderr)

    def test_the_published_page_carries_nothing_internal(self):
        """A generált oldal KIFELÉ megy: se belső út, se belső név, se e-mail/IP."""
        import re
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        tree, dist = self.tree_with_suite("280 passed, 1 skipped in 34.68s", t.name)
        self.assertEqual(self.gen(dist=dist, tree=tree).returncode, 0)
        txt = open(os.path.join(dist, "index.md"), encoding="utf-8").read()
        # A MINTÁKAT A KERESŐTŐL KÉRJÜK, nem másoljuk ide. Ez a blokk korábban a névsor saját másolatát
        # hordozta — benne a 09-20-án LECSERÉLT régi modellnevekkel. Egy elavult másolat rosszabb, mint a
        # hiánya: úgy néz ki, mint egy őr, de olyan neveket keres, amik már nem léteznek, a jelenlegieket
        # pedig nem. Így viszont a kiadási oldal automatikusan a MAI osztályokkal van mérve, és ez a fájl
        # egyetlen valódi nevet sem hordoz.
        sys.path.insert(0, HERE)
        import release_preflight as rp  # noqa: PLC0415 — a minták egyetlen forrása
        pats, note, configured = rp.leak_patterns()
        for name, pat in pats:
            self.assertIsNone(re.search(pat, txt), "%s szivárgott az oldalra (%s)" % (name, note))
        if not configured:
            self.skipTest("névsor nincs beállítva (%s) — csak az alak-osztályok lettek mérve" % rp.ROSTER_ENV)


if __name__ == "__main__":
    unittest.main()
