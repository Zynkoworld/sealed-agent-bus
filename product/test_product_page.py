"""Tests of the distribution page's GENERATOR — the page cannot claim more than the build proves.

A hand-written download page drifts: it advertises an old version, an earlier build's hash, or a chapter the
envelope measures as PENDING. So it is generated, and so it has three gates, which we MEASURE here, not assume:
a red suite -> no page; an artifact that does not fit the envelope -> no page; a missing input -> no page.
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
from version import RELEASE_VERSION  # noqa: E402 — one source; the test must not carry its own version literal

VERSION = RELEASE_VERSION
NAME = "sealed-bus-" + VERSION
import evidence as ev  # noqa: E402


@unittest.skipUnless(os.path.isfile(os.path.join(HERE, "evidence", "MANIFEST.json")), "the envelope is not built yet")
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
        """The generator reads ITS OWN tree's manifest. These tests cannot depend on what suite line currently
        stands in the repo (otherwise it is circular: the manifest also contains the result of these tests),
        so we measure on a copied tree, with a FIXED suite line."""
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
        self.assertIn(self.rel["artifact_sha256"], md)                      # the hash the installer also checks
        self.assertIn(self.rel["source_commit"], md)
        self.assertIn("--expect-sha256 " + self.rel["artifact_sha256"], md)  # the out-of-band pin ready, copyable
        self.assertIn("never count as a pass", md)                           # the meaning of PENDING/REFERENCE written out
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
        """A single modified shipped file -> the envelope no longer describes this tree -> no page."""
        with tempfile.TemporaryDirectory() as t:
            tree, dist = self.tree_with_suite("280 passed, 1 skipped in 34.68s", t)
            with open(os.path.join(tree, "bus_notary.py"), "a", encoding="utf-8") as f:
                f.write("# a line the manifest does not know\n")
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
        """The generated page goes OUT: no internal path, no internal name, no e-mail/IP."""
        import re
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        tree, dist = self.tree_with_suite("280 passed, 1 skipped in 34.68s", t.name)
        self.assertEqual(self.gen(dist=dist, tree=tree).returncode, 0)
        txt = open(os.path.join(dist, "index.md"), encoding="utf-8").read()
        # WE ASK THE FINDER FOR THE PATTERNS, we do not copy them here. This block used to carry its own copy
        # of the roster — with the old model names REPLACED on 09-20. A stale copy is worse than
        # none: it looks like a guard, but it searches for names that no longer exist, and not for the current
        # ones. This way the release page is automatically measured with TODAY's classes, and this file
        # carries not a single real name.
        sys.path.insert(0, HERE)
        import release_preflight as rp  # noqa: PLC0415 — the single source of the patterns
        pats, note, configured = rp.leak_patterns()
        for name, pat in pats:
            self.assertIsNone(re.search(pat, txt), "%s leaked onto the page (%s)" % (name, note))
        if not configured:
            self.skipTest("roster not configured (%s) — only the shape classes were measured" % rp.ROSTER_ENV)


if __name__ == "__main__":
    unittest.main()
