"""Tests of the evidence envelope's ENGINE — validating the validator.

The floor's promise: a claim is OK only if its tests are green with the guard and RED without it. This must be measured
on the engine itself too: for an ineffective mutation the engine must cry SILENT GREEN, not OK. Likewise: the manifest
check must notice a modified, a missing and a surplus file, and the PENDING chapter must never count as OK.
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
import evidence as ev  # noqa: E402


class FloorEngine(unittest.TestCase):
    """The engine runs on a small, fast tree (not the full repo): one guard, one test, and cases built around mutations."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = os.path.join(self.tmp.name, "fa")
        os.makedirs(self.tree)
        with open(os.path.join(self.tree, "guarded.py"), "w") as f:
            f.write("def belep(x):\n    if x < 0:        # OR\n        return False\n    return True\n")
        with open(os.path.join(self.tree, "test_guard.py"), "w") as f:
            f.write("import unittest, guarded\n\n\nclass T(unittest.TestCase):\n"
                    "    def test_negativ_elutasitva(self):\n        self.assertFalse(guarded.belep(-1))\n")

    def tearDown(self):
        self.tmp.cleanup()

    def claims(self, find, replace):
        return {"claims": [{"id": "proba", "claim": "a negative input is rejected", "tests": ["test_guard.py"],
                            "peer_written": False, "mutation": {"file": "guarded.py", "find": find, "replace": replace}}]}

    def test_real_guard_removal_is_OK(self):
        r = ev.run_floor(self.tree, self.claims("    if x < 0:        # OR\n        return False\n", ""))[0]
        self.assertEqual((r["status"], r["baseline_rc"]), ("OK", 0))
        self.assertNotEqual(r["mutated_rc"], 0)

    def test_ineffective_mutation_is_reported_as_a_silent_green(self):
        """The mutation only rewrites a comment — the test stays green. That is NOT OK, but a silent green."""
        r = ev.run_floor(self.tree, self.claims("# OR", "# GUARD (rewritten comment)"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("SILENT GREEN", r["reason"])

    def test_mutation_that_does_not_apply_is_a_failure_not_a_pass(self):
        r = ev.run_floor(self.tree, self.claims("no such text", "x"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("did not apply", r["reason"])
        r2 = ev.run_floor(self.tree, self.claims("return True", "return True"))[0]   # present twice? once: ok
        self.assertIn(r2["status"], ("OK", "FAIL"))

    def test_failing_baseline_is_a_failure(self):
        with open(os.path.join(self.tree, "guarded.py"), "w") as f:
            f.write("def belep(x):\n    return True\n")                    # the guard is not in there to begin with
        r = ev.run_floor(self.tree, self.claims("return True", "return False"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("do not pass", r["reason"])


class ManifestCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = os.path.join(self.tmp.name, "fa")
        os.makedirs(os.path.join(self.tree, "product"))
        for name, body in (("a.py", "print(1)\n"), ("product/b.txt", "two\n")):
            with open(os.path.join(self.tree, name), "w", encoding="utf-8") as f:
                f.write(body)
        self.manifest = {"files": {rel: ev.sha256_file(p) for rel, p in ev.walk_tree(self.tree)}}

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_tree_has_no_problems(self):
        self.assertEqual(ev.check_manifest(self.tree, self.manifest), [])

    def test_modified_missing_and_extra_files_are_all_reported(self):
        with open(os.path.join(self.tree, "a.py"), "a") as f:
            f.write("# one character\n")
        os.remove(os.path.join(self.tree, "product", "b.txt"))
        with open(os.path.join(self.tree, "uj.py"), "w") as f:
            f.write("x = 1\n")
        problems = {p["file"]: p["problem"] for p in ev.check_manifest(self.tree, self.manifest)}
        self.assertIn("differs", problems["a.py"])
        self.assertEqual(problems["product/b.txt"], "missing")
        self.assertIn("not in the manifest", problems["uj.py"])

    def test_the_envelope_does_not_describe_itself(self):
        os.makedirs(os.path.join(self.tree, "product", "evidence"))
        with open(os.path.join(self.tree, "product", "evidence", "CLAIMS.json"), "w") as f:
            f.write("{}")
        self.assertEqual(ev.check_manifest(self.tree, self.manifest), [])


@unittest.skipUnless(os.path.isfile(os.path.join(HERE, "evidence", "MANIFEST.json")), "the envelope is not built yet")
class ShippedEnvelope(unittest.TestCase):
    """On the built envelope in the repo: the buyer's command runs, and the manifest catches a corrupted file."""

    def test_quick_verify_passes_on_this_tree(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "verify_evidence.py"), "--quick", "--json"],
                           capture_output=True, text=True, timeout=600)
        rep = json.loads(p.stdout)
        by = {c["chapter"]: c["status"] for c in rep["chapters"]}
        self.assertEqual(by["1. integrity"], "OK", rep["chapters"][0])
        self.assertIn(by["2. the notary chain bites"], ("OK", "SKIP"))
        self.assertEqual(by["4. independent arms"], "PENDING")     # a PENDING sosem OK
        self.assertEqual(p.returncode, 0)

    def test_a_modified_shipped_file_fails_chapter_one(self):
        with tempfile.TemporaryDirectory() as t:
            copy = os.path.join(t, "sealed-bus")
            shutil.copytree(TREE, copy, ignore=shutil.ignore_patterns(*ev.SKIP_DIRS))
            with open(os.path.join(copy, "bus_notary.py"), "a", encoding="utf-8") as f:
                f.write("# a line nobody asked for\n")
            p = subprocess.run([sys.executable, os.path.join(copy, "product", "verify_evidence.py"), "--quick", "--json"],
                               capture_output=True, text=True, timeout=600)
            rep = json.loads(p.stdout)
            ch1 = [c for c in rep["chapters"] if c["chapter"].startswith("1.")][0]
            self.assertEqual(ch1["status"], "FAIL")
            self.assertIn("bus_notary.py", json.dumps(ch1["problems"]))
            self.assertEqual(p.returncode, 1)


class PublicProvenance(unittest.TestCase):
    """Provenance has to say something a reader of the PUBLIC repository can actually check.

    The published v1.5.1 offered exactly one provenance field, `source_commit` — a commit of the private BUILD
    repository. The public repository is a squash export, so that object is not in it: an independent arm resolved
    it and got "bad object". The one field the envelope offered was the one field a buyer could not check, and
    v1.5.5 answered that in PROSE, which reads like a check without being one.

    Three demands replaced it, and each is measured here, because dropping any one brings the defect back:
    an anchor that is RE-DERIVED from the shipped bytes; every manifest field CLASSIFIED as re-derived or
    unverifiable-in-public; and a field that cannot be checked publicly stating its reason and what covers it."""

    def _tree(self, version="9.9.9"):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        os.makedirs(os.path.join(t, "product"))
        with open(os.path.join(t, "agent_bus.py"), "w", encoding="utf-8") as f:
            f.write("x = 1\n")
        with open(os.path.join(t, "product", "version.py"), "w", encoding="utf-8") as f:
            f.write('RELEASE_VERSION = "%s"\n' % version)
        return t

    def _manifest(self, tree, version="9.9.9"):
        files = {rel: ev.sha256_file(p) for rel, p in ev.walk_tree(tree)}
        return {"product": ev.PRODUCT, "version": version, "files": files, "file_count": len(files),
                "provenance": {"content_digest": ev.content_digest(files.items()),
                               "content_digest_recipe": ev.CONTENT_DIGEST_RECIPE,
                               "verifiable_in_public": ["content_digest", "file_count", "files", "product", "version"],
                               "unverifiable_in_public": []}}

    def _problems(self, tree, man):
        return {p["file"]: p["problem"] for p in ev.check_public_provenance(tree, man)}

    def test_a_clean_manifest_has_no_provenance_problems(self):
        tree = self._tree()
        self.assertEqual(ev.check_public_provenance(tree, self._manifest(tree)), [])

    def test_the_v151_shape_with_no_provenance_block_fails(self):
        """A manifest carrying only `source_commit`: nothing publicly re-derivable, nothing marked."""
        tree = self._tree()
        man = self._manifest(tree)
        del man["provenance"]
        man["source_commit"] = "713e7b533e53613a7510f121f63b93b606e6a214"
        problems = self._problems(tree, man)
        self.assertIn("no provenance block", " ".join(problems.values()))

    def test_the_anchor_is_re_derived_from_the_bytes_not_read_back(self):
        tree = self._tree()
        man = self._manifest(tree)
        with open(os.path.join(tree, "agent_bus.py"), "a", encoding="utf-8") as f:
            f.write("# one line nobody asked for\n")
        self.assertIn("content digest re-derived", " ".join(self._problems(tree, man).values()))

    def test_an_unclassified_field_is_a_failure_so_a_check_cannot_go_missing_quietly(self):
        tree = self._tree()
        man = self._manifest(tree)
        man["source_commit"] = "713e7b533e53613a7510f121f63b93b606e6a214"      # added, classified nowhere
        self.assertIn("neither re-derived in public nor declared", self._problems(tree, man)["MANIFEST.json:source_commit"])

    def test_the_build_commit_passes_only_when_marked_with_a_reason_and_a_cover(self):
        tree = self._tree()
        man = self._manifest(tree)
        man["source_commit"] = "713e7b533e53613a7510f121f63b93b606e6a214"
        mark = {"field": "source_commit", "value": man["source_commit"],
                "reason": "a commit of the build repository; the public mirror is a squash export",
                "covered_instead_by": "content_digest"}
        man["provenance"]["unverifiable_in_public"] = [mark]
        self.assertEqual(ev.check_public_provenance(tree, man), [], "a correctly marked field must not fail the chapter")

        man["provenance"]["unverifiable_in_public"] = [dict(mark, reason="  ")]
        self.assertIn("no reason", self._problems(tree, man)["MANIFEST.json:source_commit"])

        man["provenance"]["unverifiable_in_public"] = [dict(mark, covered_instead_by="the seal")]
        self.assertIn("covered_instead_by", self._problems(tree, man)["MANIFEST.json:source_commit"])

        # It may also say that NOTHING covers it — an honest marking has to be able to admit an open gap.
        man["provenance"]["unverifiable_in_public"] = [dict(mark, covered_instead_by=ev.UNCOVERED)]
        self.assertEqual(ev.check_public_provenance(tree, man), [])

    def test_a_field_cannot_be_declared_verifiable_without_a_check_behind_it(self):
        tree = self._tree()
        man = self._manifest(tree)
        man["suite"] = "725 passed in 52.61s"
        man["provenance"]["verifiable_in_public"].append("suite")
        self.assertIn("no check for it", self._problems(tree, man)["MANIFEST.json:suite"])

    def test_dropping_the_anchor_leaves_nothing_re_derived_and_fails(self):
        tree = self._tree()
        man = self._manifest(tree)
        man["provenance"]["verifiable_in_public"].remove("content_digest")
        self.assertIn("nothing in the provenance is re-derived", " ".join(self._problems(tree, man).values()))

    def test_the_version_is_bound_to_the_shipped_version_py(self):
        tree = self._tree(version="9.9.9")
        man = self._manifest(tree, version="1.0.0")                 # the manifest claims a version the tree denies
        self.assertIn("product/version.py says", self._problems(tree, man)["MANIFEST.json:version"])

    def test_a_field_cannot_be_both_verifiable_and_unverifiable(self):
        tree = self._tree()
        man = self._manifest(tree)
        man["provenance"]["unverifiable_in_public"] = [
            {"field": "version", "reason": "trying to have it both ways", "covered_instead_by": ev.UNCOVERED}]
        self.assertIn("both verifiable and unverifiable", self._problems(tree, man)["MANIFEST.json:version"])

    @unittest.skipUnless(shutil.which("sha256sum") and shutil.which("sort"), "coreutils are not available here")
    def test_the_published_recipe_really_reproduces_the_digest_in_a_shell(self):
        """The recipe is printed for the reader, so it has to be TRUE — a hand check must land on the same digest."""
        tree = self._tree()
        man = self._manifest(tree)
        p = subprocess.run("sha256sum %s | LC_ALL=C sort -k2 | sha256sum" % " ".join(sorted(man["files"])),
                           shell=True, cwd=tree, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split()[0], man["provenance"]["content_digest"])


@unittest.skipUnless(os.path.isfile(os.path.join(HERE, "evidence", "MANIFEST.json")), "the envelope is not built yet")
class ShippedProvenance(unittest.TestCase):
    """On the envelope actually in this tree: the anchor is there, it re-derives, and the build commit is named
    as what it is instead of being offered as a check."""

    def setUp(self):
        with open(os.path.join(HERE, "evidence", "MANIFEST.json"), encoding="utf-8") as f:
            self.man = json.load(f)

    def test_the_shipped_manifest_provenance_holds(self):
        self.assertEqual(ev.check_public_provenance(TREE, self.man), [])

    def test_the_build_commit_is_marked_unverifiable_in_public(self):
        marked = {e["field"]: e for e in self.man["provenance"]["unverifiable_in_public"]}
        self.assertIn("source_commit", marked, "the build-repo commit is offered without a marking")
        self.assertTrue(marked["source_commit"]["reason"].strip())
        self.assertEqual(marked["source_commit"]["covered_instead_by"], "content_digest")

    def test_the_verifier_prints_the_limit_it_cannot_check(self):
        notes = ev.provenance_notes(self.man)
        self.assertTrue(any(n.startswith("source_commit: NOT verifiable in public") for n in notes), notes)


class PublishFurniture(unittest.TestCase):
    """The published repo gets landing files ON TOP OF the sealed product. The envelope said "not in the
    manifest" about them, and the published v1.5.1 therefore failed its OWN verifier — an independent arm measured it.

    The fix is not that the verifier becomes more lenient: the hole has EXACT NAMES, the verifier STATES what
    the seal does not cover, and every other surplus file is still a failure."""

    def _tree(self, files):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        for rel, body in files.items():
            p = os.path.join(t, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write(body)
        return t

    def _manifest(self, tree, rels):
        return {"files": {rel: ev.sha256_file(os.path.join(tree, rel)) for rel in rels}}

    def test_furniture_does_not_break_the_seal_but_is_named(self):
        tree = self._tree({"agent_bus.py": "x = 1\n", "README.md": "# landing\n", "SECURITY.md": "report here\n"})
        man = self._manifest(tree, ["agent_bus.py"])
        self.assertEqual(ev.check_manifest(tree, man), [], "the furniture failed the seal")
        self.assertEqual(ev.unsealed_present(tree), ["README.md", "SECURITY.md"],
                         "the verifier does not state what the seal does NOT cover")

    def test_any_other_unlisted_file_is_still_a_failure(self):
        tree = self._tree({"agent_bus.py": "x = 1\n", "smuggled.py": "import os\n"})
        problems = ev.check_manifest(tree, self._manifest(tree, ["agent_bus.py"]))
        self.assertEqual([p["file"] for p in problems], ["smuggled.py"])

    def test_a_listed_furniture_file_is_still_hash_checked(self):
        """If the furniture GETS INTO the manifest, it is part of the seal from then on — the exception only covers absence."""
        tree = self._tree({"agent_bus.py": "x = 1\n", "README.md": "# landing\n"})
        man = self._manifest(tree, ["agent_bus.py", "README.md"])
        open(os.path.join(tree, "README.md"), "w", encoding="utf-8").write("# tampered\n")
        problems = ev.check_manifest(tree, man)
        self.assertEqual([p["problem"] for p in problems], ["content differs from the manifest"])

    def test_the_exemption_is_names_not_a_directory(self):
        """A directory-shaped exception grows by itself as the directory fills up — this hole must not grow."""
        for name in ev.UNSEALED:
            self.assertFalse(name.endswith("/"), name)
            self.assertNotIn("*", name)
            self.assertFalse(os.path.isabs(name), name)
        self.assertLessEqual(len(ev.UNSEALED), 5, "the furniture list is silently widening")


if __name__ == "__main__":
    unittest.main()
