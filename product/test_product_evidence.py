"""A bizonyíték-boríték MOTORJÁNAK tesztjei — a validáló validálása.

A padló ígérete: egy állítás csak akkor OK, ha a tesztjei zöldek a védelemmel és PIROSAK nélküle. Ezt magán a motoron
is meg kell mérni: egy hatástalan mutációra a motornak NÉMA ZÖLD-et kell kiáltania, nem OK-t. Ugyanígy: a manifest-
ellenőrzés vegye észre a módosított, hiányzó és többlet-fájlt, és a PENDING fejezet sose számítson OK-nak.
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
    """A motor kis, gyors fán fut (nem a teljes repón): egy őr, egy teszt, és mutációk köré épített esetek."""

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
        return {"claims": [{"id": "proba", "claim": "a negatív bemenet elutasítva", "tests": ["test_guard.py"],
                            "peer_written": False, "mutation": {"file": "guarded.py", "find": find, "replace": replace}}]}

    def test_real_guard_removal_is_OK(self):
        r = ev.run_floor(self.tree, self.claims("    if x < 0:        # OR\n        return False\n", ""))[0]
        self.assertEqual((r["status"], r["baseline_rc"]), ("OK", 0))
        self.assertNotEqual(r["mutated_rc"], 0)

    def test_ineffective_mutation_is_reported_as_a_silent_green(self):
        """A mutáció csak egy megjegyzést ír át — a teszt zöld marad. Ez NEM OK, hanem néma zöld."""
        r = ev.run_floor(self.tree, self.claims("# OR", "# ŐR (átírt megjegyzés)"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("SILENT GREEN", r["reason"])

    def test_mutation_that_does_not_apply_is_a_failure_not_a_pass(self):
        r = ev.run_floor(self.tree, self.claims("nincs ilyen szöveg", "x"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("did not apply", r["reason"])
        r2 = ev.run_floor(self.tree, self.claims("return True", "return True"))[0]   # kétszer szerepel? egyszer: ok
        self.assertIn(r2["status"], ("OK", "FAIL"))

    def test_failing_baseline_is_a_failure(self):
        with open(os.path.join(self.tree, "guarded.py"), "w") as f:
            f.write("def belep(x):\n    return True\n")                    # az őr eleve nincs bent
        r = ev.run_floor(self.tree, self.claims("return True", "return False"))[0]
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("do not pass", r["reason"])


class ManifestCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = os.path.join(self.tmp.name, "fa")
        os.makedirs(os.path.join(self.tree, "product"))
        for name, body in (("a.py", "print(1)\n"), ("product/b.txt", "kettő\n")):
            with open(os.path.join(self.tree, name), "w", encoding="utf-8") as f:
                f.write(body)
        self.manifest = {"files": {rel: ev.sha256_file(p) for rel, p in ev.walk_tree(self.tree)}}

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_tree_has_no_problems(self):
        self.assertEqual(ev.check_manifest(self.tree, self.manifest), [])

    def test_modified_missing_and_extra_files_are_all_reported(self):
        with open(os.path.join(self.tree, "a.py"), "a") as f:
            f.write("# egy karakter\n")
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


@unittest.skipUnless(os.path.isfile(os.path.join(HERE, "evidence", "MANIFEST.json")), "a boríték még nincs megépítve")
class ShippedEnvelope(unittest.TestCase):
    """A repóban lévő, megépített borítékon: a vevő parancsa fut, és a manifest fog egy elrontott fájlt."""

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
                f.write("# egy sor, amit senki nem kért\n")
            p = subprocess.run([sys.executable, os.path.join(copy, "product", "verify_evidence.py"), "--quick", "--json"],
                               capture_output=True, text=True, timeout=600)
            rep = json.loads(p.stdout)
            ch1 = [c for c in rep["chapters"] if c["chapter"].startswith("1.")][0]
            self.assertEqual(ch1["status"], "FAIL")
            self.assertIn("bus_notary.py", json.dumps(ch1["problems"]))
            self.assertEqual(p.returncode, 1)


class PublishFurniture(unittest.TestCase):
    """A publikált repó a lezárt termék FÖLÉ kap landing-fájlokat. A boríték ezekre azt mondta, hogy "not in the
    manifest", és a publikált v1.5.1 emiatt megbukott a SAJÁT verifikálóján — egy független kar mérte ki.

    A javítás nem az, hogy a verifikáló elnézőbb lesz: a lyuknak PONTOS NEVEI vannak, a verifikáló KIMONDJA, mit
    nem fed a pecsét, és minden más többlet-fájl változatlanul bukás."""

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
        self.assertEqual(ev.check_manifest(tree, man), [], "a furniture megbuktatta a pecsétet")
        self.assertEqual(ev.unsealed_present(tree), ["README.md", "SECURITY.md"],
                         "a verifikáló nem mondja ki, mit NEM fed a pecsét")

    def test_any_other_unlisted_file_is_still_a_failure(self):
        tree = self._tree({"agent_bus.py": "x = 1\n", "smuggled.py": "import os\n"})
        problems = ev.check_manifest(tree, self._manifest(tree, ["agent_bus.py"]))
        self.assertEqual([p["file"] for p in problems], ["smuggled.py"])

    def test_a_listed_furniture_file_is_still_hash_checked(self):
        """Ha a furniture BEKERÜL a manifestbe, akkor onnantól a pecsét része — a kivétel csak a hiányra szól."""
        tree = self._tree({"agent_bus.py": "x = 1\n", "README.md": "# landing\n"})
        man = self._manifest(tree, ["agent_bus.py", "README.md"])
        open(os.path.join(tree, "README.md"), "w", encoding="utf-8").write("# tampered\n")
        problems = ev.check_manifest(tree, man)
        self.assertEqual([p["problem"] for p in problems], ["content differs from the manifest"])

    def test_the_exemption_is_names_not_a_directory(self):
        """Egy könyvtár-alakú kivétel magától nő, ahogy a könyvtár telik — ez a lyuk nem nőhet."""
        for name in ev.UNSEALED:
            self.assertFalse(name.endswith("/"), name)
            self.assertNotIn("*", name)
            self.assertFalse(os.path.isabs(name), name)
        self.assertLessEqual(len(ev.UNSEALED), 5, "a furniture-lista csendben tágul")


if __name__ == "__main__":
    unittest.main()
