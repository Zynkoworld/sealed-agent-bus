"""Packaging tests: deterministic release build and the fail-closed installer (from a local file:// URL, no network).

The installer's promise: the hash check runs BEFORE UNPACKING, and on failure nothing stays on disk. This is not
to be believed but measured: we corrupt the archive and check that rc is not 0 AND the target directory was not created.
stdlib unittest."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from version import RELEASE_VERSION  # noqa: E402 — one source; the test must not carry its own version literal

VERSION = RELEASE_VERSION
NAME = "sealed-bus-" + VERSION


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


@unittest.skipUnless(shutil.which("curl") and shutil.which("tar"), "curl + tar required")
class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dist = os.path.join(cls.tmp.name, "dist")
        cls.rel = cls._build(cls.dist)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def _build(cls, out, commit="HEAD"):
        p = subprocess.run([sys.executable, os.path.join(HERE, "make_release.py"), "--version", VERSION,
                            "--commit", commit, "--repo", REPO, "--out", out], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        return json.load(open(os.path.join(out, "%s.release.json" % NAME)))

    def install(self, dist=None, prefix=None, extra=()):
        prefix = prefix or tempfile.mkdtemp(dir=self.tmp.name)
        p = subprocess.run(["sh", os.path.join(HERE, "install.sh"), "--version", VERSION,
                            "--url", "file://" + (dist or self.dist), "--prefix", prefix] + list(extra),
                           capture_output=True, text=True)
        return p, os.path.join(prefix, NAME)

    # ── the release itself ──────────────────────────────────────────────────────
    def test_release_is_reproducible_and_pins_every_file(self):
        again = self._build(os.path.join(self.tmp.name, "dist2"))
        self.assertEqual(again["artifact_sha256"], self.rel["artifact_sha256"])       # built twice, byte-identical
        self.assertEqual(self.rel["artifact_sha256"], sha256_file(os.path.join(self.dist, "%s.tar.gz" % NAME)))
        for name in ("agent_bus.py", "bus_notary.py"):
            self.assertIn(name, self.rel["files"])
        if "product/install.sh" not in self.rel["files"]:      # the release is built from the COMMIT, not the working tree
            self.skipTest("the product/ files are not committed on this head yet")
        blob = subprocess.run(["git", "-C", REPO, "cat-file", "blob", "HEAD:agent_bus.py"], capture_output=True).stdout
        self.assertEqual(self.rel["files"]["agent_bus.py"], hashlib.sha256(blob).hexdigest())
        self.assertNotIn("dist", " ".join(self.rel["files"]))                          # the build output does not go in

    # ── the installer ───────────────────────────────────────────────────────────
    def test_install_verifies_then_unpacks_and_smoke_checks(self):
        p, target = self.install()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("sha256 ok", p.stdout)
        self.assertIn("modules load: ok", p.stdout)
        self.assertTrue(os.path.isfile(os.path.join(target, "agent_bus.py")))
        self.assertTrue(os.path.isfile(os.path.join(target, "product", "EVIDENCE_ENVELOPE.md")))

    def test_tampered_archive_is_refused_before_unpacking(self):
        bad = os.path.join(self.tmp.name, "bad")
        shutil.copytree(self.dist, bad)
        with open(os.path.join(bad, "%s.tar.gz" % NAME), "ab") as f:
            f.write(b"x")                                                             # a single byte
        p, target = self.install(dist=bad)
        self.assertEqual(p.returncode, 5, p.stdout + p.stderr)
        self.assertIn("HASH MISMATCH", p.stderr)
        self.assertFalse(os.path.exists(target), "the corrupt archive stayed unpacked")

    def test_matching_published_hash_but_wrong_pinned_hash_is_refused(self):
        """The attacker ALSO rewrites the hash file (same host) — the pin fixed out of band catches it."""
        bad = os.path.join(self.tmp.name, "bad2")
        self._build(bad, commit="HEAD~1")                                             # VALID, but DIFFERENT content
        art = os.path.join(bad, "%s.tar.gz" % NAME)
        with open(art + ".sha256", "w") as f:
            f.write("%s  %s.tar.gz\n" % (sha256_file(art), NAME))                     # the fake archive's own hash
        self.assertNotEqual(sha256_file(art), self.rel["artifact_sha256"])
        p, target = self.install(dist=bad)                                            # without a pin: passes ...
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("pin it with --expect-sha256", p.stdout)                         # ... but says so
        p2, target2 = self.install(dist=bad, extra=("--expect-sha256", self.rel["artifact_sha256"]))
        self.assertEqual(p2.returncode, 5, p2.stdout + p2.stderr)
        self.assertIn("PINNED HASH MISMATCH", p2.stderr)
        self.assertFalse(os.path.exists(target2))

    def test_bad_arguments_and_missing_artifact_fail_closed(self):
        prefix = tempfile.mkdtemp(dir=self.tmp.name)
        for args, rc in ((["--version", "nem-verzio"], 2), (["--version", VERSION, "--expect-sha256", "rovid"], 2)):
            p = subprocess.run(["sh", os.path.join(HERE, "install.sh"), "--url", "file://" + self.dist,
                                "--prefix", prefix] + args, capture_output=True, text=True)
            self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
        p = subprocess.run(["sh", os.path.join(HERE, "install.sh"), "--version", "9.9.9",
                            "--url", "file://" + self.dist, "--prefix", prefix], capture_output=True, text=True)
        self.assertEqual(p.returncode, 4)
        self.assertEqual(os.listdir(prefix), [])

    def test_existing_target_is_never_overwritten(self):
        prefix = tempfile.mkdtemp(dir=self.tmp.name)
        os.makedirs(os.path.join(prefix, NAME))
        open(os.path.join(prefix, NAME, "sajat.txt"), "w").write("ne ird felul")
        p, target = self.install(prefix=prefix)
        self.assertEqual(p.returncode, 6, p.stdout + p.stderr)
        self.assertEqual(open(os.path.join(target, "sajat.txt")).read(), "ne ird felul")


class ReleaseVersusProtocolVersion(unittest.TestCase):
    """The release version and the protocol version are TWO claims. The protocol version goes out on the wire
    (bus_ssh_exchange), so a packaging fix must not bump it — that would say something untrue about the contract."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import release_preflight, version  # noqa: PLC0415
        self.rp, self.ver = release_preflight, version

    def test_a_patch_release_keeps_the_protocol_line(self):
        import agent_bus  # noqa: PLC0415
        self.assertTrue(self.ver.same_line(RELEASE_VERSION, agent_bus.PROTOCOL_VERSION),
                        "the release version left the protocol's MAJOR.MINOR line")

    def test_the_rule_separates_a_patch_from_a_protocol_move(self):
        self.assertTrue(self.ver.same_line("1.5.1", "1.5.0"))
        self.assertTrue(self.ver.same_line("1.5.0", "1.5.0"))
        self.assertFalse(self.ver.same_line("1.6.0", "1.5.0"))
        self.assertFalse(self.ver.same_line("2.0.0", "1.5.0"))

    def test_the_declared_version_must_match_the_argument(self):
        ok, _ = self.rp.check_version(RELEASE_VERSION)
        self.assertTrue(ok)
        ok_wrong, detail = self.rp.check_version("9.9.9")
        self.assertFalse(ok_wrong, detail)


class ProvenanceRule(unittest.TestCase):
    """A rename once flipped five peer-written tests to "first-party" without a word — the authorship claim that
    the source-available (BSL) licence rests on. A prefix matching nothing is a broken rule, not a clean tree."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import make_provenance  # noqa: PLC0415 — the subject of the test
        self.mp = make_provenance

    def test_the_partner_prefix_still_matches_shipped_files(self):
        doc = self.mp.build()
        self.assertGreater(doc["counts"]["partner-same-business"], 0)
        self.assertEqual(doc["counts"]["third-party"], 0)

    def test_the_inventory_covers_every_file_the_packer_ships(self):
        sys.path.insert(0, HERE)
        import make_release  # noqa: PLC0415
        doc = self.mp.build()
        self.assertEqual(sorted(doc["files"]), make_release.shipped_names(REPO, "HEAD"))

    def test_the_labelled_counts_add_up_to_the_total(self):
        """A count written as "everything that is not first-party" swallowed a whole new category in silence
        and reported 15 generated files as partner-written. If the labels do not sum to the total, some file
        is being counted as something it is not."""
        c = dict(self.mp.build()["counts"])
        total = c.pop("total")
        self.assertEqual(sum(c.values()), total)
        self.assertEqual(set(c), set(self.mp.ORIGINS))

    def test_a_prefix_that_matches_nothing_stops_the_release(self):
        original = self.mp.PARTNER_PREFIXES
        self.addCleanup(setattr, self.mp, "PARTNER_PREFIXES", original)
        self.mp.PARTNER_PREFIXES = ("test_no_such_prefix_",)
        with self.assertRaises(SystemExit):
            self.mp.build()


class ShippedLeakScan(unittest.TestCase):
    """Preflight item 12: the leak scan over the WHOLE shipped set.

    Item 10 only looked at the marketing texts, but the buyer gets the whole archive — so the gate
    proved less than one could read from it. Here we measure that (1) the tree is clean now, (2) the detector
    actually CATCHES a planted leak (otherwise a silent green cannot be told from a real green),
    and (3) the pattern-holder exemption is exactly two files, not a silently widening list."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import release_preflight  # noqa: PLC0415 — the subject of the test
        self.rp = release_preflight

    # ── The roster mechanism ──────────────────────────────────────────────────────────────────────────
    # These tests work with a MADE-UP roster, not ours. This is not convenience: if our real names
    # stood here, THIS file would be the leak — exactly what the separation removed. The
    # subject of the test is the SHAPE and the loading behaviour; the names do not belong to the product.

    def _roster(self, mapping):
        """A temporary roster file, wired in via AGENTBUS_LEAK_TERMS, restored at the end of the test."""
        d = tempfile.mkdtemp()
        path = os.path.join(d, "terms.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False)
        old = os.environ.get(self.rp.ROSTER_ENV)
        os.environ[self.rp.ROSTER_ENV] = path
        self.addCleanup(lambda: os.environ.__setitem__(self.rp.ROSTER_ENV, old) if old is not None
                        else os.environ.pop(self.rp.ROSTER_ENV, None))
        self.addCleanup(shutil.rmtree, d, True)
        return path

    def test_shipped_tree_is_clean_of_every_class(self):
        """The shipped set is clean in EVERY class — not only the documentation, and not only three classes.

        Until 1.5.3 the enforced set narrowed as it went from the docs towards the code, and so the
        shipped code held 175 hits the finder ALREADY KNEW: the roster existed, it just was not
        enforced where they occurred."""
        pats, note, _ = self.rp.leak_patterns()
        hits, scanned = self.rp.scan_shipped(pats)
        self.assertGreater(scanned, 50, "the walk did not cover the set")
        # The failure message names the FILE and the CLASS, NEVER the MATCHED TEXT. This is not cosmetic:
        # the suite output goes into the shipped product/evidence/suite.txt, which this walk itself
        # covers. While the message quoted the match, the gate got stuck in a FIXED POINT — the failure wrote into the log
        # the text that the next run found there, and it never cleared on re-run.
        # In general: a leak finder must not write the finding into a log that is itself
        # shipped. It must state the number and the location, not the content.
        where = sorted({"%s [%s]" % (h.split(":")[0], h.split(": ", 1)[1].split(" (")[0]) for h in hits})
        self.assertEqual(where, [], "%d internal leak(s) in %d place(s) (%s)" % (len(hits), len(where), note))

    def test_a_missing_roster_is_visible_and_not_fatal(self):
        """There are three states, and the middle one is why the whole thing exists. NOT CONFIGURED: visible, but not an error —
        the buyer has no roster of ours, and MUST be able to run the gate on the archive received."""
        old = os.environ.pop(self.rp.ROSTER_ENV, None)
        self.addCleanup(lambda: os.environ.__setitem__(self.rp.ROSTER_ENV, old) if old is not None
                        else os.environ.pop(self.rp.ROSTER_ENV, None))
        pats, note, configured = self.rp.leak_patterns()
        self.assertFalse(configured)
        self.assertIn("NOT CONFIGURED", note, "a missing roster must be STATED, not silent")
        self.assertEqual([n for n, _ in pats], [n for n, _ in self.rp.SHAPE], "we were left without shape classes")

    def test_a_configured_but_unreadable_roster_stops_the_release(self):
        """CONFIGURED-BUT-BROKEN: someone MEANT to put a roster here, and it is not there. That would be a silent downgrade —
        exactly the class of error this file exists for —, so it is an error, not a warning."""
        # Cleanup RESTORES, it does not delete. The first version used `os.environ.pop` as cleanup, so
        # this test removed the roster for the REST of the session: the release-side guard then silently
        # measured only the shape classes, and did so in the full suite too — in the envelope's evidence
        # as well. A test that weakens a later gate is worse than a missing test.
        old = os.environ.get(self.rp.ROSTER_ENV)
        os.environ[self.rp.ROSTER_ENV] = "/nonexistent/terms.json"
        self.addCleanup(lambda: os.environ.__setitem__(self.rp.ROSTER_ENV, old) if old is not None
                        else os.environ.pop(self.rp.ROSTER_ENV, None))
        with self.assertRaises(self.rp.LeakRosterError):
            self.rp.leak_patterns()

    def test_a_typo_in_a_class_name_is_refused(self):
        """A typo in a class name would SILENTLY disable that class. So an unknown key = error."""
        self._roster({"internal agnet name": ["nosuchname"]})
        with self.assertRaises(self.rp.LeakRosterError):
            self.rp.leak_patterns()

    def test_the_detector_actually_catches_a_planted_leak(self):
        """A probe of the mechanism on made-up names: what we put into the roster, it must find."""
        self._roster({"internal path": ["/nowhere-real/"],
                      "internal agent name": ["fictitiousagent"],
                      "internal hostname": ["fakebox7"],
                      "internal model name": ["madeupname"],
                      "internal person name": ["Ödön"]})
        pats = dict(self.rp.leak_patterns()[0])
        cases = {"internal path": "DB = '/nowhere-real/bus.db'",
                 "internal agent name": "the fictitiousagent decided it",
                 "internal hostname": "ran on fakebox7 last night",
                 "internal model name": "the madeupname model arm decided it",
                 "internal person name": "Válasz Ödönnek",
                 "e-mail or IP": "reach us at ops@internal-" + "host.net"}
        for cls, sample in cases.items():
            with self.subTest(cls=cls):
                self.assertRegex(sample, pats[cls])

    def test_a_hostname_is_caught_inside_a_derived_identifier(self):
        """A hostname sticks to an identifier: a "foo2" machine becomes "foo2test", and a trailing word boundary catches
        neither. Measured on the published 1.5.3: 2 of 7 occurrences of one hostname had exactly this shape."""
        self._roster({"internal hostname": ["fakebox7"]})
        pat = dict(self.rp.leak_patterns()[0])["internal hostname"]
        for form in ("fakebox7", "fakebox7test", "a fakebox7-en"):
            with self.subTest(form=form):
                self.assertRegex(form, pat)

    def test_a_name_is_caught_when_an_identifier_grew_around_it(self):
        """The word boundary (\\b) treats UNDERSCORE as a word character, so a name stuck into an identifier passes it.

        Measured on this tree, AFTER I had called the walk clean: `<name>_entitlement` and `<name>_bus_adapter` stood in the
        shipped code, and the gate saw neither. The same blind spot we had already closed for hostnames —
        closing it in one class does not close it in the others. So the boundary is on letters/digits, not on \\b."""
        self._roster({"internal agent name": ["fictitiousagent"], "internal person name": ["Ödön"]})
        pats = dict(self.rp.leak_patterns()[0])
        for sample in ("fictitiousagent_entitlement", "vendor_fictitiousagent", "a_fictitiousagent_adapter"):
            with self.subTest(sample=sample):
                self.assertRegex(sample, pats["internal agent name"])
        self.assertRegex("Ödön_key", pats["internal person name"])
        # Counter-check: the name embedded BETWEEN LETTERS is NOT a hit — otherwise every "estimate" would be a person's name.
        self.assertNotRegex("prefictitiousagentsuffix", pats["internal agent name"])

    def test_person_names_are_caught_through_hungarian_case_endings(self):
        """A bare word boundary does not catch the form "Oedoennek" — that is exactly how a private note once
        stayed in, while the gate called the tree clean."""
        self._roster({"internal person name": ["Ödön"]})
        pat = dict(self.rp.leak_patterns()[0])["internal person name"]
        for suffixed in ("Ödönnek", "Ödöntől", "Ödönnel", "Válasz Ödönnek"):
            with self.subTest(form=suffixed):
                self.assertRegex(suffixed, pat)

    def test_a_model_codename_only_counts_near_a_model_word(self):
        """Model codenames are also ordinary English words. Bare, they would fire on every cable in the tree, so
        they only count NEAR a model word — the SHAPE is public, the codename is not."""
        self._roster({"internal model name": ["lantern"]})
        pat = dict(self.rp.leak_patterns()[0])["internal model name"]
        self.assertRegex("the lantern model signed it", pat)
        self.assertRegex("that arm runs on lantern", pat)
        self.assertNotRegex("hang the lantern by the door", pat)

    def test_example_domains_are_not_false_positives(self):
        pat = dict(self.rp.SHAPE)["e-mail or IP"]
        for safe in ("bus@example.invalid", "sk-ssh-ed25519@openssh.com", "127.0.0.1"):
            with self.subTest(safe=safe):
                self.assertNotRegex(safe, pat)

    def test_a_regex_character_class_is_not_a_link_into_private_notes(self):
        """The cross-reference shape is [[target]]; a regex character class in code is not one. The first version
        reported three of these, and a gate whose hits are routinely waved through stops being a gate."""
        pat = dict(self.rp.SHAPE)["internal cross-reference"]
        self.assertRegex("lásd [[valami-jegyzet]]", pat)
        self.assertNotRegex("[[^" + chr(92) + "]]", pat)

    def test_the_review_attribution_class_does_not_fire_on_protocol_vocabulary(self):
        """The Hungarian protocol word for round, and "round" itself, are PROTOCOL words (round_seq, round_close), not review words."""
        pat = dict(self.rp.SHAPE)["internal review attribution"]
        self.assertRegex("HIGH-2: a mérés hiánya", pat)
        self.assertRegex("lásd #1234", pat)
        self.assertNotRegex("a kör-bejegyzés round_seq mezője", pat)
        self.assertNotRegex("round2 az ack-ablakban", pat)

    def test_there_is_no_class_exemption_at_all(self):
        """The exemption table is EMPTY, and that is not an accidental state but the consequence of a retired reason.

        It held one item: LICENSE was exempt from the person-name class, because a licence MUST
        name its licensor. A real reason, stated. (Before that it was worse: LICENSE fell out because
        it has no extension — a good result for a bad reason.) The owner then switched the
        Licensor line to a company name, so the reason ran out — and with it the exemption. An exemption that outlives its reason
        is just a hole with a note on it saying why it was once allowed.

        If we ever have to put one back, that is a DECISION: this test enforces that the decision
        is visible too, because extending the table also fails this line."""
        self.assertEqual(self.rp.CLASS_EXEMPT, {},
                         "the exemption table grew back — if intentional, this test must say why it is allowed")

    def test_the_gate_would_catch_the_licensor_line_it_used_to_excuse(self):
        """A counter-check so the protection is not a vacuum: the exemption is gone, so the gate must NOW catch the OLD
        Licensor line — otherwise emptying the table achieved nothing."""
        self._roster({"internal person name": ["Ödönyi", "Kovács Elek"]})
        pat = dict(self.rp.leak_patterns()[0])["internal person name"]
        self.assertRegex("Licensor:  Examplesoft (Ödönyi Elek and Kovács Elek Pál)", pat)
        self.assertNotRegex("Licensor:  Examplesoft", pat)

    def test_the_scan_walks_everything_the_packer_ships(self):
        """The gate is read as "nothing internal ships", and that is only true if the walked set IS the
        shipped set. They were two different sets once — 87 shipped, 72 walked — and the 15 nobody looked at
        is exactly where a stale log kept naming deleted private files."""
        sys.path.insert(0, HERE)
        import make_release  # noqa: PLC0415
        packed = set(make_release.shipped_names(REPO, "HEAD"))
        self.assertGreater(len(packed), 50)
        self.assertEqual(self.rp.unscanned_shipped(), [], "a shipped file that no scan covers")
        self.assertTrue(packed <= set(self.rp.shipped_files()))

    def test_the_generated_evidence_is_scanned_too(self):
        """The specific regression: product/evidence/ is generated, shipped, and was skipped by directory."""
        walked = set(self.rp.shipped_files())
        evidence = {f for f in walked if f.startswith("product/evidence/")}
        self.assertGreater(len(evidence), 5, "the envelope files were left out of the scanned set")
        hits, scanned = self.rp.scan_shipped(self.rp.leak_patterns()[0])
        self.assertGreaterEqual(scanned, len(evidence), "the walk did not reach the envelope files")

    def test_a_directory_sized_blind_spot_is_reported(self):
        """Self-test on the attacker: if the walked set shrinks back, the check must say so by name."""
        original = self.rp.shipped_files
        self.addCleanup(setattr, self.rp, "shipped_files", original)
        self.rp.shipped_files = lambda: [f for f in original() if not f.startswith("product/evidence/")]
        blind = self.rp.unscanned_shipped()
        self.assertTrue(blind, "the blind spot was not reported")
        self.assertTrue(all(f.startswith("product/evidence/") for f in blind))
        ok, detail = self.rp.check_shipped_text(VERSION)
        self.assertFalse(ok)
        self.assertIn("no scan walks", detail)

    def test_pattern_holder_exemption_stays_minimal(self):
        """The exemption covers the files that ARE the patterns themselves: the finder and its tests, which deliberately
        plant a finding to prove the finder catches it. Listed by name, not by directory —
        a directory-shaped exemption can silently grow over a generated folder that fills up later. EXTENDING the list
        must always be a stated decision: this test is what makes it stated."""
        self.assertEqual(set(self.rp.PATTERN_HOLDERS),
                         {"product/release_preflight.py", "product/test_product_page.py",
                          "product/test_product_packaging.py"})
        for f in self.rp.PATTERN_HOLDERS:
            self.assertTrue(os.path.isfile(os.path.join(REPO, f)), "exemption for a non-existent file: %s" % f)


if __name__ == "__main__":
    unittest.main()


class PackerAndSealAgreeOnWhatShips(unittest.TestCase):
    """The artifact built from the published repo must be THE SAME as the one built from the development tree.

    1.5.2's post-publish check failed this: the verifier had learned that the landing files are outside
    the seal, but the PACKER had not — so the published repo produced 160 files and a DIFFERENT artifact hash
    than the development tree (157). A buyer rebuilding from the published repo did not get the archive
    we signed. Both sides must mean the same thing by "shipped", so there is ONE list, and both
    read it."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import evidence, make_release  # noqa: PLC0415
        self.ev, self.mr = evidence, make_release

    def test_the_packer_excludes_exactly_what_the_seal_calls_furniture(self):
        shipped = set(self.mr.shipped_names(REPO, "HEAD"))
        for name in self.ev.UNSEALED:
            self.assertNotIn(name, shipped, "the packer takes in what the seal leaves out: %s" % name)

    def test_the_two_lists_are_one_list(self):
        """Not two matching copies — the SAME object is the source. Two copies drift apart over time."""
        self.assertEqual(self.mr._unsealed(), set(self.ev.UNSEALED))

    def test_a_tree_with_furniture_ships_the_same_files_as_one_without(self):
        """The shape of the published repo: the same commit + the landing files. The shipped list must not change."""
        import subprocess, tempfile
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        clone = os.path.join(tmp, "published")
        subprocess.run(["git", "clone", "-q", REPO, clone], check=True, capture_output=True)
        before = self.mr.shipped_names(clone, "HEAD")
        for name in self.ev.UNSEALED:                      # the publish furniture goes on, as in production
            p = os.path.join(clone, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write("landing\n")
        subprocess.run(["git", "-C", clone, "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", clone, "-c", "user.email=t@e.invalid", "-c", "user.name=t",
                        "commit", "-qm", "publish furniture"], check=True, capture_output=True)
        after = self.mr.shipped_names(clone, "HEAD")
        self.assertEqual(before, after, "the furniture changed the shipped file list")
