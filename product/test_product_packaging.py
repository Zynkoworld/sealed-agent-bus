"""A csomagolás tesztjei: determinista kiadás-építés és a fail-closed telepítő (helyi file:// URL-ről, hálózat nélkül).

A telepítő ígérete: a hash-ellenőrzés a KICSOMAGOLÁS ELŐTT fut, és hiba esetén semmi nem marad a lemezen. Ezt nem
elhinni kell, hanem mérni: az archívumot elrontjuk, és azt nézzük, hogy a rc nem 0 ÉS a célkönyvtár nem jött létre.
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
from version import RELEASE_VERSION  # noqa: E402 — egy forrás; a teszt ne hordozzon saját verzió-literált

VERSION = RELEASE_VERSION
NAME = "sealed-bus-" + VERSION


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


@unittest.skipUnless(shutil.which("curl") and shutil.which("tar"), "curl + tar szükséges")
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

    # ── a kiadás maga ────────────────────────────────────────────────────────
    def test_release_is_reproducible_and_pins_every_file(self):
        again = self._build(os.path.join(self.tmp.name, "dist2"))
        self.assertEqual(again["artifact_sha256"], self.rel["artifact_sha256"])       # kétszer építve bájtazonos
        self.assertEqual(self.rel["artifact_sha256"], sha256_file(os.path.join(self.dist, "%s.tar.gz" % NAME)))
        for name in ("agent_bus.py", "bus_notary.py"):
            self.assertIn(name, self.rel["files"])
        if "product/install.sh" not in self.rel["files"]:      # a kiadás a COMMITBÓL épül, nem a munkafából
            self.skipTest("a product/ fájlok még nincsenek commitolva ezen a fejen")
        blob = subprocess.run(["git", "-C", REPO, "cat-file", "blob", "HEAD:agent_bus.py"], capture_output=True).stdout
        self.assertEqual(self.rel["files"]["agent_bus.py"], hashlib.sha256(blob).hexdigest())
        self.assertNotIn("dist", " ".join(self.rel["files"]))                          # a build kimenete nem megy bele

    # ── a telepítő ───────────────────────────────────────────────────────────
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
            f.write(b"x")                                                             # egyetlen bájt
        p, target = self.install(dist=bad)
        self.assertEqual(p.returncode, 5, p.stdout + p.stderr)
        self.assertIn("HASH MISMATCH", p.stderr)
        self.assertFalse(os.path.exists(target), "a hibás archívum kicsomagolva maradt")

    def test_matching_published_hash_but_wrong_pinned_hash_is_refused(self):
        """A támadó a hash-fájlt IS átírja (azonos hoszt) — a csatornán kívül rögzített pin fogja meg."""
        bad = os.path.join(self.tmp.name, "bad2")
        self._build(bad, commit="HEAD~1")                                             # ÉRVÉNYES, de MÁSIK tartalom
        art = os.path.join(bad, "%s.tar.gz" % NAME)
        with open(art + ".sha256", "w") as f:
            f.write("%s  %s.tar.gz\n" % (sha256_file(art), NAME))                     # a hamis archívum saját hash-e
        self.assertNotEqual(sha256_file(art), self.rel["artifact_sha256"])
        p, target = self.install(dist=bad)                                            # pin nélkül: átmegy ...
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("pin it with --expect-sha256", p.stdout)                         # ... de ezt ki is mondja
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
    """A kiadás verziója és a protokoll verziója KÉT állítás. A protokoll-verzió kimegy a drótra
    (bus_ssh_exchange), tehát egy csomagolási javítás nem billentheti — az a szerződésről mondana valótlant."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import release_preflight, version  # noqa: PLC0415
        self.rp, self.ver = release_preflight, version

    def test_a_patch_release_keeps_the_protocol_line(self):
        import agent_bus  # noqa: PLC0415
        self.assertTrue(self.ver.same_line(RELEASE_VERSION, agent_bus.PROTOCOL_VERSION),
                        "a kiadás-verzió elhagyta a protokoll MAJOR.MINOR vonalát")

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
        import make_provenance  # noqa: PLC0415 — a teszt tárgya
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
    """A 12. preflight-tétel: a szivárgás-vizsgálat a TELJES szállított készletre.

    A 10. tétel csak a marketing-szövegeket nézte, a vevő viszont az egész archívumot kapja meg — a kapu tehát
    szűkebbet bizonyított, mint amit olvasni lehet belőle. Itt azt mérjük, hogy (1) a fa most tiszta, (2) a detektor
    ténylegesen FOG egy telepített szivárgást (különben egy néma zöld nem különböztethető meg egy valódi zöldtől),
    és (3) a minta-hordozó kivétel pontosan két fájl, nem egy csendben táguló lista."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import release_preflight  # noqa: PLC0415 — a teszt tárgya
        self.rp = release_preflight

    # ── A roster mechanizmusa ─────────────────────────────────────────────────────────────────────────
    # Ezek a tesztek KITALÁLT névsorral dolgoznak, nem a miénkkel. Ez nem kényelem: ha a valódi neveink
    # állnának itt, akkor EZ a fájl lenne a szivárgás — pont az, amit a szétválasztás megszüntetett. A
    # teszt tárgya az ALAK és a betöltés viselkedése; a nevek a termékhez nem tartoznak hozzá.

    def _roster(self, mapping):
        """Ideiglenes névsor-fájl, AGENTBUS_LEAK_TERMS-szel bekötve, a teszt végén visszaállítva."""
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
        """A szállított készlet MINDEN osztályra tiszta — nem csak a dokumentáció, és nem csak három osztályra.

        Az 1.5.3-ig a kikényszerített halmaz szűkült, ahogy a doksitól a kód felé haladt, és emiatt a
        szállított kódban 175 olyan találat állt, amit a kereső MÁR ISMERT: a névsor megvolt, csak nem ott
        kényszerítettük ki, ahol előfordult."""
        pats, note, _ = self.rp.leak_patterns()
        hits, scanned = self.rp.scan_shipped(pats)
        self.assertGreater(scanned, 50, "a séta nem járta be a készletet")
        # A bukás-üzenet a FÁJLT és az OSZTÁLYT nevezi meg, a TALÁLT SZÖVEGET soha. Ez nem kozmetika:
        # a suite kimenete bekerül a szállított product/evidence/suite.txt-be, amit ez a séta maga is
        # bejár. Amíg az üzenet idézte a találatot, a kapu FIXPONTBA ragadt — a bukás beírta a naplóba
        # azt a szöveget, amit a következő futás ott megtalált, és újrafuttatással soha nem tisztult.
        # Általánosan: egy szivárgás-kereső nem írhatja bele a leletet egy olyan naplóba, ami maga is
        # szállított. A számot és a helyet kell mondania, a tartalmat nem.
        where = sorted({"%s [%s]" % (h.split(":")[0], h.split(": ", 1)[1].split(" (")[0]) for h in hits})
        self.assertEqual(where, [], "%d belső szivárgás %d helyen (%s)" % (len(hits), len(where), note))

    def test_a_missing_roster_is_visible_and_not_fatal(self):
        """Három állapot van, és a középső miatt létezik az egész. NINCS BEÁLLÍTVA: látható, de nem hiba —
        a vevőnek nincs névsorunk, és futtatnia KELL tudnia a kapun a kapott archívumot."""
        old = os.environ.pop(self.rp.ROSTER_ENV, None)
        self.addCleanup(lambda: os.environ.__setitem__(self.rp.ROSTER_ENV, old) if old is not None
                        else os.environ.pop(self.rp.ROSTER_ENV, None))
        pats, note, configured = self.rp.leak_patterns()
        self.assertFalse(configured)
        self.assertIn("NOT CONFIGURED", note, "a hiányzó névsornak KIMONDOTTNAK kell lennie, nem csendesnek")
        self.assertEqual([n for n, _ in pats], [n for n, _ in self.rp.SHAPE], "alak-osztályok nélkül maradtunk")

    def test_a_configured_but_unreadable_roster_stops_the_release(self):
        """CONFIGURED-BUT-BROKEN: valaki névsort SZÁNT ide, és az nincs ott. Ez néma visszaminősítés lenne —
        pontosan az a hibaosztály, ami miatt ez a fájl létezik —, ezért hiba, nem figyelmeztetés."""
        # A takarítás VISSZAÁLLÍT, nem töröl. Az első változat `os.environ.pop`-ot tett cleanupnak, ezért
        # ez a teszt a SESSION hátralévő részére eltüntette a névsort: a kiadási oldal őre utána csendben
        # csak az alak-osztályokat mérte, és ezt a teljes suite-ban is így tette — a boríték bizonyítékában
        # is. Egy teszt, ami egy későbbi kaput gyengít, rosszabb, mint egy hiányzó teszt.
        old = os.environ.get(self.rp.ROSTER_ENV)
        os.environ[self.rp.ROSTER_ENV] = "/nonexistent/terms.json"
        self.addCleanup(lambda: os.environ.__setitem__(self.rp.ROSTER_ENV, old) if old is not None
                        else os.environ.pop(self.rp.ROSTER_ENV, None))
        with self.assertRaises(self.rp.LeakRosterError):
            self.rp.leak_patterns()

    def test_a_typo_in_a_class_name_is_refused(self):
        """Egy elgépelt osztálynév CSENDBEN kikapcsolná azt az osztályt. Ezért ismeretlen kulcs = hiba."""
        self._roster({"internal agnet name": ["nosuchname"]})
        with self.assertRaises(self.rp.LeakRosterError):
            self.rp.leak_patterns()

    def test_the_detector_actually_catches_a_planted_leak(self):
        """A mechanizmus próbája kitalált neveken: amit a névsorba teszünk, azt meg kell találnia."""
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
        """A gépnév azonosítóba tapad: egy "foo2" gépből "foo2test" lesz, és egy záró szóhatár egyiket sem
        fogja. A publikált 1.5.3-on mérve: egy gépnév 7 előfordulásából 2 volt pontosan ilyen alakú."""
        self._roster({"internal hostname": ["fakebox7"]})
        pat = dict(self.rp.leak_patterns()[0])["internal hostname"]
        for form in ("fakebox7", "fakebox7test", "a fakebox7-en"):
            with self.subTest(form=form):
                self.assertRegex(form, pat)

    def test_a_name_is_caught_when_an_identifier_grew_around_it(self):
        """A szóhatár (\\b) az ALÁHÚZÁST szó-karakternek veszi, ezért egy azonosítóba tapadt név átmegy rajta.

        Mérve ezen a fán, MIUTÁN a sétát tisztának mondtam: `<nev>_entitlement` és `<nev>_bus_adapter` állt a
        szállított kódban, és a kapu egyiket sem látta. Ugyanaz a vakfolt, amit a gépneveknél már bezártunk —
        egy osztályban bezárni nem zárja be a többiben. A határ ezért betűre/számjegyre szól, nem \\b-re."""
        self._roster({"internal agent name": ["fictitiousagent"], "internal person name": ["Ödön"]})
        pats = dict(self.rp.leak_patterns()[0])
        for sample in ("fictitiousagent_entitlement", "vendor_fictitiousagent", "a_fictitiousagent_adapter"):
            with self.subTest(sample=sample):
                self.assertRegex(sample, pats["internal agent name"])
        self.assertRegex("Ödön_key", pats["internal person name"])
        # Ellenpróba: a név BETŰK közé ágyazva NEM találat — különben minden "estimate" személynév lenne.
        self.assertNotRegex("prefictitiousagentsuffix", pats["internal agent name"])

    def test_person_names_are_caught_through_hungarian_case_endings(self):
        """Egy csupasz szóhatár nem fogja meg az "Ödönnek" alakot — pontosan így maradt bent egyszer egy
        privát jegyzet, miközben a kapu tisztának mondta a fát."""
        self._roster({"internal person name": ["Ödön"]})
        pat = dict(self.rp.leak_patterns()[0])["internal person name"]
        for suffixed in ("Ödönnek", "Ödöntől", "Ödönnel", "Válasz Ödönnek"):
            with self.subTest(form=suffixed):
                self.assertRegex(suffixed, pat)

    def test_a_model_codename_only_counts_near_a_model_word(self):
        """A modell-kódnevek hétköznapi angol szavak is. Csupaszon minden kábelre elsülnének a fában, ezért
        csak modell-szó KÖZELÉBEN számítanak — az ALAK publikus, a kódnév nem."""
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
        """A kereszt-hivatkozás alakja [[cél]]; egy regex-karakterosztály a kódban nem az. Az első változat
        hármat jelentett ilyet, és egy kapu, aminek a találatait rutinból legyintik le, megszűnik kapu lenni."""
        pat = dict(self.rp.SHAPE)["internal cross-reference"]
        self.assertRegex("lásd [[valami-jegyzet]]", pat)
        self.assertNotRegex("[[^" + chr(92) + "]]", pat)

    def test_the_review_attribution_class_does_not_fire_on_protocol_vocabulary(self):
        """A "kör" és a "round" a PROTOKOLL szava (round_seq, round_close), nem a felülvizsgálaté."""
        pat = dict(self.rp.SHAPE)["internal review attribution"]
        self.assertRegex("HIGH-2: a mérés hiánya", pat)
        self.assertRegex("lásd #1234", pat)
        self.assertNotRegex("a kör-bejegyzés round_seq mezője", pat)
        self.assertNotRegex("round2 az ack-ablakban", pat)

    def test_there_is_no_class_exemption_at_all(self):
        """A kivétel-tábla ÜRES, és ez nem véletlen állapot, hanem egy megszűnt indok következménye.

        Volt benne egy tétel: a LICENSE mentesült a személynév-osztály alól, mert egy licencnek meg KELL
        neveznie a licencadóját. Valódi indok, kimondva. (Előtte rosszabb volt: a LICENSE azért esett ki,
        mert nincs kiterjesztése — jó eredmény rossz okból.) A tulajdonos ezután cégnévre váltotta a
        Licensor sort, tehát az indok elfogyott — és vele a kivétel. Egy kivétel, ami túléli az indokát,
        csak egy lyuk, amire rá van írva, hogy miért volt egyszer szabad.

        Ha valaha vissza kell tennünk egyet, az egy DÖNTÉS: ez a teszt kényszeríti ki, hogy a döntés
        látszódjon is, mert a tábla bővítése ezt a sort is elbuktatja."""
        self.assertEqual(self.rp.CLASS_EXEMPT, {},
                         "a kivétel-tábla visszanőtt — ha szándékos, ez a teszt írja le, miért szabad")

    def test_the_gate_would_catch_the_licensor_line_it_used_to_excuse(self):
        """Ellenpróba, hogy a védelem ne vákuum legyen: a mentesség megszűnt, tehát a RÉGI Licensor-sort
        a kapunak MOST meg kell fognia — különben a tábla ürítése semmit nem ért."""
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
        self.assertEqual(self.rp.unscanned_shipped(), [], "szállított fájl, amit egyetlen vizsgálat sem jár be")
        self.assertTrue(packed <= set(self.rp.shipped_files()))

    def test_the_generated_evidence_is_scanned_too(self):
        """The specific regression: product/evidence/ is generated, shipped, and was skipped by directory."""
        walked = set(self.rp.shipped_files())
        evidence = {f for f in walked if f.startswith("product/evidence/")}
        self.assertGreater(len(evidence), 5, "a boríték-fájlok kimaradtak a vizsgált halmazból")
        hits, scanned = self.rp.scan_shipped(self.rp.leak_patterns()[0])
        self.assertGreaterEqual(scanned, len(evidence), "a séta nem érte el a boríték-fájlokat")

    def test_a_directory_sized_blind_spot_is_reported(self):
        """Self-test on the attacker: if the walked set shrinks back, the check must say so by name."""
        original = self.rp.shipped_files
        self.addCleanup(setattr, self.rp, "shipped_files", original)
        self.rp.shipped_files = lambda: [f for f in original() if not f.startswith("product/evidence/")]
        blind = self.rp.unscanned_shipped()
        self.assertTrue(blind, "a vak folt nem lett jelentve")
        self.assertTrue(all(f.startswith("product/evidence/") for f in blind))
        ok, detail = self.rp.check_shipped_text(VERSION)
        self.assertFalse(ok)
        self.assertIn("no scan walks", detail)

    def test_pattern_holder_exemption_stays_minimal(self):
        """A mentesség azokra a fájlokra szól, amik MAGUK a minták: a kereső és a tesztjei, amik szándékosan
        ültetnek el egy leletet, hogy bizonyítsák, a kereső megfogja. Névvel felsorolva, nem könyvtárral —
        egy könyvtár-alakú kivétel csendben ránőhet egy később megtelő, generált mappára. A lista BŐVÜLÉSE
        legyen mindig kimondott döntés: ez a teszt az, ami kimondatja."""
        self.assertEqual(set(self.rp.PATTERN_HOLDERS),
                         {"product/release_preflight.py", "product/test_product_page.py",
                          "product/test_product_packaging.py"})
        for f in self.rp.PATTERN_HOLDERS:
            self.assertTrue(os.path.isfile(os.path.join(REPO, f)), "mentesség egy nem létező fájlra: %s" % f)


if __name__ == "__main__":
    unittest.main()


class PackerAndSealAgreeOnWhatShips(unittest.TestCase):
    """A publikált repóból épített artefaktum UGYANAZ legyen, mint a fejlesztési fából épített.

    Az 1.5.2 post-publish ellenőrzése ezt bukta: a verifikáló megtanulta, hogy a landing-fájlok kívül vannak
    a pecséten, a CSOMAGOLÓ viszont nem — így a publikált repóból 160 fájl és MÁS artefaktum-hash jött ki,
    mint a fejlesztési fából (157). Egy vevő, aki a publikált repóból épít újra, nem azt az archívumot kapta,
    amit aláírtunk. A két oldalnak ugyanazt kell értenie „szállított" alatt, ezért EGY lista van, és mindkettő
    azt olvassa."""

    def setUp(self):
        sys.path.insert(0, HERE)
        import evidence, make_release  # noqa: PLC0415
        self.ev, self.mr = evidence, make_release

    def test_the_packer_excludes_exactly_what_the_seal_calls_furniture(self):
        shipped = set(self.mr.shipped_names(REPO, "HEAD"))
        for name in self.ev.UNSEALED:
            self.assertNotIn(name, shipped, "a csomagoló beveszi, amit a pecsét kívül hagy: %s" % name)

    def test_the_two_lists_are_one_list(self):
        """Nem két egyező másolat — UGYANAZ az objektum forrása. Két másolat idővel szétcsúszik."""
        self.assertEqual(self.mr._unsealed(), set(self.ev.UNSEALED))

    def test_a_tree_with_furniture_ships_the_same_files_as_one_without(self):
        """A publikált repó alakja: ugyanaz a commit + a landing-fájlok. A szállított lista nem változhat."""
        import subprocess, tempfile
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        clone = os.path.join(tmp, "published")
        subprocess.run(["git", "clone", "-q", REPO, clone], check=True, capture_output=True)
        before = self.mr.shipped_names(clone, "HEAD")
        for name in self.ev.UNSEALED:                      # a publish-furniture rákerül, ahogy élesben
            p = os.path.join(clone, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write("landing\n")
        subprocess.run(["git", "-C", clone, "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", clone, "-c", "user.email=t@e.invalid", "-c", "user.name=t",
                        "commit", "-qm", "publish furniture"], check=True, capture_output=True)
        after = self.mr.shipped_names(clone, "HEAD")
        self.assertEqual(before, after, "a furniture megváltoztatta a szállított fájllistát")
