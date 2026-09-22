"""mérési köre a `40bb502`-re — a marker-könyvtár SZÜLŐJE (2026-09-16 ).

A négy szondája szó szerint átvéve, mert mind a négy mérten igaz volt:

  — a `state_dir_warnings`-nak NEM volt termelési hívója: a figyelmeztetés csak a saját
           unit-tesztjében szólalt meg. „A mátrix 6d.1 »jelzett« minősítése ezért a mai kódon nem mérhető."
           Javítva: az `agent_bus_watcher.main` — az egyetlen termelési belépő az ébresztés-úton —
           INDULÁSKOR kiírja a listát a stderr-re.
  — a verdikt csak a LEVELET nézte, a csere viszont csak a SZÜLŐRE kíván írásjogot:
           `rename(state, state.elrejtve); makedirs(state, 0700)` — a levél jogai érdektelenek (0o000-val is
           mérve). Egy root-tulajdonú 0700 levél így TISZTA bizonyítványt kapott egy világ-írható szülő alatt.
           Az ő szava: „ez rosszabb, mint a hiányzó jelzés: HAMIS MEGNYUGTATÁS." Javítva: a lánc a szülőkön
           fölfelé is vizsgált.
  — az `os.makedirs(mode=)` a KÖZTES szinteket mode nélkül hozza létre, tehát `umask 0002` alatt a
           SAJÁT kódunk állította elő a előfeltételét (szülő 0775, levél 0700). Javítva: a láncot mi
           építjük, szigorú móddal (`_make_strict_dir`).
  — a fenyegetés-leírás nevezze meg, hogy ugyanebben a könyvtárban dől el az ÜGYELET is
           (`duty_active.json`). A mátrix 6d.1 sora ezt most kimondja.

SAJÁT PONTOSÍTÁS a méréséhez: a STICKY bit (pl. `/tmp` 1777) megakadályozza IDEGEN bejegyzés átnevezését,
tehát egy sticky, root-tulajdonú szülő alatt a root-tulajdonú marker-könyvtár nem cserélhető ki. A
figyelmeztetés ezért a sticky esetet NEM jelenti — különben farkast kiáltanánk minden `/tmp` alatti futásra.

stdlib unittest.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_wake as aw  # noqa: E402


class WarningHasAProductionCaller(unittest.TestCase):
    def test_state_dir_warnings_is_called_from_production_code(self):
        """a definíción, a docstringen és a SAJÁT tesztjein kívül legyen VALÓDI hívó."""
        hits = []
        for root, dirs, files in os.walk(HERE):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "docs")]
            for f in files:
                if not f.endswith(".py") or f.startswith("test_"):
                    continue
                p = os.path.join(root, f)
                for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                    if "state_dir_warnings(" in line and not line.strip().startswith("def "):
                        hits.append("%s:%d" % (os.path.basename(p), i))
        self.assertTrue(hits, "a state_dir_warnings()-nak nincs termelési hívója — a jelzés senkihez nem jut el")

    def test_the_watcher_prints_them_on_startup(self):
        """A hívó a VALÓDI belépőn legyen, ne egy sosem futó ágban."""
        src = open(os.path.join(HERE, "agent_bus_watcher.py"), encoding="utf-8").read()
        self.assertRegex(src, r"state_dir_warnings\(\)", "a watcher nem kérdezi meg a marker-könyvtár állapotát")
        self.assertIn("stderr", src.split("state_dir_warnings")[1][:400],
                      "a figyelmeztetés nem az üzemeltetőhöz megy (stderr)")


class ParentDirIsJudged(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state")
        self.p = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.state}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        try:
            os.chmod(self.tmp.name, 0o700)
        except OSError:
            pass
        self.tmp.cleanup()

    def test_substitution_needs_only_the_parent_and_it_is_not_silent(self):
        """a csere a SZÜLŐN múlik; a levél jogai érdektelenek. A verdikt ezt mondja ki."""
        os.chmod(self.tmp.name, 0o777)
        aw.enter_sleep_safe("alfa")
        self.assertTrue(aw.is_asleep("alfa"))
        w = aw.state_dir_warnings()
        self.assertTrue(any("SZÜLŐJE" in x for x in w),
                        "a világ-írható szülő alatt a verdikt TISZTA bizonyítványt adott: %r" % w)
        # …és a csere tényleg működik: a levél jogai nem számítanak
        os.chmod(self.state, 0o000)
        os.rename(self.state, self.state + ".elrejtve")
        os.makedirs(self.state, mode=0o700)
        self.assertFalse(aw.is_asleep("alfa"), "előfeltétel: a cserével az alvó agent ébreszthetővé válik")
        os.chmod(self.state + ".elrejtve", 0o700)

    def test_writable_parent_produces_more_warnings_than_a_tight_parent(self):
        os.chmod(self.tmp.name, 0o700)
        aw.enter_sleep_safe("alfa")
        tight = len(aw.state_dir_warnings())
        os.chmod(self.tmp.name, 0o777)
        loose = len(aw.state_dir_warnings())
        self.assertGreater(loose, tight, "a tág jogú szülő ugyanannyi figyelmeztetést adott, mint a szigorú")

    @unittest.skipUnless(os.geteuid() == 0, "a ROOT-tulajdon a sticky-védés előfeltétele (Joint NIT)")
    def test_a_sticky_parent_is_not_cried_wolf_about(self):
        """SAJÁT pontosítás: a sticky bit megvédi az idegen bejegyzést — ezt nem jelentjük leletként.

        az egyik kar az eredeti alak nem-root futtatón elesett, mert a szülő tulajdonosa NEM root,
        és a uid-figyelmeztetés helyesen megszólal. A sticky-védés állítása csak root-tulajdonú szülőre szól,
        ezért a teszt most kimondja az előfeltételét, ahelyett hogy feltételezné.
        """
        os.chmod(self.tmp.name, 0o1777)
        aw.enter_sleep_safe("alfa")
        self.assertEqual([x for x in aw.state_dir_warnings() if "SZÜLŐJE" in x and "sticky" not in x], [],
                         "sticky, root-tulajdonú szülőre nem jár figyelmeztetés")


class FreshTreeParentMode(unittest.TestCase):
    def test_parent_is_strict_even_under_a_loose_umask(self):
        """`umask 0002` alatt a SAJÁT kódunk hozta létre 0775-tel a szülőt."""
        code = (
            "import os, sys, tempfile\n"
            "sys.path.insert(0, %r)\n"
            "os.umask(0o002)\n"
            "t = tempfile.mkdtemp()\n"
            "sd = os.path.join(t, 'bridge', 'state')\n"
            "os.environ['AGENT_WAKE_STATE_DIR'] = sd\n"
            "import agent_wake as aw\n"
            "aw.enter_sleep_safe('alfa')\n"
            "print('%%o %%o' %% (os.stat(os.path.dirname(sd)).st_mode & 0o777, os.stat(sd).st_mode & 0o777))\n"
            % HERE)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr[:400])
        parent_mode, leaf_mode = out.stdout.split()
        self.assertEqual(leaf_mode, "700")
        self.assertEqual(parent_mode, "700",
                         "a köztes szint a umask szerint jött létre (%s) — a saját kódunk állítja elő a "
                         "csere előfeltételét" % parent_mode)


if __name__ == "__main__":
    unittest.main()
