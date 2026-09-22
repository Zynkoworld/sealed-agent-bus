"""A termék-mód KÉT eldöntője ugyanazt a kérdést válaszolja meg — tehát együtt kell mozdulniuk.

MIÉRT LÉTEZIK EZ A FÁJL. A `bus_enforce.mode()` és az `agent_bus._product_hint()` ugyanazt dönti el:
termék-módban vagyunk-e. Az első a modul jelenlétében dönt, a második akkor, amikor a modul NEM
importálható — vagyis a végső őr, ami miatt a hiányzó modul fail-closed és nem csendes dev.

A publikált 1.5.3-on mérve: a symlink-javítás (a `realpath` is keresési hely) csak az egyik oldalra
került be. Ugyanaz a DB, ugyanaz a marker, ugyanaz a hiányzó modul — a valódi úton a `recv` megtagadta
a kézbesítést, a DB-re mutató symlinken át viszont KIADTA ugyanazokat a leveleket.

Ez nem „elfelejtettünk egy sort" hiba, hanem visszatérő osztály: EGY döntés, KÉT implementáció. Ugyanez
volt a csomagoló és a pecsét két „shipped" definíciója is. Ezért a teszt nem a TARTALMAT rögzíti (az
változhat), hanem a KETTŐ EGYEZÉSÉT: ha bármelyik oldal új keresési helyet kap és a másik nem, ez elbukik.
stdlib unittest.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as be  # noqa: E402


class TheTwoDecidersLookAtTheSamePlaces(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.real = os.path.join(self.tmp.name, "real")
        self.link = os.path.join(self.tmp.name, "link")
        os.makedirs(self.real), os.makedirs(self.link)
        self.db = os.path.join(self.real, "bus.db")
        open(self.db, "w").close()
        self.linked_db = os.path.join(self.link, "bus.db")
        os.symlink(self.db, self.linked_db)
        for k in ("AGENT_BUS_MODE", "AGENT_BUS_DIR", "AGENT_BRIDGE_DIR"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_search_sets_are_the_same(self):
        """A LÉNYEG: a két lista ugyanaz a halmaz. Ha az egyik bővül és a másik nem, ez bukik — akkor is,
        ha egyetlen konkrét forgatókönyvet sem írt meg senki az új helyre."""
        mine = {os.path.normpath(p) for p in ab._product_hint_paths(self.db)}
        theirs = {os.path.normpath(p) for p in be.marker_paths(db=self.db)}
        self.assertEqual(mine, theirs,
                         "a termék-mód két eldöntője MÁS helyeket néz — a gyengébbik lesz a fail-open")

    def test_a_symlinked_db_is_product_mode_on_both_sides(self):
        """A konkrét, mért eset: a marker a VALÓDI könyvtárban, a DB symlinken keresztül címezve."""
        open(os.path.join(self.real, ".product_mode.on"), "w").close()
        self.assertEqual(be.mode(db=self.linked_db), "product")
        self.assertTrue(ab._product_hint(self.linked_db),
                        "a végső őr nem látja a markert a symlink mögött — a modul hiányában ez fail-open")

    def test_without_a_marker_neither_side_claims_product(self):
        """Ellenpróba: a szabály nem 'mindig termék-mód'. Marker nélkül mindkettő dev."""
        self.assertEqual(be.mode(db=self.linked_db), "dev")
        self.assertFalse(ab._product_hint(self.linked_db))

    def test_an_explicit_dev_env_does_not_switch_the_marker_off(self):
        """A marker a root kezében van, az env bárkiében: `AGENT_BUS_MODE=dev` nem kapcsolhatja vissza."""
        open(os.path.join(self.real, ".product_mode.on"), "w").close()
        os.environ["AGENT_BUS_MODE"] = "dev"
        try:
            self.assertTrue(ab._product_hint(self.linked_db))
            self.assertEqual(be.mode(db=self.linked_db), "product")
        finally:
            os.environ.pop("AGENT_BUS_MODE", None)


if __name__ == "__main__":
    unittest.main()
