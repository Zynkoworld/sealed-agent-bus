"""The TWO deciders of product mode answer the same question — so they must move together.

WHY THIS FILE EXISTS. `bus_enforce.mode()` and `agent_bus._product_hint()` decide the same thing:
whether we are in product mode. The first decides when the module is present, the second when the module CANNOT be
imported — i.e. it is the final guard that makes a missing module fail-closed and not silently dev.

Measured on the published 1.5.3: the symlink fix (`realpath` is also a search location) got into only one
side. The same DB, the same marker, the same missing module — on the real path `recv` refused
delivery, but through a symlink pointing to the DB it HANDED OUT the same letters.

This is not a "we forgot a line" bug but a recurring class: ONE decision, TWO implementations. The
packer's and the seal's two "shipped" definitions were the same. So the test does not pin the CONTENT (that
may change), but that the TWO AGREE: if either side gets a new search location and the other does not, this fails.
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
        """THE POINT: the two lists are the same set. If one grows and the other does not, this fails — even
        if no one wrote a single concrete scenario for the new location."""
        mine = {os.path.normpath(p) for p in ab._product_hint_paths(self.db)}
        theirs = {os.path.normpath(p) for p in be.marker_paths(db=self.db)}
        self.assertEqual(mine, theirs,
                         "the two deciders of product mode look at DIFFERENT locations — the weaker one becomes the fail-open")

    def test_a_symlinked_db_is_product_mode_on_both_sides(self):
        """The concrete, measured case: the marker in the REAL directory, the DB addressed through a symlink."""
        open(os.path.join(self.real, ".product_mode.on"), "w").close()
        self.assertEqual(be.mode(db=self.linked_db), "product")
        self.assertTrue(ab._product_hint(self.linked_db),
                        "the final guard does not see the marker behind the symlink — without the module this is fail-open")

    def test_without_a_marker_neither_side_claims_product(self):
        """Counter-check: the rule is not 'always product mode'. Without a marker both are dev."""
        self.assertEqual(be.mode(db=self.linked_db), "dev")
        self.assertFalse(ab._product_hint(self.linked_db))

    def test_an_explicit_dev_env_does_not_switch_the_marker_off(self):
        """The marker is in root's hands, the env in anyone's: `AGENT_BUS_MODE=dev` cannot switch it back."""
        open(os.path.join(self.real, ".product_mode.on"), "w").close()
        os.environ["AGENT_BUS_MODE"] = "dev"
        try:
            self.assertTrue(ab._product_hint(self.linked_db))
            self.assertEqual(be.mode(db=self.linked_db), "product")
        finally:
            os.environ.pop("AGENT_BUS_MODE", None)


if __name__ == "__main__":
    unittest.main()
