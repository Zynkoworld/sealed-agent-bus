"""The product-mode switch could be bypassed with a symlink — (2026-09-17, MEDIUM-HIGH, conditional).

The finding: the marker's search locations were derived from the DB file's directory with `abspath`, which does NOT resolve a symlink.
From a marker-less directory, through a symlink pointing to the REAL DB, the mode became `dev` while reading the same file.
The partner arm's four measurements: A) symlink, no system marker → dev (bypassed); B) symlink + system marker → product;
C) real path → product; D) real path, without a system marker, a marker next to the DB → product.

The fix: `realpath` is the deciding location (the abspath location STAYS beside it — a union, fail-closed towards product mode), for the
bus_dir/AGENT_BUS_DIR/BRIDGE bases too. And doctor STATES the verdict's scope: this process, not the fleet.
Mutant probe: without the realpath line `test_A_symlink_to_real_db_is_product` fails.

stdlib unittest; isolated directories, SYSTEM_MARKER pointed to a non-existent tmp path, it does not touch the live /etc.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_enforce as enf  # noqa: E402


class MarkerFollowsTheRealFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.real = os.path.join(self.tmp.name, "real"); os.makedirs(self.real)
        self.db = os.path.join(self.real, "bus.db")
        open(self.db, "w").close()
        open(os.path.join(self.real, enf.MARKER), "w").close()                  # a DB MELLETTI marker (D)
        self.alias = os.path.join(self.tmp.name, "alias"); os.makedirs(self.alias)
        self.link = os.path.join(self.alias, "bus.db")
        os.symlink(self.db, self.link)                                          # points to it from a directory WITHOUT a marker
        self._env = dict(os.environ)
        os.environ.pop(enf.MODE_ENV, None)
        os.environ.pop("AGENT_BUS_DIR", None)
        self._p = mock.patch.object(enf, "SYSTEM_MARKER", os.path.join(self.tmp.name, "no-such-system-marker"))
        self._p.start()

    def tearDown(self):
        self._p.stop()
        os.environ.clear(); os.environ.update(self._env)
        self.tmp.cleanup()

    def test_A_symlink_to_real_db_is_product(self):
        self.assertEqual(enf.mode(bus_dir=self.alias, db=self.link), "product")

    def test_C_and_D_real_path_is_product(self):
        self.assertEqual(enf.mode(bus_dir=self.real, db=self.db), "product")

    def test_B_symlink_with_system_marker_is_product(self):
        with mock.patch.object(enf, "SYSTEM_MARKER", os.path.join(self.tmp.name, "sys.on")):
            open(enf.SYSTEM_MARKER, "w").close()
            os.remove(os.path.join(self.real, enf.MARKER))
            self.assertEqual(enf.mode(bus_dir=self.alias, db=self.link), "product")

    def test_control_no_marker_anywhere_is_dev(self):
        os.remove(os.path.join(self.real, enf.MARKER))
        self.assertEqual(enf.mode(bus_dir=self.alias, db=self.link), "dev")
        self.assertEqual(enf.mode(bus_dir=self.real, db=self.db), "dev")

    def test_symlinked_bus_dir_is_resolved_too(self):
        os.remove(os.path.join(self.real, enf.MARKER))
        busreal = os.path.join(self.tmp.name, "busreal"); os.makedirs(busreal)
        open(os.path.join(busreal, enf.MARKER), "w").close()
        buslink = os.path.join(self.tmp.name, "buslink"); os.symlink(busreal, buslink)
        # a bus_dir given through a symlink: the abspath location points to the same place, the realpath one too — both in the list
        paths = enf.marker_paths(bus_dir=buslink, db=self.db)
        self.assertIn(os.path.join(busreal, enf.MARKER), paths)
        self.assertEqual(enf.mode(bus_dir=buslink, db=self.db), "product")

    def test_marker_paths_state_both_forms_realpath_first(self):
        paths = enf.marker_paths(bus_dir=self.alias, db=self.link)
        self.assertEqual(paths[1], os.path.join(self.real, enf.MARKER))        # the real location is decisive
        self.assertIn(os.path.join(self.alias, enf.MARKER), paths)               # the abspath location stays


class DoctorStatesItsScope(unittest.TestCase):
    def test_doctor_says_the_verdict_is_per_process(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(enf, "SYSTEM_MARKER", os.path.join(d, "sys.on")):
            _ok, lines = enf.doctor()
            scope = [l for l in lines if l.startswith("scope:")]
            self.assertEqual(len(scope), 1, lines)
            self.assertIn("THIS process", scope[0])
            self.assertIn("ABSENT", scope[0])
            open(enf.SYSTEM_MARKER, "w").close()
            _ok, lines = enf.doctor()
            self.assertIn("MEGVAN", next(l for l in lines if l.startswith("scope:")))


if __name__ == "__main__":
    unittest.main()
