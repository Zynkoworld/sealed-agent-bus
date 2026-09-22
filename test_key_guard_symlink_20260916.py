"""A kulcs-olvasás guardja: symlink és TOCTOU — saját.

A registry-kulcs (`<agent>.pub`) és a privát seed (`<agent>.ed25519.key`) beolvasása eddig KÉT
műveletből állt: előbb `os.stat` (jogosultság-ellenőrzés), aztán `open` (olvasás). A kettő között a
fájl kicserélhető, és a `stat` a symlink CÉLJÁT követte — tehát egy root-tulajdonú fájlra mutató
symlink átment a guardon, miközben magát a linket bárki átírhatta, aki a könyvtárba írhat.

Javítás: egyetlen megnyitás `O_NOFOLLOW`-val, és a jogosultság-ellenőrzés a MEGNYITOTT fd-n
(`fstat`); a seed-útnál `lstat` + „csak valódi fájl".

MEGJEGYZÉS a fenyegetési modellhez: a kulcs-könyvtár root-tulajdonú és nem világ-írható, tehát ez
MÉLYSÉGI VÉDELEM, nem az utolsó fal. Az elv viszont áll: amit ellenőrzünk, azt olvassuk is.

stdlib unittest. Root alatt fut (a flotta így futtatja); ha nem root, a teszt kihagyja magát.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402


@unittest.skipUnless(os.geteuid() == 0, "a guard root-tulajdonú fájlokat követel")
class KeyGuardFollowsNoSymlink(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = os.path.join(self.tmp.name, "keys")
        os.makedirs(self.keys, mode=0o755)
        self.real = os.path.join(self.tmp.name, "elsewhere.pub")
        with open(self.real, "w") as f:
            f.write("ab" * 32)
        os.chmod(self.real, 0o644)

    def tearDown(self):
        self.tmp.cleanup()

    # ── kontroll: a valódi, root-tulajdonú kulcsfájl olvasható ──────────────
    def test_control_regular_root_owned_key_is_read(self):
        p = os.path.join(self.keys, "hub.pub")
        with open(p, "w") as f:
            f.write("cd" * 32)
        os.chmod(p, 0o644)
        self.assertEqual(ab._a2_guarded_read(p), "cd" * 32)
        self.assertEqual(ab._a2_load_registry_pubkey("hub", self.keys), "cd" * 32)

    # ── LELET: a symlink a kulcs helyén nem olvasható (a `stat` a CÉLT nézte) ──
    def test_symlinked_key_is_refused(self):
        p = os.path.join(self.keys, "hub.pub")
        os.symlink(self.real, p)
        self.assertIsNone(ab._a2_guarded_read(p),
                          "a symlink átment a guardon: a jogosultság a CÉLÉ, a tartalmat viszont a link gazdája "
                          "irányítja")
        self.assertIsNone(ab._a2_load_registry_pubkey("hub", self.keys))

    # ── a privát seed útján ugyanaz ─────────────────────────────────────────
    def test_symlinked_private_seed_is_refused(self):
        real = os.path.join(self.tmp.name, "seed.key")
        with open(real, "w") as f:
            f.write("11" * 32)
        os.chmod(real, 0o600)
        link = os.path.join(self.keys, "hub.ed25519.key")
        os.symlink(real, link)
        self.assertIsNone(ab._a2_default_sign_key("hub", keys_dir=self.keys),
                          "a seed helyén álló symlink elfogadott volt")

    def test_control_regular_private_seed_is_accepted(self):
        p = os.path.join(self.keys, "hub.ed25519.key")
        with open(p, "w") as f:
            f.write("22" * 32)
        os.chmod(p, 0o600)
        self.assertEqual(ab._a2_default_sign_key("hub", keys_dir=self.keys), p)

    # ── a laza jogosultság továbbra is bukik (régi szabály, nem gyengült) ────
    def test_control_lax_permissions_still_refused(self):
        p = os.path.join(self.keys, "hub.ed25519.key")
        with open(p, "w") as f:
            f.write("33" * 32)
        os.chmod(p, 0o644)
        self.assertIsNone(ab._a2_default_sign_key("hub", keys_dir=self.keys))

    # ── a traversal-kísérlet változatlanul elbukik ──────────────────────────
    def test_control_traversal_in_sender_name_is_refused(self):
        self.assertIsNone(ab._a2_load_registry_pubkey("../elsewhere", self.keys))
        self.assertIsNone(ab._a2_load_registry_pubkey("..", self.keys))
        self.assertIsNone(ab._a2_load_registry_pubkey("", self.keys))


if __name__ == "__main__":
    unittest.main()
