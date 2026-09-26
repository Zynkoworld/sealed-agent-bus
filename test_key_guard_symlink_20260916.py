"""The key-reading guard: symlink and TOCTOU — our own.

Reading the registry key (`<agent>.pub`) and the private seed (`<agent>.ed25519.key`) used to consist of TWO
operations: first `os.stat` (permission check), then `open` (read). Between the two the
file could be swapped, and `stat` followed the symlink's TARGET — so a symlink pointing to a root-owned file
passed the guard, while the link itself could be rewritten by anyone who can write to the directory.

Fix: a single open with `O_NOFOLLOW`, and the permission check on the OPENED fd
(`fstat`); on the seed path `lstat` + "a regular file only".

A NOTE on the threat model: the key directory is root-owned and not world-writable, so this is
DEFENCE IN DEPTH, not the last wall. But the principle stands: what we check is what we read.

stdlib unittest. Runs as root (the fleet runs it so); if not root, the test skips itself.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402


@unittest.skipUnless(os.geteuid() == 0, "the guard requires root-owned files")
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

    # ── control: a real, root-owned key file is read ──────────────
    def test_control_regular_root_owned_key_is_read(self):
        p = os.path.join(self.keys, "hub.pub")
        with open(p, "w") as f:
            f.write("cd" * 32)
        os.chmod(p, 0o644)
        self.assertEqual(ab._a2_guarded_read(p), "cd" * 32)
        self.assertEqual(ab._a2_load_registry_pubkey("hub", self.keys), "cd" * 32)

    # ── FINDING: a symlink in the key's place is not read (`stat` looked at the TARGET) ──
    def test_symlinked_key_is_refused(self):
        p = os.path.join(self.keys, "hub.pub")
        os.symlink(self.real, p)
        self.assertIsNone(ab._a2_guarded_read(p),
                          "the symlink passed the guard: the permissions are the target's, but the content is controlled "
                          "by the link's owner")
        self.assertIsNone(ab._a2_load_registry_pubkey("hub", self.keys))

    # ── the same on the private seed's path ─────────────────────────────────────────
    def test_symlinked_private_seed_is_refused(self):
        real = os.path.join(self.tmp.name, "seed.key")
        with open(real, "w") as f:
            f.write("11" * 32)
        os.chmod(real, 0o600)
        link = os.path.join(self.keys, "hub.ed25519.key")
        os.symlink(real, link)
        self.assertIsNone(ab._a2_default_sign_key("hub", keys_dir=self.keys),
                          "a symlink in the seed's place was accepted")

    def test_control_regular_private_seed_is_accepted(self):
        p = os.path.join(self.keys, "hub.ed25519.key")
        with open(p, "w") as f:
            f.write("22" * 32)
        os.chmod(p, 0o600)
        self.assertEqual(ab._a2_default_sign_key("hub", keys_dir=self.keys), p)

    # ── lax permissions still fail (an old rule, not weakened) ────
    def test_control_lax_permissions_still_refused(self):
        p = os.path.join(self.keys, "hub.ed25519.key")
        with open(p, "w") as f:
            f.write("33" * 32)
        os.chmod(p, 0o644)
        self.assertIsNone(ab._a2_default_sign_key("hub", keys_dir=self.keys))

    # ── a traversal attempt still fails ──────────────────────────
    def test_control_traversal_in_sender_name_is_refused(self):
        self.assertIsNone(ab._a2_load_registry_pubkey("../elsewhere", self.keys))
        self.assertIsNone(ab._a2_load_registry_pubkey("..", self.keys))
        self.assertIsNone(ab._a2_load_registry_pubkey("", self.keys))


if __name__ == "__main__":
    unittest.main()
