"""Az SSH-beléptető sor támadása — saját.

Ez a modul állítja elő azt az `authorized_keys` sort, amit az operátor a busz-gépre tesz — tehát ez az
ÉLESÍTÉS kapuja. Négy lelet a nem-Claude kartól:

  1. nincs `from=` forráskorlát -> egy kiszivárgott kulcs a világ bármely pontjáról használható.
     Javítás: `--from` kapcsoló; nélküle a CLI FIGYELMEZTET (a korlát a partner címétől függ, ezért opció).
  2. az idempotencia CSENDES DOWNGRADE volt: ha a kulcs már bent volt egy gyengébb (restrict nélküli vagy
     más identitásra pinelt) sorban, a modul „already present"-et mondott, és a korlátozott sor SOSEM
     került be. Javítás: azonos kulcs + eltérő sor -> hangos hiba.
  3. az `ssh-rsa` bármilyen hosszal átment (csak az alakot néztük). Javítás: a blob dekódolása és a modulus
     bithosszának ellenőrzése (min. 3072; ed25519 az ajánlott).
  4. MEGCÁFOLVA: shell-injekció a `command=`-ba — az identitás charsetje kötött, a kulcs-komment levágva, a
     parancs metakarakter-mentes.

stdlib unittest.
"""
import base64
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_ssh_enroll as en  # noqa: E402

CMD = "/usr/bin/python3 /opt/agent-bus/bus_ssh_exchange.py"


def _ssh_blob(*fields):
    return base64.b64encode(b"".join(struct.pack(">I", len(f)) + f for f in fields)).decode()


def ed25519_key():
    return "ssh-ed25519 %s teszt@gep" % _ssh_blob(b"ssh-ed25519", os.urandom(32))


def rsa_key(bits):
    n = (1 << (bits - 1)) | 1
    modulus = n.to_bytes(bits // 8, "big")
    return "ssh-rsa %s teszt@gep" % _ssh_blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + modulus)


class EnrollHardening(unittest.TestCase):
    # ── kontroll: a korlátozott sor alakja ──────────────────────────────────
    def test_control_line_shape(self):
        line = en.enroll_line("peer", ed25519_key(), CMD)
        self.assertTrue(line.startswith('command="%s peer",restrict,' % CMD))
        for opt in ("no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding", "no-user-rc"):
            self.assertIn(opt, line)
        self.assertNotIn("teszt@gep", line, "a kulcs-komment nem kerülhet a sorba")

    # ── 1: from= forráskorlát ───────────────────────────────────────────────
    def test_from_restriction_is_emitted_and_validated(self):
        line = en.enroll_line("peer", ed25519_key(), CMD, source="192.0.2.0/24")
        self.assertIn('from="192.0.2.0/24",restrict', line)
        for bad in ('192.0.2.5" command="rm -rf /', "192.0.2.1 192.0.2.2", 'x"y'):
            with self.subTest(src=bad):
                with self.assertRaises(ValueError):
                    en.enroll_line("peer", ed25519_key(), CMD, source=bad)

    # ── 3: kulcs-erősség ────────────────────────────────────────────────────
    def test_weak_rsa_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            en.enroll_line("peer", rsa_key(1024), CMD)
        self.assertIn("1024 bits", str(cm.exception))

    def test_strong_rsa_is_accepted(self):
        self.assertIn("ssh-rsa", en.enroll_line("peer", rsa_key(4096), CMD))

    def test_blob_type_must_match_the_prefix(self):
        fake = "ssh-ed25519 %s x" % _ssh_blob(b"ssh-rsa", os.urandom(32))
        with self.assertRaises(ValueError) as cm:
            en.enroll_line("peer", fake, CMD)
        self.assertIn("does not match", str(cm.exception))

    # ── 2: nincs csendes downgrade ──────────────────────────────────────────
    def test_existing_weaker_line_is_not_silently_kept(self):
        key = ed25519_key()
        line = en.enroll_line("peer", key, CMD)
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        with open(path, "w", encoding="utf-8") as f:                    # RÉGI, korlátozás nélküli sor
            f.write("%s\n" % " ".join(key.split()[:2]))
        with self.assertRaises(ValueError) as cm:
            en.write_line(path, line)
        self.assertIn("DIFFERENT line", str(cm.exception))

    def test_identical_line_is_a_noop(self):
        line = en.enroll_line("peer", ed25519_key(), CMD)
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        self.assertTrue(en.write_line(path, line))
        self.assertFalse(en.write_line(path, line), "ugyanaz a sor másodszor nem duplikálódik")

    def test_same_key_other_identity_is_refused(self):
        key = ed25519_key()
        path = os.path.join(tempfile.mkdtemp(), "authorized_keys")
        en.write_line(path, en.enroll_line("peer", key, CMD))
        with self.assertRaises(ValueError):
            en.write_line(path, en.enroll_line("masik", key, CMD))

    # ── 4: MEGCÁFOLT — shell-injekció a command=-ba ─────────────────────────
    def test_shell_metacharacters_cannot_enter(self):
        for ident in ("peer; rm -rf /", 'peer" ', "peer$(id)", "../peer", "peer\nmasik"):
            with self.subTest(i=ident):
                with self.assertRaises(ValueError):
                    en.enroll_line(ident, ed25519_key(), CMD)
        with self.assertRaises(ValueError):
            en.enroll_line("peer", ed25519_key(), 'python3 x.py" ; rm -rf / ; echo "')


if __name__ == "__main__":
    unittest.main()
