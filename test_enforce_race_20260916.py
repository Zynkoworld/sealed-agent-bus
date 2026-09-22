"""A kikényszerítés versenyhelyzete és néma ágai — saját.

Három lelet a nem-Claude kartól, mindhárom a `bus_enforce.check()` körül:
  1. a `seen()` és az `add()` között VERSENY van: két párhuzamos recv mindkettője „nem láttam"-ot
     mér, és mindkettő kézbesít. Az `add()` FALSE-a (INSERT OR IGNORE, „már bent volt") az egyetlen
     atomi jel — eddig eldobtuk.
  2. `record=True` seen-tár NÉLKÜL: a replay-védelem némán kimarad. A fogyasztó út sosem hívhat így.
  3. ha a termék-mód KIZÁRÓLAG a busz melletti markeren áll, akkor aki a buszra írni tud, a markert
     is törölheti -> a kapu némán dev-re esik. Ez üzemeltetési kockázat: a doctor mondja ki HANGOSAN.

Egy negyedik állítás (a `seen`-kulcs tartalmazza az aláírást, tehát újraaláírással megkerülhető)
MÉRÉSSEL CÁFOLVA: az Ed25519 determinista, ugyanaz a kulcs + ugyanaz a tartalom = ugyanaz az aláírás.

stdlib unittest + cryptography.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402


@unittest.skipUnless(ab._A2_HAVE, "cryptography szükséges")
class EnforceRaceAndSilentPaths(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(t, "bus.db")
        priv = ed25519.Ed25519PrivateKey.generate()
        self.priv = priv
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.kp = os.path.join(self.keys, "hub.ed25519.key")
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(pub)
        with open(self.kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        self.p = [
            mock.patch.dict(os.environ, {
                "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": self.keys,
                "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
                "AGENT_BUS_MODE": "product"}, clear=False),
            mock.patch.object(ab, "KEYS_DIR", self.keys),
            mock.patch.object(ab, "_a2_guarded_read",
                              lambda p: (open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None)),
        ]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def signed(self):
        ab.send("hub", "peer", "egy-uzenet", db=self.db, mirror=False, sign_key=self.kp)
        return ab.recv("peer", mark=False, limit=5, db=self.db)[0]

    # ── kontroll: a becsületes sor átmegy ────────────────────────────────────
    def test_control_signed_message_passes(self):
        self.assertEqual(enf.check(self.signed(), keys_dir=self.keys), (True, "ok"))

    # ── 1. verseny: az `add()` FALSE-a = replay, nem néma kézbesítés ─────────
    def test_lost_race_is_a_replay_not_a_delivery(self):
        m = self.signed()

        class RacyStore:
            """A másik folyamat a `seen()` ÉS az `add()` között írta be ugyanazt a kulcsot."""
            def seen(self, key):
                return False                      # mi még nem láttuk...

            def add(self, key, ts_s):
                return False                      # ...de a beszúrás azt mondja: már bent volt

        ok, why = enf.check(m, seen=RacyStore(), record=True, keys_dir=self.keys)
        self.assertFalse(ok, "a versenyt vesztő fél is kézbesített volna (dupla kézbesítés)")
        self.assertEqual(why, "replay")

    def test_control_won_race_still_delivers(self):
        m = self.signed()

        class WinningStore:
            def seen(self, key):
                return False

            def add(self, key, ts_s):
                return True                       # mi írtuk be elsőként

        self.assertEqual(enf.check(m, seen=WinningStore(), record=True, keys_dir=self.keys), (True, "ok"))

    # ── 2. fogyasztás seen-tár nélkül: programozói hiba, nem néma átengedés ──
    def test_consuming_without_a_seen_store_is_an_error(self):
        with self.assertRaises(ValueError):
            enf.check(self.signed(), seen=None, record=True, keys_dir=self.keys)

    def test_classifying_without_a_seen_store_is_allowed(self):
        self.assertEqual(enf.check(self.signed(), seen=None, record=False, keys_dir=self.keys), (True, "ok"))

    # ── 3. a doctor kimondja, ha a termék-mód busz-írható markeren áll ───────
    def test_doctor_warns_when_product_mode_rests_on_a_bus_writable_marker(self):
        open(os.path.join(self.tmp.name, enf.MARKER), "w").close()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_BUS_MODE", None)
            with mock.patch.object(enf.os.path, "exists",
                                   lambda p: False if p == enf.SYSTEM_MARKER else os.path.lexists(p)):
                ok, lines = enf.doctor()
        self.assertFalse(ok)
        self.assertTrue(any("némán dev-re esik" in l for l in lines),
                        "a doctor nem mondja ki a néma downgrade kockázatát: %r" % (lines,))

    # ── 4. MEGCÁFOLT lelet: az újraaláírás nem ad új seen-kulcsot ────────────
    def test_resigning_the_same_content_yields_the_same_key(self):
        m = self.signed()
        again = self.priv.sign(ab._a2_content_bytes(m)).hex()
        self.assertEqual(again, m["sig"], "az Ed25519 determinista: ugyanaz a tartalom = ugyanaz az aláírás")
        self.assertEqual(enf.content_key(m), enf.content_key({**m, "sig": again}),
                         "az újraaláírt másolat ugyanazt a replay-kulcsot kapja")


if __name__ == "__main__":
    unittest.main()
