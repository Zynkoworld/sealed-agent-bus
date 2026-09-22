"""Matesensei (2026-09-15 este) — a `33b1510` kétirányú `reconcile`-ja az ack ÉRTÉKÉT köti meg, a kurzor CÉLJÁT nem.

A `33b1510` javítása (`ack_logged_not_sent`) azt méri, hogy a naplózott ack-bejegyzés `(ack U)` mezője szerepel-e a
fél nyugtájában. A bejegyzés reason-formátuma azonban HÁROM számot hordoz:

    "cursor F->T (ack U)"      (`bus_notary.py:433`, írja: `bus_ssh_exchange.py:104`)

és a `reconcile` (`bus_notary.py:485-492`) az `U`-t veti a nyugtához, a kurzor célját (`T`) viszont KRITIKA NÉLKÜL
elfogadja: `expected, ack_from = to, frm`. A becsületes íráskor `T = max(F, min(U, cap))`, azaz `T <= max(F, U)`
(`agent_bus.py:681`, `_ack_target` előre-only + clamp). A nem becsületes közjegyző ezt a kötést elhagyja: a fél
VALÓDI ack-ját (U) írja be, de a kurzort tetszőlegesen előre viszi (T > U), és a busz kurzorát is oda állítja.

  - `ack_logged_not_sent` nem keletkezik: U szerepel a nyugtában;
  - `cursor_moved_without_logged_ack` nem keletkezik: a következő bejegyzés `F`-je pont az előre vitt `T`;
  - `delivered_not_received` nem keletkezik: a lenyelt postáról SEMMILYEN bejegyzés nem készül.

-> `ok:true`, `disc:[]`, `rc=0` termék-módban is, aláírt (`trusted:true`) szeleten, miközben a posta véglegesen
elveszett. A 13:BLOCKER-hez képest a hamisítás OLCSÓBB: nem kell kitalált ack-bejegyzést gyártani, elég a
becsületes bejegyzés EGY számát átírni.

A kontroll (`..._control_*`) ZÖLD: ugyanez a kód a -alakú hamisításra (kitalált U) most már jelez, tehát a
szonda nem a mérés hiányát, hanem a megmaradt rést méri.
stdlib unittest + cryptography.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class CursorTargetUnbound(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
               "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
               "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
               "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"), "AGENT_WAKE_STATE_DIR": os.path.join(t, "wst"),
               "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}
        self.p = mock.patch.dict(os.environ, env, clear=False)
        self.p.start()
        for i in range(8):
            ab.send("hub", "remote1", "titkos-%d" % i, db=self.db, mirror=False)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def forge_ack(self, frm, to, up):
        """A közjegyző saját kezűleg írt, ALAKILAG HELYES ack-bejegyzése (a napló az övé)."""
        self.notary.record(sender_identity="remote1", sender_auth="ssh-key", recipient="remote1", kind="ack",
                           decision="accepted", envelope={"ack": up, "cursor_from": frm, "cursor_to": to},
                           reason="cursor %d->%d (ack %d)" % (frm, to, up))

    def rec(self, receipts):
        return bn.reconcile(bn.export(self.log, 1), "remote1", receipts, trusted_pub=self.pub)

    # ── a lenyelés: a fél ack=4-et küld, a közjegyző a kurzort 8-ra viszi ────
    def _swallow(self, logged_to):
        self.forge_ack(0, logged_to, 4)          # a naplóba írt bejegyzés
        self.notary.checkpoint()                 # a közjegyző a SAJÁT kulcsával lezárja a hamisított szeletet
        ab.ack("remote1", 8, db=self.db)         # a valóságban a kurzor 8-ra ugrik: az 5–8. üzenet elveszett
        return [{"phase": "request", "sent": [], "ack": 4, "received": []}]   # a fél nyugtája: ack=4-et küldött

    def test_mail_is_really_lost(self):
        """Elő-feltétel: a kurzor 8-ra állítása UTÁN a fél semmit nem kap — a posta tényleg elveszett."""
        self._swallow(8)
        self.assertEqual(ab.cursor_of("remote1", db=self.db), 8)
        self.assertEqual(ab.recv("remote1", db=self.db, mark=False), [])

    def test_cursor_target_beyond_acked_is_reported(self):
        """ELVÁRÁS: a naplózott kurzor-cél (T=8) nagyobb, mint a fél ack-ja (U=4) -> eltérés."""
        r = self.rec(self._swallow(8))
        self.assertTrue(r["trusted"], "a szelet aláírt — a hamisítás a bizalmi szeleten belül van")
        self.assertFalse(r["ok"], "MÉRT: ok:true, pedig 4 üzenet véglegesen elveszett; disc=%r" % (r["discrepancies"],))

    def test_cli_rc_nonzero_in_product_mode(self):
        """ELVÁRÁS: a szkriptelt hívó termék-módban NEM kap rc=0-t erre."""
        receipts = self._swallow(8)
        rp = os.path.join(self.tmp.name, "receipts.jsonl")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(json.dumps(receipts[0]) + "\n")
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "product"}, clear=False):
            rc = bn.main(["reconcile", self.log, "--identity", "remote1", "--receipts", rp, "--pub", self.pub])
        self.assertNotEqual(rc, 0, "MÉRT: rc=0 termék-módban is")

    # ── kontrollok: a szonda a RÉST méri, nem a mérés hiányát ───────────────
    def test_control_invented_ack_value_is_caught(self):
        """A -alakú hamisítás (kitalált U=8) a 33b1510-en MÁR jelez — a javítás működik."""
        self.forge_ack(0, 8, 8)                  # kitalált U=8: a fél csak ack=4-et küldött
        self.notary.checkpoint()
        r = self.rec([{"phase": "request", "sent": [], "ack": 4, "received": []}])
        self.assertTrue(r["trusted"])
        self.assertFalse(r["ok"])
        self.assertIn("ack_logged_not_sent", [d["type"] for d in r["discrepancies"]])

    def test_control_honest_round_is_ok(self):
        """Becsületes bejegyzés (T=U=4, a kurzor is 4): nincs eltérés — a szonda nem vaktában pirosít."""
        self.forge_ack(0, 4, 4)
        self.notary.checkpoint()
        ab.ack("remote1", 4, db=self.db)
        r = self.rec([{"phase": "request", "sent": [], "ack": 4, "received": []}])
        self.assertTrue(r["ok"], "kontroll pirosodott: %r" % (r["discrepancies"],))


if __name__ == "__main__":
    unittest.main()
