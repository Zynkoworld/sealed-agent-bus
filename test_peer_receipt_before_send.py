"""Matesensei (2026-09-15 este) — a `33b1510` küldés-ELŐTTI nyugta-sora HAMISAN VÁDOLJA a becsületes közjegyzőt.

A `33b1510` a kérés-sort (`{"phase":"request","sent":[…],"ack":N}`) a `subprocess.run` ELÉ viszi
(`bus_ssh_client.py:65-70`), hogy elveszett VÁLASZ esetén is tudjuk, mit küldtünk. A sor azonban akkor is
bent marad, ha a kör el sem jutott a szerverhez — a `bus_ssh_client.py:73-78` korai `return`-jei (nem-JSON
válasz, nem-objektum válasz) és a `timeout` kivétel UTÁN már nincs, ami visszavonja.

A nyugta-fájl append-only; a `reconcile` ezt a sort a következő körökben is beszámítja. A BECSÜLETES közjegyző
naplójában nincs bejegyzés (helyesen: semmit nem kapott), tehát a report `sent_not_logged` + `ack_sent_not_logged`
eltérést ad, `ok:false`, CLI `rc=1` — miközben a közjegyző semmit nem vétett. A kiadott ack-ot a fél még csak nem
is küldte el, mégis „elküldöttként" áll a saját bizonyítékában.

Mért regresszió (ugyanaz a forgatókönyv, `ssh` = nem-JSON a stdout-on + exit 255):
    bázis `4e18fd6`: nyugta-sor 0 -> ok:true,  eltérés [],                                   rc=0
    fej   `33b1510`: nyugta-sor 1 -> ok:false, [sent_not_logged, ack_sent_not_logged],       rc=1

Irány (javaslat, nem állítás): a kérés-sor maradjon, de kapjon `outcome` mezőt, amit a kör VÉGE állít be
(`delivered-unknown` / `not-sent`), és a `reconcile` csak a `not-sent`-en KÍVÜLI sorokat vegye vádként — a
bizonytalan kimenetel („nem tudom, odaért-e") ne váljon se csendes rendben-né, se vádemeléssé.
stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402
import bus_ssh_client as sc  # noqa: E402

# nem-JSON a stdout-ra + exit 255: a tipikus ssh-hiba. Helyi folyamat, hálózat nélkül.
FAILING_SSH = ["/bin/sh", "-c", "echo 'ssh: connect to host port 22: Connection refused' >&2; echo nem-json; exit 255; :"]


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ReceiptBeforeSend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)   # BECSÜLETES: nem kapott semmit
        env = {"AGENT_BUS_DB": os.path.join(t, "bus.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
               "AGENT_BUS_MODE": "dev", "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
               "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_WAKE_DIR": os.path.join(t, "wake"),
               "AGENT_BUS_NOTARY_LOG": self.log, "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
               "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}
        self.p = mock.patch.dict(os.environ, env, clear=False)
        self.p.start()
        self.state = os.path.join(t, "state")
        os.makedirs(self.state, exist_ok=True)
        sc._save_state(sc._state_path(self.state, "remote1", "hub"), {"stored_max": 4})   # ack=4 lesz

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def failed_round(self):
        res = sc.exchange("remote1", "hub", messages=[{"to": "remote1", "body": "soha-el-nem-kuldott"}],
                          ssh_cmd=FAILING_SSH, state_dir=self.state)
        self.assertIn("error", res, "elő-feltétel: a kör tényleg elhasalt")
        rp = sc.receipts_path(self.state, "remote1", "hub")
        return [json.loads(l) for l in open(rp, encoding="utf-8") if l.strip()] if os.path.exists(rp) else []

    def test_failed_round_does_not_accuse_honest_notary(self):
        """ELVÁRÁS: az oda sem ért kör nem termel eltérést a becsületes közjegyző ellen."""
        rows = self.failed_round()
        self.notary.checkpoint()
        rep = bn.reconcile(bn.export(self.log, 1), "hub", rows, trusted_pub=self.pub)
        self.assertTrue(rep["ok"], "MÉRT: hamis vád a becsületes közjegyző ellen: %r" % ([d["type"] for d in rep["discrepancies"]],))

    def test_failed_round_cli_rc_is_zero(self):
        """ELVÁRÁS: a szkriptelt hívó nem kap rc=1-et azért, mert az SSH elhasalt."""
        rows = self.failed_round()
        self.notary.checkpoint()
        rp = os.path.join(self.tmp.name, "r.jsonl")
        with open(rp, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(r) + "\n" for r in rows))
        rc = bn.main(["reconcile", self.log, "--identity", "hub", "--receipts", rp, "--pub", self.pub])
        self.assertEqual(rc, 0, "MÉRT: rc=1 — a bázison (4e18fd6) rc=0 volt")

    # ── kontroll: a szonda nem vaktában pirosít ─────────────────────────────
    def test_control_no_round_no_discrepancy(self):
        """Kör nélkül (üres nyugta) a becsületes napló tiszta — a szonda a kör hatását méri."""
        self.notary.checkpoint()
        rep = bn.reconcile(bn.export(self.log, 1), "hub", [], trusted_pub=self.pub)
        self.assertTrue(rep["ok"], "kontroll pirosodott: %r" % (rep["discrepancies"],))


if __name__ == "__main__":
    unittest.main()
