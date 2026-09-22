"""Matesensei (2026-09-15 délután) — a `reconcile` csak a NYUGTA→NAPLÓ irányt ellenőrzi.

A `docs/FEJLESZTES_v1.5.md:51` azt állítja, hogy „a busz-gép napló nélkül előreugratja a távoli fél kurzorát
(elnyelt posta)" esetet a `reconcile` `cursor_moved_without_logged_ack`-kal mutatja ki. A fenyegetés-modell
szereplője a NEM BECSÜLETES KÖZJEGYZŐ, akinek a napló a kezében van — tehát bármely alakilag helyes bejegyzést
meg tud írni. Két úton tünteti el a jelzést, mindkettő `rc=0`-t ad:

  A) kitalált `kind=ack, decision=accepted` bejegyzés („cursor 0->N (ack N)"), amit a távoli fél SOSEM küldött:
     a `reconcile` csak azt nézi, hogy a nyugtákban szereplő ack-oknak van-e bejegyzése (`sent_acks ⊆ logged`),
     a fordított irányt (naplózott ack, amire nincs nyugta) nem; így az `expected` kurzor együtt mozog a
     hamisítással, és a `cursor_moved_without_logged_ack` nem keletkezik.
  B) `decision=delivered` bejegyzések olyan válaszokra, amiket a fél nem kapott meg: ezek az
     `unconfirmed_deliveries` listába kerülnek, de nem eltérések — `ok:true`, `rc=0` termék-módban is.

Mindkét eset teljesen fedett, aláírt szeleten (`trusted:true`) is átmegy, miközben a posta véglegesen elveszett.
A két „elvárt" teszt a mai kódon PIROS, a kontroll ZÖLD (ez bizonyítja, hogy a szonda a jelzést méri).
stdlib unittest + cryptography."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402

_REPLY_KEYS = ("id", "ts", "sender", "topic", "kind", "thread_id", "in_reply_to", "body", "sds")


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ReconcileOneWay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        self.env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
                    "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}
        self.p = mock.patch.dict(os.environ, self.env, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def queue(self, n, prefix="titkos"):
        for i in range(n):
            ab.send("hub", "remote1", "%s-%d" % (prefix, i), db=self.db, mirror=False)

    def x(self, payload):
        import bus_ssh_exchange as ex
        return ex.exchange("remote1", json.dumps(payload), db=self.db,
                           attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)

    def forge(self, **kw):
        """A közjegyző saját kezűleg írt bejegyzése (a napló az övé) — alakilag helyes."""
        self.notary.record(sender_identity="remote1", sender_auth="ssh-key", recipient="remote1", **kw)

    def rec(self, receipts, pub=None):
        return bn.reconcile(bn.export(self.log, 1), "remote1", receipts, trusted_pub=pub or self.pub)

    # ── kontroll: a jelzés MŰKÖDIK, ha a közjegyző nem hamisít ───────────────
    def test_control_withheld_cursor_jump_is_flagged(self):
        self.queue(4)
        ab.ack("remote1", 4, db=self.db)                        # elnyelés napló nélkül
        self.assertEqual(self.x({})["replies"], [])
        rep = self.rec([{"sent": [], "ack": 0, "received": []}])
        self.assertEqual([d["type"] for d in rep["discrepancies"]], ["cursor_moved_without_logged_ack"])
        self.assertFalse(rep["ok"])

    # ── A) kitalált ack-bejegyzés elfedi az elnyelést ────────────────────────
    def test_forged_ack_entry_must_not_hide_a_withheld_cursor_jump(self):
        self.queue(4)
        ab.ack("remote1", 4, db=self.db)                        # elnyelés napló nélkül
        self.forge(envelope={"ack": 4, "cursor_from": 0, "cursor_to": 4}, kind="ack", decision="accepted",
                   reason="cursor 0->4 (ack 4)")                # a fél SOSEM küldött ack-ot
        self.x({})
        self.notary.checkpoint()                                # teljesen fedett, aláírt szelet
        rep = self.rec([{"sent": [], "ack": 0, "received": []}])
        self.assertTrue(rep["trusted"], "a szelet fedett — a lelet nem a trusted:false-on múlik")
        self.assertFalse(rep["ok"], "a naplóban ack van, a fél nyugtáiban nincs: ez eltérés (ack_logged_not_sent)")

    def test_forged_ack_entry_cli_returns_nonzero(self):
        self.queue(4)
        ab.ack("remote1", 4, db=self.db)
        self.forge(envelope={"ack": 4, "cursor_from": 0, "cursor_to": 4}, kind="ack", decision="accepted",
                   reason="cursor 0->4 (ack 4)")
        self.x({})
        self.notary.checkpoint()
        t = self.tmp.name
        exp, rcp = os.path.join(t, "export.jsonl"), os.path.join(t, "receipts.jsonl")
        with open(exp, "w") as f:
            f.write("\n".join(json.dumps(r, sort_keys=True) for r in bn.export(self.log, 1)) + "\n")
        with open(rcp, "w") as f:
            f.write(json.dumps({"sent": [], "ack": 0, "received": []}) + "\n")
        p = subprocess.run([sys.executable, os.path.join(HERE, "bus_notary.py"), "reconcile", exp,
                            "--identity", "remote1", "--receipts", rcp, "--pub", self.pub],
                           capture_output=True, text=True, env=dict(os.environ, AGENT_BUS_MODE="product"))
        self.assertNotEqual(p.returncode, 0, "termék-mód, 4 elveszett üzenet: rc=0 a szkriptelt hívónak „rendben”")

    # ── B) hazug `delivered` — a fél sosem kapta meg ─────────────────────────
    def test_delivered_the_peer_never_received_must_not_be_ok_in_product_mode(self):
        self.queue(3, "elnyelt")
        rows = ab.recv("remote1", mark=False, limit=10, db=self.db)
        replies = [{k: r.get(k) for k in _REPLY_KEYS if k in r} for r in rows]
        self.forge(envelope={"identity": "remote1", "cursor": 0,
                             "reply_sha256": [bn.envelope_hash(x) for x in replies]},
                   kind="pickup", decision="accepted", reason="cursor=0 replies=%d" % len(replies))
        for x in replies:                                       # naplóz, de nem ad ki
            self.forge(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x.get("id"))
        ab.ack("remote1", 3, db=self.db)
        self.forge(envelope={"ack": 3, "cursor_from": 0, "cursor_to": 3}, kind="ack", decision="accepted",
                   reason="cursor 0->3 (ack 3)")
        self.notary.checkpoint()
        rep = self.rec([{"sent": [], "ack": 0, "received": []}])
        self.assertEqual(len(rep["unconfirmed_deliveries"]), 3)
        self.assertEqual(ab.recv("remote1", mark=False, limit=10, db=self.db), [], "a posta véglegesen elveszett")
        self.assertFalse(rep["ok"], "3 naplózott kiadás, 0 megérkezett: az `ok:true` a szkriptelt hívónak zöld")


if __name__ == "__main__":
    unittest.main()
