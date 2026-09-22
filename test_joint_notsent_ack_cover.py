"""(2026-09-15 este/2) — a `not-sent` kimenetelű kör ack-ja FEDEZI a naplózott, sosem küldött ack-ot.

A `572f84a` helyesen vezette be a kör-kimenetelt: a `not-sent` (az ssh el sem indult) kör NEM emel vádat a
közjegyző ellen — ez volt a HIGH-om javítása, és az helyes. De ugyanez a sor a FORDÍTOTT irányban is
fedezetként számít (`bus_notary.py:546`):

    sent_acks, any_acks, unknown_acks = acks(("delivered",)), acks(("delivered", "unknown", "not-sent")),...
    for a, n in have.items:
        if any_acks[a] < n: disc.append({"type": "ack_logged_not_sent",...})

Az `any_acks` a `not-sent` köröket is tartalmazza. A `not-sent` viszont azt jelenti, hogy a kérés EL SEM
INDULT — a fél tehát BIZONYOSAN nem kaphatta meg azt az ack-ot. Egy ilyen sorral a nem becsületes közjegyző
ingyen kap fedezetet a BLOCKER-em támadásához: beírja a `cursor F->T (ack U)` bejegyzést, az `expected`
kurzor együtt mozog vele, a `cursor_moved_without_logged_ack` nem keletkezik, és az `ack_logged_not_sent`-et a
not-sent sor elnyeli. Az `unknown` fedezése védhető („odaérhetett, csak a válasz nem jött"), a `not-sent`-é nem.

A támadás ráadásul OLCSÓBB, mint a -i: a közjegyzőnek nem kell eltalálnia egy valóban elküldött ack
értékét — elég egy olyan érték, amit a fél MEG AKART küldeni egy sikertelen körben (és ezt a kliens naplója
maga hirdeti; a bukott körök ack-értéke kiszámítható: a kurzor + a látott üzenetek).

A kontroll-esetek (a szonda nem vak) a mai kódon IS zöldek; a `not-sent` eset PIROS.
stdlib unittest + cryptography.
"""
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
class NotSentAckCover(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def swallow_and_forge(self, n=4):
        """A közjegyző elnyeli a postát (napló nélküli kurzor-ugratás), majd fedező ack-bejegyzést ír."""
        for i in range(n):
            ab.send("hub", "remote1", "titkos-%d" % i, db=self.db, mirror=False)
        ab.ack("remote1", n, db=self.db)                     # <- az elnyelés: napló NÉLKÜL
        self.notary.record(envelope={"cursor": n}, sender_identity="remote1", sender_auth="ssh-key",
                           recipient="remote1", kind="ack", decision="accepted",
                           reason="cursor 0->%d (ack %d)" % (n, n))
        self.assertEqual(ab.recv("remote1", db=self.db), [])  # a posta tényleg elveszett

    def rec(self, receipts):
        return bn.reconcile(bn.export(self.log, 1), "remote1", receipts, trusted_pub=self.pub)

    # ── kontroll 1: fedező nyugta-sor NÉLKÜL a jelzés működik ────────────────
    def test_control_no_receipt_row_flags_forged_ack(self):
        self.swallow_and_forge()
        rep = self.rec([])
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])
        self.assertFalse(rep["ok"])

    # ── kontroll 2: VALÓBAN kézbesített kör ack-ja jogosan fedez ─────────────
    def test_control_delivered_round_legitimately_covers(self):
        self.swallow_and_forge()
        rep = self.rec([{"phase": "request", "round": "r1", "sent": [], "ack": 4, "received": []},
                        {"phase": "outcome", "round": "r1", "outcome": "delivered", "received": []}])
        self.assertNotIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])

    # ── A LELET: a not-sent kör ack-ja NEM fedezhet ──────────────────────────
    def test_not_sent_round_must_not_cover_a_forged_ack(self):
        self.swallow_and_forge()
        rep = self.rec([{"phase": "request", "round": "r1", "sent": [], "ack": 4, "received": []},
                        {"phase": "outcome", "round": "r1", "outcome": "not-sent", "reason": "ssh: no route"}])
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]],
                      "a not-sent kör ack-ja nem érhetett a félhez, mégis fedezetnek számít")
        self.assertFalse(rep["ok"])

    # ── és a kárt is mutassuk: termék-módban is rc=0-t adna ─────────────────
    def test_not_sent_cover_is_ok_true_in_strict_mode(self):
        self.swallow_and_forge()
        receipts = [{"phase": "request", "round": "r1", "sent": [], "ack": 4, "received": []},
                    {"phase": "outcome", "round": "r1", "outcome": "not-sent", "reason": "ssh: no route"}]
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", receipts, trusted_pub=self.pub, strict=True)
        self.assertFalse(rep["ok"], "strict/termék-módban is ok:true — 4 üzenet véglegesen elveszett")


if __name__ == "__main__":
    unittest.main()
