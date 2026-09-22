"""(2026-09-16, ) — a `6115966` háromfokú kiadás-modelljének HATÓKÖRE.

A -re a javítás az ÉN kérésem volt: egy timeoutolt (`unknown`) kör után az újrakiadás ne
legyen hard `delivered_not_received` egy becsületesen eljáró közjegyzőre. A javítás viszont
SZELET-GLOBÁLIS kapcsolót kapott:

    presumed_round = any(o in ("unknown", "not-sent") for o, rc in rows if o != "outcome-row")
    for u in unconfirmed:
        if presumed_round: unresolved.append(... "delivery_outcome_unknown")
        else:              disc.append(... "delivered_not_received")

Két következménye van, és mindkettőt ez a szonda méri:

1. **Hatókör.** EGY feltételezett kimenetelű kör az ÖSSZES kör többlet-kiadását leminősíti — azokét is,
   amelyeket BIZONYÍTOTT kimenetel zár. A vád tárgyát (a becsületesen zárt kör kiadása) és a vád
   feltételezettségét (a másik kör) semmi nem köti össze.

2. **A kapcsolót a VÁDLOTT állítja, KIHAGYÁSSAL.** Az `outcome(rc)` egy `request`-sorra `unknown`-t ad,
   ha a köréhez NINCS kimenetel-sor. A nyugta-fájl a mérés egyik oldala; egy kimenetel-sor KIHAGYÁSA
   (nem hazug értéke) átfordítja a szelet egészét. Ez pontosan az a hibaosztály, amit a `verify`-ban és a
   clampben már kétszer lezártunk: a „nem tudni" nem lehet ingyen „rendben".

A szonda a `bus_notary.reconcile`-t közvetlenül méri, kézzel írt naplóval és nyugtákkal — a kiadási út
sorrendjét a `bus_ssh_exchange` mintájára követve. stdlib unittest + cryptography, hálózat nincs.
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


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography szükséges")
class PresumedRoundScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def report(self, *, second_round_unknown, strict):
        """Egy BIZONYÍTOTT kimenetelű kör (r1), amelyben a közjegyző KIADÁST naplózott, de a fél nyugtája
        szerint SEMMI nem érkezett meg — ez a valódi kézbesítés-tagadás. `second_round_unknown`: mellette
        egy MÁSIK, ártatlan kör, aminek a nyugta-fájlból KIMARADT a kimenetel-sora."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        env = {"id": 1, "sender": "hub", "recipient": "peer", "body": "fizetesi-utalvany", "ts": 1}
        rec(envelope={"identity": "peer", "cursor": 0, "reply_sha256": [bn.envelope_hash(env)]},
            kind="pickup", decision="accepted", reason="cursor=0 replies=1",
            cursor={"at": 0, "replies": 1, "pending": 1, "next_id": 0})
        rec(envelope=env, kind="pickup", decision="delivered", reason="id=1", cursor={"id": 1})
        # r1: a fél nyugtája szerint a kör LEFUTOTT (bizonyított kimenetel), de NEM kapott meg semmit
        receipts = [{"phase": "request", "sent": [], "ack": 0, "received": [], "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        if second_round_unknown:
            # r2: egy ÁRTATLAN, független kör — a kimenetel-sora KIMARADT a nyugta-fájlból
            receipts.append({"phase": "request", "sent": [], "ack": 0, "received": [], "round": "r2"})
        exp = bn.export(self.log, 1)
        r = bn.reconcile(exp, "peer", receipts, strict=strict)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "unconfirmed": len(r["unconfirmed_deliveries"])}

    # ── kontroll: a kézbesítés-tagadás egyedül HARD vád, és ok=false ──────────
    def test_control_denial_alone_is_a_hard_finding(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                r = self.report(second_round_unknown=False, strict=strict)
                self.assertEqual(r["unconfirmed"], 1, "előfeltétel: egy nem-nyugtázott kiadás")
                self.assertIn("delivered_not_received", r["hard"])
                self.assertFalse(r["ok"])

    # ── LELET-1: egy ÁRTATLAN kör kimenetel-sorának KIHAGYÁSA leminősíti a vádat ──
    def test_unknown_round_must_not_downgrade_a_proven_rounds_denial(self):
        r = self.report(second_round_unknown=True, strict=True)
        self.assertEqual(r["unconfirmed"], 1, "előfeltétel: ugyanaz az egy nem-nyugtázott kiadás")
        self.assertIn("delivered_not_received", r["hard"],
                      "egy MÁSIK kör hiányzó kimenetel-sora kiütötte a hard vádat a BIZONYÍTOTT körről "
                      "(hard=%s, soft=%s)" % (r["hard"], r["soft"]))

    # ── LELET-2: dev-módban (strict=False) a jelentés át is fordul ok=true-ra ──
    def test_downgrade_must_not_flip_ok_to_true(self):
        base = self.report(second_round_unknown=False, strict=False)
        self.assertFalse(base["ok"], "előfeltétel: a vád nélküle ok=false")
        r = self.report(second_round_unknown=True, strict=False)
        self.assertFalse(r["ok"],
                         "egy hiányzó kimenetel-sor a jelentést ok=TRUE-ra fordította (hard=%s, soft=%s): "
                         "a kézbesítés-tagadás nyomtalanul eltűnt" % (r["hard"], r["soft"]))

    # ── MÉRÉS (nem assert) ───────────────────────────────────────────────────
    def test_report_matrix(self):
        for strict in (False, True):
            for unk in (False, True):
                r = self.report(second_round_unknown=unk, strict=strict)
                sys.stderr.write("\n[MÉRÉS] strict=%-5s r2_unknown=%-5s -> ok=%-5s hard=%s soft=%s\n"
                                 % (strict, unk, r["ok"], r["hard"], r["soft"]))


if __name__ == "__main__":
    unittest.main()
