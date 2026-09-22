"""(2026-09-16, ) — a `2812b18` támadása: a napló SZÖVEGES `reason`-jére épülő
három detektor a támadó számára OPCIONÁLIS.

🔴 A LELET. A `reconcile` három kurzor-detektora a bejegyzés ember-olvasható `reason` mezőjét elemzi
   regexszel (`bus_notary.py:441-442`), és nem-illeszkedésnél NÉMÁN kihagyja a bejegyzést:

     _ROUND_RE = ^cursor=(\\d+) replies=(\\d+)$      -> `_parse_round`... `if c is None: continue`  (:537-539)
     _ACK_RE   = ^cursor (\\d+)->(\\d+) \\(ack (\\d+)\\)$ -> `if not m: continue`                        (:522-524)

   Ezzel egyetlen, a TÁMADÓ által szabadon választott karakter kikapcsolja:
     · `cursor_moved_without_logged_ack`  — az elnyelt posta ELSŐDLEGES detektora,
     · `ack_logged_not_sent`              — a BLOCKER-em javítása,
     · `cursor_target_exceeds_ack`        — a BLOCKER-em javítása (ugyanabban a match-blokkban).

   A napló írója maga a vádlott, tehát a `reason` alakja a támadó választása. A `verify` zöld marad
   (a hash-lánc ép), a `reconcile` `ok:true`, `discrepancies:[]` ÉS `unresolved:[]` — TERMÉK-/strict-módban is.
   Ez nem „nem tudni", hanem „rendben": pontosan az a hibaosztály, amit a auditunk óta viszünk.

   A mért forgatókönyv becsületes látszatú: a kör 2 üzenetet SZABÁLYOSAN kiad (a kliens nyugtája egyezik,
   `received_not_logged` és `delivered_not_received` sem szólal meg), miközben a kurzor 0-ról 4-re ugrik —
   az 1..4 posta elnyelve. A kliensnek semmi nyoma nincs róla, a naplónak sincs.

   A `reason` ELHAGYÁSA (kör-bejegyzés nélküli kiadás) ugyanígy néma — tehát a javítás nem lehet csak
   szigorúbb regex: egy `delivered` bejegyzés MÖGÖTT kötelezővé kell tenni az elemezhető kör-bejegyzést,
   az elemezhetetlen `reason`-t pedig tételként kell jelenteni (legalább `unresolved`, strictben hard).

   Gyökér-ok: a `record` (`bus_notary.py:241-245`) a kurzor-számokat csak a 200 karakterre CSONKÍTOTT,
   szabad szöveges `reason`-ben őrzi meg — a gépi mező (`envelope`) csak hash-ként kerül a naplóba.

Hálózat nincs, a napló és a nyugta memóriában/temp-ben készül. stdlib unittest + cryptography.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402

GOOD_ROUND = "cursor=4 replies=2"
BAD_ROUND = "cursor=4 replies=2 "          # EGYETLEN záró szóköz — a $-ra végződő regex nem illeszkedik
GOOD_ACK = "cursor 0->4 (ack 4)"
BAD_ACK = "cursor 0->4 (ack 4)."           # egyetlen pont


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ReasonOptOut(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {"AGENT_BUS_NOTARY_LOG": self.log, "AGENT_BUS_MODE": "dev"}, clear=False)
        self.p.start()
        self.msgs = [{"id": i, "sender": "hub", "body": "b%d" % i, "kind": "msg", "topic": ""} for i in (5, 6)]

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def log_round(self, *, ack_reason=None, round_reason=GOOD_ROUND, ack_cursor=4):
        """Egy kör naplója: (opcionális) ack-bejegyzés, kör-bejegyzés (a kurzor 0->4 ugrással), 2 kiadás."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        if ack_reason is not None:
            rec(envelope={"identity": "peer", "cursor": ack_cursor}, kind="ack", decision="accepted", reason=ack_reason)
        if round_reason is not None:
            rec(envelope={"identity": "peer", "cursor": 4, "reply_sha256": [bn.envelope_hash(m) for m in self.msgs]},
                kind="pickup", decision="accepted", reason=round_reason)
        for m in self.msgs:
            rec(envelope=m, kind="pickup", decision="delivered", reason="id=%d" % m["id"])
        return bn.export(self.log, 1)

    def receipts(self):
        """A kliens IGAZAT mond: a két üzenetet megkapta, ack-ot nem küldött."""
        return [{"phase": "request", "sent": [], "ack": 0, "received": self.msgs, "round": "r1"},
                {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]

    def report(self, recs, strict=True):
        return bn.reconcile(recs, "peer", self.receipts(), start_cursor=0, trusted_pub=self.pub, strict=strict)

    def types(self, rep):
        return sorted([d["type"] for d in rep["discrepancies"]] + [u["type"] for u in rep["unresolved"]])

    # ── KONTROLLOK (ma zöldek — a szonda nem vak) ──────────────────────────
    def test_control_wellformed_round_reason_catches_the_cursor_jump(self):
        rep = self.report(self.log_round())
        self.assertIn("cursor_moved_without_logged_ack", self.types(rep))
        self.assertFalse(rep["ok"])

    def test_control_wellformed_ack_reason_catches_the_forged_ack(self):
        rep = self.report(self.log_round(ack_reason=GOOD_ACK))
        self.assertIn("ack_logged_not_sent", self.types(rep))

    def test_control_wellformed_ack_reason_catches_the_cursor_target(self):
        """A BLOCKER-em javítása szabályos reason mellett szólal meg."""
        rep = self.report(self.log_round(ack_reason="cursor 0->9 (ack 4)"))
        self.assertIn("cursor_target_exceeds_ack", self.types(rep))

    def test_control_the_delivered_half_of_the_round_is_honest(self):
        """A kör MÁSIK fele szabályos: a kliens nyugtája és a napló kiadásai egyeznek, tehát a
        kurzor-detektoron kívül nincs másik réteg, ami megszólalhatna."""
        rep = self.report(self.log_round())
        self.assertNotIn("received_not_logged", self.types(rep))
        self.assertNotIn("delivered_not_received", self.types(rep))

    # ── A LELET ────────────────────────────────────────────────────────────
    def test_malformed_round_reason_must_not_silence_the_cursor_jump(self):
        """🔴 Egyetlen záró szóköz → a kurzor-ugrás detektora néma, strict-ben is."""
        rep = self.report(self.log_round(round_reason=BAD_ROUND))
        self.assertTrue(self.types(rep),
                        "elemezhetetlen kör-`reason` → a `_parse_round` némán kihagyja a bejegyzést: "
                        "ok=%r verify_ok=%r discrepancies=[] unresolved=[] — a napló „rendben\"-t mond "
                        "egy 0->4 kurzor-ugrásra, amelyről a kliensnek sincs nyoma" % (rep["ok"], rep["verify_ok"]))

    def test_malformed_ack_reason_must_not_silence_the_forged_ack(self):
        """🔴 Egyetlen pont → a és a BLOCKER-em javítása is kikapcsol."""
        rep = self.report(self.log_round(ack_reason=BAD_ACK, round_reason=BAD_ROUND))
        self.assertTrue(self.types(rep),
                        "elemezhetetlen ack-`reason` → az `ack_logged_not_sent` és a "
                        "`cursor_target_exceeds_ack` is néma: ok=%r" % (rep["ok"],))

    def test_omitted_round_entry_must_not_silence_the_cursor_jump(self):
        """🔴 A kör-bejegyzés ELHAGYÁSA ugyanígy néma → a javítás nem lehet csak szigorúbb regex."""
        rep = self.report(self.log_round(round_reason=None))
        self.assertTrue(self.types(rep),
                        "kör-bejegyzés nélkül a 2 `delivered` bejegyzés fedezetlen marad, és a kurzor-ugrás "
                        "nem derül ki: ok=%r" % (rep["ok"],))


if __name__ == "__main__":
    unittest.main()
