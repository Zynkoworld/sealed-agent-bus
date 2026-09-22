"""(2026-09-16, ) — a `687915f` gépi kurzor-mezője kiejtette a `verify` fogát.

🟠 A LELET (HIGH). A BLOCKER-em javítása a hamis kurzor-célt (`to > max(from, ack)`: a becsületes
   clamp csak lefelé mozgat) KÉT helyen fogta meg, és ez szándékos volt — a `bus_notary.py:385-387`
   kommentje ki is mondja: „a fél nélkül, a naplóból is ellenőrizhető", a `verify` CLI erre rc=1-et ad
   (`bus_notary.py:701-704`). A `687915f` viszont a számokat a gépi `cursor` mezőbe vitte, és csak a
   `reconcile` olvassa (`:557-559`); a `verify` maradt a `reason`-nél:

     for r in records:                                        # bus_notary.py:390-394
         if... kind == "ack" and decision == "accepted":
             m = _ACK_RE.match(r.get("reason", "") or "")     # <-- CSAK a reason
             if m and int(m.group(2)) > max(int(m.group(1)), int(m.group(3))):

   Mérve (`687915f`): egy ÚJ formátumú, érvényes bejegyzés `cursor={"from":0,"to":9,"ack":0}` gépi mezővel
   és NEM elemezhető `reason`-nel a `verify` szerint hibátlan — `ok:true`, `trusted:true`,
   `ack_target_violations:[]`, CLI rc=0 —, miközben ugyanezt a bejegyzést a `reconcile` helyesen hard
   `cursor_target_exceeds_ack`-kal vádolja. A `reason` a napló írójának (a vádlottnak) szabad választása,
   a gépi mező pedig ma ÖNMAGÁBAN elég ahhoz, hogy a `reconcile` érvényesnek fogadja: a `reason` elhagyása
   tehát nem rontja el a bejegyzést, csak a `verify`-t kapcsolja ki.

   Következmény: aki a nyugták nélküli, olcsó ellenőrzést futtatja (`bus_notary verify --file export
   --pub K`), az zöldet és `trusted:true`-t kap egy olyan szeletre, amely maga ismeri be a hamis
   kurzor-célt. Nem veszteség, de a dokumentált, fél-független réteg elveszett az új formátum alatt.

   Javítás: a `verify` ack-ellenőrzése a gépi mezőt olvassa (ha van), és csak annak hiányában a `reason`-t
   — ugyanabban a sorrendben, mint a `reconcile` (`_ints(c, ("from","to","ack"))`, majd `_ACK_RE`).

A KONTROLLOK ma zöldek: régi (csak `reason`) és kettős (`reason`+gépi mező) formátumnál a `verify` MEGFOGJA,
a `reconcile` pedig mindhárom formánál megfogja — a lelet tehát pontosan a `verify` + gépi mező sarokban van.
Hálózat nincs, minden út /tmp alá írva. stdlib unittest + cryptography.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402

LIE_REASON = "cursor 0->9 (ack 0)"                 # to=9 > max(from=0, ack=0)
LIE_CURSOR = {"from": 0, "to": 9, "ack": 0}        # ugyanaz gépi mezőben


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class VerifyBlindToMachineCursor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BUS_DB": os.path.join(t, "bus.db"), "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
            "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_WAKE_DIR": os.path.join(t, "wake"),
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att")}, clear=False)
        self.p.start()
        self.i = 0

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def slice(self, *, reason, cursor):
        """Egyetlen, aláírt ellenőrzőponttal lefedett ack-bejegyzés (trusted:true legyen)."""
        self.i += 1
        path = os.path.join(self.tmp.name, "n%d.jsonl" % self.i)
        n = bn.Notary(path, seed=self.seed, checkpoint_every=1)
        n.record(envelope={"ack": 9}, sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                 kind="ack", decision="accepted", reason=reason, cursor=cursor)
        return path, bn.read_lines(path)

    def v(self, **kw):
        path, recs = self.slice(**kw)
        rep = bn.verify(recs, trusted_pub=self.pub)
        rc = bn.main(["verify", path, "--pub", self.pub])
        return rep, rc

    def r(self, **kw):
        _, recs = self.slice(**kw)
        return bn.reconcile(recs, "peer", [], trusted_pub=self.pub, strict=True)

    # ── KONTROLLOK (ma zöldek — a szonda nem vak) ─────────────────────────────
    def test_control_verify_catches_the_old_reason_only_format(self):
        rep, rc = self.v(reason=LIE_REASON, cursor=None)
        self.assertEqual((len(rep["ack_target_violations"]), rc), (1, 1))
        self.assertTrue(rep["ok"] and rep["trusted"])            # a lánc ép, mégis hazug: pont ezt fogja a mező

    def test_control_verify_catches_the_dual_format(self):
        """Ahogy a becsületes író ma ír (reason ÉS gépi mező): a verify megfogja."""
        rep, rc = self.v(reason=LIE_REASON, cursor=LIE_CURSOR)
        self.assertEqual((len(rep["ack_target_violations"]), rc), (1, 1))

    def test_control_reconcile_catches_all_three_forms(self):
        """A reconcile (a fél nyugtái NÉLKÜL is) mindhárom alakot megfogja — a rés nem ott van."""
        for label, reason, cursor in (("régi", LIE_REASON, None), ("kettős", LIE_REASON, LIE_CURSOR),
                                      ("csak gépi", "", LIE_CURSOR)):
            with self.subTest(forma=label):
                rep = self.r(reason=reason, cursor=cursor)
                self.assertIn("cursor_target_exceeds_ack", [d["type"] for d in rep["discrepancies"]])
                self.assertFalse(rep["ok"])

    def test_control_the_machine_only_entry_is_a_valid_entry(self):
        """A `reason` nélküli bejegyzés nem sérült: a lánc ép, és a reconcile érvényesnek fogadja
        (nem `unparsable_cursor_entry`) — tehát a támadónak semmibe nem kerül elhagyni a reason-t."""
        rep = self.r(reason="", cursor=LIE_CURSOR)
        self.assertNotIn("unparsable_cursor_entry", [d["type"] for d in rep["discrepancies"]])
        self.assertTrue(rep["verify_ok"])

    # ── A LELET ───────────────────────────────────────────────────────────────
    def test_verify_must_see_the_machine_cursor_field(self):
        """🟠 Gépi mező + üres `reason` -> a verify vak: ok:true, trusted:true, rc=0."""
        rep, rc = self.v(reason="", cursor=LIE_CURSOR)
        self.assertEqual(
            (len(rep["ack_target_violations"]), rc), (1, 1),
            "a `to=9 > max(from=0, ack=0)` hamis kurzor-cél GÉPI mezőben van, a verify mégis: "
            "ok=%r trusted=%r ack_target_violations=[] rc=%d — a kurzor-cél javítás fél-független rétege "
            "az új formátum alatt elveszett" % (rep["ok"], rep["trusted"], rc))

    def test_verify_must_see_it_with_prose_reason_too(self):
        """🟠 Ugyanez akkor is, ha a `reason` nem üres, csak nem a kanonikus alak."""
        rep, rc = self.v(reason="ack elfogadva", cursor=LIE_CURSOR)
        self.assertEqual((len(rep["ack_target_violations"]), rc), (1, 1),
                         "nem-kanonikus `reason` + gépi mező -> verify ok=%r rc=%d" % (rep["ok"], rc))


if __name__ == "__main__":
    unittest.main(verbosity=2)
