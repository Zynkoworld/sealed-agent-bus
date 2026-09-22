"""(2026-09-16, ) — az `52ad412` `mark_delivered`-jének támadása.

🔴 A LELET. A `delivered_id` a busz HIGH-WATER jele: az `agent_bus.reconcile` mentőöv (A1-L2) és az
   `AGENT_BUS_STRICT_ACK` clamp (A1-L3, `_ack_target`,:680) egyaránt azt olvassa úgy, hogy
   „minden id <= delivered_id KÉZBESÍTVE" (`agent_bus.py:753-756`, INV-A1.8). A `recv(mark=True)` ezt
   betartja: ÖSSZEFÜGGŐ lapot ad a kurzortól. Az új `mark_delivered` viszont TETSZŐLEGES részhalmazra
   `MAX(ids)`-t ír (`agent_bus.py:706,711`) — a távoli kiadás pedig épp nem-összefüggő is lehet.

   Az elnyelő körben (6 üzenet, a vádlott csak az id 5,6-ot adja ki) `delivered_id=6` lesz, holott az
   1..4 SOSEM ment ki. Mért következmény — a helyi réteg MINDKÉT fele vakká válik:
     · MENTŐÖV: `agent_bus.reconcile("peer") == []` — a 4 elveszett üzenet nem visszajátszható,
       pedig a `cursor_audit` sor helyesen `skipped_undelivered=4`-et ír. A két helyi jel ELLENTMOND.
     · MEGELŐZÉS: `AGENT_BUS_STRICT_ACK=1` mellett `ack_preview("peer", 6) -> (0, 6)`, tehát a clamp
       ÁTENGEDI az elnyelést; a kurzor 0->6 megy, az 1..4 véglegesen elvész.

   A `687915f` bázison a mentőöv TELÍTVE volt (a becsületes körre is [1..6]) — ez volt a leletem.
   A javítás a telítést megszüntette, de a VALÓDI jelzést is: a 0 nem „nincs veszteség", hanem „nem látom".

   JAVASLAT (mérve, lent a kontroll-tesztben): a `delivered_id` csak az ÖSSZEFÜGGŐ kézbesített prefix
   tetejéig emelkedjen — `első kiadatlan - 1` (a busz a saját `read_at`-jéből tudja, nem a hívó szavából):
       u = SELECT COALESCE(MIN(id),0) FROM messages WHERE recipient=? AND read_at IS NULL
       top = (u - 1) if u else MAX(ids)
   Ezzel a becsületes kör változatlan (`delivered_id=6`, mentőöv `[]`, strict `0->6` — nincs befagyás),
   az elnyelő körben viszont a mentőöv listáz és a strict clamp MEGELŐZI a veszteséget (`0->0`).

stdlib unittest. Hálózat nincs, minden út /tmp alá.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402

N_MAIL = 6
N_GIVEN = 2          # a vádlott csak a LEGFELSŐ kettőt (id 5,6) adja ki -> az 1..4 nem összefüggő maradék


class DeliveredIdMustBeContiguous(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake")}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def pickup(self, given, *, contiguous_fix=False):
        """A valódi kiadási út kézbesítés-jelölése (bus_ssh_exchange.py:187-191). Visszaad: kiadott id-k."""
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)   # PEEK
        out = rows[N_MAIL - given:]
        ids = [r["id"] for r in out]
        ab.mark_delivered("peer", ids, db=self.db)
        if contiguous_fix:                      # a JAVASLAT utólag alkalmazva, hogy mérhető legyen
            c = sqlite3.connect(self.db)
            u = c.execute("SELECT COALESCE(MIN(id),0) FROM messages "
                          "WHERE recipient='peer' AND read_at IS NULL").fetchone()[0]
            c.execute("UPDATE cursors SET delivered_id=? WHERE agent='peer'", ((u - 1) if u else max(ids),))
            c.commit()
            c.close()
        return ids

    def audit_skipped(self):
        c = sqlite3.connect(self.db)
        try:
            r = c.execute("SELECT skipped_undelivered FROM cursor_audit WHERE agent='peer' AND op='ack' "
                          "ORDER BY id DESC LIMIT 1").fetchone()
            return r[0] if r else None
        finally:
            c.close()

    def lifeboat(self):
        return [m["id"] if isinstance(m, dict) else m for m in ab.reconcile("peer", db=self.db)]

    # ── KONTROLLOK: a mai kód jó tulajdonságai — ezek MA zöldek és maradjanak is ──────────
    def test_control_honest_round_does_not_freeze_the_remote_cursor(self):
        self.pickup(N_MAIL)
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "1"}):
            self.assertEqual(ab.ack_preview("peer", N_MAIL, db=self.db), (0, N_MAIL))

    def test_control_honest_round_lifeboat_is_empty(self):
        self.pickup(N_MAIL)
        ab.ack("peer", N_MAIL, db=self.db)
        self.assertEqual(self.lifeboat(), [])
        self.assertEqual(self.audit_skipped(), 0)

    def test_control_the_audit_row_already_knows_the_truth(self):
        """A cursor_audit jelzés a `52ad412`-vel MEGJAVULT (telített 6 -> pontos 4): a busz TUDJA a számot."""
        self.pickup(N_GIVEN)
        ab.ack("peer", N_MAIL, db=self.db)
        self.assertEqual(self.audit_skipped(), N_MAIL - N_GIVEN)

    def test_control_the_loss_is_real(self):
        self.pickup(N_GIVEN)
        ab.ack("peer", N_MAIL, db=self.db)
        self.assertEqual([m["id"] for m in ab.recv("peer", mark=False, limit=99, db=self.db)], [])

    # ── A LELET ──────────────────────────────────────────────────────────────────────────
    def test_lifeboat_must_list_the_swallowed_mail(self):
        self.pickup(N_GIVEN)
        ab.ack("peer", N_MAIL, db=self.db)
        boat = self.lifeboat()
        self.assertTrue(set(range(1, N_MAIL - N_GIVEN + 1)) <= set(boat),
                        "a mentőöv %r, pedig a cursor_audit %r üzenetet ír kézbesítetlennek — "
                        "a veszteség nem visszajátszható" % (boat, self.audit_skipped()))

    def test_strict_clamp_must_not_let_the_cursor_pass_undelivered_mail(self):
        self.pickup(N_GIVEN)
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "1"}):
            base, tgt = ab.ack_preview("peer", N_MAIL, db=self.db)
            ab.ack("peer", N_MAIL, db=self.db)
        self.assertLessEqual(tgt, N_MAIL - N_GIVEN,
                             "strict clamp %d->%d: a kurzor átengedve a kézbesítetlen 1..%d fölé"
                             % (base, tgt, N_MAIL - N_GIVEN))

    # ── A JAVASLAT ELLENPRÓBÁJA: a javítás ne némítsa el, amit megjavított ───────────────
    def test_proposal_fixes_both_without_breaking_the_honest_round(self):
        self.pickup(N_MAIL, contiguous_fix=True)                    # becsületes: változatlan viselkedés
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "1"}):
            self.assertEqual(ab.ack_preview("peer", N_MAIL, db=self.db), (0, N_MAIL))
        ab.ack("peer", N_MAIL, db=self.db)
        self.assertEqual((self.lifeboat(), self.audit_skipped()), ([], 0))

    def test_proposal_catches_the_swallow(self):
        self.pickup(N_GIVEN, contiguous_fix=True)
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "1"}):
            self.assertEqual(ab.ack_preview("peer", N_MAIL, db=self.db)[1], 0)   # MEGELŐZVE: a kurzor nem mozdul
        ab.ack("peer", N_MAIL, db=self.db)                                       # nem-strict: a veszteség bekövetkezik
        self.assertTrue(set(range(1, N_MAIL - N_GIVEN + 1)) <= set(self.lifeboat()))   # de VISSZAJÁTSZHATÓ


if __name__ == "__main__":
    unittest.main(verbosity=2)

