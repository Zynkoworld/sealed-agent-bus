"""59Z) — a mentőcsónak KÁRT okozó ága néma volt.

Az ő mérése szó szerint: az első javításom a `warning` mezőt KIZÁRÓLAG a `if not commit:` ágra tette, a
tényleges mentőcsónak-írás viszont a másik return-ön megy ki. Vagyis a kapu nélkül visszaírt, VÉGLEGESEN
elutasított posta pontosan azon a hívási ágon volt néma, ahol a TARTÓS ÁLLAPOT megváltozik — és a DB-ben
tényleg ott volt az aláírt másolat.

A javítás két lépés (az ő javaslatán túl is megyünk, mert ők is felvetették):
  (a) a jelzés a commit-ág válaszába is bekerül,
  (b) TERMÉK-MÓDBAN a hiányzó kapu FAIL-CLOSED: mentőcsónak kapu nélkül nem ír tartós állapotot. A száraz
      futás (`commit=False`) továbbra is megmutatja, mit tenne — a diagnózishoz van út, a kárhoz nincs.

Az ő két csapdája, amit ő maga emelt ki, itt is érvényes:
  * a `signed-copy` ág az EREDETI `in_reply_to`-t viszi át, tehát a másolatot nem lehet `in_reply_to=<id>`
    alapján keresni — minden `recipient` sor az eredetin kívül a horgony;
  * a viselkedést kell kötni, nem az ág ALAKJÁT (a `pass`-keret erre vak).

stdlib unittest.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab        # noqa: E402
import bus_enforce as enf     # noqa: E402


class LifeboatFilterFailure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "product",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()
        ab.init(self.db)
        self.mid = ab.send("hub", "peer", "posta", db=self.db, mirror=False)
        c = ab._conn(self.db)
        try:                                        # egy VÉGLEGESEN elutasított sor nyoma az auditban
            c.execute("INSERT INTO cursor_audit(seq,ts,agent,from_id,to_id,op,skipped_undelivered,"
                      "prev_row_hash,row_hash) VALUES(0,0,'peer',?,?,'enforce_reject',0,'0','0')",
                      (self.mid, self.mid))
            c.commit()
        finally:
            c.close()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def copies(self):
        c = ab._conn(self.db)
        try:
            return [dict(r) for r in c.execute("SELECT id FROM messages WHERE recipient='peer' AND id<>?",
                                               (self.mid,))]
        finally:
            c.close()

    def test_the_commit_path_must_not_be_silent_about_a_missing_gate(self):
        with mock.patch.object(enf, "check", side_effect=RuntimeError("boom")):
            live = ab.replay("peer", commit=True, db=self.db)
        named = any("warn" in k.lower() or "filter" in k.lower() or "refused" in k.lower() for k in live)
        self.assertTrue(named, "a kapu nem futott, és a commit-ág válasza erről NÉMA: %r" % live)

    def test_product_mode_writes_nothing_when_the_gate_cannot_run(self):
        with mock.patch.object(enf, "check", side_effect=RuntimeError("boom")):
            live = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(self.copies(), [],
                         "termék-módban a kapu nélkül is bekerült a másolat: %r" % self.copies())
        self.assertFalse(live.get("replayed"), "fail-closed: nem replayelünk kapu nélkül (%r)" % live)

    def test_the_dry_run_still_shows_what_it_would_do(self):
        with mock.patch.object(enf, "check", side_effect=RuntimeError("boom")):
            dry = ab.replay("peer", commit=False, db=self.db)
        self.assertIn("warning", dry)
        self.assertTrue(dry.get("would_replay"), "a száraz futásnak meg kell mutatnia, mit tenne: %r" % dry)

    def test_control_a_working_gate_filters_and_stays_quiet(self):
        with mock.patch.object(enf, "check", return_value=(False, "stale-ts")):
            dry = ab.replay("peer", commit=False, db=self.db)
        self.assertEqual(dry.get("would_replay"), [], "a végleges elutasítást ki kell szűrni: %r" % dry)
        self.assertNotIn("warning", dry, "működő kapunál nincs mit kimondani")


if __name__ == "__main__":
    unittest.main()
