"""Az ügyelet-figyelő támadása — saját.

Két javítás és két KIMONDOTT korlát.

  ZÁRVA 1 — a „jelentés" nem lehet pusztán a FÁJLNÉV: egy `touch`-olt vagy `{}`-t tartalmazó fájl eddig
            jelentésnek számított, és ebből lett a felügyelői „jelentett és tétlen — jöhet a következő".
            Mostantól szerkezeti szabály: a fájl a busz JSON-tükrének sora legyen, amit AZ AGENT küldött.
  ZÁRVA 2 — EGYETLEN `alerted` kulcs volt minden riasztás-típusra, tehát az első riasztás a MÁSIKAT is
            elnyomta a `remind_s` ablakban (pl. a „nincs panel" elnyomta a „beragadt-busy"-t). Típusonként.

  KIMONDVA 1 — a kijelölés-fájl (`duty_active.json`) nincs hitelesítve: aki írni tudja, átírhatja, ki az
            ügyeletes. A modul a SAJÁT gépünk felügyeleti segédje, nem bizalmi határ.
  KIMONDVA 2 — a „dolgozik" bizonyítéka a panel tartalma, amit AZ AGENT ír. A bájt-hash + idő (beragadás)
            ezt szűkíti, de nem teszi hamisíthatatlanná. Valódi bizonyíték a process-szintű CPU-idő lenne.

stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad  # noqa: E402

T0 = 1_700_000_000.0


class DutyHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inbox = os.path.join(self.tmp.name, "inbox", "operator")
        os.makedirs(self.inbox)

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, name, body, when=T0 + 100):
        p = os.path.join(self.inbox, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        os.utime(p, (when, when))
        return p

    def count(self):
        return ad.count_reports_inbox("agentx", T0, bridge=self.tmp.name, supervisor="operator")

    # ── kontroll: a valódi tükör-sor jelentés ───────────────────────────────
    def test_control_real_mirror_row_counts(self):
        self._report("agentx_1.json", json.dumps({"from": "agentx", "to": "operator", "kind": "msg",
                                                  "note": "kesz a meres"}))
        self.assertEqual(self.count(), 1)

    # ── 1: a puszta fájlnév nem jelentés ────────────────────────────────────
    def test_touched_empty_file_is_not_a_report(self):
        self._report("agentx_2.json", "")
        self.assertEqual(self.count(), 0, 'egy 0 bájtos fájl jelentésnek számított')

    def test_empty_json_object_is_not_a_report(self):
        self._report("agentx_3.json", "{}")
        self.assertEqual(self.count(), 0, 'egy ures JSON-objektum jelentésnek számított')

    def test_report_from_someone_else_does_not_count(self):
        self._report("agentx_4.json", json.dumps({"from": "masik", "to": "operator", "note": "nem az agenté"}))
        self.assertEqual(self.count(), 0, "más nevében írt sor nem lehet az agent jelentése")

    def test_unparseable_file_does_not_count(self):
        self._report("agentx_5.json", "{ ez nem json")
        self.assertEqual(self.count(), 0)

    # ── 2: típusonkénti riasztás-elnyomás ───────────────────────────────────
    def test_alert_types_do_not_suppress_each_other(self):
        """A „nincs panel" riasztás nem nyomhatja el a „beragadt-busy" riasztást ugyanabban az ablakban."""
        now = T0
        st = {"no_pane_since": now - 3600}
        act, st = ad.decide(st, now=now, pane=None, asleep=False, reported=0, own_prefix="x")
        self.assertEqual(act, "alert")
        self.assertIn("alerted_no_pane", st, "a riasztás-típusnak saját kulcsa van")
        # ugyanabban a percben egy BERAGADT-busy panel: a másik típusnak meg kell szólalnia
        from unittest import mock
        st2 = dict(st)
        with mock.patch.object(ad.aw, "is_busy", lambda pane: True):
            act2, st2 = ad.decide(st2, now=now, pane="$ dolgozom", asleep=False, reported=0, own_prefix="x",
                                  busy_stuck_min=0)
        self.assertEqual(act2, "alert", "a beragadt-busy riasztást elnyomta egy másik típus riasztása")
        self.assertIn("alerted_stuck", st2)


if __name__ == "__main__":
    unittest.main()
