"""A waiting-ág vak volt a beragadásra — (2026-09-17, KÖZEPES-MAGAS).

A lelet: a `decide` busy-ágán a fejlesztők már felismerték, hogy a „dolgozik" minta önbevallott állapot (egy lefagyott
panel utolsó képkockáján is ott lehet), és bájtra változatlan panelre egy óra után riasztanak. Egy sorral lejjebb a
WAITING-ág UGYANEZ a hibaosztály javítatlanul: a jóváhagyás-minta feltétel nélkül `none`-t adott — óra, számláló,
hash nélkül. ugyanaz a bájtra változatlan panel — busy-ág 61 perc → alert, waiting-ág 61 perc ÉS tíz
év → none. És a minta a panel SAJÁT kimenetéből olvas: öt ártatlan sor (telepítő [Y/n], help-kimenet, magyar log
y/n-nel, python print a forrásban, menükeret „Enter to select") mind elnémította az ügyeletet.

A javítás a busy-ág receptjének átemelése: a mintával együtt bájtra változatlan panel `waiting_stuck_min` fölött =
beragadás → alert (típusonkénti kulcs: alerted_waiting, remind_s-enként ismétel). Egy VÁLTOZÓ panel a mintával
továbbra is várakozás (none). Mutáns-próba: a hash-számlálás nélkül `test_waiting_pane_unchanged_for_an_hour_alerts`
és `test_innocent_lines_cannot_silence_the_watch_forever` bukik.

stdlib unittest; az `is_busy` mockolva False (a panel nem „dolgozik").
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_duty as ad  # noqa: E402

ASKING = "$ valami\nDo you want to proceed?\n❯ 1. Yes\n  2. No\n"
INNOCENT = ["Install now? (y/n)", "usage: tool --yes   do you want to skip prompts",
            "2026-09-17 log: folytassam? (y/n)", 'print("Do you want to proceed?")', "┌ Enter to select ┐"]


def _decide(st, now, pane, **kw):
    with mock.patch.object(ad.aw, "is_busy", lambda pane: False):
        return ad.decide(st, now=now, pane=pane, asleep=False, reported=0, own_prefix="x", **kw)


class WaitingIsSelfDeclaredToo(unittest.TestCase):
    def test_control_a_fresh_waiting_pane_is_none(self):
        act, st = _decide({}, 1000.0, ASKING)
        self.assertEqual(act, "none")
        self.assertIn("waiting_hash", st)

    def test_waiting_pane_unchanged_for_an_hour_alerts(self):
        # 61 perc bájtra változatlan → a busy-ág riaszt, a waiting-ág eddig nem
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 30 * 60, ASKING)
        self.assertEqual(act, "none")                                            # fél óra: még várakozás
        act, st = _decide(st, 1000.0 + 61 * 60, ASKING)
        self.assertEqual(act, "alert")
        self.assertTrue(st.get("stuck_waiting"))
        self.assertIn("alerted_waiting", st)
        # ismétlés csak remind_s-enként (típusonkénti kulcs — nem nyomja el a többi riasztást és azok sem ezt)
        act, st = _decide(st, 1000.0 + 62 * 60, ASKING)
        self.assertEqual(act, "none")
        act, st = _decide(st, 1000.0 + 61 * 60 + 3600, ASKING)
        self.assertEqual(act, "alert")

    def test_ten_years_later_is_not_none(self):
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 10 * 365 * 86400, ASKING)
        self.assertEqual(act, "alert")

    def test_control_a_changing_waiting_pane_is_waiting_not_stuck(self):
        act, st = _decide({}, 1000.0, ASKING)
        for k in range(1, 5):
            act, st = _decide(st, 1000.0 + k * 30 * 60, ASKING + ("." * k))       # a panel változik (két óra alatt)
            self.assertEqual(act, "none", k)
        self.assertNotIn("stuck_waiting", st)

    def test_innocent_lines_cannot_silence_the_watch_forever(self):
        # az egyik kar öt ártatlan sora: mind illeszkedik a mintára; egy óra változatlanság után mégis riaszt
        for line in INNOCENT:
            pane = "$ cat README\n" + line + "\n$ "
            self.assertIsNotNone(ad.WAITING.search(line), line)
            act, st = _decide({}, 1000.0, pane)
            self.assertEqual(act, "none", line)
            act, st = _decide(st, 1000.0 + 61 * 60, pane)
            self.assertEqual(act, "alert", line)

    def test_leaving_the_waiting_state_clears_its_clock(self):
        act, st = _decide({}, 1000.0, ASKING)
        act, st = _decide(st, 1000.0 + 10, "$ ")                                 # a kérdés eltűnt
        self.assertNotIn("waiting_hash", st)
        self.assertNotIn("waiting_same_since", st)
        act, st = _decide(st, 1000.0 + 61 * 60, ASKING)                          # új kérdés: az óra újraindul
        self.assertEqual(act, "none")

    def test_threshold_is_a_parameter(self):
        t0 = 100000.0                                                            # > remind_s: az első riasztás nem esik a 0-tól mért ablakba
        act, st = _decide({}, t0, ASKING, waiting_stuck_min=0)                   # küszöb 0: már az első kép beragadás
        self.assertEqual(act, "alert")
        act, st = _decide(st, t0 + 1, ASKING, waiting_stuck_min=0)               # remind_s-en belül nem ismétel
        self.assertEqual(act, "none")


if __name__ == "__main__":
    unittest.main()
