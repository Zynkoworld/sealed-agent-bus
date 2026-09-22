"""Az ébresztés-markerek bizalmi állapota — saját.

Két javítás és két KIMONDOTT korlát.

  ZÁRVA 1 — a marker-könyvtár bizalmi állapota eddig SEHOL nem látszott: aki oda írni tud, egy idegen
            `X.sleep_safe` létrehozásával CSENDBEN elnémíthat egy agentet, a marker törlésével pedig
            ébreszthet — és az audit `by` mezőjét is ő írja. A `state_dir_warnings()` ezt kimondja, és a
            marker-könyvtár szigorú módban (0700) jön létre.
  ZÁRVA 2 — az `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1` aláírás nélkül enged ébresztést. Létezhet (üzemeltetői
            döntés), de a HASZNÁLATA nem lehet néma: a hívó figyelmeztetést kap.

  KIMONDVA 1 — TOCTOU a `may_poke` és a `send-keys` között: a döntés és a küldés között az operátor gépelhet.
            A „szent gépelés" szabály szűkíti (nincs C-u, nincs vak újrapróbálás), de az ablak létezik.
  KIMONDVA 2 — a „dolgozik"/„gépel" felismerés a panel SZÖVEGÉBŐL jön, amit az agent maga ír: tartós ál-busy
            állapottal elérhető, hogy egy agent ébreszthetetlen legyen. Ugyanaz az osztály, mint az
            ügyelet-figyelőnél; a modul a saját gépünk felügyeleti segédje, NEM bizalmi határ.

stdlib unittest.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_wake as aw  # noqa: E402


class WakeMarkers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state")
        self.p = mock.patch.dict(os.environ, {"AGENT_WAKE_STATE_DIR": self.state}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── 1: a marker-könyvtár szigorú módban jön létre ───────────────────────
    def test_marker_dir_is_created_strict(self):
        aw.enter_sleep_safe("peer", by="operator")
        self.assertTrue(os.path.isdir(self.state))
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o700,
                         "a marker-könyvtár nem szigorú módban jött létre")
        self.assertTrue(aw.is_asleep("peer"))

    # ── 1b: a tág jogú könyvtárat KIMONDJUK ─────────────────────────────────
    def test_loose_marker_dir_is_named(self):
        os.makedirs(self.state, mode=0o777)
        os.chmod(self.state, 0o777)
        w = aw.state_dir_warnings()
        self.assertTrue(any("írható" in x for x in w), "a világ-írható marker-könyvtárat nem mondtuk ki: %r" % w)

    def test_control_strict_dir_has_no_warning(self):
        os.makedirs(self.state, mode=0o700)
        if os.geteuid() == 0:
            self.assertEqual(aw.state_dir_warnings(), [], "a szigorú, root-tulajdonú könyvtárra nincs kifogás")
        else:
            self.assertTrue(all("root" in x for x in aw.state_dir_warnings()))

    # ── 2: a kulcs nélküli operátor-kapcsoló használata nem néma ────────────
    def test_keyless_operator_switch_is_loud(self):
        import io
        from contextlib import redirect_stderr
        msg = {"sender": "operator", "kind": aw.KIND_WAKE, "body": "peer"}
        buf = io.StringIO()
        env = {"AGENT_WAKE_ALLOW_KEYLESS_OPERATOR": "1", "AGENT_WAKE_OPERATORS": "operator"}
        with mock.patch.dict(os.environ, env, clear=False), redirect_stderr(buf):
            aw.handle_operator_message(msg, verify=lambda m: "unsigned", has_key=False)
        self.assertIn("ALÁÍRÁS NÉLKÜL", buf.getvalue(),
                      "a kulcs nélküli elfogadás néma maradt: %r" % buf.getvalue())

    def test_control_without_the_switch_the_message_is_ignored(self):
        msg = {"sender": "operator", "kind": aw.KIND_WAKE, "body": "peer"}
        with mock.patch.dict(os.environ, {"AGENT_WAKE_OPERATORS": "operator"}, clear=False):
            os.environ.pop("AGENT_WAKE_ALLOW_KEYLESS_OPERATOR", None)
            self.assertEqual(aw.handle_operator_message(msg, verify=lambda m: "unsigned", has_key=False),
                             "ignored:operator-no-key")


if __name__ == "__main__":
    unittest.main()
