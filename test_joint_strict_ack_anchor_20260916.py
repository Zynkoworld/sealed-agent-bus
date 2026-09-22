"""59Z) — a menekülő ajtó ténye némán elveszhetett.

Az ő mérése: a `bus_ssh_exchange.py:194` `except Exception: pass` az EGYETLEN mechanizmust nyelte el, ami a
kör-bejegyzésbe beírja, hogy a strict ack clamp menekülő ajtaja (`AGENT_BUS_STRICT_ACK=0`) nyitva volt. Ha a
mérés dob, a vállalás elvész, és a kör-bejegyzés a SZIGORÚ körrel megkülönböztethetetlen — miközben a saját
kommentünk nyolc sorral fölötte szó szerint azt írja: „a menekülő ajtó NEM lehet néma".

Javítva: `strict_ack_unknown: 1` a kör kurzorába (HARMADIK ÁLLAPOT, pont mint a `pending_unknown`), és a
`reconcile` OLVASSA is — soft eltérésként, tehát strict/termék-módban nem zöld. (Ha csak beírnánk és senki nem
nézné, azzal ugyanazt az osztályt ismételnénk meg, amit ez a kör zár.)

Az ő csapdája, amit ő maga emelt ki: üres postával NEM születik kör-bejegyzés (`last_round_cursor == cur`),
ezért a szonda egy valódi üzenettel indul — különben „előfeltétel" hibán bukna, nem a leleten.

stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab            # noqa: E402
import bus_notary as bn           # noqa: E402
import bus_ssh_exchange as ex     # noqa: E402


class EscapeDoorMustNotBeSilent(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.log = os.path.join(t, "n.jsonl")
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        priv = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw).hex())
        self.kp = os.path.join(self.keys, "hub.ed25519.key")
        with open(self.kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50, db=self.db)
        self.p = [
            # TERMÉK-mód kell: a menekülő ajtó fogalma csak ott értelmes (`strict_ack_state` a termék-módot
            # nézi) — dev-módban a kontroll vakon zöld lenne. És ALÁÍRT posta kell, különben a kapu eldobja,
            # nincs kiadható válasz, és meg sem születik a kör-bejegyzés (a MÁSODIK csapda, amit ő is jelzett).
            mock.patch.dict(os.environ, {
                "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "product",
                "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": self.keys,
                "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
                "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_AUTO_SIGN": "0",
                "AGENT_BUS_STRICT_ACK": "0"}, clear=False),
            mock.patch.object(ab, "KEYS_DIR", self.keys),
            mock.patch.object(ab, "_a2_guarded_read",
                              lambda p: (open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None)),
        ]
        for x in self.p:
            x.start()
        ab.send("hub", "remote1", "posta", db=self.db, mirror=False, sign_key=self.kp)

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def round_cursor(self):
        ex.exchange("remote1", json.dumps({}), db=self.db,
                    attach_root=os.path.join(self.tmp.name, "att"), notary=self.notary)
        rounds = [e for e in bn.read_lines(self.log)
                  if e.get("type") == "entry" and e.get("kind") == "pickup"
                  and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)]
        self.assertTrue(rounds, "előfeltétel: született kör-bejegyzés")
        return rounds[-1]["cursor"]

    def test_control_the_open_escape_door_is_recorded(self):
        cur = self.round_cursor()
        self.assertEqual(cur.get("strict_ack"), 0,
                         "a nyitott menekülő ajtót a kör-bejegyzésnek ki kell mondania: %r" % cur)

    def test_a_throwing_measurement_must_not_look_like_a_strict_round(self):
        with mock.patch.object(ab, "strict_ack_state", side_effect=RuntimeError("boom")):
            cur = self.round_cursor()
        self.assertTrue("strict_ack" in cur or "strict_ack_unknown" in cur,
                        "a mérés dobott, és a kör a SZIGORÚ körrel megkülönböztethetetlen: %r" % cur)

    def test_the_third_state_is_read_by_reconcile_not_just_written(self):
        with mock.patch.object(ab, "strict_ack_state", side_effect=RuntimeError("boom")):
            self.round_cursor()
        exp = bn.export(self.log, 1)
        rows = []
        c = ab._conn(self.db)
        try:
            rows = [dict(r) for r in c.execute(
                "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
                "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
        finally:
            c.close()
        out = bn._audit_cross(exp, "remote1", rows)
        self.assertIn("strict_ack_unknown", {d["type"] for d in out},
                      "a harmadik állapotot beírtuk, de senki nem olvassa: %r" % out)


if __name__ == "__main__":
    unittest.main()
