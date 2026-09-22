"""A CSONKOLT `pending`-mérés harmadik állapot — saját.

A kör-bejegyzés `pending` mezője a kiadásra váró posta darabszáma. A mérés egy limitre megy
(`MAX_REPLIES * 50 + 1`), és a `+1` épp csonkolás-érzékelőnek készült — de senki nem olvasta.
Így egy limitbe ütköző, tehát CSONKA mérés pontosan úgy nézett ki, mint egy tiszta kör.

A javítás a ház szabálya szerint: a csonkolt mérés ugyanaz a harmadik állapot, mint a hiányzó
(`pending_truncated` a kör-bejegyzésben -> a következő ack `round_pending_unknown` unresolved
tételt kap, strict/termék-módban `ok:false`).

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
import bus_ssh_exchange as ex  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography szükséges")
class TruncatedPendingIsNotACleanRound(unittest.TestCase):
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

    def round_cursor(self, n_mail, *, max_replies):
        """Egy kört futtat `max_replies` kiadási limittel, és visszaadja a kör-bejegyzés gépi mezőjét."""
        for i in range(1, n_mail + 1):
            ab.send("hub", "peer", "m%d" % i, db=self.db, mirror=False)
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)     # explicit közjegyző (dev-módban nincs env-kulcs)
        with mock.patch.object(ex, "MAX_REPLIES", max_replies):
            ex.exchange("peer", bn.json.dumps({"messages": []}).encode(), db=self.db, notary=n)
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("type") == "entry" and e.get("kind") == "pickup" and e.get("decision") == "accepted"
                  and isinstance(e.get("cursor"), dict) and "at" in e["cursor"]]
        self.assertTrue(rounds, "előfeltétel: van kör-bejegyzés gépi mezővel")
        return rounds[-1]["cursor"]

    # ── kontroll: a limit alatti mérés TELJES, nincs csonkolás-jelzés ────────
    def test_control_complete_measurement_has_no_flag(self):
        c = self.round_cursor(5, max_replies=1)
        self.assertEqual(c["pending"], 5, "a limit alatt a mérés pontos")
        self.assertNotIn("pending_truncated", c)

    # ── LELET: a limitbe ütköző mérés CSONKA, és ezt ki kell mondani ─────────
    def test_truncated_measurement_is_flagged(self):
        c = self.round_cursor(55, max_replies=1)             # a mérés limitje: 1*50 -> 55 nem fér bele
        self.assertEqual(c.get("pending_truncated"), 1,
                         "a csonka `pending`-mérés (%s) tiszta körnek látszott" % c.get("pending"))

    # ── és a közjegyzői oldalon ugyanaz a harmadik állapot, mint a hiányzó mérés ──
    def test_truncated_measurement_blocks_a_clean_report(self):
        cur = ab.cursor_of("peer", db=self.db)
        c = self.round_cursor(55, max_replies=1)
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        ack_to = 1
        n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                 envelope={"ack": ack_to, "cursor_from": cur, "cursor_to": ack_to}, kind="ack", decision="accepted",
                 reason="cursor %d->%d (ack %d)" % (cur, ack_to, ack_to),
                 cursor={"from": cur, "to": ack_to, "ack": ack_to})
        rep = bn.reconcile(bn.export(self.log, 1), "peer",
                           [{"phase": "request", "sent": [], "ack": ack_to, "received": [], "round": "r1"},
                            {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}], strict=True)
        self.assertIn("round_pending_unknown", {u["type"] for u in rep["unresolved"]},
                      "a csonka mérés után a kurzor-lépés némán elfogadott lett (%r)" % (c,))
        self.assertFalse(rep["ok"])


if __name__ == "__main__":
    unittest.main()
