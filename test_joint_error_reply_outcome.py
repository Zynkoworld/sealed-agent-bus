"""(2026-09-15 este/2) — a végpont a SAJÁT válaszával fokozza le a vádat `unknown`-ra.

A `572f84a` kör-kimenetele három állapotot ismer. A besorolás (`bus_ssh_client.py:88-93`):

    if not isinstance(res, dict) or "error" in res:
        outcome = "not-sent" if proc.returncode == 255 and not isinstance(res, dict) else "unknown"

Vagyis egy ÉRVÉNYES JSON `{"error":...}` válasz `unknown`-t ad. De ez a válasz maga BIZONYÍTJA, hogy a kérés
odaért és a végpont feldolgozta — az „nem tudni, kiment-e" itt nem igaz állítás. A `reconcile` az `unknown` kör
küldéseiből nem emel `sent_not_logged` hard vádat, csak `unresolved: sent_outcome_unknown`-t (dev-módban rc=0).

Következmény: a nem becsületes közjegyző minden kör végén `{"error": "busy"}`-t ad — a postát feldolgozza
(kézbesíti a címzettnek), a naplóból kihagyja, és a fél nyugtájában soha nem keletkezik olyan kör, amiből
vádolni lehetne. A `33b1510`-en ugyanez `sent_not_logged` + rc=1 volt.

A megkülönböztető jel megvan és mérhető: a JSON-válasz ténye. A `not-sent` (ssh el sem indult) és a timeout
helyesen „nem tudni"; az érvényes, de error-t tartalmazó válasz „odaért".

A kontroll (nem-JSON szemét / rc=255) a mai kódon IS helyesen `unknown`/`not-sent` — a szonda nem vak.
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
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402
import bus_ssh_client as cl  # noqa: E402


def fake_ssh(reply: str, rc: int = 0):
    """Hamis 'ssh': a megadott sztringet írja a stdout-ra. Hálózat nincs — /bin/sh a helyi gépen."""
    return ["/bin/sh", "-c", "cat >/dev/null; printf %s " + json.dumps(reply) + "; exit %d" % rc, "--"]


class ErrorReplyOutcome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.state = os.path.join(t, "state")
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"),
            "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def run_round(self, reply, rc=0):
        msgs = [{"sender": "peer", "recipient": "remote1", "body": "fontos", "topic": "t"}]
        try:
            cl.exchange("remote1", "peer", msgs, ssh_cmd=fake_ssh(reply, rc), state_dir=self.state, db=self.db)
        except Exception:
            pass
        rp = cl.receipts_path(self.state, "remote1", "peer")
        rows = [json.loads(l) for l in open(rp) if l.strip()]
        return [r for r in rows if r.get("phase") == "outcome"][-1]

    # ── kontroll: a valóban bizonytalan esetek ──────────────────────────────
    def test_control_non_json_rc255_is_not_sent(self):
        self.assertEqual(self.run_round("szemet", rc=255)["outcome"], "not-sent")

    def test_control_non_json_other_rc_is_unknown(self):
        self.assertEqual(self.run_round("szemet", rc=1)["outcome"], "unknown")

    # ── A LELET: az érvényes JSON error-válasz bizonyítja, hogy odaért ──────
    def test_json_error_reply_must_not_be_unknown(self):
        out = self.run_round('{"error": "busy"}', rc=0)
        self.assertNotEqual(out["outcome"], "unknown",
                            "a végpont ÉRVÉNYES JSON-nal válaszolt (rc=0) — a kérés bizonyíthatóan odaért, "
                            "mégis 'nem tudni' minősítést kap, ami elnyeli a sent_not_logged vádat")

    # ── és a kár: a hard vád unresolved-re hígul ───────────────────────────
    def test_error_reply_downgrades_sent_not_logged(self):
        msgs = [{"sender": "peer", "recipient": "remote1", "body": "fontos", "topic": "t"}]
        try:
            cl.exchange("remote1", "peer", msgs, ssh_cmd=fake_ssh('{"error": "busy"}'), state_dir=self.state,
                        db=self.db)
        except Exception:
            pass
        rp = cl.receipts_path(self.state, "remote1", "peer")
        receipts = [json.loads(l) for l in open(rp) if l.strip()]
        rep = bn.reconcile([], "peer", receipts)                # üres napló: a közjegyző kihagyta a tételt
        self.assertIn("sent_not_logged", [d["type"] for d in rep["discrepancies"]],
                      "a feldolgozott és kihagyott üzenet nem kap hard vádat; unresolved=%r" % rep["unresolved"])


if __name__ == "__main__":
    unittest.main()
