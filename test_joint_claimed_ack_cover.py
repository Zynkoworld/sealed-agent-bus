"""(2026-09-16, ) — a `2812b18` háromfokú fedezete: egy MEGCÁFOLT gyanú és egy NIT.

MEGCÁFOLVA (a gyanúm, mérve — `test_control_*_real_swallow_*`): azt feltételeztem, hogy a vádlott az
azonnali, ingyenes `{"processed": false}` válasszal (vagy hallgatással) fedezetet gyárthat a hamisított
ack-bejegyzéshez, és így elejtheti a BLOCKER-em `ack_logged_not_sent` vádját. NEM működik: a kliens
ack-ja MINDIG a saját `stored_max`-ja (`bus_ssh_client.py:62`), a VALÓDI elnyeléshez pedig a kurzort a
`stored_max` FÖLÉ kell ugratni — olyan ack-értékre, amit a kliens sosem küld. A fedezet tehát felülről
kötött: a hard vád megmarad. A ti háromfokú modelletek ezen a ponton helytáll.

🟡 NIT (ami nyitva maradt): ahol a fedezet MŰKÖDIK (a kliens tényleg elküldte azt az ack-ot, csak a kör
   kimenetele bizonytalan), ott a jelentés nem mondja meg, hogy a lefokozás a VÁDLOTT saját, aláíratlan
   `processed:false` mezőjén áll-e, vagy valódi bizonytalanságon (timeout). A `sent` ágon ezt már kimondjátok
   (`peer_claimed_unprocessed`, `bus_notary.py:486,518`), az ack ágon (:573) nem — betűre ugyanaz a tétel.

KONTROLL a ti nyitott kérdésetekre („csak napló-horgonnyal enyhítsen — bevezessük?"):
   MÉRT VÁLASZ: NE. Az ellenvetésetek helytálló, és itt a bizonyítéka.

Hálózat nincs: a „távoli gép" mindenütt `/bin/sh` a helyi gépen. stdlib unittest + cryptography.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402
import bus_ssh_client as cl  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402


def fake_ssh(reply: str, rc: int = 0):
    """Hamis 'ssh': elolvassa a kérést (a bájtok KIMENTEK), majd a megadott választ adja."""
    return ["/bin/sh", "-c", "cat >/dev/null; printf %s " + json.dumps(reply) + "; exit %d" % rc, "--"]


SILENT_SSH = ["/bin/sh", "-c", "cat >/dev/null; sleep 30", "--"]
CLAIM = json.dumps({"identity": "remote1", "error": "busy", "processed": False})


class _Harness:
    """Közös, izolált környezet (a ti test_joint_ack_cover_tiers.py-tekből)."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.db = os.path.join(t, "bus.db")
        self.state = os.path.join(t, "state")
        self.log = os.path.join(t, "notary.jsonl")
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

    def receipts(self):
        return [json.loads(l) for l in open(cl.receipts_path(self.state, "remote1", "peer")) if l.strip()]

    def round(self, ssh_cmd, msgs=None, timeout=120.0):
        try:
            return cl.exchange("remote1", "peer", msgs or [], ssh_cmd=ssh_cmd, state_dir=self.state,
                               db=self.db, timeout=timeout)
        except Exception:                                   # noqa: BLE001
            return None

    def set_cursor(self, n):
        os.makedirs(self.state, exist_ok=True)
        cl._save_state(cl._state_path(self.state, "remote1", "peer"), {"stored_max": n})

    def forged_ack_log(self, up=4, frm=0, to=4):
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        n.record(sender_identity="peer", sender_auth="ssh-key", envelope={"identity": "peer", "cursor": to},
                 recipient="peer", kind="ack", decision="accepted", reason="cursor %d->%d (ack %d)" % (frm, to, up))
        return bn.export(self.log, 1)


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class PresumedCoverIsBounded(_Harness, unittest.TestCase):
    """A MEGCÁFOLT gyanú: a feltételezett fedezet felülről kötött — a valódi elnyelést nem fedi."""

    def test_control_real_swallow_survives_a_processed_false_claim(self):
        """KONTROLL (ZÖLD): a kurzor a kliens stored_max-ja (0) FÖLÉ, 10-re ugrik; a vádlott azonnali
        `processed:false`-a nem fedez, mert a kliens ack-ja 0 volt → a hard vád megmarad."""
        self.set_cursor(0)
        self.round(fake_ssh(CLAIM))
        self.assertEqual([r["ack"] for r in self.receipts() if r.get("phase") == "request"], [0])
        rep = bn.reconcile(self.forged_ack_log(up=10, to=10), "peer", self.receipts(),
                           trusted_pub=self.pub, strict=False)
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])

    def test_control_real_swallow_survives_silence(self):
        """KONTROLL (ZÖLD): ugyanez hallgatással (timeout) sem fedezhető."""
        self.set_cursor(0)
        self.round(SILENT_SSH, timeout=1.0)
        rep = bn.reconcile(self.forged_ack_log(up=10, to=10), "peer", self.receipts(),
                           trusted_pub=self.pub, strict=False)
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])

    # ── 🟡 NIT ─────────────────────────────────────────────────────────────
    def test_claimed_ack_cover_is_indistinguishable_from_a_real_timeout(self):
        """🟡 Ahol a fedezet működik, ott sem látszik, hogy a VÁDLOTT szavára épül-e."""
        self.set_cursor(4)
        self.round(fake_ssh(CLAIM))
        claimed = [u for u in bn.reconcile(self.forged_ack_log(), "peer", self.receipts(),
                                           trusted_pub=self.pub, strict=True)["unresolved"]
                   if u["type"].startswith("ack_")]
        self.tearDown(); self.setUp()
        self.set_cursor(4)
        self.round(SILENT_SSH, timeout=1.0)
        timeout = [u for u in bn.reconcile(self.forged_ack_log(), "peer", self.receipts(),
                                           trusted_pub=self.pub, strict=True)["unresolved"]
                   if u["type"].startswith("ack_")]
        self.assertTrue(claimed and timeout, "előfeltétel: mindkét ágon van ack-tétel")
        self.assertNotEqual(claimed, timeout,
                            "a vádlott állítására épülő fedezet és a valódi bizonytalanság betűre ugyanaz a "
                            "tétel: %r — a `sent` ág `peer_claimed_unprocessed`-jének ack-oldali párja hiányzik"
                            % (claimed,))


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class AnchorRuleCounterProof(_Harness, unittest.TestCase):
    """A NYITOTT KÉRDÉSETEK: „csak napló-horgonnyal enyhítsen" — bevezessük-e? MÉRT VÁLASZ: NE."""

    def test_control_honest_processed_false_never_logs_anything(self):
        """KONTROLL (ZÖLD): a becsületes végpont `processed:false` mellett NULLA bejegyzést ír
        (`bus_ssh_exchange.py:65,80,83` mind a `note(...)` ELŐTT tér vissza)."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        r1 = ex.exchange("peer", b"x" * (ex.MAX_BYTES + 1), db=self.db, notary=n)      # oversize
        with mock.patch.object(bn.Notary, "from_env", side_effect=bn.NotaryError("nincs kulcs")):
            r2 = ex.exchange("peer", json.dumps({"ack": 4, "messages": []}).encode(), db=self.db)
        self.assertIs(r1.get("processed"), False, r1)
        self.assertIs(r2.get("processed"), False, r2)
        entries = [r for r in bn.export(self.log, 1) if r.get("type") == "entry"] if os.path.exists(self.log) else []
        self.assertEqual(entries, [])

    def test_control_honest_stopped_notary_has_no_anchor_and_must_not_be_hard_accused(self):
        """KONTROLL (ZÖLD): a leállt, de BECSÜLETES közjegyző köre (a) horgony NÉLKÜL válaszol, és
        (b) ma `unresolved: peer_claimed_unprocessed`-et kap, nem hard vádat. A horgony-követelés ezt
        hard `sent_not_logged`-dá tenné → hamis vád. Az ellenvetésetek mérve helyes."""
        msg = {"sender": "peer", "recipient": "remote1", "body": "fontos"}
        with mock.patch.object(bn.Notary, "from_env", side_effect=bn.NotaryError("nincs kulcs")):
            reply = ex.exchange("peer", json.dumps({"ack": 0, "messages": [msg]}).encode(), db=self.db)
        self.assertIs(reply.get("processed"), False, reply)
        self.assertIsNone(reply.get("notary"), "a becsületes, leállt közjegyző köre horgony NÉLKÜL jön: %r" % (reply,))
        self.round(fake_ssh(json.dumps(reply)), msgs=[msg])
        rep = bn.reconcile([], "peer", self.receipts(), strict=False)     # üres napló: semmit nem írt
        self.assertEqual([d["type"] for d in rep["discrepancies"]], [])
        self.assertIn("peer_claimed_unprocessed", [u["type"] for u in rep["unresolved"]])


if __name__ == "__main__":
    unittest.main()
