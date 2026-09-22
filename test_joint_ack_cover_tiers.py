"""(2026-09-16) — a kör-kimenetel HÁROM rése a `91939aa`-n.

A `91939aa` helyesen vette ki a `not-sent` kört a fedezetből (BLOCKER-em) és vezette be a `reached`
kimenetelt (HIGH-om). A mérés a JAVÍTOTT kódon három új rést talált; mindhárom a „ki állítja, és mivel
bizonyítja" kérdésen bukik.

A) 🔴 A `unknown` kör ack-ja NYOMTALANUL fedez — és az `unknown`-t a VÁDLOTT idézi elő.
   `bus_notary.py:554-565`: `any_acks = acks(PROVEN_ARRIVED + ("unknown",))`, és a fordított irány
   (`ack_logged_not_sent`) csak azt nézi, van-e fedező sor — azt nem, hogy a fedezet BIZONYÍTOTT
   (delivered/reached) vagy csak FELTÉTELEZETT (unknown). Az `unknown_acks` ág ennek a fordítottját jelöli
   (a fél talán küldte, a napló nem tartalmazza), ezt az irányt nem.
   Támadás: a nem becsületes közjegyző elnyeli a postát, beírja a fedező `cursor F->T (ack U)` bejegyzést,
   majd a következő körben egyszerűen NEM VÁLASZOL. A kliens timeoutol → `outcome: unknown` → a BLOCKER-em `ack_logged_not_sent` vádja eltűnik — `discrepancies` ÉS `unresolved` is üres, `ok:true`
   TERMÉK-/strict-módban is. A támadónak nem kell hazudnia: elég hallgatnia.

B) 🟠 Az `error`-t is tartalmazó, de `replies`-t hozó válasz NEM kerül a nyugtába — a becsületes közjegyző
   kap hamis hard vádat. `bus_ssh_client.py:99-108`: a `reached`/`unknown` ág `_receipt`-je nem ír `received`
   listát, a kód alatta viszont feldolgozza a `replies`-t (`ab.send` a helyi buszra) és MOZDÍTJA a
   `stored_max` kurzort. A nyugta tehát hiányos, pedig a kétirányú összevetés alapfeltevése épp az, hogy
   „a fél nyugtája a fél igazsága" → `delivered_not_received` hard vád olyan válaszra, amit a fél MEGKAPOTT.

C) 🟠 A „nem tudni, mert nem jött válasz" és a „nem tudni, mert a VÁDLOTT ezt állította" ugyanaz a tétel.
   A `processed:false` helyes szándékú, de a végpont saját, aláíratlan mezője: bármely
   hibára ráteheti, és a hard `sent_not_logged` vád `unresolved: sent_outcome_unknown`-ra hígul — pont arra
   a típusra, amit a valódi bizonytalanság (timeout) is ad. A jelentésből nem derül ki, hogy a lefokozás a
   vádlott szavára épül.

A kontrollok a mai kódon IS zöldek (a szonda nem vak). Hálózat nincs: `/bin/sh` a helyi gépen.
stdlib unittest + cryptography.
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
    """Hamis 'ssh': elolvassa a kérést (tehát a bájtok KIMENTEK), majd a megadott választ adja."""
    return ["/bin/sh", "-c", "cat >/dev/null; printf %s " + json.dumps(reply) + "; exit %d" % rc, "--"]


SILENT_SSH = ["/bin/sh", "-c", "cat >/dev/null; sleep 30", "--"]   # a végpont elolvassa, de nem válaszol


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class UnknownCoverAndReceipt(unittest.TestCase):
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

    # ── segédek ────────────────────────────────────────────────────────────
    def receipts(self):
        return [json.loads(l) for l in open(cl.receipts_path(self.state, "remote1", "peer")) if l.strip()]

    def round(self, ssh_cmd, msgs=None, timeout=120.0):
        try:
            return cl.exchange("remote1", "peer", msgs or [], ssh_cmd=ssh_cmd, state_dir=self.state,
                               db=self.db, timeout=timeout)
        except Exception:                                   # noqa: BLE001 — a kimenetel-sor a lényeg, nem a kivétel
            return None

    def set_cursor(self, n):
        os.makedirs(self.state, exist_ok=True)
        cl._save_state(cl._state_path(self.state, "remote1", "peer"), {"stored_max": n})

    def forged_ack_log(self, up=4, frm=0, to=4):
        """A közjegyző elnyeli a postát: fedező `cursor F->T (ack U)` bejegyzés KÜLDÉS nélkül."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        n.record(sender_identity="peer", sender_auth="ssh-key", envelope={"identity": "peer", "cursor": to},
                 recipient="peer", kind="ack", decision="accepted", reason="cursor %d->%d (ack %d)" % (frm, to, up))
        return bn.export(self.log, 1)

    # ── A) a hallgatással gyártott, NYOMTALAN fedezet ───────────────────────
    def test_control_forged_ack_without_any_round_is_caught(self):
        """KONTROLL (ma zöld): bukott kör nélkül a hamisított ack-bejegyzés hard vádat kap."""
        recs = self.forged_ack_log()
        rep = bn.reconcile(recs, "peer", [], trusted_pub=self.pub, strict=False)
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])

    def test_silent_endpoint_must_not_erase_the_ack_accusation(self):
        """A LELET (A): a végpont hallgat → `unknown` kör → a vád nyomtalanul eltűnik, strict-ben is."""
        self.set_cursor(4)
        self.round(SILENT_SSH, timeout=1.0)
        rows = self.receipts()
        self.assertEqual([r["outcome"] for r in rows if r.get("phase") == "outcome"], ["unknown"])
        recs = self.forged_ack_log()
        rep = bn.reconcile(recs, "peer", rows, trusted_pub=self.pub, strict=True)
        self.assertFalse(
            rep["ok"] and not rep["discrepancies"] and not rep["unresolved"],
            "egyetlen, a VÁDLOTT által kikényszerített timeout-kör nyomtalanul elnyelte az "
            "ack_logged_not_sent vádat: ok=%r, discrepancies=%r, unresolved=%r — a feltételezett "
            "(unknown) fedezet nem különbözik a bizonyítottól (delivered/reached)" % (
                rep["ok"], rep["discrepancies"], rep["unresolved"]))

    def test_rc255_after_the_request_left_is_a_false_accusation(self):
        """A LELET (A/2, a ti nyitott kérdésetek): az rc 255 a kérés KIÍRÁSA UTÁN is jöhet — ilyenkor a
        `not-sent` a BECSÜLETES közjegyzőt vádolja meg, aki az ack-ot (naplózás-előbb) már beírta."""
        self.set_cursor(4)
        self.round(fake_ssh("kapcsolat megszakadt", rc=255))     # a hamis ssh ELOLVASTA a kérést
        rows = self.receipts()
        self.assertEqual([r["outcome"] for r in rows if r.get("phase") == "outcome"], ["not-sent"])
        recs = self.forged_ack_log()                              # itt ez NEM hamisítás: becsületes napló
        rep = bn.reconcile(recs, "peer", rows, trusted_pub=self.pub, strict=False)
        self.assertNotIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]],
                         "a kérés kiment (a végpont elolvasta), csak a kapcsolat szakadt meg — a becsületes "
                         "közjegyző mégis hard vádat kap; a `not-sent` csak ott áll meg, ahol bizonyított, "
                         "hogy egy bájt sem ment ki (OSError)")

    def test_control_ssh_never_started_is_a_true_accusation(self):
        """KONTROLL (ma zöld): ha az ssh EL SEM INDULT, a vád jogos — a javaslat nem üríti ki a leletet."""
        self.set_cursor(4)
        self.round(["/nincs/ilyen/ssh/binaris"])
        rows = self.receipts()
        self.assertEqual([r["outcome"] for r in rows if r.get("phase") == "outcome"], ["not-sent"])
        rep = bn.reconcile(self.forged_ack_log(), "peer", rows, trusted_pub=self.pub, strict=False)
        self.assertIn("ack_logged_not_sent", [d["type"] for d in rep["discrepancies"]])

    # ── B) a hiányos nyugta ────────────────────────────────────────────────
    def delivered_log(self, reply_msg):
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        n.record(sender_identity="peer", sender_auth="ssh-key",
                 envelope={"identity": "peer", "cursor": 0, "reply_sha256": [bn.envelope_hash(reply_msg)]},
                 recipient="peer", kind="pickup", decision="accepted", reason="cursor=0 replies=1")
        n.record(sender_identity="peer", sender_auth="ssh-key", envelope=reply_msg, recipient="peer",
                 kind="pickup", decision="delivered", reason="id=%s" % reply_msg["id"])
        return bn.export(self.log, 1)

    def test_control_clean_reply_is_in_the_receipt(self):
        """KONTROLL (ma zöld): hibamentes válasznál a nyugta tartalmazza a kapott választ, nincs vád."""
        msg = {"id": 7, "sender": "hub", "body": "valasz", "kind": "msg", "topic": ""}
        self.round(fake_ssh(json.dumps({"identity": "remote1", "replies": [msg]})))
        rep = bn.reconcile(self.delivered_log(msg), "peer", self.receipts(), trusted_pub=self.pub, strict=False)
        self.assertEqual([d["type"] for d in rep["discrepancies"]], [])

    def test_error_reply_with_replies_is_stored_but_not_receipted(self):
        """A LELET (B): a kliens eltárolja a válaszokat, de a nyugtába nem írja → hamis hard vád."""
        msg = {"id": 7, "sender": "hub", "body": "valasz", "kind": "msg", "topic": ""}
        res = self.round(fake_ssh(json.dumps({"error": "partial", "replies": [msg]})))
        self.assertEqual((res or {}).get("stored_locally"), 1, "előfeltétel: a kliens eltárolta a választ")
        self.assertEqual(len(ab.recv("peer", mark=False, db=self.db, verify_sds=False)), 1)
        rep = bn.reconcile(self.delivered_log(msg), "peer", self.receipts(), trusted_pub=self.pub, strict=False)
        self.assertNotIn("delivered_not_received", [d["type"] for d in rep["discrepancies"]],
                         "a fél a választ MEGKAPTA és a helyi buszra tárolta (stored_locally=1), a nyugtába "
                         "mégsem került `received` — a becsületes közjegyző hard vádat kap")

    # ── C) a vádlott szava vs. a valódi bizonytalanság ──────────────────────
    def unresolved_of(self, reply):
        self.round(fake_ssh(reply), msgs=[{"sender": "peer", "recipient": "remote1", "body": "fontos"}])
        return bn.reconcile([], "peer", self.receipts(), strict=False)      # üres napló = a közjegyző kihagyta

    def test_control_processed_false_still_blocks_ok_in_strict(self):
        """KONTROLL (ma zöld): strict/termék-módban a lefokozott tétel sem ad `ok:true`-t."""
        self.round(fake_ssh(json.dumps({"error": "busy", "processed": False})),
                   msgs=[{"sender": "peer", "recipient": "remote1", "body": "fontos"}])
        rep = bn.reconcile([], "peer", self.receipts(), strict=True)
        self.assertFalse(rep["ok"])

    def test_peer_claimed_downgrade_is_indistinguishable_from_real_uncertainty(self):
        """A LELET (C): a vádlott állítására épülő lefokozás ugyanazt a tételt adja, mint a valódi timeout."""
        rep = self.unresolved_of(json.dumps({"error": "busy", "processed": False}))
        self.assertEqual([d["type"] for d in rep["discrepancies"]], [],
                         "előfeltétel: a processed:false elvette a hard vádat")
        claimed = rep["unresolved"]
        self.assertTrue(claimed, "előfeltétel: maradt unresolved tétel")
        self.assertTrue(
            any(("peer" in json.dumps(u)) or ("claim" in json.dumps(u)) or ("processed" in json.dumps(u))
                for u in claimed),
            "a hard vádat a VÁDLOTT saját, aláíratlan `processed:false` mezője fokozta le, de a jelentés "
            "ezt nem mondja ki: unresolved=%r — ugyanaz a `sent_outcome_unknown` típus, amit a valódi "
            "bizonytalanság (timeout) is ad" % (claimed,))


if __name__ == "__main__":
    unittest.main()

