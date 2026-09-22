"""Kliens-aláírt SSH-csere — a két gép közti NÉMA SÜKETSÉG zárása (2026-09-21, v1.5.2).

Mért állapot a műhely-buszon (94, termék-mód): 09-19 -től MINDEN két gép közt cserélt sor eldobódott olvasáskor, miközben a küldő
`accepted=[id]`-t kapott. Ok: a csere-végpont elvből NEM írja alá a busz-gép kulcsával a távoli fél sorát
(sign_key=False — helyes: a busz-gép nem a feladó), de ugyanaznap a két név registry-kulcsot kapott, és a termék-mód a
pinelt név alatti csupasz sort eldobja. A két helyes szabály együtt
süketséget adott, és a feladó SEMMIT nem látott belőle.

Zárás (három ponton): (1) `agent_bus.sign_for_send` / `check_presigned` — a feladó a SAJÁT kulcsával írja alá a sort
a saját gépén, a busz-gép a registry ellen ellenőrzi és PONTOSAN azt tárolja (ts is a feladóé); (2) `bus_ssh_exchange`
átadja a `ts/sig/pubkey`-t, és a csupasz sort egy pinelt név alatt termék-módban OKKAL utasítja el (nem tárolja, hogy
aztán némán eldobódjon); (3) `bus_ssh_client.sign_outgoing` a kimenő üzeneteket automatikusan aláírja, ha a helyi
identitás kulcsa megvan.

Mutáns-próba: a `presigned=` átadás nélkül `test_client_signed_row_is_delivered_in_product_mode` bukik; a csere
ingest-elutasítása nélkül `test_bare_row_under_pinned_name_is_rejected_visibly` bukik; a registry-egyeztetés nélkül
`test_foreign_key_is_forged`; a tartalom-kötés nélkül `test_tampered_body_is_forged`.

stdlib unittest; izolált DB / registry / notary; a csere in-process (nincs valódi ssh).
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402
import bus_ssh_client as cli  # noqa: E402
import bus_ssh_exchange as srv  # noqa: E402


def _keypair():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv.private_bytes_raw(), pub.hex()


@unittest.skipUnless(ab._A2_HAVE, "cryptography szükséges")
class Base(unittest.TestCase):
    """Busz-gép: registry-ben `peer` (távoli) és `hub` (helyi) kulcsa; termék-mód env-ből; közjegyző kikapcsolva
    (a notary saját tesztjei fedik) — itt CSAK az aláírás-átvitel a tárgy."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.keys = os.path.join(d, "keys"); os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(d, "bus.db")
        self.peer_seed, peer_pub = _keypair()
        self.other_seed, self.other_pub = _keypair()
        with open(os.path.join(self.keys, "peer.pub"), "w") as f:
            f.write(peer_pub)
        self.peer_key = os.path.join(d, "peer.ed25519.key")           # a TÁVOLI gép privát seedje (nálunk csak a tesztben)
        with open(self.peer_key, "w") as f:
            f.write(self.peer_seed.hex())
        self.p = [mock.patch.object(ab, "KEYS_DIR", self.keys),
                  mock.patch.dict(os.environ, {"AGENT_BUS_AUTO_SIGN": "0", "AGENT_BUS_ENFORCE_DIR": os.path.join(d, "enf"),
                                               "AGENT_BUS_DIR": d, "AGENT_BUS_MODE": "product",
                                               "AGENT_BUS_NOTARY": "0"})]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def presigned(self, body="hello from the other machine", *, seed=None, sender="peer", **over):
        key = self.peer_key
        if seed is not None:
            key = os.path.join(self.tmp.name, "x.key")
            with open(key, "w") as f:
                f.write(seed.hex())
        m = {"to": "hub", "body": body, "topic": "t", "kind": "msg"}
        m.update(ab.sign_for_send(key, sender, "hub", body, topic="t", kind="msg"))
        m.update(over)
        return m

    def run_round(self, msgs, identity="peer"):
        return srv.exchange(identity, json.dumps({"ack": 0, "messages": msgs}), db=self.db, notary=None)


class ClientSigned(Base):
    def test_client_signed_row_is_delivered_in_product_mode(self):
        out = self.run_round([self.presigned()])
        self.assertEqual(out["rejected"], [])
        self.assertEqual(len(out["accepted"]), 1)
        row = ab.recv("hub", db=self.db)[0]                          # termék-módú recv: az enforce szűr
        self.assertEqual(row["sender"], "peer")
        self.assertEqual(ab.verify_sender(row, keys_dir=self.keys), "signed")
        self.assertEqual(enf.check(row, keys_dir=self.keys), (True, "ok"))

    def test_the_stored_ts_is_the_signers_ts(self):
        # a ts az aláírt tartalom része — a szerver nem oszthat újat, különben az aláírás nem verifikálna
        m = self.presigned()
        self.run_round([m])
        row = ab.recv("hub", db=self.db)[0]
        self.assertEqual(row["ts"], m["ts"])

    def test_bare_row_under_pinned_name_is_rejected_visibly(self):
        # a régi út: accepted=[id], majd olvasáskor néma eldobás. Most: rejected okkal, NEM tárolódik.
        out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}])
        self.assertEqual(out["accepted"], [])
        self.assertEqual(len(out["rejected"]), 1)
        self.assertIn("unsigned-pinned", out["rejected"][0]["reason"])
        self.assertIn("peer.ed25519.key", out["rejected"][0]["reason"])   # az ok MEGMONDJA, mit kell tenni
        self.assertEqual(ab.tail(None, limit=10, db=self.db), [])

    def test_bare_row_from_unpinned_identity_still_stored(self):
        # nem-pinelt név (nincs registry-kulcs): a back-compat út marad — a szerver tárolja (dev-módban olvasható)
        out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}], identity="guest")
        self.assertEqual(len(out["accepted"]), 1)

    def test_dev_mode_bare_row_still_stored(self):
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": ""}):
            out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}])
        self.assertEqual(len(out["accepted"]), 1)

    def test_foreign_key_is_forged(self):
        # érvényes aláírás, de NEM a registry-ben `peer`-hez kötött kulccsal → forged, nem tárolódik
        out = self.run_round([self.presigned(seed=self.other_seed)])
        self.assertEqual(out["accepted"], [])
        self.assertIn("forged", out["rejected"][0]["reason"])
        self.assertEqual(ab.tail(None, limit=10, db=self.db), [])

    def test_tampered_body_is_forged(self):
        m = self.presigned()
        m["body"] = m["body"] + " (edited in transit)"
        out = self.run_round([m])
        self.assertEqual(out["accepted"], [])
        self.assertIn("forged", out["rejected"][0]["reason"])

    def test_signature_for_another_name_does_not_verify_under_pinned_identity(self):
        # a kliens `hub` nevében ír alá, de az SSH-identitás `peer` → a feladó mindig a pinelt identitás,
        # és az aláírás rá nem verifikál (nem lehet más nevében aláírni, és nem lehet a nevet becsempészni)
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(self.other_pub)
        out = self.run_round([self.presigned(seed=self.other_seed, sender="hub")])
        self.assertEqual(out["accepted"], [])
        self.assertEqual(ab.tail(None, limit=10, db=self.db), [])

    def test_malformed_presigned_fields_are_rejected_not_crashed(self):
        for bad in ({"sig": "zz", "pubkey": "zz", "ts": 1}, {"sig": None, "pubkey": "ab" * 32, "ts": "now"},
                    {"sig": "ab" * 64, "pubkey": "ab" * 32, "ts": True}):
            m = {"to": "hub", "body": "x", **bad}
            out = self.run_round([m])
            self.assertEqual(out["accepted"], [], bad)
            self.assertEqual(len(out["rejected"]), 1, bad)

    def test_presigned_and_sign_key_are_exclusive(self):
        with self.assertRaises(ValueError):
            ab.send("peer", "hub", "x", db=self.db, mirror=False, sign_key=self.peer_key,
                    presigned=ab.sign_for_send(self.peer_key, "peer", "hub", "x"))

    def test_stale_client_ts_is_still_caught_by_enforce(self):
        # a ts a feladóé — az enforce ablaka (múlt) ugyanúgy méri, mint a helyi sorét
        old = time.time_ns() - (enf.WINDOW_PAST_S + 3600) * 1_000_000_000
        m = {"to": "hub", "body": "old", "topic": "t", "kind": "msg"}
        m.update(ab.sign_for_send(self.peer_key, "peer", "hub", "old", topic="t", kind="msg", ts=old))
        out = self.run_round([m])
        self.assertEqual(len(out["accepted"]), 1)                    # tárolva (bizonyíték), de
        self.assertEqual(ab.recv("hub", db=self.db), [])            # termék-módban nem kézbesül (stale-ts)


class ClientSideSigning(Base):
    def test_sign_outgoing_uses_local_identity_key(self):
        msgs = cli.sign_outgoing("peer", [{"to": "hub", "body": "a"}, {"to": "hub", "body": "b", "in_reply_to": 7}],
                                 sign_key=self.peer_key)
        for m in msgs:
            self.assertIn("sig", m); self.assertIn("pubkey", m); self.assertIn("ts", m)
        # amit a kliens aláírt, azt a szerver elfogadja és a címzett `signed`-nek látja
        out = self.run_round(msgs)
        self.assertEqual(out["rejected"], [])
        rows = ab.recv("hub", db=self.db)
        self.assertEqual([r["body"] for r in rows], ["a", "b"])
        self.assertEqual(rows[1]["in_reply_to"], 7)

    def test_sign_outgoing_resolves_key_from_keys_dir(self):
        kd = os.path.join(self.tmp.name, "clientkeys"); os.makedirs(kd)
        with open(os.path.join(kd, "peer.ed25519.key"), "w") as f:
            f.write(self.peer_seed.hex())
        msgs = cli.sign_outgoing("peer", [{"to": "hub", "body": "a"}], keys_dir=kd)
        self.assertIn("sig", msgs[0])

    def test_sign_outgoing_without_key_leaves_message_untouched(self):
        msgs = cli.sign_outgoing("nobody", [{"to": "hub", "body": "a"}], keys_dir=self.tmp.name)
        self.assertEqual(msgs, [{"to": "hub", "body": "a"}])

    def test_exchange_round_signs_before_sending(self):
        # a kliens kör: amit a hamis ssh megkap stdin-en, az már aláírt
        import textwrap
        cap = os.path.join(self.tmp.name, "captured.json")
        fake = os.path.join(self.tmp.name, "fake_ssh.py")
        with open(fake, "w") as f:
            f.write(textwrap.dedent("""
                import json, sys
                raw = sys.stdin.read()
                open(%r, "w").write(raw)
                print(json.dumps({"accepted": [1], "rejected": [], "replies": []}))
            """ % cap))
        local_db = os.path.join(self.tmp.name, "local.db")
        cli.exchange("busmachine", "peer", [{"to": "hub", "body": "signed?"}], ssh_cmd=[sys.executable, fake],
                     state_dir=os.path.join(self.tmp.name, "st"), db=local_db, sign_key=self.peer_key)
        sent = json.load(open(cap))["messages"][0]
        self.assertIn("sig", sent)
        # Az üzenet NEM hordoz `kind`-ot, tehát az aláírt bájtképben a kanonikus szabály szerint `kind=""`
        # áll. Ez a sor korábban `kind="msg"`-ot várt, és ezzel a RÉGI, hibás viselkedést rögzítette: a
        # kliens-aláíró saját `or "msg"` normalizálást hordozott, a bájtkép-építő nem. A négy aláírási
        # belépési pont csak véletlenül egyezett; amint kettőt a specre igazítottam, ez a teszt bukott —
        # helyesen, mert ő volt a bug utolsó őrzője.
        self.assertEqual(ab.check_presigned("peer", "hub", "signed?", sent, topic="", kind="",
                                            keys_dir=self.keys)[0], sent["ts"])
        # Ellenpróba: a RÉGI olvasat (kind="msg") mostantól NEM verifikál — ha valaha újra átmenne,
        # az azt jelenti, hogy valahol visszakerült egy második normalizálás.
        with self.assertRaises(ValueError):
            ab.check_presigned("peer", "hub", "signed?", sent, topic="", kind="msg", keys_dir=self.keys)


if __name__ == "__main__":
    unittest.main()
