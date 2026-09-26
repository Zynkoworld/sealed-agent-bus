"""Client-signed SSH exchange — closing the SILENT DEAFNESS between the two machines (2026-09-21, v1.5.2).

Measured state on the workshop bus (94, product mode): from 09-19 EVERY row exchanged between the two machines was dropped on read, while the sender
got `accepted=[id]`. Cause: by principle the exchange endpoint does NOT sign the remote party's row with the bus machine's key
(sign_key=False — correct: the bus machine is not the sender), but the same day the two names got registry keys, and product mode
drops a bare row under a pinned name. The two correct rules together
gave deafness, and the sender saw NOTHING of it.

Closure (at three points): (1) `agent_bus.sign_for_send` / `check_presigned` — the sender signs the row with ITS OWN key
on its own machine, the bus machine checks it against the registry and stores EXACTLY that (the ts is the sender's too); (2) `bus_ssh_exchange`
passes `ts/sig/pubkey` on, and in product mode rejects a bare row under a pinned name WITH A REASON (it does not store it only for it
to be silently dropped later); (3) `bus_ssh_client.sign_outgoing` signs outgoing messages automatically if the local
identity's key is present.

Mutant probe: without passing `presigned=`, `test_client_signed_row_is_delivered_in_product_mode` fails; without the exchange's
ingest rejection `test_bare_row_under_pinned_name_is_rejected_visibly` fails; without the registry match
`test_foreign_key_is_forged`; without the content binding `test_tampered_body_is_forged`.

stdlib unittest; isolated DB / registry / notary; the exchange is in-process (no real ssh).
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


@unittest.skipUnless(ab._A2_HAVE, "cryptography required")
class Base(unittest.TestCase):
    """Bus machine: the keys of `peer` (remote) and `hub` (local) in the registry; product mode from env; notary off
    (the notary's own tests cover it) — here ONLY the transfer of the signature is the subject."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.keys = os.path.join(d, "keys"); os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(d, "bus.db")
        self.peer_seed, peer_pub = _keypair()
        self.other_seed, self.other_pub = _keypair()
        with open(os.path.join(self.keys, "peer.pub"), "w") as f:
            f.write(peer_pub)
        self.peer_key = os.path.join(d, "peer.ed25519.key")           # the REMOTE machine's private seed (here only in the test)
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
        row = ab.recv("hub", db=self.db)[0]                          # product-mode recv: enforce filters
        self.assertEqual(row["sender"], "peer")
        self.assertEqual(ab.verify_sender(row, keys_dir=self.keys), "signed")
        self.assertEqual(enf.check(row, keys_dir=self.keys), (True, "ok"))

    def test_the_stored_ts_is_the_signers_ts(self):
        # the ts is part of the signed content — the server cannot assign a new one, otherwise the signature would not verify
        m = self.presigned()
        self.run_round([m])
        row = ab.recv("hub", db=self.db)[0]
        self.assertEqual(row["ts"], m["ts"])

    def test_bare_row_under_pinned_name_is_rejected_visibly(self):
        # the old path: accepted=[id], then a silent drop on read. Now: rejected with a reason, NOT stored.
        out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}])
        self.assertEqual(out["accepted"], [])
        self.assertEqual(len(out["rejected"]), 1)
        self.assertIn("unsigned-pinned", out["rejected"][0]["reason"])
        self.assertIn("peer.ed25519.key", out["rejected"][0]["reason"])   # the reason SAYS what to do
        self.assertEqual(ab.tail(None, limit=10, db=self.db), [])

    def test_bare_row_from_unpinned_identity_still_stored(self):
        # a non-pinned name (no registry key): the back-compat path stays — the server stores it (readable in dev mode)
        out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}], identity="guest")
        self.assertEqual(len(out["accepted"]), 1)

    def test_dev_mode_bare_row_still_stored(self):
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": ""}):
            out = self.run_round([{"to": "hub", "body": "bare", "topic": "t"}])
        self.assertEqual(len(out["accepted"]), 1)

    def test_foreign_key_is_forged(self):
        # a valid signature, but NOT with the key bound to `peer` in the registry → forged, not stored
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
        # the client signs in `hub`'s name, but the SSH identity is `peer` → the sender is always the pinned identity,
        # and the signature does not verify for it (one cannot sign in someone else's name, and cannot smuggle the name in)
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
        # the ts is the sender's — the enforce window (past) measures it just like a local row's
        old = time.time_ns() - (enf.WINDOW_PAST_S + 3600) * 1_000_000_000
        m = {"to": "hub", "body": "old", "topic": "t", "kind": "msg"}
        m.update(ab.sign_for_send(self.peer_key, "peer", "hub", "old", topic="t", kind="msg", ts=old))
        out = self.run_round([m])
        self.assertEqual(len(out["accepted"]), 1)                    # stored (evidence), but
        self.assertEqual(ab.recv("hub", db=self.db), [])            # not delivered in product mode (stale-ts)


class ClientSideSigning(Base):
    def test_sign_outgoing_uses_local_identity_key(self):
        msgs = cli.sign_outgoing("peer", [{"to": "hub", "body": "a"}, {"to": "hub", "body": "b", "in_reply_to": 7}],
                                 sign_key=self.peer_key)
        for m in msgs:
            self.assertIn("sig", m); self.assertIn("pubkey", m); self.assertIn("ts", m)
        # what the client signed, the server accepts, and the recipient sees it as `signed`
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
        # the client round: what the fake ssh receives on stdin is already signed
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
        # The message carries NO `kind`, so per the canonical rule the signed byte image has `kind=""`.
        # This line used to expect `kind="msg"`, and so pinned the OLD, faulty behaviour: the
        # client signer carried its own `or "msg"` normalization, the byte-image builder did not. The four signing
        # entry points only matched by chance; as soon as I aligned two with the spec, this test failed —
        # correctly, because it was the bug's last guardian.
        self.assertEqual(ab.check_presigned("peer", "hub", "signed?", sent, topic="", kind="",
                                            keys_dir=self.keys)[0], sent["ts"])
        # Counter-check: the OLD reading (kind="msg") no longer verifies — if it ever passed again,
        # that means a second normalization got back in somewhere.
        with self.assertRaises(ValueError):
            ab.check_presigned("peer", "hub", "signed?", sent, topic="", kind="msg", keys_dir=self.keys)


if __name__ == "__main__":
    unittest.main()
