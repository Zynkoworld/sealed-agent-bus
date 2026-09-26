"""An attack on the SDS envelope bridge — our own.

Three findings from the non-Claude arm:
  1. the EXTERNAL validator decided alone, and an arbitrary module could be loaded from an env variable
     (`AGENT_BUS_SDS_VALIDATOR=rogue:ok`) -> signature, admission, everything could be bypassed.
     Fix: the BUILT-IN check runs first, the external one can ONLY TIGHTEN.
  2. the admission `config_id` was OPTIONAL -> without it the binding was silently skipped, and an envelope
     transplanted into another config context also passed (cross-config replay).
     Fix: a missing binding -> `unverifiable(no-config-binding)`, a third state.
  3. the Unicode form of role/org (NFC vs NFD) gives two DIFFERENT signed byte sequences for the same apparent
     value. Fix: we normalize the admission fields to NFC when building the signed message.

stdlib unittest + cryptography.
"""
import hashlib
import json
import os
import sys
import tempfile
import unicodedata
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sds_envelope as sds  # noqa: E402


def _keypair():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    k = ed25519.Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return k, pub


@unittest.skipUnless(sds.HAVE_CRYPTO, "cryptography required")
class SdsBridgeUnderAttack(unittest.TestCase):
    def setUp(self):
        self.key, self.pub = _keypair()
        self.role, self.org = "operator", "node"
        rec = {"kind": "note", "body": "measurement"}
        rec["record_id"] = sds.record_id_of(rec)
        domain = {"project": "node", "stream": "meres", "repo": "agent-bus"}
        env = {"record_id": rec["record_id"], "config_id": "sha256:" + "11" * 32,
               "domain": domain, "domain_hash": hashlib.sha256(sds.jcs(domain)).hexdigest(),
               "epoch": 1, "sigs": []}
        msg = sds.signed_message(env, self.role, self.org)
        env["sigs"] = [{"issuer": self.pub, "sig": self.key.sign(msg).hex()}]
        self.framed = {"record": rec, "envelope": env}
        self.body = json.dumps(self.framed, sort_keys=True)
        self.admission = {"config_id": env["config_id"],
                          "admitted": [{"sender": "hub", "issuer": self.pub, "org": self.org, "role": self.role}]}

    def verify(self, **kw):
        kw.setdefault("sender", "hub")
        kw.setdefault("admission", self.admission)
        kw.setdefault("registry_pubkey", self.pub)
        return sds.verify(self.body, **kw)

    # ── control: the honest envelope is valid ──────────────────────────────
    def test_control_honest_envelope_is_valid(self):
        self.assertEqual(self.verify(), ("valid", ""))

    # ── control: a bad signature fails ─────────────────────────────────────
    def test_control_bad_signature_is_invalid(self):
        env = json.loads(self.body)
        env["envelope"]["sigs"][0]["sig"] = "00" * 64
        self.body = json.dumps(env, sort_keys=True)
        self.assertEqual(self.verify()[0], "invalid")

    # ── 1: the external validator CANNOT make an invalid envelope valid ──
    def test_external_validator_cannot_upgrade_an_invalid_envelope(self):
        env = json.loads(self.body)
        env["envelope"]["sigs"][0]["sig"] = "00" * 64            # a forged signature
        self.body = json.dumps(env, sort_keys=True)
        with mock.patch.object(sds, "_external_validator", lambda: (lambda framed, ctx: "valid")):
            status, why = self.verify()
        self.assertEqual(status, "invalid", "the external validator overrode the built-in rejection (%s)" % why)

    # ── 1b: the external validator CAN still tighten ───────────────────────────
    def test_external_validator_may_still_tighten(self):
        with mock.patch.object(sds, "_external_validator", lambda: (lambda framed, ctx: ("invalid", "policy"))):
            self.assertEqual(self.verify(), ("invalid", "policy"))

    # ── 1c: the external validator also gets the built-in result ─────────────
    def test_external_validator_sees_the_builtin_result(self):
        seen = {}

        def ext(framed, ctx):
            seen.update(ctx.get("builtin") or {})
            return "valid"

        with mock.patch.object(sds, "_external_validator", lambda: ext):
            self.verify()
        self.assertEqual(seen.get("status"), "valid", "the external validator does not see what the built-in one said")

    # ── 2: a missing config binding = a third state, not a silent pass ─────────
    def test_missing_config_binding_is_not_silent(self):
        adm = dict(self.admission)
        adm.pop("config_id")
        self.assertEqual(self.verify(admission=adm), ("unverifiable", "no-config-binding"))

    def test_control_wrong_config_id_is_invalid(self):
        adm = dict(self.admission, config_id="sha256:" + "22" * 32)
        self.assertEqual(self.verify(admission=adm), ("invalid", "config-mismatch"))

    # ── 3: NFC/NFD — the same role in two forms means the same ────────────
    def test_role_unicode_forms_agree(self):
        role_nfd = unicodedata.normalize("NFD", "kávé-operátor")
        role_nfc = unicodedata.normalize("NFC", "kávé-operátor")
        self.assertNotEqual(role_nfd, role_nfc, "precondition: the two forms differ in bytes")
        env = json.loads(self.body)["envelope"]
        env["sigs"] = []
        msg = sds.signed_message(env, role_nfc, self.org)        # SIGNED with the NFC form
        env["sigs"] = [{"issuer": self.pub, "sig": self.key.sign(msg).hex()}]
        self.body = json.dumps({"record": json.loads(self.body)["record"], "envelope": env}, sort_keys=True)
        adm = {"config_id": env["config_id"],
               "admitted": [{"sender": "hub", "issuer": self.pub, "org": self.org, "role": role_nfd}]}  # NFD in the admission
        self.assertEqual(self.verify(admission=adm), ("valid", ""),
                         "because of the NFD-form admission role the honest signature looked invalid")


if __name__ == "__main__":
    unittest.main()
