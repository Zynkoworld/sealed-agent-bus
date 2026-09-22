"""Az SDS-boríték hídjának támadása — saját.

Három lelet a nem-Claude kartól:
  1. a KÜLSŐ validátor egyedül döntött, és egy env-változóból tetszőleges modul betölthető
     (`AGENT_BUS_SDS_VALIDATOR=rogue:ok`) -> aláírás, admission, minden megkerülhető volt.
     Javítás: a BEÉPÍTETT ellenőrzés fut előbb, a külső CSAK SZIGORÍTHAT.
  2. az admission `config_id` OPCIONÁLIS volt -> hiányában a kötés csendben kimaradt, és egy másik
     config-kontextusba átültetett boríték is átment (cross-config replay).
     Javítás: hiányzó kötés -> `unverifiable(no-config-binding)`, harmadik állapot.
  3. a role/org Unicode-alakja (NFC vs NFD) két KÜLÖNBÖZŐ aláírt bájtsort ad ugyanarra a látszólagos
     értékre. Javítás: az admission mezőit NFC-re normalizáljuk az aláírt üzenet építésekor.

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


@unittest.skipUnless(sds.HAVE_CRYPTO, "cryptography szükséges")
class SdsBridgeUnderAttack(unittest.TestCase):
    def setUp(self):
        self.key, self.pub = _keypair()
        self.role, self.org = "operator", "node"
        rec = {"kind": "note", "body": "mérés"}
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

    # ── kontroll: a becsületes boríték érvényes ──────────────────────────────
    def test_control_honest_envelope_is_valid(self):
        self.assertEqual(self.verify(), ("valid", ""))

    # ── kontroll: a rossz aláírás bukik ─────────────────────────────────────
    def test_control_bad_signature_is_invalid(self):
        env = json.loads(self.body)
        env["envelope"]["sigs"][0]["sig"] = "00" * 64
        self.body = json.dumps(env, sort_keys=True)
        self.assertEqual(self.verify()[0], "invalid")

    # ── 1: a külső validátor NEM tehet érvényessé egy érvénytelen borítékot ──
    def test_external_validator_cannot_upgrade_an_invalid_envelope(self):
        env = json.loads(self.body)
        env["envelope"]["sigs"][0]["sig"] = "00" * 64            # hamis aláírás
        self.body = json.dumps(env, sort_keys=True)
        with mock.patch.object(sds, "_external_validator", lambda: (lambda framed, ctx: "valid")):
            status, why = self.verify()
        self.assertEqual(status, "invalid", "a külső validátor felülírta a beépített elutasítást (%s)" % why)

    # ── 1b: a külső validátor viszont SZIGORÍTHAT ───────────────────────────
    def test_external_validator_may_still_tighten(self):
        with mock.patch.object(sds, "_external_validator", lambda: (lambda framed, ctx: ("invalid", "policy"))):
            self.assertEqual(self.verify(), ("invalid", "policy"))

    # ── 1c: a külső validátor megkapja a beépített eredményt is ─────────────
    def test_external_validator_sees_the_builtin_result(self):
        seen = {}

        def ext(framed, ctx):
            seen.update(ctx.get("builtin") or {})
            return "valid"

        with mock.patch.object(sds, "_external_validator", lambda: ext):
            self.verify()
        self.assertEqual(seen.get("status"), "valid", "a külső validátor nem látja, mit mondott a beépített")

    # ── 2: hiányzó config-kötés = harmadik állapot, nem csendes pass ─────────
    def test_missing_config_binding_is_not_silent(self):
        adm = dict(self.admission)
        adm.pop("config_id")
        self.assertEqual(self.verify(admission=adm), ("unverifiable", "no-config-binding"))

    def test_control_wrong_config_id_is_invalid(self):
        adm = dict(self.admission, config_id="sha256:" + "22" * 32)
        self.assertEqual(self.verify(admission=adm), ("invalid", "config-mismatch"))

    # ── 3: NFC/NFD — ugyanaz a role két alakban ugyanazt jelenti ────────────
    def test_role_unicode_forms_agree(self):
        role_nfd = unicodedata.normalize("NFD", "kávé-operátor")
        role_nfc = unicodedata.normalize("NFC", "kávé-operátor")
        self.assertNotEqual(role_nfd, role_nfc, "előfeltétel: a két alak bájtban különbözik")
        env = json.loads(self.body)["envelope"]
        env["sigs"] = []
        msg = sds.signed_message(env, role_nfc, self.org)        # NFC alakkal ALÁÍRVA
        env["sigs"] = [{"issuer": self.pub, "sig": self.key.sign(msg).hex()}]
        self.body = json.dumps({"record": json.loads(self.body)["record"], "envelope": env}, sort_keys=True)
        adm = {"config_id": env["config_id"],
               "admitted": [{"sender": "hub", "issuer": self.pub, "org": self.org, "role": role_nfd}]}  # NFD az admissionban
        self.assertEqual(self.verify(admission=adm), ("valid", ""),
                         "az NFD-alakú admission-role miatt a becsületes aláírás érvénytelennek látszott")


if __name__ == "__main__":
    unittest.main()
