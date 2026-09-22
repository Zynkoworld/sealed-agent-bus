"""v1.4 — SCE végponttól végpontig: busz-sor (sds-envelope, record.payload = sce-arm-envelope/v1) → sce_hook →
döntő. A HAMIS döntő ugyanazt a szerződést valósítja meg, mint az egyik kar adaptere (kar-borítékok be, verdikt ki),
motor-kód nélkül. Mátrix (SCE-kar megvesztegetése): egy kar nem dönthet; aláíratlan sorból nincs kar."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sce_hook as sh  # noqa: E402

ARMS = ("app", "node", "aux")


def arm(name, *, derive="h1", seed="s1", cand="C", ref="R"):
    return {"schema": sh.ARM_SCHEMA, "arm": name, "seed": seed, "candidate_package": cand,
            "reference_package": ref, "derive_hash": derive}


def row(payload, *, sds="valid", rid=1, sender="x"):
    framed = {"record": {"payload": payload}, "envelope": {"record_id": "0" * 64}}
    return {"id": rid, "sender": sender, "kind": "sds-envelope", "body": json.dumps(framed), "sds": sds}


def fake_decider(envs):
    """A az egyik kar adapter szerződése, motor nélkül: 3 különböző kar kell, azonos seed; eltérő derive → ABORT;
    egyező derive, de a jelölt nem utódja a referenciának (itt: cand == 'REGRESS') → REJECT; különben ACCEPT."""
    by = {}
    for e in envs:
        if e.get("schema") != sh.ARM_SCHEMA or e.get("arm") not in ARMS or e["arm"] in by:
            return {"verdict": "ABORT", "reason": "bad_or_duplicate_arm"}
        by[e["arm"]] = e
    if set(by) != set(ARMS):
        return {"verdict": "ABORT", "reason": "missing_arm"}
    if len({e["seed"] for e in by.values()}) != 1 or len({e["derive_hash"] for e in by.values()}) != 1:
        return {"verdict": "ABORT", "reason": "byte_lock_failed"}
    if by["app"]["candidate_package"] == "REGRESS":
        return {"verdict": "REJECT", "reason": "not_valid_successor"}
    return {"verdict": "ACCEPT"}


class Mapping(unittest.TestCase):
    def test_payload_extracted_only_from_valid_rows(self):
        self.assertEqual(sh.arm_envelope_of(row(arm("node"))), arm("node"))
        self.assertIsNone(sh.arm_envelope_of(row(arm("node"), sds="unsigned")))
        self.assertIsNone(sh.arm_envelope_of(row(arm("node"), sds="invalid(forged-sender)")))
        self.assertIsNone(sh.arm_envelope_of(row({"schema": "other"})))
        self.assertIsNone(sh.arm_envelope_of({"sds": "valid", "body": "not json"}))


class EndToEnd(unittest.TestCase):
    def rows(self, **kw):
        return [row(arm(a, **kw.get(a, {})), rid=i + 1, sender=a) for i, a in enumerate(ARMS)]

    def test_accept(self):
        self.assertEqual(sh.decide_rows(self.rows(), decider=fake_decider)["verdict"], "ACCEPT")

    def test_reject_not_successor(self):
        r = [row(arm(a, cand="REGRESS"), rid=i + 1) for i, a in enumerate(ARMS)]
        self.assertEqual(sh.decide_rows(r, decider=fake_decider)["verdict"], "REJECT")

    def test_abort_missing_arm(self):
        self.assertEqual(sh.decide_rows(self.rows()[:2], decider=fake_decider)["verdict"], "ABORT")

    def test_abort_when_one_arm_unsigned(self):
        r = self.rows(); r[2]["sds"] = "unsigned"
        res = sh.decide_rows(r, decider=fake_decider)
        self.assertEqual((res["verdict"], res["reason"]), ("ABORT", "missing_arm"))

    def test_abort_on_derive_disagreement(self):
        r = self.rows(aux={"derive": "h2"})
        self.assertEqual(sh.decide_rows(r, decider=fake_decider)["verdict"], "ABORT")

    def test_no_decider_no_decision(self):
        self.assertIsNone(sh.decide_rows(self.rows(), spec=""))


class RealAdapterOptional(unittest.TestCase):
    """Ha a partner-kar adaptere importálható, a hook-specen át hiányzó karra ABORT-ot ad. Különben tisztán kihagyva."""

    def test_real_adapter_missing_arm_aborts(self):
        root = os.environ.get("SCE_ROOT", "")                           # csak kifejezetten megadott útról
        if root and os.path.isdir(root) and root not in sys.path:
            sys.path.insert(0, root)
        try:
            import importlib
            importlib.import_module("app.sce_bus_adapter")
        except Exception as e:                                               # noqa: BLE001
            self.skipTest("app adapter nem elérhető: %s" % type(e).__name__)
        res = sh.decide_rows([row(arm("node"))], spec="app.sce_bus_adapter:decide")
        self.assertEqual(res["verdict"], "ABORT")


if __name__ == "__main__":
    unittest.main()
