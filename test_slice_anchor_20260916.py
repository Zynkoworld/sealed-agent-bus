"""The START of the slice is a claim too — our own.

`trusted` used to measure the slice's TAIL (one arm: every entry must be covered by a verified
checkpoint). In our own attack round the non-Claude arm hit the other end: an
`export --from-seq 11` slice was internally intact, signed and `trusted:true`, while entries 1..10
were MISSING. The log alone does not show this — the deletion falls before the slice.

The shape of the fix is the same as for today's other items: **silence is not evidence, but not an accusation either**.
The report states where the slice starts (`slice_start_seq`) and whether it is anchored (`anchored`:
it starts from genesis, or the caller gave the `start_prev_hash` known out of band); an unanchored
slice is `trusted:false`, and the CLI refuses it in product mode.

stdlib unittest + cryptography (for the checkpoint signature).
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography required")
class SliceStartIsAlsoAClaim(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "notary.jsonl")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "dev"}, clear=False)
        self.p.start()
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=5)
        for i in range(1, 21):
            n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                     envelope={"i": i}, kind="pickup", decision="accepted", reason="r%d" % i)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── control: the full slice is trusted ─────────────────────────────────
    def test_control_full_slice_is_trusted(self):
        rep = bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)
        self.assertTrue(rep["ok"])
        self.assertTrue(rep["trusted"])
        self.assertEqual(rep["slice_start_seq"], 1)
        self.assertTrue(rep["anchored"])

    # ── control: a row deleted from the MIDDLE of the slice is still caught today ────────────────
    def test_control_deletion_inside_the_slice_is_caught(self):
        lines = [l for l in open(self.log, encoding="utf-8").read().splitlines()
                 if '"reason": "r7"' not in l and '"reason": "r8"' not in l]
        cut = os.path.join(self.tmp.name, "cut.jsonl")
        with open(cut, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        rep = bn.verify(bn.export(cut, 1), trusted_pub=self.pub)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("gap" in e["error"] for e in rep["errors"]))

    # ── FINDING: an unanchored slice starting in the middle cannot be "trusted" ──
    def test_unanchored_slice_is_not_trusted(self):
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub)
        self.assertTrue(rep["ok"], "the slice is internally intact — the chain was not damaged")
        self.assertEqual(rep["slice_start_seq"], 11)
        self.assertFalse(rep["anchored"])
        self.assertFalse(rep["trusted"],
                         "the slice starting at entry 11 looked trusted, although the absence of 1..10 "
                         "does not show in it")

    # ── with the anchor, however, the same slice is trusted ─────────────────────
    def test_anchored_slice_is_trusted_again(self):
        prev = [r for r in bn.export(self.log, 11) if r.get("type") == "entry"][0]["prev_hash"]
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub, start_prev_hash=prev)
        self.assertTrue(rep["anchored"])
        self.assertTrue(rep["trusted"], "with an anchor known out of band a partial slice is trusted too")

    # ── a lying anchor gets caught ─────────────────────────────────────────────
    def test_wrong_anchor_is_rejected(self):
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub, start_prev_hash="0" * 64)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("does not continue" in e["error"] for e in rep["errors"]))

    # ── CLI: in product mode an unanchored slice is refused ─────────────────
    def test_cli_refuses_an_unanchored_slice_in_product_mode(self):
        path = os.path.join(self.tmp.name, "exp.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 11):
                f.write(bn.json.dumps(e, ensure_ascii=False) + "\n")
        args = ["verify", path, "--pub", self.pub]
        self.assertEqual(bn.main(args), 0, "in dev mode a warning, but not an error")
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "product"}, clear=False):
            self.assertEqual(bn.main(args), 3, "in product mode the unanchored slice is refused")
            prev = [r for r in bn.export(self.log, 11) if r.get("type") == "entry"][0]["prev_hash"]
            self.assertEqual(bn.main(args + ["--start-prev-hash", prev]), 0,
                             "with an anchor it is accepted in product mode too")


if __name__ == "__main__":
    unittest.main()
