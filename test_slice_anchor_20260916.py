"""A szelet ELEJE is állítás — saját.

A `trusted` eddig a szelet FARKÁT mérte (az egyik kar minden bejegyzést fedjen ellenőrzött
ellenőrzőpont). A saját támadókörben a nem-Claude kar a másik végét találta el: egy
`export --from-seq 11` szelet belsőleg ép, aláírt és `trusted:true` volt, miközben az 1..10
bejegyzés HIÁNYZOTT. A napló önmagában ezt nem mutatja — a törlés a szelet elé esik.

A javítás alakja ugyanaz, mint a többi mai tételnél: **a hallgatás nem bizonyíték, de nem is vád**.
A jelentés kimondja, hol kezdődik a szelet (`slice_start_seq`) és hogy horgonyzott-e (`anchored`:
genesis-től indul, vagy a hívó megadta a csatornán kívül ismert `start_prev_hash`-t); horgonytalan
szelet `trusted:false`, a CLI termék-módban megtagadja.

stdlib unittest + cryptography (az ellenőrzőpont-aláíráshoz).
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography szükséges")
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

    # ── kontroll: a teljes szelet megbízható ─────────────────────────────────
    def test_control_full_slice_is_trusted(self):
        rep = bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)
        self.assertTrue(rep["ok"])
        self.assertTrue(rep["trusted"])
        self.assertEqual(rep["slice_start_seq"], 1)
        self.assertTrue(rep["anchored"])

    # ── kontroll: a szelet KÖZEPÉBŐL törölt sor ma is lebukik ────────────────
    def test_control_deletion_inside_the_slice_is_caught(self):
        lines = [l for l in open(self.log, encoding="utf-8").read().splitlines()
                 if '"reason": "r7"' not in l and '"reason": "r8"' not in l]
        cut = os.path.join(self.tmp.name, "cut.jsonl")
        with open(cut, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        rep = bn.verify(bn.export(cut, 1), trusted_pub=self.pub)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("gap" in e["error"] for e in rep["errors"]))

    # ── LELET: horgony nélküli, közepén kezdődő szelet nem lehet „megbízható" ──
    def test_unanchored_slice_is_not_trusted(self):
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub)
        self.assertTrue(rep["ok"], "a szelet belsőleg ép — a lánc nem sérült")
        self.assertEqual(rep["slice_start_seq"], 11)
        self.assertFalse(rep["anchored"])
        self.assertFalse(rep["trusted"],
                         "a 11. bejegyzéstől induló szelet megbízhatónak látszott, pedig az 1..10 hiánya "
                         "belőle nem látszik")

    # ── a horgonnyal ugyanaz a szelet viszont megbízható ─────────────────────
    def test_anchored_slice_is_trusted_again(self):
        prev = [r for r in bn.export(self.log, 11) if r.get("type") == "entry"][0]["prev_hash"]
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub, start_prev_hash=prev)
        self.assertTrue(rep["anchored"])
        self.assertTrue(rep["trusted"], "a csatornán kívül ismert horgonnyal a részszelet is megbízható")

    # ── a hazug horgony lebukik ─────────────────────────────────────────────
    def test_wrong_anchor_is_rejected(self):
        rep = bn.verify(bn.export(self.log, 11), trusted_pub=self.pub, start_prev_hash="0" * 64)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("does not continue" in e["error"] for e in rep["errors"]))

    # ── CLI: termék-módban a horgonytalan szelet megtagadva ─────────────────
    def test_cli_refuses_an_unanchored_slice_in_product_mode(self):
        path = os.path.join(self.tmp.name, "exp.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 11):
                f.write(bn.json.dumps(e, ensure_ascii=False) + "\n")
        args = ["verify", path, "--pub", self.pub]
        self.assertEqual(bn.main(args), 0, "dev-módban figyelmeztetés, de nem hiba")
        with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "product"}, clear=False):
            self.assertEqual(bn.main(args), 3, "termék-módban a horgonytalan szelet megtagadva")
            prev = [r for r in bn.export(self.log, 11) if r.get("type") == "entry"][0]["prev_hash"]
            self.assertEqual(bn.main(args + ["--start-prev-hash", prev]), 0,
                             "horgonnyal termék-módban is elfogadott")


if __name__ == "__main__":
    unittest.main()
