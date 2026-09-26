"""The SCHEMA doc's `signed shape v:2` section is measured FROM THE CODE, not believed.

A normative description no one runs is the same class of error as a hand-typed label list: today
the same reason dropped out of one of these twice (once from an outbound document, once from a static
meter). So we RECOMPUTE the doc's conformance vector with the shipped code, and derive its field list from the
actual output of `_a2_content_bytes` — if the code moves and the doc does not, this test is red.

What it measures separately: the integer-serialization trap. `ts` in nanoseconds is above 2**53, so whoever writes the
numbers through an IEEE-754 double (the RFC 8785 JCS number rule) gets a different byte image — the doc warns
about this, and here we measure that the warning is TRUE, not overcaution.
stdlib unittest."""
import hashlib
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(HERE, "docs", "AGENT_BUS_SCHEMA.md")
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402

VECTOR = {"sender": "alpha", "recipient": "beta", "topic": "agentbus.rollout", "kind": "msg",
          "in_reply_to": None, "body": "árvíztűrő", "ts": 1789803064437527544}


def doc_text():
    return open(DOC, encoding="utf-8").read()


class SignedShapeDoc(unittest.TestCase):
    def test_the_documented_vector_is_reproduced_by_the_shipped_code(self):
        doc = doc_text()
        seed_hex = re.search(r"seed\s*=\s*([0-9a-f]{64})", doc).group(1)
        content = ab._a2_content_bytes(VECTOR)
        self.assertIn(content.decode("utf-8"), doc, "the doc's content line is not what the code signs")
        self.assertIn(hashlib.sha256(content).hexdigest(), doc, "the doc's sha256 is stale")
        self.assertIn("%d bytes" % len(content), doc, "the doc's length figure is stale")
        rec = ab._a2_sign(bytes.fromhex(seed_hex), VECTOR)
        self.assertIn(rec["pubkey"], doc, "the doc's pubkey is stale")
        self.assertIn(rec["sig"], doc, "the doc's signature is stale")

    def test_the_documented_empty_kind_vector_is_reproduced_by_the_shipped_code(self):
        """The SECOND vector: the empty `kind`. This is the point where a reimplementation most often
        diverges — and where OUR OWN client signer diverged too, while it carried its own normalization.

        The vector is self-contained: the seed, the full input, the content, the sha256, the pubkey and the signature are all in the
        doc. A hash WITHOUT ITS INPUT is not a check — I measured this lesson on myself: I first tried to reproduce the finding's
        hash with my own field values, it did not match, and I nearly reported it as a discrepancy,
        although the hash was right, only the input was different."""
        doc = doc_text()
        seed_hex = re.search(r"seed\s*=\s*([0-9a-f]{64})", doc).group(1)
        vec = dict(VECTOR, kind="")
        content = ab._a2_content_bytes(vec)
        self.assertIn(content.decode("utf-8"), doc, "the doc's empty-kind content line is not what the code signs")
        self.assertIn(hashlib.sha256(content).hexdigest(), doc, "the doc's empty-kind sha256 is stale")
        rec = ab._a2_sign(bytes.fromhex(seed_hex), vec)
        self.assertIn(rec["sig"], doc, "the doc's empty-kind signature is stale")

    def test_an_absent_or_null_kind_gives_the_same_bytes_as_an_empty_one(self):
        """The doc claims this; measured here. If the three shapes diverge, a partner's signature fails silently."""
        empty = ab._a2_content_bytes(dict(VECTOR, kind=""))
        absent = dict(VECTOR); del absent["kind"]
        self.assertEqual(ab._a2_content_bytes(absent), empty, "an omitted kind gives a different byte image")
        self.assertEqual(ab._a2_content_bytes(dict(VECTOR, kind=None)), empty, "a null kind gives a different byte image")

    def test_the_documented_field_list_is_the_one_the_code_signs(self):
        """The table's field names from the code's ACTUAL output, not from reading."""
        signed = json.loads(ab._a2_content_bytes(VECTOR).decode("utf-8"))
        doc = doc_text()
        section = doc[doc.index("## 2b."):doc.index("## 3. ")]
        for name in signed:
            self.assertIn("`%s`" % name, section, "the doc does not list the signed field: %s" % name)
        for excluded in ("id", "thread_id"):
            self.assertNotIn(excluded, signed, "the code SIGNS what the doc calls excluded: %s" % excluded)
            self.assertIn("`%s`" % excluded, section, "the doc does not state the exclusion: %s" % excluded)
        self.assertEqual(signed["v"], 2, "the signed-shape version moved out from under the doc")

    def test_the_optional_fields_fall_back_the_way_the_doc_states(self):
        bare = json.loads(ab._a2_content_bytes({"sender": "a", "recipient": "b", "ts": 1}).decode("utf-8"))
        self.assertEqual(bare["topic"], "")
        self.assertEqual(bare["kind"], "")
        self.assertEqual(bare["body"], "")
        self.assertIsNone(bare["in_reply_to"])

    def test_the_integer_trap_the_doc_warns_about_is_real(self):
        """The warning measured: a ts written via a double gives a DIFFERENT byte image."""
        ts = VECTOR["ts"]
        self.assertGreater(ts, 2 ** 53, "the vector's ts no longer falls into the trap range — review the doc text")
        self.assertNotEqual(int(float(ts)), ts, "the double round trip loses nothing — the warning would be misleading")
        exact = ab._a2_content_bytes(VECTOR)
        via_double = ab._a2_content_bytes(dict(VECTOR, ts=int(float(ts))))
        self.assertNotEqual(exact, via_double)
        self.assertEqual(len(exact), len(via_double),
                         "the doc claims the trap does NOT change the LENGTH — that claim has fallen")

    def test_the_verdict_vocabulary_in_the_doc_is_the_one_the_code_returns(self):
        section = doc_text()
        got = set(re.findall(r'return "(signed|unsigned|unsigned-pinned|forged)"',
                             open(os.path.join(HERE, "agent_bus.py"), encoding="utf-8").read()))
        self.assertEqual(got, {"signed", "unsigned", "unsigned-pinned", "forged"},
                         "a verify_sender verdikt-halmaza elmozdult")
        for verdict in sorted(got):
            self.assertIn("`%s`" % verdict, section, "the doc does not list the verdict: %s" % verdict)


if __name__ == "__main__":
    unittest.main()
