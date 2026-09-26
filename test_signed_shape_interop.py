"""The four INTEROP properties of `signed shape v:2` pinned — where another arm would silently diverge.

WHY THIS FILE EXISTS. We are not the only ones building the byte image: an interop partner reimplements it from the
documentation. Whatever is NOT STATED in the documentation, everyone decides by their own language's
default — and the languages' defaults differ. Then the result is not an error message
but an invalid signature: the row is fine at the sender and wrong at the receiver.

Four such points were measured by an independent reimplementation from a foreign family (its own JS vectors, node:crypto).
All four are TRUE on our tree too — this file measures that, it does not believe it. The doc's §2b states the same
normatively; if the two diverge, it fails here, not on a partner's integration.

The direction of the pinning matters: these are NOT wishes, but TODAY's measured behaviour. If any of them
changes, that should be a two-arm decision, not a side effect of a commit.
stdlib unittest.
"""
import os
import sys
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402

BASE = {"v": 2, "sender": "a", "recipient": "b", "topic": "t", "kind": "msg",
        "in_reply_to": None, "body": "x", "ts": 1758265200123456789}


class SignedShapeInterop(unittest.TestCase):
    def test_no_unicode_normalisation_happens(self):
        """NFC and NFD give DIFFERENT signatures. Whoever normalizes builds a silent verify failure."""
        nfc = ab._a2_content_bytes(dict(BASE, body=unicodedata.normalize("NFC", "ő")))
        nfd = ab._a2_content_bytes(dict(BASE, body=unicodedata.normalize("NFD", "ő")))
        self.assertNotEqual(nfc, nfd, "the byte image normalizes — that is a DEVIATION from the stated behaviour")

    def test_the_timestamp_is_an_integer_not_a_float(self):
        """The nanosecond ts > 2^53: as floating point, precision is lost already at STORAGE.

        THE PIN MOVED DELIBERATELY. This test first pinned that a float `ts` gives a DIFFERENT byte image
        — true, but weak: the caller signed a silent, spec-violating byte image, and the error surfaced on the partner's
        side. The canonicalizer has since become a type guard too: a non-integer `ts` raises a CLEAR error, not a
        byte image. This is stricter, and the spec (§2b: ts is an integer) is now enforced in the code too."""
        as_int = ab._a2_content_bytes(dict(BASE, ts=1758265200123456789))
        self.assertIn(b'"ts":1758265200123456789', as_int, "the integer ts is not written exactly")
        with self.assertRaises(ValueError):
            ab._a2_content_bytes(dict(BASE, ts=float(1758265200123456789)))
        for bad in (1.5, True, "123", None):
            with self.subTest(ts=bad), self.assertRaises(ValueError):
                ab._a2_content_bytes(dict(BASE, ts=bad))

    def test_the_key_order_is_alphabetical_not_the_field_list_order(self):
        """In the field list the SET is frozen, not the order. Serialization sorts."""
        import re
        out = ab._a2_content_bytes(BASE).decode("utf-8")
        keys = re.findall(r'"([a-z_]+)":', out)
        self.assertEqual(keys, sorted(keys), "the keys are not alphabetical")
        self.assertEqual(keys, ["body", "in_reply_to", "kind", "recipient", "sender", "topic", "ts", "v"])
        self.assertNotEqual(keys, list(ab._A2_SIGNED_FIELDS),
                            "if the two coincided, the test would say nothing about the order")

    def test_excluded_and_unknown_fields_do_not_change_the_bytes(self):
        """The byte image is built from EXACTLY the eight fields — that is why the sender can sign and the receiver can verify
        from a slightly differently shaped record."""
        noisy = dict(BASE, id=42, thread_id="t1", read_at=1, sig="ab" * 64, pubkey="cd" * 32,
                     a_field_nobody_has_defined_yet=[1, 2, 3])
        self.assertEqual(ab._a2_content_bytes(BASE), ab._a2_content_bytes(noisy))

    def test_a_missing_optional_field_falls_to_the_documented_default(self):
        """Counter-check: the pinning is not about EVERYTHING being irrelevant. Missing optional fields
        fall to a documented default, and that is a DIFFERENT byte image from a filled-in field."""
        bare = {"sender": "a", "recipient": "b", "ts": BASE["ts"]}
        self.assertIn(b'"topic":""', ab._a2_content_bytes(bare))
        self.assertIn(b'"in_reply_to":null', ab._a2_content_bytes(bare))
        self.assertNotEqual(ab._a2_content_bytes(bare), ab._a2_content_bytes(BASE))


if __name__ == "__main__":
    unittest.main()
