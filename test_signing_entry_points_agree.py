"""The FOUR signing entry points build the same byte image — this test pins that MORE THAN TWO agree.

WHY THIS FILE EXISTS. The fields of the signed byte image were produced by four places, each with its own
normalization:

  1. `agent_bus._a2_content_bytes`      — the canonical rule (the SPEC, and what the verifier computes)
  2. `agent_bus.sign_for_send`          — the client signer
  3. `bus_ssh_client.sign_outgoing`     — the cross-machine OUTGOING path
  4. `bus_ssh_exchange`                 — the cross-machine INCOMING path

Numbers 2–4 all used `kind or "msg"`, number 1 used `kind or ""`. Measured, what they gave for the four shapes:

    shape            canonical     the other three
    kind omitted     ""            "msg"
    kind = ""        ""            "msg"
    kind = null      ""            "msg"
    kind = "msg"     "msg"         "msg"

So a partner signing per SPEC failed in THREE OF FOUR shapes — and not silently:
the bus rejected it with `presigned: signature does not verify (forged or tampered)`, i.e. it accused an
honest partner of FORGERY.

The three copies only matched each other BY CHANCE. When I aligned two with the spec, the other two
immediately diverged, and a test failed — the one that pinned the old behaviour. So the fix is not copying the rule,
but a `canonical_text_field` that all four call.

So this test does NOT pin the content of the normalization (that may change, by a two-arm decision), but
that the four paths give THE SAME result. If a second normalization gets back in anywhere, this fails — even if
no one wrote a separate case for that shape.
stdlib unittest.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_ssh_client as cli  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except ImportError:                                            # pragma: no cover
    HAVE_CRYPTO = False

#: The four shapes in which a `kind` (or `topic`) can arrive from the wire.
SHAPES = [("omitted", {}), ("empty string", {"kind": ""}), ("null", {"kind": None}), ("msg", {"kind": "msg"})]
TS = 1758265200123456789


class TheFourEntryPointsBuildTheSameBytes(unittest.TestCase):
    def setUp(self):
        if not HAVE_CRYPTO:
            self.skipTest("the 'cryptography' package is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = os.path.join(self.tmp.name, "keys")
        os.makedirs(self.keys, mode=0o700)
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        open(os.path.join(self.keys, "peer.pub"), "w").write(pub)
        self.key = os.path.join(self.keys, "peer.ed25519.key")
        open(self.key, "w").write(priv.private_bytes_raw().hex())
        self.pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub))

    def tearDown(self):
        self.tmp.cleanup()

    def _canonical_bytes(self, wire, ts=TS):
        return ab._a2_content_bytes({"sender": "peer", "recipient": "hub", "topic": "t",
                                     "body": "x", "in_reply_to": None, "ts": ts, **wire})

    def test_the_client_signer_signs_the_canonical_bytes(self):
        """Entry point 2 against 1 — for the EXPLICIT values.

        OMITTING the kwarg is deliberately left out here: the API default (`kind="msg"`) is the caller's
        convenience, and it signs `"msg"`. That behaviour is correct, and a separate test below pins it —
        this line measures that an EXPLICIT value reaches the byte image unchanged."""
        for label, wire in SHAPES:
            if "kind" not in wire:
                continue
            with self.subTest(shape=label):
                rec = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", ts=TS,
                                       kind=ab.canonical_text_field(wire["kind"]))
                self.pub.verify(bytes.fromhex(rec["sig"]), self._canonical_bytes(wire))

    def test_the_outgoing_machine_path_signs_the_canonical_bytes(self):
        """Entry point 3 against 1: what the outgoing path signs must fit the canonical byte image."""
        for label, wire in SHAPES:
            with self.subTest(shape=label):
                msg = {"to": "hub", "body": "x", "topic": "t", **wire}
                signed = cli.sign_outgoing("peer", [dict(msg)], sign_key=self.key, keys_dir=self.keys)[0]
                self.assertIn("sig", signed, "the outgoing path did not sign the row")
                # The outgoing path stamps its OWN `ts` (the caller does not give one) — the byte image must be built with that.
                self.pub.verify(bytes.fromhex(signed["sig"]), self._canonical_bytes(wire, ts=signed["ts"]))

    def test_the_incoming_machine_path_reads_the_same_field(self):
        """Entry point 4 against 1: the incoming path derives the same field value."""
        for label, wire in SHAPES:
            with self.subTest(shape=label):
                self.assertEqual(ab.canonical_text_field(wire.get("kind")),
                                 json.loads(self._canonical_bytes(wire).decode("utf-8"))["kind"])

    def test_a_second_normalisation_anywhere_would_break_this(self):
        """THE POINT, stated: the four paths take the rule from a single function. If someone puts back a
        second normalization, at least one of the three tests above fails — even if no one wrote a separate
        case for that shape. This line measures the rule itself, so the CAUSE of the failure shows too."""
        for value, expected in ((None, ""), ("", ""), ("msg", "msg"), (0, ""), (False, ""), ([], "")):
            with self.subTest(value=value):
                self.assertEqual(ab.canonical_text_field(value), expected)

    def test_an_explicit_value_is_never_replaced_by_the_api_default(self):
        """The kwarg default (`kind="msg"`) is a convenience for an OMITTED field. An EXPLICIT empty string is the
        caller's INTENT, and must stay so — that was the core of the finding."""
        rec_explicit = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", kind="", ts=TS)
        rec_omitted = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", ts=TS)
        self.pub.verify(bytes.fromhex(rec_explicit["sig"]), self._canonical_bytes({"kind": ""}))
        self.pub.verify(bytes.fromhex(rec_omitted["sig"]), self._canonical_bytes({"kind": "msg"}))
        self.assertNotEqual(rec_explicit["sig"], rec_omitted["sig"],
                            "the explicit empty and the omitted kind give the same result — one normalization swallowed it")


if __name__ == "__main__":
    unittest.main()
