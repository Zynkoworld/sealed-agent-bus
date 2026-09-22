"""A NÉGY aláírási belépési pont ugyanazt a bájtképet építi — ez a teszt a KETTŐNÉL TÖBB EGYEZÉSÉT köti.

MIÉRT LÉTEZIK EZ A FÁJL. Az aláírt bájtkép mezőit négy hely állította elő, mindegyik a saját
normalizálásával:

  1. `agent_bus._a2_content_bytes`      — a kanonikus szabály (a SPEC, és amit a verifikáló számol)
  2. `agent_bus.sign_for_send`          — a kliens-aláíró
  3. `bus_ssh_client.sign_outgoing`     — a gépek közti KIMENŐ út
  4. `bus_ssh_exchange`                 — a gépek közti BEJÖVŐ út

A 2–4. mind `kind or "msg"`-ot használt, az 1. `kind or ""`-t. Mérve, mit adott a négy alakra:

    alak             kanonikus     a másik három
    kind elhagyva    ""            "msg"
    kind = ""        ""            "msg"
    kind = null      ""            "msg"
    kind = "msg"     "msg"         "msg"

Vagyis egy SPEC szerint számoló partner aláírása NÉGYBŐL HÁROM alakban megbukott — és nem csendben:
a busz `presigned: signature does not verify (forged or tampered)`-rel utasította el, tehát egy
tisztességes partnert HAMISÍTÁSSAL vádolt meg.

A három másolat csak VÉLETLENÜL egyezett egymással. Amikor kettőt a specre igazítottam, a másik kettő
azonnal elvált, és egy teszt bukott — az, amelyik a régi viselkedést rögzítette. Ezért nem a szabály
átmásolása a javítás, hanem egy `canonical_text_field`, amit mind a négy hív.

Ez a teszt ezért NEM a normalizálás tartalmát rögzíti (az változhat, kétkaros döntéssel), hanem azt,
hogy a négy út UGYANAZT adja. Ha bárhová visszakerül egy második normalizálás, ez bukik — akkor is, ha
arra az alakra senki nem írt külön esetet.
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

#: A négy alak, amiben egy `kind` (vagy `topic`) megérkezhet a drótról.
SHAPES = [("elhagyva", {}), ("ures string", {"kind": ""}), ("null", {"kind": None}), ("msg", {"kind": "msg"})]
TS = 1758265200123456789


class TheFourEntryPointsBuildTheSameBytes(unittest.TestCase):
    def setUp(self):
        if not HAVE_CRYPTO:
            self.skipTest("a 'cryptography' csomag nincs telepítve")
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
        """2. belépési pont a 1. ellen — az EXPLICIT értékekre.

        A kwarg ELHAGYÁSA itt szándékosan kimarad: az API-alapértelmezés (`kind="msg"`) a hívó
        kényelme, és az `"msg"`-ot ír alá. Az a viselkedés helyes, és külön teszt köti lejjebb —
        ez a sor azt méri, hogy egy EXPLICIT érték változatlanul jut el a bájtképig."""
        for label, wire in SHAPES:
            if "kind" not in wire:
                continue
            with self.subTest(shape=label):
                rec = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", ts=TS,
                                       kind=ab.canonical_text_field(wire["kind"]))
                self.pub.verify(bytes.fromhex(rec["sig"]), self._canonical_bytes(wire))

    def test_the_outgoing_machine_path_signs_the_canonical_bytes(self):
        """3. belépési pont a 1. ellen: amit a kimenő út aláír, a kanonikus bájtképre kell illenie."""
        for label, wire in SHAPES:
            with self.subTest(shape=label):
                msg = {"to": "hub", "body": "x", "topic": "t", **wire}
                signed = cli.sign_outgoing("peer", [dict(msg)], sign_key=self.key, keys_dir=self.keys)[0]
                self.assertIn("sig", signed, "a kimenő út nem írta alá a sort")
                # A kimenő út SAJÁT `ts`-t bélyegez (a hívó nem adja meg) — a bájtképet azzal kell építeni.
                self.pub.verify(bytes.fromhex(signed["sig"]), self._canonical_bytes(wire, ts=signed["ts"]))

    def test_the_incoming_machine_path_reads_the_same_field(self):
        """4. belépési pont a 1. ellen: a bejövő út ugyanazt a mezőértéket származtatja."""
        for label, wire in SHAPES:
            with self.subTest(shape=label):
                self.assertEqual(ab.canonical_text_field(wire.get("kind")),
                                 json.loads(self._canonical_bytes(wire).decode("utf-8"))["kind"])

    def test_a_second_normalisation_anywhere_would_break_this(self):
        """A LÉNYEG, kimondva: a négy út egyetlen függvényből veszi a szabályt. Ha valaki visszatesz egy
        második normalizálást, a fenti három teszt közül legalább egy bukik — akkor is, ha arra az alakra
        nem írt senki külön esetet. Ez a sor magát a szabályt méri, hogy a hiba OKA is látszódjon."""
        for value, expected in ((None, ""), ("", ""), ("msg", "msg"), (0, ""), (False, ""), ([], "")):
            with self.subTest(value=value):
                self.assertEqual(ab.canonical_text_field(value), expected)

    def test_an_explicit_value_is_never_replaced_by_the_api_default(self):
        """A kwarg-alapértelmezés (`kind="msg"`) az ELHAGYOTT mező kényelme. Az EXPLICIT üres string a
        hívó SZÁNDÉKA, és annak kell maradnia — ez volt a lelet magja."""
        rec_explicit = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", kind="", ts=TS)
        rec_omitted = ab.sign_for_send(self.key, "peer", "hub", "x", topic="t", ts=TS)
        self.pub.verify(bytes.fromhex(rec_explicit["sig"]), self._canonical_bytes({"kind": ""}))
        self.pub.verify(bytes.fromhex(rec_omitted["sig"]), self._canonical_bytes({"kind": "msg"}))
        self.assertNotEqual(rec_explicit["sig"], rec_omitted["sig"],
                            "az explicit üres és az elhagyott kind ugyanazt adja — az egyik normalizálás elnyelte")


if __name__ == "__main__":
    unittest.main()
