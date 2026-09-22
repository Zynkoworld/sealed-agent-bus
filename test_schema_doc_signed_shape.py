"""A SCHEMA-doc `signed shape v:2` szakasza a KÓDBÓL van mérve, nem elhíve.

Egy normatív leírás, amit senki nem futtat, ugyanaz a hibaosztály, mint egy kézzel gépelt címke-lista: ma
kétszer esett ki ugyanaz az ok egy ilyenből (egyszer egy kifelé menő dokumentumból, egyszer egy statikus
mérőből). Ezért a doc konformancia-vektorát ÚJRASZÁMOLJUK a szállított kóddal, a mezőlistáját pedig a
`_a2_content_bytes` tényleges kimenetéből vezetjük le — ha a kód mozdul és a doc nem, ez a teszt piros.

Amit külön mér: az egész-szerializálás csapdáját. A `ts` nanoszekundumban 2**53 fölött van, tehát aki a
számokat IEEE-754 double-ön át írja ki (az RFC 8785 JCS szám-szabálya), más bájtképet kap — a doc erre
figyelmeztet, és itt megmérjük, hogy a figyelmeztetés IGAZ, nem óvatoskodás.
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
        self.assertIn(content.decode("utf-8"), doc, "a doc content-sora nem az, amit a kód aláír")
        self.assertIn(hashlib.sha256(content).hexdigest(), doc, "a doc sha256-a elavult")
        self.assertIn("%d bájt" % len(content), doc, "a doc hossz-adata elavult")
        rec = ab._a2_sign(bytes.fromhex(seed_hex), VECTOR)
        self.assertIn(rec["pubkey"], doc, "a doc pubkey-e elavult")
        self.assertIn(rec["sig"], doc, "a doc aláírása elavult")

    def test_the_documented_empty_kind_vector_is_reproduced_by_the_shipped_code(self):
        """A MÁSODIK vektor: az üres `kind`. Ez az a pont, ahol egy újraimplementáció a leggyakrabban
        elválik — és ahol a SAJÁT kliens-aláírónk is elvált, amíg saját normalizálást hordozott.

        A vektor önhordó: a seed, a teljes bemenet, a content, a sha256, a pubkey és az aláírás mind a
        doksiban áll. Egy hash a BEMENETE NÉLKÜL nem ellenőrzés — ezt a leckét magamon mértem: a lelet
        hashét először saját mezőértékekkel próbáltam reprodukálni, nem egyezett, és majdnem eltérésnek
        jelentettem, holott a hash jó volt, csak a bemenet volt más."""
        doc = doc_text()
        seed_hex = re.search(r"seed\s*=\s*([0-9a-f]{64})", doc).group(1)
        vec = dict(VECTOR, kind="")
        content = ab._a2_content_bytes(vec)
        self.assertIn(content.decode("utf-8"), doc, "a doc üres-kind content-sora nem az, amit a kód aláír")
        self.assertIn(hashlib.sha256(content).hexdigest(), doc, "a doc üres-kind sha256-a elavult")
        rec = ab._a2_sign(bytes.fromhex(seed_hex), vec)
        self.assertIn(rec["sig"], doc, "a doc üres-kind aláírása elavult")

    def test_an_absent_or_null_kind_gives_the_same_bytes_as_an_empty_one(self):
        """A doksi ezt állítja; itt mérve. Ha a három alak elválik, egy partner aláírása némán bukik."""
        empty = ab._a2_content_bytes(dict(VECTOR, kind=""))
        absent = dict(VECTOR); del absent["kind"]
        self.assertEqual(ab._a2_content_bytes(absent), empty, "az elhagyott kind más bájtképet ad")
        self.assertEqual(ab._a2_content_bytes(dict(VECTOR, kind=None)), empty, "a null kind más bájtképet ad")

    def test_the_documented_field_list_is_the_one_the_code_signs(self):
        """A táblázat mezőnevei a kód TÉNYLEGES kimenetéből, nem olvasásból."""
        signed = json.loads(ab._a2_content_bytes(VECTOR).decode("utf-8"))
        doc = doc_text()
        section = doc[doc.index("## 2b."):doc.index("## 3. ")]
        for name in signed:
            self.assertIn("`%s`" % name, section, "a doc nem sorolja fel az aláírt mezőt: %s" % name)
        for excluded in ("id", "thread_id"):
            self.assertNotIn(excluded, signed, "a kód ALÁÍRJA, amit a doc kizártnak mond: %s" % excluded)
            self.assertIn("`%s`" % excluded, section, "a doc nem mondja ki a kizárást: %s" % excluded)
        self.assertEqual(signed["v"], 2, "a signed-shape verzió elmozdult a doc alól")

    def test_the_optional_fields_fall_back_the_way_the_doc_states(self):
        bare = json.loads(ab._a2_content_bytes({"sender": "a", "recipient": "b", "ts": 1}).decode("utf-8"))
        self.assertEqual(bare["topic"], "")
        self.assertEqual(bare["kind"], "")
        self.assertEqual(bare["body"], "")
        self.assertIsNone(bare["in_reply_to"])

    def test_the_integer_trap_the_doc_warns_about_is_real(self):
        """A figyelmeztetés mérve: a double-úton kiírt ts MÁS bájtképet ad."""
        ts = VECTOR["ts"]
        self.assertGreater(ts, 2 ** 53, "a vektor ts-e már nem esik a csapda-tartományba — nézd át a doc szövegét")
        self.assertNotEqual(int(float(ts)), ts, "a double-oda-vissza nem veszít — a figyelmeztetés félrevezető volna")
        exact = ab._a2_content_bytes(VECTOR)
        via_double = ab._a2_content_bytes(dict(VECTOR, ts=int(float(ts))))
        self.assertNotEqual(exact, via_double)
        self.assertEqual(len(exact), len(via_double),
                         "a doc azt állítja, hogy a csapda a HOSSZAT nem változtatja — ez az állítás dőlt meg")

    def test_the_verdict_vocabulary_in_the_doc_is_the_one_the_code_returns(self):
        section = doc_text()
        got = set(re.findall(r'return "(signed|unsigned|unsigned-pinned|forged)"',
                             open(os.path.join(HERE, "agent_bus.py"), encoding="utf-8").read()))
        self.assertEqual(got, {"signed", "unsigned", "unsigned-pinned", "forged"},
                         "a verify_sender verdikt-halmaza elmozdult")
        for verdict in sorted(got):
            self.assertIn("`%s`" % verdict, section, "a doc nem sorolja fel a verdiktet: %s" % verdict)


if __name__ == "__main__":
    unittest.main()
