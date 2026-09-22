"""A `signed shape v:2` négy INTEROP-tulajdonsága rögzítve — amiken egy másik kar némán divergálna.

MIÉRT LÉTEZIK EZ A FÁJL. A bájtképet nem csak mi építjük: egy interop-partner a dokumentációból
implementálja újra. Ami a dokumentációban NINCS KIMONDVA, azt mindenki a saját nyelvének
alapértelmezése szerint dönti el — és a nyelvek alapértelmezései eltérnek. Ilyenkor nem hibaüzenet
lesz, hanem érvénytelen aláírás: a sor a feladónál jó, a vevőnél rossz.

Négy ilyen pontot egy idegen családú, független újraimplementáció (saját JS-vektorok, node:crypto)
mért ki. Mind a négy IGAZ a mi fánkon is — ez a fájl ezt méri, nem elhiszi. A doksi §2b ugyanezt
mondja ki normatívan; ha a kettő elválik, az itt bukik el, nem egy partner integrációján.

A rögzítés iránya fontos: ezek NEM kívánságok, hanem a MAI mért viselkedés. Ha valamelyik
megváltozik, az kétkaros döntés legyen, ne egy commit mellékhatása.
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
        """NFC és NFD KÜLÖNBÖZŐ aláírást ad. Aki normalizál, csendes verify-bukást épít."""
        nfc = ab._a2_content_bytes(dict(BASE, body=unicodedata.normalize("NFC", "ő")))
        nfd = ab._a2_content_bytes(dict(BASE, body=unicodedata.normalize("NFD", "ő")))
        self.assertNotEqual(nfc, nfd, "a bájtkép normalizál — ez ELTÉRÉS a kimondott viselkedéstől")

    def test_the_timestamp_is_an_integer_not_a_float(self):
        """A nanoszekundumos ts > 2^53: lebegőpontosan már a TÁROLÁSNÁL elveszik a pontosság.

        A PIN SZÁNDÉKOSAN MOZDULT. Ez a teszt először azt rögzítette, hogy a float `ts` MÁS bájtképet
        ad — igaz volt, de gyenge: a hívó néma, spec-ellenes bájtképet írt alá, és a hiba a partner
        oldalán jött elő. A kanonizáló azóta típus-őr is: a nem-egész `ts` ÉRTHETŐ hibát dob, nem
        bájtképet. Ez szigorúbb, és a spec (§2b: a ts egész) mostantól a kódban is ki van kényszerítve."""
        as_int = ab._a2_content_bytes(dict(BASE, ts=1758265200123456789))
        self.assertIn(b'"ts":1758265200123456789', as_int, "az egész ts nem pontosan íródik ki")
        with self.assertRaises(ValueError):
            ab._a2_content_bytes(dict(BASE, ts=float(1758265200123456789)))
        for bad in (1.5, True, "123", None):
            with self.subTest(ts=bad), self.assertRaises(ValueError):
                ab._a2_content_bytes(dict(BASE, ts=bad))

    def test_the_key_order_is_alphabetical_not_the_field_list_order(self):
        """A mezőlistában a HALMAZ fagyott, nem a sorrend. A szerializálás rendez."""
        import re
        out = ab._a2_content_bytes(BASE).decode("utf-8")
        keys = re.findall(r'"([a-z_]+)":', out)
        self.assertEqual(keys, sorted(keys), "a kulcsok nem alfabetikusak")
        self.assertEqual(keys, ["body", "in_reply_to", "kind", "recipient", "sender", "topic", "ts", "v"])
        self.assertNotEqual(keys, list(ab._A2_SIGNED_FIELDS),
                            "ha a kettő egybeesne, a teszt nem mondana semmit a sorrendről")

    def test_excluded_and_unknown_fields_do_not_change_the_bytes(self):
        """A bájtkép PONTOSAN a nyolc mezőből épül — ezért írhat alá a feladó és ellenőrizhet a vevő
        kissé eltérő alakú rekordból."""
        noisy = dict(BASE, id=42, thread_id="t1", read_at=1, sig="ab" * 64, pubkey="cd" * 32,
                     a_field_nobody_has_defined_yet=[1, 2, 3])
        self.assertEqual(ab._a2_content_bytes(BASE), ab._a2_content_bytes(noisy))

    def test_a_missing_optional_field_falls_to_the_documented_default(self):
        """Ellenpróba: a rögzítés nem arról szól, hogy MINDEN mindegy. A hiányzó opcionálisak
        dokumentált alapértékre esnek, és az MÁS bájtkép, mint egy kitöltött mező."""
        bare = {"sender": "a", "recipient": "b", "ts": BASE["ts"]}
        self.assertIn(b'"topic":""', ab._a2_content_bytes(bare))
        self.assertIn(b'"in_reply_to":null', ab._a2_content_bytes(bare))
        self.assertNotEqual(ab._a2_content_bytes(bare), ab._a2_content_bytes(BASE))


if __name__ == "__main__":
    unittest.main()
