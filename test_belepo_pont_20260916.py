"""A BELÉPŐ PONT: a másik fél exportja FÁJLKÉNT.

A capsule2-oldalon a korpusz-fájlon találtam meg ezt az osztályt (nyers `JSONDecodeError` a `verify_vectors`
belépő pontján), és utána megnéztem, áll-e ugyanez a buszon. Áll, három alakban — és a harmadik a legrosszabb:

    `5` egy sorban       -> AttributeError: 'int' object has no attribute 'get'   (NYERS TRACEBACK)
    `[1,2,3]` egy sorban -> AttributeError: 'list' object has no attribute 'get'  (NYERS TRACEBACK)
    ÜRES fájl            -> rc=0, ZÖLD                                            (NÉMA ZÖLD)

A `read_lines` `type: garbage` sora jó ötlet volt — de csak a JSON-PARSE hibát fedte. Ami JSON-ként érvényes,
de nem OBJEKTUM, az egyenesen a `.get()`-be futott. Az üres fájl pedig nem „hibátlan napló", hanem NULLA
BIZONYÍTÉK: nincs mit ellenőrizni, tehát nincs mit igazolni. Ugyanaz az osztály, mint a hiányzó horgonynál
(`audit_anchor_absent`) és a hiányzó második nyilvántartásnál (`audit_register_absent`) — csak a legkorábbi
ponton, ahol a partner bájtjai egyáltalán kódot érnek.

stdlib unittest.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402


class ReadLinesNeverHandsBackANonRecord(unittest.TestCase):
    def _read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write(text)
            p = f.name
        try:
            return bn.read_lines(p)
        finally:
            os.unlink(p)

    def test_every_returned_record_is_a_dict(self):
        """A ZÁRÓ SZABÁLY: bármit kapunk, a hívó SZÓTÁRAKAT lát — `.get()` sosem száll el."""
        recs = self._read('5\n[1,2,3]\n"szoveg"\ntrue\nnull\nez nem json\n{"type": "entry"}\n')
        self.assertTrue(all(isinstance(r, dict) for r in recs),
                        "nem-szótár jutott ki a beolvasóból: %r" % recs)

    def test_a_scalar_line_is_named_garbage_with_its_type(self):
        recs = self._read("5\n")
        self.assertEqual(recs[0]["type"], "garbage")
        self.assertEqual(recs[0]["parsed_as"], "int")
        self.assertEqual(recs[0]["line"], 1)

    def test_a_json_array_line_is_named_too(self):
        recs = self._read("[1,2,3]\n")
        self.assertEqual(recs[0]["type"], "garbage")
        self.assertEqual(recs[0]["parsed_as"], "list")

    def test_a_non_json_line_keeps_its_old_naming(self):
        recs = self._read("ez nem json\n")
        self.assertEqual(recs[0]["type"], "garbage")
        self.assertNotIn("parsed_as", recs[0], "a PARSE-hiba és a rossz TÍPUS két külön eset")

    def test_the_line_number_survives_blank_lines(self):
        recs = self._read("\n\n5\n")
        self.assertEqual(recs[0]["line"], 3, "a sorszám a FÁJL sorszáma legyen, ne a rekordoké")

    def test_a_bom_does_not_poison_the_first_record(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8-sig") as f:
            f.write('{"type": "entry", "seq": 1}\n')
            p = f.name
        try:
            recs = bn.read_lines(p)
        finally:
            os.unlink(p)
        self.assertEqual(recs[0].get("type"), "entry", "a BOM miatt az első sor szemétnek látszott: %r" % recs)


class AnEmptyLogIsNotAPass(unittest.TestCase):
    def _cli(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write(text)
            p = f.name
        try:
            return subprocess.run([sys.executable, os.path.join(HERE, "bus_notary.py"), "verify", p],
                                  capture_output=True, text=True, timeout=120)
        finally:
            os.unlink(p)

    def test_an_empty_file_is_rejected_not_passed(self):
        r = self._cli("")
        self.assertEqual(r.returncode, 1, "az ÜRES napló zöld bizonyítványt kapott: rc=%s" % r.returncode)
        self.assertIn("NULLA", r.stderr, r.stderr[-300:])

    def test_a_whitespace_only_file_is_the_same_case(self):
        self.assertEqual(self._cli("\n\n   \n").returncode, 1)

    def test_no_input_class_produces_a_traceback(self):
        """A traceback nem diagnózis — a MÁSIK fél exportja megbízhatatlan bemenet."""
        for name, text in (("nem-JSON", "ez nem json\n"),
                           ("félbevágott", '{"type": "entry", "seq": 1, "prev_hash": "aaa'),
                           ("skalár", "5\n"), ("tömb", "[1,2,3]\n"), ("üres", ""),
                           ("csak whitespace", "\n\n \n")):
            r = self._cli(text)
            self.assertNotIn("Traceback", r.stderr, "%s -> nyers traceback: %s" % (name, r.stderr[-300:]))
            self.assertNotEqual(r.returncode, 0, "%s -> a jelentés ZÖLD maradt" % name)


if __name__ == "__main__":
    unittest.main()
