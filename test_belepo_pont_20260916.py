"""THE ENTRY POINT: the other party's export AS A FILE.

On the capsule2 side I found this class on the corpus file (a raw `JSONDecodeError` at the `verify_vectors`
entry point), and then checked whether the same holds on the bus. It does, in three shapes — and the third is the worst:

    `5` on one line       -> AttributeError: 'int' object has no attribute 'get'   (RAW TRACEBACK)
    `[1,2,3]` on one line -> AttributeError: 'list' object has no attribute 'get'  (RAW TRACEBACK)
    EMPTY file            -> rc=0, GREEN                                            (SILENT GREEN)

The `type: garbage` line of `read_lines` was a good idea — but it covered only the JSON-PARSE error. What is valid as JSON
but not an OBJECT ran straight into `.get()`. And the empty file is not a "clean log", but ZERO
EVIDENCE: there is nothing to check, so nothing to attest. The same class as the missing anchor
(`audit_anchor_absent`) and the missing second record (`audit_register_absent`) — just at the earliest
point, where the partner's bytes reach code at all.

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
        """THE CLOSING RULE: whatever we get, the caller sees DICTS — `.get()` never blows up."""
        recs = self._read('5\n[1,2,3]\n"text"\ntrue\nnull\nthis is not json\n{"type": "entry"}\n')
        self.assertTrue(all(isinstance(r, dict) for r in recs),
                        "a non-dict got out of the reader: %r" % recs)

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
        recs = self._read("this is not json\n")
        self.assertEqual(recs[0]["type"], "garbage")
        self.assertNotIn("parsed_as", recs[0], "a PARSE error and a wrong TYPE are two separate cases")

    def test_the_line_number_survives_blank_lines(self):
        recs = self._read("\n\n5\n")
        self.assertEqual(recs[0]["line"], 3, "the line number must be the FILE's line number, not the records'")

    def test_a_bom_does_not_poison_the_first_record(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8-sig") as f:
            f.write('{"type": "entry", "seq": 1}\n')
            p = f.name
        try:
            recs = bn.read_lines(p)
        finally:
            os.unlink(p)
        self.assertEqual(recs[0].get("type"), "entry", "because of the BOM the first line looked like garbage: %r" % recs)


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
        self.assertEqual(r.returncode, 1, "the EMPTY log got a green certificate: rc=%s" % r.returncode)
        self.assertIn("ZERO", r.stderr, r.stderr[-300:])

    def test_a_whitespace_only_file_is_the_same_case(self):
        self.assertEqual(self._cli("\n\n   \n").returncode, 1)

    def test_no_input_class_produces_a_traceback(self):
        """A traceback is not a diagnosis — the OTHER party's export is untrusted input."""
        for name, text in (("non-JSON", "this is not json\n"),
                           ("truncated", '{"type": "entry", "seq": 1, "prev_hash": "aaa'),
                           ("scalar", "5\n"), ("array", "[1,2,3]\n"), ("empty", ""),
                           ("whitespace only", "\n\n \n")):
            r = self._cli(text)
            self.assertNotIn("Traceback", r.stderr, "%s -> raw traceback: %s" % (name, r.stderr[-300:]))
            self.assertNotEqual(r.returncode, 0, "%s -> the report stayed GREEN" % name)


if __name__ == "__main__":
    unittest.main()
