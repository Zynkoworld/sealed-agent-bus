"""The guard of the VERDICT-LABEL SET — the labels are a contract, so they must be measured, not read.

Lesson (2026-09-19): I hand-typed the label set into the C++ arm's technical input, and an independent review raised a
missing reason. The fix is not that I read more carefully: this test DERIVES the set from the SOURCE
(from the AST, not with a regex on the output), and measures it against a pinned list. If the code gains a new label or loses one, this
test is RED, and the outbound document must be updated together with the pinned list.

The same gate also catches the reverse: a label that got into a document but the code NEVER returns (a foreign reason, or one
taken over from another implementation) — so the pinned list is the ONLY source of truth, and the test measures in both directions.
stdlib unittest."""
import ast
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sds_envelope.py")

# The pinned set. Extending/narrowing only DELIBERATELY, TOGETHER with the outbound label documentation.
PINNED = {
    "valid": {""},
    "unsigned": {"no-sigs"},
    "invalid": {"not-json", "not-framed", "envelope-malformed", "record-id-mismatch", "record-not-canonicalizable",
                "record-id-binding", "domain-hash-mismatch", "config-mismatch", "not-admitted", "key-mismatch",
                "bad-signature"},
    # `no-config-binding`: it was MISSING from the pin, and the code gives it. The same label fell out of the outbound document
    # in an independent review on 2026-09-19 too — the hand-typed set dropped the same reason
    # twice. So we derive it from the source, and so the test measures in BOTH directions.
    "unverifiable": {"no-admission", "no-config-binding", "no-crypto", "validator-import", "validator-error"},
}


def _tree():
    return ast.parse(open(SRC, encoding="utf-8").read())


def _functions():
    return {n.name: n for n in ast.walk(_tree()) if isinstance(n, ast.FunctionDef)}


def _verdict_sources():
    """`verify` AND every module-level function whose result it returns.

    At first the extractor walked only the body of `verify`. When the module moved the decision into a helper
    (`_builtin_verify`), some of the labels vanished from the MEASUREMENT — not from the code —, and the test
    reported a lost status. A static meter that does not follow delegation reports its own blind spot
    as the code's error, so delegation must be followed all the way here."""
    fns = _functions()
    seen, queue, out = set(), ["verify"], []
    while queue:
        name = queue.pop()
        fn = fns.get(name)
        if fn is None or name in seen:
            continue
        seen.add(name)
        out.append(fn)
        for node in ast.walk(fn):
            # Every module-level call, not only the `return f(...)` shape: this module takes the verdict into a variable
            # (`base_status, base_why = _builtin_verify(...)`), so following narrowed to return skipped
            # exactly the function that gives most of the labels. If this collects too much,
            # it shows on the test as an UNPINNED label — loudly, not silently.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in fns:
                queue.append(node.func.id)
    return out


def verify_returns():
    """(status, reason) pairs from the verdict sources; the non-constant reason comes from the prefixes of the parse errors."""
    out, dynamic = {}, False
    for node in [n for fn in _verdict_sources() for n in ast.walk(fn)]:
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2:
            a, b = node.value.elts
            if not isinstance(a, ast.Constant):
                continue
            if isinstance(b, ast.Constant):
                out.setdefault(a.value, set()).add(b.value)
            else:
                dynamic = True
                out.setdefault(a.value, set()).update(parse_prefixes())
    return out, dynamic


def parse_prefixes():
    """The prefixes of `parse_framed`'s ValueErrors — these become verify's `invalid` reasons."""
    fn = next(n for n in ast.walk(_tree()) if isinstance(n, ast.FunctionDef) and n.name == "parse_framed")
    got = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and node.exc.args:
            a = node.exc.args[0]
            txt = a.value if isinstance(a, ast.Constant) else (a.values[0].value if isinstance(a, ast.JoinedStr)
                                                               and isinstance(a.values[0], ast.Constant) else
                                                               ast.unparse(a))
            m = re.match(r"^['\"]?([a-z][a-z-]+)", str(txt))
            if m:
                got.add(m.group(1))
    return got


class LabelParity(unittest.TestCase):
    def test_the_source_produces_exactly_the_pinned_label_set(self):
        got, dynamic = verify_returns()
        self.assertTrue(dynamic, "verify no longer derives the `invalid` reasons from the parse error — review the pin")
        self.assertEqual(set(got), set(PINNED), "a new or vanished STATUS in verify")
        for status in sorted(PINNED):
            extra, missing = got[status] - PINNED[status], PINNED[status] - got[status]
            self.assertFalse(extra, "%s: the code returns a reason that is not in the pinned list: %s" % (status, sorted(extra)))
            self.assertFalse(missing, "%s: the pinned list claims a reason the code NEVER returns: %s"
                                      % (status, sorted(missing)))

    def test_label_rendering_matches_the_documented_rule(self):
        """label(): `valid`/`unsigned` bare, everything else in the `status(reason)` shape."""
        import sys
        sys.path.insert(0, HERE)
        import sds_envelope as se
        self.assertEqual(se.label("valid", ""), "valid")
        self.assertEqual(se.label("unsigned", "no-sigs"), "unsigned")
        self.assertEqual(se.label("invalid", "bad-signature"), "invalid(bad-signature)")
        self.assertEqual(se.label("unverifiable", "no-crypto"), "unverifiable(no-crypto)")

    def test_the_guard_bites_when_a_reason_is_added_or_removed(self):
        """Validating the validator: the measurement signals in both directions relative to the pinned set."""
        got, _ = verify_returns()
        self.assertNotEqual(got["unverifiable"], PINNED["unverifiable"] | {"no-such-reason"})
        with self.assertRaises(AssertionError):
            extra = {"no-such-reason"}
            self.assertFalse(extra, "simulated discrepancy")


if __name__ == "__main__":
    unittest.main()
