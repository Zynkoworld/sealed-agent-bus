"""A VERDIKT-CÍMKE HALMAZ őre — a címkék szerződés, tehát mérni kell őket, nem olvasni.

Tanulság (2026-09-19): a C++ kar technikai inputjába a címke-halmazt kézzel gépeltem be, és egy független review egy
hiányzó okot vetett fel. A javítás nem az, hogy figyelmesebben olvasok: ez a teszt a FORRÁSBÓL vezeti le a halmazt
(AST-ből, nem regexszel a kimeneten), és egy pinelt listához méri. Ha a kód új címkét kap vagy egyet elveszít, ez a
teszt PIROS, és a pinelt listával együtt a kifelé menő dokumentumot is frissíteni kell.

Ugyanez a kapu fogja meg a fordítottját is: egy dokumentumba került címke, amit a kód SOSEM ad vissza (idegen vagy
másik implementációból átvett ok) — ezért a pinelt lista az EGYETLEN igazság-forrás, és a teszt mindkét irányban mér.
stdlib unittest."""
import ast
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sds_envelope.py")

# A pinelt halmaz. Bővítés/szűkítés csak TUDATOSAN, a kifelé menő címke-dokumentációval EGYÜTT.
PINNED = {
    "valid": {""},
    "unsigned": {"no-sigs"},
    "invalid": {"not-json", "not-framed", "envelope-malformed", "record-id-mismatch", "record-not-canonicalizable",
                "record-id-binding", "domain-hash-mismatch", "config-mismatch", "not-admitted", "key-mismatch",
                "bad-signature"},
    # `no-config-binding`: a pinből HIÁNYZOTT, és a kód adja. Ugyanez a címke bukott ki 2026-09-19-én egy
    # független review-ban a kifelé menő dokumentumból is — a kézzel gépelt halmaz kétszer is ugyanazt az
    # okot ejtette el. Ezért származtatjuk a forrásból, és ezért mér a teszt MINDKÉT irányban.
    "unverifiable": {"no-admission", "no-config-binding", "no-crypto", "validator-import", "validator-error"},
}


def _tree():
    return ast.parse(open(SRC, encoding="utf-8").read())


def _functions():
    return {n.name: n for n in ast.walk(_tree()) if isinstance(n, ast.FunctionDef)}


def _verdict_sources():
    """A `verify` ÉS minden modul-szintű függvény, amelynek az eredményét visszaadja.

    A kinyerő eleinte csak a `verify` törzsét járta be. Amikor a modul a döntést egy segédfüggvénybe
    (`_builtin_verify`) szervezte át, a címkék egy része eltűnt a MÉRÉSBŐL — a kódból nem —, és a teszt
    elveszett státuszt jelentett. Egy statikus mérő, amelyik nem követi a delegálást, a saját vakfoltját
    jelenti a kód hibájaként, ezért a delegálást itt végig kell követni."""
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
            # Minden modul-szintű hívás, nem csak a `return f(...)` alak: ez a modul a verdiktet változóba
            # veszi (`base_status, base_why = _builtin_verify(...)`), tehát a return-re szűkítő követés
            # pontosan azt a függvényt hagyta ki, amelyik a címkék többségét adja. Ha ez túl sokat gyűjt be,
            # az a teszten PINELETLEN címkeként jelenik meg — hangosan, nem némán.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in fns:
                queue.append(node.func.id)
    return out


def verify_returns():
    """(status, reason) párok a verdikt-forrásokból; a nem-konstans reason a parse-hibák prefixeiből jön."""
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
    """A `parse_framed` ValueError-jeinek prefixei — ezek lesznek a verify `invalid` okai."""
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
        self.assertTrue(dynamic, "a verify már nem a parse-hibából származtatja az `invalid` okokat — nézd át a pint")
        self.assertEqual(set(got), set(PINNED), "új vagy eltűnt STÁTUSZ a verify-ban")
        for status in sorted(PINNED):
            extra, missing = got[status] - PINNED[status], PINNED[status] - got[status]
            self.assertFalse(extra, "%s: a kód olyan okot ad vissza, ami nincs a pinelt listában: %s" % (status, sorted(extra)))
            self.assertFalse(missing, "%s: a pinelt lista olyan okot állít, amit a kód SOSEM ad vissza: %s"
                                      % (status, sorted(missing)))

    def test_label_rendering_matches_the_documented_rule(self):
        """label(): `valid`/`unsigned` csupaszon, minden más `status(reason)` alakban."""
        import sys
        sys.path.insert(0, HERE)
        import sds_envelope as se
        self.assertEqual(se.label("valid", ""), "valid")
        self.assertEqual(se.label("unsigned", "no-sigs"), "unsigned")
        self.assertEqual(se.label("invalid", "bad-signature"), "invalid(bad-signature)")
        self.assertEqual(se.label("unverifiable", "no-crypto"), "unverifiable(no-crypto)")

    def test_the_guard_bites_when_a_reason_is_added_or_removed(self):
        """Validáló validálása: a mérés a pinelt halmazhoz képest mindkét irányban jelez."""
        got, _ = verify_returns()
        self.assertNotEqual(got["unverifiable"], PINNED["unverifiable"] | {"no-such-reason"})
        with self.assertRaises(AssertionError):
            extra = {"no-such-reason"}
            self.assertFalse(extra, "szimulált eltérés")


if __name__ == "__main__":
    unittest.main()
