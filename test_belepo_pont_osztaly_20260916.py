"""AZ OSZTÁLY őrszeme: MINDEN CLI al-parancs, ami fájlt vesz.

Ez a szonda HÁROMSZOR volt vak, és mindháromszor másképp — a történetet itt hagyom, mert a tanulság a
szondáról szól, nem a kódról:

  1. az al-parancsokat az `--help` SZÖVEG sorainak elejéről kereste; az argparse behúzva, `{a,b,c}` alakban
     írja ki őket -> egyetlen al-parancsot sem hívott meg;
  2. javítva: a parserből vette az al-parancsokat — de `[modul, al-parancs, fájl]` alakban hívott, a KÖTELEZŐ
     kapcsolók nélkül, így 23-ból 22 **argparse-hibán** (rc=2) állt meg, amit „rendben"-nek olvasott.
     Ténylegesen EGYETLEN al-parancsot mért: a `bus_notary verify`-t — azt, amelyik már javítva volt.
     (NIT mérte ki; a MEDIUM lelete — `reconcile` üres naplóra rc=0 — épp a vak
     halmazban ült.)
  3. a bemeneti alakokból hiányzott az, ami a HIGH-t adja: az ÉRVÉNYES JSON-OBJEKTUM, ami nem bejegyzés.

Ezért a szonda mostantól a KÖTELEZŐ ARGUMENTUMOKAT IS A PARSERBŐL tölti ki (a súgó szöveg formázás, a parser
a tény), és külön teszt köti, hogy a TÉNYLEGESEN LEFUTOTT al-parancsok száma ne essen egy padló alá — egy
szonda, ami nem fut le, nem zöld, hanem NEM MÉRT.

A kötött szabály: egyetlen belépő pont sem válaszolhat hibás fájlra **tracebackkel**, és nem mondhat rá
**rc=0**-t sem.

stdlib unittest.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

CASES = {"nem-JSON": "ez nem json\n",
         "félbevágott": '{"type": "entry", "seq": 1, "prev',
         "skalár sor": "5\n",
         "JSON-tömb": "[1,2,3]\n",
         "üres fájl": "",
         "csak whitespace": "\n\n \n",
         # EZ az alak hiányzott — érvényes JSON-objektum, ami nem bejegyzés.
         "üres objektum": "{}\n",
         "idegen rekordtípus": '{"kind":"valami"}\n'}

# Al-parancsok, amik NEM fájlt vesznek (kulcs, állapotírás, hálózat). SZŰK és NEVESÍTETT lista.
SKIP = {("bus_notary.py", "keygen"), ("bus_notary.py", "checkpoint"), ("bus_notary.py", "record"),
        ("bus_singleflight.py", "guard")}


def _cli_modules():
    out = []
    for f in sorted(os.listdir(HERE)):
        if not f.endswith(".py") or f.startswith("test_"):
            continue
        src = open(os.path.join(HERE, f), encoding="utf-8").read()
        if "argparse" in src and "__main__" in src:
            out.append(f)
    return out


def _help(mod_file, *sub):
    """Az argparse SAJÁT súgója, ALFOLYAMATBAN. SOHA nem importálunk és NEM hívunk a modulból semmit.

    Saját hiba, rögzítve: az előző alak a modul minden callable attribútumát MEGHÍVTA, hogy parser-objektumot
    találjon — és ezzel lefuttatta az `agent_bus.main()`-t, ami a pytest ARGV-jét kezdte parse-olni és
    `SystemExit(2)`-vel szállt el. Egy szonda, ami a vizsgált modul kódját futtatja, nem szonda.
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, mod_file)] + list(sub) + ["--help"],
                       capture_output=True, text=True, timeout=60)
    return (r.stdout or "") + (r.stderr or "")


def _subcommands(mod_file):
    """Az al-parancsok az argparse `{a,b,c}` blokkjából — ez a parser saját kiírása, nem a mi találgatásunk."""
    m = re.search(r"\{([a-z0-9_,\-]{3,})\}", _help(mod_file))
    return sorted(m.group(1).split(",")) if m else []


def _usage(mod_file, sub):
    txt = _help(mod_file, sub)
    m = re.search(r"usage:(.*?)(?:\n\n|\Z)", txt, re.S)
    return m.group(1) if m else ""


FILEISH = ("file", "log", "receipt", "audit", "path", "jsonl", "corpus", "export")

# NEVESÍTETT felülírás: ahol a metavar NEVE nem árulja el, hogy fájlt vesz. A név-egyeztetés önmagában
# bizonyítottan hamis eredményt ad (a `bus_notary compare a b` két NAPLÓT vesz, de a metavarok semmit nem
# mondanak) — ezért nem okosabb heurisztikát írok, hanem kimondom, és a lista rövid marad.
POS_FILES = {("bus_notary.py", "compare"): 2}


def _file_slot(mod_file, sub):
    """-> ("pos", None) | ("opt", "--log") | None, ha ez az al-parancs EGYÁLTALÁN NEM vesz fájlt.

    A szonda eredeti premisszája hibás volt: azt hitte, minden belépő pont fájlt vesz. Nem: az
    `agent_bus ack <agent> <id>`, a `send <ki> <kinek> <szöveg>` és a többség NEM fájl-alapú, ezért a
    `[modul, al-parancs, FÁJL]` hívás náluk argparse-hibán állt meg — és a szonda ezt „rendben"-nek olvasta.
    Akit nem lehet fájllal etetni, azt NEM MÉRJÜK, de KIMONDJUK, hogy nem mértük.
    """
    u = _usage(mod_file, sub)
    stripped = re.sub(r"\[[^\]]*\]", " ", u)
    # ELŐBB a POZICIONÁLIS: a `reconcile`-nak pozicionális `file`-ja IS van és fájl-szagú KAPCSOLÓI is
    # (`--receipts`). Az előző alak a kapcsolót választotta, a pozicionális kimaradt, és az argparse
    # „the following arguments are required: file"-lal állt meg — a szonda megint a saját hibáját mérte.
    tail = re.sub(r"^\s*\S+\s+\S+\s*", "", stripped.strip())
    tail = re.sub(r"--[A-Za-z0-9\-]+\s+[A-Z][A-Z_0-9]*", " ", tail)
    for tok in re.findall(r"[A-Za-z][A-Za-z_0-9\-]*", tail):
        if any(k in tok.lower() for k in FILEISH):
            return ("pos", None)
    # A fájl-RÉST a TELJES usage-ben keressük, nem a zárójel-mentesítettben: a `bus_notary export [--log LOG]`
    # fájl-kapcsolója OPCIONÁLIS, tehát a zárójel-szűrő kidobta — és a szonda „nem fájl-alapú"-nak minősítette
    # azt az al-parancsot, amin az egyik kar épp leletet mért (`export --log <szemét>` -> rc=0, üres export).
    # A zárójel csak azt dönti el, mi KÖTELEZŐ; azt nem, hogy mi VESZ FÁJLT.
    for opt, _meta in re.findall(r"(--[A-Za-z0-9][A-Za-z0-9\-]*)\s+([A-Z][A-Z_0-9]*)", u):
        if any(k in opt for k in FILEISH):
            return ("opt", opt)
    return None


def _required_opts(mod_file, sub, tmpdir):
    """A KÖTELEZŐ kapcsolók a `usage:` sorból: az argparse a nem kötelezőket SZÖGLETES ZÁRÓJELBE teszi.

    Enélkül a szonda 23 al-parancsból 22-t argparse-hibán mért, és a saját hibáját olvasta „rendben"-nek.
    """
    txt = _help(mod_file, sub)
    m = re.search(r"usage:(.*?)(?:\n\n|\Z)", txt, re.S)
    if not m:
        return []
    usage = re.sub(r"\[[^\]]*\]", " ", m.group(1))          # a NEM kötelezőket kivesszük
    argv = []
    for opt, meta in re.findall(r"(--[A-Za-z0-9][A-Za-z0-9\-]*)\s+([A-Z][A-Z_0-9]*)", usage):
        val = "1" if meta.endswith(("SEC", "SECS", "N", "COUNT", "SEQ", "WINDOW")) else "x"
        if any(k in opt for k in ("file", "log", "receipt", "audit", "path", "out", "pub")):
            val = os.path.join(tmpdir, "req_%s.jsonl" % opt.strip("-").replace("-", "_"))
            if not os.path.exists(val):
                open(val, "w", encoding="utf-8").write(
                    '{"phase":"outcome","outcome":"delivered","round":"r1","rc":0}\n')
        argv += [opt, val]
    return argv


def _names_it(r):
    """Kimondja-e a futás, hogy mi a baj? (REJECT / KIMONDVA / FIGYELEM a stderr-en)"""
    err = (r.stderr or "")
    return any(k in err for k in ("REJECT", "KIMONDVA", "FIGYELEM", "NULLA BIZONYÍTÉK"))


def _is_usage_error(r):
    """argparse használati hiba = a szonda NEM MÉRT, nem az, hogy a kód rendben van."""
    err = (r.stderr or "")
    return r.returncode == 2 and ("usage:" in err or "arguments are required" in err
                                  or "invalid choice" in err or "unrecognized arguments" in err)


def _sweep():
    """-> (mérve, nem_mérve, leletek)"""
    measured, unmeasured, bad, notfile = [], [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        for mod in _cli_modules():
            for sub in _subcommands(mod):
                if (mod, sub) in SKIP:
                    continue
                slot = _file_slot(mod, sub)
                npos = POS_FILES.get((mod, sub))
                if npos:
                    slot = ("pos", npos)
                if slot is None:                      # nem fájl-alapú al-parancs: KIMONDVA, nem elhallgatva
                    notfile.append("%s %s" % (mod, sub))
                    continue
                extra = _required_opts(mod, sub, tmp)
                for name, text in CASES.items():
                    path = os.path.join(tmp, "case.jsonl")
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(text)
                    if slot[0] == "opt":
                        argv = [sub] + extra + [slot[1], path]
                    elif isinstance(slot[1], int):
                        argv = [sub] + [path] * slot[1] + extra
                    else:
                        argv = [sub, path] + extra
                    try:
                        r = subprocess.run([sys.executable, os.path.join(HERE, mod)] + argv,
                                           capture_output=True, text=True, timeout=120)
                    except subprocess.TimeoutExpired:
                        bad.append("%s %s / %s -> TIMEOUT" % (mod, sub, name))
                        continue
                    if _is_usage_error(r):
                        unmeasured.append("%s %s / %s" % (mod, sub, name))
                        continue
                    measured.append("%s %s / %s" % (mod, sub, name))
                    if "Traceback" in (r.stderr or ""):
                        bad.append("%s %s / %s -> TRACEBACK: %s"
                                   % (mod, sub, name, (r.stderr.strip().splitlines() or [""])[-1][:70]))
                    elif r.returncode == 0 and not _names_it(r):
                        # A szabály ÉLESEBB alakja: nem az `rc=0` a lelet, hanem a NÉMA `rc=0`. Egy üres
                        # napló dev-módban lehet rc=0 — de akkor KI KELL MONDANIA, hogy mi hiányzik.
                        # (Ez a finomítás abból jött, hogy a saját őrszemem és a saját „ismeretlen kimenetel
                        # nem vád" kontrollom ütközött: az egyik tiltotta az rc=0-t, a másik megkövetelte.)
                        bad.append("%s %s / %s -> NÉMA ZÖLD (rc=0, a stderr nem mond semmit)"
                                   % (mod, sub, name))
    return measured, unmeasured, bad, notfile


class TheSentryMustActuallyRun(unittest.TestCase):
    """ELŐFELTÉTEL: egy szonda, ami nem fut le, nem zöld — NEM MÉRT."""

    def test_most_subcommands_are_really_invoked(self):
        measured, unmeasured, _, notfile = _sweep()
        total = len(measured) + len(unmeasured)
        self.assertGreater(total, 0, "a szonda egyetlen al-parancsot sem talált")
        arany = len(measured) / float(total)
        self.assertGreaterEqual(arany, 0.75,
                                "a szonda a hívások %.0f%%-át argparse-hibán mérte — vagyis a saját hibáját "
                                "mérte a kód helyett. NEM MÉRT: %s" % (100 * (1 - arany), unmeasured[:8]))
        subs = {x.rsplit(" / ", 1)[0] for x in measured}
        self.assertGreaterEqual(len(subs), 4,
                                "csak %d al-parancs futott le ténylegesen (%s) — a szonda vakon lenne zöld. "
                                "Nem fájl-alapú (KIMONDVA, nem elhallgatva): %s"
                                % (len(subs), sorted(subs), notfile))


class NoEntryPointAnswersWithATraceback(unittest.TestCase):
    def test_no_malformed_file_produces_a_traceback_or_a_green_rc(self):
        measured, unmeasured, bad, notfile = _sweep()
        self.assertEqual(bad, [], "hibás fájlra traceback vagy zöld (%d mérve, %d nem mérve):\n  %s"
                         % (len(measured), len(unmeasured), "\n  ".join(bad)))


if __name__ == "__main__":
    unittest.main()
