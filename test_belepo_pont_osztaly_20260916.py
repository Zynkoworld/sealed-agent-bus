"""The CLASS sentinel: EVERY CLI sub-command that takes a file.

This probe was blind THREE times, and differently each time — I leave the story here, because the lesson is about the
probe, not the code:

  1. it looked for the sub-commands at the start of the lines of the `--help` TEXT; argparse prints them indented, in the
     `{a,b,c}` shape -> it did not call a single sub-command;
  2. fixed: it took the sub-commands from the parser — but it called them as `[module, sub-command, file]`, without the REQUIRED
     switches, so 22 of 23 stopped at an **argparse error** (rc=2), which it read as "fine".
     It actually measured ONE sub-command: `bus_notary verify` — the one that was already fixed.
     (A NIT measured this; the MEDIUM finding — `reconcile` on an empty log gives rc=0 — sat exactly in the blind
     set.)
  3. the input shapes lacked the one that gives the HIGH: a VALID JSON OBJECT that is not an entry.

So the probe now fills in the REQUIRED ARGUMENTS FROM THE PARSER TOO (the help text is formatting, the parser
is the fact), and a separate test pins that the number of sub-commands ACTUALLY RUN does not drop below a floor — a
probe that does not run is not green, it is NOT MEASURED.

The bound rule: no entry point may answer a broken file with a **traceback**, nor may it say
**rc=0** to it.

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

CASES = {"non-JSON": "this is not json\n",
         "truncated": '{"type": "entry", "seq": 1, "prev',
         "scalar line": "5\n",
         "JSON array": "[1,2,3]\n",
         "empty file": "",
         "whitespace only": "\n\n \n",
         # THIS shape was missing — a valid JSON object that is not an entry.
         "empty object": "{}\n",
         "foreign record type": '{"kind":"something"}\n'}

# Sub-commands that do NOT take a file (key, state writing, network). A NARROW and NAMED list.
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
    """argparse's OWN help, in a SUBPROCESS. We NEVER import and do NOT call anything from the module.

    Our own error, recorded: the previous shape CALLED every callable attribute of the module to find a parser
    object — and so it ran `agent_bus.main()`, which started parsing pytest's ARGV and
    blew up with `SystemExit(2)`. A probe that runs the examined module's code is not a probe.
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, mod_file)] + list(sub) + ["--help"],
                       capture_output=True, text=True, timeout=60)
    return (r.stdout or "") + (r.stderr or "")


def _subcommands(mod_file):
    """The sub-commands from argparse's `{a,b,c}` block — this is the parser's own output, not our guess."""
    m = re.search(r"\{([a-z0-9_,\-]{3,})\}", _help(mod_file))
    return sorted(m.group(1).split(",")) if m else []


def _usage(mod_file, sub):
    txt = _help(mod_file, sub)
    m = re.search(r"usage:(.*?)(?:\n\n|\Z)", txt, re.S)
    return m.group(1) if m else ""


FILEISH = ("file", "log", "receipt", "audit", "path", "jsonl", "corpus", "export")

# A NAMED override: where the metavar's NAME does not reveal that it takes a file. Name matching alone
# provably gives a false result (`bus_notary compare a b` takes two LOGS, but the metavars say
# nothing) — so I do not write a smarter heuristic, I state it, and the list stays short.
POS_FILES = {("bus_notary.py", "compare"): 2}


def _file_slot(mod_file, sub):
    """-> ("pos", None) | ("opt", "--log") | None if this sub-command takes NO file AT ALL.

    The probe's original premise was wrong: it believed every entry point takes a file. No: the
    `agent_bus ack <agent> <id>`, `send <who> <to whom> <text>` and the majority are NOT file-based, so the
    `[module, sub-command, FILE]` call stopped at an argparse error for them — and the probe read that as "fine".
    Whatever cannot be fed a file we do NOT MEASURE, but we STATE that we did not measure it.
    """
    u = _usage(mod_file, sub)
    stripped = re.sub(r"\[[^\]]*\]", " ", u)
    # POSITIONAL FIRST: `reconcile` has a positional `file` AND file-smelling SWITCHES too
    # (`--receipts`). The previous shape chose the switch, the positional was left out, and argparse
    # stopped with "the following arguments are required: file" — the probe measured its own error again.
    tail = re.sub(r"^\s*\S+\s+\S+\s*", "", stripped.strip())
    tail = re.sub(r"--[A-Za-z0-9\-]+\s+[A-Z][A-Z_0-9]*", " ", tail)
    for tok in re.findall(r"[A-Za-z][A-Za-z_0-9\-]*", tail):
        if any(k in tok.lower() for k in FILEISH):
            return ("pos", None)
    # We look for the file SLOT in the FULL usage, not in the bracket-stripped one: the file switch of
    # `bus_notary export [--log LOG]` is OPTIONAL, so the bracket filter threw it out — and the probe rated as "not file-based"
    # the very sub-command on which one arm had just measured a finding (`export --log <garbage>` -> rc=0, empty export).
    # The brackets only decide what is REQUIRED; not what TAKES A FILE.
    for opt, _meta in re.findall(r"(--[A-Za-z0-9][A-Za-z0-9\-]*)\s+([A-Z][A-Z_0-9]*)", u):
        if any(k in opt for k in FILEISH):
            return ("opt", opt)
    return None


def _required_opts(mod_file, sub, tmpdir):
    """The REQUIRED switches from the `usage:` line: argparse puts the non-required ones in SQUARE BRACKETS.

    Without this the probe measured 22 of 23 sub-commands on an argparse error, and read its own error as "fine".
    """
    txt = _help(mod_file, sub)
    m = re.search(r"usage:(.*?)(?:\n\n|\Z)", txt, re.S)
    if not m:
        return []
    usage = re.sub(r"\[[^\]]*\]", " ", m.group(1))          # we remove the NON-required ones
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
    """Does the run state what is wrong? (REJECT / STATED / WARNING on stderr)"""
    err = (r.stderr or "")
    return any(k in err for k in ("REJECT", "STATED", "WARNING", "ZERO EVIDENCE"))


def _is_usage_error(r):
    """An argparse usage error = the probe did NOT MEASURE, not that the code is fine."""
    err = (r.stderr or "")
    return r.returncode == 2 and ("usage:" in err or "arguments are required" in err
                                  or "invalid choice" in err or "unrecognized arguments" in err)


def _sweep():
    """-> (measured, not_measured, findings)"""
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
                if slot is None:                      # not a file-based sub-command: STATED, not kept quiet
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
                        # The SHARPER form of the rule: the finding is not `rc=0` but a SILENT `rc=0`. An empty
                        # log may be rc=0 in dev mode — but then it MUST STATE what is missing.
                        # (This refinement came from my own sentinel colliding with my own "unknown outcome
                        # is not an accusation" control: one forbade rc=0, the other required it.)
                        bad.append("%s %s / %s -> SILENT GREEN (rc=0, stderr says nothing)"
                                   % (mod, sub, name))
    return measured, unmeasured, bad, notfile


class TheSentryMustActuallyRun(unittest.TestCase):
    """PRECONDITION: a probe that does not run is not green — it is NOT MEASURED."""

    def test_most_subcommands_are_really_invoked(self):
        measured, unmeasured, _, notfile = _sweep()
        total = len(measured) + len(unmeasured)
        self.assertGreater(total, 0, "the probe found not a single sub-command")
        arany = len(measured) / float(total)
        self.assertGreaterEqual(arany, 0.75,
                                "the probe measured %.0f%% of the calls on an argparse error — i.e. it measured its own "
                                "error instead of the code. NOT MEASURED: %s" % (100 * (1 - arany), unmeasured[:8]))
        subs = {x.rsplit(" / ", 1)[0] for x in measured}
        self.assertGreaterEqual(len(subs), 4,
                                "only %d sub-command(s) actually ran (%s) — the probe would be blindly green. "
                                "Not file-based (STATED, not kept quiet): %s"
                                % (len(subs), sorted(subs), notfile))


class NoEntryPointAnswersWithATraceback(unittest.TestCase):
    def test_no_malformed_file_produces_a_traceback_or_a_green_rc(self):
        measured, unmeasured, bad, notfile = _sweep()
        self.assertEqual(bad, [], "traceback or green on a broken file (%d measured, %d not measured):\n  %s"
                         % (len(measured), len(unmeasured), "\n  ".join(bad)))


if __name__ == "__main__":
    unittest.main()
