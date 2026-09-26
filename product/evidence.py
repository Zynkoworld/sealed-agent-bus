#!/usr/bin/env python3
"""evidence.py — the machinery behind the evidence envelope: manifest check, coverage floor, chapter runner.

Used by `make_evidence.py` (at release) and by `verify_evidence.py` (on the buyer's machine). The floor is the part
that matters: for every claim it removes the guard from a COPY of the shipped source and requires the claim's tests
to go red. A claim whose tests stay green without its guard is a silent green, and the floor fails. stdlib only."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SKIP_DIRS = {".git", "__pycache__", "dist", ".pytest_cache"}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_tree(tree: str):
    """The tree's shipped files. The SKIP names are skipped AS FILES too, not only as directories.

    In a git WORKTREE `.git` is not a directory but a file (`gitdir: …`). The first version only filtered
    directories, so in the main checkout it worked correctly for years, but in a worktree `.git`
    got walked as a file, and the integrity chapter failed with ".git: not in the manifest". An environment-
    dependent verifier bug: the tree was not different, only where we looked from."""
    for root, dirs, files in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name in SKIP_DIRS:
                continue
            p = os.path.join(root, name)
            yield os.path.relpath(p, tree).replace(os.sep, "/"), p


def load_claims(product_dir: str) -> dict:
    with open(os.path.join(product_dir, "claims.json"), encoding="utf-8") as f:
        return json.load(f)


#: Publish-time FURNITURE: files added to the public landing page after the product was sealed. They are not
#: part of the sealed product, they cannot change its behaviour, and the seal deliberately does not cover them.
#: An independent arm found the published v1.5.1 failing its OWN verifier because these three were present and
#: unlisted — the envelope said "not in the manifest" about files the seal was never meant to describe.
#: EXACT names, never a directory: a directory-shaped exemption grows on its own as the directory fills, and a
#: hole that grows is worse than the gap it patched. The verifier NAMES whatever it finds here rather than
#: skipping it quietly, so a reader sees exactly what the seal does not cover.
UNSEALED = ("README.md", "SECURITY.md", "assets/sab.png")


def unsealed_present(tree: str) -> list:
    """Which furniture files are actually here — reported by the verifier, not silently passed over."""
    return sorted(rel for rel, _ in walk_tree(tree) if rel in UNSEALED)


def check_manifest(tree: str, manifest: dict) -> list:
    """-> a list of problems; empty means every SEALED file is byte-identical to the manifest.

    Publish-time furniture (see `UNSEALED`) is outside the seal by design and is reported separately."""
    problems, expected = [], manifest.get("files", {})
    seen = set()
    for rel, path in walk_tree(tree):
        if rel.startswith("product/evidence/"):                     # the envelope describes the code, not itself
            continue
        if rel in UNSEALED and rel not in expected:                 # furniture, named by the verifier instead
            continue
        seen.add(rel)
        if rel not in expected:
            problems.append({"file": rel, "problem": "not in the manifest"})
        elif sha256_file(path) != expected[rel]:
            problems.append({"file": rel, "problem": "content differs from the manifest"})
    for rel in expected:
        if rel not in seen:
            problems.append({"file": rel, "problem": "missing"})
    return problems


def _copy_tree(tree: str, dest: str) -> None:
    shutil.copytree(tree, dest, ignore=shutil.ignore_patterns(*SKIP_DIRS))


#: Exceptions that mean the mutated tree is BROKEN rather than caught. A guard removed by hand can leave a name
#: undefined or an import dangling, and then every test in the file dies for a reason that has nothing to do with
#: the claim. Counting those as "the guard was measured" is how a floor reports strength it does not have.
_CRASH_MARKERS = ("ImportError", "ModuleNotFoundError", "SyntaxError", "IndentationError", "NameError",
                  "UnboundLocalError", "AttributeError", "TypeError", "INTERNALERROR")


def _classify(message: str) -> str:
    """'assertion' (the test decided) or 'exception' (the tree fell over)."""
    head = (message or "")[:4000]
    if "AssertionError" in head or "assert" in head.lower():
        return "assertion"
    return "exception" if any(m in head for m in _CRASH_MARKERS) else "assertion"


def _run_tests(tree: str, test_files, timeout=900):
    """-> (rc, tail, outcomes) with outcomes mapping a test id to 'passed' | 'failed:assertion' |
    'failed:exception' | 'error' | 'skipped'.

    Two things changed here after an independent arm measured the floor rather than reading it. It ran the
    tests with `unittest` while the package ships and advertises `pytest` — two collectors, so the floor was
    not measuring the suite the product claims. And it returned only an exit code, which is a single bit: a
    claim whose run went 16 failed / 17 passed BEFORE and 16 failed / 17 passed AFTER carried zero signal and
    still counted as "red without the guard". Per-test outcomes are what let `run_floor` ask the real
    question — which tests changed, and in which direction."""
    xml = os.path.join(tempfile.mkdtemp(), "floor.xml")
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junit-xml", xml]
                       + list(test_files), cwd=tree, capture_output=True, text=True, timeout=timeout,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    tail = (p.stdout + p.stderr).strip().splitlines()
    outcomes = {}
    try:
        root = ET.parse(xml).getroot()
        for case in root.iter("testcase"):
            tid = "%s::%s" % (case.get("classname") or "", case.get("name") or "")
            kids = {k.tag: k for k in case}
            if "skipped" in kids:
                outcomes[tid] = "skipped"
            elif "error" in kids:
                outcomes[tid] = "error"
            elif "failure" in kids:
                node = kids["failure"]
                outcomes[tid] = "failed:" + _classify((node.get("message") or "") + (node.text or ""))
            else:
                outcomes[tid] = "passed"
    except (ET.ParseError, OSError):
        pass                                   # no XML: outcomes stay empty, and run_floor treats that as no signal
    return p.returncode, " | ".join(tail[-2:])[:200], outcomes


def apply_mutation(tree: str, mutation: dict) -> str | None:
    """-> None on success, or why the mutation could not be applied (which is itself a floor failure)."""
    path = os.path.join(tree, mutation["file"])
    if not os.path.isfile(path):
        return "the file to mutate does not exist: %s" % mutation["file"]
    src = open(path, encoding="utf-8").read()
    n = src.count(mutation["find"])
    if n != 1:
        return "the guard text was found %d times in %s (expected exactly once)" % (n, mutation["file"])
    open(path, "w", encoding="utf-8").write(src.replace(mutation["find"], mutation["replace"]))
    return None


def run_floor(tree: str, claims: dict, only=None, baseline_cache=None) -> list:
    """For every claim: the tests must pass on the shipped tree and FAIL once the guard is mutated away."""
    results, baseline_cache = [], {} if baseline_cache is None else baseline_cache
    for c in claims["claims"]:
        if only and c["id"] not in only:
            continue
        key = tuple(c["tests"])
        row = {"id": c["id"], "claim": c["claim"], "tests": c["tests"], "peer_written": c.get("peer_written", False)}
        if key not in baseline_cache:
            with tempfile.TemporaryDirectory() as t:
                dest = os.path.join(t, "clean")
                _copy_tree(tree, dest)
                baseline_cache[key] = _run_tests(dest, c["tests"])
        row["baseline_rc"], row["baseline_tail"], base_out = baseline_cache[key]
        with tempfile.TemporaryDirectory() as t:
            dest = os.path.join(t, "mutant")
            _copy_tree(tree, dest)
            why = apply_mutation(dest, c["mutation"])
            if why:
                row.update(mutated_rc=None, mutated_tail=why, status="FAIL",
                           reason="the guard-off mutation did not apply")
                results.append(row)
                continue
            row["mutated_rc"], row["mutated_tail"], mut_out = _run_tests(dest, c["tests"])

        # The question is not "did the exit code change" but "WHICH tests changed, and in which direction".
        base_red = {t for t, o in base_out.items() if o != "passed" and o != "skipped"}
        mut_red = {t for t, o in mut_out.items() if o != "passed" and o != "skipped"}
        newly_red = sorted(mut_red - base_red)
        resurrected = sorted(base_red - mut_red)          # the mutation made a failing test pass — also a finding
        killed_semantically = [t for t in newly_red if mut_out.get(t) == "failed:assertion"]
        row.update(newly_red=newly_red, resurrected=resurrected,
                   semantic_kills=killed_semantically,
                   baseline_red=len(base_red), mutant_red=len(mut_red))

        if row["baseline_rc"] != 0:
            row.update(status="FAIL", reason="the tests do not pass on the shipped tree (%d red)" % len(base_red))
        elif not base_out or not mut_out:
            row.update(status="FAIL", reason="no per-test outcomes were collected — the floor measured nothing")
        elif resurrected:
            # A mutation that REVIVES tests is not a guard being measured; it is the suite moving under the
            # claim. Nobody looked at this direction before, and one claim was resurrecting five tests.
            row.update(status="FAIL", reason="the mutation RESURRECTED %d test(s): %s"
                                             % (len(resurrected), ", ".join(resurrected[:3])))
        elif not newly_red:
            row.update(status="FAIL", reason="SILENT GREEN: no test changed when the guard was removed")
        elif not killed_semantically:
            # The tree fell over instead of the claim being caught: an import or a name died, so every red
            # here is collateral. Honest middle state — it is not a pass, and it is not "did not apply".
            row.update(status="WEAK", reason="only crash-kills (%s) — no test DECIDED against the mutation"
                                             % ", ".join("%s=%s" % (t.split("::")[-1], mut_out[t])
                                                         for t in newly_red[:3]))
        else:
            row.update(status="OK", reason="green with the guard; %d test(s) decided against it without it"
                                           % len(killed_semantically))
        results.append(row)
    return results


def run_notary_chapter(tree: str, timeout=300):
    """-> (status, rows). Runs the shipped chain probe; SKIP only if `cryptography` is absent."""
    probe = os.path.join(tree, "product", "_notary_probe.py")
    if not os.path.isfile(probe):
        return "FAIL", [{"probe": "probe script", "ok": False, "detail": "product/_notary_probe.py is missing"}]
    p = subprocess.run([sys.executable, probe], cwd=tree, capture_output=True, text=True, timeout=timeout,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    rows = []
    for line in p.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    if p.returncode == 2:
        return "SKIP", rows or [{"probe": "chapter", "ok": None, "detail": "cryptography is not installed"}]
    return ("OK" if p.returncode == 0 and rows else "FAIL"), rows or [{"probe": "chapter", "ok": False,
                                                                       "detail": (p.stderr or "no output")[:200]}]
