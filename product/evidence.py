#!/usr/bin/env python3
"""evidence.py — the machinery behind the evidence envelope: manifest check, coverage floor, chapter runner.

Used by `make_evidence.py` (at release) and by `verify_evidence.py` (on the buyer's machine). The floor is the part
that matters: for every claim it removes the guard from a COPY of the shipped source and requires the claim's tests
to go red. A claim whose tests stay green without its guard is a silent green, and the floor fails. stdlib only."""
from __future__ import annotations

import hashlib
import json
import os
import re
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


#: The product name the seal is for. One literal, compared instead of read back, so `product` is a checked field
#: rather than a decorative one.
PRODUCT = "sealed-bus"

#: THE PUBLICLY RE-DERIVABLE ANCHOR, and why it had to exist.
#:
#: The manifest's `source_commit` names a commit of the BUILD repository. The public repository is a squash
#: export, so that object is not in it: an independent arm tried to resolve the commit of the published v1.5.1
#: and got "bad object". A provenance field that a reader cannot resolve is not provenance, it is decoration —
#: and v1.5.5 only labelled it in prose, which reads like a check but is not one.
#:
#: So the seal also carries a digest over the SHIPPED BYTES. It is derivable from a fresh clone or an unpacked
#: archive with nothing but a hash tool, the verifier RE-DERIVES it instead of reading it back, and it is the
#: field the commit's own marking points at as its replacement.
CONTENT_DIGEST_RECIPE = ("sha256 over one line per sealed file — \"<sha256 of the file>  <path>\\n\" — sorted by "
                         "path: i.e. the bytes of `sha256sum` output for the sealed files, hashed again. By hand "
                         "from the tree root: sha256sum $(the sealed paths) | LC_ALL=C sort -k2 | sha256sum")

#: What `covered_instead_by` says when NOTHING covers the field. A marking is only honest if it may also say
#: that the gap is open; the alternative is that every unverifiable field acquires a fake guardian.
UNCOVERED = "nothing — stated as an unchecked claim"


def content_digest(entries) -> str:
    """-> the content digest of (path, sha256) pairs, per `CONTENT_DIGEST_RECIPE`."""
    blob = "".join("%s  %s\n" % (sha, rel) for rel, sha in sorted(entries))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def sealed_entries(tree: str, manifest: dict) -> list:
    """-> [(path, sha256)] MEASURED FROM DISK for every sealed file that is actually here.

    Measured from disk, not read out of the manifest: a digest recomputed from the list it is supposed to bind
    would agree with any list. A file that is missing or modified changes this digest, and `check_manifest`
    names it as well — the two findings are the same fact seen from two sides."""
    sealed = set(manifest.get("files", {}))
    return [(rel, sha256_file(path)) for rel, path in walk_tree(tree) if rel in sealed]


def _pc_product(tree, manifest, digest):
    got = manifest.get("product")
    return None if got == PRODUCT else "the manifest is for product %r, this tree's seal is for %r" % (got, PRODUCT)


def _pc_version(tree, manifest, digest):
    """The manifest's version against `product/version.py`, which is itself a sealed file — so this is a real
    binding to the shipped bytes, not the manifest agreeing with itself."""
    path = os.path.join(tree, "product", "version.py")
    if not os.path.isfile(path):
        return "product/version.py is not in the tree, so the version cannot be checked against it"
    m = re.search(r'^RELEASE_VERSION\s*=\s*"([^"]+)"', open(path, encoding="utf-8").read(), re.M)
    if not m:
        return "product/version.py declares no RELEASE_VERSION"
    return (None if m.group(1) == manifest.get("version") else
            "the manifest says version %r, the shipped product/version.py says %r" % (manifest.get("version"), m.group(1)))


def _pc_files(tree, manifest, digest):
    return None if manifest.get("files") else "the manifest lists no files, so it seals nothing"


def _pc_file_count(tree, manifest, digest):
    n, listed = manifest.get("file_count"), len(manifest.get("files") or {})
    return None if n == listed else "the manifest claims %r files and lists %d" % (n, listed)


def _pc_content_digest(tree, manifest, digest):
    claimed = (manifest.get("provenance") or {}).get("content_digest")
    if not claimed:
        return "the provenance block states no content_digest, so there is no publicly re-derivable anchor"
    return (None if claimed == digest else
            "the content digest re-derived from the shipped bytes is %s, the manifest claims %s" % (digest, claimed))


#: The checks the verifier really performs on a public clone. A field may be listed as verifiable-in-public ONLY
#: if it has an entry here: a name with no check behind it is exactly the silent drop this block exists to forbid.
PUBLIC_CHECKS = {"product": _pc_product, "version": _pc_version, "files": _pc_files,
                 "file_count": _pc_file_count, "content_digest": _pc_content_digest}


def check_public_provenance(tree: str, manifest: dict) -> list:
    """-> a list of problems with the manifest's PROVENANCE, in the same shape as `check_manifest`'s.

    Three separate demands, because dropping any one of them brings the original defect back:
      1. every manifest field is CLASSIFIED — re-derived in public, or declared unverifiable-in-public with a
         reason. A field that is neither is believed without anyone deciding to believe it.
      2. a field declared verifiable has an actual check behind it (`PUBLIC_CHECKS`), and that check runs.
      3. an unverifiable field says WHY, and names what covers it instead — a verified field, or `UNCOVERED`,
         which admits the gap out loud."""
    problems = []
    prov = manifest.get("provenance")
    if not isinstance(prov, dict):
        return [{"file": "product/evidence/MANIFEST.json",
                 "problem": "no provenance block: the manifest states no publicly re-derivable anchor, and nothing "
                            "says which of its fields a reader of the public repository cannot check"}]
    verifiable = [n for n in (prov.get("verifiable_in_public") or []) if isinstance(n, str)]
    unverifiable = [e for e in (prov.get("unverifiable_in_public") or []) if isinstance(e, dict)]

    declared = set(verifiable) | {e.get("field") for e in unverifiable}
    for key in sorted(k for k in manifest if k != "provenance"):
        if key not in declared:
            problems.append({"file": "MANIFEST.json:%s" % key,
                             "problem": "a manifest field that is neither re-derived in public nor declared "
                                        "unverifiable-in-public — a check cannot go missing quietly"})
    for name in verifiable:
        if name not in PUBLIC_CHECKS:
            problems.append({"file": "MANIFEST.json:%s" % name,
                             "problem": "declared verifiable-in-public, but the verifier has no check for it"})
    if "content_digest" not in verifiable:
        problems.append({"file": "product/evidence/MANIFEST.json",
                         "problem": "content_digest is not declared verifiable-in-public — then nothing in the "
                                    "provenance is re-derived, and the seal rests on the file list alone"})
    for e in unverifiable:
        field, where = e.get("field"), "MANIFEST.json:%s" % e.get("field")
        if not str(e.get("reason") or "").strip():
            problems.append({"file": where, "problem": "declared unverifiable-in-public with no reason"})
        cover = e.get("covered_instead_by")
        if cover != UNCOVERED and cover not in verifiable:
            problems.append({"file": where,
                             "problem": "covered_instead_by is %r — it must name a field that IS re-derived in "
                                        "public, or say %r" % (cover, UNCOVERED)})
        if field in verifiable:
            problems.append({"file": where, "problem": "declared both verifiable and unverifiable in public"})

    digest = content_digest(sealed_entries(tree, manifest))
    for name in verifiable:
        check = PUBLIC_CHECKS.get(name)
        if check is None:
            continue                                   # already reported above as a claim with no check behind it
        why = check(tree, manifest, digest)
        if why:
            problems.append({"file": "MANIFEST.json:%s" % name, "problem": why})
    return problems


def provenance_notes(manifest: dict) -> list:
    """One line per field a reader of the PUBLIC repository cannot check: the field, why, and what covers it
    instead. The verifier prints these, so the limit is read by whoever runs the check, not only by whoever
    opens the JSON."""
    prov = manifest.get("provenance") or {}
    return ["%s: NOT verifiable in public (%s) — covered instead by: %s"
            % (e.get("field"), e.get("reason"), e.get("covered_instead_by"))
            for e in (prov.get("unverifiable_in_public") or []) if isinstance(e, dict)]


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


def have_pytest() -> bool:
    """Is the product's OWN runner available? The floor is measured with `pytest`, because this tree's own guard
    test measures that `unittest` discovery silently skips some files — so a floor run with another collector is
    not the floor the product claims. Without it the chapter is NOT MEASURED, which is a stated state, never a
    pass and never a measured failure: reported as FAIL it said "the guard is not covered" about a guard nobody
    looked at (measured on a machine that has cryptography but no pytest: 9/9 claims "FAIL ... (0 red)" in 1s)."""
    return subprocess.run([sys.executable, "-c", "import pytest"], capture_output=True).returncode == 0


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

        if row["baseline_rc"] != 0 and not base_out:
            # ZERO per-test outcomes with a non-zero exit code: the runner never got as far as a test body, so
            # nothing was measured in EITHER direction. Calling that "the tests do not pass" states a measurement
            # that did not happen. NOT MEASURED is its own state — it is not a pass either, and `make_evidence`
            # and the release gate both refuse to cut a release on it.
            row.update(status="PENDING", reason="NOT MEASURED here: the runner produced no test outcome at all (%s)"
                                               % (row["baseline_tail"] or "no output"))
        elif row["baseline_rc"] != 0:
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
