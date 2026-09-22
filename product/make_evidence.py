#!/usr/bin/env python3
"""make_evidence.py — build the evidence envelope that ships with the artifact.

    python3 product/make_evidence.py --version 1.5.3 --commit HEAD

Writes product/evidence/: MANIFEST.json (version, source commit, per-file sha256, environment), CLAIMS.json (the
coverage-floor result, measured now), floor/<claim>.txt (what was mutated and what the tests did), suite.txt (the
full test run), notary/ (a real, signed demo chain + its public key) and EXTERNAL.json (chapter 4, PENDING until the
independent arms close). Everything here is re-derivable by the buyer: `verify_evidence.sh` recomputes it."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import evidence as ev  # noqa: E402

EV = os.path.join(HERE, "evidence")


def git(*args):
    p = subprocess.run(["git", "-C", TREE] + list(args), capture_output=True, text=True)
    if p.returncode:
        raise SystemExit("git %s failed: %s" % (" ".join(args), p.stderr.strip()))
    return p.stdout


def write(name, obj):
    path = os.path.join(EV, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(obj, (dict, list)):
            json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
        else:
            f.write(obj)
    return path


def demo_chain():
    """A real chain, signed with a key generated for this release: the buyer sees a genuine signed artifact, and can
    re-verify it with the public key next to it. It carries probe data only — no customer traffic, ever."""
    sys.path.insert(0, TREE)
    import bus_notary as bn
    if not bn.HAVE_CRYPTO:
        return {"status": "SKIP", "reason": "cryptography is not installed on the build machine"}
    log = os.path.join(EV, "notary", "chain.jsonl")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    if os.path.exists(log):
        os.remove(log)
    seed, pub = bn.keypair()
    n = bn.Notary(log, seed=seed, checkpoint_every=4)
    for i in range(12):
        n.record(envelope={"demo": i, "note": "release evidence chain, no customer data"}, sender_identity="release",
                 sender_auth="ssh-key", recipient="hub", kind="msg",
                 decision="accepted" if i % 4 else "rejected", reason="" if i % 4 else "policy")
    n.checkpoint()
    rep = bn.verify(bn.export(log, 1), trusted_pub=pub)
    write("notary/PUBKEY.txt", pub + "\n")
    return {"status": "OK" if rep["ok"] and rep["trusted"] else "FAIL", "entries": rep["head"]["seq"],
            "verified_checkpoints": rep["verified_checkpoint_count"], "trusted": rep["trusted"],
            "verify": "python3 bus_notary.py verify product/evidence/notary/chain.jsonl --pub $(cat product/evidence/notary/PUBKEY.txt)"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--external-root", default=None,
                    help="a partner-repó helyi checkoutja: a Chapter 4 pinelt fájljait újra hasheli")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="csak próbafuttatáshoz: piszkos munkafán is épít (a suite-sor ilyenkor nem a fáról szól)")
    ap.add_argument("--skip-floor", action="store_true", help="only for a dry run: the floor is the point")
    a = ap.parse_args(argv)
    t0 = time.time()
    commit = git("rev-parse", a.commit).strip()
    # A boríték a COMMIT fáját írja le, a suite viszont a MUNKAFÁN fut: ha a kettő eltér, a manifestbe egy olyan
    # suite-sor kerülne, ami nem a szállított fáról szól (mérve 2026-09-19: épp emiatt lett '1 failed' a manifestben).
    dirty = [l[3:] for l in git("status", "--porcelain").splitlines()
             if l[3:].strip() and not l[3:].startswith("product/evidence/")]
    if dirty and not a.allow_dirty:
        raise SystemExit("a munkafa nem tiszta (%s%s) — előbb commitold a kódot, a boríték csak utána épül"
                         % (", ".join(dirty[:4]), " …" if len(dirty) > 4 else ""))
    os.makedirs(EV, exist_ok=True)

    files = {}
    for name in sorted(n for n in git("ls-tree", "-r", "--name-only", commit).splitlines() if n.strip()):
        if name.startswith("product/evidence/"):
            continue
        blob = subprocess.run(["git", "-C", TREE, "cat-file", "blob", "%s:%s" % (commit, name)],
                              capture_output=True).stdout
        files[name] = __import__("hashlib").sha256(blob).hexdigest()

    print("==> test suite")
    # pytest if present: this tree's own guard test measures that unittest discovery silently skips some files, and a
    # silently partial suite is exactly what this envelope exists to forbid. Without pytest the run is labelled partial.
    have_pytest = subprocess.run([sys.executable, "-c", "import pytest"], capture_output=True).returncode == 0
    cmd = ([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"] if have_pytest
           else [sys.executable, "-m", "unittest", "discover", "-q", "-p", "test_*.py"])
    suite = subprocess.run(cmd, cwd=TREE, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    suite_tail = (suite.stdout + suite.stderr).strip().splitlines()
    write("suite.txt", "runner: %s\n\n%s" % (" ".join(cmd[1:]), suite.stdout + suite.stderr))
    suite_line = "%s%s" % (suite_tail[-1] if suite_tail else "no output",
                           "" if have_pytest else "  [PARTIAL: pytest not installed on the build machine]")
    print("    %s" % suite_line)

    floor = []
    if not a.skip_floor:
        print("==> coverage floor (every claim's guard removed, its tests must go red)")
        claims = ev.load_claims(HERE)
        floor = ev.run_floor(TREE, claims)
        for r in floor:
            print("    %-8s %-24s %s" % (r["status"], r["id"], r["reason"]))
            write("floor/%s.txt" % r["id"], "claim: %s\ntests: %s\npeer_written: %s\nmutation: %s\n"
                  "baseline rc=%s %s\nmutated  rc=%s %s\nstatus: %s (%s)\n"
                  % (r["claim"], ", ".join(r["tests"]), r["peer_written"],
                     json.dumps(claims_mutation(claims, r["id"]), ensure_ascii=False),
                     r["baseline_rc"], r["baseline_tail"], r["mutated_rc"], r["mutated_tail"], r["status"], r["reason"]))

    print("==> notary chapter (probes + a signed demo chain)")
    chain = demo_chain()
    status, probes = ev.run_notary_chapter(TREE)
    print("    chain: %s, probes: %s" % (chain.get("status"), status))

    write("MANIFEST.json", {"product": "sealed-bus", "version": a.version, "source_commit": commit,
                            "files": files, "file_count": len(files),
                            "built": {"python": sys.version.split()[0], "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                            "suite": suite_line, "suite_runner": " ".join(cmd[1:])})
    write("CLAIMS.json", {"floor_note": ev.load_claims(HERE)["floor_note"], "measured_utc":
                          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": floor,
                          "notary_probes": probes, "demo_chain": chain})
    ext = json.load(open(os.path.join(HERE, "external_arms.json"), encoding="utf-8"))
    if a.external_root:                                    # a pinelt artefaktumok ÚJRAMÉRÉSE egy helyi checkoutból
        for arm in ext["arms"]:
            for f in arm.get("files") or []:
                fp = os.path.join(a.external_root, f["path"])
                f["reverified"] = (os.path.isfile(fp) and ev.sha256_file(fp) == f["sha256"])
    write("EXTERNAL.json", ext)
    # MÁSODIK MENET: a suite-ot az ELKÉSZÜLT borítékkal is lefuttatjuk, és EZT írjuk a manifestbe. Az első menet a
    # RÉGI borítékot méri (a boríték önellenőrző tesztje ilyenkor jogosan piros), tehát az a sor nem a szállított
    # fáról szólna. A fájl-hash-eket ez nem érinti: a manifest a product/evidence/-et kihagyja.
    suite2 = subprocess.run(cmd, cwd=TREE, capture_output=True, text=True,
                            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    tail2 = (suite2.stdout + suite2.stderr).strip().splitlines()
    final_line = "%s%s" % (tail2[-1] if tail2 else "no output", "" if have_pytest else "  [PARTIAL: pytest not installed]")
    write("suite.txt", "runner: %s\n\nelso menet (a korabbi boritek ellen):\n%s\n\nmasodik menet (a kesz boritekkel):\n%s"
          % (" ".join(cmd[1:]), suite.stdout + suite.stderr, suite2.stdout + suite2.stderr))
    man = json.load(open(os.path.join(EV, "MANIFEST.json"), encoding="utf-8"))
    man["suite"], man["suite_first_pass"] = final_line, suite_line
    write("MANIFEST.json", man)
    print("==> suite (masodik menet, a kesz boritekkel): %s" % final_line)
    print("\nevidence written to %s (%.0fs)" % (EV, time.time() - t0))
    # WEAK is a REPORTED state of the evidence, not a build error: the mutation applied, something went red, and
    # no test decided. The envelope and the gate both name it, so a build that exits non-zero on it would make
    # the honest state indistinguishable from a broken one — and a script that always exits 1 stops being read.
    # FAIL still fails: that is a floor that measured nothing, or measured backwards.
    failed = [r["id"] for r in floor if r["status"] not in ("OK", "WEAK")]
    weak = [r["id"] for r in floor if r["status"] == "WEAK"]
    if weak:
        print("\n!! %d claim(s) are WEAK — the mutation applied and something went red, but no test DECIDED "
              "against it: %s\n   This is stated in chapter 3 and by the release gate; it is not a pass."
              % (len(weak), ", ".join(weak)))
    return 1 if failed or status == "FAIL" or chain.get("status") == "FAIL" or suite2.returncode else 0


def claims_mutation(claims, cid):
    for c in claims["claims"]:
        if c["id"] == cid:
            return c["mutation"]
    return {}


if __name__ == "__main__":
    sys.exit(main())
