#!/usr/bin/env python3
"""verify_evidence.py — re-verify the evidence envelope on YOUR machine, offline.

    ./product/verify_evidence.sh            # chapters 1-4
    python3 product/verify_evidence.py --quick   # skip the coverage floor (chapters 1, 2, 4 only)

Chapters: (1) every shipped file against the manifest; (2) the notary chain probes, run with the shipped code;
(3) the coverage floor — every claim's guard removed from a copy, its tests must go red; (4) independent arms: the
pinned second-implementation byte-match (REFERENCE by default, re-hashed with --external-root) plus anything not yet
pinned, which stays PENDING. PENDING and REFERENCE never count as OK. Exit 0 only if no chapter failed."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import evidence as ev  # noqa: E402

EV = os.path.join(HERE, "evidence")


def load(name):
    p = os.path.join(EV, name)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="skip chapter 3 (the coverage floor takes minutes)")
    ap.add_argument("--external-root", default=None,
                    help="a local checkout of the partner repo: Chapter 4's pinned file hashes re-measured")
    ap.add_argument("--json", dest="as_json", action="store_true", help="machine-readable summary on stdout")
    a = ap.parse_args(argv)
    t0, chapters = time.time(), []

    manifest = load("MANIFEST.json")
    if manifest is None:
        chapters.append({"chapter": "1. integrity", "status": "FAIL", "detail": "product/evidence/MANIFEST.json is missing"})
    else:
        problems = ev.check_manifest(TREE, manifest)
        furniture = ev.unsealed_present(TREE)
        # The source commit belongs to the BUILD repository. A squash-published mirror does not contain it, and
        # an independent arm reasonably tried to resolve it and got "bad object". The seal's authority is the
        # file hashes, not the commit, so the commit is labelled as what it is instead of reading as a promise.
        chapters.append({"chapter": "1. integrity", "status": "OK" if not problems else "FAIL",
                         "detail": ("%d files match the manifest (version %s; build-repo commit %s — a "
                                    "squash-published mirror will not contain that object, the seal rests on "
                                    "the hashes)%s"
                                    % (len(manifest.get("files", {})), manifest.get("version"),
                                       (manifest.get("source_commit") or "")[:12],
                                       "" if not furniture else
                                       "; NOT covered by the seal (publish-time furniture): " + ", ".join(furniture)))
                                   if not problems else
                                   "; ".join("%s: %s" % (p["file"], p["problem"]) for p in problems[:5]),
                         "problems": problems, "unsealed": furniture})

    status, rows = ev.run_notary_chapter(TREE)
    bad = [r for r in rows if r.get("ok") is False]
    chapters.append({"chapter": "2. the notary chain bites", "status": status,
                     "detail": ("%d/%d probes behaved as claimed" % (len(rows) - len(bad), len(rows))) if status != "SKIP"
                               else "skipped: python3 'cryptography' is not installed",
                     "probes": rows})

    if a.quick:
        chapters.append({"chapter": "3. coverage floor", "status": "PENDING", "detail": "skipped with --quick"})
    else:
        claims = ev.load_claims(HERE)
        results = ev.run_floor(TREE, claims)
        failed = [r for r in results if r["status"] != "OK"]
        chapters.append({"chapter": "3. coverage floor", "status": "OK" if not failed else "FAIL",
                         "detail": "%d/%d claims are green with their guard and red without it"
                                   % (len(results) - len(failed), len(results)),
                         "claims": results})

    external = load("EXTERNAL.json") or {}
    arms = external.get("arms") or []
    lines, worst = [], "OK" if arms else "PENDING"
    for arm in arms:
        st = arm.get("status")
        if st == "measured":
            files = arm.get("files") or []
            if a.external_root:                            # we re-hash the pinned files on the buyer's own checkout
                bad = [f["path"] for f in files
                       if not (os.path.isfile(os.path.join(a.external_root, f["path"]))
                               and ev.sha256_file(os.path.join(a.external_root, f["path"])) == f["sha256"])]
                s_arm = "OK" if not bad else "FAIL"
                lines.append("%s %s: %d pinned files re-hashed%s" % (s_arm, arm["id"], len(files),
                                                                     "" if not bad else "; MISMATCH: " + ", ".join(bad[:3])))
                worst = "FAIL" if s_arm == "FAIL" else worst
            else:
                s_arm = "REFERENCE"
                lines.append("REFERENCE %s: %s @ %s, %d pinned files (re-check with --external-root DIR)"
                             % (arm["id"], arm.get("repository"), (arm.get("commit") or "")[:12], len(files)))
                worst = "PENDING" if worst == "OK" else worst
        else:
            lines.append("PENDING %s: %s" % (arm["id"], st))
            worst = "PENDING" if worst != "FAIL" else worst
    chapters.append({"chapter": "4. independent arms", "status": worst,
                     "detail": "; ".join(lines) if lines else "no external arms pinned",
                     "arms": arms})

    if a.as_json:
        print(json.dumps({"chapters": chapters, "seconds": round(time.time() - t0, 1)}, ensure_ascii=False, indent=1))
    else:
        print("Sealed Agent Bus — evidence envelope\n")
        for c in chapters:
            print("  %-8s %-28s %s" % (c["status"], c["chapter"], c["detail"]))
            for r in (c.get("claims") or []):
                if r["status"] != "OK":
                    print("           - %s: %s" % (r["id"], r.get("reason")))
            for r in (c.get("probes") or []):
                if r.get("ok") is False:
                    print("           - %s: %s" % (r.get("probe"), r.get("detail")))
        failed = [c["chapter"] for c in chapters if c["status"] == "FAIL"]
        pending = [c["chapter"] for c in chapters if c["status"] in ("PENDING", "SKIP")]
        print("\n  %s in %.0fs%s" % ("FAILED: " + ", ".join(failed) if failed else "all measured chapters passed",
                                     time.time() - t0,
                                     ("; not measured: " + ", ".join(pending)) if pending else ""))
        if pending and not failed:
            print("  (PENDING is not OK: an unmeasured chapter is stated, never assumed.)")
    return 1 if any(c["status"] == "FAIL" for c in chapters) else 0


if __name__ == "__main__":
    sys.exit(main())
