#!/usr/bin/env python3
"""verify_evidence.py — re-verify the evidence envelope on YOUR machine, offline.

    ./product/verify_evidence.sh            # chapters 1-4
    python3 product/verify_evidence.py --quick   # skip the coverage floor (chapters 1, 2, 4 only)

Chapters: (1) every shipped file against the manifest, plus the manifest's provenance — the content digest is
re-derived here from the shipped bytes, and a field a reader of the public repository cannot check (the build
repository's commit) has to be marked unverifiable-in-public with a reason; (2) the notary chain probes, run with the shipped code;
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
        # Two questions, not one. (a) is every sealed file byte-identical to the manifest, and (b) does the
        # manifest's PROVENANCE say anything a reader of the PUBLIC repository can check? `source_commit` belongs
        # to the BUILD repository, a squash-published mirror does not contain that object, and an independent arm
        # reasonably tried to resolve it and got "bad object". v1.5.5 answered that in prose, which reads like a
        # check and is not one. Now the seal carries a CONTENT DIGEST that is re-derived here from the shipped
        # bytes, the commit is marked unverifiable-in-public with its reason, and a manifest field that is
        # neither re-derived nor so marked FAILS the chapter — a check cannot go missing quietly.
        problems = ev.check_manifest(TREE, manifest) + ev.check_public_provenance(TREE, manifest)
        furniture = ev.unsealed_present(TREE)
        digest = ev.content_digest(ev.sealed_entries(TREE, manifest))
        notes = ev.provenance_notes(manifest)
        chapters.append({"chapter": "1. integrity", "status": "OK" if not problems else "FAIL",
                         "detail": ("%d files match the manifest (version %s); content digest %s re-derived here "
                                    "from the shipped bytes and it matches%s"
                                    % (len(manifest.get("files", {})), manifest.get("version"), digest[:12],
                                       "" if not furniture else
                                       "; NOT covered by the seal (publish-time furniture): " + ", ".join(furniture)))
                                   if not problems else
                                   "; ".join("%s: %s" % (p["file"], p["problem"]) for p in problems[:5]),
                         "problems": problems, "unsealed": furniture,
                         "content_digest": digest, "content_digest_recipe": ev.CONTENT_DIGEST_RECIPE,
                         "not_verifiable_in_public": notes})

    status, rows = ev.run_notary_chapter(TREE)
    bad = [r for r in rows if r.get("ok") is False]
    skip_why = next((r.get("reason") for r in rows if r.get("reason")), "python3 'cryptography' is unavailable")
    chapters.append({"chapter": "2. the notary chain bites", "status": status,
                     "detail": ("%d/%d probes behaved as claimed" % (len(rows) - len(bad), len(rows))) if status != "SKIP"
                               else "NOT MEASURED: %s" % skip_why,
                     "probes": rows})

    if a.quick:
        chapters.append({"chapter": "3. coverage floor", "status": "PENDING", "detail": "skipped with --quick"})
    elif not ev.have_pytest():
        # The floor runs the PRODUCT'S OWN runner or it is not the product's floor (see `ev.have_pytest`). Absent,
        # the chapter is stated as unmeasured — it used to read as nine measured failures.
        chapters.append({"chapter": "3. coverage floor", "status": "SKIP",
                         "detail": "NOT MEASURED: python3 'pytest' is not installed, and the floor is measured "
                                   "with the runner the product ships with, not with another one"})
    else:
        claims = ev.load_claims(HERE)
        results = ev.run_floor(TREE, claims)
        failed = [r for r in results if r["status"] not in ("OK", "PENDING")]
        unmeasured = [r for r in results if r["status"] == "PENDING"]
        chapters.append({"chapter": "3. coverage floor",
                         "status": "FAIL" if failed else ("PENDING" if unmeasured else "OK"),
                         "detail": "%d/%d claims are green with their guard and red without it%s"
                                   % (len(results) - len(failed) - len(unmeasured), len(results),
                                      "" if not unmeasured else "; %d NOT MEASURED" % len(unmeasured)),
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
            for n in (c.get("not_verifiable_in_public") or []):
                # Printed, not only recorded: a limit a reader has to open the JSON to find is a limit nobody reads.
                print("           - %s" % n)
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
