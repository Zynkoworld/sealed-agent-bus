#!/usr/bin/env python3
"""make_provenance.py — regenerate the origin inventory the BSL licence depends on.

    python3 product/make_provenance.py            # rewrite product/provenance.json
    python3 product/make_provenance.py --check    # fail if it is out of date (no write)

Source-available (BSL) licensing is only possible if every shipped file is ours to relicense, so the origin of each file is recorded
and the release preflight refuses anything unlisted or third-party. Keeping that list by hand would rot, so it is
generated: the file list comes from git, the default origin is first-party, and the known partner-written files
(the review-written tests, same business) are marked as such. A file whose origin cannot be decided mechanically is
written as `third-party`, which fails the release — the safe direction."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
OUT = os.path.join(HERE, "provenance.json")
PARTNER_PREFIXES = ("test_peer_",)              # a partner-kar (ugyanaz a vállalkozás) által írt, szó szerint szállított tesztek
# A közös review-vonal fájljai: némelyik a partner szondája szó szerint, némelyik a mi válaszunk ugyanarra a
# leletre. A kettő fájlnévből NEM megállapítható, és egy licenc-állítást nem tippelünk meg: ez a címke azt
# mondja, ami igaz — közös vonal, egy vállalkozás, a relicencelési jog ugyanaz.
JOINT_PREFIXES = ("test_joint_",)

RULE = ("Source-available (BSL) licensing is only possible because the copyright of every shipped file is ours to "
        "relicense. This "
        "inventory records the origin of each shipped file; the release preflight fails if a shipped file is not "
        "listed, or is listed as third-party. A genuinely external contribution would break the BSL licence, so "
        "it has to be refused at release time rather than discovered later.")
ORIGINS = {"first-party": "written by us (Zynkoworld), the default for this tree",
           "partner-same-business": ("written by the partner arm (Joint) — the same business, so the copyright "
                                     "is ours to relicense; these are the review-written tests, shipped verbatim on "
                                     "purpose because an outside author is what makes them evidence"),
           "joint-review-line": ("produced in the joint review line with the partner arm — some are the partner's "
                                 "probes taken verbatim, some were written here in answer to the same finding; the "
                                 "same business either way, so ours to relicense. Authorship is NOT separated file "
                                 "by file, and this label says so instead of guessing one"),
           "generated-here": ("produced by this tree's own tooling (make_evidence.py) out of first-party "
                              "sources — ours to relicense; listed rather than skipped, because an inventory "
                              "that says 'every shipped file' has to mean every file in the archive"),
           "third-party": "not ours — must not be shipped while the BSL licence stands"}
NOTE = ("LICENSE is the Business Source License 1.1; the licence template is (c) MariaDB Corporation Ab and is "
        "reproduced under its terms, and the Parameters (Licensor, Licensed Work, Additional Use Grant, Change Date, "
        "Change License) are ours.")


def build() -> dict:
    # The whole archive, generated evidence included — the list comes from the packer, so "every shipped file"
    # means every file that actually ships. It used to stop at product/evidence/, which made the inventory
    # cover 72 of the 87 files in the archive while claiming to cover all of them.
    sys.path.insert(0, HERE)
    import make_release  # noqa: PLC0415 — one definition of what ships
    files = make_release.shipped_names(TREE, "HEAD")
    origin = {f: ("partner-same-business" if os.path.basename(f).startswith(PARTNER_PREFIXES) else
                  "joint-review-line" if os.path.basename(f).startswith(JOINT_PREFIXES) else
                  "generated-here" if f.startswith("product/evidence/") else "first-party")
              for f in files}
    # A prefix that matches nothing quietly turns an authorship claim into "all ours" — which is what a rename
    # did once already. Zero matches is a defect in the rule, not a clean tree, so it fails loudly here.
    for prefix in PARTNER_PREFIXES + JOINT_PREFIXES:
        if not any(os.path.basename(f).startswith(prefix) for f in files):
            raise SystemExit("provenance: the partner prefix %r matches no shipped file — were those files "
                             "renamed or removed? Fix PARTNER_PREFIXES; do not ship an unchecked "
                             "authorship claim." % prefix)
    # Count each label by name, never as "everything that is not first-party": that negation quietly swallowed
    # a whole new category the moment one was added, and reported 15 generated files as partner-written.
    counts = {"total": len(files)}
    for label in ORIGINS:
        counts[label] = sum(1 for o in origin.values() if o == label)
    unknown = sorted(set(origin.values()) - set(ORIGINS))
    if unknown:
        raise SystemExit("provenance: origin label(s) with no definition in ORIGINS: %s" % ", ".join(unknown))
    return {"rule": RULE, "origins": ORIGINS, "files": origin, "counts": counts, "note_on_license_text": NOTE}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="only report whether the file on disk is current")
    a = ap.parse_args(argv)
    doc = build()
    text = json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    current = open(OUT, encoding="utf-8").read() if os.path.isfile(OUT) else ""
    if a.check:
        same = current == text
        print("provenance.json %s (%d files, %d partner-same-business)"
              % ("is current" if same else "IS OUT OF DATE — run without --check", doc["counts"]["total"],
                 doc["counts"]["partner-same-business"]))
        return 0 if same else 1
    open(OUT, "w", encoding="utf-8").write(text)
    c = doc["counts"]
    print("provenance.json: %d files, %s"
          % (c["total"], ", ".join("%d %s" % (c[k], k) for k in sorted(ORIGINS))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
