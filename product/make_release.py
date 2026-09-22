#!/usr/bin/env python3
"""make_release.py — build the published artifact from a pinned commit, reproducibly.

    python3 product/make_release.py --version 1.5.3 --commit <sha> --out dist/

Produces (in --out):
    sealed-bus-<version>.tar.gz          the artifact served from the distribution page
    sealed-bus-<version>.tar.gz.sha256   `sha256sum -c` format, the published hash
    sealed-bus-<version>.release.json    what went in: version, commit, per-file sha256, builder environment

Reproducible by construction: the file list and its order come from `git ls-tree` (sorted), every tar entry gets
uid/gid 0, mtime = the commit's author date, mode 0644/0755 only, and the gzip header carries no timestamp or name.
Building the same commit twice gives a byte-identical archive, so a buyer — or an independent reviewer — can rebuild
it and compare hashes instead of trusting the seller. stdlib only."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile

EXCLUDE_PREFIXES = ("dist/",)                     # never ship the build output itself


def shipped_names(repo, commit="HEAD"):
    """Exactly the files that go into the archive, sorted as the archive orders them.

    This is the ONE definition of "what ships". Anything that needs the list — a leak scan, an inventory —
    asks the packer instead of re-deriving it, because a second derivation drifts silently: one of them once
    filtered out product/evidence/ on its own, and the files nobody was looking at are where a stale log sat.

    The publish-time furniture is excluded here TOO, and that symmetry is the point. The verifier learned to
    treat README.md / SECURITY.md / assets/sab.png as outside the seal, but the packer did not, so building
    from the PUBLISHED repository picked them up and produced a different artifact hash than building from
    the development tree — 160 files against 157. The packer and the seal have to mean the same thing by
    "shipped", or the archive a buyer rebuilds is not the archive we signed. One list, read by both."""
    full = git(repo, "rev-parse", commit).strip()
    names = [n for n in git(repo, "ls-tree", "-r", "--name-only", full).splitlines() if n.strip()]
    return sorted(n for n in names if not n.startswith(EXCLUDE_PREFIXES) and n not in _unsealed())


def _unsealed():
    """The furniture list, from the module that owns the seal — not a second copy that can drift."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import evidence  # noqa: PLC0415 — deliberately late: keeps the packer importable on its own
    return set(evidence.UNSEALED)


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True)
    if p.returncode:
        raise SystemExit("git %s failed: %s" % (" ".join(args), p.stderr.strip()))
    return p.stdout


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build(repo: str, version: str, commit: str, out_dir: str) -> dict:
    full = git(repo, "rev-parse", commit).strip()
    when = int(git(repo, "show", "-s", "--format=%at", full).strip())
    names = shipped_names(repo, full)
    root = "sealed-bus-%s" % version
    files, buf = {}, io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:                    # uncompressed first, then a fixed-header gzip
        for name in names:
            blob = subprocess.run(["git", "-C", repo, "cat-file", "blob", "%s:%s" % (full, name)],
                                  capture_output=True).stdout
            mode = git(repo, "ls-tree", full, "--", name).split()[0]
            info = tarfile.TarInfo("%s/%s" % (root, name))
            info.size, info.mtime = len(blob), when
            info.mode = 0o755 if mode == "100755" else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(blob))
            files[name] = sha256_bytes(blob)
    raw = buf.getvalue()
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", compresslevel=9, mtime=0) as f:   # mtime=0: no timestamp in the header
        f.write(raw)
    data = gz.getvalue()
    os.makedirs(out_dir, exist_ok=True)
    art = os.path.join(out_dir, "%s.tar.gz" % root)
    with open(art, "wb") as f:
        f.write(data)
    digest = sha256_bytes(data)
    with open(art + ".sha256", "w", encoding="utf-8") as f:
        f.write("%s  %s.tar.gz\n" % (digest, root))
    rel = {"product": "sealed-bus", "version": version, "source_commit": full, "artifact": "%s.tar.gz" % root,
           "artifact_sha256": digest, "file_count": len(files), "files": files,
           "builder": {"python": sys.version.split()[0], "tar_format": "ustar", "reproducible": True}}
    with open(os.path.join(out_dir, "%s.release.json" % root), "w", encoding="utf-8") as f:
        json.dump(rel, f, indent=1, sort_keys=True)
        f.write("\n")
    return rel


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--out", default="dist")
    a = ap.parse_args(argv)
    rel = build(a.repo, a.version, a.commit, a.out)
    print("%s  %s" % (rel["artifact_sha256"], rel["artifact"]))
    print("source commit %s, %d files -> %s/" % (rel["source_commit"][:12], rel["file_count"], a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
