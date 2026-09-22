# Release checklist

Two rules frame everything below. **The one who builds is not the one who verifies** — the packaging and the
verdict are different people. And **a release needs two keys**: the person who built it does not land it alone.

The checklist has an executable spine, so the steps cannot quietly be skipped:

```
python3 product/release_preflight.py --version X.Y.Z
```

It exits non-zero and names the failing item. It writes nothing into the tree: every build goes to a temporary
directory. `--skip-slow` leaves out the full suite and the second reproducibility build — for a quick look only,
never for the release itself.

## Order of operations

| # | step | who | how it is checked |
|---|---|---|---|
| 1 | land the code | builder | working tree clean; the artifact is built from a commit, so uncommitted work would simply not ship |
| 2 | licence in the tree | owner decides once, then it stays | preflight item 2 refuses without it — the README promises a licence inside the archive |
| 3 | `python3 product/make_evidence.py --version X.Y.Z --commit HEAD [--external-root <checkout>]` | builder | refuses on a dirty tree; runs the suite twice and records the pass made against the finished envelope |
| 4 | commit **only** `product/evidence/` | builder | preflight item 5: the manifest's file hashes must match the shipped tree |
| 5 | `python3 product/make_release.py --version X.Y.Z --commit HEAD --out dist/` | builder | preflight item 7: built twice, byte-identical, or it is not a release |
| 6 | `python3 product/make_release_page.py --dist dist/ --version X.Y.Z` | builder | refuses on a red suite line or an envelope that does not describe the shipped tree |
| 7 | independent verification | **verifier, not the builder** | rebuilds from the same commit and compares the artifact hash; runs `./product/verify_evidence.sh` on an unpacked copy |
| 8 | publish artifact + hash file + page | owner / platform | the published hash is what the installer checks; hand the hash to buyers through a second channel as well |
| 9 | record the release | builder | version, commit, artifact sha256, and the evidence chapter statuses as they stood |

## What the verifier does, independently

1. Rebuild: `make_release.py` from the same commit, compare the artifact sha256 with the published one. Different
   hash means the published artifact is not what the repository says it is — stop.
2. Unpack the **published** archive (not the local build) and run `./product/verify_evidence.sh`. Chapters 1–3 must
   be `OK`. Chapter 4 is `REFERENCE` without a checkout of the pinned partner repository, and `OK` with one
   (`--external-root`).
3. Read the page: version, hash and suite line must match the artifact, and the "what it does not claim" section
   must still be there. A page that claims more than the envelope measures does not go up.

## Key operations — never done alone

Signing the published hash, rotating the notary key, and anything that touches a trust root are **owner
operations**. They are announced before and reported after; the builder does not perform them on their own
initiative. If a release needs one and the owner is not available, the release waits.

## When something fails

A failed preflight item is a stop, not a note. The two cases that look like failures but are not:

- **`PENDING` / `REFERENCE` in chapter 4** — an unmeasured chapter, stated honestly. Not a blocker for release;
  a blocker for *claiming* it.
- **A red envelope self-check right after a code commit** — the envelope still describes the previous tree. The fix
  is step 3, not a retry.

Everything else that is red stays red until it is fixed or the claim behind it is removed from the README.
