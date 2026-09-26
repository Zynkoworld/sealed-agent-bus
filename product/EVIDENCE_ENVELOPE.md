# Evidence envelope — design

Draft for review. The envelope turns the README's claims into artifacts a buyer can check **on their own machine,
offline, without trusting the seller**. One command, exit code 0 or 1.

The rule it exists to enforce: **no silent green.** A green test suite proves nothing unless the same suite goes red
when the guard it tests is removed. Every claim below therefore ships with a probe that must fail.

## Layout (inside the published artifact)

```
sealed-bus-<version>/
  product/
    verify_evidence.sh          # one command; runs chapters 1-3, prints a verdict per claim
    make_evidence.py            # how the envelope was produced (re-runnable by the buyer)
    evidence/
      MANIFEST.json             # version, file hashes, content digest, provenance classes, environment, suite result
      CLAIMS.json               # claim -> tests -> guard-off mutation -> measured result
      floor/<claim>.txt         # per claim: the mutation, the test command, the observed exit codes
      suite.txt                 # full test-suite output as produced at release time
      notary/                   # chapter 2 inputs: a released demo chain + its public key
      external/                 # chapter 3: hashes and provenance of the independent second arm
  ... the shipped source ...
```

`MANIFEST.json` is the anchor: the release version, the SHA-256 of every shipped file, the **content digest** over
those hashes, the provenance classes (below), the interpreter version used at release, and the suite result at
release time. The archive's own SHA-256 is published next to it on the distribution page, so the chain is:
published hash -> archive -> manifest -> every file.

## Chapter 1 — integrity of what you received, and provenance you can check

`verify_evidence.sh` re-computes the SHA-256 of every file listed in `MANIFEST.json` and compares.

- Any mismatch, missing or extra file is a hard failure.
- This is deliberately not a signature check: a signature would prove we signed it, not that you got what we
  shipped. The signature lives one level up, on the published hash. (Release signing is an owner/key operation and
  is listed as an open item, not silently implied.)

The chapter also checks the manifest's **provenance**, and it exists because of a measured defect. The published
v1.5.1 offered exactly one provenance field, `source_commit` — a commit of the **build** repository. The public
repository is a squash export, so that object is not in it: an independent arm resolved the commit and got
`bad object`. The one provenance field on offer was the one field a reader could not check. v1.5.5 answered that in
prose, which reads like a check without being one.

So the manifest now classifies **every** one of its fields, and the verifier enforces the classification:

| class | meaning | enforced as |
|---|---|---|
| `verifiable_in_public` | the verifier RE-DERIVES it on your machine | every listed name must have a real check behind it (`evidence.PUBLIC_CHECKS`), and that check runs |
| `unverifiable_in_public` | you cannot check it from a public clone | each entry must state a `reason` and a `covered_instead_by` — either a field that IS re-derived, or, out loud, `nothing — stated as an unchecked claim` |

A manifest field in **neither** class fails the chapter. That is the point: a check cannot go missing quietly, and
a field cannot be dropped instead of explained.

The anchor is `content_digest`, which is derivable from any fresh clone or unpacked archive:

```
sha256sum <the sealed paths> | LC_ALL=C sort -k2 | sha256sum
```

`source_commit` is still in the manifest — dropping it would hide the gap rather than close it — but it is marked
`unverifiable_in_public`, with the reason above, and points at `content_digest` as what covers it instead. The
verifier prints that line every run.

## Chapter 2 — the notary chain bites (run on your machine, not ours)

The verifier builds a **fresh** chain in a temporary directory using the shipped code, then attacks it and requires
the shipped `bus_notary verify` to catch each attack:

| probe | expected |
|---|---|
| clean chain with a signed checkpoint, correct `--pub` | `ok:true`, `trusted:true`, rc=0 |
| one entry edited | error at that seq, rc=1 |
| entry re-hashed after editing | chain breaks at the next entry; full re-chaining breaks the signed checkpoint |
| one entry deleted | gap reported, rc=1 |
| two entries swapped | reordered / chain broken, rc=1 |
| checkpoint signature forged, or signed by another key | forged / untrusted key, rc=1 |
| slice with no verified checkpoint | `trusted:false`; product mode refuses (rc=3) |
| two divergent exports compared | `fork`, first differing seq; no overlap is reported as "not comparable", never as "fine" |
| ack entry whose cursor target exceeds `max(from, ack)` | reported (`ack_target_violations`), rc=1 |

The same chapter also replays the **released** chain in `evidence/notary/` against its public key, so a buyer can see
a real chain, not only a synthetic one. The released chain contains no message bodies — by construction the log only
ever holds hashes and metadata, and a probe asserts that a known plaintext does not appear in it.

## Chapter 3 — coverage floor: every claim has a red probe

For each claim: a **mutation** (a minimal, mechanical edit of the shipped source in a temporary copy) and the tests
that must fail because of it. The floor passes only if every mutation makes its tests go red, and the unmutated tree
is green.

**What the floor actually measures, and what it once did not.** An independent arm attacked this chapter rather than
reading it, and found the engine weaker than the chapter sounded. It compared only the exit code, so a claim whose
run was `16 failed / 17 passed` before AND after the mutation carried no signal at all and still counted as proven.
It could not tell a test *deciding* against a mutation from the tree falling over with an `UnboundLocalError`. It
never looked at the other direction, where a mutation **resurrects** failing tests. And it ran the tests with a
different collector than the one this package ships. All four are closed: the engine now diffs the per-test outcome
**sets** between the clean and the mutated tree, classifies each new red as an assertion (a test decided) or an
exception (collateral damage), fails the claim if the mutation revives anything, and uses the shipped collector.

A claim killed only by collateral damage is reported as **WEAK** — its own state, neither a pass nor a crash —
because "the mutation applied and something went red" is not the same sentence as "a test caught it".

**The floor's strength depends on who runs it.** Measured on this build machine as root: **8 claims proven by
assertion, 1 WEAK** (`a log write failure blocks the operation` — its mutation kills only by exception). The same
floor measured by an independent arm as a NON-root user comes out weaker, and the reason is chapter-relevant rather
than cosmetic: the shipped tests assume a root-owned key registry, so ~19 of them are already red before any
mutation, and a set difference carries no signal on a test that was failing anyway. **A buyer running this floor as
a non-root user will not reproduce the number above**, and that is a property of the evidence, not a mistake in it.

| # | claim | guard-off mutation | tests that must go red |
|---|---|---|---|
| 1 | inbound is logged before it takes effect | move the notary call after `ab.send` | `test_peer_notary_failopen.py` (peer-written), inbound fail-closed tests |
| 2 | outbound replies and cursor moves are logged before hand-out | skip the outbound entries | `test_peer_outbound_notary.py` (peer-written), outbound tests |
| 3 | a log write failure blocks the operation | swallow the notary exception | fail-closed tests on both boundaries |
| 4 | omission and withholding are detectable | one-way reconcile (drop the reverse checks) | peer-written forgery tests, reconcile tests |
| 5 | a forged cursor target is rejected | drop the `T <= max(F, U)` bound | cursor-target tests |
| 6 | product mode refuses unsigned / forged / stale / replayed / malformed | let the enforce gate return ok | enforcement suite |
| 7 | the log never carries plaintext or ciphertext | log the body instead of its hash | leak tests on both boundaries |
| 8 | a dead owner's lock does not block | drop the liveness check | single-flight race tests |

Provenance matters here: the tests in claims 1, 2 and 4 were **written by the independent second arm** (the reviewing
party), not by us, and are shipped verbatim with their authorship recorded in `CLAIMS.json`. A vendor's own test
passing is weak evidence; a reviewer's test that the vendor could not weaken is stronger.

## Chapter 4 — independent arms (pinned, not promised)

The canonical envelope layer this product relies on is implemented **twice, by two organizations**, and the two
implementations byte-match on a pinned corpus. That is the authenticity core, and it exists **today**:

| | |
|---|---|
| arm A | org `zynko`, Python engine, impl `1572ed148c1c` |
| arm B | org `matesensei`, independent Rust crate, impl `127bf1a1e2e9` (v2 outputs at `ed7f4aeedb13`) |
| measured | `two_arm_compare.py` rc=0 — 140/140 pinned outputs byte-match; `verify_v2.py --two-arm` rc=0 — 173 outputs, DIFFER 0; `blind_attest_gate.py` rc=0 — each transcript bound to its own arm-signed attestation |
| pinned | repository + commit `a131d977…` + the sha256 of all ten artifacts, in `evidence/EXTERNAL.json` |

These artifacts are **not shipped inside the archive** — they belong to the partner line. What ships is the pin, so
the claim is checkable rather than asserted: with a checkout of that repository,

```
./product/verify_evidence.sh --external-root /path/to/that/checkout
```

re-hashes every pinned file and turns the chapter from `REFERENCE` into `OK` or `FAIL`. Without a checkout the
chapter reports `REFERENCE`, which — like `PENDING` — never counts as a pass.

Still open, and listed so the gap is visible rather than quietly omitted:

- **A further partner arm** (reported 231/231 two-arm byte-lock) is **not pinned here**: its commit and hashes are
  not available on this machine, so the envelope does not claim it.
- **A live isolation (jail) audit** by an independent auditor is months from maturity. The envelope deliberately does
  not depend on it; its findings will be an *additional* data point, not the basis of this chapter.

## Release flow (why the envelope is built in two commits)

The manifest hashes the files **of a commit**, and the envelope itself lives in the tree, so it is built in this
order — each step is re-runnable by anyone with the repository:

```
1. commit the code                                   # the tree the manifest will describe
2. python3 product/make_evidence.py --version X --commit HEAD
3. commit ONLY product/evidence/                     # the manifest excludes this directory, so it stays valid
4. python3 product/make_release.py --version X --commit HEAD --out dist/
```

Step 3 may not touch anything else: if it did, the manifest would describe a tree that is not the one shipped, and
chapter 1 would fail on the buyer's machine — which is exactly what it is for.

## Verdict format

`verify_evidence.sh` prints one line per claim (`OK` / `FAIL` / `PENDING`) and a final summary, and exits 1 if any
chapter fails. `PENDING` never counts as `OK`: an unmeasured chapter is stated as unmeasured, which is the same rule
the product applies to itself internally.

## Open items (not silently assumed)

1. Release signing of the published hash (key operation; owner decision).
2. Chapter 4's live-audit findings (independent auditor, in progress).
3. The external reference block's commit pin (filled at release from the second-arm line).
4. Distribution page layout and the exact URLs on the platform.
