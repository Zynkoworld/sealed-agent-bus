# Sealed Agent Bus

Multi-agent coordination with a notarized, tamper-evident audit trail.

Autonomous agents already talk to each other. What is usually missing is the part a third party can check
afterwards: **what crossed the boundary, when, from whom, and what the machine refused**. The Sealed Agent Bus is
that part. It is a message bus for agents (local processes, or machines over SSH) where every boundary event is
written into a hash-chained, signed, append-only notary log **before** it takes effect, and where a buyer can
re-verify the shipped artifact offline, without trusting us.

Status: **1.5.3.** Every number in this document is measured and reproducible on
the shipped source; the chapters that are not yet measured say so.

---

## What it is

- **A bus, not a framework.** Append-only SQLite; `send` / `recv` / `ack` / `tail` / `thread`; a frozen schema with a
  `verify` command that exits non-zero on drift. Nothing is ever deleted: a refused message stays in the database
  with the reason recorded.
- **Notarized boundary.** Both remote transports (SSH exchange, HTTP relay) record every accepted, rejected and
  delivered item in `bus_notary`: a JSONL hash chain (`entry_hash = sha256(JCS(entry))`, each entry linked to the
  previous one), closed periodically by an Ed25519-signed checkpoint. The log holds **hashes and metadata only** —
  never message bodies, never sealed ciphertext (enforced by tests on both boundaries).
- **Log first, act second.** The notary entry is written *before* the message is inserted, before an attachment is
  stored, before the cursor moves, before replies are handed out. If the log cannot be written, the operation does
  not happen and the caller gets a fail-closed answer. Over-logging is allowed; under-logging is not.
- **Two-way reconciliation.** The remote side keeps its own receipts (what it sent, what it acknowledged, what it
  received, and the round's outcome). `bus_notary reconcile` compares receipts against an exported log slice in both
  directions, so neither a missing entry nor an invented one passes silently.
- **Product mode.** One switch (`AGENT_BUS_MODE=product`) turns the permissive development defaults into a
  fail-closed profile: unsigned messages, forged signatures, stale or future timestamps, replays and malformed
  attachment descriptors are refused at `recv`, the notary cannot be turned off, and unsigned cursor moves are
  refused.

## What it does not claim

Honesty is part of the product, so the limits are stated in the same place as the features:

- The notary proves **what the boundary recorded**, not that a message is true. Content-level proof is a separate
  layer (SDS), and the two layers are **not** wired together today.
- A gap in the sequence numbers proves that a written entry was **deleted**. It does not prove omission: an entry
  that was never written leaves no gap. That is what `reconcile` is for, and it needs the peer's receipts.
- The peer's receipt file is today the peer's own unsigned file. In a dispute it is word against word; a **signed**
  peer receipt is planned (v1.7), not shipped.
- In product mode the SSH transport does not yet deliver messages from a remote sender: the remote side cannot sign
  a bus row yet (v1.7). Measured, and written down rather than hidden.
- Isolation (jail) hardening is **not claimed**: no independent audit of a running deployment has closed yet. The
  independent-arm evidence this product does carry is about the canonical envelope layer (chapter 4), not isolation.

## What is in the box

| | |
|---|---|
| `agent_bus.py` | bus core: send / recv / ack / tail / thread / verify, Ed25519 row signing, signed cursor moves |
| `bus_enforce.py` | product-mode gate: unsigned / forged / stale / replay / bad attachment refusal, with reasons |
| `bus_notary.py` | hash-chained notary log, signed checkpoints, `export` / `verify` / `compare` / `reconcile` |
| `bus_ssh_exchange.py`, `bus_ssh_client.py`, `bus_ssh_enroll.py` | machine-to-machine transport over SSH force-command; the identity is pinned by the key, never taken from the payload |
| `bus_relay.py` | blind relay for sealed envelopes, signed pickup, SSE "you have mail" |
| `bus_attach.py` | content-addressed attachments (chunked, hash- and size-checked, quarantine instead of delete) |
| `bus_singleflight.py` | one-owner locks with liveness checks (a dead owner's lock never blocks) |
| `sds_envelope.py`, `sce_hook.py` | canonical (RFC 8785 JCS) envelope handling and the hook to the decision layer |
| `docs/` | design, schema, per-version development notes including the threat model |
| `product/` | this README, the installer, the evidence envelope and its verifier |

Python 3.12, standard library only, plus `cryptography` for Ed25519. No service to run, no account, no telemetry:
the bus is files on your disk. Licence: Business Source License 1.1 (source-available); production and commercial
use need a commercial licence + an activated product key (see below).

## Install (one command)

Distribution is from our own platform, versioned and hashed. The installer verifies the archive against the
published SHA-256 before unpacking anything:

```
curl -fsSL https://zynko.dev/sealed-bus/install.sh | sh -s -- --version 1.5.3
```

The same two steps by hand, if you prefer not to pipe into a shell:

```
curl -fO https://zynko.dev/sealed-bus/sealed-bus-1.5.3.tar.gz
curl -fO https://zynko.dev/sealed-bus/sealed-bus-1.5.3.tar.gz.sha256
sha256sum -c sealed-bus-1.5.3.tar.gz.sha256 && tar xzf sealed-bus-1.5.3.tar.gz
```

(The published artifact and its hash are produced by the release step; until the first publication these URLs are
placeholders — see `product/EVIDENCE_ENVELOPE.md`.)

## Evidence — check us, do not trust us

Every copy ships with an **evidence envelope**: the claims of this README as machine-checkable artifacts, plus one
command that re-verifies them on your machine, offline.

```
cd sealed-bus-1.5.3 && ./product/verify_evidence.sh
```

It re-computes the file hashes against the manifest, replays the notary chain and its signed checkpoints, and
re-runs the coverage floor: for every security claim there is a probe that must go **red** when the guard is removed.
A test suite that stays green after a guard is disabled is a silent green, and the floor is what forbids it.

The fourth chapter is the independent second implementation: the canonical envelope layer is implemented twice, by
two organizations, and the two byte-match on a pinned corpus (140/140 and 173 outputs, DIFFER 0). The envelope ships
the repository, commit and file hashes; `--external-root <checkout>` re-hashes them on your machine.

**Two things to expect when you run it yourself, said here rather than discovered:**

- **The key registry is root-owned by design.** The bus only reads a signing key if the file *and* its directory are
  owned by root and not group- or world-writable — that guard is what stops a local user from planting a key under
  someone else's name. As a consequence, roughly nineteen of the shipped tests are red for a non-root user. That is
  the guard working, not a broken build; run the suite as root, or point `AGENT_BUS_KEYS_DIR` at a directory you own
  and expect the registry-guard tests to be red.
- **The coverage floor is therefore weaker for a non-root runner.** The floor asks which tests change when a guard is
  removed; a test that was already red tells it nothing. A non-root run will report fewer proven claims than the
  number in the envelope, and the envelope says so in its third chapter rather than quoting the flattering figure.

- **The landing page's own files are outside the seal.** `README.md`, `SECURITY.md` and `assets/` are added to the
  public repository after the product is sealed; the manifest does not cover them and the verifier names them as
  uncovered. The seal is about the code you run, not the page you arrived on.

- **`source_commit` is a commit you cannot resolve, and the manifest says so.** It belongs to the private build
  repository; the public repository is a squash export, so `git cat-file` answers `bad object` — an independent arm
  measured exactly that on the published v1.5.1. The publicly re-derivable anchor is `content_digest`, a hash over
  the shipped files' hashes that the verifier recomputes on your machine
  (`sha256sum <the sealed paths> | LC_ALL=C sort -k2 | sha256sum`). Every manifest field is classified as either
  re-derived in public or unverifiable-in-public with a reason, and a field in neither class fails chapter 1 — so a
  check cannot go missing quietly.

Full description: `product/EVIDENCE_ENVELOPE.md`.

## Pricing (draft)

Source-available. The whole tree is published so you can read, modify and run it in non-production for free — free
to download is not free to use. Production and commercial use need a commercial licence and an activated product
key. What else is paid is the part that costs us time:

| | |
|---|---|
| **Non-production** | free: download, read, modify, and use for evaluation, testing, development and research |
| **Commercial licence** | production / commercial use of the same code, plus the product key that activates it (`sab activate`; one key covers 2 machines, more → email) |
| **Support** | per-year subscription: private issue channel, upgrade notes, response-time commitment |
| **Audited deployment** | one-off: your deployment reviewed against the threat model by an independent second arm, with the audit findings handed over as evidence |

The introductory commercial licence price is €490; support, audits and integration are priced per engagement. See
`product/PRICING.md` and `product/COMMERCIAL.md`.

## Licence and contact

**Source-available under the Business Source License 1.1** (`LICENSE` in the archive root). The whole product — bus,
notary, product mode, reconciliation, evidence envelope, installer — is published so you can read it, review it and
verify it. Nothing is held back and no feature sits behind a build flag. The source is visible so it can be
**verified**, not so that use is free: **free to download is not free to use.**

Downloading, reading, copying, modifying and **non-production** use (evaluation, testing, development, research) are
free. **Production and commercial use** require a **commercial licence** from the Licensor **and** an activated
product key — `sab activate`, one key covers two machines, more machines → email us. See `product/COMMERCIAL.md`.
There is no copyleft to reason about; BSL is not a copyleft licence.

On the **Change Date, 2030-09-20**, each version we shipped converts to **AGPL-3.0-or-later** (the Change License),
so nothing is locked away forever.

Third-party dependency: `cryptography` (Apache-2.0 / BSD-3-Clause, compatible). Everything else is the Python
standard library.

Contact and support channels are listed on the product page at zynko.dev.
