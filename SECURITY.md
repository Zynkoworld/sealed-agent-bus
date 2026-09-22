# Security Policy

  Sealed Agent Bus is built on a single principle — verify, don't trust — so its security posture
  is part of the product, not an afterthought. This document explains how to report a vulnerability and
  summarizes the hardening the bus already enforces.

  ## Reporting a vulnerability

  Please report security issues privately, not as a public issue or pull request.

  - Preferred: open a private report via GitHub's "Report a vulnerability" button under this
    repository's Security tab (GitHub private security advisories).
  - We aim to acknowledge a report within a few days and to keep you updated as it is triaged.

  When you report, please include: the affected version/commit, a minimal reproduction, the impact you
  observed, and — if possible — a proof of concept. A finding is most useful when it reproduces: a
  one-command, isolated, deterministic repro is worth more than a description.

  Please do not run tests against anyone else's live deployment. Reproduce on an isolated local
  target only.

  ## Supported versions

## Supported versions

The project is pre-1.0 in public terms; security fixes land on the default branch (main). Pin a
commit for reproducibility and re-verify the evidence envelope (python3 product/verify_evidence.py)
after updating.

## Hardening the bus already enforces

- Product mode (bus_enforce.py): in a release build, unsigned, forged, stale, and replayed
  messages are refused, fail-closed.
- Signed messages (Ed25519): senders are authenticated; a forged sender is detectable
  (signed | unsigned | forged), and a strict mode can require signatures.
- Notary (bus_notary.py): every accepted or rejected item at a trust boundary is a hash-chained
  entry with periodic Ed25519-signed checkpoints. Open content never enters the log — only hashes
  and metadata. Tampering, gaps, reordering, forged checkpoints and backdating are detectable
  offline.
- Append-only ledger: the bus never deletes; a removed entry leaves a detectable gap.

## Deployment note — the relay must sit behind a TLS proxy

If you expose the relay publicly, put it only behind a TLS-terminating, rate-limiting reverse
proxy. The built-in limits (known-recipient checks, per-recipient rate and queue caps, a total spool
cap) protect against flooding but do not replace the proxy. Do not expose the relay directly.

## Keyless operator switch is dev-only

AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1 disables operator-key enforcement and must be used only in a
dev/test environment. In production it is unsafe: anyone who writes under the operator's sender name
could wake or sleep agents. Leave it off in any real deployment.
