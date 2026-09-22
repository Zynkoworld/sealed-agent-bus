# Licence — DECIDED: Business Source License 1.1 (source-available)

**Decision (owner, 2026-09-20): Business Source License 1.1 for the Sealed Agent Bus — source-available, not
open-source.** The source is published in full so it can be *verified*; it is not published so that use is free.
Free to download ≠ free to use.

- **Licence:** Business Source License 1.1 (BSL 1.1). Licensor: Zynkoworld (full legal names in `LICENSE`).
  Licensed Work: Sealed Agent Bus, (c) 2026 Zynkoworld.
- **What is free:** downloading, reading, copying, modifying, and **non-production** use — evaluation, testing,
  development, research. No key, no account, no call-home needed for any of that.
- **What is paid:** the Additional Use Grant is **None**, so **all production and commercial use** requires a
  commercial licence from the Licensor **and** an activated product key (`sab activate`; one key covers two
  machines, more machines → email the Licensor). Activation tooling is in progress.
- **Change Date:** 2030-09-20. **Change License:** AGPL-3.0-or-later. Each published version converts to
  AGPL-3.0-or-later on the Change Date (or the fourth anniversary of that version's first public distribution,
  whichever is first).

## Why this, and not open-source-now

The value of this product is that the whole boundary is inspectable: the notary, the fail-closed product mode, the
evidence envelope and its verifier are all in front of you, and a buyer can re-verify the shipped artifact offline.
**Verifiability is the moat** — a competitor cannot copy "you can check every claim on your own machine" by forking
the code, because the value is the evidence chain and the arm behind it, not secrecy. So the source stays visible.

But visible is not the same as free-to-run-in-production. An open-now licence would give away exactly the thing the
business sells: the right to put the bus into production without ever paying. BSL keeps the source open to reading,
review and modification while reserving production and commercial use — which is where the revenue is — for a paid
licence and an activated key. In 2030 each version we shipped becomes AGPL-3.0-or-later, so nothing is locked away
forever; the reserved window is what funds the work of shipping it.

## What this changed in the tree

- `LICENSE` at the archive root is now the Business Source License 1.1 with our Parameters block (Licensor, Licensed
  Work, Additional Use Grant = None, Change Date 2030-09-20, Change License AGPL-3.0-or-later).
- `product/COMMERCIAL.md` describes the commercial licence + activation path for production use.
- `product/PRICING.md` states the split: non-production free, production/commercial paid.
- `README` and the release page carry the BSL name and the "free to download ≠ free to use" line instead of the old
  open-core / AGPL framing.

## The precondition, unchanged

Licensing under BSL still requires the right to relicense **every** shipped file — the same precondition the dual
licence had, for the same reason. The tree is written by us, and the review-written tests it ships verbatim come
from the partner arm (the same business), so the copyright is ours. This is checked, not remembered:
`product/provenance.json` records the origin of every shipped file, and the release preflight fails if a file is
unlisted or marked third-party. A genuinely external contribution is refused at release time rather than discovered
later.

Nothing above is a legal opinion; it is the engineering record of the decision and what it changed in the tree.
