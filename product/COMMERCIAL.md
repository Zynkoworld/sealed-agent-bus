# Commercial licence (for production and commercial use)

The Sealed Agent Bus is released under the **Business Source License 1.1** (see `LICENSE` in the archive root). The
source is published in full so you can read it, review it, modify it and run it in non-production — evaluation,
testing, development, research — free of charge. That is deliberate: verifiability is the value, so the code is
visible. **Free to download is not free to use in production.**

A commercial licence exists for the line the BSL draws: **you want to run the bus in production, or use it
commercially.** Under BSL the Additional Use Grant is *None*, so any production or commercial use requires a
commercial licence from the Licensor **and** an activated product key. That is a licensing question, not a feature
question — the software is the same either way.

## Which one applies to you

| you… | what you need |
|---|---|
| read, copy or modify the source | nothing — the BSL grants that free of charge |
| evaluate, test, develop against or research the bus (non-production) | nothing — non-production use is free |
| run the bus in production, or use it in a commercial product or service | a **commercial licence** + an activated product key |

There is no copyleft to trigger and no §13 network clause to reason about: BSL is not a copyleft licence. The only
line is production/commercial versus non-production.

## Activation

Production use is gated by a terminal product-key activation:

```
sab activate <key>
```

One key covers **two machines**. If you need more, email the Licensor and we will issue what you need. (The
activation tooling is in progress; the mechanism is described here so the terms are legible before you adopt it.)

## What the commercial licence is, and is not

- **Is:** permission to run the same code in production and commercially, for a fee, with the terms agreed per
  engagement, plus the product key that activates it.
- **Is not:** a different or "enterprise" build. There is **one codebase**, and the security posture is identical
  whether you run it free in non-production or paid in production. The evidence envelope, the fail-closed product
  mode and the notary are in that one codebase for everyone.
- **Is not:** a support contract. Support is priced separately (`PRICING.md`); a commercial licence without support
  is fine.

## Why source-available rather than open or permissive

A permissive or open-now licence would give away the one thing the business sells: the right to run the bus in
production without paying. BSL keeps the source open to reading, review and modification — which is what makes the
product verifiable — while reserving production and commercial use for a paid licence. On the Change Date
(2030-09-20) each shipped version converts to AGPL-3.0-or-later, so nothing is locked away forever; the reserved
window is what funds the work. Free stays free where it should — inspection and non-production — and the paid track
sells production permission plus time and evidence, never the safety of the product.

## The precondition, and how it is kept

Selling a commercial licence requires the right to relicense **every** shipped file. That holds here for a specific
reason, not by assumption: the tree is written by us, and the review-written tests it ships verbatim come from the
partner arm, which is the same business — so the copyright is ours to relicense. Those tests stay in the archive on
purpose: an outside author is exactly what makes them evidence in the coverage floor.

Because the BSL licence depends on that, it is checked rather than remembered. `product/provenance.json` records the
origin of every shipped file, and the release preflight fails if a file is unlisted or marked third-party. A
genuinely external contribution would break it, so it is refused at release time instead of being discovered
afterwards.

Contact for commercial terms and activation keys: the product page.
