# Pricing — source-available, draft

What this document fixes is the **boundary** — what is free, what is paid, and what we will not do — because that
boundary is a promise a buyer has to be able to read before talking to anyone. Under the Business Source License 1.1
the line is not "open core"; it is **production use**. Free to download is not free to use.

## What is free

Everything about the source except running it in production:

- **Download, read, copy, modify.** The whole tree is published — bus, notary, product-mode enforcement,
  reconciliation, the evidence envelope and its verifier, the one-command installer. Nothing is held back and no
  feature sits behind a build flag.
- **Non-production use** — evaluation, testing, development, research — is free of charge. No key, no account, no
  call-home. This is how you satisfy yourself that the claims hold before you pay for anything.

The reason the source is open is verification, not price: a buyer, a security reviewer or a competitor can read
every line and re-verify the shipped artifact offline. That is the moat, and it stays intact.

## What is paid

**Production and commercial use.** Under BSL the Additional Use Grant is *None*, so running the bus in production or
using it commercially requires a **commercial licence + an activated product key**. This is not a trial of the code
and not an "enterprise" edition: there is one codebase and the security posture is identical. Activation is a
terminal command (`sab activate`); one key covers **two machines**, and if you need more you email the Licensor.

| tier | what it is | what it is not |
|---|---|---|
| **Commercial licence** | permission to run the same code in production / commercially, plus the product key that activates it (`COMMERCIAL.md`) | not a different build and not an "enterprise" edition: one codebase, identical security posture |
| **Support** | a private channel with a stated response time, upgrade notes written for your deployment, and a say in what the next version fixes | not the licence itself: it is priced separately |
| **Audited deployment** | a one-off review of *your* deployment against the threat model by an independent second arm, handed over as a finding set you can show a third party | not a certificate and not a guarantee: findings are evidence, not absolution |
| **Integration work** | connecting the bus to your transports, identity and storage, and writing the conformance vectors for your own boundary | not a fork: what we build is the same code, or it is your code in your repository |

The introductory commercial licence price for the Sealed Agent Bus is **€490**. Support, audits and integration are
priced per engagement, as below.

## What we will not do

- **No per-seat telemetry, ever.** The bus is files on your disk; we never learn how many agents you run. The
  product key activates a machine, it does not phone home your usage.
- **No held-back features.** There is no "enterprise" build. The fail-closed product mode, the notary and the
  coverage floor are in the one codebase everyone reads. Selling the safety of the thing as an upgrade would be the
  wrong product.
- **No relicensing away from you.** On the Change Date (2030-09-20) each shipped version becomes AGPL-3.0-or-later.
  A version you hold cannot be taken back behind a stricter licence later.
- **No claim we cannot show.** Every number in the README is re-verifiable on the buyer's machine, and the chapters
  that are not measured say `PENDING` rather than nothing.

## How a price is justified

The commercial licence sells production permission for a product whose value you have already been able to verify
for free. Support is a time commitment, priced per year, per deployment — not per agent or per message. An audit is
work with a fixed output, priced per engagement; integration likewise. Nothing is priced on the volume of data
crossing the bus, because that would create an incentive to make the bus chattier.
