#!/usr/bin/env python3
"""make_release_page.py — the distribution page, generated from the artifact, never typed by hand.

    python3 product/make_release_page.py --dist dist/ --version 1.5.3

Why a generator: a hand-written download page drifts. It keeps saying 1.4.0, or quotes a hash from the previous
build, or claims a chapter that the envelope reports as PENDING. Everything on this page is read out of the release
manifest, the evidence envelope and the README, so the page cannot claim more than the artifact proves. If an input
is missing, the page is not written at all.

Output (into --dist): index.md and index.html — self-contained, no external assets, no trackers, no scripts."""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence as ev  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
EV = os.path.join(HERE, "evidence")
BASE_URL = "https://zynko.dev/sealed-bus"


def read_json(path, what):
    if not os.path.isfile(path):
        raise SystemExit("missing input (%s): %s — build the artifact and the envelope first" % (what, path))
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def readme_section(title):
    """A README egy szakasza — hogy az oldal ne mondjon mást, mint a csomagban lévő szöveg."""
    src = open(os.path.join(HERE, "README.md"), encoding="utf-8").read()
    m = re.search(r"^## %s\s*$(.*?)(?=^## )" % re.escape(title), src, re.M | re.S)
    return (m.group(1).strip() if m else "")


def chapter_rows(claims, external):
    rows = [("1. integrity", "OK", "every shipped file re-hashed against the manifest"),
            ("2. the notary chain bites", "OK" if all(p.get("ok") for p in claims.get("notary_probes") or [])
             else "CHECK", "%d chain probes, run with the shipped code on your machine"
             % len(claims.get("notary_probes") or []))]
    floor = claims.get("results") or []
    ok = [r for r in floor if r["status"] == "OK"]
    rows.append(("3. coverage floor", "OK" if len(ok) == len(floor) and floor else "CHECK",
                 "%d/%d claims green with their guard, red without it" % (len(ok), len(floor))))
    arms = external.get("arms") or []
    measured = [a for a in arms if a.get("status") == "measured"]
    pending = [a for a in arms if a.get("status") != "measured"]
    rows.append(("4. independent arms", "REFERENCE" if measured else "PENDING",
                 "%d pinned second-implementation artifact set%s, %d item%s not pinned (never counted as passing)"
                 % (len(measured), "" if len(measured) == 1 else "s", len(pending), "" if len(pending) == 1 else "s")))
    return rows


def envelope_drift(man):
    """A kérdés nem az, hogy melyik commit — hanem hogy a boríték A SZÁLLÍTOTT FÁT írja-e le. Ezt a manifest
    fájl-hash-eivel mérjük (ugyanaz az ellenőrzés, amit a vevő futtat), nem git-tel: így egy git nélküli másolaton,
    és a vevő gépén is ugyanaz a válasz."""
    problems = ev.check_manifest(TREE, man)
    if problems:
        return "; ".join("%s: %s" % (p["file"], p["problem"]) for p in problems[:4])
    return None


def build(dist: str, version: str) -> dict:
    name = "sealed-bus-%s" % version
    rel = read_json(os.path.join(dist, "%s.release.json" % name), "release manifest")
    man = read_json(os.path.join(EV, "MANIFEST.json"), "evidence manifest")
    claims = read_json(os.path.join(EV, "CLAIMS.json"), "evidence claims")
    external = read_json(os.path.join(EV, "EXTERNAL.json"), "external arms")
    art = os.path.join(dist, "%s.tar.gz" % name)
    if not os.path.isfile(art):
        raise SystemExit("missing input (artifact): %s" % art)
    if man.get("version") != version:
        raise SystemExit("the evidence envelope is for version %s, the artifact for %s" % (man.get("version"), version))
    suite = man.get("suite", "")
    if re.search(r"\b(\d+ failed|failed|error)\b", suite, re.I) and "0 failed" not in suite:
        raise SystemExit("the release suite line is not green (%r) — no page is written for a red build" % suite)
    drift = envelope_drift(man)
    if drift:
        raise SystemExit("the evidence envelope does not describe the shipped tree: %s" % drift)
    ctx = {"version": version, "name": name, "sha256": rel["artifact_sha256"], "size": os.path.getsize(art),
           "commit": rel["source_commit"], "files": rel["file_count"], "suite": man.get("suite", ""),
           "chapters": chapter_rows(claims, external), "limits": readme_section("What it does not claim"),
           "measured_utc": claims.get("measured_utc", "")}
    os.makedirs(dist, exist_ok=True)
    md = render_md(ctx)
    open(os.path.join(dist, "index.md"), "w", encoding="utf-8").write(md)
    open(os.path.join(dist, "index.html"), "w", encoding="utf-8").write(render_html(ctx, md))
    return ctx


def render_md(c) -> str:
    lim = "\n".join("- %s" % l.lstrip("- ") for l in
                    re.findall(r"^- (.+?)(?=\n- |\n\n|\Z)", c["limits"], re.S | re.M))
    chap = "\n".join("| %s | %s | %s |" % r for r in c["chapters"])
    return f"""# Sealed Agent Bus {c['version']}

Multi-agent coordination with a notarized, tamper-evident audit trail. Every boundary event is written into a
hash-chained, signed, append-only log **before** it takes effect — and you can re-verify the copy you downloaded on
your own machine, offline, without trusting us.

## Download

| | |
|---|---|
| artifact | [`{c['name']}.tar.gz`]({BASE_URL}/{c['name']}.tar.gz) ({c['size']:,} bytes, {c['files']} files) |
| sha256 | `{c['sha256']}` |
| hash file | [`{c['name']}.tar.gz.sha256`]({BASE_URL}/{c['name']}.tar.gz.sha256) |
| source commit | `{c['commit']}` |
| test suite at release | {c['suite']} |

One command, which verifies the hash before unpacking anything:

```
curl -fsSL {BASE_URL}/install.sh | sh -s -- --version {c['version']}
```

The hash file is served from this host, so on its own it proves transfer integrity, not authenticity. If you got the
hash from us through another channel, pin it:

```
curl -fsSL {BASE_URL}/install.sh | sh -s -- --version {c['version']} --expect-sha256 {c['sha256']}
```

By hand instead, if you would rather not pipe into a shell:

```
curl -fO {BASE_URL}/{c['name']}.tar.gz
curl -fO {BASE_URL}/{c['name']}.tar.gz.sha256
sha256sum -c {c['name']}.tar.gz.sha256 && tar xzf {c['name']}.tar.gz
```

## Evidence, measured at release ({c['measured_utc']})

```
cd {c['name']} && ./product/verify_evidence.sh
```

| chapter | at release | what it checks on your machine |
|---|---|---|
{chap}

`PENDING` and `REFERENCE` never count as a pass: an unmeasured chapter is stated, not assumed. Chapter 4 becomes a
measurement on your machine with `--external-root <checkout of the pinned repository>`.

## What it does not claim

{lim}

## Pricing

Source-available (Business Source License 1.1): the bus, the notary, the fail-closed product mode, the evidence
envelope and the installer are published in full and free to download, read, modify and use in non-production — free
to download is not free to use. Production and commercial use need a commercial licence + an activated product key
(one key covers 2 machines, more → email). The introductory commercial price is €490; support, an audited deployment
by an independent second arm, and integration work are priced per engagement. The boundary is in `product/PRICING.md`
inside the artifact.
"""


def render_html(c, md) -> str:
    body = []
    for line in md.splitlines():
        body.append(html.escape(line))
    return ("<!-- generated by product/make_release_page.py; do not edit by hand -->\n"
            "<meta charset=\"utf-8\"><title>Sealed Agent Bus %s</title>\n"
            "<style>body{max-width:52rem;margin:2rem auto;padding:0 1rem;font:16px/1.55 system-ui,sans-serif}"
            "pre{white-space:pre-wrap;background:#f6f6f6;padding:.75rem;border-radius:4px}</style>\n"
            "<pre>%s</pre>\n" % (html.escape(c["version"]), "\n".join(body)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--version", required=True)
    a = ap.parse_args(argv)
    c = build(a.dist, a.version)
    print("page written: %s/index.md, %s/index.html (version %s, sha %s…)" % (a.dist, a.dist, c["version"],
                                                                              c["sha256"][:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
