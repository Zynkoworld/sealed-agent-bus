#!/usr/bin/env python3
"""release_preflight.py — the release checklist with an executable spine.

    python3 product/release_preflight.py --version 1.5.3

A checklist that only exists as prose gets skipped under time pressure, and the step that gets skipped is the one
that would have caught the problem. Every item below is measured here; the script exits non-zero if any of them
fails, and it says which. It changes nothing: it builds into a temporary directory and never writes to the tree.

Items, in the order a release actually happens:
  1  working tree clean            — the artifact is built from a commit, so uncommitted work would not ship
  2  LICENSE present               — the README promises one inside the archive
  3  version consistent            — argument, declared release version and envelope agree; protocol same line
  4  suite green                   — the whole suite, run now, not the number someone remembers
  5  envelope describes this tree  — the manifest's file hashes against the tree (what the buyer checks)
  6  envelope chapters             — coverage floor all OK, chain probes all OK, chapter 4 pins present
  7  artifact reproducible         — built twice into two directories, byte-identical
  8  installer end to end          — install from a local file:// copy, hash verified, smoke check
  9  page generates                — and carries the artifact's own hash
 10  outgoing text clean           — the seller-facing pages against the same classes as item 12
 11  provenance: all ours          — every shipped file's origin is recorded, and none of it is third-party
 12  shipped text clean            — the same leak scan over the WHOLE archive: every class, every file;
                                    the SHAPE it matches is shipped, the ROSTER of names is not
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import evidence as ev  # noqa: E402
import make_release as mr  # noqa: E402 — one definition of what ships; the scanner asks the packer
import version as ver  # noqa: E402 — the release version, which is not the protocol version

EV = os.path.join(HERE, "evidence")
PY = sys.executable
# ── Leak classes: the SHAPE ships, the ROSTER does not ────────────────────────────────────────────────
# A leak scanner has two halves. One half is a property of the text: an e-mail address looks like an e-mail
# address in anyone's repository, and a link into someone's private notes has the same shape whoever wrote
# it. That half belongs in the open — it is the mechanism a buyer audits, and publishing it costs nothing.
#
# The other half is WHO we are: our agents, our machines, our colleagues, our model codenames. A scanner
# that carries that list ships the very roster it exists to keep out of the archive, and it does so in the
# one file a reader is most likely to open, because it is the file that proves the archive was checked.
# Up to 1.5.3 this file carried the roster. That is the leak this split closes.
#
# So the class names, the matching shapes, the exemptions and this entire mechanism are public; the terms
# are read at run time from a file named by AGENTBUS_LEAK_TERMS, which is neither committed nor shipped.
SHAPE = (
    # Addresses, minus the ones that cannot be ours: loopback, the unspecified address, and the ranges
    # RFC 5737 reserves for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Test fixtures
    # belong in those ranges precisely so a reader can tell an example from a real host.
    ("e-mail or IP", r"[A-Za-z0-9._%+-]+@(?!noreply\.anthropic|openssh\.com|example\.|[A-Za-z0-9.-]*\.invalid\b)"
                     r"[A-Za-z0-9.-]+\.[a-z]{2,}"
                     r"|\b(?!127\.0\.0\.1\b|0\.0\.0\.0\b|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"
                     r"(\d{1,3}\.){3}\d{1,3}\b"),
    # A link target starts with a word character: a regex character class in shipped code ("[[^\\]]")
    # is not a link into anyone's notes, and the first version of this pattern reported three of them.
    ("internal cross-reference", r"\[\[\w[^\]\n]{0,79}\]\]"),
    # Internal review ATTRIBUTION, which is a shape and not a roster: a ticket number, a severity label from
    # our own triage, a round reference, a dated "measured on" line. This is the half of an internal comment
    # that has to go. The other half — WHY the guard is there — is worth more to a buyer than to us and stays.
    # Keeping the two apart is the whole rule: the technical reason ships, the who/when/which-ticket does not.
    # It is deliberately a SHAPE class: it keeps working when the roster changes, and it needs no names to
    # be published in order to work. Measured on 1.5.3: 30 ticket numbers, 141 severity labels and 29 dated
    # review lines were standing in the archive.
    #
    # What is NOT in it, and why: "round" and "kör" were, and they fired on the protocol's own vocabulary —
    # round_seq, round_close, "a kör-bejegyzés". A leak class that matches the product's domain language
    # produces hits nobody can act on, and a gate whose hits are routinely waved through stops being a gate.
    # "támadókör" stays: that one is only ever our own review.
    ("internal review attribution",
     # A jegyszám EGYJEGYŰ is lehet. Az első változat 2-5 számjegyet kért, és pontosan emiatt maradt bent
     # egy "#6 15:37Z BLOCKER:" attribúció a szállított product/claims.json-ban — a kapu tisztát mondott.
     r"(?i)(?<![\w&])#\d{1,5}\b"
     # Súlyossági címke számmal ÉS anélkül: a "BLOCKER:" önmagában is a mi triázsunk szava.
     r"|\b(?:HIGH|MEDIUM|LOW|BLOCKER|CRITICAL|KRITIKUS|NIT)(?:-\d)?\s*(?:\([^)\n]{0,12}\))?\s*:"
     r"|\b(?:HIGH|MEDIUM|LOW|BLOCKER|CRITICAL|KRITIKUS)-\d\b"
     r"|\bt[áa]mad[óo]k[öo]r\b"
     # Belső időbélyeg (a kör órája), csonka alakban is — a scrub ilyen törmeléket hagy maga után.
     # ...de NEM egy ISO-8601 időbélyeg belsejében: a "2026-09-21T19:06:42Z" mérési idő a publikált
     # bizonyítékban legitim, és az első változat a "06:42Z" darabját leletnek jelentette. Egy kapu,
     # aminek a találatait rutinból legyintik le, megszűnik kapu lenni.
     r"|(?<![\d:])\d{1,2}:\d\d[Zz]\b|(?<=#\s)\d{1,2}[Zz]\b"
     r"|\b20\d\d-\d\d-\d\d[^\n]{0,20}\b(?:blocker|review)\b"),
)

ROSTER_ENV = "AGENTBUS_LEAK_TERMS"

#: Words that make an ordinary English word read as a model codename. Public on purpose: it is the shape,
#: not the roster — knowing that we look near the word "model" tells a reader nothing about our models.
MODEL_CONTEXT = r"model|modell|arm|kar|codename|k[óo]dn[ée]v|llm|impl|pin"

#: How a term of each class may appear in text. `%s` takes the alternation of the configured terms.
ROSTER_SHAPE = {
    # A path fragment carries its own boundaries; matching it as written is the whole rule.
    "internal path": r"%s",
    # A szóhatár (\b) az ALÁHÚZÁST szó-karakternek veszi, ezért egy azonosítóba tapadt név — `<nev>_entitlement`,
    # `<nev>_bus_adapter` — ÁTMEGY rajta. Mérve ezen a fán, MIUTÁN a sétát tisztának mondtam: két ilyen állt a
    # szállított kódban. Ugyanaz a vakfolt, mint a gépneveknél; a határ ezért betűre/számjegyre szól, nem \b-re.
    "internal agent name": r"(?i)(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])",
    # A machine name gets concatenated into identifiers — a host "foo2" turns up as "foo2test" — and a
    # trailing \b steps over exactly those. Measured on the published 1.5.3: of the 7 occurrences of one
    # machine name in the shipped set, 2 were of that form and a \b-anchored pattern found neither.
    "internal hostname": r"(?i)\b(?:%s)\w*",
    # Hungarian case endings: a bare \b misses the suffixed forms ("Ödönyinek", "Kovácsnak"), which is how a
    # private note once slipped
    # past the first version of this check.
    "internal person name": r"(?i)(?<![A-Za-z0-9])(?:%s)(nak|nek|val|vel|t[óo]l|t[őo]l|r[óo]l|r[őo]l|hoz|hez|ban|ben|"
                            r"ba|be|n[áa]l|n[ée]l|ra|re|[ée]k|[ée]|t|n)?(?![A-Za-z0-9])",
    # Model codenames double as ordinary English words, so a bare term fires on every cable in the tree.
    # The term counts only NEAR a model-ish word, in either order, on the same line.
    "internal model name": None,                    # built by _contextual()
}
ROSTER_CLASSES = tuple(ROSTER_SHAPE)


class LeakRosterError(RuntimeError):
    """The roster was asked for and could not be honoured. Never raised for 'no roster configured'."""


def _contextual(terms):
    t, c = "(?:%s)" % terms, "(?:%s)" % MODEL_CONTEXT
    return r"(?i)\b%s\b(?=[^\n]{0,60}\b%s\b)|\b%s\b[^\n]{0,60}?\b%s\b" % (t, c, c, t)


def load_roster():
    """-> (patterns, note, configured). Three states, and the middle one is the reason this exists.

    NOT CONFIGURED is visible and does not fail: a buyer holds no roster of ours and must still be able to
    run this gate on the archive they received. CONFIGURED-BUT-BROKEN fails hard — someone meant a roster to
    be enforced and it silently was not, which is the exact failure class this whole file is here to stop.
    CONFIGURED is enforced. A release run of our own passes --require-roster, so for us the first state is a
    failure too; the flag is what makes "we forgot the roster" impossible to ship past."""
    path = os.environ.get(ROSTER_ENV, "").strip()
    if not path:
        return [], "roster NOT CONFIGURED (%s unset) — shape classes only" % ROSTER_ENV, False
    if not os.path.isfile(path):
        raise LeakRosterError("%s points at %s, which does not exist" % (ROSTER_ENV, path))
    try:
        cfg = json.load(open(path, encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise LeakRosterError("%s (%s) could not be read: %s" % (ROSTER_ENV, path, e))
    if not isinstance(cfg, dict):
        raise LeakRosterError("%s (%s) must hold an object of class -> [terms]" % (ROSTER_ENV, path))
    # A key starting with "_" is a note to whoever maintains the roster; everything else must name a class
    # this scanner has a shape for. A typo in a class name would otherwise disable that class in silence.
    unknown = sorted(k for k in set(cfg) - set(ROSTER_SHAPE) if not k.startswith("_"))
    if unknown:
        raise LeakRosterError("%s names classes this scanner has no shape for: %s" % (ROSTER_ENV, ", ".join(unknown)))
    pats, counts = [], []
    for name in ROSTER_CLASSES:
        terms = [str(t) for t in cfg.get(name, []) if str(t).strip()]
        if not terms:
            continue
        alt = "|".join(re.escape(t) for t in terms)
        shape = ROSTER_SHAPE[name]
        pats.append((name, _contextual(alt) if shape is None else shape % alt))
        counts.append("%s:%d" % (name.replace("internal ", ""), len(terms)))
    if not pats:
        raise LeakRosterError("%s (%s) is configured but holds no terms" % (ROSTER_ENV, path))
    # The note carries COUNTS, never the terms: this line is printed, and a printed roster is the leak again.
    return pats, "roster configured (%s), %d classes [%s]" % (os.path.basename(path), len(pats), " ".join(counts)), True

#: The files that ARE the patterns: the scanner, and the tests that plant a leak on purpose to prove the
#: scanner catches it. A named list of files, never a directory — an exemption that can only be widened
#: by naming another file cannot quietly grow to cover a directory that later fills with generated text.
PATTERN_HOLDERS = ("product/release_preflight.py", "product/test_product_page.py",
                   "product/test_product_packaging.py")

#: A class may be exempt in ONE named file, never a whole file and never a directory.
#:
#: This table is EMPTY, and the story of how it emptied is the point. It once held
#: {"LICENSE": ("internal person name",)}, because a licence must name its licensor or nobody can tell who
#: granted the rights — a real, stated reason for a real exemption. (Before that it was worse: LICENSE fell
#: outside the strict scope because it has no file extension. The right result for the wrong reason —
#: accidental, not decided.) The owner then chose to license under the company name alone, so the reason is
#: gone, and with it the exemption. An exemption that outlives its reason is just a hole with a comment on it.
#:
#: A test holds this table to at most one file, so it cannot quietly grow back.
CLASS_EXEMPT = {}

#: Set from --require-roster. Our own release runs with it, so "we forgot the roster" cannot ship; a buyer
#: runs without it, because they hold no roster of ours and must still be able to check their archive.
REQUIRE_ROSTER = False


def leak_patterns():
    """Every (class, pattern) this scan enforces: the shape classes always, the roster classes when
    configured. -> (patterns, note, configured)"""
    roster, note, configured = load_roster()
    return list(SHAPE) + roster, note, configured


def run(cmd, cwd=None, timeout=1800):
    p = subprocess.run(cmd, cwd=cwd or TREE, capture_output=True, text=True, timeout=timeout,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return p.returncode, (p.stdout + p.stderr)


def check_clean(_):
    rc, out = run(["git", "status", "--porcelain"])
    dirty = [l[3:] for l in out.splitlines() if l[3:].strip()]
    return (not dirty), ("clean" if not dirty else "uncommitted: " + ", ".join(dirty[:4]))


def check_license(_):
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        p = os.path.join(TREE, name)
        if os.path.isfile(p) and os.path.getsize(p) > 200:
            return True, "%s (%d bytes)" % (name, os.path.getsize(p))
    return False, "no LICENSE in the tree — the README promises one inside the archive"


def check_version(version):
    """The release version and the protocol version are two different claims, so they are checked as two.

    The argument, the declared release version and the envelope must agree exactly; the protocol only has to
    be on the same MAJOR.MINOR line. Requiring the protocol to equal the release version would mean a
    packaging fix announces a protocol change to every peer on the wire, which is a lie about the contract."""
    man = json.load(open(os.path.join(EV, "MANIFEST.json"), encoding="utf-8")) if os.path.isfile(
        os.path.join(EV, "MANIFEST.json")) else {}
    rc, out = run([PY, "-c", "import agent_bus; print(agent_bus.PROTOCOL_VERSION)"])
    proto = out.strip().splitlines()[-1] if rc == 0 else "?"
    declared = ver.RELEASE_VERSION
    ok = man.get("version") == version and declared == version and ver.same_line(version, proto)
    return ok, "release %s (declared %s), envelope %s, protocol %s%s" % (
        version, declared, man.get("version"), proto, "" if ok else " — MISMATCH")


def check_suite(_):
    rc, out = run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    last = out.strip().splitlines()[-1] if out.strip() else "no output"
    return rc == 0, last


def check_envelope_fresh(_):
    man_path = os.path.join(EV, "MANIFEST.json")
    if not os.path.isfile(man_path):
        return False, "no envelope: run make_evidence.py"
    problems = ev.check_manifest(TREE, json.load(open(man_path, encoding="utf-8")))
    return (not problems), ("every shipped file matches the manifest" if not problems else
                            "; ".join("%s: %s" % (p["file"], p["problem"]) for p in problems[:3]))


def check_chapters(_):
    cp = os.path.join(EV, "CLAIMS.json")
    xp = os.path.join(EV, "EXTERNAL.json")
    if not (os.path.isfile(cp) and os.path.isfile(xp)):
        return False, "the envelope is incomplete"
    claims = json.load(open(cp, encoding="utf-8"))
    ext = json.load(open(xp, encoding="utf-8"))
    floor = claims.get("results") or []
    # WEAK is its own state, not a pass and not a crash: the mutation applied and something went red, but every
    # red was the tree falling over rather than a test DECIDING against the claim. It is reported separately so
    # "floor 9/9" can never again stand for a set where some claims were only measured by collateral damage.
    weak_floor = [r["id"] for r in floor if r["status"] == "WEAK"]
    bad_floor = [r["id"] for r in floor if r["status"] not in ("OK", "WEAK")]
    probes = claims.get("notary_probes") or []
    bad_probe = [p.get("probe") for p in probes if p.get("ok") is False]
    pinned = [a for a in (ext.get("arms") or []) if a.get("status") == "measured"]
    ok = floor and not bad_floor and probes and not bad_probe and pinned
    proven = len(floor) - len(bad_floor) - len(weak_floor)
    return ok, "floor %d/%d PROVEN%s, chain probes %d/%d, chapter 4 pinned arms %d%s" % (
        proven, len(floor),
        "" if not weak_floor else " (+%d weak: %s)" % (len(weak_floor), ", ".join(weak_floor)),
        len(probes) - len(bad_probe), len(probes), len(pinned),
        "" if ok else " — " + ", ".join(bad_floor + [str(b) for b in bad_probe]))


def check_reproducible(version, keep=None):
    outs = []
    for i in (1, 2):
        d = keep if (keep and i == 1) else tempfile.mkdtemp()
        rc, out = run([PY, os.path.join(HERE, "make_release.py"), "--version", version, "--commit", "HEAD",
                       "--repo", TREE, "--out", d])
        if rc:
            return False, out.strip().splitlines()[-1][:120]
        outs.append(json.load(open(os.path.join(d, "sealed-bus-%s.release.json" % version)))["artifact_sha256"])
    return outs[0] == outs[1], "two builds: %s / %s" % (outs[0][:16], outs[1][:16])


def check_installer(version, dist):
    with tempfile.TemporaryDirectory() as t:
        rc, out = run(["sh", os.path.join(HERE, "install.sh"), "--version", version, "--url", "file://" + dist,
                       "--prefix", t, "--expect-sha256",
                       open(os.path.join(dist, "sealed-bus-%s.tar.gz.sha256" % version)).read().split()[0]])
        ok = rc == 0 and os.path.isfile(os.path.join(t, "sealed-bus-%s" % version, "agent_bus.py"))
        return ok, ("installed and smoke-checked from a local copy" if ok else out.strip().splitlines()[-1][:120])


def check_page(version, dist):
    rc, out = run([PY, os.path.join(HERE, "make_release_page.py"), "--dist", dist, "--version", version])
    if rc:
        return False, out.strip().splitlines()[-1][:140]
    md = open(os.path.join(dist, "index.md"), encoding="utf-8").read()
    sha = json.load(open(os.path.join(dist, "sealed-bus-%s.release.json" % version)))["artifact_sha256"]
    return sha in md, "page written, artifact hash %s" % ("present" if sha in md else "MISSING")


def check_outgoing_text(_, dist=None):
    pats, _note, _cfg = leak_patterns()
    files = [os.path.join(HERE, n) for n in ("README.md", "PRICING.md", "EVIDENCE_ENVELOPE.md")]
    if dist and os.path.isfile(os.path.join(dist, "index.md")):
        files.append(os.path.join(dist, "index.md"))
    hits = []
    for f in files:
        if not os.path.isfile(f):
            continue
        txt = open(f, encoding="utf-8").read()
        for name, pat in pats:
            m = re.search(pat, txt)
            if m:
                hits.append("%s: %s (%r)" % (os.path.basename(f), name, m.group(0)[:30]))
    return (not hits), ("%d outgoing files clean" % len(files) if not hits else "; ".join(hits[:3]))


def shipped_files():
    """Every file the packer ships, plus anything staged but not yet committed.

    It asks make_release for the list instead of re-deriving it. The first version re-derived it and dropped
    product/evidence/ on its own: 87 files shipped, 72 were scanned, and one of the 15 nobody walked was a
    stale suite log still naming deleted private files. A scan proves only as much as it walks."""
    names = set(mr.shipped_names(TREE, "HEAD"))
    rc, out = run(["git", "ls-files"])            # uncommitted work too, so a leak shows up before release day
    names |= {f for f in out.split() if not f.startswith(mr.EXCLUDE_PREFIXES)}
    return sorted(names)


def scan_shipped(pats, docs=None):
    """Shipped files against the given (class, pattern) pairs. Returns (hits, files_scanned).

    `docs`: True = only the shipped documentation (*.md), False = everything else, None = both.

    The buyer receives the whole archive, not just the README, so the leak scan has to cover the whole archive —
    otherwise the gate proves something narrower than what it is read as proving. Nothing is skipped by
    directory: the only exemption is PATTERN_HOLDERS, which is a list of NAMED files, so an exemption cannot
    quietly grow to cover a directory that later fills up with generated text."""
    hits, scanned = [], 0
    for f in shipped_files():
        # A minta-tartó mentesség CSAK az ALAK-osztályokra szól, mert azokra van indoka: ezek a fájlok
        # e-mail- és IP-ALAKÚ mintákat, attribúció-példákat és beültetett leleteket hordoznak, azoktól
        # tisztává tenni őket értelmetlen. A NÉVSOR-osztályokra viszont NINCS indok: a névsor 1.5.4 óta
        # nem a kódban él, tehát egy minta-tartónak semmi oka valódi nevet tartalmaznia.
        #
        # Ez nem elméleti szigorítás. Egy ellenpróba-teszt, amit ÉN írtam ebbe a fájlba, a valódi
        # licencadó-nevet használta példaként — és mivel a mentesség akkor MINDEN osztályra szólt, a séta
        # nullát jelentett, miközben a név BENNE VOLT a kicsomagolt archívumban. A fa-szintű nulla nem
        # ugyanaz, mint "az archívumban nincs név", amíg egy kivétel a kettő közé áll.
        holder_classes = {n for n, _ in SHAPE} if f in PATTERN_HOLDERS else set()
        if docs is not None and f.endswith(".md") != docs:
            continue
        p = os.path.join(TREE, f)
        if not os.path.isfile(p):
            continue
        try:
            txt = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        exempt = set(CLASS_EXEMPT.get(f, ())) | holder_classes
        for name, pat in pats:
            if name in exempt:
                continue
            for m in re.finditer(pat, txt):
                hits.append("%s: %s (%r)" % (f, name, m.group(0)[:40]))
    return hits, scanned


def unscanned_shipped():
    """Files that go in the archive but no scan walks. This is the check on the check.

    A leak scan is read as "nothing internal ships", and that reading is only true if the set it walks is the
    set that ships. Those were two different sets once, and the difference grew in silence — so the difference
    is measured here and reported as a number next to the other one, not assumed to be zero."""
    packed = set(mr.shipped_names(TREE, "HEAD"))
    walked = {f for f in shipped_files() if f not in PATTERN_HOLDERS
              and os.path.isfile(os.path.join(TREE, f))}
    return sorted(packed - walked - set(PATTERN_HOLDERS))


def check_shipped_text(_):
    """The leak scan over the WHOLE archive, every class, every shipped file.

    Until 1.5.4 the enforced set narrowed as it moved from documentation to code: docs were held to every
    class, code only to path, address and model name. Measured on the published 1.5.3, that left 175 matches
    of names the scanner ALREADY KNEW standing in shipped code, because the class that knew them was reported
    and not enforced. Two separate holes wore one name: a roster that was missing terms, and a roster whose
    terms were not enforced where they actually occurred. Widening the roster alone would have fixed neither."""
    blind = unscanned_shipped()
    if blind:
        return False, "%d shipped file(s) no scan walks: %s" % (len(blind), ", ".join(blind[:4]))
    try:
        pats, note, configured = leak_patterns()
    except LeakRosterError as e:
        return False, "leak roster: %s — configured and not honoured is a silent downgrade, so it stops here" % e
    if REQUIRE_ROSTER and not configured:
        return False, "%s; --require-roster was given, and a release of ours does not go out with the roster " \
                      "classes unchecked" % note
    hits, n = scan_shipped(pats)
    packed = len(mr.shipped_names(TREE, "HEAD"))
    if hits:
        return False, "%d hit(s): %s" % (len(hits), "; ".join(hits[:4]))
    return True, ("%d of %d shipped files walked, %d exempt as pattern holders, %d class exemption(s); "
                  "%d class(es) enforced; %s" % (n, packed, len(PATTERN_HOLDERS),
                                                 sum(len(v) for v in CLASS_EXEMPT.values()), len(pats), note))


def check_provenance(_):
    """A BSL alatt licencelni CSAK saját (vagy egy-vállalkozáson belüli) szerzői joggal lehet: minden szállított fájl
    eredete rögzítve, és ami nincs a listán vagy harmadik féltől van, az MEGÁLLÍTJA a kiadást."""
    pp = os.path.join(HERE, "provenance.json")
    if not os.path.isfile(pp):
        return False, "product/provenance.json is missing — the BSL licence needs a recorded origin per file"
    doc = json.load(open(pp, encoding="utf-8"))
    origins = doc.get("files", {})
    # The whole archive, generated evidence included. This list used to stop at product/evidence/, so an
    # inventory that reads "every shipped file" covered 72 of the 87 that ship — the same blind spot as the
    # leak scan, one claim over.
    shipped = mr.shipped_names(TREE, "HEAD")
    unlisted = [f for f in shipped if f not in origins]
    third = [f for f, o in origins.items() if o == "third-party"]
    gone = [f for f in origins if f not in shipped]
    bad = unlisted + third
    counts = {}
    for f in shipped:
        counts[origins.get(f, "?")] = counts.get(origins.get(f, "?"), 0) + 1
    detail = "%d files: %s" % (len(shipped), ", ".join("%d %s" % (n, k) for k, n in sorted(counts.items())))
    if bad:
        detail = "unlisted: %s; third-party: %s" % (", ".join(unlisted[:3]) or "-", ", ".join(third[:3]) or "-")
    elif gone:
        detail += " (stale entries: %s)" % ", ".join(gone[:3])
    return (not bad), detail


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--skip-slow", action="store_true", help="skip the suite and the second reproducibility build")
    ap.add_argument("--require-roster", action="store_true",
                    help="fail item 12 unless %s names a readable roster (use this for our own releases)" % ROSTER_ENV)
    a = ap.parse_args(argv)
    global REQUIRE_ROSTER
    REQUIRE_ROSTER = a.require_roster
    dist = tempfile.mkdtemp()
    items = [("1  working tree clean", check_clean),
             ("2  LICENSE present", check_license),
             ("3  version consistent", check_version),
             ("4  suite green", (lambda v: (None, "skipped")) if a.skip_slow else check_suite),
             ("5  envelope describes this tree", check_envelope_fresh),
             ("6  envelope chapters", check_chapters),
             ("7  artifact reproducible", (lambda v: check_reproducible(v, keep=dist))),
             ("8  installer end to end", (lambda v: check_installer(v, dist))),
             ("9  page generates", (lambda v: check_page(v, dist))),
             ("10 outgoing text clean", (lambda v: check_outgoing_text(v, dist))),
             ("11 provenance: all ours", check_provenance),
             ("12 shipped text clean", check_shipped_text)]
    print("Sealed Agent Bus — release preflight %s\n" % a.version)
    failed = []
    for label, fn in items:
        try:
            ok, detail = fn(a.version)
        except Exception as e:                                    # noqa: BLE001 — egy szakadt lépés is BUKÁS, nem kihagyás
            ok, detail = False, "%s: %s" % (type(e).__name__, str(e)[:120])
        mark = "SKIP" if ok is None else ("OK" if ok else "FAIL")
        print("  %-5s %-32s %s" % (mark, label, detail))
        if ok is False:
            failed.append(label)
    shutil.rmtree(dist, ignore_errors=True)
    print("\n  %s" % ("READY TO RELEASE" if not failed else "NOT READY: " + ", ".join(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
