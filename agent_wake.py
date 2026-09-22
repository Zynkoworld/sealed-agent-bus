#!/usr/bin/env python3
"""agent_wake — ébresztési szabályok: SZENT gépelés, SLEEP-SAFE, operátori WAKE. Stdlib-only.

A `bus_poke` (tmux-bökés) és az `agent_bus_watcher` (headless wake) EGY helyről kérdezi meg, szabad-e
egy agenthez nyúlni. Az élő flottában szerzett szabályok, általánosítva:

1. **A gépelés SZENT.** Az operátor KÖZVETLENÜL is gépel az agentek promptjába. Egy félig beírt, el nem
   küldött sor fölé írni vagy azt törölni (C-u) adatvesztés — ez egyszer meg is történt. Ezért:
   - küldés ELŐTT és minden újrapróbálás előtt megnézzük a prompt-sort; ha élő szöveg van benne → NEM küldünk;
   - SOHA nincs C-u / törlés;
   - kétség esetén „typed" (fail-safe): egy elmaradt bökés ártalmatlan, egy felülírt parancs nem.
   A Claude Code halvány (dim, SGR 2) felajánlása NEM gépelés („ghost").
2. **Dolgozó agentet nem bökünk** (busy-jelek a panel alján, konfigurálható).
3. **SLEEP-SAFE.** Egy alvó agent panelébe semmi nem megy és headless wake sem indul — akkor sem, ha van
   olvasatlan üzenete. Marker: globális (mindenki alszik) vagy agentenkénti. A motorok/cronok ettől FUTNAK
   tovább; a sleep az agentre vonatkozik, nem a gépre.
4. **Ébreszteni csak az operátor tud.** `operator-wake` / `operator-sleep-safe` kindú busz-üzenet CSAK az
   engedélyezett operátor-identitásoktól számít (AGENT_WAKE_OPERATORS), és ha a feladónak van registry-kulcsa,
   az üzenetnek érvényesen aláírtnak kell lennie (A2). Agent magát (vagy mást) NEM ébresztheti.
5. **NINCS TÖRLÉS.** A WAKE nem törli a markert, hanem a `history/` alá mozgatja (ki, mikor) — auditálható.

Konfiguráció (env):
  AGENT_WAKE_STATE_DIR   markerek helye (default: <AGENT_BRIDGE_DIR>/state)
  AGENT_WAKE_OPERATORS   vesszővel elválasztott operátor-identitások (default: üres = senki)
  AGENT_WAKE_PROMPT_CHAR prompt-jel a panelen (default: ❯)
  AGENT_WAKE_BUSY        '|'-vel elválasztott busy-jelek (default: esc to interrupt|Compacting|Context limit)
"""
from __future__ import annotations

import json
import os
import sys
import re
import subprocess
import time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))

KIND_WAKE = "operator-wake"
KIND_SLEEP = "operator-sleep-safe"
GLOBAL_MARKER = ".SLEEP_SAFE_MODE"

_SGR = re.compile("\x1b\\[([0-9;]*)m")
_ANSI_ANY = re.compile("\x1b\\[[0-9;]*[A-Za-z]")
_BLANK = (" ", "\t", "\r", "\n", " ")


def state_dir():
    return os.environ.get("AGENT_WAKE_STATE_DIR") or os.path.join(BRIDGE, "state")


def state_dir_warnings(path=None):
    """A marker-könyvtár bizalmi állapota. -> figyelmeztetés-lista (üres = rendben)

    Saját az alvás/ébrenlét markerjeit eddig SEMMI nem védte — aki a könyvtárba írni tud,
    az egy idegen `X.sleep_safe` létrehozásával CSENDBEN elnémíthat egy agentet, vagy a marker törlésével
    ébreszthet, és az audit-bejegyzés `by` mezőjét is ő írja. A markerek helye ezért legyen root-tulajdonú és
    NEM csoport/világ-írható; ha nem az, azt ki kell mondani — nem elhallgatni.
    """
    path = path or state_dir()
    out = []
    try:
        st = os.stat(path)
    except OSError:
        return out
    if st.st_uid != 0:
        out.append("a marker-könyvtár (%s) NEM root-tulajdonú (uid=%d): bárki, aki ide ír, agentet némíthat "
                   "vagy ébreszthet, és az audit `by` mezőjét is ő írja" % (path, st.st_uid))
    if st.st_mode & 0o022:
        out.append("a marker-könyvtár (%s) csoport/világ-írható (mód=%o)" % (path, st.st_mode & 0o777))
    #: a verdikt eddig CSAK a levelet nézte, a CSERÉHEZ viszont
    # elég a SZÜLŐRE írni: `rename(state, state.elrejtve); makedirs(state, 0700)` — a levél jogai
    # érdektelenek (0o000-val is mérve). Egy root-tulajdonú 0700 levél így TISZTA bizonyítványt kapott egy
    # világ-írható szülő alatt: ez rosszabb, mint a hiányzó jelzés, mert HAMIS MEGNYUGTATÁS. A lánc tehát a
    # szülőkön FÖLFELÉ is nézendő — ugyanaz az elv, amit az sshd az authorized_keys-nél alkalmaz.
    parent = os.path.dirname(os.path.abspath(path))
    seen = set()
    while parent and parent not in seen:
        seen.add(parent)
        try:
            pst = os.stat(parent)
        except OSError:
            break
        if pst.st_uid != 0:
            out.append("a marker-könyvtár SZÜLŐJE (%s) NEM root-tulajdonú (uid=%d): a könyvtár átnevezéssel "
                       "KICSERÉLHETŐ, és a sleep-safe védelem NÉMÁN elvész (a levél jogai ehhez nem "
                       "számítanak)" % (parent, pst.st_uid))
        # A STICKY bit (0o1000) megakadályozza IDEGEN bejegyzés átnevezését/törlését — egy sticky, root-tulajdonú
        # szülő (pl. /tmp) alatt a root-tulajdonú marker-könyvtár NEM cserélhető ki. Ezt megmértük, tehát nem
        # kiáltunk farkast: a tág jog önmagában csak akkor lelet, ha a sticky bit nincs ott.
        if (pst.st_mode & 0o022) and not (pst.st_mode & 0o1000):
            out.append("a marker-könyvtár SZÜLŐJE (%s) csoport/világ-írható (mód=%o), és NEM sticky: a "
                       "könyvtár átnevezéssel kicserélhető" % (parent, pst.st_mode & 0o777))
        nxt = os.path.dirname(parent)
        if nxt == parent:
            break
        parent = nxt
    return out


def _make_strict_dir(path, mode=0o700):
    """A teljes láncot mi hozzuk létre, szigorú móddal (a `makedirs(mode=)` csak a LEVÉLRE hat)."""
    path = os.path.abspath(path)
    parts, cur = [], path
    while not os.path.isdir(cur):
        parts.append(cur)
        nxt = os.path.dirname(cur)
        if nxt == cur:
            break
        cur = nxt
    for d in reversed(parts):
        try:
            os.mkdir(d, mode)
        except FileExistsError:
            pass


def operators():
    raw = os.environ.get("AGENT_WAKE_OPERATORS", "")
    return {x.strip() for x in raw.split(",") if x.strip()}


def _prompt_char():
    return os.environ.get("AGENT_WAKE_PROMPT_CHAR", "❯")


def _busy_markers():
    raw = os.environ.get("AGENT_WAKE_BUSY", "esc to interrupt|Compacting|Context limit")
    return [x for x in raw.split("|") if x]


def _safe(agent):
    s = os.path.basename(str(agent or ""))
    return s if s and s not in (".", "..") else "x"


# ── 1. prompt-állapot (tiszta függvény, a `tmux capture-pane -p -e` kimenetén) ─────────────────
def prompt_input_state(pane_text):
    """A prompt-sor állapota: 'empty' | 'ghost' (csak dim felajánlás) | 'typed' (élő gépelés) | 'dead' (None).
    Az UTOLSÓ prompt-jeles sort nézi, az escape-eket megtartva, hogy a dim (SGR 2) szöveg felismerhető legyen."""
    if pane_text is None:
        return "dead"
    pc = _prompt_char()
    prompt_raw = None
    for ln in pane_text.splitlines():
        if _ANSI_ANY.sub("", ln).lstrip().startswith(pc):
            prompt_raw = ln
    if prompt_raw is None:
        return "empty"
    idx = prompt_raw.find(pc)
    seg = prompt_raw[idx + len(pc):] if idx >= 0 else prompt_raw
    dim = typed = ghost = False
    i, n = 0, len(seg)
    while i < n:
        m = _SGR.match(seg, i)
        if m:
            codes = [int(x) for x in m.group(1).split(";") if x != ""] or [0]
            for c in codes:
                if c == 2:
                    dim = True
                elif c in (0, 22):
                    dim = False
            i = m.end()
            continue
        m2 = _ANSI_ANY.match(seg, i)
        if m2:
            i = m2.end()
            continue
        if seg[i] not in _BLANK:
            if dim:
                ghost = True
            else:
                typed = True
        i += 1
    return "typed" if typed else ("ghost" if ghost else "empty")


def is_busy(pane_text):
    """Dolgozik-e az agent (a panel utolsó nem-üres sorai közt busy-jel)."""
    if not pane_text:
        return False
    plain = _ANSI_ANY.sub("", pane_text)
    tail = "\n".join([ln for ln in plain.splitlines() if ln.strip()][-8:])
    return any(b in tail for b in _busy_markers())


# ── 3. SLEEP-SAFE markerek ─────────────────────────────────────────────────────────────────────
def _marker_path(agent=None):
    return os.path.join(state_dir(), GLOBAL_MARKER if agent is None else "%s.sleep_safe" % _safe(agent))


def is_asleep(agent):
    """Alszik-e az agent: globális marker VAGY agentenkénti marker létezik."""
    return os.path.exists(_marker_path(None)) or os.path.exists(_marker_path(agent))


def enter_sleep_safe(agent=None, *, by="operator", now=None):
    """Marker írása (agent=None → mindenki). Tartalom: ki és mikor (audit).
    A könyvtár SZIGORÚ móddal jön létre (0700); a meglévő, tág jogú könyvtárra a `state_dir_warnings` szól."""
    # (mérve): az `os.makedirs(..., mode=)` a KÖZTES szinteket mode NÉLKÜL hozza létre,
    # tehát `umask 0002` alatt a saját kódunk állította elő a előfeltételét (szülő 0775, levél 0700).
    # A láncot magunk építjük, szigorú móddal — a meglévő könyvtárak jogait NEM írjuk át (az üzemeltetőé).
    _make_strict_dir(state_dir())
    p = _marker_path(agent)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"by": by, "ts": int(now if now is not None else time.time()), "scope": agent or "all"}, f)
    os.replace(tmp, p)
    return p


def wake_up(agent=None, *, by="operator", now=None):
    """WAKE: a markert NEM töröljük, hanem history/ alá mozgatjuk (ki ébresztett, mikor). agent=None → globális
    marker + minden agentenkénti marker. Visszaadja a mozgatott markerek számát."""
    hist = os.path.join(state_dir(), "history")
    ts = int(now if now is not None else time.time())
    targets = [_marker_path(agent)]
    if agent is None and os.path.isdir(state_dir()):
        targets += [os.path.join(state_dir(), f) for f in os.listdir(state_dir()) if f.endswith(".sleep_safe")]
    moved = 0
    for p in targets:
        if not os.path.exists(p):
            continue
        os.makedirs(hist, exist_ok=True)
        dst = os.path.join(hist, "%s.woke-%d-by-%s" % (os.path.basename(p).lstrip("."), ts, _safe(by)))
        os.replace(p, dst)
        moved += 1
    return moved


# ── 4. operátori parancs a buszról ───────────────────────────────────────────────────────────
def handle_operator_message(msg, *, verify=None, has_key=None):
    """Egy recv-elt busz-sor feldolgozása. Csak KIND_WAKE / KIND_SLEEP kindot néz; minden más → None.
    Visszaad: 'woke' | 'slept' | 'ignored:<ok>'. `verify(msg)` → 'signed'|'unsigned'|'forged' (default: agent_bus.verify_sender).
    Body: üres/"all" → mindenki; egyébként JSON {"agents": [...]} vagy egyetlen agent-név."""
    kind = msg.get("kind")
    if kind not in (KIND_WAKE, KIND_SLEEP):
        return None
    sender = msg.get("sender") or ""
    if sender not in operators():
        return "ignored:not-operator"
    if verify is None:
        import agent_bus
        verify = agent_bus.verify_sender
        if has_key is None:
            has_key = agent_bus._a2_load_registry_pubkey(sender, agent_bus.KEYS_DIR) is not None
    elif has_key is None:
        has_key = True
    # kulcs nélküli operátor-név puszta sender-stringgel megszemélyesíthető — ez az EGYETLEN kapu
    # a wake/sleep-parancsra, ezért alapból NEM fogadjuk el. Fejlesztői kivétel csak explicit kapcsolóval.
    if not has_key and os.environ.get("AGENT_WAKE_ALLOW_KEYLESS_OPERATOR") != "1":
        return "ignored:operator-no-key"
    if not has_key:
        # Saját ez a kapcsoló aláírás nélkül enged ébresztést. Létezhet (üzemeltetői döntés),
        # de a HASZNÁLATA nem lehet néma — a hívó lássa, hogy aláírás-ellenőrzés NÉLKÜL fogadtuk el.
        sys.stderr.write("agent_wake: FIGYELEM — AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1: az operátor-üzenetet "
                         "ALÁÍRÁS NÉLKÜL fogadtuk el (%s)\n" % sender)
    auth = verify(msg)
    if auth == "forged" or (has_key and auth != "signed"):
        return "ignored:bad-signature"
    targets = _targets(msg.get("body"))
    if targets is None:
        return "ignored:bad-body"
    if sender in [t for t in targets if t is not None]:
        return "ignored:self"                                   # agent/operátor magát nem ébreszti/altatja így
    for t in targets:
        if kind == KIND_WAKE:
            wake_up(t, by=sender)
        else:
            enter_sleep_safe(t, by=sender)
    return "woke" if kind == KIND_WAKE else "slept"


_AGENT_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")


def _targets(body):
    b = (body or "").strip()
    if b in ("", "all"):
        return [None]
    if b.startswith("{"):
        try:
            agents = json.loads(b).get("agents")
        except (ValueError, AttributeError):
            return None
        if agents == "all":
            return [None]
        # a JSON-ág ugyanazt a szigorú névszabályt kapja, mint a sima string — különben egy
        # 300 bájtos név fájlnév-hibával (ENAMETOOLONG) leállította a watchert.
        if (not isinstance(agents, list) or not agents
                or not all(isinstance(a, str) and _AGENT_NAME.fullmatch(a) for a in agents)):
            return None
        return agents
    return [b] if _AGENT_NAME.fullmatch(b) else None


# ── 1+2. biztonságos küldés a panelbe ──────────────────────────────────────────────────────────
def _default_run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=5)


def capture(target, *, run=None):
    run = run or _default_run
    try:
        r = run(["tmux", "capture-pane", "-p", "-e", "-t", target])
    except Exception:
        return None
    return r.stdout if getattr(r, "returncode", 1) == 0 else None


def may_poke(agent, target, *, run=None):
    """Szabad-e most a panelbe írni? → (bool, ok). Sorrend: sleep-safe → halott panel → dolgozik → gépelés."""
    if is_asleep(agent):
        return False, "sleep-safe"
    pane = capture(target, run=run)
    if pane is None:
        return False, "dead"
    if is_busy(pane):
        return False, "busy"
    st = prompt_input_state(pane)
    if st == "typed":
        return False, "typed"
    return True, st


def safe_send(agent, target, text, *, run=None, settle=None):
    """FIX szöveg + Enter a panelbe, a szent-gépelés szabállyal. SOHA nincs C-u, és nincs vak újrapróbálás.
    Küldés ELŐTT ellenőriz (sleep-safe/halott/dolgozik/gépel). Utána: ha a prompt üres vagy az agent dolgozik →
    'sent'; ha szöveg ragadt a promptban → 'stuck' (NEM töröljük: lehet, hogy közben az operátor is gépelt).
    Visszaad: 'sent' | 'stuck' | 'error' | a may_poke tiltó oka."""
    run = run or _default_run
    settle = settle if settle is not None else (lambda: time.sleep(1))
    ok, why = may_poke(agent, target, run=run)
    if not ok:
        return why
    try:
        r1 = run(["tmux", "send-keys", "-t", target, "-l", text])
        r2 = run(["tmux", "send-keys", "-t", target, "Enter"])
    except Exception:
        return "error"
    if getattr(r1, "returncode", 1) != 0 or getattr(r2, "returncode", 1) != 0:
        return "error"
    settle()
    after = capture(target, run=run)
    if after is None:
        return "error"
    if prompt_input_state(after) != "typed" or is_busy(after):
        return "sent"
    return "stuck"
