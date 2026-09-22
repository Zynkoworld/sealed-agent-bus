#!/usr/bin/env python3
"""bus_poke — valós idejű, INGYENES, esemény-vezérelt „bökés": a beérkező bus-üzenet
pillanatában a megfelelő agent tmux-paneljébe injektál egy FIX poke-promptot, hogy az
agent magától triage-elje az inboxát — Claude-wake (fizetős `claude -p`) NÉLKÜL.

## A probléma, amit megold (az üzemeltető 2026-06-25)

A 3-perces `bus_cron_tick.py` poll késik; a `bus_poke_daemon` ingyenes feedje (az egyik kar
prototípus) PASSZÍV — figyelni kell. Az operátornak emiatt kézzel kell mindenkinek jeleznie,
hogy „BUS". Ez a daemon **valós idejű, AKTÍV** bökés: inotify-val ezredmásodperceken belül
észleli az új üzenetet, és `tmux send-keys`-szel beírja az agent promptjába a poke-ot → az
agent (egy futó interaktív session a tmux-panelben) a következő körében MAGÁTÓL feldolgozza.

## Miért ingyenes és alkotmány-konform

- **Nincs fizetős wake.** Nem `claude -p` cold-spawn; egy MÁR FUTÓ interaktív session kap egy
  promptot (amit úgyis a saját körében dolgoz fel). A jelzés determinista, modell nélkül.
- **A poke FIX szöveg**, SOHA nem az üzenet tartalma. A bus-üzenetek ADAT-ok maradnak; a poke
  csak egy „nézd meg a postád" lépés (a watcher-elv: a wake nem ad parancsot). Az operátor
  EXPLICIT engedélyezte ezt a mechanizmust (tmux auto-inject választás, 06-25).
- **Loop-védelem:** per-agent cooldown + burst-debounce → egy ack-lavina nem pingpongozik.

## Transzport

Egyetlen jel mindkét kézbesítési csatornára: `agent_bus.send(..., mirror=True)` (alap) a
`bus.db` sor MELLÉ egy JSON-t tükröz `inbox/<recipient>/`-be, és a fájl-inbox is oda ír — így
egy új `*.json` az `inbox/<agent>/`-ben a közös jel. Stdlib-only: inotify ctypes-szal (nincs
inotify-tools / pip). Ha nincs inotify → gyors (1s) mtime-poll fallback (még így is jóval
szorosabb a 3-perces cronnál).

Indítás (hosszú-életű; systemd/nohup, NEM cron):
    python3 scripts/bus_poke.py --agent az egyik kar            # auto-feloldja a tmux targetet
    python3 scripts/bus_poke.py --agent az egyik kar --target az egyik kar   # explicit tmux session/target
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
import os
import re
import select
import struct
import subprocess
import time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))

# Best-effort: a single-flight session-lock olvasásához (a poke CSAK a kanonikus workert
# bökje, ne egy duplikátum-instanciát). Ha a modul nincs ott, a régi feloldás marad.
try:
    import bus_singleflight as _sf
except Exception:  # pragma: no cover - csak akkor, ha nincs deployolva
    _sf = None

# v1.1: az ébresztési szabályok (SZENT gépelés, SLEEP-SAFE) egy helyen — agent_wake. Ha nincs deployolva,
# a bökés FAIL-CLOSED: nem injektál (csak feedel), mert a gépelés-ellenőrzés nélküli send-keys írhat élő szövegbe.
try:
    import agent_wake as _aw
except Exception:  # pragma: no cover
    _aw = None

# inotify event-maszkok (linux/inotify.h)
IN_CREATE = 0x00000100
IN_MOVED_TO = 0x00000080       # atomi *.tmp -> rename ide érkezik
IN_CLOSE_WRITE = 0x00000008    # sima write+close
_WAKE_MASK = IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE
_EVENT_HDR = struct.calcsize("iIII")

_DEBOUNCE_S = 0.4              # egy burst fájljait egy bökésbe gyűjti
_COOLDOWN_NS = 8 * 1_000_000_000   # per-agent: max egy inject / 8s (ack-lavina-védelem)

# A FIX poke-prompt — SOHA nem az üzenet tartalma (alkotmány: a bus-üzenet ADAT, a poke csak
# „nézd meg a postád" lépés). Az agent a STARTUP_MEMO szerint tudja, mit jelent a drain.
POKE_TEXT = ("📬 agent-bridge BÖKÉS: új üzenet az inboxodban — triage-eld most "
             "(act → reply atomként → archiváld), majd folytasd a feladatod.")

# Opcionális agent → munka-könyvtár térkép a cwd-alapú tmux-target auto-detektáláshoz. Telepítés-függő,
# ezért NINCS beégetve: AGENT_POKE_DIRS="agent=/ut,masik=/masik-ut" adja meg, vagy hagyd üresen és
# használd a --target kapcsolót. Üres térkép = nincs auto-detektálás, nem hiba.
def _parse_agent_dirs(spec):
    out = {}
    for item in (spec or "").split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip()] = os.path.expanduser(v.strip())
    return out


_AGENT_DIRS = _parse_agent_dirs(os.environ.get("AGENT_POKE_DIRS"))

_LOG = None


def _log(msg):
    if not _LOG:
        return
    try:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write("[%d] %s\n" % (time.time_ns(), msg))
    except OSError:
        pass


def classify(d):
    """Determinista, modell-mentes triage → durva osztály. `needs-action` amire egy session
    reagáljon (kérés/kérdés), `info` a tiszta ADAT (ack/fyi/answer/announce)."""
    kind = (d.get("kind") or "").lower()
    if kind in ("question", "request", "task", "ask"):
        return "needs-action"
    return "info"


def count_json_events(data):
    """A nyers inotify-bufferben a *.json fájlt nevező események száma."""
    n, i = 0, 0
    while i + _EVENT_HDR <= len(data):
        _wd, _mask, _cookie, nlen = struct.unpack_from("iIII", data, i)
        i += _EVENT_HDR
        name = data[i:i + nlen].split(b"\x00", 1)[0]
        i += nlen
        if name.endswith(b".json"):
            n += 1
    return n


def _safe(s):
    """Log-higiénia: ctrl-/escape-karakterek (köztük \\n, \\r, \\x1b) eltávolítása a feedbe
    írt ADAT-mezőkből → egy bus-üzenet egy mezője nem hamisíthat log-sort és nem injektálhat
    terminál-escape-et `tail`-nél (az egyik kar 06-25 hardening; LOW, nem billentyű-injekció)."""
    # Saját az ESC/C0 szűrése miatt escape-injekció nem megy — DE átment az U+2028/U+2029
    # (LINE/PARAGRAPH SEPARATOR), az U+0085 (NEL) és a kétirányúság-vezérlők (U+202A..U+202E, U+2066..U+2069):
    # ezekkel a feed-sor VIZUÁLISAN hamisítható (hamis log-sor, megfordított szöveg) a `tail` nézetében.
    _BAD = {0x85, 0x2028, 0x2029} | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0xFEFF}
    return "".join(c for c in str(s)
                   if (c == "\t" or (ord(c) >= 0x20 and ord(c) != 0x7f)) and ord(c) not in _BAD)



_TARGET_RE = re.compile(r"^[A-Za-z0-9_.-]+(:[0-9]+(\.[0-9]+)?)?$")


def _safe_target(t):
    """A tmux-target ALAKJA kötött: `session[:ablak[.panel]]`, semmi más.

    Saját a target három forrásból jöhet (explicit kapcsoló, a single-flight lock JSON-je,
    illetve egy registry-fájl) — a lock-JSON-t és a fájlt NEM feltétlenül az agent írja. Egy `-`-szal kezdődő
    vagy tmux-szintaxist tartalmazó string a `send-keys -t` értékében más panelbe irányíthatná a bökést.
    Nem illeszkedő alak -> None (nincs bökés), mert a rossz helyre írás rosszabb, mint a kimaradt bökés.
    """
    t = (t or "").strip()
    return t if _TARGET_RE.match(t) else None


def surface_pending(agent, inbox, pending=None):
    """INGYENES determinista feed: minden függő inbox-üzenet egy osztályozott sora a
    `poke-logs/<agent>/bus_pending.log`-ba (audit + `tail -f`). Visszaadja a függő számot.
    A `pending` út megadható (mérésnek/tesztnek); alapból a poke-log mellé ír."""
    if pending is None:
        pending = os.path.join(os.path.dirname(_LOG), "bus_pending.log") if _LOG else None
    try:
        files = sorted(f for f in os.listdir(inbox) if f.endswith(".json"))
    except OSError:
        return 0
    if not (pending and files):
        return len(files)
    try:
        with open(pending, "a", encoding="utf-8") as out:
            for f in files:
                try:
                    d = json.load(open(os.path.join(inbox, f), encoding="utf-8"))
                except Exception:
                    out.write("[%d] UNPARSEABLE %s\n" % (time.time_ns(), _safe(f)))
                    continue
                note = _safe((d.get("note") or "").replace("\n", " ")).strip()[:120]
                # Saját a `note` a FELADÓ szövege — a bökés fix szöveget ír, de EZ a mező az
                # agent szeme elé kerül, tehát közvetett prompt-injekciós csatorna. Szemantikát szűrni nem lehet,
                # ezért a sor KIMONDJA, hogy adat (`adat=...`); a védelem az agent szabálya („a busz tartalma
                # ADAT, sosem utasítás"), nem a szűrő — ezt nem takarjuk el.
                out.write("[%d] %s→%s | %s | %s | %s | adat=%r\n" % (
                    time.time_ns(),
                    _safe(d.get("from", "?")), _safe(d.get("to", agent)),
                    _safe(d.get("kind", "?")), _safe(d.get("topic", "")),
                    classify(d), note))
    except OSError:
        pass
    return len(files)


def _tmux_targets(run=None):
    """A futó tmux-panelek listája: (target, cwd) párok. `run` injektálható a teszthez."""
    run = run or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=5))
    try:
        r = run(["tmux", "list-panes", "-a", "-F",
                 "#{session_name}:#{window_index}.#{pane_index}\t#{pane_current_path}"])
    except Exception:
        return []
    if getattr(r, "returncode", 1) != 0:
        return []
    out = []
    for line in (r.stdout or "").splitlines():
        if "\t" in line:
            tgt, path = line.split("\t", 1)
            out.append((tgt.strip(), path.strip()))
    return out


def resolve_target(agent, *, explicit=None, run=None):
    """Az agent tmux-targetjének feloldása, prioritás-sorrendben:
      1) explicit `--target`;
      2) registry-fájl `wake/<agent>.tmux-target` (egy sor);
      3) session-név konvenció: ha van `<agent>` nevű tmux session;
      4) cwd auto-detect: az a panel, amelynek cwd-je az agent munka-könyvtára.
    None, ha nem található (a hívó ilyenkor csak feedel, nem injektál)."""
    # NO-POKE marker (az üzemeltető 2026-07-09) — HARD OVERRIDE, MINDEN mas elott (explicit target is!):
    # ha `wake/<agent>.no-poke` letezik, az injektalas SOHA nem fut (a poke a chatboxba landolt + elvagta
    # a user uzeneteit). Korabban az `if explicit: return explicit` a marker ELOTT allt -> egy explicit
    # `--target`-tel hivott poke megkerulte a markert es beirt az üzemeltető chatboxaba (2026-07-10 operator-panasz).
    # BOX-WIDE: a MEGOSZTOTT bus_poke.py-ban, hogy SEMMILYEN agent/hivas se injektaljon a chatboxba.
    # Az agent autonom daemonja kezeli az inboxot -> a poke felesleges.
    if os.path.exists(os.path.join(BRIDGE, "wake", "%s.no-poke" % agent)):
        return None
    if explicit:
        return _safe_target(explicit)
    # 1b) single-flight: az ÉLŐ session-lock-tulajdonos (a kanonikus worker) targetje. Így a
    # poke sosem ébreszt fel egy duplikátum-instanciát ugyanarra a munkára (collision-gyökér).
    if _sf is not None:
        try:
            lock = _sf.SessionLock(agent, bridge=BRIDGE)
            cur = lock.holder()
            if cur and lock._holder_alive(cur, time.time_ns()) and cur.get("target"):
                return _safe_target(cur["target"])      # a lock-JSON-t más is írhatja: NEM kerülhet nyersen a -t-be
        except Exception:
            pass
    reg = os.path.join(BRIDGE, "wake", "%s.tmux-target" % agent)
    try:
        with open(reg, encoding="utf-8") as f:
            t = f.read().strip()
            if t:
                return _safe_target(t)
    except OSError:
        pass
    targets = _tmux_targets(run=run)
    # 3) session-név konvenció
    for tgt, _path in targets:
        if tgt.split(":", 1)[0] == agent:
            return tgt
    # 4) cwd-egyezés
    want = _AGENT_DIRS.get(agent)
    if want:
        for tgt, path in targets:
            if path == want:
                return tgt
    return None


def pin_to_claude_pane(target, *, run=None):
    """A targetet a `claude`-ot futtató PANELRE pinneli (nem a session aktív paneljére).

    Gyökér-bugfix (az üzemeltető 2026-06-27: „néhány bökés a chatboxba megy"): egy session-név-only target a `send-keys` idején az AKTÍV panelra megy — ha az nem a claude-pane (pl. egy
    megnyitott chatbox-/dev-panel), a poke OTT köt ki. Ezért a session ÖSSZES panele közül a `claude`
    parancsút (a legkisebb window.pane indexűt — a kanonikus agent-session) választjuk ki precízen.
    Fallback: az eredeti target, ha nincs claude-pane v. tmux-hiba (nem ront a meglévőn)."""
    run = run or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=5))
    session = str(target).split(":", 1)[0]
    try:
        r = run(["tmux", "list-panes", "-t", session, "-F",
                 "#{window_index}.#{pane_index}\t#{pane_current_command}"])
        if getattr(r, "returncode", 1) != 0:
            return target
        claude_panes = []
        for line in (r.stdout or "").splitlines():
            if "\t" not in line:
                continue
            wp, cmd = line.split("\t", 1)
            if cmd.strip() == "claude":
                w, p = wp.split(".")
                claude_panes.append((int(w), int(p)))
        if not claude_panes:
            return target                                   # nincs claude-pane -> fallback (ne rontsunk)
        w, p = min(claude_panes)                            # a legkisebb index = a kanonikus agent-session
        return "%s:%d.%d" % (session, w, p)
    except Exception:
        return target


def inject_status(target, text=POKE_TEXT, *, agent=None, run=None, settle=None):
    """A fix poke-promptot beírja a tmux-targetbe + Enter — CSAK az agent_wake szabályai szerint.
    A target a `claude`-panelra PINNELŐDIK (sosem a session aktív/chatbox-paneljére). v1.1: küldés előtt
    sleep-safe / halott / dolgozik / ÉLŐ GÉPELÉS ellenőrzés; gépelésbe SOHA nem ír, C-u nincs.
    Visszaad: 'sent' | 'stuck' | 'error' | 'sleep-safe' | 'dead' | 'busy' | 'typed' | 'no-wake-module'."""
    run = run or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=5))
    target = pin_to_claude_pane(target, run=run)            # GYÖKÉR-FIX: a claude-panelra, ne a chatboxba
    if _aw is None:
        return "no-wake-module"                             # fail-closed: ellenőrzés nélkül nem írunk panelbe
    who = agent or str(target).split(":", 1)[0]
    return _aw.safe_send(who, target, text, run=run, settle=settle)


def inject(target, text=POKE_TEXT, *, run=None, agent=None, settle=None):
    """Back-compat: True, ha a bökés ténylegesen elment (lásd inject_status)."""
    return inject_status(target, text, agent=agent, run=run, settle=settle) == "sent"


class Poker:
    """A bökés-állapot: per-agent cooldown, hogy egy ack-lavina ne pingpongozzon. A
    `tmux`-hívás (`run`) injektálható a determinista teszthez."""

    def __init__(self, agent, *, explicit_target=None, run=None, cooldown_ns=_COOLDOWN_NS, settle=None):
        self.agent = agent
        self.explicit_target = explicit_target
        self.run = run
        self.cooldown_ns = cooldown_ns
        self.inbox = os.path.join(BRIDGE, "inbox", agent)
        self._last_inject_ns = 0
        self.settle = settle

    def on_new(self, n, *, now_ns=None):
        """Egy bökés kezelése: MINDIG ingyenes feed; majd cooldown-on belül NEM injektál
        (csak feedel), azon túl tmux-inject (ha van target). Visszaadja az akciót:
        'injected' | 'cooldown' | 'no-target' | 'no-mail' | 'sleep-safe' | 'typed' | 'busy' | 'stuck'."""
        now = now_ns if now_ns is not None else time.time_ns()
        pend = surface_pending(self.agent, self.inbox)
        if pend == 0:
            return "no-mail"
        _log("poke: %d új -> feed (ingyen); pending=%d" % (n, pend))
        if now - self._last_inject_ns < self.cooldown_ns:
            _log("cooldown -> csak feed (nincs inject)")
            return "cooldown"
        if _aw is not None and _aw.is_asleep(self.agent):
            _log("%s SLEEP-SAFE -> csak feed (alvó agent panelébe nem írunk)" % self.agent)
            return "sleep-safe"
        target = resolve_target(self.agent, explicit=self.explicit_target, run=self.run)
        if not target:
            _log("nincs tmux-target az agentnek (%s) -> csak feed" % self.agent)
            return "no-target"
        st = inject_status(target, agent=self.agent, run=self.run, settle=self.settle)
        if st == "sent":
            self._last_inject_ns = now
            _log("INJECT -> tmux %s (%d függő)" % (target, pend))
            return "injected"
        _log("inject kihagyva/sikertelen (tmux %s): %s" % (target, st))
        return st if st in ("typed", "busy", "sleep-safe", "stuck") else "no-target"


def _has_json(inbox):
    try:
        return any(f.endswith(".json") for f in os.listdir(inbox))
    except OSError:
        return False


def _inotify_loop(poker):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init()
    if fd < 0:
        return False
    wd = libc.inotify_add_watch(fd, poker.inbox.encode("utf-8"), _WAKE_MASK)
    if wd < 0:
        os.close(fd)
        return False
    # Az inotify-fd NEM-BLOKKOLÓVÁ tétele.
    # ELŐTTE: az `inotify_init()` blokkoló fd-t ad, így a debounce utáni "maradék-szippantás"
    # (`os.read(fd, 65536)`) a KÖVETKEZŐ eseményig blokkolt — az `except BlockingIOError`
    # csak nem-blokkoló fd-n fog. Következmény: a daemon az első esemény után beragadt,
    # `on_new` sosem futott le rá, és az inbox NÉMÁN gyűlt (a feed 07-19 óta üres volt,
    # miközben a unit `active` maradt = hamis zöld). A blokkoló olvasást most a `select`
    # végzi (az ébresztés változatlanul esemény-vezérelt, nem poll).
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    _log("inotify figyel: %s" % poker.inbox)
    try:
        while True:
            try:
                if not select.select([fd], [], [])[0]:
                    continue
                data = os.read(fd, 4096)
            except InterruptedError:
                continue
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                raise
            time.sleep(_DEBOUNCE_S)
            try:
                data += os.read(fd, 65536)
            except (BlockingIOError, OSError):
                pass
            n = count_json_events(data)
            if n:
                poker.on_new(n)
    finally:
        os.close(fd)
    return True


def _poll_loop(poker, period=1.0):
    _log("inotify nincs -> gyors-poll %ss" % period)
    seen = _dir_sig(poker.inbox)
    while True:
        time.sleep(period)
        sig = _dir_sig(poker.inbox)
        if sig != seen and _has_json(poker.inbox):
            poker.on_new(1)
        seen = sig


def _dir_sig(inbox):
    try:
        return tuple(sorted((f, os.path.getmtime(os.path.join(inbox, f)))
                            for f in os.listdir(inbox) if f.endswith(".json")))
    except OSError:
        return ()


def main(argv=None):
    global _LOG
    p = argparse.ArgumentParser(prog="bus_poke")
    p.add_argument("--agent", required=True)
    p.add_argument("--target", default=None,
                   help="explicit tmux-target (session v. session:win.pane); alap: auto-feloldás")
    p.add_argument("--log-dir", default=None,
                   help="alap: <AGENT_BRIDGE_DIR>/poke-logs/<agent> (sosem ír testvér-fába)")
    p.add_argument("--once-setup", action="store_true",
                   help="ellenőrzi az inbox + inotify + tmux-target elérhetőséget, majd kilép")
    a = p.parse_args(argv)
    inbox = os.path.join(BRIDGE, "inbox", a.agent)
    os.makedirs(inbox, exist_ok=True)
    log_dir = a.log_dir or os.path.join(BRIDGE, "poke-logs", a.agent)
    os.makedirs(log_dir, exist_ok=True)
    _LOG = os.path.join(log_dir, "bus_poke.log")

    if a.once_setup:
        ok = ctypes.CDLL("libc.so.6", use_errno=True).inotify_init()
        avail = ok >= 0
        if avail:
            os.close(ok)
        tgt = resolve_target(a.agent, explicit=a.target)
        print("inbox=%s inotify=%s tmux-target=%s" % (
            inbox, "available" if avail else "POLL-FALLBACK", tgt or "NINCS"))
        return 0

    _log("bus_poke start agent=%s target=%s" % (a.agent, a.target or "auto"))
    poker = Poker(a.agent, explicit_target=a.target)
    if not _inotify_loop(poker):
        _poll_loop(poker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
