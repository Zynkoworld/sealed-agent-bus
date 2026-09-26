#!/usr/bin/env python3
"""agent_wake — wake rules: SACRED typing, SLEEP-SAFE, operator WAKE. Stdlib-only.

`bus_poke` (tmux poke) and `agent_bus_watcher` (headless wake) ask ONE place whether it is allowed
to touch an agent. The rules learned in the live fleet, generalized:

1. **Typing is SACRED.** The operator also types DIRECTLY into the agents' prompts. Writing over a half-typed,
   unsent line or clearing it (C-u) is data loss — this did happen once. So:
   - BEFORE sending and before every retry we look at the prompt line; if it has live text in it → we do NOT send;
   - NEVER a C-u / clearing;
   - when in doubt, "typed" (fail-safe): a missed poke is harmless, an overwritten command is not.
   Claude Code's faded (dim, SGR 2) suggestion is NOT typing ("ghost").
2. **A working agent is not poked** (busy signals at the bottom of the pane, configurable).
3. **SLEEP-SAFE.** Nothing goes into a sleeping agent's pane and no headless wake starts — even if it has
   unread messages. Marker: global (everyone sleeps) or per agent. Engines/crons KEEP RUNNING
   regardless; sleep applies to the agent, not the machine.
4. **Only the operator can wake.** A bus message of kind `operator-wake` / `operator-sleep-safe` counts ONLY from
   authorized operator identities (AGENT_WAKE_OPERATORS), and if the sender has a registry key,
   the message must be validly signed (A2). An agent CANNOT wake itself (or others).
5. **NO DELETION.** WAKE does not delete the marker, it moves it under `history/` (who, when) — auditable.

Configuration (env):
  AGENT_WAKE_STATE_DIR   location of the markers (default: <AGENT_BRIDGE_DIR>/state)
  AGENT_WAKE_OPERATORS   comma-separated operator identities (default: empty = no one)
  AGENT_WAKE_PROMPT_CHAR prompt character on the pane (default: ❯)
  AGENT_WAKE_BUSY        '|'-separated busy signals (default: esc to interrupt|Compacting|Context limit)
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
    """The trust state of the marker directory. -> list of warnings (empty = fine)

    Until now NOTHING protected the sleep/wake markers — whoever can write to the directory
    can SILENTLY mute an agent by creating a foreign `X.sleep_safe`, or wake it by deleting the marker,
    and they also write the audit entry's `by` field. So the markers' location should be root-owned and
    NOT group/world-writable; if it is not, that must be stated — not kept quiet.
    """
    path = path or state_dir()
    out = []
    try:
        st = os.stat(path)
    except OSError:
        return out
    if st.st_uid != 0:
        out.append("the marker directory (%s) is NOT root-owned (uid=%d): anyone who writes here can mute "
                   "or wake an agent, and also writes the audit `by` field" % (path, st.st_uid))
    if st.st_mode & 0o022:
        out.append("the marker directory (%s) is group/world-writable (mode=%o)" % (path, st.st_mode & 0o777))
    #: the verdict used to look ONLY at the leaf, but for a SWAP it is enough
    # to write to the PARENT: `rename(state, state.hidden); makedirs(state, 0700)` — the leaf's permissions are
    # irrelevant (measured even with 0o000). A root-owned 0700 leaf thus got a CLEAN certificate under a
    # world-writable parent: that is worse than a missing signal, because it is FALSE REASSURANCE. So the chain must
    # also be checked UPWARDS through the parents — the same principle sshd applies to authorized_keys.
    parent = os.path.dirname(os.path.abspath(path))
    seen = set()
    while parent and parent not in seen:
        seen.add(parent)
        try:
            pst = os.stat(parent)
        except OSError:
            break
        if pst.st_uid != 0:
            out.append("the marker directory's PARENT [SZÜLŐJE] (%s) is NOT root-owned (uid=%d): the directory can be "
                       "SWAPPED by renaming, and sleep-safe protection is SILENTLY lost (the leaf's permissions do not "
                       "matter for this)" % (parent, pst.st_uid))
        # The STICKY bit (0o1000) prevents renaming/deleting a FOREIGN entry — under a sticky, root-owned
        # parent (e.g. /tmp) the root-owned marker directory CANNOT be swapped. We measured this, so we do not
        # cry wolf: broad permissions alone are a finding only if the sticky bit is absent.
        if (pst.st_mode & 0o022) and not (pst.st_mode & 0o1000):
            out.append("the marker directory's PARENT [SZÜLŐJE] (%s) is group/world-writable (mode=%o), and NOT sticky: the "
                       "directory can be swapped by renaming" % (parent, pst.st_mode & 0o777))
        nxt = os.path.dirname(parent)
        if nxt == parent:
            break
        parent = nxt
    return out


def _make_strict_dir(path, mode=0o700):
    """We create the whole chain ourselves, with a strict mode (`makedirs(mode=)` only affects the LEAF)."""
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


# ── 1. prompt state (a pure function, on the output of `tmux capture-pane -p -e`) ─────────────────
def prompt_input_state(pane_text):
    """The prompt line's state: 'empty' | 'ghost' (only a dim suggestion) | 'typed' (live typing) | 'dead' (None).
    It looks at the LAST line with a prompt character, keeping escapes, so that dim (SGR 2) text can be recognized."""
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
    """Is the agent working (a busy signal among the pane's last non-empty lines)."""
    if not pane_text:
        return False
    plain = _ANSI_ANY.sub("", pane_text)
    tail = "\n".join([ln for ln in plain.splitlines() if ln.strip()][-8:])
    return any(b in tail for b in _busy_markers())


# ── 3. SLEEP-SAFE markerek ─────────────────────────────────────────────────────────────────────
def _marker_path(agent=None):
    return os.path.join(state_dir(), GLOBAL_MARKER if agent is None else "%s.sleep_safe" % _safe(agent))


def is_asleep(agent):
    """Is the agent asleep: a global marker OR a per-agent marker exists."""
    return os.path.exists(_marker_path(None)) or os.path.exists(_marker_path(agent))


def enter_sleep_safe(agent=None, *, by="operator", now=None):
    """Write the marker (agent=None → everyone). Content: who and when (audit).
    The directory is created with a STRICT mode (0700); `state_dir_warnings` speaks up about an existing, broadly permissioned directory."""
    # (measured): `os.makedirs(..., mode=)` creates the INTERMEDIATE levels WITHOUT the mode,
    # so under `umask 0002` our own code produced the precondition (parent 0775, leaf 0700).
    # We build the chain ourselves, with a strict mode — we do NOT rewrite the permissions of existing directories (they are the operator's).
    _make_strict_dir(state_dir())
    p = _marker_path(agent)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"by": by, "ts": int(now if now is not None else time.time()), "scope": agent or "all"}, f)
    os.replace(tmp, p)
    return p


def wake_up(agent=None, *, by="operator", now=None):
    """WAKE: we do NOT delete the marker, we move it under history/ (who woke it, when). agent=None → the global
    marker + every per-agent marker. Returns the number of markers moved."""
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


# ── 4. operator command from the bus ─────────────────────────────────────────────────────────
def handle_operator_message(msg, *, verify=None, has_key=None):
    """Process a recv'd bus row. Looks only at KIND_WAKE / KIND_SLEEP kinds; everything else → None.
    Returns: 'woke' | 'slept' | 'ignored:<reason>'. `verify(msg)` → 'signed'|'unsigned'|'forged' (default: agent_bus.verify_sender).
    Body: empty/"all" → everyone; otherwise JSON {"agents": [...]} or a single agent name."""
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
    # a keyless operator name can be impersonated with a bare sender string — this is the ONLY gate
    # for the wake/sleep command, so by default we do NOT accept it. A developer exception only with an explicit switch.
    if not has_key and os.environ.get("AGENT_WAKE_ALLOW_KEYLESS_OPERATOR") != "1":
        return "ignored:operator-no-key"
    if not has_key:
        # this switch allows waking without a signature. It may exist (an operator decision),
        # but its USE must not be silent — the caller must see that we accepted it WITHOUT a signature check.
        sys.stderr.write("agent_wake: WARNING — AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1: the operator message was accepted "
                         "WITHOUT A SIGNATURE (%s)\n" % sender)
    auth = verify(msg)
    if auth == "forged" or (has_key and auth != "signed"):
        return "ignored:bad-signature"
    targets = _targets(msg.get("body"))
    if targets is None:
        return "ignored:bad-body"
    if sender in [t for t in targets if t is not None]:
        return "ignored:self"                                   # an agent/operator does not wake/sleep itself this way
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
        # the JSON branch gets the same strict name rule as the plain string — otherwise a
        # 300-byte name stopped the watcher with a filename error (ENAMETOOLONG).
        if (not isinstance(agents, list) or not agents
                or not all(isinstance(a, str) and _AGENT_NAME.fullmatch(a) for a in agents)):
            return None
        return agents
    return [b] if _AGENT_NAME.fullmatch(b) else None


# ── 1+2. safe sending into the pane ──────────────────────────────────────────────────────────
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
    """Is it allowed to write into the pane now? → (bool, reason). Order: sleep-safe → dead pane → working → typing."""
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
    """FIXED text + Enter into the pane, with the sacred-typing rule. NEVER a C-u, and no blind retry.
    Checks BEFORE sending (sleep-safe/dead/working/typing). Afterwards: if the prompt is empty or the agent is working →
    'sent'; if text got stuck in the prompt → 'stuck' (we do NOT clear it: the operator may have typed meanwhile).
    Returns: 'sent' | 'stuck' | 'error' | may_poke's refusing reason."""
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
