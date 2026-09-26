#!/usr/bin/env python3
"""agent_duty — DUTY: is the work queue's active agent really working (AgentBus v1.3).

The fleet's rule: ONE agent works at a time, the others rest in sleep-safe; the operator (or the supervisor agent)
wakes the next one after checking the previous one's report. In practice it turned out this can stall silently:
the wake-up text got stuck in the tmux prompt (the Enter was lost), and for hours "everyone slept". This module catches that.

Input: an active-assignment JSON ({"active": <agent>, "topic": <task>, "since": <epoch>}), written by the waker.
Decision (a pure function, `decide`), one action per row:
  none        working / awaiting approval / legitimately asleep / the time has not elapsed yet
  enter       OUR OWN wake-up text got stuck in the prompt (prefix match) → one Enter; other text is SACRED, we do not touch it
  nudge       idle, empty prompt ≥ IDLE_NUDGE minutes → one fixed-text poke (agent_wake.safe_send: sacred typing, no C-u)
  done        idle AND has reported since the wake-up → tells the supervisor to advance the queue (does not keep poking a finished agent)
  alert       still not started ≥ DUTY_ALERT minutes after the poke, or no pane → alert (at most one per hour)
It does NOT advance the queue by itself: a human/the supervisor checks the report (label ≤ proof).
Sleep: agent_wake.is_asleep (global or per-agent marker) → none.

Configuration (env): AGENT_DUTY_ACTIVE (JSON path), AGENT_DUTY_STATE, AGENT_DUTY_OWN_PREFIX (the start of the wake-up text),
AGENT_DUTY_IDLE_NUDGE_MIN (10), AGENT_DUTY_ALERT_MIN (20), AGENT_DUTY_REMIND_S (3600),
AGENT_DUTY_NOTIFY (notifier module:function, e.g. Telegram — by default only a bus message to the supervisor),
AGENT_DUTY_SUPERVISOR (the supervisor's bus identity, default: operator).
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_wake as aw  # noqa: E402

_ANSI = re.compile("\x1b\\[[0-9;]*[A-Za-z]")
# v1.4: a running background shell visible on the status line ("· 5 shells ·") = the agent is waiting for a measurement → working, we do NOT poke
# (on 09-14 the fleet twice poked an agent waiting for a background measurement this way).
SHELLS = re.compile(r"·\s*0*[1-9]\d* shells?\s*(?:·|$)", re.I)


def _bg_shells(pane):
    """ONLY the bottom `⏵⏵` status line counts (the text of a printed bus message cannot silence
    duty), and at least 1 shell is required ("0 shells" is not work)."""
    for ln in reversed(_ANSI.sub("", pane).splitlines()[-4:]):
        if "⏵⏵" in ln:
            return bool(SHELLS.search(ln))
    return False
WAITING = re.compile(r"Do you want to|Would you like to proceed|Enter to select|^\s*❯\s*1\.\s*Yes|\(y/n\)", re.I | re.M)


def _envf(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


def prompt_text(pane):
    """The text of the last prompt line (without ANSI, after the prompt character)."""
    pc = aw._prompt_char()
    last = None
    for ln in (pane or "").splitlines():
        plain = _ANSI.sub("", ln).strip()
        if plain.startswith(pc):
            last = plain[len(pc):].strip()
    return last or ""


def decide(state, *, now, pane, asleep, reported, own_prefix,
           idle_nudge_min=10.0, alert_min=20.0, remind_s=3600.0, busy_stuck_min=60.0, waiting_stuck_min=60.0):
    """→ (action, new_state). Side-effect free; the caller supplies all times.
    `waiting_stuck_min`: the approval pattern is just as much a self-reported state as "working" — if the pane
    stays BYTE-identical together with the pattern for this many minutes, it is stuck (the question stuck in the prompt), not waiting."""
    st = dict(state or {})
    if asleep:
        return "none", st
    if pane is None:
        st["no_pane_since"] = st.get("no_pane_since") or now
        # a single `alerted` key for EVERY alert type -> the first alert
        # suppressed the OTHER one too until `remind_s` (e.g. no-pane suppressed the stuck-busy alert). Per type.
        if now - st["no_pane_since"] >= alert_min * 60 and now - st.get("alerted_no_pane", 0) >= remind_s:
            st["alerted_no_pane"] = now
            return "alert", st
        return "none", st
    st.pop("no_pane_since", None)
    if aw.is_busy(pane) or _bg_shells(pane):
        # the "working" text pattern alone is not evidence — it may be on the last frame of a frozen
        # pane. If the pane's content stays BYTE-identical for busy_stuck_min minutes, it is stuck, not working.
        h = hashlib.sha256(_ANSI.sub("", pane).encode("utf-8", "replace")).hexdigest()
        if st.get("busy_hash") != h:
            st.update(busy_hash=h, busy_same_since=now)
        st.update(idle_since=None, nudged=None, last_working=now)
        if now - st.get("busy_same_since", now) >= busy_stuck_min * 60:
            if now - st.get("alerted_stuck", 0) >= remind_s:
                st["alerted_stuck"] = now
                st["stuck_busy"] = True
                return "alert", st
        return "none", st
    st.pop("busy_hash", None); st.pop("busy_same_since", None)
    if WAITING.search("\n".join(_ANSI.sub("", pane).splitlines()[-40:])):
        # (2026-09-17): an error class ALREADY fixed on the busy branch was unfixed here — the approval pattern unconditionally
        # gave `none` (no clock, counter, hash), while waiting for approval is EXACTLY the state an
        # agent sits in for hours, and the pattern reads from the pane's OWN output (a printed README/help also silenced duty).
        # The same recipe as on the busy branch: a pane byte-identical together with the pattern above a threshold = stuck.
        h = hashlib.sha256(_ANSI.sub("", pane).encode("utf-8", "replace")).hexdigest()
        if st.get("waiting_hash") != h:
            st.update(waiting_hash=h, waiting_same_since=now)
        if now - st.get("waiting_same_since", now) >= waiting_stuck_min * 60:
            if now - st.get("alerted_waiting", 0) >= remind_s:
                st["alerted_waiting"] = now
                st["stuck_waiting"] = True
                return "alert", st
        return "none", st
    st.pop("waiting_hash", None); st.pop("waiting_same_since", None)
    typed = aw.prompt_input_state(pane) == "typed"
    text = prompt_text(pane)
    if typed:
        if own_prefix and text.startswith(own_prefix) and now - st.get("enter_sent", 0) >= 240:
            st["enter_sent"] = now
            return "enter", st
        return "none", st                                   # other text in the prompt: sacred
    st["idle_since"] = st.get("idle_since") or now
    idle_min = (now - st["idle_since"]) / 60
    if reported and idle_min >= 5:
        if not st.get("done_alerted"):
            st["done_alerted"] = now
            return "done", st
        return "none", st
    if idle_min >= idle_nudge_min and not st.get("nudged"):
        st["nudged"] = now
        return "nudge", st
    if st.get("nudged") and (now - st["nudged"]) / 60 >= alert_min and now - st.get("alerted_idle", 0) >= remind_s:
        st["alerted_idle"] = now
        return "alert", st
    return "none", st


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _load_active(path):
    """→ (dict|None, ok). A missing/damaged assignment is NOT the same as "all fine"."""
    try:
        with open(path) as f:
            d = json.load(f)
    except FileNotFoundError:
        return None, "missing"
    except Exception:
        return None, "corrupt"
    if not isinstance(d, dict):
        return None, "corrupt"
    return d, "ok"


def count_reports_inbox(agent, since, *, bridge=None, supervisor=None):
    """The default `count_reports`: the number of `<agent>_*.json` files that arrived in the supervisor's JSON mirror inbox
    since the wake-up. Filtering machine guard messages is the caller's job (AGENT_DUTY_REPORT_EXCLUDE regex)."""
    import re as _re
    bridge = bridge or os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))
    supervisor = supervisor or os.environ.get("AGENT_DUTY_SUPERVISOR", "operator")
    d = os.path.join(bridge, "inbox", supervisor)
    excl = os.environ.get("AGENT_DUTY_REPORT_EXCLUDE", "")
    try:
        names = os.listdir(d)
    except OSError:
        return 0
    n = 0
    for f in names:
        if not (f.startswith(agent + "_") and f.endswith(".json")):
            continue
        if excl and _re.search(excl, f):
            continue
        try:
            fp = os.path.join(d, f)
            # until now `touch`ing an EMPTY file with a matching name also counted as a "report", and the
            # supervisor message turned it into "reported and idle — the next one may go". A report must at least be
            # PARSEABLE JSON with real content — this is not proof, but it rules out a 0-byte file.
            if os.path.getsize(fp) < 2:
                continue
            with open(fp, encoding="utf-8") as _fh:
                _d = json.load(_fh)
            # A STRUCTURAL rule (not a content one): the report must be a row of the bus JSON mirror sent BY THE AGENT
            # — an `echo {} >` file is not. We do not rate content; this is not proof, just removing the
            # "report = file name" equation.
            if not isinstance(_d, dict) or str(_d.get("from") or "").strip() != agent:
                continue
            if os.path.getmtime(fp) > since:
                n += 1
        except (OSError, ValueError):            # unreadable OR unparseable JSON -> not a report
            continue
    return n


def _notify(text):
    spec = os.environ.get("AGENT_DUTY_NOTIFY", "")
    if ":" in spec:
        mod, fn = spec.split(":", 1)
        try:
            getattr(importlib.import_module(mod), fn)(text)
        except Exception as e:                                 # the alert was LOST — this cannot be silent
            sys.stderr.write("AGENT_DUTY_NOTIFY (%s) failed (%s): the alert did NOT go out: %s\n"
                             % (spec, e.__class__.__name__, text[:120]))


def run_once(*, now=None, run=None, bus_send=None, count_reports=None, mono=None):
    if now is None:                                        # a live run: wall and monotonic clock together
        now, mono = time.time(), (mono if mono is not None else time.monotonic())
    base = aw.state_dir()
    state_path = os.environ.get("AGENT_DUTY_STATE", os.path.join(base, "duty_state.json"))
    sup = os.environ.get("AGENT_DUTY_SUPERVISOR", "operator")
    active, why = _load_active(os.environ.get("AGENT_DUTY_ACTIVE", os.path.join(base, "duty_active.json")))
    if active is None:
        # it cannot be measured who is on duty → its own status + alert (at most one per hour)
        gst = _load(state_path, {})
        if now - gst.get("unknown_alerted", 0) >= _envf("AGENT_DUTY_REMIND_S", 3600):
            msg = "DUTY: it cannot be measured who is on duty (the assignment %s) — no one is watching the work." % why
            if bus_send:
                bus_send(sup, msg)
            _notify(msg)
            gst["unknown_alerted"] = now
            _save(state_path, gst)
        return "unknown"
    agent, topic = active.get("active"), active.get("topic", "")
    if not agent:
        return "no-duty"                                    # deliberately no one on duty (e.g. the fleet is resting) — stated
    st = _load(state_path, {})
    if st.get("agent") != agent or st.get("topic") != topic:
        st = {"agent": agent, "topic": topic}
    # against wall-clock jumps we compare the elapsed time with the monotonic clock; on a jump the stored
    # timestamps are shifted, so the elapsed time is preserved (neither delay nor a false alert).
    lw, lm = st.get("last_wall"), st.get("last_mono")
    if mono is not None and isinstance(lw, (int, float)) and isinstance(lm, (int, float)) and mono >= lm:
        drift = now - (lw + (mono - lm))
        if abs(drift) > 60:
            for k in ("idle_since", "nudged", "alerted", "alerted_no_pane", "alerted_stuck", "alerted_idle",
                      "enter_sent", "done_alerted", "no_pane_since", "busy_same_since"):
                if isinstance(st.get(k), (int, float)):
                    st[k] = st[k] + drift
            st["clock_jump"] = drift
    if mono is not None:
        st["last_wall"], st["last_mono"] = now, mono
    pane = aw.capture(agent, run=run)
    reported = count_reports(agent, float(active.get("since") or 0)) if count_reports else 0
    own = os.environ.get("AGENT_DUTY_OWN_PREFIX", "Agent")
    action, st = decide(st, now=now, pane=pane, asleep=aw.is_asleep(agent), reported=reported, own_prefix=own,
                        idle_nudge_min=_envf("AGENT_DUTY_IDLE_NUDGE_MIN", 10), alert_min=_envf("AGENT_DUTY_ALERT_MIN", 20),
                        remind_s=_envf("AGENT_DUTY_REMIND_S", 3600))
    runner = run or aw._default_run
    if action == "enter":
        runner(["tmux", "send-keys", "-t", agent, "Enter"])
    elif action == "nudge":
        aw.safe_send(agent, agent, f"{own} duty: you are the active agent ({topic}). Check your bus and continue; report when done.", run=run)
    elif action in ("done", "alert"):
        if action == "done":
            msg = f"DUTY: {agent} ({topic}) has reported and is idle — the next one may go (after checking)."
        elif st.get("stuck_busy"):
            msg = f"DUTY: {agent} ({topic}) looks \"working\", but the pane has been unchanged for hours — stuck?"
        else:
            msg = f"DUTY: no one is working — {agent} ({topic}) idle / no pane, did not start even after the poke."
        if bus_send:
            bus_send(sup, msg)
        if action == "alert":
            _notify(msg)
    _save(state_path, st)
    return action


def _save(path, st):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, path)


def _main():
    def _bus_send(to, msg):
        import agent_bus
        agent_bus.send("ugyelet", to, msg, topic="UGYELET", kind="alert")
    res = run_once(bus_send=_bus_send, count_reports=count_reports_inbox)
    print(res)
    return 2 if res == "unknown" else 0          # "not measurable" cannot be rc=0


if __name__ == "__main__":
    raise SystemExit(_main())
