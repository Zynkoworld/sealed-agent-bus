#!/usr/bin/env python3
"""agent_duty — ÜGYELET: a munkasor aktív agentje tényleg dolgozik-e (AgentBus v1.3).

A flotta szabálya: egyszerre EGY agent dolgozik, a többi sleep-safe-ben pihen; az operátor (vagy a felügyelő agent)
ébreszti a következőt, miután ellenőrizte az előző jelentését. A gyakorlatban kiderült, hogy ez csendben megakadhat:
az ébresztő szövege a tmux-promptban ragadt (az Enter elveszett), és órákig „mindenki aludt". Ez a modul ezt fogja meg.

Bemenet: egy aktív-kijelölés JSON ({"active": <agent>, "topic": <feladat>, "since": <epoch>}), amit az ébresztő ír.
Döntés (tiszta függvény, `decide`), soronként egy akció:
  none        dolgozik / jóváhagyásra vár / jogosan alszik / még nem telt le az idő
  enter       a SAJÁT ébresztő-szövegünk ragadt a promptban (előtag-egyezés) → egy Enter; más szöveg SZENT, ahhoz nem nyúlunk
  nudge       tétlen, üres prompt ≥ IDLE_NUDGE perc → egy fix szövegű bökés (agent_wake.safe_send: szent gépelés, nincs C-u)
  done        tétlen ÉS az ébresztés óta jelentett → szól a felügyelőnek, hogy léptesse a sort (nem bökdösi a kész agentet)
  alert       a bökés után ≥ DUTY_ALERT perc sem indult, vagy nincs panel → riasztás (óránként legfeljebb egy)
A sort NEM lépteti magától: a jelentést ember/felügyelő ellenőrzi (label ≤ proof).
Alvás: agent_wake.is_asleep (globális vagy agentenkénti marker) → none.

Konfiguráció (env): AGENT_DUTY_ACTIVE (JSON-út), AGENT_DUTY_STATE, AGENT_DUTY_OWN_PREFIX (az ébresztő-szöveg eleje),
AGENT_DUTY_IDLE_NUDGE_MIN (10), AGENT_DUTY_ALERT_MIN (20), AGENT_DUTY_REMIND_S (3600),
AGENT_DUTY_NOTIFY (értesítő modul:függvény, pl. Telegram — alapból csak busz-üzenet a felügyelőnek),
AGENT_DUTY_SUPERVISOR (a felügyelő busz-identitása, alap: operator).
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
# v1.4: a státuszsorban látszó futó háttér-shell ("· 5 shells ·") = az agent egy mérésre vár → dolgozik, NEM bökjük
# (a flottában 09-14-én kétszer bökött meg így egy háttérmérésre váró agentet).
SHELLS = re.compile(r"·\s*0*[1-9]\d* shells?\s*(?:·|$)", re.I)


def _bg_shells(pane):
    """CSAK a legalsó `⏵⏵` státuszsor számít (egy kiírt busz-üzenet szövege nem némíthatja el
    az ügyeletet), és legalább 1 shell kell (a „0 shells" nem munka)."""
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
    """Az utolsó prompt-sor szövege (ANSI nélkül, a prompt-jel után)."""
    pc = aw._prompt_char()
    last = None
    for ln in (pane or "").splitlines():
        plain = _ANSI.sub("", ln).strip()
        if plain.startswith(pc):
            last = plain[len(pc):].strip()
    return last or ""


def decide(state, *, now, pane, asleep, reported, own_prefix,
           idle_nudge_min=10.0, alert_min=20.0, remind_s=3600.0, busy_stuck_min=60.0, waiting_stuck_min=60.0):
    """→ (akció, új_állapot). Mellékhatás nélküli; minden időt a hívó ad.
    `waiting_stuck_min`: a jóváhagyás-minta ugyanúgy önbevallott állapot, mint a „dolgozik" — ha a panel
    a mintával együtt ennyi percig BÁJTRA változatlan, az beragadás (a kérdés a promptban ragadt), nem várakozás."""
    st = dict(state or {})
    if asleep:
        return "none", st
    if pane is None:
        st["no_pane_since"] = st.get("no_pane_since") or now
        # Saját egyetlen `alerted` kulcs MINDEN riasztás-típusra -> az első riasztás
        # `remind_s`-ig elnyomta a MÁSIKAT is (pl. a no-pane elnyomta a beragadt-busy riasztást). Típusonként.
        if now - st["no_pane_since"] >= alert_min * 60 and now - st.get("alerted_no_pane", 0) >= remind_s:
            st["alerted_no_pane"] = now
            return "alert", st
        return "none", st
    st.pop("no_pane_since", None)
    if aw.is_busy(pane) or _bg_shells(pane):
        # a „dolgozik" szövegminta önmagában nem bizonyíték — egy lefagyott panel utolsó képkockáján
        # is ott lehet. Ha a panel tartalma busy_stuck_min percig BÁJTRA változatlan, az beragadás, nem munka.
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
        # (2026-09-17): a busy-ágon MÁR javított hibaosztály itt javítatlan volt — a jóváhagyás-minta feltétel
        # nélkül `none`-t adott (óra, számláló, hash nélkül), miközben a jóváhagyásra-várás ÉPP az az állapot, amiben egy
        # agent órákig áll, és a minta a panel SAJÁT kimenetéből olvas (egy kiírt README/help is elnémította az ügyeletet).
        # Ugyanaz a recept, mint a busy-ágon: a mintával együtt bájtra változatlan panel egy küszöb fölött = beragadás.
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
        return "none", st                                   # más szöveg a promptban: szent
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
    """→ (dict|None, ok). a hiányzó/sérült kijelölés NEM azonos a „minden rendben"-nel."""
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
    """Alapértelmezett `count_reports`: a felügyelő JSON-tükör inboxában az ébresztés óta
    érkezett `<agent>_*.json` fájlok száma. A gépi őr-üzenetek szűrése a hívó dolga (AGENT_DUTY_REPORT_EXCLUDE regex)."""
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
            # Saját eddig egy ÜRES, megfelelő nevű fájl `touch`-olása is „jelentés" volt, és a
            # felügyelői üzenet ebből lett „jelentett és tétlen — jöhet a következő". A jelentés legalább
            # PARSE-olható JSON legyen, valódi tartalommal — ez nem bizonyíték, de a 0 bájtos fájlt kizárja.
            if os.path.getsize(fp) < 2:
                continue
            with open(fp, encoding="utf-8") as _fh:
                _d = json.load(_fh)
            # SZERKEZETI szabály (nem tartalmi): a jelentés a busz JSON-tükrének egy sora legyen, amit AZ AGENT
            # küldött — egy `echo {} >` fájl nem az. Tartalmat nem minősítünk; ez nem bizonyíték, csak a
            # „jelentés = fájlnév" egyenlet megszüntetése.
            if not isinstance(_d, dict) or str(_d.get("from") or "").strip() != agent:
                continue
            if os.path.getmtime(fp) > since:
                n += 1
        except (OSError, ValueError):            # nem olvasható VAGY nem értelmezhető JSON -> nem jelentés
            continue
    return n


def _notify(text):
    spec = os.environ.get("AGENT_DUTY_NOTIFY", "")
    if ":" in spec:
        mod, fn = spec.split(":", 1)
        try:
            getattr(importlib.import_module(mod), fn)(text)
        except Exception as e:                                 # a riasztás ELVESZETT — ez nem lehet néma
            sys.stderr.write("AGENT_DUTY_NOTIFY (%s) hibára futott (%s): a riasztás NEM ment ki: %s\n"
                             % (spec, e.__class__.__name__, text[:120]))


def run_once(*, now=None, run=None, bus_send=None, count_reports=None, mono=None):
    if now is None:                                        # éles futás: fali és monoton óra együtt
        now, mono = time.time(), (mono if mono is not None else time.monotonic())
    base = aw.state_dir()
    state_path = os.environ.get("AGENT_DUTY_STATE", os.path.join(base, "duty_state.json"))
    sup = os.environ.get("AGENT_DUTY_SUPERVISOR", "operator")
    active, why = _load_active(os.environ.get("AGENT_DUTY_ACTIVE", os.path.join(base, "duty_active.json")))
    if active is None:
        # nem mérhető, ki az ügyeletes → saját státusz + riasztás (óránként legfeljebb egy)
        gst = _load(state_path, {})
        if now - gst.get("unknown_alerted", 0) >= _envf("AGENT_DUTY_REMIND_S", 3600):
            msg = "ÜGYELET: nem mérhető, ki az ügyeletes (a kijelölés %s) — senki nem figyeli a munkát." % why
            if bus_send:
                bus_send(sup, msg)
            _notify(msg)
            gst["unknown_alerted"] = now
            _save(state_path, gst)
        return "unknown"
    agent, topic = active.get("active"), active.get("topic", "")
    if not agent:
        return "no-duty"                                    # szándékosan nincs ügyeletes (pl. a flotta pihen) — kimondva
    st = _load(state_path, {})
    if st.get("agent") != agent or st.get("topic") != topic:
        st = {"agent": agent, "topic": topic}
    # fali-óra ugrás ellen a monoton órával vetjük össze az eltelt időt; ugrásnál a tárolt
    # időbélyegeket eltoljuk, hogy az eltelt idő megmaradjon (se késleltetés, se hamis riasztás).
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
        aw.safe_send(agent, agent, f"{own} ügyelet: te vagy az aktív agent ({topic}). Nézd meg a buszod és folytasd; ha kész, jelents.", run=run)
    elif action in ("done", "alert"):
        if action == "done":
            msg = f"ÜGYELET: {agent} ({topic}) jelentett és tétlen — jöhet a következő (ellenőrzés után)."
        elif st.get("stuck_busy"):
            msg = f"ÜGYELET: {agent} ({topic}) „dolgozik”-nak látszik, de a panel órák óta változatlan — beragadt?"
        else:
            msg = f"ÜGYELET: senki nem dolgozik — {agent} ({topic}) tétlen / nincs panel, bökés után sem indult."
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
    return 2 if res == "unknown" else 0          # a „nem mérhető" nem lehet rc=0


if __name__ == "__main__":
    raise SystemExit(_main())
