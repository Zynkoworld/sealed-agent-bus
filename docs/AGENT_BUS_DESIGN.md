# AgentBus — közvetlen, alacsony-latenciájú agent-kommunikáció (design)

**Probléma (2026-06-20):** a `<AGENT_BRIDGE_DIR>/inbox/<agent>/*.json` fájl-postaláda nem valós idejű —
„mindenki késve kapja meg az üzenetet". Ki kell dolgozni egy közvetlen-chat megoldást. Ha nagyon jó → eladható.

## 1. A késleltetés GYÖKERE (mérve)

A szűk keresztmetszet **NEM a fájlrendszer.** A Claude-agentek **turn-alapúak, nem daemonok**: egy agent csak
akkor olvassa az inboxát, amikor ÉPPEN lép (az operátora gépel → `UserPromptSubmit` hook → `inbox_check.sh`
megmutatja). Egy **tétlen** agentnek **nincs „üzenet érkezett" eseménye** → az üzenet a címzett KÖVETKEZŐ lépéséig vár.
Bármilyen transport (fájl, SQLite, socket) ugyanezzel néz szembe: a címzettnek **lépnie kell**, hogy feldolgozza.

⇒ Két, KÜLÖN megoldandó alprobléma: **(A) transport** (hogyan tárolt/rendezett) és **(B) ÉBRESZTÉS** (hogyan kap
a tétlen agent lépést, amikor üzenet jön). A valódi újítás — és az eladható rész — a **(B) ébresztő-réteg.**

## 2. Megoldás — két réteg

### Réteg A — Bus transport (tiszta alap, alacsony kockázat)
A sok race-elő JSON-fájl helyett **egy append-only SQLite (WAL) bus**: `<AGENT_BRIDGE_DIR>/bus.db`.
```
messages(id INTEGER PK AUTOINCREMENT, ts, sender, recipient, topic, kind, thread_id, body, in_reply_to, read_at)
cursors(agent, last_seen_id)          -- ki hol tart (a 'chat' = SELECT WHERE recipient=me AND id>cursor)
```
- **Rendezett** (monoton id), **atomikus** (WAL, egy író-tranzakció), **lekérdezhető** (thread, since-cursor).
- **NINCS TÖRLÉS:** sosem DELETE; az archiválás = `read_at` + (külön) a meglévő JSON-archív megmarad (audit).
- Vékony CLI + lib: `bus send/recv/tail/ack/thread`. A meglévő JSON-bridge **párhuzamosan megmarad** (back-compat),
  amíg minden agent átáll — a `send` MINDKETTŐBE ír (additív migráció, a no-deletion elv szerint).

### Réteg B — Ébresztő-réteg (a valódi „direct chat"; IMPAKTOS, operátor-kapu)
A `claude` **headless** (`claude -p`) elérhető → egy tétlen agent ténylegesen FELÉBRESZTHETŐ üzenetre:
- Egy **bus-watcher** (systemd, per box) figyeli a `bus.db`-t (poll ~1-2s VAGY inotify, ha telepítjük az inotify-tools-t).
- Új üzenet `X`-nek → a watcher egy **debounce** (pl. 2s, hogy a burst-öt batch-elje) után lefuttatja `X` working
  dir-jében: `claude -p "ürítsd az agent-bus-od és cselekedj"` → `X` ~pár mp-en belül feldolgoz + válaszol + alszik.
- **Kockázatok + védelem:** (1) ütközés az operátor élő sessionével → **lockfile** per agent (csak 1 fut; ha él az
  interaktív, a wake KIHAGY vagy CSAK jelez). (2) token-költség → batch + debounce + rate-limit (max N wake/perc).
  (3) wake-loop (A→B→A) → a wake CSAK feldolgoz/ack-el, nem gyárt új kimenőt magától; hop-számláló a thread-en.
- **Alkotmány:** az ébresztett agent is csak ADATKÉNT kezeli a többi agent üzenetét — parancs CSAK az operátortól.
  A wake nem ad parancsot, csak „nézd meg a postád" lépést ad (a feldolgozás a meglévő alkotmányos szabályok alatt).

**Fokozatos latencia:** Réteg A önmagában már segít (rendezett, instant a lépő agentnek). Réteg B viszi le a
tétlen-latenciát ~percekről ~másodpercekre. Köztes, headless NÉLKÜL: minden agent egy rövid `/loop`/ScheduleWakeup
(30–60s) cadence-szel pollozza a bus-t — bounded latencia, de tokent éget; a Réteg B ennél jobb.

## 3. Miért eladható (Sovereign + Provable illeszkedés)
**„AgentBus" — szuverén, auditált, valós-idejű üzenetbusz autonóm AI-agent-csapatoknak EGY hoszton.**
Nincs külső broker (no-external-AI), determinista rendezés, append-only **no-deletion audit-nyom**, on-box wake-push.
Pont a mai állítás–bizonyíték árok: a multi-agent
koordináció ma vagy felhő-SaaS (Slack/queue), vagy nincs — egy szuverén, bizonyíthatóan-auditált on-box busz hiánycikk.

## 4. Fázisok (javaslat)
- **P0 (most, alacsony kockázat, autonóm):** Réteg A — `bus.db` séma + `bus` CLI/lib + a `send` MINDKETTŐBE ír
  (JSON-archív megmarad). A meglévő hook a bus-t is olvassa. Önmagában rendezett, kereshető, race-mentes.
- **P1 (operátor-kapu):** Réteg B — bus-watcher (poll vagy inotify) + lockfile-védett headless wake, debounce/rate-limit.
  Cross-agent rollout (a többi agent watcher-egységei) — koordináció a bridge-en.
- **P2 (eladható csomag):** `bus tail -f` élő-chat nézet, presence („ki van ébren"), és a wake-protokoll dokumentálva.

**DÖNTÉS, ami az üzemeltetőé:** a Réteg B headless-ébresztés impaktos (autonóm sessiont indít + token + cross-agent). A P0-t
bármikor megépíthetem (reverzibilis, additív). A P1-hez kell a Te zöld utad (és a többi agent operátorának koordinációja).
