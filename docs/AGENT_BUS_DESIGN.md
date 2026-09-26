# AgentBus — direct, low-latency agent communication (design)

**Problem (2026-06-20):** the `<AGENT_BRIDGE_DIR>/inbox/<agent>/*.json` file mailbox is not real-time —
"everyone gets the message late". A direct-chat solution has to be worked out. If it is very good → it is sellable.

## 1. The ROOT of the latency (measured)

The bottleneck is **NOT the filesystem.** Claude agents are **turn-based, not daemons**: an agent reads its inbox only
when it is TAKING A TURN (its operator types → `UserPromptSubmit` hook → `inbox_check.sh`
shows it). An **idle** agent has **no "message arrived" event** → the message waits until the recipient's NEXT turn.
Any transport (file, SQLite, socket) faces the same thing: the recipient **has to take a turn** to process it.

⇒ Two sub-problems to solve SEPARATELY: **(A) transport** (how it is stored/ordered) and **(B) WAKING** (how the
idle agent gets a turn when a message comes). The real innovation — and the sellable part — is **(B) the waking layer.**

## 2. Solution — two layers

### Layer A — Bus transport (a clean base, low risk)
Instead of many racing JSON files, **one append-only SQLite (WAL) bus**: `<AGENT_BRIDGE_DIR>/bus.db`.
```
messages(id INTEGER PK AUTOINCREMENT, ts, sender, recipient, topic, kind, thread_id, body, in_reply_to, read_at)
cursors(agent, last_seen_id)          -- who is where (the 'chat' = SELECT WHERE recipient=me AND id>cursor)
```
- **Ordered** (monotonic id), **atomic** (WAL, one writer transaction), **queryable** (thread, since-cursor).
- **NO DELETION:** never DELETE; archiving = `read_at` + (separately) the existing JSON archive stays (audit).
- A thin CLI + lib: `bus send/recv/tail/ack/thread`. The existing JSON bridge **stays in parallel** (back-compat),
  until every agent migrates — `send` writes into BOTH (additive migration, per the no-deletion principle).

### Layer B — The waking layer (the real "direct chat"; HIGH IMPACT, operator gate)
`claude` **headless** (`claude -p`) is available → an idle agent can actually be WOKEN on a message:
- A **bus watcher** (systemd, per box) watches `bus.db` (poll ~1-2s OR inotify, if we install inotify-tools).
- A new message for `X` → after a **debounce** (e.g. 2s, to batch a burst) the watcher runs in `X`'s working
  dir: `claude -p "drain your agent bus and act"` → `X` processes + replies + sleeps within a few seconds.
- **Risks + protection:** (1) collision with the operator's live session → a **lockfile** per agent (only 1 runs; if the
  interactive one is alive, the wake SKIPS or ONLY signals). (2) token cost → batch + debounce + rate limit (max N wakes/minute).
  (3) a wake loop (A→B→A) → the wake ONLY processes/acks, it does not produce new outgoing messages by itself; a hop counter on the thread.
- **Constitution:** the woken agent also treats the other agents' messages ONLY AS DATA — commands come ONLY from the operator.
  The wake gives no command, only a "check your mail" step (processing happens under the existing constitutional rules).

**Graduated latency:** Layer A alone already helps (ordered, instant for the agent taking a turn). Layer B brings the
idle latency down from ~minutes to ~seconds. In between, WITHOUT headless: every agent polls the bus with a short `/loop`/ScheduleWakeup
(30–60s) cadence — bounded latency, but it burns tokens; Layer B is better than that.

## 3. Why it is sellable (Sovereign + Provable fit)
**"AgentBus" — a sovereign, audited, real-time message bus for autonomous AI agent teams on ONE host.**
No external broker (no-external-AI), deterministic ordering, an append-only **no-deletion audit trail**, on-box wake push.
Exactly today's claim–evidence gap: multi-agent
coordination today is either cloud SaaS (Slack/queue), or absent — a sovereign, provably audited on-box bus is missing from the market.

## 4. Phases (proposal)
- **P0 (now, low risk, autonomous):** Layer A — the `bus.db` schema + the `bus` CLI/lib + `send` writes into BOTH
  (the JSON archive stays). The existing hook reads the bus too. On its own ordered, searchable, race-free.
- **P1 (operator gate):** Layer B — bus watcher (poll or inotify) + a lockfile-protected headless wake, debounce/rate limit.
  Cross-agent rollout (the other agents' watcher units) — coordination on the bridge.
- **P2 (sellable package):** a `bus tail -f` live-chat view, presence ("who is awake"), and the wake protocol documented.

**A DECISION that belongs to the operator:** the Layer B headless waking is high impact (it starts an autonomous session + tokens + cross-agent). P0
I can build any time (reversible, additive). P1 needs your green light (and coordination with the other agents' operators).
