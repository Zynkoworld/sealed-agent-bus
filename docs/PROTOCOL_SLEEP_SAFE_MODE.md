# ENTER_SLEEP_SAFE_MODE — protocol (for agents)

**Who can issue it:** the operator (or a supervisor identity they designate) — with a bus message of kind `operator-sleep-safe`
or by writing the marker directly (`agent_wake.enter_sleep_safe`). Marker: `<AGENT_WAKE_STATE_DIR>/.SLEEP_SAFE_MODE`
(everyone) or `<agent>.sleep_safe` (one agent).
**Whom it affects:** only the AI agents. The deterministic engines (cron, systemd, daemons) keep running.

## Eight steps, in order
1. **Finish the atomic step** you are in; whatever cannot be closed safely within 1–2 minutes, roll back. No open lock, half-finished write or abandoned commit may remain.
2. **A full engine check** in your own lane: is it running, is the heartbeat fresh, is there an error code, is it producing. Whatever you find stuck, **report it** — do not fix it in a hurry before falling asleep.
3. **A full save:** commit and push to the internal git server. **No deletion.**
4. **Handover file:** where you are, what the next step is, on which commit, what remained open.
5. **A one-line report** on the bus: `sleep-safe OK | engines: <n> alive / <n> stuck | push: <sha> | handover: <file>`.
6. **Rest:** do not start a new task, do not explore, do not spin your watchers.
7. **Do not switch off an engine, do not arm a cron, do not delete anything.** Sleep applies to the agent, not the machine.
8. **Wait.** As long as the marker exists, you sleep.

## Release — only an explicit WAKE
- Only the operator can release it: with a message of kind `operator-wake`, from an authorized and (if it has a key) signed sender.
- **No one wakes by themselves:** not an incoming task, not a bus message, not a watchdog. An agent cannot wake itself.
- WAKE does not delete the marker, it moves it under `history/` (who, when).
- On waking, first read your own handover file, only then the bus.

## What it does not mean
- It is not a shutdown: the tmux session is alive, the inbox accumulates.
- It does not exempt you from the rules: no deletion, outward only with operator permission, report measured.
