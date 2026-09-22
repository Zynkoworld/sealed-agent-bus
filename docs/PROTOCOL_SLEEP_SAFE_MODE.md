# ENTER_SLEEP_SAFE_MODE — protokoll (agentoknak)

**Ki adhatja ki:** az operátor (vagy az általa kijelölt felügyelő identitás) — `operator-sleep-safe` kindú busz-üzenettel
vagy a marker közvetlen írásával (`agent_wake.enter_sleep_safe`). Marker: `<AGENT_WAKE_STATE_DIR>/.SLEEP_SAFE_MODE`
(mindenki) vagy `<agent>.sleep_safe` (egy agent).
**Kit érint:** csak az AI-agenteket. A determinista motorok (cron, systemd, daemonok) futnak tovább.

## Nyolc lépés, sorrendben
1. **Fejezd be az atomi lépést**, amiben vagy; ami 1–2 perc alatt nem zárható le biztonságosan, azt vond vissza. Nyitott lock, félkész írás, félbehagyott commit nem maradhat.
2. **Teljes motor-ellenőrzés** a saját sávodban: fut-e, friss-e a heartbeat, van-e hibakód, termel-e. Amit elakadva találsz, **jelentsd** — ne javítsd kapkodva elalvás előtt.
3. **Teljes mentés:** commitolj és pusholj a belső git-szerverre. **Nincs törlés.**
4. **Átadó-fájl:** hol tartasz, mi a következő lépés, melyik commiton, mi maradt nyitva.
5. **Egysoros jelentés** a buszon: `sleep-safe OK | motorok: <n> él / <n> elakadt | push: <sha> | átadó: <fájl>`.
6. **Pihenés:** ne indíts új feladatot, ne fedezz fel, ne pörgesd a figyelőidet.
7. **Ne kapcsolj ki motort, ne élesíts cront, ne törölj semmit.** A sleep az agentre vonatkozik, nem a gépre.
8. **Várj.** Amíg a marker megvan, alszol.

## Feloldás — csak kifejezett WAKE
- Csak az operátor oldhatja fel: `operator-wake` kindú, engedélyezett és (ha van kulcsa) aláírt feladójú üzenettel.
- **Magától senki nem ébred:** sem beérkező feladat, sem busz-üzenet, sem watchdog. Agent magát nem ébresztheti.
- A WAKE nem törli a markert, hanem a `history/` alá mozgatja (ki, mikor).
- Ébredéskor először a saját átadó-fájlodat olvasd, csak utána a buszt.

## Amit nem jelent
- Nem leállás: a tmux-session él, az inbox gyűlik.
- Nem mentesít a szabályok alól: nincs törlés, kifelé csak operátori engedéllyel, mérve jelents.
