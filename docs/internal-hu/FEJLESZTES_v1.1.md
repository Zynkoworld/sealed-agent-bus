# AgentBus v1.1 — mit fejlesztettünk és miért (2026-09-14)

A külső értékelés után két irányban léptünk: behoztuk azokat a
szabályokat, amelyeket az élő flotta üzemeltetése közben tanultunk, és megcsináltuk a külső review három additív SDS-lépését.

## 1. Amit az élő flottából hoztunk

### „Ne írjon a chatboxba" — a gépelés szent
Az operátor közvetlenül is gépel az agentek promptjába. Egyszer egy automatikus bökés előtti „beragadt szöveg törlése"
(C-u) kitörölte az operátor beírt, el nem küldött parancsát. Egy másik alkalommal a bökés nem az agent paneljébe,
hanem a session aktív (chatbox) paneljébe ment. A szabály azóta:
- a bökés mindig az agent (`claude`) paneljére pinnelődik, soha nem az aktív panelre;
- küldés előtt megnézzük a prompt-sort: ha élő szöveg van benne, **nem küldünk**;
- **soha nincs C-u**; ha a saját szövegünk ragadt a promptban, jelentjük (`stuck`), nem töröljük;
- kétség esetén „gépel" — egy elmaradt bökés ártalmatlan, egy felülírt parancs nem.
Kód: `agent_wake.prompt_input_state`, `agent_wake.safe_send`, `bus_poke.inject_status`.

### Sleep-safe — „ne zaklassa és ne egye a tokent"
Az operátor elaltathatja az agenteket (mindet vagy egyenként). Alvó agent panelébe nem megy bökés, és a headless
watcher sem ébreszti — akkor sem, ha van olvasatlan üzenete. A motorok közben futnak.
Protokoll: `docs/PROTOCOL_SLEEP_SAFE_MODE.md`. Kód: `agent_wake.is_asleep / enter_sleep_safe / wake_up`.

### Wake-up — csak az operátor ébreszt
`operator-wake` / `operator-sleep-safe` kindú busz-üzenet csak az `AGENT_WAKE_OPERATORS` listán szereplő feladótól
számít; ha a feladónak van registry-kulcsa, az üzenetnek érvényesen aláírtnak kell lennie (A2). Agent magát nem
ébresztheti. A WAKE nyomot hagy (`history/`), semmit nem töröl.

### Egy agent — egy instancia
`bus_singleflight`: ha ugyanabból az agentből két session fut, csak az egyik drainel (session-lock + atomi claim).

## 2. A külső review három lépése — SDS boríték a buszon

| lépés | mit csinál | kód |
|---|---|---|
| 1. boríték mint busz-üzenet | `send --kind sds-envelope`: csak SPEC §5.5 keretezett `{record, envelope}` fogadható el | `sds_envelope.check_framed_shape`, `agent_bus.send` |
| 2. ellenőrzés a fogadó oldalon | `recv --verify-sds` → `valid / invalid(ok) / unsigned / unverifiable(ok)`; `--strict-sds` csak a valid sds-sorokat adja | `sds_envelope.verify`, `agent_bus._sds_annotate` |
| 3. kormányzás-híd | helyi admission-fájl (feladó → issuer/org/role) + A2 kulcs-registry: `not-admitted`, `key-mismatch`, `forged-sender` | `sds_envelope.verify`, `agent_bus._sds_annotate` |

A beépített ellenőrzés **szándékosan minimális**: §2 record_id újraszámolás szűk JCS-profillal, §5.5 fogadó-oldali
domain_hash és record_id-kötés, §5 aláírt üzenet-oktettek issuerenként. Nem ellenőrzi a JOINT genezis-láncot (§5.1–5.2),
a gyenge kulcs predikátumot (§5.6) és a teljes elutasítási sorrendet (§3) — ezekre a cserélhető validátor való
(`AGENT_BUS_SDS_VALIDATOR=modul:függvény`, pl. a capsule2 referencia-verifikátor köré írt adapter).
Kereszt-ellenőrzés: a beépített record_id mind a 7 pozitív `framed_vectors.jsonl` páron egyezik.

## Verziók
- `PROTOCOL_VERSION = 1.1.0` (új kindok + új recv-kapcsolók, additív).
- `SCHEMA_VERSION = 1.0.0` marad: a DB-séma nem változott, és a `verify` minden pin-eltérést DRIFT-nek jelez.

## Tesztek
`python3 -m pytest -q` a repó gyökerében.
