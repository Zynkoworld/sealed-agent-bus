# AgentBus v1.4 — kikényszerítés (PR )

**Alap:** egy független támadási mátrix, v0 (2026-09-14). Fő lelete: a busz gyengesége **nem kriptográfiai, hanem kikényszerítési**. Az aláírás megvolt, de a busz csak *jelölte* a hitelességet, és alapból mindent kézbesített — a támadónak nem kellett feltörnie az aláírást, elég volt **elhagynia** (unsigned-downgrade).

Ez a PR a termék-profil kapuját adja, úgy, hogy az élő flotta (dev mód) viselkedése bájtra változatlan marad.

---

## 1. Termék-mód — `bus_enforce.py`

**Mit:** egyetlen kapcsoló: `AGENT_BUS_MODE=product` **vagy** a `.product_mode.on` marker a busz könyvtárában. Termék-módban a `recv` a nem megfelelő sort **kiveszi a kimenetből** és okot ír:

| ok | mikor | mátrix |
|---|---|---|
| `unsigned-downgrade` | nincs aláírás | |
| `forged` | érvénytelen aláírás, vagy a registry más kulcsot köt a feladóhoz | |
| `stale-ts` / `future-ts` | az aláírt `ts` az ablakon kívül (alap: −7 nap / +300 s — ; env csak szűkíthet; `AGENT_BUS_WINDOW_PAST_S`, `AGENT_BUS_WINDOW_FUTURE_S`) | |
| `replay` | ugyanaz az aláírt tartalom (aláírt bájtkép + sig) már kézbesült — **új id-vel újra beszúrva is** | |
| `attachment-descriptor` | `attachment` kind, de a leíró hiányos (ugyanaz a validátor, mint a send-nél) | |

Termék-módban az `sds-envelope` sorok **kötelezően** ellenőrzöttek, és csak a `valid` marad.

**Miért így:**
- **Alapból dev.** Ha a default a product lenne, a ma futó, részben aláíratlan flotta-forgalom egy frissítéssel elnémulna — ez maga is csendes hiba lenne. Ezért a kiadási/termék-profil **kifejezetten** bekapcsolja, és az `abus doctor` dev módban hangosan figyelmeztet (rc=1).
- **Semmi nem törlődik.** Az elutasított sor a DB-ben marad (tail/thread látja); az ok az `enforce/rejected.jsonl` naplóba kerül. Peek (nem-mark) recv csak ellenőriz, nem fogyaszt.
- **Tartós seen-tár.** Címzettenként append-only JSONL, fsync-kel; új folyamat is látja (teszt: külön Python-folyamat utasítja el a visszajátszást). A tömörítés csak a frissességi ablak kétszeresénél régebbi kulcsot hagyja el — azt a ts-kapu úgyis elutasítja. Külön fájl → **nincs DB-séma-változás**, `SCHEMA_VERSION` marad 1.0.0.
- **A csatolmány leírója aláírt.** A leíró a `body`-ban él, a `body` része az aláírt mezőknek → a leíró cseréje `forged` (teszt). A tartalom sha-ját a lehúzás (`bus_attach`) ellenőrzi.

## 2. Relay — tartós nonce-tár (`bus_relay.py`)

**Mit:** a lehúzási kérések nonce-cache-e a spool melletti `.pickup_nonces.jsonl`-be is íródik; újraindításkor betöltődik (csak a még élő kulcsok).
**Miért:** a v1.2 memória-cache mellett újraindítás után egy <2 perces aláírt lehúzás egyszer visszajátszható volt (PR nyitott kockázata). Mátrix . Teszt: relay leállítva és újraindítva ugyanazon a spoolon → ugyanaz a kérés 401, friss kérés 200.

## 3. SCE végponttól végpontig (`sce_hook.py`)

**A leképezés (szerződés):** a busz `sds-envelope` body-ja a keretezett `{record, envelope}` pár; **a record `payload` mezője hordozza a `sce-arm-envelope/v1` objektumot** (schema, arm, seed, candidate_package, reference_package, derive_hash[, candidate_hash]). Így az SDS-aláírás a kar-borítékot is köti.
- `arm_envelope_of`: csak a busz által **valid**-nak címkézett sorból ad kar-borítékot. Aláíratlan vagy hamis sorból nincs kar → a döntő hiányzó karra **ABORT**, nem „két kar is elég". (Mátrix egy kar nem dönthet, és egy megvesztegetett, aláírás nélküli kar nem léphet be.)
- `decide_rows`: sorok → kar-borítékok → döntő (`AGENT_BUS_SCE_DECIDER`).
- Tesztek: hamis döntő a külső adapter szerződésével (ACCEPT, REJECT nem-utód, ABORT hiányzó kar / aláíratlan kar / derive-eltérés), és egy opcionális teszt a **valódi** külső `sce_bus_adapter:decide`-dal (hiányzó karra ABORT; kihagyva, ha a motor nincs a gépen). Motor-kód nem került a buszba.

## 4. Ügyelet — háttér-shell (`agent_duty.py`)

A státuszsorban látszó futó háttér-shell (`· 5 shells ·`) munkának számít: egy mérésre váró agentet nem bökünk meg (a flottában 09-14-én kétszer előfordult).

---

## Maradék kockázatok (kimondva)

- **A kikényszerítés csak product módban él.** Aki kiadásnál nem kapcsolja be, a v1.3 viselkedést kapja — ezért a `doctor`, de ez figyelmeztetés, nem kényszer.
- **A feladó maga választja a `ts`-t.** Az ablak a régi (visszadátumozott) üzenetet fogja meg, de az ablakon belüli visszadátumozást nem; ehhez a közjegyzői napló kell (érkezési idő + ujjlenyomat, PR terv) .
- **Óra-eltérés.** A +60 s jövő-ablak NTP-szinkront feltételez; nagy eltérésű gépen legitim üzenet is `future-ts` lehet.
- **A seen-tár helyi.** Két fogadó példány ugyanarra a címzettre két tárat lát; a single-flight (egy aktív worker) ezt fedi, de elosztott fogadóra nem elég.
- **DoS és prompt-injekció nincs ebben a PR-ban.** A poke fix szöveg marad; a busz-tartalom adat. Rate-limit: következő kör.
- **A közjegyzői napló átírása :** a `cursor_audit` hash-lánc megvan, de a lánc-ellenőrzés rendszeres futtatása és a két félnek letölthető napló a PR tárgya.
- **Forward secrecy** továbbra sincs a relay-titkosításban (statikus X25519).
- Minden kar és ez a kód is Claude-agent munkája; a független támadó (Codex, 09-28-tól) még hátravan.

## utáni állapot (2026-09-14)

- A „tartós seen-tár" a kézbesítő `recv --mark` útján ma a busz-DB `enforce_seen` táblája (/); a `SeenStore` fájl-osztály csak back-compat API.
- Az elutasítás nem veszít postát: `enforce_reject:<ok>` audit-sor + `reconcile` jelölt . Termék-módban a `replay --commit` `system` feladóval küld — ha a `system`-nek nincs aláíró kulcsa, az újrakézbesített sor is elutasítódik (nyitott: operátori aláíró kulcs a replayhez).
- A részletes lelet → javítás táblát a CHANGELOG v1.4 szakasza foglalja össze.
