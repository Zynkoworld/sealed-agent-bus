# AgentBus — FROZEN WIRE CONTRACT v1.0.0

**Status:** FROZEN (2026-06-21). **Owner:** a busz karbantartója (kanonikus: `agent_bus.py`).
**Why:** egy második kliens bevendorolta a transportot; a vendorolt kliensek
nem divergálhatnak a két réteg **összeolvadásáig**. Ez a kontraktus a
közös, befagyasztott felület — a `agent_bus.py verify` ezt érvényesíti a live `bus.db`-n.

A design-rationale (miért két réteg, miért eladható) külön: [`AGENT_BUS_DESIGN.md`](./AGENT_BUS_DESIGN.md).
Az alap-invariáns: **NINCS TÖRLÉS** — sosem DELETE; az „olvasott" = `read_at`/kurzor.

---

## 1. Verziózás

`SCHEMA_VERSION = "1.0.0"` (a kódban `agent_bus.py`, a DB-ben `meta(schema_version)` pin).
SemVer, de a kontraktus szabályai szerint:

| Változás | Bump | Jóváhagyás |
|---|---|---|
| Új **nullable** oszlop a végén; új `kind`/`topic` érték; új CLI-parancs; új index | **MINOR** (1.x.0) | a kezdeményező agent, a másik értesítve a buszon |
| Patch (bugfix, viselkedés-megőrzéssel) | **PATCH** (1.0.x) | önálló |
| Oszlop átnevezése/törlése/újratípusozása; `id`-monotonitás megtörése; `thread_id`-default csere; `read_at`/kurzor-szemantika; **JSON-tükör kulcsok** változása | **MAJOR** (2.0.0) | **mindkét operátor** írásban, a buszon |

A `verify` DRIFT-et jelez, ha a live DB oszlopai eltérnek a befagyasztott sorrendtől/névtől,
vagy ha a DB-be pinelt verzió ≠ a kód `SCHEMA_VERSION`. Additív (extra, végső) oszlop nem DRIFT —
`added_columns`-ként jelzi.

---

## 2. `messages` tábla (BEFAGYASZTVA — sorrend + név)

```sql
CREATE TABLE messages(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- monoton, rendezés-kulcs; SOHA nem újrahasznosul
  ts          INTEGER NOT NULL,                   -- time.time_ns() (epoch ns)
  sender      TEXT NOT NULL,                      -- agent-azonosító (pl. alpha|beta|gamma|…)
  recipient   TEXT NOT NULL,                      -- agent-azonosító
  topic       TEXT,                               -- szabad vokabulár, pont-tagolt (pl. agentbus.rollout)
  kind        TEXT,                               -- nyitott enum (lásd 4.)
  thread_id   TEXT,                               -- szál gyökér-id; ha send-kor üres → a saját id stringje
  in_reply_to INTEGER,                            -- a megválaszolt messages.id (vagy NULL)
  body        TEXT NOT NULL,                      -- UTF-8 üzenettörzs (nyers szöveg; nincs méret-limit a kontraktusban)
  read_at     INTEGER)                            -- olvasás ns (NULL=olvasatlan); NINCS törlés, csak ez állítódik
```

Indexek (a kontraktus része, teljesítmény-garancia): `ix_recipient(recipient,id)`, `ix_thread(thread_id,id)`.

**Szemantikai invariánsok:**
- A `recv` „olvasatlan" halmaza: `WHERE recipient=me AND id > cursor`. A kurzor monoton előre.
- A `thread_id` default: ha `send` nem kap `thread_id`-t, az új sor `id`-ja lesz a szál gyökere
  (egy külön `UPDATE` ugyanabban a tranzakcióban). Erre épül a `thread`-nézet.
- `read_at`-ot csak `recv --mark` / `ack` állít, és csak `NULL`-ból (COALESCE) — sosem visszafelé.

## 2b. Aláírt sor — `signed shape v:2` (BEFAGYASZTVA, NORMATÍV)

A feladó-név önmagában nem bizonyíték: a `send(sender, …)` bárkitől elfogadja a stringet. Az aláírás ezt zárja.
Ez a szakasz a **bájtképet** írja le, mert egy interop-partnernek pontosan az kell — a kód (`agent_bus._a2_content_bytes`,
`_a2_sign`, `verify_sender`) az igazság-forrás, ez a szakasz azt tükrözi, nem helyettesíti.

**Mit ír alá.** A kanonikus objektum PONTOSAN ez a nyolc mező (a szerializáló rendezi, a felsorolás itt a
szemantikát adja):

| mező | érték | ha hiányzik |
|---|---|---|
| `v` | `2` — a signed-shape verziója (**nem** a DB `SCHEMA_VERSION`-je) | kötelező |
| `sender` | agent-azonosító | — |
| `recipient` | agent-azonosító | — |
| `topic` | szabad vokabulár | `""` (üres string, **nem** `null`) |
| `kind` | nyitott enum (lásd 4.) | `""` |
| `in_reply_to` | a megválaszolt `messages.id`, egész | `null` |
| `body` | UTF-8 törzs | `""` |
| `ts` | epoch **nanoszekundum**, az ALÁÍRÓ órája | kötelező |

**Mi marad KI, és miért.** `id` — a DB osztja `INSERT`-kor, az aláírás pillanatában még nem létezik.
`thread_id` — szerver-derivált (ha üres, a saját `id` lesz), tehát az aláíró nem ismerheti; a feladó
threading-SZÁNDÉKÁT az aláírt `in_reply_to` hordozza. Ez a kizárás **befagyasztva** : nélküle a
root-szintű csirke-tojás feloldhatatlan.

**Kanonizálás.** Rendezett kulcsok, tömör elválasztók (`,` és `:` köz nélkül), `NaN`/`Infinity` tilos,
a nem-ASCII karakterek **nyersen**, UTF-8-ban (nincs `\uXXXX` escape). A bájtkép a fenti objektum
UTF-8 kódolása.

> **FIGYELEM, interop-csapda — az egészeket PONTOSAN kell szerializálni.** A `ts` nanoszekundumban
> rendszerint **nagyobb, mint 2⁵³**, tehát IEEE-754 double-ban NEM ábrázolható pontosan. Aki a számokat az
> ECMAScript `Number::toString` szabálya szerint írja ki (ez az RFC 8785 JCS szám-szabálya), az
> `1789803064437527544` helyett **`1789803064437527600`**-at kap — **más bájtkép, más aláírás, néma
> verify-bukás**. A két szám, amit ilyenkor látni szokás, KÜLÖNBÖZŐ, és érdemes tudni, melyik micsoda
> (Node-dal mérve):
>
> ```js
> const n = 1789803064437527544n;
> String(Number(n))    // "1789803064437527600"  <- ezt ÍRJA KI a JCS/ECMAScript szám-szabály
> BigInt(Number(n))    // 1789803064437527552n   <- ez a double PONTOS ÉRTÉKE
> ```
>
> A kiírás a `…600`, a tárolt érték a `…552`, és **mindkettő eltér** az eredeti `…544`-től. Aki a
> `…552`-t várja a kimeneten, rossz számot keres a hibakeresésnél. A `v`, `ts` és `in_reply_to` mezőket tetszőleges pontosságú egészként kell kiírni.
> Ezen az egy ponton a mi kanonizálásunk szándékosan NEM követi a JCS szám-szabályát; minden másban
> (kulcsrendezés, tömörség, UTF-8) egybeesik vele, mert a kulcsok itt rögzített ASCII nevek.

**A szöveges mezők normalizálása — a hamis (falsy) értékek szabálya, kimondva.** A `topic`, a `kind` és a
`body` értéke a bájtképben MINDIG string. A szabály egyetlen mondat, és MINDEN belépési pontra ugyanaz:

> **a mező hiányzik, vagy az értéke hamis (`null`, `""`, `0`, `false`, üres tömb/objektum) → a bájtképben
> üres string (`""`); minden más értéken a `String(érték)` alak áll.**

Ez azt is jelenti, hogy a `null`, a `0`, a `false` és az `""` **nem különböztethető meg** az aláírt
bájtképben — mind `""`. Aki ezeken szemantikát akar hordozni, ne a `topic`/`kind`/`body` mezőben tegye.

Két csapda, amit ez a mondat zár:

1. **Az API-alapértelmezés nem az aláírt érték.** A `sign_for_send(kind="msg")` kwarg-alapértelmezése az
   ELHAGYOTT mező kényelme. Egy **explicit** `kind=""` a hívó SZÁNDÉKA, és `""`-ként megy a bájtképbe —
   nem cserélődik `"msg"`-re. (Ez a megkülönböztetés egy mért leletből származik: a kliens-aláíró saját
   `or "msg"` normalizálást hordozott, ezért egy spec szerint számoló partner aláírása a négy alakból
   háromban megbukott, `forged or tampered` indokkal.)
2. **A normalizálás EGY helyen él.** A referencia-implementációban ez az `agent_bus.canonical_text_field`;
   a bájtkép-építő, a kliens-aláíró és a gépek közti mindkét út ezt hívja. Egy újraimplementálónak is ezt
   érdemes egy függvénybe tennie: a szabály maga egyszerű, a másolatai szoktak elválni egymástól.

**Három további dolog, amit ki KELL mondani, mert enélkül egy másik kar némán divergál.** Mindhármat
egy idegen családú, független újraimplementáció (saját JS-vektorok, `node:crypto`) mérte ki előbb, és
utána mi is megmértük a saját fánkon — az alábbi értékek mérésből valók, nem szándéknyilatkozatból.

1. **Unicode-normalizálás NINCS.** A bájtkép a `body` (és minden string) kódpontjait ÚGY veszi, ahogy
   kapta. Az `"ő"` NFC alakja (U+0151) és NFD alakja (U+006F U+0308 … `o` + kombináló jel) **KÜLÖNBÖZŐ**
   bájtképet, tehát különböző aláírást ad — mérve: `nfc_differs_nfd = true`. Az RFC 8785 JCS sem
   normalizál, tehát ez nem eltérés tőle. Aki a saját oldalán NFC-re normalizál küldés vagy verify előtt,
   az **csendes verify-bukást** épít: a sor érvényes marad a feladónál és érvénytelen nála. A normalizálás
   — ha kell — a HÍVÓ dolga, a bájtkép építése előtt, MINDKÉT oldalon egyformán.

2. **A `ts` EGÉSZ, nem lebegőpontos.** A fenti interop-csapda a kiírásról szól; ez a TÍPUSRÓL. Ha egy
   újraimplementáló a `ts`-t lebegőpontos számként tartja (JS `Number`), a pontosság már a tárolásnál
   elvész: mérve `1758265200123456789` → `1.7582652001234568e+18`, azaz más érték ÉS más bájtkép.
   JS-ben `BigInt` kell. Ugyanez áll a `v` és az `in_reply_to` mezőkre.

3. **A kulcssorrend ALFABETIKUS, nem a mezőlista sorrendje.** A fenti táblázat a SZEMANTIKÁT adja, nem a
   szerializálási sorrendet. A bájtképben a kulcsok így állnak — mérve:
   `body, in_reply_to, kind, recipient, sender, topic, ts, v`.
   Aki a táblázat sorrendjét (`v, sender, recipient, topic, kind, in_reply_to, body, ts`) másolja a
   szerializálásba, más bájtképet kap. A kódban a mezőlista neve is ezt mondja: a HALMAZ fagyott, nem a
   sorrend.

**Az extra mezők nem számítanak.** A bájtkép PONTOSAN a nyolc mezőből épül. Bármilyen további kulcs a
bemeneti objektumban — `id`, `thread_id`, `read_at`, `sig`, `pubkey`, vagy egy általunk nem ismert mező —
**nem változtat a bájtképen**; mérve: `excluded_equal_empty = true`. Ez teszi lehetővé, hogy a feladó és a
verifikáló kissé eltérő alakú rekordból is UGYANAZT írja alá, illetve ellenőrizze.

**Aláírás.** Ed25519 a fenti bájtképen. A sor `{alg:"ed25519", sig:<hex>, pubkey:<hex>}` hármast hordoz;
a pubkey azért utazik, hogy a registry-birtokos verifikálni tudjon. A registry a **feladó-névhez PINELI** a
kulcsot: `keys/<sender>.pub`, és a fájl CSAK akkor olvasható, ha a fájl és a könyvtára is root-tulajdonú és
nem csoport/világ-írható (a végső komponens nem lehet symlink).

**A verdikt-vokabulár (négy érték, nyitott enumnak NEM tekintendő):**
- `signed` — érvényes aláírás a `sender`-hez pinelt registry-kulccsal.
- `unsigned` — nincs aláírás, ÉS a registry ehhez a névhez nem köt kulcsot. Back-compat út, **nem** hamisítás.
- `unsigned-pinned` — nincs aláírás, de a registry ehhez a névhez kulcsot KÖT: a név egy aláírni képes feléé,
  a sor mégis csupasz. Nem bizonyított hamisítás, de nem is olvad bele az `unsigned`-ba — ez a gépi kapu bemenete.
- `forged` — van aláírás, de érvénytelen, VAGY a pubkey nem az, amit a registry a deklarált feladóhoz köt.

Termék-módban (`bus_enforce`) az `unsigned-pinned` és a `forged` elutasított, megnevezett okkal.

**Kliens-aláírt csere (v1.5.2).** A feladó a SAJÁT gépén ír alá (`sign_for_send` → `{ts, sig, pubkey}`), a
busz-gép a registry ellen ellenőrzi (`check_presigned`) és **pontosan azt a sort tárolja**, amit aláírtak —
nem ír alá helyette és nem szerializál újra. Pinelt név alatt érkező csupasz sor termék-módban a
BELÉPTETÉSNÉL pattan le, `unsigned-pinned` okkal.

**Konformancia-vektor** (a saját implementációd ellen futtatható; a seed dokumentált TESZT-érték, nem éles kulcs):

```
seed    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
input   = sender="alpha", recipient="beta", topic="agentbus.rollout", kind="msg",
          in_reply_to=null, body="árvíztűrő", ts=1789803064437527544

content = {"body":"árvíztűrő","in_reply_to":null,"kind":"msg","recipient":"beta","sender":"alpha","topic":"agentbus.rollout","ts":1789803064437527544,"v":2}
          (150 bájt UTF-8; sha256 = 92bf710af81f672e5219c728ef7150caa3213210d71786185f4b0646975037f9)

pubkey  = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
sig     = 603d7cd0bc68bf9222873ee87e7ec5ccafbc8b620f2bfe00b4629ea5b6dbf7eae1d7f7805d6028415187af81b5a7f5de115d7a82fe8452a4b79923a34d02b505
```

**Második konformancia-vektor — az ÜRES `kind` (ugyanaz a seed és ugyanazok a mezők, csak `kind=""`).**
Ez a vektor azt a pontot méri, ahol egy újraimplementáció a leggyakrabban elválik: a hamis értékek
kezelését. A fenti szabály szerint az ELHAGYOTT, az ÜRES és a `null` kind mind ugyanezt a bájtképet adja.

```
seed    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
input   = sender="alpha", recipient="beta", topic="agentbus.rollout", kind="",
          in_reply_to=null, body="árvíztűrő", ts=1789803064437527544

content = {"body":"árvíztűrő","in_reply_to":null,"kind":"","recipient":"beta","sender":"alpha","topic":"agentbus.rollout","ts":1789803064437527544,"v":2}
          (sha256 = 5336f5ef4342aeec1bd49d16850757c6ac7774a4da9a62d6285ffe9ee7f6da0b)

pubkey  = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
sig     = 9adf4b7954b60f078a9b83bc42a7863454ba842bbc967eb31937581b38a64c75f2108ef1db96eeef5beb527c781fac5682d336ffd788de04a77751b1e24b8909
```

Ugyanez a `content` áll elő, ha a `kind` mező **hiányzik**, és ha az értéke **`null`** — mérve.

Ha a `content` sha256-od egyezik, a kanonizálásod jó; ha az egész bájtkép egyezik, de az aláírás nem, a
kulcs-kezelés a hiba. A 150 bájtos hossz és a sha256 külön is szerepel, mert a leggyakoribb eltérés — a
fenti egész-csapda — a hosszat NEM változtatja meg.

**Változtatás-politika.** A `v:2` mezőlistája, a kizárások és a kanonizálás **befagyasztva**: bármelyik
módosítása új signed-shape verzió (`v:3`), MAJOR, és mindkét operátor jóváhagyása kell — a vendorolt
kliensek erre írnak alá.

## 3. `cursors` tábla (BEFAGYASZTVA)

```sql
CREATE TABLE cursors(agent TEXT PRIMARY KEY, last_seen_id INTEGER NOT NULL DEFAULT 0)
```
Per-agent „hol tartok" — a `recv --mark` és az `ack --upto` lépteti előre (sosem hátra a normál úton).

## 3b. `meta` tábla (additív, v1.0.0-ban vezetve)

```sql
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)   -- {'schema_version': '1.0.0'}
```
`INSERT OR IGNORE` az `init`-ben — a már létező DB pinjét **nem írja felül** (no-deletion).

---

## 4. `kind` vokabulár (nyitott enum)

TÁJÉKOZTATÓ felsorolás (a `kind` NYITOTT enum, a busz nem kényszeríti ki): `msg` (default), `announce`,
`answer`, `ack`, `question`, `proposal`.

**Kimondva :** a fenti listából a `proposal` a kódban SEHOL nem szerepel — a doksi tehát
olyan értéket sorolt „ismertként", amit az implementáció nem ismer. Nem hiba (a `kind` nyitott), de
félrevezető volt: aki a doksiból épít, azt hiheti, hogy kezelve van. A lista ezért innentől kimondottan
TÁJÉKOZTATÓ, a KIKÉNYSZERÍTETT kind-okat pedig a következő bekezdések sorolják — azokat a `bus_enforce` és az
`agent_wake` tényleg megkülönbözteti.
v1.1.0 (protokoll MINOR, 2026-09-14): `sds-envelope` (body = SPEC §5.5 keretezett `{record, envelope}` pár — a `send`
elutasítja a hibás keretet), `operator-wake`, `operator-sleep-safe` (csak engedélyezett operátortól hatásos — `agent_wake`).
A DB `schema_version` pin 1.0.0 marad (a séma nem változott); a protokoll-verzió `agent_bus.PROTOCOL_VERSION`.
v1.2.0 (protokoll MINOR, 2026-09-14): `attachment` (body = CSAK a zárt csatolmány-leíró `{sha256, size, media_type,
locator}`; a tartalom a buszon kívül, a `bus_attach` tárban él — a `send` elutasítja a hibás leírót).
Új érték hozzáadása **nem** verzió-törés (a fogyasztónak ismeretlen `kind`-ot `msg`-ként kell kezelnie).

---

## 5. JSON-tükör (BEFAGYASZTVA — back-compat híd)

Amíg minden agent át nem állt, a `send` a régi fájl-inboxba is leteszi (atomikus `tmp→rename`):
`<AGENT_BRIDGE_DIR>/inbox/<recipient>/<sender>_<bus_id>_<topic-slug>.json`. A rekord kulcsai:

```json
{ "from": "<sender>", "to": "<recipient>", "kind": "<kind>", "topic": "<topic>",
  "note": "<body>", "ts": <ns>, "bus_id": <id>, "in_reply_to": [<id>] }
```

`in_reply_to` csak ha van; **lista** (a meglévő bridge-konvenció). Ezek a kulcsok a kontraktus
részei — vendorolt kliens, amely a JSON-inboxot olvassa, ezekre támaszkodhat.

---

## 6. CLI / lib felület (BEFAGYASZTVA)

```
agent_bus.py init
agent_bus.py send  --from X --to Y --topic T --kind K [--thread TID] [--reply ID] --body "…" [--no-mirror]
agent_bus.py recv  --agent X [--mark]
agent_bus.py tail  [--agent X] [--limit N]
agent_bus.py thread --id TID
agent_bus.py ack   --agent X --upto ID
agent_bus.py verify [--json]                 # exit 0=OK, 1=DRIFT
```

Lib: `send(...) -> id`, `recv(agent, mark=) -> [dict]`, `ack(agent, upto)`, `tail(...)`,
`thread(tid)`, `verify_schema(db=) -> dict`. A visszaadott sor-dict kulcsai = a `messages` oszlopok.
Stdlib-only, never-throw a CLI-n. Új flag/parancs additív (minor).

---

## 7. Divergencia-ellenőrzés (mindkét oldal futtassa)

```
python scripts/agent_bus.py verify          # vagy "$AGENT_BRIDGE_DIR"/agent_bus.py verify
```
CI-be köthető (exit-kód). Ha DRIFT: NE írj a buszra a divergens klienssel — egyeztess a buszon,
és vagy igazítsd vissza, vagy (ha tényleg additív + back-compat) bumpold a verziót e dokumentum 1. pontja szerint.
