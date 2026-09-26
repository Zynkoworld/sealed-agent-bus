# AgentBus v1.5 — közjegyzői napló (PR )

**Alap:** a v1.4 után két maradék kockázat nyitva maradt.
1. **Visszadátumozás az ablakon belül.** az egyik kar B2-lelete: az aláíró maga választja a `ts`-t. A v1.4 frissességi ablaka (−7 nap / +300 s) a kézbesítést védi, de nem bizonyítja, hogy az üzenet mikor érkezett.
2. **A támadási mátrix .** A napló átírása legyen kimutatható, és az ellenőrzés fusson rendszeresen. A `cursor_audit` hash-lánc a busz-DB-n belül él, így aki a DB-t írja, az a láncot is újraszámolhatja, és nincs második tanú.

A közjegyzői napló a **fogadás tényét** rögzíti a szállítási határon, a fogadó óráján. A láncot időnként aláírt ellenőrzőpont zárja, és ezt **mindkét fél letölti és összeveti**. A napló nem azt bizonyítja, hogy az üzenet igaz, hanem azt, hogy **mikor, kitől (hitelesített identitással) és milyen hash-ű tartalom érkezett**, és hogy a határ elfogadta vagy elutasította.

---

## 1. Bejegyzés és ellenőrzőpont — `bus_notary.py`

| mező | jelentés |
|---|---|
| `seq` | 1-től folytonos. Egy rés egy **már megírt** bejegyzés törlését bizonyítja; egy **meg sem írt** bejegyzés nem hagy rést (a `seq` a fájl fejéből folytatódik). A kihagyás ellen a `reconcile` véd (lásd 4.) |
| `prev_hash` | az előző bejegyzés `entry_hash`-e (az első esetén genezis `0…0`) |
| `received_at_ms` | a **közjegyző** órája (nem a feladóé) |
| `envelope_sha256` | a boríték kanonikus (JCS) bájtjainak hash-e |
| `sender_identity`, `sender_auth` | `ssh-key` (force-command identitás, nem hamisítható), `pickup-sig` (aláírt lehúzás) vagy `unauthenticated-claim` (a relay `/deliver` `from` mezője nem hitelesített, ezért így is címkézve) |
| `recipient`, `kind` | metaadat |
| `decision`, `reason` | `accepted` / `rejected` / `delivered` (kiadott válasz az SSH-határon) + ok; az `ack` és a kiadási kör kurzor-értékei a `reason`-ben (`cursor A->B (ack U)`, `cursor=C replies=N`) |
| `claimed_ts_ms` | a feladó állított ideje (üzenet- vagy SDS-rekord-`ts`, relay-`ts`; s/ms/µs/ns ms-ra normálva) vagy `null` |

`entry_hash = sha256(JCS(a fenti mezők))`. Az ellenőrzőpont `{seq, head_hash, ts_ms, notary_pub, sig}`, ahol `sig = Ed25519(JCS(sig nélkül))`. Alapból 50 bejegyzésenként keletkezik (`AGENT_BUS_NOTARY_EVERY`), kézzel `bus_notary.py checkpoint --key …`.

**Miért így:**
- **Külön JSONL-fájl, nem DB-tábla.** Így letölthető és offline ellenőrizhető, a busz-DB-hez nem kell hozzáférni, és a `SCHEMA_VERSION` 1.0.0 marad.
- **Csak hash + metaadat.** A sealed `ct`, a nyílt törzs és a csatolmány-tartalom sosem kerül a naplóba; ezt teszt ellenőrzi mindkét határon. A napló így megosztható a másik féllel anélkül, hogy tartalmat szivárogtatna.
- **A fej a fájlból jön, nem memóriából.** Az írás flock alatt történik, fsync-kel; több határ-folyamat (SSH-exchange példányok, relay) ugyanazt a láncot folytatja.

## 2. Export, offline ellenőrzés, összevetés

```
python3 bus_notary.py export --from 1200 > mi.jsonl          # a közjegyző gépén
python3 bus_notary.py verify mi.jsonl --pub <a közjegyző publikus kulcsának 64-hex ÉRTÉKE, nem fájl-út>  # bárhol, hálózat nélkül; rc=1 hibánál
# --pub nélkül: a report `trusted:false`, `signer_unverified:true` (dev: figyelmeztetés; termék-mód: rc=2, megtagadva)
# ellenőrzött ellenőrzőpont nélküli szelet --pub-bal: `trusted:false`, `no_checkpoint_in_range:true` (dev: figyelmeztetés; termék-mód: rc=3)
python3 bus_notary.py compare mi.jsonl ti.jsonl              # a két fél korábbi letöltése; rc=1 eltérésnél
```

| támadás | mit lát a `verify` / `compare` | teszt |
|---|---|---|
| egy bejegyzés átírása | `entry rewritten` az adott seq-nél | `test_edited_entry_fails_at_that_seq` |
| átírás hash-újraszámolással | a következő seq `chain broken`; teljes újraláncoláskor az **aláírt** head nem egyezik | `test_rewrite_with_recomputed_hash_breaks_chain_and_checkpoint` |
| bejegyzés törlése | `gap: entries N..M missing` | `test_deleted_entry_is_a_gap` |
| átrendezés | `reordered` / `chain broken` | `test_reordered_entries_detected` |
| hamis ellenőrzőpont-aláírás | `forged checkpoint signature` | `test_forged_checkpoint_signature_rejected` |
| más kulccsal aláírt ellenőrzőpont | `untrusted key` | `test_checkpoint_by_other_key_rejected` |
| két fél exportja eltér | `first_diff: <seq>` | `test_diverging_exports_report_first_differing_seq` |
| a közjegyző egy bejövő tételt meg sem ír (kihagyás) | `verify` **semmit** (nincs rés); `reconcile`: `sent_not_logged` | `test_reconcile_detects_omitted_inbound` |
| a busz-gép napló nélkül előreugratja a távoli fél kurzorát (elnyelt posta) | `verify` semmit; a következő kör bejegyzése + `reconcile`: `cursor_moved_without_logged_ack`. Ha a közjegyző ehhez egy **kitalált** `ack`-bejegyzést is ír: `ack_logged_not_sent` (a fél nyugtájában nincs ilyen ack). Ha a fél **valódi** ack-ját írja, de a kurzor célját hamisítja (`cursor 0->8 (ack 4)`): `cursor_target_exceeds_ack` — a becsületes clamp `T <= max(F, U)`, ezt a `verify` is jelzi (`ack_target_violations`, rc=1), a fél nélkül, a naplóból. Hazug `delivered` (a fél nem kapta meg): `delivered_not_received` | `test_withheld_outbound_leaves_a_trace`, `test_reconcile_detects_withheld_outbound` |
| visszadátumozott üzenet | `backdated: [seq…]`, a bejegyzés megmarad | `test_backdated_claim_flagged_not_dropped` |
| termék-mód crypto nélkül | `NotaryError`, a határ nem fogad | `test_product_without_crypto_fails_closed`, `test_exchange_fails_closed_when_notary_unavailable` |

## 3. Integráció és mód

- **`bus_ssh_exchange`, bejövő:** üzenetenként és csatolmányonként egy bejegyzés, elfogadva és elutasítva is, **a mellékhatás előtt** (naplózás-előbb: naplóhiba -> nincs busz-beszúrás / tárba írás; send- vagy tár-hiba a naplózás után -> második, `rejected` bejegyzés `send_failed` / `store_failed` okkal). Ha a napló be van kapcsolva, de nem indítható (termék-mód crypto vagy kulcs nélkül), a teljes csere elutasítva: `notary unavailable (fail-closed)`.
- **`bus_ssh_exchange`, kimenő:** a távoli fél `ack`-ja `kind="ack"` bejegyzést kap a kurzor régi->új értékével, **a kurzor mozgatása előtt**; a kiadott válaszok előtt egy `kind="pickup"` kör-bejegyzés (a kurzor és a válaszok hash-listája; akkor íródik, ha van válasz, vagy a kurzor eltér a legutóbb naplózott körétől), majd válaszonként egy `kind="pickup"`, `decision="delivered"` bejegyzés, ahol az `envelope_sha256` a kiadott válasz-dict JCS-hash-e. Bármely naplóhiba -> nincs kurzor-mozgás, és a válaszok nem mennek ki. A csere válasza **napló-horgonyt** ad: `notary: {seq, head_hash}` a kör utolsó bejegyzéséről, így a távoli fél tudja, melyik szeletet kell exportáltatnia.
- **`bus_ssh_client`:** körönként egy nyugta-sor a `…receipts.jsonl`-be: a pontosan elküldött üzenet-dictek, a küldött `ack`, a kapott válaszok, az `accepted` id-k és a horgony.
- **`bus_relay`:** a `/deliver` minden kimenetele (200/400/404/429) és a `/pickup` (hiteles vagy 401) bejegyzést kap. Ha a napló írása nem sikerül, a válasz 503, és a már kiírt boríték kikerül a kézbesíthető sorból: átnevezés `.unnotarized`-re, nem törlés. Így nincs nem naplózott kézbesítés.
- **Mód:** termék-módban (`bus_enforce.mode()`) a napló **be van kapcsolva, és nem kapcsolható ki** (`AGENT_BUS_NOTARY=off` hatástalan). Dev-módban alapból ki van kapcsolva, így a v1.4 viselkedés bájtra változatlan; `AGENT_BUS_NOTARY=on` bekapcsolja.
- **Konfiguráció:**
  - `AGENT_BUS_NOTARY_LOG`: a napló útja (alap `$AGENT_BRIDGE_DIR/notary/notary.jsonl`);
  - `AGENT_BUS_NOTARY_KEY`: 32 bájtos seed; létrehozás: `bus_notary.py keygen --out …`, 0600 jog, a fájl nem íródik felül;
  - `AGENT_BUS_NOTARY_EVERY`: ellenőrzőpont-sűrűség.

## 4. Fenyegetés-modell

**Kinek szól:** két, egymásban nem feltétlenül bízó félnek, a busz üzemeltetőjének (a közjegyzőnek, azaz nekünk) és a távoli félnek, amikor utólag vita van arról, mi érkezett és mikor.

**Egy rosszhiszemű közjegyző (mi magunk):**
- **megtagadhat vagy kihagyhat bejegyzést.** Ezt nem akadályozza meg semmi. **A seq-rés NEM mutatja**: a rés csak egy már megírt bejegyzés **törlésére** bizonyíték; egy meg sem írt bejegyzés után a `seq` folytatódik, a lánc ép, a `verify` `ok:true`. A kihagyás ellen a **feladó-oldali összevetés** véd:
  ```
  python3 bus_notary.py export --from <horgony seq-je körüli tartomány> > napló.jsonl       # a közjegyző gépén
  python3 bus_notary.py reconcile napló.jsonl --identity <én> --receipts <state>/ssh_<cél>__<én>.receipts.jsonl --pub <a közjegyző publikus kulcsának 64-hex ÉRTÉKE, nem fájl-út>
  ```
  A távoli fél újraszámolja a saját elküldött üzeneteinek és kapott válaszainak JCS-hash-ét, és a naplóval veti össze: `sent_not_logged`, `received_not_logged`, `ack_sent_not_logged`, `cursor_moved_without_logged_ack` (napló nélkül előreugratott kurzor = elnyelt posta); rc=1, ha van eltérés. **A reconcile kétirányú**: a nyugtát a naplóhoz ÉS a naplót a nyugtához méri — `ack_logged_not_sent` (naplózott ack, amit a fél nem küldött) és `delivered_not_received` (naplózott kiadás, ami nem érkezett meg). **A közjegyző által írt, aláíratlan `ack`/`delivered` bejegyzés önmagában NEM bizonyíték** — csak a fél nyugtájával együtt; a nyugta a fél igazsága. A `delivered_not_received` lehet túl-naplózás (naplóhiba utáni fail-closed kör) is, ezért a report mindig `ok:false`, a CLI termék-módban vagy `--strict`-tel rc=1, dev-ben rc=0 + stderr-figyelmeztetés. A kliens a kérés-sort (küldött dictek + ack, `round` azonosítóval) a küldés ELŐTT írja a nyugta-fájlba, a kör végén egy `outcome` sort (append-only): `delivered` (a szerver válaszolt — ebből vádol a reconcile), `unknown` (kimehetett, a válasz nem jött vagy hibás — `unresolved` lista, ok:false csak termék-módban / `--strict`-tel), `not-sent` (az ssh el sem indult, vagy 255-tel lépett ki nem-JSON válasszal — nem vád). Így egy el sem jutott kör nem vádolja hamisan a becsületes közjegyzőt. **Maradék rés (réteg-kérdés):** amíg a nyugta a fél saját, aláíratlan fájlja, a vitában szó áll szó ellen; a fél ALÁÍRT nyugtája (sds_envelope / aláírt pickup) a v1.7 iránya. Korlát: a reconcile a szelet teljességére támaszkodik; ha a szelet nem megbízható (`trusted:false`), a `reconcile` figyelmeztet.
- **nem hamisíthat feladói aláírást.** A napló csak hash-t tart; az aláírt tartalom a feladó kulcsán múlik. A közjegyző legfeljebb hamis *bejegyzést* írhat, de az SSH-identitás vagy a feladó aláírása nélkül ez nem bizonyít semmit a feladó ellen.
- **nem írhatja át azt az ellenőrzőpontot, amit a másik fél már letöltött.** Az aláírt `head_hash` a letöltés pillanatában rögzíti a láncot; egy későbbi átírás a `compare`-ben első eltérő seq-ként jelenik meg, a régi aláírt ellenőrzőpont pedig a saját kulcsunkkal írt ellentmondás.
- **átírhatja a le nem töltött jövőt.** Az utolsó letöltött ellenőrzőpont utáni szakasz a következő letöltésig csak a mi szavunk.
- **az ellenőrizetlen farok (`unverified_tail`).** Az utolsó, a megbízott kulccsal ellenőrzött ellenőrzőpont utáni bejegyzéseket csak a hash-lánc köti, aláírás nem — ezt a közjegyző szabadon újraláncolhatja. A `verify` ezért külön visszaadja: `checkpoint_count`, `verified_checkpoint_count`, `covered_to_seq`, `unverified_tail`, `no_checkpoint_in_range`. **`trusted` csak akkor igaz, ha a szeletben legalább egy ellenőrzőpont a `--pub` kulccsal ténylegesen ellenőrződött** (egy friss napló első <N bejegyzése, vagy a következő ellenőrzőpont előtti export korábban a helyes kulccsal is `trusted:true`-t kapott úgy, hogy egyetlen aláírás sem ellenőrződött). Ellenőrzőpont nélküli szelet: dev-módban rc=0 + `trusted:false` + stderr-figyelmeztetés, **termék-módban rc=3, megtagadva**.

**Amit NEM old meg:**
- Ha a közjegyző **az első bejegyzéstől hazudik**, és **senki nem veti össze** a letöltéseket, egy belsőleg konzisztens hamis lánc minden ellenőrzésen átmegy. A napló tamper-evident, nem tamper-proof: a védelem az összevetésből jön, nem a fájlból.
- **A feladó órája továbbra is a feladóé.** A `backdated` jelzés csak azt mondja, hogy az állított idő régebbi a fogadásnál; hogy mikor írták a tartalmat, azt nem bizonyítja.
- **A relay `/deliver` feladója nem hitelesített.** A bejegyzés ezt `unauthenticated-claim`-ként rögzíti, a feladói hitelességet a sealed boríték visszafejtése adja a fogadónál.
- **A közjegyző órája.** A `received_at_ms` a mi óránk; egy nagy óraugrás látszik a láncban (nem monoton idők), de nem korrigálódik.

**Üzemeltetési kötelesség (e nélkül a fentiek nem érvényesek):**
1. **Mindkét fél rendszeresen töltse le** az ellenőrzőpontot és az exportot (javaslat: naponta, és minden vitás üzenet után), és őrizze meg a saját gépén.
2. Letöltéskor futtassa a `verify --pub`-ot a **korábban, csatornán kívül rögzített** közjegyző-kulccsal, és a `compare`-t az előző letöltésével.
3. A közjegyző-kulcs cseréjét előre, aláírt üzenetben jelezzük; ismeretlen kulcs mindig `untrusted`.

## 5. Kompatibilitás és teszt

- `PROTOCOL_VERSION` 1.5.0 (MINOR: új modul és új határ-mellékhatás; a busz-szerződés változatlan). `SCHEMA_VERSION` 1.0.0.
- Dev-módban minden korábbi teszt változatlanul zöld. Új tesztek: `test_bus_notary.py`, 20 db: lánc, ellenőrzőpont, export, CLI, a hét tamper-eset, módok és fail-closed, integráció mindkét határon.


### Kör-kimenetel
- `not-sent` = az ssh el sem indult / rc 255 nem-JSON; az ilyen kör ack-ja **nem fedez** naplózott ack-ot (`ack_logged_not_sent`).
- `unknown` = timeout, nem-JSON vagy **üres** kimenet, illetve a végpont `"processed": false` hibaválasza (a feldolgozás ELŐTT utasított el) → `unresolved`, strict/termék-módban `ok:false`.
- `reached` = érvényes JSON-objektum válasz (akár hiba) `processed:false` nélkül → a kérés bizonyítottan odaért, úgy vádol, mint `delivered`.
- Egy körhöz több, eltérő kimenetel-sor: az **első** számít, az ütközés `outcome_conflict` (unresolved).
- **Nyitott:** az ssh rc 255 a kérés kiírása UTÁN is jöhet (a kapcsolat menet közben szakad) — ilyenkor a `not-sent` egy becsületes közjegyzőt is vádolhat (`ack_logged_not_sent`), illetve egy elküldött üzenet ellenőrizetlen maradhat. A kliens ma nem tudja, kiírta-e már a kérést; a pontos megoldás (kiírt-bájt számláló vagy aláírt nyugta, v1.7) nyitott.


### Háromfokú fedezet
| fok | kimenetel | ack-fedezet | vád |
|---|---|---|---|
| **bizonyított** | `delivered`, `reached` | fedez | a naplóhiány hard vád |
| **feltételezett** | timeout/`unknown`, rc 255 + nem-JSON (`not-sent` rc-vel), `processed:false` (külön típus: `peer_claimed_unprocessed`) | `ack_cover_unknown` (unresolved; strict/termék-módban `ok:false`) | nincs hard vád, de nem is néma |
| **kizárt** | `OSError` (`not-sent` rc nélkül: egy bájt sem ment ki) | nem fedez | `ack_logged_not_sent` hard vád |

Az `error` mellett érkező `replies` és napló-horgony is a nyugtába kerül (`received`, `notary`).
**Kimondott korlát:** a kliens nyugtája a fél **aláíratlan** állítása — egy rosszhiszemű kliens hamis `received`-sorral vádat gyárthat egy becsületes közjegyző ellen. A nyugta ezért bizonyíték a fél *saját* igazságára, nem harmadik fél előtti bizonyíték; ezt a v1.7 aláírt nyugtája zárja.


### Gépi kurzor-mező
- Az `ack` és a kör (`pickup accepted`) bejegyzés **hash-elt, szám-típusú `cursor` mezőt** kap (`{from,to,ack}` ill. `{at,replies}`); a `record()` csak nem-negatív `int`-et fogad (bool/str elutasítva).
- A `reconcile` a gépi mezőt olvassa; a szabad szöveges `reason` csak régi bejegyzésnél számít. Elemezhetetlen kurzor-bejegyzés **sosem néma**: `unparsable_cursor_entry` — nem-strict módban unresolved, strict/termék-módban hard.
- `delivered` csak kör-bejegyzés mögött állhat (`delivered_without_round`); a kör `replies` száma kötött (`round_replies_mismatch`); a `cursor` és a `reason` ellentmondása hard `cursor_reason_mismatch`.
- `ack_cover_unknown` `claimed: true`, ha a fedezet a vádlott `processed:false` állítására épül.


### A kurzor kötése a kiadatlan postához
- A kör-bejegyzés gépi mezője: `{at, replies, pending, next_id}` — `next_id` az első **ki nem adott** üzenet id-je (0 = nincs ilyen); a `delivered` bejegyzésé `{id}`.
- `reconcile`: csonkolt körnél (`pending > replies`) az ack a kurzort csak `next_id - 1`-ig viheti; fölötte hard **`cursor_skips_undelivered`**.
- A kiadás mostantól KÉZBESÍTÉS-jelölést ír a buszon (`agent_bus.mark_delivered`: `read_at` + `delivered_id`, a **kurzor nem mozdul**) — ettől a helyi mentőöv és az `AGENT_BUS_STRICT_ACK` clamp a távoli úton is működik (eddig a peek miatt vak/befagyott volt).
- A `verify` (nyugták nélküli, olcsó ellenőrzés) is a gépi mezőt olvassa; a `reason` elhagyása nem kapcsolja ki.
- az ack-ig több kör **összeadódik** (nem írják felül egymást); a mérés hiánya `pending_unknown` → `round_pending_unknown` (nem néma); kör-bejegyzés nélkül mozduló kurzor → `cursor_moved_without_round` (unresolved: a szelet kezdődhet ack-kal).
- **Kimondott korlát:** a `pending`/`next_id` a vádlott saját állítása; a hazug érték a busz saját, hash-láncolt `cursor_audit` sorával kerül ellentmondásba — a bizonyíték a két nyilvántartás összevetése, nem a napló önmagában.


### A clamp kikapcsolhatatlan, a vízszint igaz
- **** a hiányzó `pending`, a hiányzó `next_id` (csonkolt körnél) és a `pending_unknown` mind **harmadik állapot**: a következő ack `round_pending_unknown` unresolved tételt kap (strict/termék-módban `ok:false`), nem esik vissza némán a régi korlátra. A `next_id: 0` **csonkolt** körnél ellentmondás → hard `round_next_id_contradicts_pending`.
- **** a `mark_delivered()` a `delivered_id`-t az **összefüggő kézbesített prefix** tetejére állítja (első olvasatlan − 1, a busz saját `read_at`-jéből), nem `MAX(ids)`-re. Ettől a helyi mentőöv látja a kihagyott postát, és az `AGENT_BUS_STRICT_ACK` clamp nem engedi át a kurzort.
- **** a kézbesítés-jelölés írási hibája naplóba kerül (`pickup/rejected, mark_delivered_failed`); ha a jelzés sem írható, a válasz **fail-closed** — posta nem megy ki.
- a `delivered_id` újraszámolt (egy később beérkező, alacsonyabb id-jű **olvasatlan** üzenet lejjebb viszi a vízszintet — a `MAX()` fölötte maradt volna).


### Kiadható prefix, kiadás-oldali háromfokú modell, audit-horgony
- **BLOCKER (a prefix-vízszint befagyott):** a `mark_delivered()` a **kiadható** (a `recv` szűrőjén átmenő) és még olvasatlan sorok közül veszi az első id-t; egy termék-módban elutasított (pl. `stale-ts`) sor többé nem fagyasztja be a kurzort, és a kiadás nem halmozódik körönként.
- **** a **peek-út is** megírja az `enforce_reject:<ok>` audit-sort (idempotensen), és a mentőöv `extra` ága az **audit-sorra** támaszkodik, nem a `read_at`-re — így az elutasított posta nevesítve látszik, a már kiadott pedig nem kerül hamisan a listára.
- **(háromfokú modell a kiadás oldalán):** ha a szeletben van **feltételezett** kimenetelű kör (`unknown`/`not-sent`), a többlet-kiadás `delivery_outcome_unknown` (unresolved), nem hard `delivered_not_received`; ugyanez a `round_replies_mismatch` → `round_replies_outcome_unknown`. Hard csak ott, ahol minden kört bizonyított kimenetel zár.
- **Audit-horgony:** a kör-bejegyzés envelope-ja hordozza a busz saját, hash-láncolt `cursor_audit` láncának fejét (`audit_seq`, `audit_hash`). **Kimondott korlát:** a `pending`/`next_id` önbevallott szám; a log önmagában nem cáfolja. A horgony teszi utólag összevethetővé a busz saját naplójával — a hazugság ott lesz bizonyítható, nem itt.


### A két nyilvántartás összevetése (09-16, a nyitott tétel lezárása felé)
A kör-bejegyzés `pending`/`next_id` száma a busz **önbevallása** — a napló önmagában nem cáfolja. Ezért:
- `agent_bus.audit_export(agent)` — a busz hash-láncolt `cursor_audit` sorai gépi alakban; `audit_chain_verify(rows)` a lánc önellenőrzése (sorfolytonos `seq` + `row_hash`).
- `bus_notary.reconcile(..., bus_audit=rows)` és a CLI `--bus-audit <fájl>`: a napló ack-jainak kurzor-lépése a busz audit-soraihoz mérve (`audit_cursor_mismatch`), és ha a busz saját naplója **kiadatlan fölötti lépést** rögzít (`skipped_undelivered > 0`), miközben a közjegyzői napló „nincs kiadatlan"-t állít → **`audit_skipped_contradicts_log`** (hard).
- A CLI a bemenetet előbb **önellenőrzi**: sérült audit-lánc → rc=1, összevetés nincs (nem hamis zöld).
- **Marad a korlát:** ha mindkét nyilvántartást ugyanaz a fél írja, az egyidejű hazugság nem zárható ki — de már **két** helyen kell hazudnia, és a két lánc ellentmondása bizonyíték.


### Átmeneti vs. végleges elutasítás, kézbesítés-bizonyíték, élő replay
- **BLOCKER (átmeneti elutasítás):** az elutasítás két fajta. **Átmeneti** (`future-ts`; illetve `forged` a kulcs-rollout alatt) → a sor **blokkolja** a vízszintet, mert még kijöhet. **Végleges** (`stale-ts`, `unsigned-downgrade`) → nem blokkol. A `forged` kegyelmi ideje idő-korlátos: `AGENT_BUS_FORGED_GRACE_S` (alap 24 h) vagy operátori rollout-marker (`/etc/agent-bus/key_rollout.on`) — különben egyetlen régi szemét sor **örökre** lefogná a vízszintet (DoS).
- **(a nyitott vád lezárása):** az `enforce_reject` audit-sort **csak pontosan ugyanarra az id-re** szóló kézbesítés-sor zárja (`recv_mark` / `remote_delivered`, id-szintű bejegyzés). A tartomány-alapú zárás a köztes, **nem** kézbesített id-ket is elnémította volna.
- **(a lefokozás hatóköre):** a `delivered_not_received` → `delivery_outcome_unknown` enyhítés csak arra az envelope-ra jár, amelyből a fél **ténylegesen kapott** legalább egy példányt; egy soha meg nem érkezett envelope továbbra is hard eltérés.
- **** termék-módban a `replay` az **eredeti, aláírt sort** viszi át épen (új id, változatlan aláírt bájtkép), mert a becsomagolt `system`-üzenetet a kikényszerítés `unsigned-downgrade` miatt eldobta. **Kimondott korlát:** aláírás **nélküli** eredeti termék-módban továbbra sem kézbesíthető — a mentőöv megnevezi, de kiadni nem tudja; ez a kikényszerítés szándéka.
- **7 (nem-Claude kar, a feltöltés előtt):** öt lelet, négy valós és javítva:
  1. a `forged` kegyelmi idő a **feladó** `ts`-éből számolt → jövőbeli dátummal örök kegyelem; mostantól jövőbeli (óracsúszáson túli) vagy értelmezhetetlen `ts` = nem friss → végleges;
  2. az `enf.check` kivétele a **globális** fail-closed ágba esett (minden sor blokkolt) → per-sor kezelés: az értelmezhetetlen sor sosem adható ki, tehát nem blokkol (a mentőöv továbbra is listázza);
  3. a replay aláírt **másolata** egy későbbi kurzor-ugrás után maga is jelöltté vált volna (másolat-lavina) → a `to_id` is kizár, a másolat+napló-sor egy `BEGIN IMMEDIATE` tranzakcióban készül, és `ux_replay_once` egyedi index tiltja a második replay-sort ugyanarra az eredetire (TOCTOU);
  4. a `mark_delivered` **bármely** id-re írt kézbesítés-sort → a távoli fél hazug ackja lezárhatta volna a nyitott `enforce_reject` nyomot; mostantól a véglegesen elutasított id kimarad, és külön `remote_delivered_refused` sorba kerül (a visszautasítás maga is a hash-láncba).
  - Az ötödik lelet (`got[sha]` → KeyError) **cáfolva**: a `got` egy `Counter`, a hiányzó kulcs 0-t ad. Nem javítottunk, hogy a diff ne állítson valótlant.
- Regresszió: `test_glm_round7_20260916.py` (7 teszt). Mindegyik **megbukik** a javítás nélküli fán (mutáns-próba, egyesével mérve) — a teszt bizonyít, nem díszít.


### A hazug clamp-mező lezárása: a második nyilvántartás kötelező (09-16, a `ClampLiedFields` korlát)
A kör-bejegyzés `pending`/`next_id` mezője a vádlott önbevallása. Eddig ezt **kimondtuk**; most zárjuk:
- **`_audit_cross` élesebb:** a „nem hagytam ki semmit" állítás akkor is teljesül, ha a bejelentett `next_id` a naplózott ack **legmagasabb célja fölé** esik — ez ugyanaz az állítás más szavakkal, és a busz `skipped_undelivered > 0` sorával **hard** ellentmondás (`audit_skipped_contradicts_log`).
- **A hiányzó ack-cél nem vád:** ha a szeletben nincs egyetlen naplózott ack-cél sem (`ack_top == 0`), ez az ág **hallgat** — különben minden becsületes csonkolt kör hamis vádat kapna.
- **A könyvtár nem vádolja a kört** azért, mert nincs mellette a másik nyilvántartás (az hamis vád lenne) — **a CLI viszont nem ad zöld lámpát**: strict/termék-módban, önbevallott kurzor-számok mellett `--bus-audit` nélkül **rc=1, „hiányos bizonyíték"**.
- **Mérés:** `test_clamp_lied_with_audit_20260916.py` — mindkét hazugság (`pending_down`, `next_id_up`) a busz saját naplójával összevetve `audit_skipped_contradicts_log`-ot kap; összevetés nélkül (kontroll) valóban átmegy; a CLI strict-ben `--bus-audit` nélkül rc=1, vele rc=0.
- **8:** két megkerülés **megcáfolva méréssel** — a „valljon be kihagyást, de tolja a `next_id`-t az ack alá" a régi `cursor_skips_undelivered` szabályba fut, a „ne írj gépi mezőt" pedig `round_pending_unknown`-ba (strict → nem zöld). Két lelet javítva: az `ack_top == 0` hamis vádja és a CLI kétszeri fájlolvasása (TOCTOU: a két olvasás közben cserélt fájl deszinkron rc-t adhatott).
- **Marad a korlát:** ha ugyanaz a fél írja mindkét nyilvántartást, az egyidejű hazugság nem zárható ki — de már **két** helyen kell hazudnia, és a két lánc ellentmondása bizonyíték.


### A szelet ELEJE is állítás
A `trusted` eddig a szelet **farkát** mérte (minden bejegyzést fedjen ellenőrzött ellenőrzőpont). A saját támadókörben a nem-Claude kar a másik véget találta el: egy `export --from-seq 11` szelet belsőleg ép, aláírt és **`trusted:true`** volt, miközben az 1..10 bejegyzés hiányzott — a törlés a szelet ELÉ esik, a napló önmagában nem mutatja.
- A jelentés új mezői: **`slice_start_seq`** (hol kezdődik a szelet) és **`anchored`** (genesis-től indul, vagy a hívó megadta a csatornán kívül ismert `start_prev_hash`-t). Horgonytalan szelet → `trusted:false`.
- A CLI **termék-módban megtagadja** a horgonytalan szeletet (rc=3), dev-módban figyelmeztet; a horgony értékét az `export` már eddig is kiírta (`verify --start-prev-hash <hash>`).
- **Nem vád:** a horgonytalan szelet nem hazugság-bizonyíték, hanem **hiányos bizonyíték** — ugyanaz az alak, mint a `--bus-audit` politikánál.
- Mérés: `test_slice_anchor_20260916.py` (6 teszt) — a teljes szelet megbízható, a szelet közepéből törölt sor ma is `gap`-et ad, a horgonytalan részszelet `trusted:false`, a helyes horgonnyal újra `trusted:true`, a hazug horgony lebukik, és a CLI mindhárom rc-je mért.


### A csonka mérés is harmadik állapot
A kör-bejegyzés `pending` mezője egy limitre menő mérés (`MAX_REPLIES * 50 + 1`), és a `+1` épp csonkolás-érzékelőnek készült — **de senki nem olvasta**. Egy limitbe ütköző, tehát csonka mérés pontosan úgy nézett ki, mint egy tiszta kör.
- A kiadási oldal mostantól jelöli: `pending_truncated: 1` a kör-bejegyzés gépi mezőjében.
- A közjegyzői oldal ezt **ugyanannak a harmadik állapotnak** veszi, mint a hiányzó mérést (`round_pending_unknown` unresolved → strict/termék-módban `ok:false`).
- Mérés: `test_pending_truncated_20260916.py` (3 teszt, mutáns-próbával igazolva); a limit alatti mérés változatlanul jelöletlen.

**NYITOTT DÖNTÉS (operátor + mindkét kliens):** a busz-oldali `AGENT_BUS_STRICT_ACK` (az ack a `delivered_id`-ig clamp-el, nem a high-waterig) ma **opt-in**, termék-módban sem alapértelmezés. A kör ezt jogosan nevezte meg: enélkül egy `ack --upto BIG` átugorhat kézbesítetlen posta fölött (a busz `cursor_audit` sora `skipped_undelivered`-del ezt rögzíti, tehát tamper-evidens, de nem akadályozza meg). A default-tá tétel MAJOR-kapu (a vendorolt kliens bájt-viselkedése változik), ezért **nem** kapcsoltuk be egyoldalúan — az operátor és az egyik kar döntése.


### A kikényszerítés versenyhelyzete és néma ágai
- **Verseny (javítva):** a `seen()` és az `add()` között két párhuzamos `recv` mindkettője „nem láttam"-ot mért, és mindkettő kézbesített volna. Az `add()` FALSE-a (`INSERT OR IGNORE` → „már bent volt") az egyetlen **atomi** jel — eddig eldobtuk, mostantól `replay` ítélet.
- **Fogyasztás seen-tár nélkül (javítva):** a `check(..., record=True, seen=None)` némán kihagyta a replay-védelmet. Ez fogyasztó út, tehát programozói hiba → `ValueError`. A peek/osztályozó hívások változatlanul `record=False`-szal jönnek.
- **Néma downgrade (kimondva, nem javítva egyoldalúan):** ha a termék-mód KIZÁRÓLAG a busz melletti markeren áll, akkor aki a buszra írni tud, a markert is törölheti, és a kapu **némán dev-re esik** (onnantól aláíratlan sort is kézbesít). A `doctor` ezt mostantól **hangosan** kimondja (`ok:false`), és a root-tulajdonú `/etc/agent-bus/product_mode.on`-t javasolja. A „ragadós termék-mód" (a busz emlékezzen rá, hogy már futott termék-módban, és csak root-kezelt fájllal lehessen visszakapcsolni) **megépült és visszavonva**: üzemeltetői viselkedést változtat (a kikapcsoláshoz új fájl kell), ezért az operátor + az egyik kar döntése.
- **Megcáfolt lelet:** „a `seen`-kulcs tartalmazza az aláírást, tehát újraaláírással megkerülhető" — az Ed25519 **determinista**: ugyanaz a kulcs + ugyanaz a tartalom = ugyanaz az aláírás, tehát ugyanaz a replay-kulcs (mérve).
- Mérés: `test_enforce_race_20260916.py` (7 teszt, mutáns-próbával igazolva).


### Kulcs-olvasás: symlink és TOCTOU
A registry-kulcs (`<agent>.pub`) és a privát seed (`<agent>.ed25519.key`) guardja **két** műveletből állt: `os.stat` (jogosultság), majd `open` (olvasás). A kettő között a fájl kicserélhető, és a `stat` a **symlink célját** követte — tehát egy root-tulajdonú fájlra mutató symlink átment a guardon, miközben a link tartalmát a link gazdája irányítja.
- `_a2_guarded_read`: egyetlen megnyitás `O_NOFOLLOW`-val, a jogosultság-ellenőrzés a **megnyitott fd-n** (`fstat`) — amit ellenőrzünk, azt olvassuk.
- `_a2_default_sign_key`: `lstat` + „csak valódi fájl" (a symlink a seed helyén elutasítva).
- **Fenyegetési kontextus:** a kulcs-könyvtár root-tulajdonú és nem világ-írható, tehát ez **mélységi védelem**, nem az utolsó fal. Az elv viszont áll.
- Mérés: `test_key_guard_symlink_20260916.py` (6 teszt, mutáns-próbával). **Megcáfolt lelet ugyanebből a körből:** „a sender-név útvonalként kitörhet a kulcs-könyvtárból" — a feloldás `os.path.basename` + explicit `.`/`..` tiltás (tesztben rögzítve).


### Csatolmány-tár: a munkafájlok kvótája
A tár **sosem töröl** — a félbehagyott `.partial` és a hash-hibás `.rejected.*` fájlok szándékosan megmaradnak (bűnjel, no-deletion). A nem-Claude kar erre mutatott rá: a méret-plafon **egy** csatolmányra szólt, a felhalmozódásra nem, tehát ismételt félbehagyott vagy hash-hibás átvitellel a lemez korlátlanul fogyasztható (DoS).
- **Kvóta a munkafájlokra** (`AGENT_BUS_ATTACH_WORK_QUOTA`, alap 2 GiB): fölötte **új** átvitel nem indul (fail-closed); a **futóban lévő** befejezhető (a kvóta nem szakít félbe).
- **Semmit nem törlünk:** a takarítás operátori döntés marad, a `Store.work_stats()` megmutatja, mennyi és mely fájl fekszik ott.
- **Megcáfolt lelet:** „a hazug `last: true` hamis »kész« jelzést ad" — nem: a `last` után a teljes tartalom hash+méret ellenőrzésen megy át, hiányos tartalom nem kerül a tárba (mérve). Ugyanígy: a `sha256`-alapú, hex-validált útvonal miatt traversal/symlink úton semmi nem írható felül.
- Mérés: `test_attach_quota_20260916.py` (6 teszt, mutáns-próbával).


### Relay: archív-kvóta és SSE-korlát
A „nincs törlés" elv árnyékában két számolatlan halom nőtt a relay spool-jában:
- a **lehúzott** boríték a `.picked/` alá kerül (másik könyvtár), a közjegyzői írás hibájánál pedig `.unnotarized` néven marad (rejtett név) — **egyiket sem** számolta a spool-limit. Egy hitelesített fél ismételt küldés+lehúzás körrel megtöltheti a lemezt.
- **Javítás:** külön `archive_total()` és `MAX_ARCHIVE_TOTAL` (`AGENT_BUS_RELAY_MAX_ARCHIVE`, alap 100 000 darab). Fölötte **új kézbesítés 429** (fail-closed), de **semmit nem törlünk** — a takarítás operátori döntés, a szám az övé.
- **SSE:** egy hitelesített fél korlátlan `/events` kapcsolatot nyithatott, mindegyik egy szálat és egy fd-t tart akár egy órán át → a `/deliver` is megbénul. **Javítás:** agentenkénti egyidejű SSE-korlát (`AGENT_BUS_RELAY_MAX_SSE`, alap 2) → 429; a hely a kapcsolat zárásakor felszabadul (`finally`).
- **Megcáfolt leletek ugyanebből a körből:** a lehúzási kérés visszajátszása (tartós, purpose-höz kötött nonce-tár), a tartalom olvasása a relay-en (AEAD + AAD-kötés), a feladó hamisítása (`from` az AAD-ban), a sorrend-manipuláció (a fájlnév relay-oldali `time.time_ns()`), és a két párhuzamos lehúzás versenye (az `os.replace` atomi).
- Mérés: `test_relay_archive_sse_20260916.py` (5 teszt, mutáns-próbával).


### A második nyilvántartás horgonya
**** a `--bus-audit` export **rövidebb, de belsőleg ép** változata kioltotta a bizonyítékot — a hazug kör `audit_skipped_contradicts_log` helyett **zöldet** kapott. Nem hazugság, nem hamisítás: elég volt egy sorral kevesebbet átadni. Ugyanaz a hibaosztály, amit a naplónál (`unverified_tail`, `slice_start_seq`/`anchored`) és a `compare`-nál (`no_overlap`) már bezártunk.
- **A horgonyt a KÖZJEGYZŐ írja, nem az írófél:** a kör-bejegyzés `cursor`-ába `audit_seq` + `audit_hash` kerül (`audit_head()` — eddig holt kód volt). Üres láncnál a horgony a **genezis**, és ez is állítás. A horgony a `cursor`-ban utazik, tehát az `entry_hash` köti. Az `audit_hash` az egyetlen nem-szám mező a kurzorban (64 hex, külön validálva).
- **`audit_chain_verify(rows, start_row_hash=None)`** mostantól kimondja: `slice_start_seq`, `anchored`. Az `ok` a lánc épségét jelenti (mint a napló `verify`-jánál), a horgonyról a **fogyasztó** dönt: a CLI termék/strict módban **megtagadja** a horgonytalan exportot (`--bus-audit-anchor <row_hash>` a részszelethez).
- **`_audit_cross` új eltérései:** `audit_identity_mismatch` (idegen agent exportja), `audit_row_missing` (naplózott ack-hoz nincs audit-sor), `audit_head_not_covered` (az export nem ér el a horgonyig), `audit_head_hash_mismatch` (a horgony **hash**-e nem egyezik), `audit_evidence_absent` (üresen átadott export), `audit_chain_broken` (a könyvtári út is önellenőrzi a láncot), és harmadik állapotként `audit_anchor_absent` (a horgony **kimaradt** — nem vád, de strict-ben nem zöld).
- **** a kikényszerített politika eddig **nem létező parancsra** küldte az üzemeltetőt. Megvan: `agent_bus.py audit-export --agent <agent> [--from-seq N]` (JSONL), és részszeletnél a stderr kiírja a horgonyt.
- **** a modul-szintű utak import-időben fagytak be — egy mérő hívás a **termelő** buszra írhatott. Mostantól a `db=None` út **hívás-időben** olvassa az env-et (az explicit monkeypatch továbbra is nyer), és van `reload_paths()`.
- **9 (a feltöltés előtt):** négy megkerülés, mind javítva — a horgony fail-open kimaradása, a seq-hézagos export a könyvtári úton, a **hash** nélküli (csak seq-) horgony-ellenőrzés, és az üresen átadott export.
- **MÉRT KORLÁT, kimondva:** a horgony a kör **elején** íródik, tehát a saját köre ack-sorát még nem köti. Egy **egykörös** szeletben a második nyilvántartás következetes újraláncolása nem bukik le — ez ugyanaz a kimondott korlát, hogy mindkét nyilvántartást ugyanaz a fél írja. Amint van **későbbi** kör, annak horgonya a korábbi sorok tartalmát is köti (mérve: `audit_head_hash_mismatch`).
- Regresszió: az egyik kar szondája (`test_joint_audit_anchor_20260916.py`) 10-ből **9 zöld**; a tizedik (`test_chain_verify_must_anchor_the_slice_start`) a saját fájljában lévő `test_supported_from_seq_slice_must_not_hide_an_older_round` **előfeltételével ellentmond** (az egyik `ok:false`-ot vár a horgonytalan szeletre, a másik `ok:true`-t ugyanarra) — a prózáját követtük (mezők + fogyasztó-oldali kikényszerítés). Sajátunk: `test_glm_round9_20260916.py` (5 teszt, mind a négy javítás mutáns-próbával igazolva).


### A strict ack clamp TERMÉK-MÓDBAN ALAPÉRTELMEZÉS
A MAJOR-kapu megnyílt. Előzmény: az `AGENT_BUS_STRICT_ACK` opt-in volt, tehát termék-módban is átugorhatott az ack **kiadatlan** posta fölött (a busz `cursor_audit` sora ezt `skipped_undelivered`-del rögzítette — tamper-evidens, de nem akadályozta meg).
- **az egyik kar mért érve a bekapcsolás mellett:** a clamp **a kárt magát szünteti meg** — a kurzor nem tud kiadatlan posta fölött lépni, ezért `skipped_undelivered` sem keletkezik. A +11 teszt-bukás mind **fixture-előfeltétel** (a kár-forgatókönyv előállítása), nem termék-kód.
- **Alak:** termék-módban ON; menekülő ajtó `AGENT_BUS_STRICT_ACK=0/false/no/off`; a **kikapcsolás ténye** bekerül a kör-bejegyzésbe (`strict_ack: 0`), és az összevetésben harmadik állapot (`strict_ack_disabled`, unresolved → strict-ben nem zöld). Dev-módban változatlanul opt-in (bájt-azonos a vendorolt klienssel).
- A két érintett fixture **kimondja** a menekülő ajtót, ahogy ő javasolta — a szondák logikája változatlan.

### Az SDS-boríték hídja
- **A külső validátor CSAK SZIGORÍTHAT.** Eddig egyedül döntött, és egy env-változóból (`AGENT_BUS_SDS_VALIDATOR=modul:fn`) **tetszőleges modul** betölthető — aláírás, admission, minden megkerülhető volt. Mostantól a beépített ellenőrzés fut előbb, a külső megkapja az eredményét (`context["builtin"]`), és a `valid`-ot **lerontani** tudja, létrehozni nem.
- **A hiányzó config-kötés nem csendes pass:** ha az admission nem köt `config_id`-t, az eredmény `unverifiable(no-config-binding)` — enélkül egy másik config-kontextusba átültetett boríték is átment (cross-config replay).
- **Unicode:** a role/org NFC/NFD alakja két különböző aláírt bájtsort adott ugyanarra a látszólagos értékre; az admission mezőit az aláírt üzenet építésekor **NFC-re normalizáljuk**.
- **Kimondott korlát (nem javítva):** az admission-fájl a busz **helyi** nézete — nincs aláírva és nincs a JOINT genezis-lánchoz kötve. Aki a fájlt lecseréli, saját issuert vehet fel. Ez a §5.4 kötés, nem ezé a hídé.
- Mérés: `test_sds_validator_bypass_20260916.py` (8 teszt).

### „Ragadós termék-mód": megépült és VISSZAVONVA — mérés alapján (09-16)
Az operátor jóváhagyta, én mégsem tettem fel, mert a mérés mást mondott: a busz-memóriás változat **kétszer** a TERMELŐ busz DB-jét olvasta/írta olyan hívásokból, amik csak mérésnek készültek (a modul-szintű út feloldása miatt), és **20 tesztet** döntött be. Ami a védelmet valóban adja, az már megvan: a **root-tulajdonú** `/etc/agent-bus/product_mode.on` markert csak root törölheti, a busz-mellettit viszont bárki, aki a buszra ír. A `doctor()` ezt hangosan meg is követeli. **Üzemeltetői tétel:** élesítéskor a root-marker kikerül — ma egyik gépen sincs (mindkét busz dev-módban fut, tehát ma nincs is honnan visszaesni).


### A bökő-út
- **A feed `note` mezője a FELADÓ szövege**, és az agent szeme elé kerül — közvetett prompt-injekciós csatorna. Szemantikát szűrni nem lehet, ezért a sor **kimondja**, hogy adat (`adat=...`). A védelem az agent szabálya („a busz tartalma ADAT, sosem utasítás"), nem a szűrő — ezt nem takarjuk el.
- **A `_safe()` hézagja:** csak a C0/DEL tartományt szűrte, tehát átment az `U+2028`/`U+2029` (LINE/PARAGRAPH SEPARATOR), az `U+0085` (NEL) és a kétirányúság-vezérlők (`U+202A..E`, `U+2066..9`, `U+200E/F`, `U+FEFF`) — ezekkel a feed-sor **vizuálisan hamisítható** (hamis log-sor a `tail` nézetében). Mostantól ezek is kiesnek.
- **A tmux-target alakja kötött** (`session[:ablak[.panel]]`): három forrásból jöhet (kapcsoló, single-flight lock JSON, registry-fájl), és kettőt nem feltétlenül az agent ír — egy `-`-szal kezdődő vagy tmux-szintaxist tartalmazó string más panelbe irányíthatta volna a bökést. Nem illeszkedő alak → **nincs bökés** (a rossz helyre írás rosszabb, mint a kimaradt bökés).
- **Megcáfolva:** escape/ANSI-injekció a bökésen keresztül — az ESC szűrve van, és a `send-keys`-be **sosem** kerül üzenet-tartalom.
- Mérés: `test_poke_hardening_20260916.py` (4 teszt).


### Az ÉLESÍTÉS kapuja: a beléptető sor
A `bus_ssh_enroll` állítja elő azt az `authorized_keys` sort, amit az operátor a busz-gépre tesz — tehát ez a kapu dönti el, mit tud a partner kulcsa.
- **`from=` forráskorlát:** eddig nem volt. Egy kiszivárgott kulcs a világ bármely pontjáról használható. Mostantól `--from <IP/CIDR/hosztminta>` (az opciók elején), és **ha nincs megadva, a CLI figyelmeztet** — a korlát a partner címétől függ, ezért opció, nem kötelező mező.
- **Csendes downgrade (javítva):** ha a kulcs már bent volt egy **gyengébb** (pl. `restrict` nélküli vagy más identitásra pinelt) sorban, a modul „already present"-et mondott, és a korlátozott sor **sosem** került be. Mostantól: azonos sor → no-op; azonos kulcs + **eltérő** sor → hangos hiba, a meglévő és a kívánt sorral együtt.
- **Kulcs-erősség (javítva):** az `ssh-rsa` bármilyen hosszal átment, mert csak a base64 **alakját** néztük. Most a blobot dekódoljuk, ellenőrizzük, hogy a benne lévő típus egyezik a prefixszel, és az RSA modulus **≥ 3072 bit** (ed25519 az ajánlott).
- **Megcáfolva:** shell-injekció a `command=`-ba — az identitás charsetje kötött, a kulcs-komment levágva, a parancs metakarakter-mentes (mérve 6 alakkal).
- Mérés: `test_enroll_hardening_20260916.py` (9 teszt).


### A single-flight zár
- **Injektálható óra (javítva):** a hívó által adott `now_ns` korlátlan volt, tehát egy `acquire(..., now_ns=2**62)` hívással bárki **stale**-nek láthatott egy **élő**, TTL-alapú zárat, és elvehette. Az **életről döntő** óra mostantól csak a valóságtól 24 órán belüli hívói értéket fogadja el — a valósághű idő-szimuláció (teszt, mérés) továbbra is működik, az audit-időbélyeg marad a hívóé.
- **TOCTOU (javítva):** az `acquire` flockkal sorba volt rendezve, a `heartbeat` és a `release` **nem** — egy takeover és egy heartbeat közé beékelődve két fél is „tulajdonosnak" hihette magát, és az egyik vakon felülírhatta a másik zárát. Most mindhárom ugyanazon a mutexen megy.
- **KIMONDOTT korlát (nem javítva, mert hívói szerződést változtatna):** a `release` csak az `instance` **nevét** kéri, tehát aki a lock-fájlt olvassa, egy élő tulajdonos zárát is elengedheti; és a `target`-liveness `owner_pid` nélkül egy élő panelhez köt (élő panel + halott worker = tartósan „élő" zár, rendelkezésre-állási támadás, **nem** duplikátum). Mindkettő zárása acquire-kori titkos token, illetve kötelező `owner_pid` — **MAJOR-kapu**, a vendorolt hívókat érinti: az operátor + az egyik kar döntése.
- Mérés: `test_singleflight_clock_20260916.py` (6 teszt, a két javítás mutáns-próbával; a két kimondott korlát **mérésként** rögzítve, nem vádként).


### Az ügyelet-figyelő
- **A „jelentés" nem lehet puszta fájlnév (javítva):** egy `touch`-olt vagy `{}`-t tartalmazó fájl eddig jelentésnek számított, és ebből lett a felügyelői „jelentett és tétlen — jöhet a következő". Mostantól **szerkezeti** szabály: a fájl a busz JSON-tükrének sora legyen, amit **az agent** küldött (`from == agent`); nem értelmezhető JSON sem számít. Tartalmat nem minősítünk — ez nem bizonyíték, csak a „jelentés = fájlnév" egyenlet megszüntetése.
- **Riasztás-típusok (javítva):** egyetlen `alerted` kulcs volt mindenre, tehát az első riasztás a **másik típust** is elnyomta a `remind_s` ablakban (a „nincs panel" elnyomta a „beragadt-busy"-t). Típusonkénti kulcs.
- **KIMONDOTT korlátok:** a kijelölés-fájl nincs hitelesítve (aki írni tudja, átírja, ki az ügyeletes), és a „dolgozik" bizonyítéka a panel tartalma, amit **az agent maga ír** — a bájt-hash + idő szűkíti, de nem teszi hamisíthatatlanná; valódi bizonyíték a process-szintű CPU-idő lenne. Ez a modul a **saját gépünk felügyeleti segédje, nem bizalmi határ** — és ezt most ki is mondjuk.
- Mérés: `test_duty_hardening_20260916.py` (6 teszt). az egyik kar `test_LOW2_default_count_reports_reads_supervisor_inbox` fixture-je a `{}`-s jelentést valódi tükör-sorra cserélve (a szonda logikája változatlan, a csere kommentelve).


### A claim-oldali életjel és a hívói óra ÍRÓ oldala
- **** a `MessageClaim.requeue_dead` a `pid_of(inst) → is_alive(None) → False` láncon a **bizonyíték hiányát** „halott"-nak vette, tehát egy **élő**, stabil nevű worker (`claude-alfa-session`) claimjeit bárki kirequeue-olhatta alóla — ugyanaz a hibaosztály, amit a `SessionLock` oldalán a B1-ben már bezártunk. A naiv javítás (`pid is None → continue`) a **másik** végén nyit lyukat (a valóban halott claimer üzenetei örökre bent ragadnának) — ezt ők is megmérték. Ezért **harmadik állapot**, mérhető jelhez kötve: **pid → session-lock → a claim-könyvtár frissessége** (`AGENT_BUS_CLAIM_TTL_S`, alap 1 óra). Se az „él", se a „halott" oldalra nem esünk némán.
- **** az előző óra-javítás **csak az olvasó** oldalt korlátozta; a fájlba a **nyers** hívói óra került, tehát a hívó órája továbbra is életről döntött — csak egy lépéssel később és **mindenki más** számára. Mérve mindkét irányban: múltbeli bélyeg → **két `acquired`** ugyanarra az identitásra; jövőbeli bélyeg + pid nélküli instance → **örök zár**. Mostantól a `ts_ns` a **korlátozott** érték, a hívó nyers bélyege pedig a `caller_ts_ns` **audit**-mezőben marad (és semmilyen döntésbe nem folyik bele). A `heartbeat` ugyanígy.
- **** a `requeue_dead(now_ns=...)` elfogadta és eldobta a paramétert.
- Mérés: `test_claim_liveness_20260916.py` (6 teszt, mindkét javítás mutáns-próbával: a régi claim-életjellel az élő worker claimjei elvehetők, a nyers órával a három óra-teszt bukik).


### Ébresztés / alvás-markerek
- **A marker-könyvtár bizalmi állapota (jelzett):** aki oda írni tud, egy idegen `X.sleep_safe` létrehozásával **csendben elnémíthat** egy agentet, a marker törlésével pedig ébreszthet — és az audit `by` mezőjét is ő írja. A könyvtár mostantól **0700**-zal jön létre, és a `state_dir_warnings()` kimondja, ha nem root-tulajdonú vagy csoport/világ-írható. Ez **jelzés**, nem zárás: a zárást a root-tulajdonú elhelyezés adja (üzemeltetői lépés).
- **`AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1` (nem néma):** a kapcsoló aláírás nélkül enged ébresztést; létezhet, de a **használata** mostantól figyelmeztetést ír a hívónak.
- **KIMONDOTT korlátok:** TOCTOU a `may_poke` és a `send-keys` között (a „szent gépelés" szabály szűkíti, de az ablak létezik), és a „dolgozik"/„gépel" felismerés a **panel szövegéből** jön, amit az agent maga ír — tartós ál-busy állapottal egy agent ébreszthetetlenné tehető. Ugyanaz az osztály, mint az ügyelet-figyelőnél: **felügyeleti segéd, nem bizalmi határ**.
- Mérés: `test_wake_markers_20260916.py` (5 teszt).


### A kör ZÁRÓ horgonya — a támadási mátrix 2.7-es nyitott sora
- **A nyitott sor:** a kör-bejegyzés horgonya a busz audit-láncának **akkori** fejére köt, és a kör **saját** sorai (`remote_delivered`, `ack`) ez **után** keletkeznek. Többkörös exportnál a következő kör horgonya lefedi őket — **egykörös** szeleten viszont semmi: a második nyilvántartás a horgony fölött **következetesen újraláncolható** volt (a lánc belsőleg ép marad). Mérve: a kör saját sorát elhagyva és a maradékot újraszámolva a `reconcile` **zöldet** adott.
- **A javítás:** minden mellékhatás **után** egy `round_close` bejegyzés, benne `audit_end_seq` + `audit_end_hash`. A horgonyt — a nyitó horgony mintájára — a **KÖZJEGYZŐ** számolja, nem az író fél.
- **A nem-Claude kar köre ezen a javításon (mind mérve):**
  - Tévesen azt feltételezte, hogy a `closes: 1` vállalást a közjegyző írja — nálunk az **író fél** írta. A tévedése volt a lelet: a busz-gép egyszerűen „nem vállalt" volna, és a záratlan kör néma marad. A vállalás **átkerült a közjegyzőbe**. Ekkor derült ki, hogy a közjegyzői horgony-injektálás a valódi úton **soha nem futott le** (az író fél maga tette be az `audit_seq`-et), tehát a horgony értéke eddig **az írófél szava** volt: a közjegyző mostantól **felülírja**.
  - „A záró horgony régi láncfejre mutathat" → **igaz**: a horgony mostantól **monoton** (`audit_close_before_open`).
  - „Egy máshonnan való zárás lezártnak mutathat egy záratlan kört" → a lánc-integritás ezt fogja, de olcsóbb és szigorúbb kötés is van: a zárás **megnevezi** a körét (`round_seq`); ha hazudik róla, a párosítás elmarad — hiányzó zárás, nem hamis zöld.
  - „Minden kör záratlanul hagyva a soft-zajban elvész" → **igaz**: a jelentés mostantól **számot** ad (`rounds_pledged`, `rounds_unclosed`).
- **Visszamenőleges hatás nincs:** a régi naplókban nincs `closes`, tehát rájuk semmit nem kérünk számon.
- **KIMONDVA:** a záró írás **fail-OPEN** — a posta ekkor már kiment, fail-closed nem lehet. A hibát a válasz `round_close: "failed"` mezője és a `audit_close_missing` **soft** eltérés mondja ki; a teljes zárás továbbra is **külső tanú** (v1.7, operátori döntés).
- Mérés: `test_round_close_anchor_20260916.py` (8 teszt), mutáns-próba **átlós**: mindegyik kötés pontosan a saját szondáját tartja. Suite: 505 zöld, 1 skip, 3 kimondottan nyitott szonda.


### A CI zárványa pineli önmagát — a mátrix 7.2-es sora (09-16)
- **A lelet:** a `--require-hashes` a **csomagokat** köti, a **listát** nem. Aki a `requirements-ci.txt`-t kicseréli, a benne lévő hash-eket is átírja, és a pip boldogan telepíti az ÚJ closure-t — a „hash-lockolt, fail-closed telepítés" mondat közben végig igaz marad.
- **A zárás:** a closure fájl digestje a **workflow-ban** áll (`CLOSURE_SHA256`), és a lépés a telepítés **előtt** fut. A cseréhez így **két egyidejű szerkesztés** kell, és mindkettő látszik a PR diffjében.
- **Nálunk is mérjük, nem csak a runneren:** `test_ci_closure_pin_20260916.py` (4 teszt) elesik, ha a closure elsodródik a pintől, ha a pin eltűnik, ha a pin-lépés a telepítés **után** kerül, vagy ha a `--require-hashes`/`--no-deps` kikerül. Mutáns-próbával mindegyik igazolva.
- **KIMONDVA:** ez a **7.2**-t zárja, **nem a 7.1-et** — a workflow-fájl maga a HEAD-en él, azt repó-beállítás (required status check, ami a HIÁNYZÓ checket is pirosnak veszi) zárja: tulajdonosi döntés, nem kódkérdés.


### A marker-könyvtár SZÜLŐJE — 50Z)
- **** a `state_dir_warnings()`-nak **nem volt termelési hívója** — a figyelmeztetés csak a saját unit-tesztjében szólalt meg, tehát a mátrix „jelzett" minősítése **nem volt mérhető**. Ez pontosan az az alak, amit a 6d.2-nél mi magunk utasítottunk el („néma engedmény nincs"). Az `agent_bus_watcher.main()` — az egyetlen termelési belépő az ébresztés-úton — indulskor kiírja a listát a **stderr**-re.
- **** a verdikt **csak a levelet** nézte, a csere viszont **csak a szülőre** kíván írásjogot: `rename(state, state.elrejtve); makedirs(state, 0700)` — a levél jogai érdektelenek (0o000-val is mérve). Egy root-tulajdonú 0700 levél így **tiszta bizonyítványt** kapott világ-írható szülő alatt. Az ő szava áll: ez **rosszabb**, mint a hiányzó jelzés, mert hamis megnyugtatás. A verdikt mostantól a **szülő-láncot** is nézi.
- **SAJÁT pontosítás:** a **sticky** bit (pl. `/tmp` 1777) megakadályozza idegen bejegyzés átnevezését, tehát sticky, root-tulajdonú szülő alatt a marker-könyvtár nem cserélhető ki — ezt **nem** jelentjük leletként, különben minden `/tmp` alatti futásra farkast kiáltanánk.
- **** az `os.makedirs(..., mode=)` a **köztes** szinteket mode nélkül hozza létre, tehát `umask 0002` alatt a **saját kódunk** állította elő a előfeltételét (szülő 0775, levél 0700). A láncot mostantól `_make_strict_dir()` építi, szigorú móddal; meglévő könyvtár jogait **nem** írjuk át (az az üzemeltetőé).
- **** ugyanebben a könyvtárban dől el az **ügyelet** is (`duty_active.json`), és egy odadobott fájl a 6c-s riasztást is elnémíthatja. A 6d.1 sor ezt most kimondja: a könyvtár **állapot**, nem **bizonyíték**.
- Mérés: `test_joint_wake_parent_20260916.py` (6 teszt, az ő négy szondája szó szerint); mutáns-próba: a javítás nélkül 6-ból **5 elesik**, a hatodik (sticky-kontroll) helyesen mindkét állapotban zöld. Készlet: **515 zöld**, 1 skip, 3 kimondottan nyitott szonda.


### A NÉMA kivétel-ágak rendszeres felmérése (09-16, saját kör)
- **A módszer a capsule2-oldalról jött:** ott a B-kar háromszor mondta ki ugyanazt az osztályt — *a mérés HIÁNYA harmadik állapot, nem zöld*. A busz-oldalon ez `except …: pass` alakban él, ezért nem vártuk meg, hogy megtalálják: AST-vel végigmértük **mind a 28** néma ágat, és megnéztük, melyik ül **bizonyíték-hordozó** úton.
- **Három javítva:**
  1. `bus_notary._audit_cross` — a busz audit-láncának **önellenőrzése** `except Exception: pass`-ban ült. Ha a lánc-verifikáló bármiért dob (hiányzó mező vagy rossz típus a MÁSIK fél exportjában), a `audit_chain_broken` eltérés **némán eltűnt**, és a jelentés zöld maradt. Innentől `audit_chain_unverifiable` (soft): a mérés hiánya **látszik**.
  2. `agent_duty._notify` — a riasztás-hook hibája **elnyelte a riasztást**. Innentől a stderr kimondja, hogy a riasztás NEM ment ki.
  3. `agent_bus.replay_lifeboat` — a végleges elutasítás szűrője `pass`-szal bukott, tehát a **véglegesen elutasított** sor is visszakerülhetett a mentőcsónakba, csendben. Innentől a válasz `warning` mezője kimondja, hogy a szűrés nem futott.
- **A többi 25 ág mérten ártalmatlan** (`FileExistsError` mkdir-nél, `BrokenPipeError` lezárt SSE-nél, `OSError` takarításnál) — ezért a teszt nem tiltja az összeset, hanem a hármat köti, és **keretet** szab a bizonyíték-hordozó modulokra (új néma ág ne jelenjen meg észrevétlenül).
- Mérés: `test_silent_handlers_20260916.py` (4 teszt); mutáns-próba: a javítás nélkül 4-ből **3 elesik**. Készlet: **519 zöld**, 1 skip, 3 kimondottan nyitott szonda.


### A napló ALAKJA — rendszeres söprés (09-16, saját kör)
- **A módszer ugyanaz, mint a korpusz-oldalon:** minden bejegyzés-mezőt egyenként törölve, `null`-ra, `0`-ra és `"X"`-re állítva megnéztük, mit mond a `reconcile`.
- **Jó hír:** a hash-lánc **minden érték-változást** elkap (még a `claimed_ts_ms` valódi számra írását is: `verify_ok: false`) — a naplót érték szinten nem lehet átírni.
- **Lelet:** a hiányzó vagy rossz típusú mező **összeomlasztotta** a vizsgálatot (`envelope_sha256` törölve → `KeyError` az összevetés közepén; `reason: null` → `TypeError`). A MÁSIK fél exportja megbízhatatlan bemenet, és egy összeomlott `reconcile` semmit nem mond arról, hogy a napló hazudott-e. **A traceback nem diagnózis** — ezt a szabályt a B-kar mondta ki a korpuszra, és ugyanúgy áll itt.
- **Javítás:** alak-kapu a naplóra (`malformed_entry`), a `reconcile` elején. Újramérve: **0 traceback**, és az egyetlen „néma" eset (`claimed_ts_ms: null`) a VALÓDI érték a legtöbb bejegyzésen, tehát nem rés.
- Mérés: `test_log_shape_20260916.py` (4 teszt, benne a kontroll, hogy az alak-kapu **nem helyettesíti** a hash-láncot).


### A néma-ág felmérés FELE volt kész — 59Z)
- **** az első javításom a `warning`-ot **kizárólag a száraz ágra** (`if not commit:`) tette, a **kár** viszont a **commit-ágon** áll be: a véglegesen elutasított sor **aláírt másolata bekerült a DB-be**, és a válasz erről néma volt. Az ő mérése a valódi úton (termék-mód, `stale-ts`, `enf.check` dobásra állítva) ezt pontosan megmutatta. Két változás: (a) a jelzés a commit-ág válaszába is bekerül, (b) **termék-módban FAIL-CLOSED** — mentőcsónak kapu nélkül nem ír tartós állapotot; a száraz futás továbbra is megmutatja, mit tenne.
- **második fele (az ő mutáns-próbája):** a javítás ÉRTÉKÉT semmi nem kötötte — a `TheSweepItself` keret a `pass` **alakot** méri, nem a viselkedést, tehát a `_lifeboat_warn` sor törlése a készletet nem mozdította. Mostantól `test_joint_silent_lifeboat_20260916.py` a **viselkedést** köti.
- **** a `bus_ssh_exchange.py:194` néma ága az **egyetlen** mechanizmust nyelte el, ami a kör-bejegyzésbe írja, hogy a strict-ack **menekülő ajtó** nyitva volt — pont amit a fölötte lévő saját kommentünk tilt („NEM lehet néma"). A kör ettől megkülönböztethetetlen lett a szigorútól. Innentől `strict_ack_unknown: 1` (harmadik állapot), és a `reconcile` **olvassa is** soft eltérésként — ha csak beírnánk, ugyanazt az osztályt ismételnénk.
- **A keret bővült:** a `bus_ssh_exchange.py`, a `bus_singleflight.py` és az `agent_duty.py` is benne van (az ő leletének gyökere épp a keretből kimaradt modul volt).
- **** a sticky-kontroll teszt root-tulajdonú szülőt feltételezett, és az ő nem-root gépükön elesett — mostantól `skipUnless(geteuid()==0)`, tehát kimondja az előfeltételét.
- Mérés: az ő két szondája szó szerint átvéve (7 teszt); mutáns-próba: a javítás nélkül **7-ből 4 elesik**. Készlet: **530 zöld**, 1 skip, 3 kimondottan nyitott szonda.


### Az `ok` NEVE két dolgot jelentett — az egyik kar nyitott szondája zárva (09-16)
- **A lelet az övé:** a DB-úton (`audit_verify`) az `ok` = ép **ÉS** horgonyzott (mindig a genezisből indul), az exportált úton (`audit_chain_verify`) viszont csak az **épséget** mondta. Ugyanaz a mezőnév, két garancia — aki csak az `ok`-ot olvassa, hamis zöldet kap egy horgonyzatlan szeletre.
- **Javítás:** az `ok` a **szigorúbb** jelentést hordozza (ép ÉS horgonyzott), a szelet épsége a `chain_ok`. A `reconcile` a `chain_ok`-ot olvassa (ott a horgonyt külön mezők kötik: `audit_head_not_covered`, `audit_head_hash_mismatch`).
- **Az ő tesztjében egyetlen sort írtam át**, és azt ki is mondom: a testvér-szonda ELŐFELTÉTELE (`later … ["ok"]`) az épségre kérdezett, tehát `chain_ok`-ra váltott. A szonda LELETE változatlan.
- Mérés: `test_joint_audit_anchor_20260916.py` **10/10 zöld** (eddig 9/10). Nyitott szonda: 3 → 2.

### A maradék két szonda: KIMONDOTT ellentmondás, nem mulasztás
- A `test_joint_delivery_outcome.py` két szondája (`hazug next_id`, `hazug pending`) azt kéri, hogy a **könyvtári** `reconcile` a busz audit-exportja **NÉLKÜL** is jelezzen. Ugyanennek a fájlnak a **kontrollja** viszont azt kéri, hogy a becsületes kör ugyanilyen feltételek mellett `hard=[] ÉS soft=[]` legyen.
- **Megmértük**: a két elvárás könyvtári szinten **kölcsönösen kizárja egymást**. A hazug és a becsületes kör a naplóból önmagában megkülönböztethetetlen — épp ezért van a második nyilvántartás. Ma harmadszor próbáltuk meg feloldani (soft harmadik állapottal); a kísérlet a becsületes kontrollokat vitte pirosra, ezért **visszavettük**.
- Ami ma is áll: a **CLI** termék/strict módban `--bus-audit` nélkül nem ad zöldet (rc=1, „hiányos bizonyíték"), és a kereszt-ellenőrzéssel a hazugság **hard** eltérés (`audit_skipped_contradicts_log`). A szondák ezért **szándékosan pirosak**, és ez a mátrixban ki van mondva.


### A napló-söprés is ÁLLANDÓ ŐRSZEM lett (09-16)
- Ugyanaz a fordulat, mint a capsule2-oldalon: a söprés eddig **egyszeri mérés** volt, mostantól a CI futtatja minden push-ra (`sweep_log_probe.py`). Felépít egy VALÓDI kört (posta → kiadás → ack, közjegyzővel és a busz audit-táblájával), és minden bejegyzés-mezőre végigmegy a hamisításokon: törlés / `null` / `0` / `"X"` / üres lista.
- **Amit a szonda azonnal talált:** a `seq: []` továbbra is **tracebacket** adott, mert az alak-kapu a `verify()` UTÁN futott — a rossz típus már ott elszállt. A kapu mostantól a `reconcile` **legelső** lépése, és a `verify()` bejegyzés-hash-guardja a `TypeError`-t is fogja.
- Mérés: `69 tamper | silent=0 crash=0`. A no-op hamisítás (a `claimed_ts_ms` `null`-ra írása ott, ahol már `null`) ki van hagyva — az semmit nem mér.


### A mátrix állításai a KÓDHOZ kötve (09-16)
- **Mérés:** a támadási mátrix 60 sorából **20 „ZÁRVA"/„CÁFOLVA" sor prózán állt** — egyetlen olyan azonosítót sem nevezett meg, ami a kódban létezik. Egy „zárva", amit semmi nem köt a kódhoz, pontosan az az osztály, amit a B-kar a korpuszban háromszor is kimért nálunk: **állításnak látszik, de nem az**.
- **Javítás:** mind a 20 sor megnevezi a megvalósító kód-szimbólumot (`entry_hash`, `audit_chain_verify`, `_key_bits_ok`, `_safe_name`, `MAX_SSE_PER_AGENT`, `_builtin_verify`, `_now_for_liveness`, …), és a `docs_bind_probe.py` **kikényszeríti**: minden „ZÁRVA"/„CÁFOLVA" sor nevezzen meg legalább egy LÉTEZŐ azonosítót (kód-szimbólum vagy fájl). A „NYITVA" sorokra ez nem áll — ott épp az a lényeg, hogy nincs mechanizmus.
- **Mutáns-próba:** egyetlen kötés kivétele („1.1 · kód: `entry_hash`") azonnal `rc=1`-et ad. A CI minden push-ra futtatja.


### Az alak-kapu „ne nézz ide" gombbá vált — a nem-Claude kar köre a mai javításon (09-16)
- **A lelet:** a `reconcile` alak-kapuja **korai `return`-nel** állt meg, tehát egy **szándékos** formai szemét (`seq: []`) egyetlen bejegyzésben megakadályozta, hogy a MÉLYEBB ellenőrzés (aláírás, backdate, hash-lánc) egyáltalán lefusson — és a válasz ártatlan **formai hibának** látszott. A támadónak ez a legolcsóbb „ne nézz ide" eszköz.
- **Javítás:** mostantól **mindkettő fut**. A rossz alakú sorokat kimondjuk (`malformed_entry`), a MARADÉKON lefuttatjuk a `verify`-t, és a mögötte lévő lánc-hibát külön néven hozzuk ki (`chain_error_behind_the_malformed`, plusz `verify_partial_ok` és a `verified_without_the_malformed` darabszám). A tracebacket továbbra is elkerüljük: a rossz alakú sorokat OBJEKTUM szerint szűrjük ki (nem a — épp hibás típusú — `seq` szerint).
- **Telemetria (az ő (1)/(2) pontja):** a harmadik állapotok egyedi eseményként „zajnak" tűnnek, ezért a jelentés mostantól **számot** ad róluk: `strict_ack_unknown`, `chain_unverifiable`, `rounds_unclosed` / `rounds_pledged`. Egy tartós, szándékos minta így aggregátumban látszik.
- **Az (1)-es pontja (a fail-closed mentőcsónak rendelkezésre-állási felületet nyit) elfogadva, KIMONDVA:** igen, aki eléri, hogy a kapu dobjon, a jogos visszaállítást is blokkolja. A kisebbik rossz mégis a fail-closed: egy becsúszott, kapu nélküli replay **tartósan** mérgezi a naplót, míg az elmaradt replay később pótolható — és a száraz futás (`commit=False`) továbbra is megmutatja, mit tenne.
- Mérés: `test_log_shape_20260916.py` 5 teszt; mutáns-próba: a javítás nélkül a „szemét elrejti a lánc-törést" szonda elesik. `sweep_log_probe: 69 tamper | silent=0 crash=0`.


### A séma-doksi is kötve — és a saját szondám egységét is mérni kellett (09-16)
- **Lelet:** az `AGENT_BUS_SCHEMA.md` „ismert értékként" sorolta a `proposal` kind-ot, ami a kódban **sehol nem szerepel**. Nem hiba (a `kind` nyitott enum), de félrevezető: aki a doksiból épít, azt hiheti, kezelve van.
- **Javítás:** a felsorolás kimondottan **TÁJÉKOZTATÓ**, a kikényszerített kind-ok (`sds-envelope`, `attachment`, `operator-wake`, `operator-sleep-safe`) külön állnak, és a `docs_bind_probe.py` kiterjed a séma-doksira is.
- **A saját szondám hibája, mérve:** először **bekezdés**-szinten jelöltem a kivételt — és egyetlen magyarázó mondat („…TÁJÉKOZTATÓ…") az **egész bekezdést** kivonta a mérés alól, tehát a mutáns némán átment. A szabály **sor-szintű** lett; a mutánsok (nem létező kind, átnevezett kind) most elesnek.
- **A diagnózis szövege is javítva:** a mátrix-sor és a séma-doksi két különböző hiba, tehát két különböző mondatot kapnak.
