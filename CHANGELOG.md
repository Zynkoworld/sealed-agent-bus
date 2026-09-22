## [1.5.3] — 2026-09-21 — a csomagoló és a pecsét egyet ért „szállított" alatt; a padló 9/9 őszintén

Javító kiadás: PONTOSAN a publikált 1.5.2 teljes utó-ellenőrzésének két lelete, semmi más. `PROTOCOL_VERSION` marad 1.5.0, `SCHEMA_VERSION` 1.0.0. Az 1.5.2 tag fagyott; ez az ág arról a commitról indul, három változott fájllal.

- **A PUBLIKÁLT REPÓBÓL MÁS ARTEFAKTUM ÉPÜLT, MINT AMIT ALÁÍRTUNK.** A verifikáló megtanulta, hogy a publikáláskor rákerülő landing-fájlok (`README.md`, `SECURITY.md`, `assets/sab.png`) kívül vannak a pecséten — a CSOMAGOLÓ viszont nem tudta. Ezért a publikált repóból 160 fájl és eltérő artefaktum-hash jött ki, a fejlesztési fából 157 és az aláírt hash. Egy vevő, aki a publikált repóból épít újra, **nem azt az archívumot kapta volna, amit aláírtunk** — pedig ez a termék egyetlen önmagáról szóló ígérete.
  Javítás: a csomagoló a pecsét listáját OLVASSA, nem egy másolatot tart; teszt követeli, hogy ez **egy** lista legyen, ne két egyező. A döntő próba klónozza a repót, rákommitolja a furniture-t (ahogy a publikálás teszi), és megköveteli, hogy a szállított fájllista változatlan maradjon. **Pontos nevek, nem könyvtár-minta**: egy `assets/**` alakú kivétel magától nő, ahogy a könyvtár telik.
- **A PADLÓ 9/9 — ŐSZINTÉN, KÜSZÖB-LAZÍTÁS NÉLKÜL.** A `log-write-failure-blocks` mutációja a `raise`-t `pass`-ra cserélte, amitől egy változó hozzárendelés nélkül maradt, és a tesztek `UnboundLocalError`-ral haltak meg: a fa omlott össze, nem az állítás bukott meg. Az 1.5.2 ezt WEAK-ként **kimondta**, és úgy is jelent meg a kiadásban. A recept mostantól `return`-t ad — ez a valódi fail-open, a napló kimarad, a művelet folytatódik —, és a claimet **hat assertion-ölés** bizonyítja, nem járulékos kár.

## [1.5.2] — 2026-09-21 — a két gép közti csatorna némasága, és a 09-17-i keményítő kör

A termék-ág 09-15-én ágazott le, és azóta nem kapta meg a fejlesztési ág köreit. Ez a kiadás behozza őket. `PROTOCOL_VERSION` marad 1.5.0, `SCHEMA_VERSION` 1.0.0.

- **A KÉT GÉP KÖZTI CSATORNA SÜKET VOLT 09-19 ÓTA.** A fogadó oldal `enforce_reject:unsigned-pinned` okkal dobta el a sorokat — 25 + 7064 sort, **nyomtalanul**: a küldő nem kapott jelzést, a fogadó nem naplózta láthatóan. Javítás: a **küldő a saját gépén írja alá a saját sorát** (`agent_bus.sign_for_send` / `check_presigned`, a csere átadja az előre aláírt sort, a kliens `sign_outgoing`), a busz a regiszter ellen ellenőrzi és **pontosan azt tárolja**; egy pinelt név alatt érkező aláíratlan sor **megnevezett okkal** pattan le a beléptetésnél. Élő próbával igazolva. 15 teszt, mutáns-próbával.
- **Lekérés-irány (09-20):** a kliens leírókat kér, a tartalom-címzett tár a darabokat adja vissza, körönkénti korlátokkal.
- **A 09-17-i keményítő kör:** pid-újrahasználat a single-flightban (folyamat-identitás, nem TTL); **HIGH** — távoli végpont nem írhat egy helyi agent nevében (feladó-névtér, és a pinelt név alatti csupasz sor külön osztály); az elhagyott részleges átvitel nem blokkolja örökre a tartalmat; a felügyeleti figyelő VÁRAKOZÓ ága is megkapja a beragadás-receptet; a termék-mód markerét a VALÓDI úton keressük (symlink nem ad dev-módot); az `AUTO_SIGN` nem folyamat-globális többé; az `_audit_cross` KULCS szerint párosít és kétirányú.
- **Két szándékosan piros szonda KIMONDVA, nem elnémítva.** A partner `ClampLiedFields` két szondája azt méri, hogy a kör-bejegyzés `pending`/`next_id` mezője a vádlott önbevallása, amit a közjegyzői napló önmagában nem cáfol. A szonda igazat mér, ezért **nem írtuk át** (szó szerint szállított bizonyíték); a futtató mondja ki, hogy a pirosuk VÁRT, `strict` módon — ha valaha átmennének, a suite pirosra vált és rákérdez. A korlát lezárása egy réteggel feljebb mérve van: a busz saját, hash-láncolt `cursor_audit` exportjával mindkét hazugság `audit_skipped_contradicts_log`.
- **A PADLÓ-MOTOR MEGERŐSÍTVE — a bizonyítékunk bizonyítéka volt gyenge.** Egy független kar nem elolvasta, hanem MEGTÁMADTA ezt a fejezetet, és négy valódi rést mért ki. A motor (1) csak a kilépési kódot nézte, így egy állítás, aminek a futása a mutáció előtt ÉS után is `16 bukott / 17 átment` volt, **nulla jelet** hordozott, és mégis bizonyítottnak számított; (2) nem különböztette meg, hogy egy teszt DÖNTÖTT a mutáció ellen, vagy a fa omlott össze egy `UnboundLocalError`-ral; (3) soha nem nézte a másik irányt, ahol a mutáció **feltámaszt** bukó teszteket; (4) `unittest`-tel mért, miközben a csomag pytestet hirdet — két külön gyűjtő. Mind a négy zárva: per-teszt kimenetel-**halmazok** diffje, minden új piros osztályozása (assertion = döntés / exception = járulékos kár), feltámasztásra bukás, és a szállított gyűjtő.
  Új, harmadik állapot: **WEAK** — a mutáció alkalmazódott és lett piros, de senki nem döntött. Nem pass és nem crash. A 6. kapu-tétel mostantól `floor N/M PROVEN (+k weak: <nevek>)` alakban ír, tehát a „9/9" nem állhat többé olyan halmazra, amiben van csak járulékosan mért sor.
  **MÉRVE ezen a gépen, rootként: 8 bizonyított, 1 WEAK** (`a naplóírás hibája megállítja a műveletet` — a mutációja csak kivétellel öl).
- **A padló erőssége függ attól, KI futtatja — és ezt a boríték kimondja.** A szállított tesztek root-tulajdonú kulcs-registryt feltételeznek (ez az őr akadályozza meg, hogy egy helyi felhasználó más nevében helyezzen el kulcsot), ezért nem-root vevőnél ~19 teszt eleve piros, és a halmaz-diff egy eleve bukó teszten nem hordoz jelet. Egy nem-root futás KEVESEBB bizonyított állítást fog jelenteni, mint a borítékban álló szám — ez a bizonyíték tulajdonsága, nem hibája, és a README is kimondja, a hízelgőbb szám helyett.
- **A publikált boríték megbukott a SAJÁT verifikálóján.** A publikálás után a landing-oldalra kerülő fájlok (`README.md`, `SECURITY.md`, `assets/`) nincsenek a manifestben, és a verifikáló „not in the manifest"-et mondott rájuk — a publikus v1.5.1 ma megbukik a saját ellenőrzésén. Javítás: ezek **pontos NEVEKKEL** kivételek (soha nem könyvtár-mintával: egy könyvtár-alakú kivétel magától nő, ahogy a könyvtár telik), és a verifikáló **kiírja**, mit nem fed a pecsét, ahelyett hogy csendben átlépné. Minden más listázatlan fájl változatlanul bukás, és ha egy furniture-fájl BEKERÜL a manifestbe, onnantól hash-ellenőrzött — mindhárom irány teszttel rögzítve.
  A manifest `source_commit`-ja az ÉPÍTŐ repóé; egy squash-publikálású tükörben az az objektum nem létezik, és egy független kar jogosan próbálta feloldani („bad object"). A verifikáló mostantól kimondja, hogy a pecsét a **hash-eken** áll, nem a commiton.
- **SPEC: az aláírt sor (`signed shape v:2`) NORMATÍV leírása a séma-dokumentumba** (`docs/AGENT_BUS_SCHEMA.md` §2b). A hotfix eddig CSAK kódot és tesztet változtatott: egy interop-partnernek kötelező protokoll-elem volt leírás nélkül, a független kar a szállított tesztből és egy docstringből volt kénytelen visszafejteni. A szakasz megadja a nyolc aláírt mezőt sorrendben és az alapértelmezéseket, a két kizárást (`id`, `thread_id`) az indokkal, a kanonizálást, a verdikt-vokabulárt, a kliens-aláírt cserét, és egy futtatható **konformancia-vektort** (seed + bájtkép + sha256 + pubkey + aláírás).
  Egy interop-csapdát külön kimondtunk, mert MÉRTÜK: a `ts` nanoszekundumban 2⁵³ fölött van, tehát aki a számokat az RFC 8785 JCS szám-szabálya (ECMAScript `Number::toString`, IEEE-754 double) szerint írja ki, `…544` helyett `…552`-t kap — más bájtkép, más aláírás, néma verify-bukás, és a hossz NEM változik, tehát a szokásos ellenőrzés sem fogja. A kanonizálásunk ezen az egy ponton szándékosan nem JCS; minden másban egybeesik vele.
  A doc nem elhitt, hanem mért: `test_schema_doc_signed_shape.py` újraszámolja a vektort a szállított kóddal, a mezőlistát a `_a2_content_bytes` tényleges kimenetéből vezeti le, és a csapdát is megméri — ha a kód mozdul és a doc nem, ez a teszt piros.
- **Címke-őr javítva — a mérő volt vak, nem a kód.** A verdikt-címkék halmazát AST-ből vezetjük le; amikor a modul a döntést `_builtin_verify`-ba szervezte, a kinyerő nem követte a delegálást, és „eltűnt státuszt" jelentett, miközben minden címke a helyén volt. A követés mostantól végigmegy a hívási láncon — és rögtön talált egy VALÓDI hiányt: a kód ad egy `unverifiable(no-config-binding)` okot, ami a pinelt listából kimaradt. Ugyanezt az okot egy független review is hiányolta egy kifelé menő dokumentumból 09-19-én; a kézzel gépelt halmaz kétszer ejtette el ugyanazt.
- **Proveniencia — új `joint-review-line` eredet.** A közös review-vonal 22 tesztfájljáról fájlnévből nem állapítható meg, melyik a partner szondája szó szerint és melyik a mi válaszunk. Egy licenc-állítást nem tippelünk meg: az új címke azt mondja ki, ami igaz (közös vonal, egy vállalkozás, a relicencelési jog ugyanaz), ahelyett hogy hamis pontosságot mutatna.
- **Csomagolási tisztítás a behozott körön:** az operátor titkos fájljaira mutató abszolút utak a merge-gomb szerszám alapértelmezéseiből a felhasználó saját konfig-könyvtárába kerültek (és használatkor bontjuk ki); a fejlesztési doksikból kikerültek a belső szereplő-nevek; a teszt-fixtúrák címei a dokumentációs tartományba (RFC 5737) költöztek, és a szivárgás-kereső mostantól tudja, hogy egy dokumentációs című nem lehet a miénk.

## [1.5.1] — 2026-09-21 — kiadás-kapu: a vizsgálat annyit ér, amennyit bejár

Csomagolás és kiadás-kapu; a busz-szerződés és a kód viselkedése VÁLTOZATLAN. `PROTOCOL_VERSION` marad 1.5.0, `SCHEMA_VERSION` 1.0.0.

- **A szivárgás-vizsgálat hatóköre a teljes archívum.** A kapu korábban a 87 szállított fájlból 72-t járt be: saját szűrővel újraszármaztatta a listát, és kihagyta a generált `product/evidence/`-et — abban ült egy elavult suite-napló, ami még törölt privát fájlneveket nevezett meg. Mostantól EGY definíciója van annak, mi megy ki (`make_release.shipped_names`), és a vizsgálat is, a proveniencia-leltár is attól kérdezi meg. Könyvtár-szintű kihagyás nincs; az egyetlen kivétel egy nevesített fájllista (maguk a minta-hordozók).
- **A szám a verdikt része:** „85 of 87 shipped files walked, 2 exempt as pattern holders". Ha egy szállított fájlt egyetlen séta sem ér el, a tétel megnevezve bukik — teszt zsugorítja vissza a bejárt halmazt és követeli, hogy a kapu észrevegye.
- **A proveniencia-leltár is a teljes archívumot fedi** (87 fájl): új `generated-here` eredet a saját gépezetünk által előállított boríték-fájloknak. A címkék NÉVEN számolódnak — a korábbi „partner = minden, ami nem first-party" alakú számláló az új kategóriát némán bekebelezte volna; teszt követeli, hogy a címkék összege = total.
- **A kiadás verziója elvált a protokoll verziójától** (`product/version.py`). A protokoll-verzió kimegy a drótra, tehát egy csomagolási javítás nem billentheti: a 3. kapu-tétel mostantól a kiadás-verzió pontos egyezését kéri az argumentummal és a boríték-manifesttel, a protokolltól pedig csak azt, hogy ugyanazon a MAJOR.MINOR vonalon legyen.

## [1.5.0] — 2026-09-14 — közjegyzői napló (notary log)

A v1.4 két nyitott maradéka: a visszadátumozás az ablakon BELÜL és a mátrix (a napló átírása legyen kimutatható, és az ellenőrzés fusson rendszeresen — két félnél).

- **Új: `bus_notary.py` + `test_bus_notary.py` (20 teszt).** Append-only, hash-láncolt JSONL: `{seq, prev_hash, received_at_ms, envelope_sha256, sender_identity, sender_auth, recipient, kind, decision, reason, claimed_ts_ms}`, `entry_hash = sha256(JCS(bejegyzés))`; N bejegyzésenként aláírt ellenőrzőpont `{seq, head_hash, ts_ms, notary_pub, sig}` (Ed25519). flock-kal folyamatok közt szerializált, fsync.
- **Export / offline verify / compare:** `export --from SEQ` (+ a legutolsó aláírt ellenőrzőpont); `verify` újraszámolja a láncot (átírás → hibás hash az adott seq-nél; teljes újraláncolás → az aláírt head nem egyezik; törlés → rés; átrendezés), ellenőrzi az aláírást és a megbízott kulcsot; `compare` a közös seq-tartományon bájtra, első eltérő seq-kel.
- **Visszadátumozás:** a feladó állított ideje (üzenet `ts`, SDS-rekord `ts`, relay-boríték `ts`; s/ms/µs/ns → ms) a fogadási időhöz mérve; ami az ablaknál régebbi → `backdated` (bizonyítékként a naplóban marad, nem dobjuk el).
- **Integráció:** `bus_ssh_exchange` üzenetenként és csatolmányonként (`sender_auth=ssh-key`); `bus_relay` `/deliver` (`unauthenticated-claim` — a `from` ott nem hitelesített, így is címkézve) és `/pickup` (`pickup-sig` / elutasítva). Sealed `ct` és nyílt törzs sosem kerül a naplóba (teszttel).
- **Mód:** termék-módban kötelező, kikapcsolhatatlan; cryptography vagy kulcs nélkül fail-closed (exchange: `notary unavailable (fail-closed)`, írási hiba → `notary write failed (fail-closed)`, a hátralévő tételek nem mennek át; relay: indulás megtagadva, írási hiba → 503 és a boríték nem marad a spoolban). Dev-módban alapból ki (a v1.4 viselkedés változatlan), `AGENT_BUS_NOTARY=on`.
- Külön napló-fájl → **SCHEMA_VERSION marad 1.0.0**; `PROTOCOL_VERSION` 1.5.0.
- **Javítás — 23Z):** `verify` `--pub` nélkül egy idegen kulccsal aláírt, önmagában konzisztens hamis láncot is `ok:true`-nak adott, és a report nem mutatta az aláírót. Most: ellenőrzőpontonként `notary_pub` + `trusted`; felső szinten `trusted` (csak megbízott `--pub`-bal lehet igaz), `signer_unverified`, `signers`. CLI `--pub` nélkül: dev-módban stderr-figyelmeztetés; **termék-módban megtagadás (rc=2)**. 3 új teszt.
- **Javítás — 25Z):** ellenőrzőpont nélküli szelet (friss napló <N bejegyzése, vagy a következő ellenőrzőpont előtti export) a HELYES `--pub`-bal `trusted:true`, `signer_unverified:false` választ kapott, pedig egyetlen aláírás sem ellenőrződött (termék-módban is). Most `trusted` csak akkor igaz, ha legalább egy ellenőrzőpont a megbízott kulccsal ténylegesen ellenőrződött és egy exportált bejegyzéshez kötődik; új mezők: `checkpoint_count`, `verified_checkpoint_count`, `covered_to_seq`, `unverified_tail`, `no_checkpoint_in_range`. CLI: ilyen szeletre dev-módban figyelmeztetés (rc=0, `trusted:false`), **termék-módban megtagadás (rc=3)**; ellenőrizetlen farokról stderr-megjegyzés. 3 új teszt (`test_M6b_*`).
- Teszt: **205 passed, 1 skipped** (a v1.4 + -javítás merge és a javítások után).

## [1.4.0] — 2026-09-14 — kikényszerítés (termék-mód)

Egy független támadási mátrix (v0) fő lelete alapján: a gyengeség nem kriptográfiai, hanem kikényszerítési (a busz annotált, a default megengedte az aláírás elhagyását).

- **Új: `bus_enforce.py` + `test_bus_enforce.py` (15 teszt).** Termék-mód: `AGENT_BUS_MODE=product` vagy `.product_mode.on`. A recv ELUTASÍTJA: aláíratlan (`unsigned-downgrade`, ), hamis / kulcs-eltérés (`forged`, ), ablakon kívüli ts (`stale-ts` / `future-ts`, ; alap −300 s / +60 s), visszajátszott tartalom (`replay`, — tartós seen-tár, új folyamatban is), hiányos csatolmány-leíró (`attachment-descriptor`, ). Termék-módban az sds-envelope kötelezően ellenőrzött, csak valid marad.
- **Alapértelmezés: dev** (a v1.3 viselkedés bájtra változatlan) — az élő flotta nem törik el. **A termék-/kiadási profil a product módot állítja be.** `abus doctor`: dev módban hangos figyelmeztetés, rc=1.
- **Semmi nem törlődik:** az elutasított sor a DB-ben marad; az ok a `enforce/rejected.jsonl`-ben. A seen-tár külön append-only fájl → **SCHEMA_VERSION marad 1.0.0**.
- **`bus_relay`: tartós lehúzási nonce-tár** (a spool mellett) — a v1.2 „újraindítás utáni egyszeri visszajátszás" kockázata zárva . 2 új teszt.
- **`sce_hook`: dokumentált leképezés** busz-sor → `sce-arm-envelope/v1` (a SDS record `payload` mezője) + `decide_rows`; végponttól végpontig teszt (8) hamis döntővel és opcionálisan a valódi külső adapterrel .
- **`agent_duty`:** a látható futó háttér-shell munkának számít (1 új teszt).
- `PROTOCOL_VERSION` 1.4.0 (MINOR). Teszt: **128 passed** (102 + 26).
- **review javításai (2026-09-14):**
  - a kikényszerítés a recv kurzor-tranzakcióján BELÜL, a kurzor előtt fut; az elutasított sor nem emeli a `delivered_id`-t, `read_at` NULL marad, `enforce_reject:<ok>` audit-sort kap → a `reconcile`/`replay` látja. Alap ts-ablak **−7 nap / +300 s** (a replay-tár fogja a duplát ablak nélkül is).
  - termék-módban a JSON-tükör csak aláírt sorra fut és hordozza a `sig`/`pubkey`-t; `tools/inbox_watch.sh` termék-módban megtagadja a futást (rc=3).
  - a marker a DB-fájl mellett és `/etc/agent-bus/product_mode.on` alatt is keresett (unió) — env-vel (AGENT_BRIDGE_DIR/AGENT_BUS_DIR/AGENT_BUS_MODE=dev) nem kapcsolható vissza; az ablak-env csak szűkíthet. ismeretlen `AGENT_BUS_MODE` érték → product.
  - /a kézbesítő recv seen-tára a DB-ben (`enforce_seen`, lusta tábla, a kurzorral atomi) — a fájl törlése nem nyitja újra a replayt, más UID nem ütközik fájl-jogosultságba; `rejected.jsonl` best-effort. Relay: hiányzó nonce-tár esetén az indulás előtti kérés elutasítva.
  - `recv_mark` audit `skipped` = elutasítottak száma. stderr-összegzés (peeknél is). `bus_enforce` opcionális import (termék-jelnél fail-closed). `agent_duty` SHELLS csak a `⏵⏵` státuszsoron, ≥1. recv-integrációs peek-teszt + ablak-pin. kikényszerítési hiba → fail-closed, kurzor nem mozdul, nincs traceback.
  - Teszt: **174 passed, 1 skipped** (+21 regressziós teszt).

## [1.3.1] — javításai

- **** a hiányzó/sérült ügyeletes-kijelölés `unknown` (rc=2, riasztás óránként), a szándékos „nincs ügyeletes" `no-duty` — egyik sem azonos a „minden rendben" `none`-nal.
- **** a „dolgozik" szövegminta mellé változás-bizonyíték: ha a busy-panel `busy_stuck_min` (alap 60) percig bájtra változatlan → `alert` („beragadt?").
- **** fali-óra ugrás ellen monoton órás összevetés; ugrásnál a tárolt időbélyegek eltolódnak, az eltelt idő megmarad.
- **/ ** pontos határteszt az enter-cooldownra (240 s), a done-küszöbre (5 perc), az alert-küszöbre és a halott-panel riasztásra (20 perc).
- **** agent/topic-váltás tesztelve (az előzmény törlődik).
- **** alapértelmezett `count_reports_inbox` (a felügyelő JSON-tükör inboxa) és valódi `bus_send` a `__main__`-ben.
Teszt: `test_agent_duty.py::MateReviewPR3` (11) — a javítás előtt 7 bukott.

## [1.3.0] — 2026-09-14 — ügyelet (agent_duty)

- **Új: `agent_duty.py` + `test_agent_duty.py` (11 teszt).** A munkasor aktív agentjét figyeli: dolgozik-e.
  - beragadt SAJÁT ébresztő a promptban → egy Enter (előtag-egyezés; más szöveg szent);
  - tétlen, üres prompt ≥10 perc → egy fix szövegű bökés (`agent_wake.safe_send`);
  - a bökés után ≥20 perc sem indul, vagy nincs panel → riasztás (óránként legfeljebb egy, cserélhető értesítővel);
  - ha az ébresztés óta jelentett és tétlen → a felügyelő kap jelzést, hogy léptesse a sort — a kész agentet nem bökdösi;
  - sleep-safe alatt néma; jóváhagyásra váró panelhez nem nyúl; a sort nem lépteti magától.
- **Miért:** 2026-09-14 reggel a flottában az ébresztő szövege a tmux-promptban ragadt (az Enter elveszett), és órákig senki nem dolgozott, miközben a sor szerint egy agentnek kellett volna.
- `PROTOCOL_VERSION` 1.3.0 (MINOR: új modul, busz-szerződés változatlan).

# CHANGELOG — AgentBus

## [1.2.1] — javításai

- **HIGH — `/deliver` flood:** beépített, fail-closed korlátok a relayben MÉG a proxy előtt: csak a registryben szereplő címzettnek fogad (ismeretlen → 404), címzettenkénti percenkénti ráta (`AGENT_BUS_RELAY_MAX_PER_MIN`, alap 120), címzettenkénti várakozó-plafon (`AGENT_BUS_RELAY_MAX_PENDING`, alap 200), teljes spool-plafon (`AGENT_BUS_RELAY_MAX_SPOOL`, alap 5000) → 429. Teszt: `test_bus_relay.py::test_H_deliver_*` (a külső review 500-as reprójával; a javítás előtt 3 teszt bukott).
- **Nyilvános kitétel:** a relay továbbra is CSAK TLS-t végző és rate-limitelő proxy mögött tehető ki; a beépített korlát a kézbesíthetőséget védi, nem helyettesíti a proxyt (README).
- LOW (nonce-cache perzisztencia) → a v1.4 zárja; LOW (forward secrecy) és INFO (CI, vegyes tesztstílus) → nyitott, ld. a v1.4 fejlesztési naplóját.

## v1.2.0 — 2026-09-14 (protokoll MINOR; DB-séma változatlan: 1.0.0)

### Új
- **`bus_ssh_exchange.py` / `bus_ssh_enroll.py` / `bus_ssh_client.py`** — szállítás gépek között SSH-n:
  - a távoli gép KIFELÉ SSH-zik (NAT-on át, a távoli oldalon nincs portnyitás);
  - a busz-gépen a kulcs egy `command="… bus_ssh_exchange.py <identity>",restrict,no-pty,…` sorhoz kötött —
    az identitás a parancs-argumentumból jön, a payload `from`/`sender` mezője figyelmen kívül marad;
  - méret-plafon (stdin, üzenet/kör), üzenetenkénti elutasítás, sds-envelope átmegy és a válaszok `sds` címkét kapnak;
  - legalább-egyszer kézbesítés: a válasz peek, a kurzor a kliens következő körbeli `ack`-jára lép; a kliens a
    távoli id alapján dedupol;
  - az enroll CSAK sort állít elő / a megadott fájlba ír, az sshd-konfigurációhoz nem nyúl.
- **`bus_relay.py`** — vak store-and-forward relay, ha nincs közvetlen SSH:
  - E2E borítékolás (X25519 → HKDF-SHA256 → ChaCha20-Poly1305), a relay csak opak borítékot tárol;
  - **aláírt lehúzás** (`/pickup`): Ed25519, célhoz kötött (`pickup`/`events`), ±120 s ts-ablak, nonce-replay-cache;
  - **SSE** (`/events`): hitelesített feliratkozás, csak „N várakozó" jelzés, tartalom soha; a kliens pollozásra esik vissza;
  - fail-closed: `cryptography` nélkül vagy üres registry-vel nem indul; lehúzott boríték `.picked/` alá (nincs törlés).
- **`bus_attach.py`** — nagy tartalom csatolmányként: tartalom-címzett, write-once tár; a busz `attachment` kindja
  csak a leírót viszi (`sha256`, `size`, `media_type`, `locator`); olvasáskor hash+méret ellenőrzés; darabolt
  szállítás SSH-n és relay-en, a tárba csak a teljes hash-ellenőrzés után kerül.
- **`sce_hook.py`** — csatlakozási pont a Silent Consensus Engine-hez (`AGENT_BUS_SCE_DECIDER=modul:függvény`);
  motor-kód nincs; nincs döntő → nincs döntés; hibás döntő → ABORT.

### Változott
- `agent_bus.py`: `PROTOCOL_VERSION = "1.2.0"`; `send` elutasítja a nem-leíró body-t `attachment` kindnál.
  A 64 KB-os body-plafon változatlan.

### Szándékosan kimaradt
- **ICE / WebRTC:** a kifelé irányuló SSH ugyanazt a NAT-problémát megoldja külső STUN/TURN szerverek és nagy
  támadási felület nélkül.

### Tesztek
- 31 új (SSH 11, relay 9, csatolmány 7, SCE-hook 4); a teljes csomag 91 zöld.

## [1.1.1] — javításai

- **B1 (BLOCKER) — `bus_singleflight`:** az `acquire` CLI egyszeri folyamat, a saját pid-je nem tulajdonos. Most: (1) a check→stale→visszaigénylés lépéssor egy oldalfájlon tartott `flock` alatt atomi; (2) a CLI alapból a HÍVÓ (szülő) pid-jét veszi tulajdonosnak, ha nincs `--owner-pid`/`--target`; (3) nem-pid alakú instance friss zárja a TTL-ig él (korábban azonnal halottnak látszott); (4) identitás-visszanyerés csak ugyanannak a tulajdonosnak jár. Teszt: `test_bus_singleflight.py` (valódi OS-folyamatokkal, a külső review mindkét reprójával — a javítás előtt 4 teszt bukott).
- **H1 — tmux-target + halott explicit owner-pid:** a zár már nem ragad be (`pid_src=owner` esetén a pid halála is a zár halála).
- **H2 — watcher DoS:** a JSON-törzs agent-nevei ugyanazt a szigorú `[A-Za-z0-9._-]{1,64}` szabályt kapják; a watcher diszpécsere nem állhat le egy operátor-parancs kivételén.
- **H3:** `bus_singleflight` dedikált tesztkészletet kapott.
- **M1:** a teljes készlet CSAK `python3 -m pytest -q`-val fut le; `test_runner_guard.py` unittest alatt hangosan bukik (a korábbi „vagy `python3 -m unittest`" téves volt).
- **M2 — kulcs nélküli operátor:** alapból elutasítva (`ignored:operator-no-key`); fejlesztői kivétel csak `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1`-gyel.

## v1.1.0 — 2026-09-14 (protokoll MINOR; DB-séma változatlan: 1.0.0)

### Javítás — 29Z)
- **B1-var:** `acquire --target <nem élő panel>` megtagadva (`target-not-live`, rc=4, nincs lock-írás) — korábban a
  sosem-élő targettel írt zárat a másik hívó azonnal stale-nek látta → 9/15 körben két `acquired`. Regresszió:
  `test_B1var_owner_pid_vs_nonexistent_target_never_double_acquired` (15 kör), `test_B1var_acquire_with_dead_target_is_refused_and_writes_nothing`.
- **WAKE_DIR:** `agent_bus_watcher.wake_dir()` a hívás idején: `AGENT_WAKE_DIR` vagy `<AGENT_BRIDGE_DIR>/wake` (korábban import-időben
  befagyott, telepítés-alapértelmezett `wake` könyvtár). A tesztek `Env` alapja a tmp alá irányítja mindhárom könyvtárat.
- README: az `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR` dev-kapcsoló dokumentálva.

### Új
- **`agent_wake.py`** — az ébresztési szabályok egy helyen:
  - *szent gépelés*: élő, el nem küldött szöveget tartalmazó promptba soha nem ír, és nem töröl (nincs C-u);
    a halvány (dim) felajánlás nem gépelés; kétség esetén „gépel";
  - dolgozó agentet nem bök;
  - *sleep-safe*: globális vagy agentenkénti marker; alvó agent panelébe nem megy bökés és headless wake sem indul;
  - *operátori wake*: `operator-wake` / `operator-sleep-safe` kind, csak engedélyezett (és ha van kulcsa, aláírt)
    operátortól; agent magát nem ébresztheti; a WAKE a markert `history/` alá mozgatja (nincs törlés).
- **`sds_envelope.py`** + `agent_bus` bekötés (a külső review három lépése):
  - `send --kind sds-envelope`: csak SPEC §5.5 keretezett `{record, envelope}` pár;
  - `recv --verify-sds [--strict-sds] [--sds-admission PATH]`: `valid | invalid(<ok>) | unsigned | unverifiable(<ok>)`;
    cserélhető validátor (`AGENT_BUS_SDS_VALIDATOR` / `CAPSULE2_SDS_VALIDATOR`);
  - kormányzás-híd: helyi admission-fájl + A2 kulcs-registry → `not-admitted`, `key-mismatch`, `forged-sender`.
- **`bus_singleflight.py`** — egy agent-identitásból egyszerre csak egy instancia drainel (session-lock + atomi claim).
- Tesztek: `test_agent_wake.py`, `test_sds_envelope.py`, `test_agent_bus_security.py`, `test_bus_poke_pin.py`.

### Változott
- `bus_poke.py`: az inject az `agent_wake` szabályain megy át; ha a modul hiányzik, **nem injektál** (fail-closed).
  Új `Poker.on_new` eredmények: `sleep-safe`, `typed`, `busy`, `stuck`.
- `agent_bus_watcher.py`: alvó agentet nem ébreszt; a címzettnek érkező operátori WAKE/SLEEP parancsokat alkalmazza.
- `agent_bus.py`: `PROTOCOL_VERSION = "1.1.0"`; `SCHEMA_VERSION` szándékosan `1.0.0` marad (a `verify` a pin-eltérést
  DRIFT-nek jelzi, a séma pedig nem változott).

## v1.0.0 — 2026-06-21
Befagyasztott wire-kontraktus (lásd `docs/AGENT_BUS_SCHEMA.md`).

