# AgentBus v1.5 — támadási mátrix

**Dátum:** 2026-09-16 · **Fej:** `dev/v1.5-notary` · **Mérte:** a belső mérő-kar + a nem-Claude kar + az egyik kar (B kar, külön szervezet)

Ez a lap egy helyen mondja meg, **mi van megmérve, mi van zárva, és mi van nyitva**. Minden sor mögött futtatás áll, nem vélemény. Ahol „nyitva", ott a **kimondott korlát** is ott van — mert egy nyitott rés kimondva olcsóbb, mint eltakarva.

## Hogyan olvasd

- **ZÁRVA** — van rá mechanizmus ÉS regressziós teszt, amit a javítás visszavételével megbuktattunk (mutáns-próba).
- **CÁFOLVA** — valaki állította, hogy rés, és a mérés szerint nem az. A negatív eredmény is eredmény.
- **NYITVA** — mérten fennáll. Mellette, hogy mi zárná, és kinek a döntése.

---

## 1. Közjegyzői napló (a bizonyíték-réteg)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 1.1 | bejegyzés utólagos átírása | **ZÁRVA** | `entry rewritten (hash mismatch)`; élő adaton is (a két gépes próbán) · kód: `entry_hash` |
| 1.2 | bejegyzés törlése a lánc közepéből | **ZÁRVA** | `gap: entries N..M missing` + `chain broken` · kód: `audit_chain_verify` |
| 1.3 | a szelet FARKÁNAK levágása (ellenőrzőpont után) | **ZÁRVA** | `unverified_tail` → `trusted:false` |
| 1.4 | a szelet ELEJÉNEK elhagyása (horgonytalan szelet) | **ZÁRVA** (2026-09-16 kiterjesztve) | `slice_start_seq` + `anchored`; termék-módban a CLI megtagadja (rc=3). **Új:** az `audit_chain_verify().ok` NEVE eddig két különböző dolgot jelentett — a DB-úton (`audit_verify`) ép ÉS horgonyzott, az exportált úton csak ép. Aki az `ok`-ot olvasta, hamis zöldet kapott egy horgonyzatlan szeletre. Az `ok` mostantól a szigorúbb jelentést hordozza, a szelet épségét a `chain_ok` mondja (a `reconcile` azt olvassa). az egyik kar nyitott szondája ezzel ZÁRVA: `test_joint_audit_anchor_20260916.py` 10/10 zöld |
| 1.5 | kitalált lánc saját kulccsal | **ZÁRVA** (részben) | `trusted:false` `--pub` nélkül; termék-módban a `--pub` kötelező · kód: `trusted_pub` |
| 1.6 | **equivocation** (két ág, mindkettő aláírva, az egyik eltitkolva) | **NYITVA** | a `compare` csak akkor lát forkot, ha MINDKÉT export megvan. **Zárja:** külső tanú (off-box/enklávé) — v1.7, operátori döntés |

## 2. A kurzor és a kiadás (a szállítási réteg)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 2.1 | ack átugrik kiadatlan posta fölött | **ZÁRVA** | a strict clamp termék-módban ALAPÉRTELMEZÉS (09-16); a menekülő ajtó ténye a naplóba kerül (`strict_ack: 0` → `strict_ack_disabled`) |
| 2.2 | a kör letagadja a kiadatlan postát (`pending`/`next_id` hazugság) | **ZÁRVA** | a busz saját `cursor_audit`-jával összevetve `audit_skipped_contradicts_log` |
| 2.3 | a MÁSODIK nyilvántartás megrövidítése (ép, de hiányos export) | **ZÁRVA** | `audit_row_missing`, `audit_head_not_covered`, `audit_head_hash_mismatch`, `audit_evidence_absent`, `audit_chain_broken`, `audit_identity_mismatch` |
| 2.4 | a horgony elhagyása (fail-open írás) | **ZÁRVA** (harmadik állapot) | `audit_anchor_absent` (unresolved → strict-ben nem zöld) |
| 2.5 | a vízszint befagyasztása egy szemét sorral (DoS) | **ZÁRVA** | átmeneti vs. végleges elutasítás; a `forged` kegyelmi ideje korlátos (24 h / rollout-marker), jövőbeli `ts` nem friss |
| 2.6 | hazug ack lezárja a nyitott elutasítás-nyomot | **ZÁRVA** | `remote_delivered` csak kiadható id-re; a visszautasítás `remote_delivered_refused` sorba kerül |
| 2.7 | **egykörös** szeleten a második nyilvántartás következetes újraláncolása | **ZÁRVA** (2026-09-16) | a kör VÉGÉN `round_close` bejegyzés, a horgonyt (`audit_end_seq`/`audit_end_hash`) a KÖZJEGYZŐ számolja; a nyitó bejegyzésbe szintén ő írja a `closes: 1` vállalást, tehát az író fél nem hagyhatja el. A zárás MEGNEVEZI a körét (`round_seq`), a horgony MONOTON (`audit_close_before_open`), a hiányzó zárás SOFT + **számolva** (`rounds_unclosed`/`rounds_pledged`). Mérés: `test_round_close_anchor_20260916.py` (8 eset), mutáns-próba átlós. **Kimondva:** a záró írás fail-OPEN (a posta ekkor már kiment) — a hibát a válasz `round_close: "failed"` mezője és a soft-eltérés mondja ki; a teljes zárás külső tanú (v1.7, operátori döntés) |

## 3. A kapu (kikényszerítés)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 3.1 | aláíratlan / hamis / elavult / visszajátszott sor | **ZÁRVA** | `unsigned-downgrade` / `forged` / `stale-ts` / `replay` |
| 3.2 | replay-verseny (két párhuzamos recv) | **ZÁRVA** | az `add()` FALSE-a = `replay` (az egyetlen atomi jel) |
| 3.3 | fogyasztás seen-tár nélkül | **ZÁRVA** | `record=True, seen=None` → `ValueError` |
| 3.4 | újraaláírással új replay-kulcs | **CÁFOLVA** | az Ed25519 determinista: ugyanaz a tartalom = ugyanaz az aláírás · kód: `verify_sender` |
| 3.5 | a termék-mód markerének törlése (néma downgrade dev-re) | **NYITVA** | ha a mód CSAK busz-melletti markeren áll. **Zárja:** a root-tulajdonú `/etc/agent-bus/product_mode.on` — a `doctor()` hangosan követeli; élesítéskor operátori lépés |
| 3.6 | JSON-tükör mint „második ajtó" | **ZÁRVA** | termék-módban csak ALÁÍRT üzenet tükröződik, és a tükör viszi a `sig`/`pubkey`-t |

## 4. Kulcsok és identitás

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 4.1 | más nevében küldés (A2) | **ZÁRVA** | a registry-pubkey köti a sendert; eltérés → `forged` |
| 4.2 | a sender-név mint útvonal (traversal a kulcs-tárba) | **CÁFOLVA** | `os.path.basename` + `.`/`..` tiltás |
| 4.3 | symlink a kulcsfájl helyén / TOCTOU a guardban | **ZÁRVA** | `O_NOFOLLOW` + `fstat` a megnyitott fd-n; a seed-útnál `lstat` + „csak valódi fájl" |
| 4.4 | típus-zsonglőrködés az aláírt bájtképben (None/"" , int/str) | **CÁFOLVA** | a verify a KAPOTT dictből épít → bármely típusváltás aláírás-hiba · kód: `verify_sender` |
| 4.5 | gyenge kulcs beléptetése | **ZÁRVA** | a beléptető sor RSA-nál ≥ 3072 bit; a blob típusa egyezik a prefixszel · kód: `_key_bits_ok` |
| 4.6 | a beléptető sor csendes gyengítése (meglévő, korlátozás nélküli sor) | **ZÁRVA** | azonos kulcs + eltérő sor → hangos hiba · kód: `write_line` |
| 4.7 | kiszivárgott kulcs bárhonnan | **NYITVA (opció)** | `--from` forráskorlát megvan; ha nincs megadva, a CLI figyelmeztet. **Zárja:** a partner címének ismerete — üzemeltetői döntés |

## 5. Szállítás gépek között (SSH, relay, csatolmány)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 5.1 | tetszőleges parancs / port-forward / PTY / agent-forward a force-command mögött | **CÁFOLVA** | a B kar valódi `sshd`-vel mérte (PR ) |
| 5.2 | a feladó hamisítása a payloadból | **CÁFOLVA** | a feladó a force-command argumentumából jön · kód: `_safe_name` |
| 5.3 | a relay olvassa a tartalmat | **CÁFOLVA** | X25519→HKDF→ChaCha20-Poly1305, AAD-kötés · kód: `ChaCha20Poly1305` |
| 5.4 | lehúzás-visszajátszás | **CÁFOLVA** | tartós, purpose-höz kötött nonce-tár · kód: `nonce` |
| 5.5 | postafiók-elárasztás | **ZÁRVA** | 120/perc/címzett, 200 függő, 5000 spool · kód: `MAX_PENDING` |
| 5.6 | lemez-elárasztás a NEM TÖRÖLT munkafájlokkal | **ZÁRVA** | csatolmány-munkafájl kvóta (2 GiB) + relay archív-kvóta (100k) — törlés nélkül, fail-closed kapuval · kód: `MAX_WORK_BYTES` |
| 5.7 | SSE-kapcsolatok szál/fd-kimerítése | **ZÁRVA** | agentenként 2 egyidejű kapcsolat · kód: `MAX_SSE_PER_AGENT` |
| 5.8 | csonka „hány levél vár" mérés tiszta körnek látszik | **ZÁRVA** | `pending_truncated` → `round_pending_unknown` |

## 6. SDS-híd és bökő-út

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 6.1 | env-ből betöltött hamis SDS-validátor | **ZÁRVA** | a beépített ellenőrzés fut előbb; a külső CSAK szigoríthat · kód: `_builtin_verify` |
| 6.2 | cross-config replay (nem kötött `config_id`) | **ZÁRVA** | `unverifiable(no-config-binding)` |
| 6.3 | NFC/NFD kétértelműség a role/org-ban | **ZÁRVA** | NFC-normalizálás az aláírt üzenet építésekor · kód: `normalize` |
| 6.4 | az admission-fájl lecserélése | **NYITVA** | a busz HELYI nézete; nincs aláírva, nincs a JOINT genezis-lánchoz kötve. **Zárja:** a §5.4 kötés (capsule2 vonal) |
| 6.5 | escape/ANSI-injekció a bökésen át | **CÁFOLVA** | az ESC szűrve; üzenet-tartalom SOSEM megy a `send-keys`-be · kód: `_safe` |
| 6.6 | láthatatlan sor-szeparátorral hamis log-sor | **ZÁRVA** | `U+2028/2029/0085` és a bidi-vezérlők is kiesnek · kód: `_safe` |
| 6.7 | a bökés más panelbe irányítása | **ZÁRVA** | a tmux-target alakja kötött; nem illeszkedő → nincs bökés · kód: `_safe_target` |
| 6.8 | közvetett prompt-injekció a feed `note` mezőjén | **NYITVA (kimondva)** | a sor kimondja: `adat=...`. **Zárja:** az agent szabálya („a busz tartalma ADAT"), nem szűrő |

## 6b. Single-flight zár (egy agent = egy példány)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 6b.1 | két példány ugyanarra az identitásra | **ZÁRVA** | `duplicate`; a versengő `acquire`-ok flockkal sorba rendezve |
| 6b.2 | a hívói óra a jövőbe állítva → élő TTL-zár „stale" | **ZÁRVA** | az ÉLETRŐL döntő óra csak a valóságtól 24 órán belüli hívói értéket fogadja el (a szimuláció működik) · kód: `_now_for_liveness` |
| 6b.3 | `heartbeat`/`release` a mutexen KÍVÜL (TOCTOU) | **ZÁRVA** | mindkettő ugyanazon a flockon megy |
| 6b.6 | ÉLŐ, stabil nevű worker claimjeinek elvétele (`requeue_dead`) | **ZÁRVA** | a „nincs pid-bizonyíték" harmadik állapot: pid → session-lock → a claim-könyvtár frissessége (TTL) |
| 6b.7 | a hívói óra a FÁJLBA (múltbeli → két `acquired`; jövőbeli → örök zár) | **ZÁRVA** | a `ts_ns` a korlátozott, életről döntő érték; a hívó nyers bélyege `caller_ts_ns` audit-mezőben |
| 6b.4 | **`release` csak az `instance` NEVET kéri** | **NYITVA (kimondva)** | aki a lock-fájlt olvassa, egy ÉLŐ tulajdonos zárát is elengedheti. **Zárja:** acquire-kor adott titkos token — a vendorolt hívók szerződését változtatja (MAJOR-kapu), tulajdonosi döntés |
| 6b.5 | `target`-liveness `owner_pid` nélkül: élő panel + halott worker | **NYITVA (kimondva)** | rendelkezésre-állási támadás (a törvényes agent `duplicate`-t kap), **nem** duplikátum. **Zárja:** kötelező `owner_pid` a target-ágon — szintén hívói szerződés |

## 6c. Ügyelet-figyelő (felügyeleti segéd, NEM bizalmi határ)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 6c.1 | „jelentés" = puszta fájlnév (`touch`, `{}`) | **ZÁRVA** | a fájl a busz JSON-tükrének sora kell legyen, `from == agent`; nem értelmezhető JSON sem számít |
| 6c.2 | egy riasztás elnyomja a másik TÍPUST | **ZÁRVA** | típusonkénti kulcs (`alerted_no_pane` / `alerted_stuck` / `alerted_idle`) |
| 6c.3 | a kijelölés-fájl (`duty_active.json`) átírása | **NYITVA (kimondva)** | nincs hitelesítve; aki írni tudja, átírja, ki az ügyeletes. A modul a SAJÁT gépünk felügyeleti segédje |
| 6c.4 | a „dolgozik" jelzés hamisítása a panel tartalmával | **NYITVA (kimondva)** | a panelt AZ AGENT írja; a bájt-hash + idő (beragadás-figyelés) szűkíti, de nem teszi hamisíthatatlanná. **Zárja:** process-szintű CPU-idő |

## 6d. Ébresztés / alvás-markerek (felügyeleti segéd, NEM bizalmi határ)

| # | Támadás | Állapot | Mérés |
|---|---|---|---|
| 6d.1 | idegen `sleep_safe` marker → csendes elnémítás; marker törlése → ébresztés; **a könyvtár CSERÉJE a szülőn át** | **KIMONDVA + jelzett (a jelzés 2026-09-16 óta tényleg eljut)** | a `state_dir_warnings()`-nak NEM volt termelési hívója (csak a saját tesztje), a verdikt pedig CSAK a levelet nézte — a cseréhez viszont elég a SZÜLŐRE írni (`rename` + `makedirs`), a levél jogaitól függetlenül, tehát egy root-tulajdonú 0700 levél tiszta bizonyítványt kapott világ-írható szülő alatt (**hamis megnyugtatás**). Ezen felül a `makedirs(mode=)` a köztes szinteket a umask szerint hozta létre, tehát `umask 0002` alatt a SAJÁT kódunk állította elő a csere előfeltételét. Most: a watcher INDULÁSKOR kiírja a listát (stderr), a verdikt a szülő-láncot is nézi (a **sticky** szülőt nem jelenti, mert az megvédi az idegen bejegyzést), és a láncot szigorú móddal magunk építjük. Mérés: `test_joint_wake_parent_20260916.py` (6 teszt, mutáns-próbával 5 elesik a javítás nélkül). **KIMONDVA:** ugyanebben a könyvtárban dől el az ÜGYELET is (`duty_active.json`), és egy odadobott fájl a 6c-s riasztást is elnémíthatja — a könyvtár ÁLLAPOT, nem BIZONYÍTÉK |
| 6d.2 | `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR=1` — aláírás nélküli ébresztés | **ZÁRVA (nem néma)** | a kapcsoló használata figyelmeztetést ír; nélküle `ignored:operator-no-key` · kód: `AGENT_WAKE_ALLOW_KEYLESS_OPERATOR` |
| 6d.3 | TOCTOU a `may_poke` és a `send-keys` között | **NYITVA (kimondva)** | a „szent gépelés" szabály szűkíti (nincs C-u, nincs vak újrapróbálás), az ablak létezik |
| 6d.4 | ál-busy panel → az agent ébreszthetetlen | **NYITVA (kimondva)** | a felismerés a panel szövegéből jön, amit az agent maga ír. **Zárja:** strukturált jel (process-állapot / heartbeat) |

## 7. Ami a felületen kívül van

| # | Tétel | Állapot |
|---|---|---|
| 7.1 | a CI workflow a HEAD-en él (egy PR kikapcsolhatja) | **NYITVA** — required status check kell hozzá, ami a HIÁNYZÓ checket is pirosnak veszi (repó-beállítás, tulajdonosi döntés) |
| 7.2 | a `requirements-ci.txt` nem pineli önmagát | **ZÁRVA** (2026-09-16) — a `--require-hashes` a CSOMAGOKAT köti, a LISTÁT nem: aki a closure-t kicseréli, a hash-eket is átírja. A fájl digestje ezért a workflow-ban áll (`CLOSURE_SHA256`), a lépés a telepítés ELŐTT fut, és a repóban is mérjük (`test_ci_closure_pin_20260916.py`, 4 teszt, mutáns-próbával). **Kimondva:** ez a 7.2-t zárja, nem a 7.1-et |
| 2.9 | egy TOVÁBBI, önmagában becsületes kör kioltja a kereszt-ellenőrzés vádját | **ZÁRVA** — a vád globális ∀-kvantoron állt (`claimed_all = all(...)`), így egyetlen szabályos, hazugságot NEM tartalmazó kör-bejegyzés visszamenőleg mentesítette a hazug kört is. A kihagyás mostantól ahhoz a körhöz tartozik, amelyiknek az ACK-je hozta a `skipped_undelivered > 0`-t (`_audit_cross`, `per_round`), a hozzárendelhetetlen kihagyás pedig `audit_skip_unattributable` (soft). Mutáns-próbával |
| 2.10 | a kör-záró horgony számonkérését az ELLENŐRZÖTT fél mezője kapcsolja ki | **ZÁRVA** — a `closes` a naplóban utazik, tehát annak a szava, akit vizsgálunk, és a hiánya eddig CSAK egy minősítetlen számlálóban látszott. Mostantól `rounds_unpledged` számláló, és ha EGYETLEN kör sem vállal: `audit_close_pledge_absent` (soft, NEM vád — egy régi közjegyző ép, aláírt láncot ír) |
| 2.11 | a MÁSODIK NYILVÁNTARTÁS hiánya némán zöld | **KIMONDVA, DÖNTÉSRE VÁR** (2026-09-16) — `bus_audit=None` mellett a kör önbevallott számai ellenőrizetlenek; ez mostantól `audit_register_absent` a `notes` csatornán (kimondva, de NEM verdikt). `unresolved`-be téve HÁROM becsületes kontroll-teszt vált pirosra (mérve: `test_joint_clamp_optout`, `test_joint_cursor_skips_undelivered`, `test_log_shape_20260916`) — a szigorítás szerződés-kérdés, nem egyoldalú döntés |
| 2.12 | a KONZISZTENS ÍRÓ: aki a naplót írja, a hash-láncot is újraszámolja | **KIMONDVA + MÉRVE** — a `cursor` almezőinek söprése hamisítás UTÁNI újraláncolással: ALÁÍRT ellenőrzőpontot tartalmazó exporton 68 hamisításból **0** néma, ALÁÍRÁS NÉLKÜLI szeleten **42** (11 mező). A fedezet tehát nem az, hogy bárki OLVASSA ezeket a mezőket, hanem az ALÁÍRÁS — az író újraláncolhat, de a közjegyző checkpointját nem tudja újra aláírni. A 11 nem ellenőrzött almező a `sweep_log_probe.CURSOR_UNCHECKED` táblában NÉVVEL és INDOKKAL áll; egy NEM deklarált néma mező a szondát megbuktatja. Az aláírás nélküli szeletet a `reconcile` mostantól kimondja (`slice_without_signed_checkpoint`, notes) |
| 2.13 | a kör-bejegyzés a SAJÁT ack-je MÖGÉ írva leminősíti a bizonyítékot | **ZÁRVA** (2026-09-16, nem-Claude kar a kvantor-javításra) — a vádat az ack ELŐTTI utolsó körhöz kötöttük, tehát ha a `pickup` a saját ack-je mögött áll, nem volt „előtte" kör, és a KEMÉNY `audit_skipped_contradicts_log` némán `audit_skip_unattributable`-re (soft) gyengült: a támadó pusztán a SORRENDDEL minősít le bizonyítékot. Mostantól a vád az ack UTÁNI legelső körre köt, és a rendellenes sorrend külön kimondva: `round_entry_after_its_ack` |
| 2.14 | a BELÉPŐ PONT: a másik fél exportja FÁJLKÉNT | **ZÁRVA** (2026-09-16) — a `read_lines` `type: garbage` sora csak a JSON-PARSE hibát fedte: ami JSON-ként érvényes, de nem OBJEKTUM (`5`, `[1,2,3]`), az egyenesen a `.get()`-be futott (`AttributeError`, NYERS TRACEBACK). Az ÜRES fájl pedig `rc=0`-t, azaz ZÖLD bizonyítványt kapott — a legüresebb lehetséges bemenet. Mostantól minden visszaadott rekord SZÓTÁR (a rossz típus nevesítve, a `parsed_as` mezővel), és az üres napló NEVESÍTETT elutasítás: nulla bejegyzésen nincs hazugság, de bizonyíték sincs. `test_belepo_pont_20260916.py`, 9 teszt, mutáns-próbával |
| 2.15 | a belépő-pont osztály MINDEN CLI al-parancson | **ZÁRVA** (2026-09-16) — a 2.14-et a `bus_notary verify`-ban zártam, és az utána írt gyors söprésem „mind OK"-ot mondott a többire. A söprés **VAK volt**: az al-parancsokat az `--help` SZÖVEG sorainak elejéről kereste, az argparse viszont `{verify,reconcile,…}` alakban, behúzva írja ki — így egyetlen al-parancsot sem hívott meg, és a paraméter nélküli hívás argparse-hibáját (rc=2) „rendben"-nek olvasta. A `test_belepo_pont_osztaly_20260916.py` az al-parancsokat a PARSER-ből veszi (a szöveg formázás, a parser a tény), és külön ELŐFELTÉTEL-teszt köti, hogy a szonda legalább a `bus_notary verify`-t megtalálja — különben vakon zöld. Mutáns-próbával |
| 2.16 | a felelős kört a TÁMADÓ választja meg (egy kihagyott mezővel) | **ZÁRVA** — a vád az ack ELŐTTI UTOLSÓ `pickup`-ra szállt, ezért elég volt egy további kör-bejegyzést a hazug kör és a saját ack-je KÖZÉ írni, ami a `cursor`-jából KIHAGYJA a `pending`-et: semmit nem állít, tehát nem felel — és a vád eltűnt (dev-módban rc=0, `ok:true` NÉGY véglegesen elveszett üzenet fölött). Mostantól az ACK-ABLAK felel: az előző naplózott ack és ez az ack között nyitott MINDEN kör tagja, és aki közülük ÁLLÍTJA, hogy nem hagyott ki semmit, az felel (`_claimers`). Aki hallgat, nem felel — de nem is MENTESÍT mást. Mutáns-próbával |
| 2.17 | az üres-napló elutasítás a SOROK számához volt kötve, nem a bizonyítékhoz | **ZÁRVA** — egyetlen `{}` sor nem-üressé tette a listát, a BEJEGYZÉSEK száma maradt nulla, és a `verify` zöld bizonyítványt adott. Mostantól `_no_evidence()`: 0 entry + 0 checkpoint -> nevesített elutasítás, a sorok számától függetlenül. Ugyanez az `export`-on (szemét forrásból csendben üres szelet készült, rc=0) |
| 2.18 | `reconcile`: a nulla bizonyíték vs. az „ismeretlen kimenetel nem vád" ÜTKÖZÉSE | **KIMONDVA, RÉSZBEN ZÁRVA** — a `verify` alakjában átvéve az elutasítás elbuktatja a `test_unknown_outcome_is_unresolved_not_an_accusation` kontrollt, ami épp a partner SAJÁT osztályát köti. A `reconcile` nem ugyanaz az eset: ott a napló nem az egyetlen bizonyíték, a nyugta a másik oldal. Ezért: SZEMÉT sor -> elutasítás minden módban; ÜRES napló -> strict/termék-módban rc=1, dev-módban NEVESÍTVE (harmadik csatorna). A szigorítás szerződés-kérdés, a PR-ben felvetve |
| 2.19 | az osztály-őrszem HÁROMSZOR volt vak, mindháromszor másképp | **ZÁRVA** (2026-09-16) — (1) a súgó SZÖVEGÉBŐL kereste az al-parancsokat; (2) javítva, de a KÖTELEZŐ kapcsolók nélkül hívott, így 23-ból 22 argparse-hibán állt meg, amit „rendben"-nek olvasott — ténylegesen EGYETLEN al-parancsot mért; (3) a parser-kereső minden callable attribútumot MEGHÍVOTT, és ezzel lefuttatta az `agent_bus.main()`-t. Mostantól (`test_belepo_pont_osztaly_20260916.py`): `_help()` alfolyamatban kérdezi az argparse-t (semmi import, semmi hívás), `_subcommands()` a `{a,b,c}` blokkból, `_file_slot()` és `_required_opts()` a SAJÁT `usage:` sorból, a nem fájl-alapú al-parancsok a `notfile` listán KIMONDVA, és a `TheSentryMustActuallyRun` ELŐFELTÉTEL-teszt köti, hogy legalább 4 al-parancs tényleg lefusson. A szabály élesebb alakja (`_names_it()`): nem az `rc=0` a lelet, hanem a NÉMA `rc=0` |
| 2.20 | a `rounds` SZŰRŐ maga a rés — négy mező, mind a támadó kezében | **ZÁRVA** (2026-09-16, SAJÁT kör: a ``-on kimondott 3. pontunk bizonyítása). A partner három szabadságfokot talált (kvantor `b66bac3`, sorrend `40396fc`, KI FELEL `0d300da`), és mindháromra kapu került. Az állításunk az volt, hogy a gyökér nem a kapuk hiánya, hanem hogy **az ellenőrzött fél írja a bizonyítékot szabad alakban** — és ezt meg is mértük: a `rounds` szűrő a `recipient`, `kind`, `decision` és a `cursor` TÍPUSA négyesen áll, és **mind a négy a támadó kezében van**. Bármelyiket elrontva a hazug kör kiesik a szűrőből, és a kemény `audit_skipped_contradicts_log` némán SOFT `audit_skip_unattributable`-re gyengül (dev-módban `ok=true` négy véglegesen elveszett üzenet fölött). A javítás NEM ötödik kapu, hanem különbségtétel (`round_shape_dodges_attribution`): ha az ack-ablakban NINCS bejegyzés, az tényleg nem mérhető (soft marad); ha VAN, de egyik sem kör-alakú, az nem a bizonyíték HIÁNYA, hanem a KIKERÜLÉSE — és az vád. Két kontrollal és mutáns-próbával (`test_joint_kvantor_valalas_20260916.TheShapeFilterWasTheFourthDegreeOfFreedom`) |
| 2.21 | az ÖTÖDIK szabadságfok: a kikerülés-detektor ablaka MAGA is önbevallott címkén állt | **ZÁRVA** — a `round_shape_dodges_attribution` ablaka (`_win`) a `kind != "ack"` CÍMKÉRE szűrt; a hazug kört `kind="ack"`-ra átcímkézve kiesett a `rounds`-ból, a `logged`-ból ÉS az ablakból is: néma soft, dev-módban rc=0 HAT véglegesen elveszett üzenet fölött, ép lánccal. A `kind` fehérlistázása NEM segít (ő mérte): az "ack" szabályos érték. Javítva az ő javaslatával: a kizárás a naplózott ack-ok SEQ-halmazán áll (`_ack_seqs`), nem a címkén. Mutáns-próbával (`test_joint_otodik_fok_20260916.py`). A tanulság kimondva: amíg az attribúció bemenete a vádlott ÍRÁSA, a szabadságfokok száma a mezők számával nő — a szerkezeti válasz a származtatás a busz sorából (hipotézis, még nem mérve) |
| 2.11 (LEZÁRVA) | a MÁSODIK NYILVÁNTARTÁS hiánya | **KIMONDOTT KORLÁT, nem lelet** — bizonyítva: a becsületes teljes kör és a hazug kör naplója a második nyilvántartás NÉLKÜL ALAKRA AZONOS (mérve: azonos `(kind, decision, cursor-kulcsok)` halmaz), tehát nincs olyan függvénye a naplónak, ami az egyiket jelöli, a másikat nem. A lezárás a `test_clamp_lied_with_audit_20260916.py`: ugyanaz a forgatókönyv `bus_audit`-tal, ott a vád kemény |
| 7.3 | azonos-uid (root) támadó mindkét nyilvántartást átírja | **NYITVA** — külső tanú (v1.7) |
| 7.4 | két gép, EGY szervezet | **NYITVA** — a két szervezetes élő próbához a partner gépe kell |

---

## Számok (2026-09-16)

- teszt-készlet: **468 passed, 1 skipped**, 3 deklarált nyitott szonda (a CI külön lépésben futtatja és kiírja őket);
- CI: **zöld egy harmadik gépen** (GitHub runner, hash-lockolt closure, nincs harmadik féltől származó action);
- élő, két gépes, **aláírt** próba: `reconcile --bus-audit --strict` → `ok: true, trusted: true`, 0 eltérés;
- a nem-Claude kar köreiből ~30 lelet: javítva vagy **méréssel cáfolva** — a cáfolatok is ki vannak írva.
