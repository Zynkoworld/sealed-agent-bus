# Élő, két gépes mérés — AgentBus v1.5 SSH-csere + közjegyzői napló

**Dátum:** 2026-09-16 · **Mérte:** a belső mérő-kar · **Státusz:** mérés, nem jóváhagyás

Ez a v1.5 utolsó nyitott terméktétele volt: minden korábbi szám egy gépen, helyi `ssh`-hamisítvánnyal
készült. Itt **két valódi gép** cserélt postát **valódi SSH-n**, és a bizonyíték-láncot utólag
összevetettük.

## Elrendezés

| | gép A (kliens) | gép B (busz-végpont) |
|---|---|---|
| szerep | `gép-A` — a kérést indítja | `gép-B` — a buszt tartja, válaszol |
| hálózat | privát szegmens, valódi `ssh -T` | ugyanaz |
| adatok | **külön, ideiglenes** busz-DB és napló (`/tmp/...`) | ugyanígy (`/tmp/abus_live2`) |
| mód | dev (lásd „Kimondott korlát") | dev |

**A termelő buszhoz egyik oldalon sem nyúltunk:** minden út `/tmp` alá mutatott, külön DB-vel,
külön közjegyzői naplóval. Semmit nem töröltünk.

## Amit mértünk

| kör | mit tett | idő | eredmény |
|---|---|---|---|
| 1 | 3 üzenet `gép-A` → `gép-B-teszt` | **1,78 s** | mindhárom elfogadva; napló-horgony `seq=3`; a túloldali postafiókban mérve 3 |
| 2 | üres kérés; a az egyik kar közben válaszolt | **0,83 s** | **1 válasz visszaérkezett**; horgony `seq=5` |
| 3 | ack-kör | **0,68 s** | horgony `seq=7` |

A távoli napló a kör végén **7 bejegyzés**: `msg/accepted` (a bejövő posta), `pickup/accepted` (a kör
gépi kurzor-mezővel), `pickup/delivered` (a kiadott válasz), `ack/accepted` (a kurzor-lépés).

## A bizonyíték-lánc összevetése (ez a lényeg)

A kliens nyugta-fájlját (`ssh_gépA__gépA.receipts.jsonl`, 6 sor), a busz-gép közjegyzői naplóját
(7 bejegyzés) és a busz **saját**, hash-láncolt `cursor_audit` exportját (2 sor) egymáshoz mértük:

```
bus_notary reconcile <távoli napló> --identity az egyik kar --receipts <nyugták> --bus-audit <busz-audit>
-> ok: true, verify_ok: true, discrepancies: [], unresolved: []
   counts: entries 7 · sent 3 · received 1 · acks_sent 1 · delivered_logged 1
```

Minden szám egyezik a ténylegesen elküldött/megkapott/ackolt darabszámmal.

## Hamisítás-próbák ugyanezen az ÉLŐ adaton

| próba | mit csináltunk | mit mondott az összevetés |
|---|---|---|
| kiadás eltüntetése | kitöröltük a `pickup/delivered` bejegyzést a naplóból | **`received_not_logged`** (hard) + `round_replies_mismatch` (soft), `verify_ok:false` |
| ack átírása | a `cursor 0->1 (ack 1)` sort `cursor 0->99 (ack 99)`-re írtuk | **`cursor_reason_mismatch`** (hard), `verify_ok:false` |

Vagyis a napló **nem** tudja letagadni a kiadást, és **nem** tud nagyobb kurzor-lépést állítani, mint
amit a saját bejegyzései és a fél nyugtái alátámasztanak — élő adaton is.

## Kimondott korlátok

1. **A mérés dev-módban futott, mert a `cryptography` csomag a gép-B-n NINCS telepítve.** Ezért a
   távoli oldal nem írt **aláírt ellenőrzőpontot**, és az összevetés `trusted:false` — a hash-lánc
   konzisztens, de aláírás nem köti. A termék-módú, aláírt élő próbához a csomag telepítése kell a
   gép-B-re: **operátori döntés**, nem a mi egyoldalú lépésünk.
2. **Nincs force-command a mérésben.** A végpontot a meglévő root-SSH-val hívtuk meg közvetlenül. A
   force-command biztonsági szerepét a Matesensei-oldal külön, valódi `sshd`-vel már mérte (PR ):
   tetszőleges parancs, port-forward, PTY, agent-forward mind elutasítva. Az élesítéshez a
   `bus_ssh_enroll.py` szerinti `authorized_keys` sor kell — szintén operátori lépés.
3. **Két gép, egy szervezet.** Mindkét gépet mi üzemeltetjük, tehát ez **szállítási** bizonyíték, nem
   „két, egymásban nem bízó fél" bizonyítéka. Az utóbbihoz a gép kell (a publikus
   kulcsukat a szálán elküldték).
4. A mérés egyszeri; nincs CI, ami újrafuttatná.

## Reprodukció

A parancsok és a munkakönyvtárak a mérés idején: kliens oldal `/tmp/live94_*`, busz oldal
`/tmp/abus_live2` (mindkettő megmaradt, semmit nem töröltünk). A modulok bájtazonos másolatai a
`dev/v1.5-notary` ág aktuális fejéről kerültek a túloldalra.

---

## Újramérés a NAP VÉGI kóddal (2026-09-16 este, második gép)

**Miért:** a fenti mérés a délelőtti fejen készült. Aznap a csere- és összevetés-út sokat változott
(kör-záró horgony, alak-kapu, fail-closed mentőcsónak, `strict_ack_unknown`, partial-verify). Egy termék-állítás
nem alapulhat azon, hogy „a tesztek zöldek" — a változtatásokat ugyanazon a felületen kell újramérni, amin az
eredeti állítás született.

**Elrendezés:** ugyanaz az elv — **két valódi gép, valódi `ssh -T`**, minden út `/tmp` alatt (`/tmp/abus_live3`),
külön busz-DB, külön közjegyzői napló, külön kulcs. A termelő buszhoz egyik oldalon sem nyúltunk, és a mérés
végén a távoli munkakönyvtár **törölve**.

| kör | mit tett | idő |
|---|---|---|
| 1 | 3 üzenet `gép-A` → `gép-B-teszt` | **0,63 s** |
| 2 | üres kérés; a túloldal közben válaszolt | **0,65 s** |
| 3 | ack-kör | **0,55 s** |

**A távoli napló 9 bejegyzés, 9 aláírt ellenőrzőponttal** (`AGENT_BUS_NOTARY_EVERY=1`), és benne a MAI
mechanizmus is látszik élesben:

```
 4 pickup       accepted   {"at": 0, "audit_hash": "000…0", "audit_seq": 0, "closes": 1, …}
 5 pickup       delivered  {"id": 4}
 6 round_close  accepted   {"at": 0, "audit_end_hash": "f75c2a…", "audit_end_seq": …, "round_seq": 4}
 7 ack          accepted   {"ack": 4, "from": 0, "to": 4}
 8 pickup       accepted   {"at": 4, "audit_hash": "6ce840…", "closes": 1, …}
 9 round_close  accepted   {"at": 4, "audit_end_hash": "6ce840…", "round_seq": 8}
```

**Összevetés (strict, két nyilvántartással, aláírás-ellenőrzéssel):**

```
ok=True | verify_ok=True | trusted=True
eltérés: []            harmadik állapot: []
számlálók: {'entries': 9, 'sent': 3, 'received': 1, 'acks_sent': 1, 'delivered_logged': 1,
            'rounds_pledged': 2, 'rounds_unclosed': 0, 'strict_ack_unknown': 0, 'chain_unverifiable': 0}
```

**Amit ez bizonyít:** a mai változtatások élő, két gépes úton is működnek — a kör-záró horgony megszületik és
párosul (`rounds_pledged: 2, rounds_unclosed: 0`), a harmadik állapotok számlálói nullák, és az aláírt
ellenőrzőpontokkal a szelet `trusted`.

**Amit NEM bizonyít (kimondva):** ez továbbra is **egykarú** mérés — mindkét oldal a mi kódunk. A két-karú
bájt-egyezés a B-kar futásával születik meg, nem ezzel. A mérés dev-módban futott (a termék-mód root-tulajdonú
kulcs-registryt kíván, ami ezen a gépen nincs), és a `trusted` az ellenőrzőpontok miatt igaz — 9 bejegyzésre
9 ellenőrzőponttal; a default (50) mellett egyetlen ellenőrzőpont sem esne bele, és akkor a `trusted` HELYESEN
`false` (ezt külön megmértük: `trusted=False`, mert nincs mit aláírva ellenőrizni).
