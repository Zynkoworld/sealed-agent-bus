# AgentBus v1.2 — gépek közti szállítás, SSE, csatolmányok, SCE-csatlakozás

**Dátum:** 2026-09-14 · **Protokoll:** 1.2.0 (MINOR) · **DB-séma:** 1.0.0 (változatlan)

A v1.1 a buszt egy gépen belül tette biztonságossá (szent gépelés, sleep-safe, operátori wake) és ráültette
a külső review három SDS-lépését. A v1.2 ugyanezt **gépek között** is elérhetővé teszi — úgy, hogy a hálózat semmit ne
gyengítsen abból, amit a helyi réteg garantál.

---

## 1. SSH-szállítás (`bus_ssh_exchange.py`, `bus_ssh_enroll.py`, `bus_ssh_client.py`)

**Mit csinál.** A távoli gép KIFELÉ SSH-zik a busz gépére. A busz-gépen a távoli kulcs az authorized_keys-ben egy
korlátozott sorhoz kötött, amely CSAK a csere-végpontot futtatja. Egy SSH-hívás egy atomi csere-kör: a kimenő
üzenetek (és csatolmány-darabok) stdin-en mennek, a várakozó válaszok stdout-on jönnek vissza.

**Miért így.** A júliusi SSH-bridge-ünk bevált mintája, általánosítva: a felhasználó gépén nem kell portot nyitni,
a titkosítást és a kulcsos hitelesítést az SSH adja, és nincs új, saját hálózati kód, amit meg kellene védeni.

**Fenyegetés → védelem**

| fenyegetés | védelem |
|---|---|
| a távoli fél más nevében ír | az identitás a `command=` argumentumából jön; a payload `from`/`sender` mezője figyelmen kívül |
| shell / port-forward a kulccsal | `restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc` |
| túlméretes bemenet (DoS) | stdin-plafon (`AGENT_BUS_SSH_MAX_BYTES`, alap 4 MB), ≤200 üzenet/kör, a busz 64 KB-os body-plafonja |
| hamis SDS-tartalom | a keretet a `send` ellenőrzi; az aláírást a fogadó `recv --verify-sds` útja — a válaszok `sds` címkét kapnak |
| elveszett válasz megszakadt SSH-nál | peek + következő körbeli `ack` (legalább-egyszer), a kliens a távoli id-re dedupol |
| a busz-gép kulcsa aláír egy távoli üzenetet | a végpont kikapcsolja az AUTO-SIGN-t; a hitelességet az SSH-kulcs és az SDS-aláírás adja |
| az eszköz átírja az sshd-t | az enroll CSAK sort ad / a megadott fájlba ír; hová kerül, operátori döntés |

## 2. Relay + SSE (`bus_relay.py`)

**Mit csinál.** Ha nincs közvetlen SSH (mindkét gép NAT mögött), egy relay közvetít: a feladó a címzett
nyilvános kulcsára titkosít, a relay csak az opak borítékot tárolja, a címzett **aláírt kéréssel** húzza le. Az
**SSE** (`/events`) csak annyit üzen, hogy „N boríték vár" — így a címzett azonnal lehúz, nem kell percenként kérdezni.

**Miért most kapott aláírt lehúzást.** A júliusi relay-ben a lehúzás nem volt hitelesítve: bárki lehúzhatta (és
ezzel elarchiválhatta) más sorát — a tartalom titkos maradt, de a kézbesítés megtagadható volt. **A külső review nyitott
HIGH-lelete a hálózati rétegen pontosan az ilyen réseket célozza; ezért a v1.2 relay-e aláírt lehúzással és
fail-closed indulással jön**, és addig nem javasoljuk élesre tenni, amíg a külső review ezt a réteget le nem mérte.

| fenyegetés | védelem |
|---|---|
| a relay olvassa a tartalmat | E2E: X25519 → HKDF-SHA256 → ChaCha20-Poly1305; a routing-mezők AAD (hitelesek, de nem titkosak) |
| nyílt szöveg a relay-en | `/deliver` csak a zárt sealed-boríték alakot fogadja |
| más húzza le a sorát | Ed25519-aláírt kérés a relay registry-jében lévő kulccsal |
| visszajátszott lehúzási kérés | célhoz kötött aláírás (`pickup` ≠ `events`), ±120 s ts-ablak, nonce-cache |
| SSE-n tartalom szivárog | az esemény csak darabszám |
| hamisított/módosított boríték | AEAD-ellenőrzés a címzettnél; hiba → kimarad (fail-closed) |
| crypto-könyvtár hiányzik | a relay nem indul (nincs nyílt szöveges tartalék) |

**Maradék kockázat (kimondva):** a nonce-cache memóriában él — relay-újraindítás után egy 120 s-on belüli kérés
egyszer visszajátszható (a boríték akkor is csak a jogos címzettnek visszafejthető); a relay nyilvános kitétele
TLS-t és proxy-oldali rate-limitet kíván — ez operátori döntés, a kód nem nyit portot magától; a statikus X25519
kulcsnak nincs forward secrecy-je (a júliusi modellel azonos, későbbi finomítás).

## 3. Csatolmányok (`bus_attach.py`)

**Mit csinál.** A nagy JSON / fájl a buszon kívül, tartalom-címzett tárban él (`<gyökér>/<hash[:2]>/<hash>`). A busz
`attachment` kindú üzenete csak a leírót viszi: `sha256`, `size`, `media_type`, `locator`. A leírót egy sds-envelope
rekordja is aláírhatja — így a nagy tartalom is bizonyítható.

**Miért így.** A busz koordinációra való; a 64 KB-os plafon szándékos és marad. A hash-es leíróval a tartalom
bárhonnan lehúzható, és a fogadó bájtra ellenőrzi.

| fenyegetés | védelem |
|---|---|
| módosított tartalom | `get()` sha256 + méret ellenőrzés; eltérés → hiba |
| felülírás | write-once; ugyanaz a hash = dedupe, a meglévőt újraellenőrzi |
| hibás / sorrenden kívüli darab | sorszám-kötés; a tárba csak a teljes hash-ellenőrzés után kerül; a hibás részt megőrzi vizsgálatra |
| törlés | nincs törlő API |

## 4. SCE-csatlakozás (`sce_hook.py`)

**Mit csinál.** Stabil pont, ahol a busz a karok sds-envelope-jait átadja egy operátor által bekötött döntőnek
(`AGENT_BUS_SCE_DECIDER=modul:függvény`), amely ACCEPT / REJECT / ABORT verdiktet ad.

**Miért csak csatlakozás.** A Silent Consensus Engine egy külön projektben él (három független implementáció
bájt-egyezése + érvényes leszármazás). A busz nem másolja és nem helyettesíti. Szándékosan nincs „konszenzus-erősség"
vagy jelentés-vektoros összeolvasztás: hasonló vélemények átlaga nem bizonyíték.

Nincs döntő → nincs döntés. Kivételt dobó, nem-dict vagy ismeretlen verdiktet adó döntő → ABORT.

---

## Amit szándékosan nem építettünk be

- **ICE / WebRTC.** Két NAT mögötti gép közvetlen kapcsolatához STUN/TURN szerverek és nagy, nem-stdlib könyvtárak
  kellenének. A kifelé irányuló SSH (és szükség esetén a vak relay) ugyanezt megoldja, kisebb támadási felülettel.

## Mérve

- `python3 -m pytest -q` → **91 passed** (v1.1: 60, v1.2 új: 31 — SSH 11, relay 9, csatolmány 7, SCE-hook 4).
- A hálózati tesztek csak `127.0.0.1`-en futnak; az SSH-tesztek helyi „hamis ssh"-val hívják a végpontot, valódi
  hostra nem csatlakoznak.

## Nincs benne / következő lépések

- Éles bekötés (dedikált SSH-fiók, authorized_keys helye, relay TLS mögé tétele) — operátori kapu.
- A relay nonce-cache perzisztenciája és a forward secrecy (efemer kulcsok).
- A külső SCE-motorhoz egy adapter (`modul:decide`) — a motor oldalán.
