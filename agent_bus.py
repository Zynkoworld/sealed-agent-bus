#!/usr/bin/env python3
"""agent_bus — AgentBus P0: append-only, rendezett, auditált üzenetbusz az agentek közt (SQLite WAL).

A fájl-inbox late-delivery problémájának transport-rétege (lásd docs/architecture/AGENT_BUS_DESIGN.md).
EGY `bus.db` (WAL): rendezett (monoton id), atomikus, kereshető — a 'chat' = a saját kurzor utáni üzenetek.
NINCS TÖRLÉS: sosem DELETE; az 'olvasott' = read_at; a kurzor jelzi hol tart az agent. ADDITÍV: a `send`
a régi JSON-inboxba IS tükröz (back-compat, amíg minden agent átáll). Stdlib-only, self-contained, never-throw a CLI-n.

CLI:
  agent_bus.py init
  agent_bus.py send --from X --to Y --topic T --kind K [--thread TID] [--reply ID] [--sign-key PATH] --body "..."
  agent_bus.py recv --agent X [--mark] [--verify-sds [--strict-sds] [--sds-admission PATH]]
                                                  # olvasatlanok (id>kurzor); --mark: kurzor előre + read_at
                                                  # v1.1: sds-envelope sorok ellenőrzése (valid|invalid|unsigned|unverifiable)
  agent_bus.py tail --agent X [--limit N]        # legutóbbi üzenetek (neki vagy tőle)
  agent_bus.py thread --id TID                    # egy szál időrendben
  agent_bus.py ack --agent X --upto ID           # kurzor előre (olvasottnak jelöl ID-ig)
  agent_bus.py verify [--json]                    # divergencia-őr: a DB egyezik-e a befagyasztott sémával
"""
from __future__ import annotations
import argparse, hashlib, json, os, sqlite3, stat, sys, time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))  # site root; every default hangs off it
DB = os.environ.get("AGENT_BUS_DB", os.path.join(BRIDGE, "bus.db"))
INBOX_ROOT = os.environ.get("AGENT_BRIDGE_INBOX", os.path.join(BRIDGE, "inbox"))  # back-compat JSON-tükör
KEYS_DIR = os.environ.get("AGENT_BUS_KEYS_DIR", os.path.join(BRIDGE, "keys"))     # A2: identity↔pubkey registry
_IMPORT_DB, _IMPORT_INBOX = DB, INBOX_ROOT                     # amit IMPORT-kor láttunk (a patch-elés felismeréséhez)


def _db_path():
    """A busz DB útja HÍVÁS-időben. A modul-szintű út import-időben fagyott be, ezért aki a modult előbb
    importálta és csak utána állította az env-et (tipikus in-process mérés), annál minden `db=None`-os hívás a
    BEÉGETETT alapértelmezett DB-re ment — egy éles gépen ez a TERMELŐ buszra írt volna egy pusztán mérésnek
    szánt hívásból. Szabály: az explicit monkeypatch (ab.DB = ...) nyer, egyébként az env a mérvadó."""
    return DB if DB != _IMPORT_DB else os.environ.get("AGENT_BUS_DB", DB)


def _inbox_root():
    return INBOX_ROOT if INBOX_ROOT != _IMPORT_INBOX else os.environ.get("AGENT_BRIDGE_INBOX", INBOX_ROOT)


def reload_paths():
    """A modul-szintű utak ÚJRAOLVASÁSA a környezetből (mérő-kódnak, ha az env az import után állt be)."""
    global DB, INBOX_ROOT, KEYS_DIR
    DB = os.environ.get("AGENT_BUS_DB", _IMPORT_DB)
    INBOX_ROOT = os.environ.get("AGENT_BRIDGE_INBOX", _IMPORT_INBOX)
    KEYS_DIR = os.environ.get("AGENT_BUS_KEYS_DIR", KEYS_DIR)
    return {"DB": DB, "INBOX_ROOT": INBOX_ROOT, "KEYS_DIR": KEYS_DIR}

# ── FROZEN WIRE CONTRACT v1.0.0 ──────────────────────
# A vendorolt kliensek ERRE támaszkodnak; a séma a II-fúzióig befagyasztva.
# Változtatás CSAK additív/back-compat (új nullable oszlop, új kind/topic-érték, új CLI) → minor bump.
# Oszlop átnevezése/törlése/újratípusozása, id-monotonitás, a thread_id-default, a read_at/kurzor-szemantika
# vagy a JSON-tükör kulcsai megtörése = MAJOR, és mindkét operátor jóváhagyása kell.
# Teljes kontraktus: docs/architecture/AGENT_BUS_SCHEMA.md
SCHEMA_VERSION = "1.0.0"
# v1.1 (2026-09-14): PROTOKOLL-verzió (kind-vokabulár + CLI), KÜLÖN a DB-séma pinjétől. Az új kindok (sds-envelope,
# operator-wake, operator-sleep-safe) és az új recv-kapcsolók additívak (MINOR). A DB SCHEMA_VERSION SZÁNDÉKOSAN
# marad 1.0.0: a séma nem változott, és a verify a pin-eltérést DRIFT-nek jelzi — egy bump minden élő DB-t pirosra vinne.
# v1.2 (2026-09-14): gépek közti szállítás (bus_ssh_*, bus_relay), csatolmány-leíró kind (`attachment`), SCE-csatlakozási
# pont (sce_hook). Additív → MINOR; a DB-séma továbbra sem változik (SCHEMA_VERSION marad 1.0.0).
# v1.4.0: KIKÉNYSZERÍTÉS (bus_enforce): termék-mód (AGENT_BUS_MODE=product / .product_mode.on) → a recv ELUTASÍTJA az
# aláíratlan/hamis/elavult/visszajátszott sort; a seen-tár külön append-only fájl → a DB-séma NEM változik; a default
# (dev) viselkedés bájtra a régi. Additív → MINOR.
PROTOCOL_VERSION = "1.5.0"
SDS_KIND = "sds-envelope"
ATTACH_KIND = "attachment"
MESSAGE_COLUMNS = ("id", "ts", "sender", "recipient", "topic", "kind",
                   "thread_id", "in_reply_to", "body", "read_at",
                   "sig", "pubkey")                                         # befagyasztva: rend+név; A2: sig/pubkey append-only (nullable)
CURSOR_COLUMNS = ("agent", "last_seen_id")                                  # befagyasztva
JSON_MIRROR_KEYS = ("from", "to", "kind", "topic", "note", "ts", "bus_id")  # +opc. "in_reply_to"

_MAX_BODY = 64 * 1024                                            # D#1: AgentBus = KOORDINÁCIÓ (I2) → body felső méret (mint a ledger)
_MAX_FIELD = 4096                                               # R3-D#1: a body-cap-ot megkerülő mező-DoS ellen (sender/recipient/topic/kind/thread_id is kapot kap)
_RECV_LIMIT = 500                                               # D#2: recv lapozás (a 'minden olvasatlan memóriába' DoS ellen)
_CLOCK_SKEW_S = 300                                             # a korhatárnál megengedett óra-csúszás
_SQLITE_INT_MAX = 2 ** 63 - 1                                   # R3-I#3: a sqlite 8-bájtos signed INTEGER felső határa

# C4: a divergencia-őr a TÍPUST/NOTNULL/PK-t is nézi (nem csak a nevet) — (name, type.upper(), notnull, pk).
_FROZEN_MESSAGES = (("id", "INTEGER", 0, 1), ("ts", "INTEGER", 1, 0), ("sender", "TEXT", 1, 0),
                    ("recipient", "TEXT", 1, 0), ("topic", "TEXT", 0, 0), ("kind", "TEXT", 0, 0),
                    ("thread_id", "TEXT", 0, 0), ("in_reply_to", "INTEGER", 0, 0),
                    ("body", "TEXT", 1, 0), ("read_at", "INTEGER", 0, 0))
_FROZEN_CURSORS = (("agent", "TEXT", 0, 1), ("last_seen_id", "INTEGER", 1, 0))


def _safe_name(s):
    """Fájlrendszer-biztos NÉV-komponens. CSAK ASCII [A-Za-z0-9._-]; minden más → '-'; '', '.', '..' → 'x'.
    R2-A1: ha a nyers input >64 VAGY nem-ASCII → rövid hash-utótag — különben két KÜLÖNBÖZŐ recipient/sender
    ugyanarra a fájl/dir-névre csonkolhatna, vagy unicode-homoglyph ütközhetne (cross-recipient szivárgás/spoof).
    B1: a hash-utótag akkor is kell, ha BÁRMELY karaktert sanitizáltunk ('safe != raw') —
    különben rövid ASCII speciális-karakteres nevek ütköznek (pl. 'a/b' és 'a-b' egyaránt 'a-b'-re mappel)."""
    import string, hashlib
    raw = s or ""
    safe = "".join(ch if ch in (string.ascii_letters + string.digits + "._-") else "-" for ch in raw)
    if len(safe) > 64 or any(ord(ch) > 127 for ch in raw) or safe != raw:   # csonkolás / nem-ASCII / BÁRMELY sanitizált char (B1: injektív) → ütközés-rezisztens utótag
        safe = safe[:48] + "~" + hashlib.sha1(raw.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    safe = safe[:64]
    return safe if safe and safe not in (".", "..") else "x"


def _conn(db=None):
    path = db or _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA wal_autocheckpoint=256")               # R2-B#2: a -wal ne nőjön korlátlanul (checkpoint-starvation DoS)
    c.execute("PRAGMA journal_size_limit=%d" % (16 * 1024 * 1024))  # checkpoint után truncate vissza
    c.row_factory = sqlite3.Row
    return c


# A1-L1: kurzor-mozgás audit (append-only, HASH-LÁNCOLT, ÉSZLELÉS). ADDITÍV/belső observability — NEM wire-kontraktus
# (a vendorolt kliensek nem építenek rá), ezért NEM jár SCHEMA_VERSION-bumppal; a frozen messages/cursors/meta/JSON-tükör érintetlen.
# A per-agent hash-lánc (prev_row_hash, a kurzor-mozgással EGY SQLite-tranzakcióban) a TANÚSÍTHATÓ SZUBSZTRÁTUM: elkapja a
# baleseti + naiv/inkonzisztens babrálást. RECALIBRÁCIÓ: a lokális FILE-HORGONY HALASZTVA — egy
# determinált azonos-uid (root) támadó a láncot ÉS a lokális horgonyt is konzisztensen átírná, így a horgony tamper-evidens
# értéke CSAK külső tanú (vendor-aláírt off-box / remote tier) mellett valós; oda kerül (sign_audit_head-minta, gated).
_GENESIS = "0" * 64
_AUDIT_DDL = ("CREATE TABLE IF NOT EXISTS cursor_audit("
              "id INTEGER PRIMARY KEY AUTOINCREMENT, seq INTEGER NOT NULL, ts INTEGER NOT NULL, agent TEXT NOT NULL, "
              "from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, op TEXT NOT NULL, "
              "skipped_undelivered INTEGER NOT NULL DEFAULT 0, prev_row_hash TEXT NOT NULL, row_hash TEXT NOT NULL)")


def _canonical(obj):
    """Kanonikus JSON a hash-eléshez: rendezett kulcs, tömör, allow_nan=False (a Kernel core/hashing.py:canonical mintája, K-46)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


# ── A2: feladó-autentikáció (anti-spoof, Ed25519) ────────────────────────────────────────────────
# A red-team A2-lyuk zárása: a `send(sender, …)` eddig VAKON megbízott a sender-stringben → bárki lokális
# hívó bármelyik agentnek adhatta ki magát. Most a feladó OPCIONÁLISAN aláírja a tartalmat (Ed25519,
# aszimmetrikus+determinista), a vevő pedig a root-tulajdonú registry-pubkey ellen verifikál.
# Tervjavaslat + referencia (az egyik kar): docs/security/agentbus-a2-sender-authentication.md + a2_ref.py.
# Az aláírt bájtkép a `_canonical`-lal készül = BYTE-AZONOS az a2_ref `<our engine>.determinism.canonical`-jával
# (igazolt). FROZEN: a `thread_id` KI van zárva az aláírt mezőkből (szerver-derivált; a sender
# threading-SZÁNDÉKÁT az aláírt `in_reply_to` hordozza) → feloldja a root csirke-tojást. signed-shape v:2.
# ADDITÍV: aláírás ha sign_key adott, VAGY (auto-sign) ha a sender guard-olt default seed-fájlja létezik a
# registry-ben (keys/<sender>.ed25519.key) — opt-out: AGENT_BUS_AUTO_SIGN=0. Kulcs nélküli küldők VÁLTOZATLANOK.
# strict CSAK ha AGENT_BUS_REQUIRE_SIG=1 (default OFF). NINCS SCHEMA_VERSION-bump (a delivered_id mintára).
_A2_ALG = "ed25519"
#: A FROZEN MEZŐKÉSZLET (thread_id KIZÁRVA — szerver-derivált). Ez a HALMAZ kötött, NEM a sorrend: az
#: aláírt bájtképben a kulcsok ALFABETIKUS sorrendben állnak (sort_keys), nem ebben a sorrendben.
#: A korábbi "FROZEN sorrend" komment félrevezető volt — egy újraimplementáló ezt a tuple-sorrendet
#: másolhatta volna a szerializálásba, és néma divergenciát kap. Mérve: a bájtkép sorrendje
#: body, in_reply_to, kind, recipient, sender, topic, ts, v.
_A2_SIGNED_FIELDS = ("v", "sender", "recipient", "topic", "kind", "in_reply_to", "body", "ts")
try:
    from cryptography.hazmat.primitives import serialization as _a2_ser
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _a2_ed
    _A2_HAVE = True
    _A2_RAW_ENC, _A2_RAW_PUB = _a2_ser.Encoding.Raw, _a2_ser.PublicFormat.Raw
except Exception:                                                # pragma: no cover - környezet-függő
    _A2_HAVE = False


def canonical_text_field(value):
    """Egy ALÁÍRT szöveges mező (topic, kind, body) kanonikus értéke. EGY forrás, mindenki ezt hívja.

    MIÉRT NYILVÁNOS. Ugyanezt a szabályt eddig HÁROM hely valósította meg külön: a bájtkép-építő
    (`_a2_content_bytes`), a kliens-aláíró (`sign_for_send`) és a gépek közti bejövő út
    (`bus_ssh_exchange`). Mérve, ahogy a három alakot kezelték:

        alak            kanonikus      bejövő út (régi)
        kind elhagyva   ""             "msg"
        kind = ""       ""             "msg"
        kind = null     ""             "msg"
        kind = "msg"    "msg"          "msg"

    Vagyis egy SPEC szerint számoló partner aláírása a négy alakból HÁROMBAN megbukott a
    bejövő úton — és nem „csendben": a busz `presigned: signature does not verify (forged or
    tampered)`-rel utasította el, tehát egy tisztességes partnert HAMISÍTÁSSAL vádolt meg.

    A javítás nem a szabály átmásolása egy harmadik helyre volt, hanem ez a függvény: aki az
    aláírt bájtkép egy mezőjét állítja elő, ezt hívja. Ha a szabály változik, egy helyen változik."""
    return "" if value is None else str(value) if value else ""


def _signed_integer(name, value, *, allow_none=False):
    """Egy ALÁÍRT egész mező (ts, in_reply_to) ellenőrzött értéke. Nem-egész → érthető hiba, nem néma bájtkép.

    MIÉRT FAIL-CLOSED. A spec a `ts`-t EGÉSZNEK írja elő, a kanonizáló viszont nem volt típus-ellenőrző:
    mérve `ts=1.5` → `"ts":1.5`, `ts=True` → `"ts":true`, `ts="123"` → `"ts":"123"`. Mindhárom olyan
    bájtképet ad, ami a SAJÁT specünk szerint érvénytelen — és aláírható. A hívó nem kap jelzést; a partner
    oldalán lesz belőle megmagyarázhatatlan verify-bukás vagy egy `true` egy egész mezőben.

    A `bool` KÜLÖN ki van zárva, pedig Pythonban az `int` leszármazottja: a `True` egész értéke 1, de a
    JSON-ban `true`-ként íródik ki — épp az a néma alakváltás, amit ez az őr megfog."""
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("signed shape: '%s' must be an integer (got %s) — a non-integer would sign a "
                         "byte image this spec calls invalid" % (name, type(value).__name__))
    return value


def _a2_content_bytes(msg):
    """Az aláírt tartalom kanonikus bájtképe (id KIZÁRVA — DB osztja insert-kor; thread_id KIZÁRVA — szerver-derivált). A hiányzó opcionális mezők None/""-re esnek, hogy a feladó és a verifikáló kicsit eltérő dict-ből is
    UGYANAZT a bájtképet építse. `v:2` = signed-shape verzió (≠ DB SCHEMA_VERSION)."""
    content = {
        "v": 2,
        "sender": msg.get("sender"),
        "recipient": msg.get("recipient"),
        "topic": canonical_text_field(msg.get("topic")),
        "kind": canonical_text_field(msg.get("kind")),
        "in_reply_to": _signed_integer("in_reply_to", msg.get("in_reply_to"), allow_none=True),
        "body": canonical_text_field(msg.get("body")),
        "ts": _signed_integer("ts", msg.get("ts")),
    }
    return _canonical(content).encode("utf-8")                   # == the reference engine's determinism.canonical(content) (igazolt byte-eq)


def _a2_sign(seed, msg):
    """A tartalom aláírása 32-bájtos Ed25519 privát seeddel → {alg, sig, pubkey} (a pubkey utazik, hogy a registry-birtokos verifikálhasson)."""
    if not _A2_HAVE:
        raise RuntimeError("ed25519 requires the 'cryptography' package")
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    priv = _a2_ed.Ed25519PrivateKey.from_private_bytes(seed)
    sig = priv.sign(_a2_content_bytes(msg))
    pub = priv.public_key().public_bytes(_A2_RAW_ENC, _A2_RAW_PUB)
    return {"alg": _A2_ALG, "sig": sig.hex(), "pubkey": pub.hex()}


def _a2_guarded_read(path):
    """Registry-kulcsfájl olvasása CSAK ha a fájl ÉS a dir-je root-tulajdonú és nem csoport/világ-írható — ez a
    PONTOSAN UGYANAZ a bizalmi guard, mint amit az `agent_bus_watcher.is_armed` használ a wake arm-flagre. Visszaad:
    a strippelt hex, vagy None ha a guard bukik / a fájl hiányzik."""
    # Saját a `stat` és az `open` KÉT külön művelet volt — a köztes pillanatban a fájl (vagy egy
    # symlink a helyén) kicserélhető, és a guard a RÉGI fájlt ellenőrizte, az olvasás az ÚJAT kapta. Ezért: egyetlen
    # megnyitás O_NOFOLLOW-val (a végső komponens nem lehet symlink), és a jogosultság-ellenőrzés a MEGNYITOTT fd-n.
    try:
        dst = os.stat(os.path.dirname(path))
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or (st.st_mode & 0o022) or dst.st_uid != 0 or (dst.st_mode & 0o022):
            return None
        with os.fdopen(fd, encoding="utf-8") as f:
            fd = -1                                              # a fájl-objektum vette át a fd tulajdonjogát
            return f.read().strip()
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _a2_load_registry_pubkey(agent, keys_dir):
    """A bizalmi horgony: az `agent`-hez kötött registry-pubkey, vagy None ha nincs regisztrálva / bukik a guard.
    Az `agent` basename-szanitizált, hogy egy ügyeskedett név ne törhessen ki a `keys_dir`-ből."""
    safe = os.path.basename(agent)                               # se '/', se '..' traversal
    if not safe or safe in (".", ".."):
        return None
    return _a2_guarded_read(os.path.join(keys_dir, "%s.pub" % safe))


def _a2_auto_sign_enabled():
    """AUTO-SIGN opt-out kapcsoló: AGENT_BUS_AUTO_SIGN=0/false/no/off → OFF; minden más (a default is) → ON."""
    return os.environ.get("AGENT_BUS_AUTO_SIGN", "").strip().lower() not in ("0", "false", "no", "off")


def _a2_default_sign_key(sender, keys_dir=None):
    """A sender default privát seed-fájlának útja (keys/<sender>.ed25519.key), vagy None ha nincs / bukik a guard.
    Guard: a seed-fájl root-tulajdonú és SZIGORÚAN privát (0600 — se csoport, se világ bit), a dir root-tulajdonú
    és nem csoport/világ-írható. A sender basename-szanitizált (traversal ellen). A guard bukása → None (a küldés
    aláíratlanul megy tovább, ahogy eddig) — az auto-sign kényelmi réteg, nem enforcement (az a strict mód)."""
    if keys_dir is None:
        keys_dir = KEYS_DIR
    safe = os.path.basename(sender or "")
    if not safe or safe in (".", ".."):
        return None
    path = os.path.join(keys_dir, "%s.ed25519.key" % safe)
    try:                                                         # symlink a seed helyén: a guard megkerülhető lenne
        st = os.lstat(path)                                      # (ez az ág csak UTAT ad vissza, fd-t nem)
        dst = os.stat(os.path.dirname(path))
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o077) \
            or dst.st_uid != 0 or (dst.st_mode & 0o022):
        return None
    return path


def verify_sender(msg, keys_dir=None):
    """Egy beérkezett (recv-elt) üzenet hitelességének osztályozása a registry ellen:
      - "unsigned" — nincs aláírás ÉS a registry a sender-hez NEM köt kulcsot (back-compat út; NEM hamisítás).
      - "unsigned-pinned" — nincs aláírás, de a registry a deklarált sender-hez kulcsot KÖT: a név egy aláírásra
                     képes feléé, a sor mégis csupasz. NEM bizonyított hamisítás (a back-compat út legális), de
                     nem is olvad bele a névtelen `unsigned`-ba — (2026-09-17): egy 100%-ban aláíró
                     feladó nevében érkező csupasz sor addig csak EMBERI/statisztikai
                     észlelés volt, gépi kapu nélkül. Ez az osztály a gépi kapu bemenete (strict/product mód).
      - "forged"   — van aláírás, de érvénytelen, VAGY a pubkey NEM az, amit a registry a deklarált sender-hez köt (impersonation).
      - "signed"   — érvényes aláírás a `msg['sender']`-hez tartozó registry-kulccsal.
    A `sig`/`pubkey`-t közvetlenül a recv-elt `msg`-ből olvassa (a recv beleteszi az oszlopokból).
    A `keys_dir` None esetén a MODUL-szintű KEYS_DIR-re old fel FUTÁSIDŐBEN (nem definíció-időben) — így a
    deploy a live értéket, a teszt a monkeypatch-elt értéket látja."""
    if keys_dir is None:
        keys_dir = KEYS_DIR
    sig_hex = msg.get("sig")
    if not sig_hex:
        if _A2_HAVE and _a2_load_registry_pubkey(msg.get("sender", ""), keys_dir) is not None:
            return "unsigned-pinned"
        return "unsigned"
    if not _A2_HAVE:
        return "forged"
    pub_hex = msg.get("pubkey") or ""
    expect = _a2_load_registry_pubkey(msg.get("sender", ""), keys_dir)
    if expect is None or pub_hex != expect:                      # ismeretlen sender vagy kulcs-eltérés
        return "forged"
    try:
        pub = _a2_ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), _a2_content_bytes(msg))
        return "signed"
    except Exception:
        return "forged"


_REQUIRE_SIG_MARKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".require_sig.on")


def _a2_strict():
    """Opt-in strict mód: a recv MEGJELÖLI (auth) minden sor feladó-hitelességét (annotál, NEM dob el).
    Bekapcsolható AGENT_BUS_REQUIRE_SIG=1/true/yes/on env-varral VAGY a fleet-wide, reverzibilis
    `.require_sig.on` marker-fájllal (rm a markert = kikapcsol). Default OFF (env üres + nincs marker)."""
    if os.environ.get("AGENT_BUS_REQUIRE_SIG", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return os.path.exists(_REQUIRE_SIG_MARKER)


def _audit_row_hash(seq, ts, agent, op, from_id, to_id, skipped, prev_hash):
    content = {"seq": seq, "ts": ts, "agent": agent, "op": op, "from_id": from_id,
               "to_id": to_id, "skipped_undelivered": skipped, "prev_row_hash": prev_hash}
    return hashlib.sha256(_canonical(content).encode("utf-8")).hexdigest()


def _append_audit(c, agent, from_id, to_id, op, skipped):
    """Egy HASH-LÁNCOLT cursor_audit sort fűz a HÍVÓ tranzakciójában (→ atomi a kurzor-mozgással, nincs TOCTOU; Q1).
    Per-agent lánc: prev = az agent utolsó row_hash-e (genesis ha első). A row_hash a (prev_row_hash + tartalom) felett → bármely sor törlése/átírása lánc-törést/hash-eltérést ad (audit_verify)."""
    ts = time.time_ns()
    prev_row = c.execute("SELECT seq,row_hash FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT 1", (agent,)).fetchone()
    # fix: ha az utolsó sor LEGACY (pre-chain, row_hash IS NULL a nem-üres migrációból) → friss lánc-kezdet
    # GENESIS-ből (a NULL-okra nem láncolunk). Csak ha az utolsó sor MÁR láncolt (row_hash NOT NULL), folytatjuk.
    if prev_row and prev_row["row_hash"] is not None:
        seq = prev_row["seq"] + 1
        prev = prev_row["row_hash"]
    else:
        seq = 0
        prev = _GENESIS
    rh = _audit_row_hash(seq, ts, agent, op, from_id, to_id, skipped, prev)
    c.execute("INSERT INTO cursor_audit(seq,ts,agent,from_id,to_id,op,skipped_undelivered,prev_row_hash,row_hash) "
              "VALUES(?,?,?,?,?,?,?,?,?)", (seq, ts, agent, from_id, to_id, op, skipped, prev, rh))


def init(db=None):
    c = _conn(db)
    try:
        # R2-B#3: ha a séma MÁR megvan, NE nyiss write-tranzakciót minden hívásnál → a read-only ops (tail/thread/recv)
        # ne kontendáljanak egy hosszú íróval. (Az INSERT OR IGNORE write-txn volt a fő contention-forrás.)
        primed = False
        try:
            primed = bool(c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone())
        except sqlite3.OperationalError:
            pass                                             # a meta tábla még nincs → teljes init kell
        if not primed:
            _init_schema(c)
        # A1-L1 additív migráció (cursor_audit hash-lánc). CSAK akkor nyit write-txn-t, ha tényleg hiányzik/régi a tábla
        # (a létezés/oszlop-checkek olvasások → nincs write-contention a meglévő esetben).
        have_audit = bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cursor_audit'").fetchone())
        chained = have_audit and "row_hash" in {r[1] for r in c.execute("PRAGMA table_info(cursor_audit)")}
        if (not have_audit) or (not chained):
            with c:
                if not have_audit:
                    c.execute(_AUDIT_DDL)
                elif c.execute("SELECT COUNT(*) FROM cursor_audit").fetchone()[0] == 0:
                    # régi (lánc nélküli), ÜRES cursor_audit → újragyártás (belső observability, no-deletion ok)
                    c.execute("DROP TABLE cursor_audit")
                    c.execute(_AUDIT_DDL)
                else:
                    # nem-üres régi tábla → additív nullable hash-oszlopok (a régi sorok lánc-előttiek)
                    for _col in ("seq INTEGER", "prev_row_hash TEXT", "row_hash TEXT"):
                        c.execute("ALTER TABLE cursor_audit ADD COLUMN %s" % _col)
        # 7/3: LEGFELJEBB EGY replay eredetinként — a párhuzamos operátor-hívás (TOCTOU) így
        # nem duplikálhat: a második beszúrás IntegrityError-t kap. Régi DB-n (ha már van duplikátum) csak kimarad.
        try:
            with c:
                c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_replay_once ON cursor_audit(agent, from_id) WHERE op='replay'")
        except sqlite3.DatabaseError:
            pass
        # A1-L3 additív migráció: cursors.delivered_id (a legmagasabb ténylegesen KÉZBESÍTETT id; CSAK a mark-recv emeli).
        # PREFIX-frozen (CURSOR_COLUMNS=(agent,last_seen_id) érintetlen). SEED: a LÉTEZŐ kurzorokra delivered_id:=last_seen_id
        # (a pre-L3 előzmény legitim-kézbesített baseline-ja) → a reconcile ne jelöljön mindent kihagyottnak (default 0 miatt).
        try:
            _has_delivered = "delivered_id" in {r[1] for r in c.execute("PRAGMA table_info(cursors)")}
        except sqlite3.OperationalError:
            _has_delivered = True                            # a cursors tábla még nincs (friss init majd létrehozza)
        if not _has_delivered and c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cursors'").fetchone():
            with c:
                c.execute("ALTER TABLE cursors ADD COLUMN delivered_id INTEGER NOT NULL DEFAULT 0")
                c.execute("UPDATE cursors SET delivered_id = last_seen_id")   # seed: legitim baseline
        # A2 additív migráció: messages.sig / messages.pubkey (nullable, feladó-aláírás). A delivered_id/cursor_audit
        # precedensét tükrözi → NINCS SCHEMA_VERSION-bump; a régi (aláíratlan) sorok NULL-ban maradnak (no-deletion).
        try:
            _msg_cols = {r[1] for r in c.execute("PRAGMA table_info(messages)")}
        except sqlite3.OperationalError:
            _msg_cols = {"sig", "pubkey"}                     # a messages tábla még nincs (friss init majd létrehozza)
        for _col in ("sig", "pubkey"):
            if _col not in _msg_cols:
                with c:
                    c.execute("ALTER TABLE messages ADD COLUMN %s TEXT" % _col)
    finally:
        c.close()


def _init_schema(c):
    with c:
        c.execute("""CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
            topic TEXT, kind TEXT, thread_id TEXT, in_reply_to INTEGER,
            body TEXT NOT NULL, read_at INTEGER,
            sig TEXT, pubkey TEXT)""")                            # A2: nullable feladó-aláírás (append-only; aláíratlan sor = NULL)
        c.execute("CREATE INDEX IF NOT EXISTS ix_recipient ON messages(recipient, id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_thread ON messages(thread_id, id)")
        c.execute("""CREATE TABLE IF NOT EXISTS cursors(
            agent TEXT PRIMARY KEY, last_seen_id INTEGER NOT NULL DEFAULT 0,
            delivered_id INTEGER NOT NULL DEFAULT 0)""")             # A1-L3: a legmagasabb KÉZBESÍTETT id (mark-only)
        c.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")  # additív: verzió-pin
        # a befagyasztott verziót CSAK akkor írjuk, ha még nincs (a régebbi DB-t nem írjuk felül; no-deletion)
        c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))


def verify_schema(db=None):
    """Divergencia-őr: a live DB sémája egyezik-e a befagyasztott kontraktussal. Never-throw → dict.
    R2-keményítés: a (név,típus,notnull,pk) prefix MELLETT VALÓDI AUTOINCREMENT (regex az id-soron, nem akármelyik
    'AUTOINCREMENT' substring egy carrier-oszlopban/kommentben — R2-C1); a fagyasztott táblákban TILOS a viselkedés-
    módosító CHECK/COLLATE/GENERATED (R2-C3/C4); additív oszlop CSAK ha INSERT-elhető (nullable v. default — R2-C6);
    TILOS trigger/view (egy trigger törölhetne sorokat = no-deletion sérülés — R2-C7); a meta-tábla is a kontraktus része (R2-C5)."""
    import re
    out = {"ok": True, "schema_version": SCHEMA_VERSION, "pinned": None, "problems": []}
    try:
        c = _conn(db)
        try:
            def _info(tbl):
                return list(c.execute("PRAGMA table_info(%s)" % tbl))
            mi, ci, meta_i = _info("messages"), _info("cursors"), _info("meta")

            def _tup(rows):
                return tuple((r["name"], (r["type"] or "").upper(), r["notnull"], r["pk"]) for r in rows)
            msg, cur, meta = _tup(mi), _tup(ci), _tup(meta_i)

            def _sql(name):
                r = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
                return (r["sql"] or "") if r else ""
            msg_sql, cur_sql = _sql("messages"), _sql("cursors")
            objs = [r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view')")]
            row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            out["pinned"] = row["value"] if row else None
        finally:
            c.close()
    except sqlite3.Error as e:
        out["ok"] = False
        out["problems"].append("db-open: %s" % e)
        return out
    P = out["problems"]
    if msg[:len(_FROZEN_MESSAGES)] != _FROZEN_MESSAGES:
        P.append("messages schema drift: %r != frozen %r" % (msg, _FROZEN_MESSAGES))
    if cur[:len(_FROZEN_CURSORS)] != _FROZEN_CURSORS:
        P.append("cursors schema drift: %r != frozen %r" % (cur, _FROZEN_CURSORS))
    # R2-C1: VALÓDI AUTOINCREMENT az id-oszlopon (substring-megkerülés ellen)
    # R3-A1: az id-oszlop lehet quote-olt/bracket-elt ("id"/[id]/`id`) ÉS akkor is VALÓDI AUTOINCREMENT (a tuple-check már
    # igazolta hogy a 0. oszlop neve 'id' + pk=1); a regex ezeket is fogadja, különben egy szemantikusan AZONOS séma FALSE-DRIFT.
    if not re.search(r'(?:\bID\b|"ID"|\[ID\]|`ID`)\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', (msg_sql or "").upper()):
        P.append("messages.id nem valódi AUTOINCREMENT (id-monotonitás veszélyben)")
    # R2-C3/C4: a fagyasztott táblák DDL-je nem tartalmazhat viselkedés-módosító elemet (a tuple-compare vak rá).
    # R3-A1: a token-scan SZÓHATÁRRAL és a QUOTE-OLT azonosítók/string-literálok KISZŰRÉSE után — különben egy LEGITIM
    # additív oszlop puszta NEVE ('checksum'/'collate_marker'/'generated_at') vagy egy DEFAULT 'unchecked' string FALSE-OK
    # helyett FALSE-DRIFT-et adott (guard-DoS: a kontraktus által megengedett additív oszlop elutasítva).
    def _strip_literals(sq):
        # quoted/bracket-identifiereket, '…' string-literálokat ÉS SQL-kommenteket (--… és /*…*/) semlegesítünk a
        # token-scan ELŐTT (a forbidden token csak NYERS DDL-ben számít). R4-B2: a kommentek kiszűrése nélkül egy
        # ártalmatlan `/* CHECK */` / `-- COLLATE` komment FALSE-DRIFT-et adott (guard-DoS: legitim séma elutasítva).
        # Az alternáció balról-jobbra illeszt → egy string-literálon BELÜLI '--'/'/*' a stringként fogy el (nem komment).
        return re.sub(r'''"[^"]*"|\[[^\]]*\]|`[^`]*`|'[^']*'|--[^\n]*|/\*.*?\*/''', " ", sq or "", flags=re.DOTALL)
    for nm, sq in (("messages", msg_sql), ("cursors", cur_sql)):
        u = _strip_literals(sq).upper()
        for tok in ("CHECK", "COLLATE", "GENERATED"):
            if re.search(r"\b%s\b" % tok, u):           # szóhatár: 'checksum' már nem talál CHECK-et
                P.append("%s tábla tiltott DDL-elem: %s (a fagyasztott kontraktus nem tartalmaz ilyet)" % (nm, tok))
    # R2-C7: a kontraktusban NINCS trigger/view (egy AFTER INSERT trigger törölhetne sorokat → no-deletion sérülés)
    if objs:
        P.append("tiltott trigger/view: %s" % ", ".join(sorted(objs)))
    # R2-C6: additív (extra) oszlop CSAK ha INSERT-elhető (nullable VAGY van default) — különben verify-OK de send() törött
    for r in mi[len(_FROZEN_MESSAGES):]:
        if r["notnull"] and r["dflt_value"] is None:
            P.append("additív oszlop megtöri az INSERT-et (NOT NULL default nélkül): %s" % r["name"])
    extra = msg[len(_FROZEN_MESSAGES):]
    if extra:
        out["added_columns"] = [e[0] for e in extra]
    # R2-C5: a meta-tábla (a verzió-pin hordozója) is a kontraktus része
    if meta[:2] != (("key", "TEXT", 0, 1), ("value", "TEXT", 0, 0)):
        P.append("meta tábla drift: %r" % (meta,))
    if out["pinned"] is None:                                # C5: a pin HIÁNYA is probléma (nem csendes false-OK)
        P.append("schema_version not pinned (meta)")
    elif out["pinned"] != SCHEMA_VERSION:
        P.append("version mismatch: db pinned %s, code %s" % (out["pinned"], SCHEMA_VERSION))
    out["ok"] = not P
    return out


def _mirror_json(row_id, sender, recipient, topic, kind, thread_id, in_reply_to, body, ts, inbox_root=None, sig=None, pubkey=None):
    """Back-compat JSON-tükör (atomikus tmp→rename). HARDENED (red-team A1–A8, I4): `_safe_name` a recipient/sender/topic
    minden út-komponensén (path-traversal/clobber/terminál-injekció ellen) + realpath-confinement (a feloldott út az
    inboxon BELÜL kell maradnia) + O_EXCL|O_NOFOLLOW (nincs symlink-follow / néma felülírás). Best-effort: BÁRMILYEN hiba →
    skip (I7 fail-safe), SOSEM propagál a send-be. Megj.: a tükör SZÁNDÉKOSAN lossy/legacy (a DB az igazság-forrás, C6);
    az in_reply_to a bevett LISTA-alak marad (I1 — a vendorolt kliensek erre építenek)."""
    try:
        root = os.path.realpath(inbox_root or INBOX_ROOT)
        d = os.path.realpath(os.path.join(root, _safe_name(recipient)))
        if d != root and not d.startswith(root + os.sep):       # I4 realpath-confinement: a recipient nem törhet ki
            raise OSError("recipient escapes inbox: %r" % recipient)
        os.makedirs(d, exist_ok=True)
        rec = {"from": sender, "to": recipient, "kind": kind, "topic": topic,
               "note": body, "ts": ts, "bus_id": row_id}
        if in_reply_to:
            rec["in_reply_to"] = [in_reply_to]
        if sig:                                                  # a tükör-fogyasztó is ellenőrizhet
            rec["sig"], rec["pubkey"] = sig, pubkey
        base = os.path.join(d, "%s_%d_%s.json" % (_safe_name(sender), row_id, _safe_name(topic or "msg")))
        tmp = base + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # A4/A7b: nincs clobber/symlink-follow
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False, indent=2)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, base)
        return base
    except Exception as e:                                       # D#9: best-effort → bármilyen hiba = skip, never-throw
        sys.stderr.write("  (json-mirror skip: %s)\n" % e)
        return None


def check_presigned(sender, recipient, body, presigned, *, topic="", kind="msg", in_reply_to=None, keys_dir=None):
    """Egy KLIENS-OLDALON aláírt sor ellenőrzése az INSERT ELŐTT (v1.5.2, 2026-09-21). `presigned` = {ts, sig, pubkey}
    ahogy a feladó adta. Visszaad: (ts:int, sig:str, pubkey:str), vagy ValueError-t dob.
    MIÉRT: az SSH-csere elvből nem írja alá a busz-gép kulcsával a TÁVOLI fél sorát (sign_key=False) — helyes, mert a
    busz-gép nem a feladó. De a termék-mód a registry-ben pinelt név alatti csupasz sort elutasítja (`unsigned-pinned`), így 09-19 óta a két gép közti MINDEN sor csendben eldobódott olvasáskor (audit: 25 az egyik kar→a partner-kar,
    7064 a partner-kar→az egyik kar). A hiányzó láncszem: a feladó a SAJÁT kulcsával írja alá a saját sorát, a szerver a registry
    ellen ellenőrzi, és pontosan azt tárolja. A `ts` a feladóé (benne van az aláírt tartalomban), az enforce ablaka
    (múlt/jövő) ugyanúgy méri, mint a helyi sorét. Fail-closed: ismeretlen feladó, kulcs-eltérés, rossz aláírás,
    hibás alak → ValueError (a hívó ezt LÁTHATÓ elutasításként adja vissza, nem néma eldobásként)."""
    if not _A2_HAVE:
        raise ValueError("presigned: ed25519 requires the 'cryptography' package")
    if not isinstance(presigned, dict):
        raise ValueError("presigned: must be an object {ts, sig, pubkey}")
    ts, sig_hex, pub_hex = presigned.get("ts"), presigned.get("sig"), presigned.get("pubkey")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts <= 0 or ts > _SQLITE_INT_MAX:
        raise ValueError("presigned: ts must be a positive integer (ns)")
    if not isinstance(sig_hex, str) or not isinstance(pub_hex, str) or len(pub_hex) != 64 or len(sig_hex) != 128:
        raise ValueError("presigned: sig (128 hex) and pubkey (64 hex) required")
    expect = _a2_load_registry_pubkey(sender, keys_dir if keys_dir is not None else KEYS_DIR)
    if expect is None:
        raise ValueError("presigned: sender '%s' has no registry key (unknown sender)" % sender)
    if pub_hex != expect:
        raise ValueError("presigned: pubkey is not the registry key of '%s' (forged)" % sender)
    try:
        pub = _a2_ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), _a2_content_bytes({"sender": sender, "recipient": recipient, "topic": topic,
                                                              "kind": kind, "in_reply_to": in_reply_to, "body": body,
                                                              "ts": ts}))
    except Exception:
        raise ValueError("presigned: signature does not verify (forged or tampered)")
    return ts, sig_hex, pub_hex


def sign_for_send(sign_key, sender, recipient, body, *, topic="", kind="msg", in_reply_to=None, ts=None):
    """A KLIENS oldala: a saját seed-fájlával aláírt {ts, sig, pubkey} egy majdani `send(..., presigned=...)`-hez.
    A tartalom-bájtkép ugyanaz, mint a helyi `send`-nél (`_a2_content_bytes`), így a busz-gép `check_presigned`-je és
    a címzett `verify_sender`-e ugyanazt ellenőrzi.

    EZ A DOCSTRING EGYSZER HAZUDOTT. A függvény SAJÁT normalizálást hordozott a mezőkön (`kind or "msg"`,
    `topic or ""`), mielőtt átadta őket — így egy EXPLICIT `kind=""` esetén `"msg"`-ot írt alá, miközben a
    `_a2_content_bytes` (a spec, és amit a verifikáló számol) `""`-t. Mérve: a `sign_for_send(kind="")`
    aláírása a `kind="msg"` bájtképre illik, a `kind=""`-re NEM — vagyis egy spec szerint számoló partner
    verify-ja NÉMÁN bukik. Egy döntés, két implementáció; a gyengébbik győzött.

    A kwarg-alapértelmezés (`kind="msg"`) az ELHAGYOTT mező API-kényelme, és az marad. Az EXPLICIT üres
    string az hívói SZÁNDÉK, és `""`-ként megy tovább. Normalizálni CSAK a `_a2_content_bytes` normalizál."""
    if in_reply_to is not None:
        in_reply_to = int(in_reply_to)
    ts = time.time_ns() if ts is None else int(ts)
    seed = bytes.fromhex(open(sign_key, encoding="utf-8").read().strip())
    rec = _a2_sign(seed, {"sender": sender, "recipient": recipient, "topic": topic, "kind": kind,
                          "in_reply_to": in_reply_to, "body": body, "ts": ts})
    return {"ts": ts, "sig": rec["sig"], "pubkey": rec["pubkey"]}


def send(sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None,
         db=None, mirror=True, inbox_root=None, sign_key=None, presigned=None):
    if body is not None and len(body.encode("utf-8", "surrogatepass")) > _MAX_BODY:  # D#1/R3-A5: BYTE-méret (nem char) → a multibyte 4× bypass ellen
        raise ValueError("body exceeds %d B (AgentBus = koordináció, I2)" % _MAX_BODY)
    # R3-D#1: a body-cap-ot megkerülő mező-DoS ellen — a routing/szál-mezők is kötöttek (egy 500K thread_id ×4 = MB-ok)
    for _nm, _v in (("sender", sender), ("recipient", recipient), ("topic", topic),
                    ("kind", kind), ("thread_id", thread_id)):
        if _v is not None and len(str(_v)) > _MAX_FIELD:
            raise ValueError("%s exceeds %d chars (AgentBus = koordináció, I2)" % (_nm, _MAX_FIELD))
    # R3-I#3: in_reply_to a sqlite 8-bájtos INTEGER-be megy → tartomány-ellenőrzés (≥0, ≤2^63-1), különben az insert
    # nyers OverflowError-t dobna (a CLI 'never-throw' ígérete sérülne) → kontrollált ValueError
    if in_reply_to is not None:
        try:
            _ir = int(in_reply_to)
        except (TypeError, ValueError):
            raise ValueError("in_reply_to must be an integer")
        if not (0 <= _ir <= _SQLITE_INT_MAX):
            raise ValueError("in_reply_to out of range [0, 2^63-1]")
        in_reply_to = _ir
    if kind == ATTACH_KIND:                                      # v1.2: a csatolmány-üzenet body-ja CSAK a zárt leíró (a tartalom a buszon kívül él)
        import bus_attach
        try:
            bus_attach.check_descriptor(body)
        except ValueError as e:
            raise ValueError("attachment refused: %s" % e)
    if kind == SDS_KIND:                                         # v1.1 (a partner-kar 1. lépés): a keret szerkezete kötött — hibás keret nem kerül a buszra
        import sds_envelope
        try:
            sds_envelope.check_framed_shape(body)
        except ValueError as e:
            raise ValueError("sds-envelope refused: %s" % e)
    init(db)
    ts = time.time_ns()
    # A2: ha sign_key adott, a tartalmat (id/thread_id KIZÁRVA, ) Ed25519-cel aláírjuk az INSERT ELŐTT →
    # a sig/pubkey a sorba kerül. AUTO-SIGN: sign_key nélkül a sender guard-olt default seed-je oldódik fel
    # (keys/<sender>.ed25519.key) — a "kimaradt sign_key=" rés zárása; opt-out AGENT_BUS_AUTO_SIGN=0.
    # Se explicit kulcs, se default → mindkettő NULL, byte-azonos az eddigi (aláíratlan) viselkedéssel.
    # PRESIGNED (v1.5.2): a feladó a saját gépén írta alá — a registry ellen ellenőrizve PONTOSAN azt tároljuk
    # (a ts is az övé); a busz-gép kulcsa ilyenkor NEM ír alá (a két út kizárja egymást).
    sig = pubkey = None
    if presigned is not None:
        if sign_key:
            raise ValueError("presigned and sign_key are mutually exclusive")
        ts, sig, pubkey = check_presigned(sender, recipient, body, presigned, topic=topic, kind=kind,
                                          in_reply_to=in_reply_to)
        sign_key = False
    if sign_key is None and _a2_auto_sign_enabled():
        sign_key = _a2_default_sign_key(sender)
    if sign_key:
        seed = bytes.fromhex(open(sign_key, encoding="utf-8").read().strip())   # 32-bájtos hex seed
        _rec = _a2_sign(seed, {"sender": sender, "recipient": recipient, "topic": topic,
                               "kind": kind, "in_reply_to": in_reply_to, "body": body, "ts": ts})
        sig, pubkey = _rec["sig"], _rec["pubkey"]
    c = _conn(db)
    with c:
        cur = c.execute(
            "INSERT INTO messages(ts,sender,recipient,topic,kind,thread_id,in_reply_to,body,sig,pubkey) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, sender, recipient, topic, kind, thread_id, in_reply_to, body, sig, pubkey))
        rid = cur.lastrowid
        if not thread_id:                                   # ha nincs szál, a saját id a szál gyökere
            c.execute("UPDATE messages SET thread_id=? WHERE id=?", (str(rid), rid))
    c.close()
    # termék-módban a JSON-tükör CSAK aláírt sorra fut (és a sig/pubkey benne van) — a
    # kikényszerítetlen régi csatornán nem jelenhet meg aláíratlan üzenet. Dev módban változatlan.
    if mirror and (sig or not _is_product(db)):
        _mirror_json(rid, sender, recipient, topic, kind, thread_id or str(rid), in_reply_to, body, ts, inbox_root,
                     sig=sig, pubkey=pubkey)
    return rid


def _sds_annotate(rows, *, strict=False, admission_path=None):
    """v1.1 (a partner-kar 2+3. lépés): minden sds-envelope sorra `sds` = valid | invalid(<ok>) | unsigned | unverifiable(<ok>).
    A feladó registry-kulcsa (A2, root-guardolt) és a helyi admission-fájl köti a feladót a beengedett issuerhez.
    Ha a busz-sor A2-aláírása HAMIS, a boríték invalid(forged-sender). strict → a nem-valid sds-sorok kimaradnak a
    KIMENETBŐL (a DB-ben megmaradnak, tail/thread látja; no-deletion). A többi kind érintetlen."""
    import sds_envelope
    adm = sds_envelope.load_admission(admission_path or os.environ.get("AGENT_BUS_SDS_ADMISSION"))
    out = []
    for m in rows:
        if m.get("kind") != SDS_KIND:
            out.append(m)
            continue
        if m.get("sig") and verify_sender(m) == "forged":
            st, why = "invalid", "forged-sender"
        else:
            st, why = sds_envelope.verify(m.get("body") or "", sender=m.get("sender"), admission=adm,
                                          registry_pubkey=_a2_load_registry_pubkey(m.get("sender", ""), KEYS_DIR))
        m["sds"] = sds_envelope.label(st, why)
        if not strict or st == "valid":
            out.append(m)
    return out


def _enforce_module():
    """a bus_enforce OPCIONÁLIS import — részleges deploy (csak agent_bus.py) dev módban nem
    állítja le a postát. None ha hiányzik."""
    try:
        import bus_enforce
        return bus_enforce
    except ImportError:
        return None


def _product_hint_paths(db=None):
    """A marker MINDEN keresési helye a modul NÉLKÜLI úton. Ugyanaz az unió, amit a `bus_enforce.marker_paths`
    néz — és ez a lényeg: ez a két lista ugyanarra a kérdésre válaszol, tehát együtt kell mozdulniuk.

    Ez a függvény akkor dönt, amikor a `bus_enforce` NEM importálható, vagyis pontosan abban a helyzetben,
    amiért a végső őr létezik. Egy korábbi változat csak az `abspath`-ot nézte, a `realpath`-ot nem — mérve a
    publikált 1.5.3-on: ugyanaz a DB a valódi útján megtagadta a kézbesítést (fail-closed), symlinken át
    viszont kiadta ugyanazokat a leveleket. A symlink-javítás megvolt a modulban, csak ide nem ért el: egy
    döntés, két implementáció, és a gyengébbik nyílt ki."""
    dbp = db or DB
    paths = ["/etc/agent-bus/product_mode.on",
             os.path.join(os.path.dirname(os.path.realpath(dbp)), ".product_mode.on"),
             os.path.join(os.path.dirname(os.path.abspath(dbp)), ".product_mode.on")]
    # A BRIDGE (a site gyökere) is keresési hely: a modul oldalán mindig az volt, és a két listának EGYEZNIE
    # kell. Ezt nem én vettem észre — a most írt egyezés-teszt bukott el rajta elsőre.
    for base in (os.environ.get("AGENT_BUS_DIR"), BRIDGE):
        if base:
            paths.append(os.path.join(os.path.realpath(base), ".product_mode.on"))
            paths.append(os.path.join(base, ".product_mode.on"))
    return list(dict.fromkeys(paths))


def _product_hint(db=None):
    """bus_enforce NÉLKÜL is felismerhető termék-mód jel (env nem-dev érték / marker BÁRMELYIK keresési helyen) →
    a hiányzó modul ilyenkor fail-closed, nem csendes dev."""
    raw = os.environ.get("AGENT_BUS_MODE", "").strip().lower()
    if raw and raw != "dev":
        return True
    return any(os.path.exists(p) for p in _product_hint_paths(db))


def _is_product(db=None):
    enf = _enforce_module()
    return (enf.mode(db=db) == "product") if enf is not None else _product_hint(db)


def recv(agent, *, mark=False, limit=_RECV_LIMIT, db=None, verify_sds=False, strict_sds=False, sds_admission=None):
    """A kurzor utáni olvasatlanok (id>kurzor), LEGFELJEBB `limit`. `mark`:
    a kurzor a visszaadott LAP utolsó id-jére lép → a következő hívás a következő lapot adja (kurzor-szemantika megőrizve).
    B#3: `mark` esetén a read+mark EGY immediate-tranzakcióban (write-lock upfront) → két párhuzamos recv nem kézbesít duplán.
    v1.4 + termék-módban a kikényszerítés UGYANEBBEN a tranzakcióban fut, a kurzor ELŐTT (/):
    az elutasított sor nem emeli a delivered_id-t, read_at-je NULL marad, `enforce_reject:<ok>` audit-sort kap (→ a
    reconcile/replay látja), a recv_mark audit skipped=elutasítottak száma; a seen-tár a DB-ben (/)."""
    init(db)
    enf = _enforce_module()
    if enf is None:
        if _product_hint(db):                                   # termék-mód jelezve, modul nincs → fail-closed
            sys.stderr.write("recv refused: termék-mód jelezve, de a bus_enforce modul hiányzik (fail-closed; "
                             "a kurzor nem mozdult)\n")
            return []
        product = False
    else:
        product = enf.mode(db=db) == "product"
    rejected = []
    c = _conn(db)
    try:
        if mark:
            c.isolation_level = None                            # explicit tranzakció-vezérlés EHHEZ a connectionhöz
            c.execute("BEGIN IMMEDIATE")                        # B#3: write-lock előre → read+mark szerializált
        row = c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        last = row["last_seen_id"] if row else 0
        rows = c.execute("SELECT * FROM messages WHERE recipient=? AND id>? ORDER BY id LIMIT ?",
                         (agent, last, max(1, int(limit)))).fetchall()
        out = [dict(r) for r in rows]
        if _a2_strict():                                        # A2 opt-in strict (AGENT_BUS_REQUIRE_SIG=1): minden sor auth-státusza (default OFF → érintetlen)
            for _m in out:
                _m["auth"] = verify_sender(_m)
        if product:
            try:
                _store, _kept = enf.DbSeenStore(c, agent), []
                if mark:
                    _store.ensure()
                for _m in out:
                    _ok, _why = enf.check(_m, seen=_store, record=mark)   # peek: csak ellenőriz, NEM fogyaszt
                    if _ok:
                        _kept.append(_m)
                    else:
                        _m["enforce"] = _why                    # a sor a DB-ben marad (no-deletion)
                        rejected.append(_m)
                if not mark and rejected:                       # a peek-út is NEVESÍTI az elutasítást
                    for _m in rejected:                         # (idempotens: egy sorra egy audit-bejegyzés)
                        have_row = c.execute("SELECT 1 FROM cursor_audit WHERE agent=? AND from_id=? AND op LIKE "
                                             "'enforce_reject%' LIMIT 1", (agent, _m["id"])).fetchone()
                        if not have_row:
                            _append_audit(c, agent, _m["id"], _m["id"], "enforce_reject:%s" % _m["enforce"], 1)
                    c.commit()
            except Exception as e:                              # never-throw, fail-closed, a kurzor NEM mozdul
                if mark:
                    c.execute("ROLLBACK")
                sys.stderr.write("recv refused: kikényszerítési hiba (%s) — fail-closed, a kurzor nem mozdult\n"
                                 % type(e).__name__)
                return []
            out = _kept
        if mark and rows:
            top = rows[-1]["id"]
            now = time.time_ns()
            if product:
                acc = [m["id"] for m in out]
                # a delivered_id CSAK a ténylegesen kézbesítettig (monoton MAX); az elutasított sor read_at NULL
                c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                          "last_seen_id=excluded.last_seen_id, delivered_id=MAX(cursors.delivered_id, excluded.delivered_id)",
                          (agent, top, max(acc) if acc else 0))
                c.executemany("UPDATE messages SET read_at=? WHERE id=? AND read_at IS NULL", [(now, i) for i in acc])
                for _m in rejected:                             # a lánc az elutasítást rögzíti, nem kézbesítést
                    _append_audit(c, agent, _m["id"], _m["id"], "enforce_reject:%s" % _m["enforce"], 1)
                _append_audit(c, agent, last, top, "recv_mark", len(rejected))
            else:
                # A1-L3: a mark-fogyasztó recv KÉZBESÍT → emeli a delivered_id-t (monoton MAX) UGYANEBBEN a tranzakcióban a
                # kurzorral + a lánc-sorral (atomi, nincs TOCTOU; INV-A1.6). A non-mark recv (watcher-poll) PEEK → ide nem ér.
                c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                          "last_seen_id=excluded.last_seen_id, delivered_id=MAX(cursors.delivered_id, excluded.delivered_id)",
                          (agent, top, top))
                c.execute("UPDATE messages SET read_at=? WHERE recipient=? AND read_at IS NULL AND id<=?",
                          (now, agent, top))
                # A1-L1: a recv-mark az imént KÉZBESÍTETT lapot fedi (last→top == a visszaadott sorok) → skipped=0; hash-láncolt
                _append_audit(c, agent, last, top, "recv_mark", 0)
        if mark:
            c.execute("COMMIT")
    finally:
        c.close()
    if product:
        if rejected:                                            # az elutasítás NEM néma (peeknél sem)
            cnt = {}
            for _m in rejected:
                cnt[_m["enforce"]] = cnt.get(_m["enforce"], 0) + 1
            sys.stderr.write("# %d sor elutasítva (termék-mód): %s%s\n" % (
                len(rejected), ", ".join("%s×%d" % kv for kv in sorted(cnt.items())),
                " — helyreállítás: reconcile/replay" if mark else ""))
            if mark:
                for _m in rejected:
                    enf.log_rejected(agent, _m, _m["enforce"])  # best-effort 
        # product módban az sds-envelope KÖTELEZŐEN ellenőrzött és csak valid marad (nincs 'unsigned' boríték)
        verify_sds, strict_sds = True, True
    if verify_sds or strict_sds:
        out = _sds_annotate(out, strict=strict_sds, admission_path=sds_admission)
    return out


def _strict_ack(db=None):
    """A1-L3: az ack a delivered_id-ig clamp-el (nem a high-waterig) — TERMÉK-MÓDBAN ALAPÉRTELMEZÉS.

    A MAJOR-kapu megnyílt (az üzemeltető 2026-09-16 „igen mehet"; az egyik kar mért véleménye: a clamp bekapcsolva A KÁRT
    MAGÁT szünteti meg — a kurzor nem tud kiadatlan posta fölött átlépni, ezért `skipped_undelivered` sem
    keletkezik; a +11 teszt-bukása mind FIXTURE-előfeltétel, nem termék-kód).
    Menekülő ajtó: `AGENT_BUS_STRICT_ACK=0/false/no/off` — a kikapcsolás TÉNYE bekerül a kör-bejegyzésbe
    (`strict_ack: 0`), tehát nem néma. Dev-módban változatlanul opt-in (byte-azonos a vendorolt klienssel).
    """
    raw = os.environ.get("AGENT_BUS_STRICT_ACK", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return _is_product(db)


def strict_ack_state(db=None):
    """(aktív, kikapcsolva_termék-módban) — a kör-bejegyzésnek, hogy a menekülő ajtó használata látszódjon."""
    active = _strict_ack(db)
    return active, bool(_is_product(db) and not active)


def _ack_target(c, agent, upto, db=None):
    """(jelenlegi kurzor, az ack utáni kurzor) — az ack clamp-szabálya egy helyen (az ack és a naplózás-előbb előnézete)."""
    hi = c.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE recipient=?", (agent,)).fetchone()[0]
    row = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent=?", (agent,)).fetchone()
    base = row["last_seen_id"] if row else 0
    cap = (row["delivered_id"] if row else 0) if _strict_ack(db) else hi   # strict → kézbesítettig; default → high-water
    return base, max(base, min(int(upto), cap))                  # előre-only + (strict: delivered / default: high-water) clamp


def ack_preview(agent, upto, db=None):
    """v1.5 SSH naplózás-előbb: (kurzor most, kurzor az ack után) — az ack MEGHÍVÁSA NÉLKÜL, ugyanazzal a szabállyal."""
    init(db)
    c = _conn(db)
    try:
        return _ack_target(c, agent, upto, db=db)
    finally:
        c.close()


def audit_head(agent, db=None):
    """Az agent hash-láncolt cursor_audit láncának feje: (seq, row_hash) — 0/None, ha még nincs sor.

    54Z: a kör-bejegyzés ÖNBEVALLOTT számait (pending/next_id) a log önmagában nem cáfolja;
    a horgony teszi utólag összevethetővé a busz SAJÁT, hash-láncolt naplójával (a két nyilvántartás egyike hazudik).
    """
    init(db)
    c = _conn(db)
    try:
        r = c.execute("SELECT seq,row_hash FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT 1", (agent,)).fetchone()
        return (r["seq"], r["row_hash"]) if r else (0, None)
    finally:
        c.close()


# a kikényszerítési elutasítás lehet VÉGLEGES vagy ÁTMENETI. A vízszint (delivered_id)
# csak a VÉGLEGESEN kiadhatatlan sort lépheti át; az átmenetit (előre járó óra, még be nem jegyzett kulcs) meg kell várni,
# különben egy óracsúszás vagy egy futó kulcs-rollout véglegesen elnyeli a legitim postát.
TRANSIENT_REJECT = ("future-ts",)          # magától letelik (a feladó órája előre jár)
# D: a `forged` alapból VÉGLEGES (egy szemét sor különben örökre lefogná a vízszintet = DoS). a partner-kar
# kulcs-rollout esete valós, de OPERÁTORI ablak: /etc/agent-bus/key_rollout.on (vagy a DB mellett .key_rollout.on)
# jelenlétében a `forged` átmenetinek számít — szándékos, látható, visszavonható kapcsoló.
ROLLOUT_MARKERS = ("/etc/agent-bus/key_rollout.on",)
FORGED_GRACE_S = int(os.environ.get("AGENT_BUS_FORGED_GRACE_S", str(24 * 3600)))


def _key_rollout(db=None):
    if any(os.path.exists(p) for p in ROLLOUT_MARKERS):
        return True
    try:
        return os.path.exists(os.path.join(os.path.dirname(os.path.abspath(db or DB)), ".key_rollout.on"))
    except Exception:
        return False


def _reject_age_s(m):
    """A sor kora MÁSODPERCBEN a saját `ts`-éből — vagy None, ha a `ts` nem használható korhatárhoz.

    7/1: a `ts` a FELADÓ mezője, egy `forged` sornál pedig épp az a kérdés, hogy hihető-e.
    Egy jövőbeli `ts` NEGATÍV kort adott → a grace örökre igaz maradt → a sor véglegesen lefogta a vízszintet.
    Ezért: jövőbeli (óra-csúszáson túli) vagy értelmezhetetlen `ts` → None = NEM friss, tehát nem átmeneti.
    """
    try:
        raw = int(m.get("ts") or 0)
    except (TypeError, ValueError):
        return None
    if raw <= 0:
        return None
    secs = raw / 1e9 if raw > 1e12 else raw
    age = time.time() - secs
    if age < -_CLOCK_SKEW_S:                     # a jövőből érkezett „friss" sor: nem kap kegyelmi időt
        return None
    return max(0.0, age)


def pending_blocking_ids(agent, db=None):
    """A kurzor fölötti sorok, amelyek MA kiadhatók VAGY átmenetileg elutasítottak (tehát még kijöhetnek). -> [id]"""
    init(db)
    c = _conn(db)
    try:
        cur = (c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone() or {"last_seen_id": 0})["last_seen_id"]
        rows = [dict(r) for r in c.execute("SELECT * FROM messages WHERE recipient=? AND id>? AND kind IS NOT 'replay' "
                                           "ORDER BY id LIMIT ?", (agent, cur, _RECV_LIMIT))]
    finally:
        c.close()
    if not _product_hint(db):
        return [r["id"] for r in rows]
    try:
        import bus_enforce as enf
    except Exception:
        return [r["id"] for r in rows]                 # nincs kikényszerítés-modul: fail-closed (inkább várunk)
    rollout = _key_rollout(db)
    out = []
    for m in rows:
        try:
            ok, why = enf.check(m, seen=None, record=False)
        except Exception:
            # 7/2: egy ÉRTELMEZHETETLEN sor a recv-en is elbukna, tehát SOSEM adható ki —
            # ha blokkolónak vennénk, egyetlen szemét sorral örökre megállítható lenne a vízszint (DoS).
            continue                                   # nem blokkol; a mentőöv (reconcile) továbbra is listázza
        # `forged` = a feladó kulcsa (még) nincs a registryben VAGY az aláírás rossz. Az első ÁTMENETI (kulcs-rollout),
        # a második VÉGLEGES — a kettőt innen nem tudjuk szétválasztani, ezért IDŐKORLÁT: FORGED_GRACE_S-ig (alap 24 h,
        # illetve rollout-marker mellett korlátlanul) átmeneti, utána végleges. Így a friss posta védett, egy régi
        # szemét sor viszont nem fogja le örökre a vízszintet.
        transient = list(TRANSIENT_REJECT)
        if why == "forged":
            age = _reject_age_s(m)
            if rollout or (age is not None and age <= FORGED_GRACE_S):
                transient.append("forged")
        if ok or why in transient:
            out.append(m["id"])
    return out


def audit_export(agent, from_seq: int = 0, db=None) -> list:
    """Az agent hash-láncolt cursor_audit sorai (gépi, átvihető alak) — a közjegyzői naplóval való ÖSSZEVETÉSHEZ.

    54Z nyitott tétele: a kör-bejegyzés `pending`/`next_id` száma a busz ÖNBEVALLÁSA. Ez az export
    teszi a másik gépen összevethetővé: a `bus_notary.reconcile(..., bus_audit=...)` a kettő ellentmondását jelzi.
    """
    init(db)
    c = _conn(db)
    try:
        return [{"seq": r["seq"], "ts": r["ts"], "agent": r["agent"], "from_id": r["from_id"], "to_id": r["to_id"],
                 "op": r["op"], "skipped_undelivered": r["skipped_undelivered"],
                 "prev_row_hash": r["prev_row_hash"], "row_hash": r["row_hash"]}
                for r in c.execute("SELECT * FROM cursor_audit WHERE agent=? AND seq>=? ORDER BY id", (agent, from_seq))]
    finally:
        c.close()


def audit_chain_verify(rows: list, start_row_hash: str | None = None) -> dict:
    """Az exportált audit-lánc önellenőrzése: sorfolytonos seq + hash-lánc. -> {ok, errors[], slice_start_seq, anchored}

    a belsőleg ép lánc ÖNMAGÁBAN nem állítás a teljes láncról — pontosan az a
    hibaosztály, amit a közjegyzői `verify`-ban (`unverified_tail`, majd `slice_start_seq`/`anchored`) már
    kétszer bezártunk. Ezért ez is kimondja, hol kezdődik a szelet, és hogy HORGONYZOTT-e: a GENEZIS-ből indul
    (seq 0, prev = GENESIS), vagy a hívó adott csatornán kívül ismert `start_row_hash`-t. Az ellenpróba a saját
    modulunkban volt: a DB-beli `audit_verify()` mindig `_GENESIS`-ből indul — az exportált úton veszett el.
    """
    errors, prev = [], None
    for i, r in enumerate(rows):
        try:
            rh = _audit_row_hash(r["seq"], r["ts"], r["agent"], r["op"], r["from_id"], r["to_id"],
                                 r["skipped_undelivered"], r["prev_row_hash"])
        except Exception as e:
            errors.append({"seq": r.get("seq"), "error": "hash: %s" % type(e).__name__}); continue
        if rh != r.get("row_hash"):
            errors.append({"seq": r["seq"], "error": "row_hash mismatch"})
        if prev is not None:
            if r["prev_row_hash"] != prev["row_hash"]:
                errors.append({"seq": r["seq"], "error": "chain break"})
            if r["seq"] != prev["seq"] + 1:
                errors.append({"seq": r["seq"], "error": "seq gap"})
        prev = r
    first = rows[0] if rows else None
    if first is not None:
        if start_row_hash is not None:
            anchored = first.get("prev_row_hash") == start_row_hash
            if not anchored:
                errors.append({"seq": first.get("seq"), "error": "chain does not continue from the given start_row_hash"})
        else:
            # A `ok` a LÁNC épségét mondja (mint a közjegyzői `verify`-nál), a horgonyt külön mező hordozza, és a
            # FOGYASZTÓ (reconcile / CLI) dönt róla — így a részszelet-export továbbra is ellenőrizhető marad.
            anchored = first.get("seq") == 0 and first.get("prev_row_hash") == _GENESIS
    else:
        anchored = False
    # (nyitott szonda, most zárva): az `ok` NEVE két különböző dolgot jelentett. A DB-úton
    # (`audit_verify`) mindig a GENEZIS-ből indul, tehát ott az `ok` = ép ÉS horgonyzott; az exportált úton
    # viszont csak az épséget mondta — ugyanaz a mező, két garancia. Aki csak az `ok`-ot olvassa, hamis zöldet
    # kap egy horgonyzatlan szeletre. A név mostantól a SZIGORÚBB jelentést hordozza, a szelet-ellenőrzés
    # pedig a `chain_ok`-on át továbbra is elérhető (a `reconcile` azt használja).
    return {"ok": (not errors) and bool(anchored), "chain_ok": not errors, "errors": errors,
            "rows": len(rows), "slice_start_seq": (first or {}).get("seq"), "anchored": bool(anchored)}


def _permanent_rejects(agent, ids, db=None):
    """Azok az id-k a megadottak közül, amiket a kikényszerítés VÉGLEGESEN elutasít (sosem adhatók ki). -> set"""
    ids = [int(i) for i in (ids or [])]
    if not ids or not _product_hint(db):
        return set()
    try:
        import bus_enforce as enf
    except Exception:
        return set()
    c = _conn(db)
    try:
        q = ",".join("?" * len(ids))
        rows = [dict(r) for r in c.execute("SELECT * FROM messages WHERE recipient=? AND id IN (%s)" % q, tuple([agent] + ids))]
    finally:
        c.close()
    rollout, out = _key_rollout(db), set()
    for m in rows:
        try:
            ok, why = enf.check(m, seen=None, record=False)
        except Exception:
            out.add(m["id"])                       # értelmezhetetlen sor: a recv-en is elbukna -> végleges
            continue
        if ok:
            continue
        transient = list(TRANSIENT_REJECT)
        if why == "forged":
            age = _reject_age_s(m)
            if rollout or (age is not None and age <= FORGED_GRACE_S):
                transient.append("forged")
        if why not in transient:
            out.add(m["id"])
    return out

def mark_delivered(agent, ids, db=None):
    """A TÁVOLI (SSH) kiadás kézbesítés-jelölése: read_at + delivered_id (monoton MAX) — a KURZOR NEM mozdul.

    a peek-kiadás (recv mark=False) eddig nem emelte a delivered_id-t, ezért
    (1) a helyi mentőöv (reconcile/skipped_undelivered) a becsületes körre is teljes ablakot jelentett, és
    (2) az AGENT_BUS_STRICT_ACK clamp befagyasztotta a távoli kurzort. A kurzort továbbra is CSAK az ack mozdítja.
    """
    ids = [int(i) for i in (ids or []) if isinstance(i, int) and not isinstance(i, bool) and i > 0]
    if not ids:
        return 0
    del_top = None
    init(db)
    # 7/4: a távoli oldal ackja NEM bizonyíték. Ha olyan id-t jelentene kézbesítettnek, amit a
    # kikényszerítés VÉGLEGESEN elutasít (pl. stale-ts), akkor a read_at-jelölés + a `remote_delivered` sor
    # HAMISAN zárná le a nyitott enforce_reject nyomot. Az ilyen id-ket kivesszük, és külön sorban rögzítjük.
    refused = sorted(_permanent_rejects(agent, ids, db=db))
    if refused:
        ids = [i for i in ids if i not in set(refused)]
        cr = _conn(db)
        try:
            with cr:
                for _i in refused:
                    _append_audit(cr, agent, _i, _i, "remote_delivered_refused", 0)
        finally:
            cr.close()
    if not ids:
        return 0
    now = int(time.time())
    top = max(ids)
    # az "olvasatlan" NEM azonos a "kiadhatóval" — egy termék-módban elutasított
    # (pl. stale-ts) sor olvasatlan marad, de sosem adható ki. A vízszint a KIADHATÓ prefix teteje, ezért a
    # kiadható halmazt ugyanazzal a szűrővel kérdezzük le, amivel a recv dolgozik (a tranzakció ELŐTT).
    try:                                               # a kiadható MELLETT az átmenetileg elutasított is blokkol
        pend = pending_blocking_ids(agent, db=db)
    except Exception:
        pend = None
    c = _conn(db)
    try:
        c.execute("BEGIN IMMEDIATE")
        c.executemany("UPDATE messages SET read_at=? WHERE id=? AND recipient=? AND read_at IS NULL",
                      [(now, i, agent) for i in ids])
        # a delivered_id HIGH-WATER invariánsa (INV-A1.8) csak az ÖSSZEFÜGGŐ
        # kézbesített prefix tetejéig emelhető — a részhalmaz-kiadás (MAX) átengedte volna a strict clampet.
        if pend is None:                                       # a szűrt lekérdezés nem ment: fail-closed, marad a nyers olvasatlan
            row = c.execute("SELECT MIN(id) AS m FROM messages WHERE recipient=? AND read_at IS NULL", (agent,)).fetchone()
            first_unread = row["m"] if row and row["m"] is not None else None
        else:                                                  # a KIADHATÓ és még OLVASATLAN sorok közül a legkisebb
            unread = {r["id"] for r in c.execute("SELECT id FROM messages WHERE recipient=? AND read_at IS NULL", (agent,))}
            left = [i for i in pend if i in unread and i not in set(ids)]
            first_unread = min(left) if left else None
        top_row = c.execute("SELECT MAX(id) AS x FROM messages WHERE recipient=?", (agent,)).fetchone()
        prefix_top = (first_unread - 1) if first_unread is not None else (top_row["x"] if top_row and top_row["x"] else 0)
        # C: a MAX egy KÉSŐBB beérkezett, alacsonyabb id-jű olvasatlan üzenet fölött is megtartotta
        # volna a régi vízszintet -> a delivered_id az ÖSSZEFÜGGŐ prefix ÚJRASZÁMOLT értéke (a read_at az igazság).
        c.execute("INSERT INTO cursors(agent,last_seen_id,delivered_id) VALUES(?,0,?) ON CONFLICT(agent) DO UPDATE SET "
                  "delivered_id=excluded.delivered_id", (agent, prefix_top))
        # a KÉZBESÍTÉS ténye külön, hash-láncolt sor -> a korábbi enforce_reject „lezárul" rá
        for _i in sorted(set(ids)):                        # ID-SZINTŰ sor; a tartomány a köztes, NEM kézbesített
            _append_audit(c, agent, _i, _i, "remote_delivered", 0)   # id-t is „lezárta" volna (hamis némaság)
        c.execute("COMMIT")
        return len(ids)
    finally:
        c.close()


def cursor_of(agent, db=None):
    """Az agent kurzora (last_seen_id; 0, ha még nincs)."""
    init(db)
    c = _conn(db)
    try:
        row = c.execute("SELECT last_seen_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        return row["last_seen_id"] if row else 0
    finally:
        c.close()


def ack(agent, upto, db=None):
    """A kurzor előre-mozgatása. HARDENED: a cél `max(jelenlegi, min(upto, MAX(id)))` → CSAK ELŐRE
    és SOSEM a valós üzeneteken túl. A1-L3 strict (opt-in): a high-water HELYETT a delivered_id-ig clamp-el → egy egy-lépéses
    `ack --upto BIG` nem ugorhat KÉZBESÍTETLEN fölé (a naiv/egy-lépéses delivery-tagadás ellen; a 2-lépéses a remote tier)."""
    init(db)
    c = _conn(db)
    with c:
        base, tgt = _ack_target(c, agent, upto, db=db)
        if tgt > base:
            # A1-L1: az ack NEM kézbesítés — a (base,tgt] tartomány OLVASATLANjai (read_at IS NULL) = potenciálisan
            # kézbesítés nélkül átugrott üzenetek. Egy nagy `skipped_undelivered` egy ack-soron = gyanús ugrás (tamper-evidens).
            skipped = c.execute("SELECT COUNT(*) FROM messages WHERE recipient=? AND id>? AND id<=? AND read_at IS NULL",
                                (agent, base, tgt)).fetchone()[0]
            _append_audit(c, agent, base, tgt, "ack", skipped)
        c.execute("INSERT INTO cursors(agent,last_seen_id) VALUES(?,?) "
                  "ON CONFLICT(agent) DO UPDATE SET last_seen_id=excluded.last_seen_id", (agent, tgt))
        c.execute("UPDATE messages SET read_at=COALESCE(read_at,?) WHERE recipient=? AND id<=?",
                  (time.time_ns(), agent, tgt))
    c.close()


def reconcile(agent, db=None):
    """A1-L2 (HELYREÁLLÍTÁS, advisory): a kézbesítés NÉLKÜL átugrott üzenetek. A1-L3 óta EGZAKT (a túl-listázó audit-jump-
    heurisztika helyett): a `delivered_id < id <= cursor` tartomány = a kurzor fölé mozdult, de SOSEM kézbesített üzenetek
    (mark-only delivered_id; INV-A1.8). Kizárja a MÁR újrakézbesítetteket (kind='replay', in_reply_to=orig_id) és magukat a
    replay-üzeneteket. CSAK listáz."""
    init(db)
    c = _conn(db)
    try:
        replayed = {r[0] for r in c.execute(
            "SELECT in_reply_to FROM messages WHERE kind='replay' AND in_reply_to IS NOT NULL")}
        row = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent=?", (agent,)).fetchone()
        cursor = row["last_seen_id"] if row else 0
        delivered = row["delivered_id"] if row else 0
        out = []
        for m in c.execute("SELECT * FROM messages WHERE recipient=? AND id>? AND id<=? AND kind IS NOT 'replay' "
                           "ORDER BY id", (agent, delivered, cursor)):
            if m["id"] in replayed:
                continue
            out.append(dict(m))
        # a termék-módban ELUTASÍTOTT sorok (enforce_reject audit) akkor is jelöltek, ha egy
        # későbbi elfogadott sor a delivered_id-t fölébük emelte — különben a mentőöv vak lenne rájuk.
        have = {m["id"] for m in out}
        extra = {}
        # egy enforce_reject sor NYITOTT, amíg NINCS utána ugyanarra az id-re kézbesítést rögzítő sor
        # (recv_mark / remote_delivered) — különben a később rendben kiadott posta hamis vádat kapna.
        arows = [dict(a) for a in c.execute("SELECT id, from_id, to_id, op FROM cursor_audit WHERE agent=? ORDER BY id",
                                            (agent,))]
        for i, a in enumerate(arows):
            if not str(a["op"]).startswith("enforce_reject"):
                continue
            mid = a["from_id"]
            # CSAK a tényleges kézbesítés zár (remote_delivered). A recv_mark sor tartománya a rejected id-t is fedi,
            # pedig azt NEM kézbesítette — azzal a hamis vád helyett hamis NÉMASÁG keletkezne.
            closed = any(str(b["op"]) == "remote_delivered" and b["from_id"] <= mid <= b["to_id"] for b in arows[i + 1:])
            if not closed:
                extra.setdefault(mid, a["op"].partition(":")[2] or "enforce_reject")
        for mid in sorted(set(extra) - have - replayed):
            m = c.execute("SELECT * FROM messages WHERE id=? AND recipient=? AND kind IS NOT 'replay'",
                          (mid, agent)).fetchone()          # az audit-sor a jel, nem a read_at (az ack mindent beállít)
            if m:
                out.append({**dict(m), "enforce": extra[mid]})
        for m in out:
            if m["id"] in extra:
                m["enforce"] = extra[m["id"]]
        out.sort(key=lambda m: m["id"])
    finally:
        c.close()
    return out


def replay(agent, *, commit=False, limit=100, db=None):
    """A1-L2: a kihagyott-kézbesítetlen üzenetek ÚJRAKÉZBESÍTÉSE — NEM kurzor-visszatekerés (a forward-only invariáns
    terhelt: L1 tamper-evidence + remote I4(a) monoton seq-anchor), hanem ÚJ üzenet (from=system, kind='replay',
    in_reply_to=orig_id, új id>kurzor). A no-deletion miatt az eredeti megvan a másoláshoz. `commit=False` → dry-run
    (csak megmutatja mit tenne); a tényleges replay OPERÁTOR-HÍVOTT (azonos-uid lokálisan → replay-flood kockázat)."""
    cands = reconcile(agent, db=db)[:max(0, int(limit))]
    c0 = _conn(db)                                             # IDEMPOTENCIA — amit már replay-eltünk, nem ismételjük
    try:
        already = set()
        for a in c0.execute("SELECT from_id, to_id FROM cursor_audit WHERE agent=? AND op='replay'", (agent,)):
            already.add(a["from_id"])
            already.add(a["to_id"])                            # 7/3: a MÁSOLAT sem replay-elhető újra
    finally:                                                   # (különben a kézbesítetlen másolat másolatot szülne: flood)
        c0.close()
    cands = [m for m in cands if m["id"] not in already]
    if _product_hint(db):                                      # a VÉGLEGESEN elutasított sor (pl. stale-ts) újra elbukna
        try:
            import bus_enforce as enf
            cands = [m for m in cands if enf.check(dict(m), seen=None, record=False)[0]
                     or enf.check(dict(m), seen=None, record=False)[1] in TRANSIENT_REJECT]
            _filtered = True
        except Exception as _e:
            # Ez az ág `pass` volt: ha a kapu nem futtatható, a VÉGLEGESEN elutasított sor is visszakerülhet a
            # mentőcsónakba — csendben. A szűrés HIÁNYA harmadik állapot, nem „rendben".
            # (mérve): az első javításom a `warning`-ot CSAK a száraz ágra tette,
            # a KÁR viszont a commit-ágon áll be (a véglegesen elutasított sor aláírt másolata bekerül a DB-be),
            # és ott néma maradt. Két változás: (a) a jelzés a commit-ág válaszába is bekerül, (b) TERMÉK-MÓDBAN
            # a hiányzó kapu FAIL-CLOSED — mentőcsónak kapu nélkül nem ír tartós állapotot. A száraz futás
            # (`commit=False`) továbbra is megmutatja, MIT csinálna, tehát van menekülő út a diagnózishoz.
            _filtered = False
            _lifeboat_warn = "enforce_filter_unavailable:%s" % _e.__class__.__name__
    if not commit:
        _out = {"committed": False, "would_replay": [{"orig": m["id"], "from": m["sender"]} for m in cands]}
        if locals().get("_lifeboat_warn"):
            _out["warning"] = _lifeboat_warn
        return _out
    done = []
    product = _product_hint(db)
    if locals().get("_lifeboat_warn") and product:
        # fail-closed: a kapu nem futott, tehát nem tudjuk, hogy a sor VÉGLEGESEN elutasított-e
        return {"committed": False, "replayed": [], "warning": _lifeboat_warn,
                "refused": "the enforcement gate could not run, so the lifeboat did not write anything "
                           "(product mode); run with commit=False to see what it would replay"}
    for m in cands:
        if product and m.get("sig"):
            # termék-módban a replay az EREDETI, ALÁÍRT sort viszi át
            # épen (új id, azonos aláírt mezők) — a becsomagolt `system`-üzenetet a kikényszerítés `unsigned-downgrade`
            # miatt eldobta, tehát a mentőöv „listáz, de nem kézbesít" volt. Az aláírt bájtkép (v,sender,recipient,
            # topic,kind,in_reply_to,body,ts) VÁLTOZATLAN marad, ezért az aláírás továbbra is érvényes.
            cc = _conn(db)
            try:                                   # (TOCTOU): a MÁSOLAT és a napló-sor EGY írózáras tranzakcióban
                cc.execute("BEGIN IMMEDIATE")      # -> két párhuzamos operátor-replay közül a második nem duplikál
                if cc.execute("SELECT 1 FROM cursor_audit WHERE agent=? AND op='replay' AND from_id=?",
                              (agent, m["id"])).fetchone():
                    cc.execute("ROLLBACK")
                    continue
                cur = cc.execute("INSERT INTO messages(sender,recipient,kind,topic,thread_id,in_reply_to,body,ts,read_at,"
                                 "sig,pubkey) VALUES(?,?,?,?,?,?,?,?,NULL,?,?)",
                                 (m["sender"], agent, m["kind"], m["topic"], m["thread_id"], m["in_reply_to"],
                                  m["body"], m["ts"], m["sig"], m["pubkey"]))
                new_id = cur.lastrowid
                _append_audit(cc, agent, m["id"], new_id, "replay", 0)
                cc.execute("COMMIT")
            except sqlite3.IntegrityError:         # ux_replay_once: valaki megelőzött -> nem gyártunk másodikat
                cc.execute("ROLLBACK")
                continue
            finally:
                cc.close()
            done.append({"orig": m["id"], "new": new_id, "mode": "signed-copy"})
            continue
        body = "[replay #%d ← %s] %s" % (m["id"], m["sender"], m["body"] or "")
        new_id = send("system", agent, body, topic=m["topic"] or "", kind="replay",
                      thread_id=m["thread_id"], in_reply_to=m["id"], db=db)
        cc = _conn(db)
        with cc:
            _append_audit(cc, agent, m["id"], new_id, "replay", 0)   # a replay-esemény is a hash-láncba kerül
        cc.close()
        done.append({"orig": m["id"], "new": new_id})
    _res = {"committed": True, "replayed": done}
    if locals().get("_lifeboat_warn"):          # dev-mód: átmegy, de NEM néma
        _res["warning"] = _lifeboat_warn
    return _res


def audit(agent=None, *, limit=50, db=None):
    """A1-L1: a kurzor-mozgás napló (legutóbbi sorok). agent szűkít; None = mind."""
    init(db)
    c = _conn(db)
    if agent:
        rows = c.execute("SELECT * FROM cursor_audit WHERE agent=? ORDER BY id DESC LIMIT ?", (agent, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM cursor_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]


def audit_verify(agent=None, db=None):
    """A1-L1 tamper-EVIDENCIA (FAIL-CLOSED): a per-agent hash-láncot ellenőrzi. Aki a kurzort mozdította és a naplót
    átírta/törölte (NEM determinált same-uid, hanem baleseti/naiv/inkonzisztens), itt BUKIK: lánc-törés
    (prev_row_hash≠előző row_hash) VAGY row_hash-újraszámítás-eltérés → ok=False. Never-throw → dict; beszúrt sor DETEKTÁLT, nem DoS.
    (A determinált same-uid támadó konzisztensen újraláncol → ellene csak külső tanú/remote tier véd; lásd a fenti recalibrációt.)"""
    init(db)
    out = {"ok": True, "checked": 0, "pre_chain": 0, "problems": []}
    try:
        c = _conn(db)
        try:
            agents = ([agent] if agent
                      else [r[0] for r in c.execute("SELECT DISTINCT agent FROM cursor_audit ORDER BY agent")])
            for ag in agents:
                # fix: a LEGACY (pre-chain, row_hash IS NULL) sorokat NEM ellenőrizzük (nem flageljük tamper-ként,
                # csak számoljuk) — a lánc GENESIS-ből az első LÁNCOLT (row_hash NOT NULL) sortól. No-deletion: a legacy sorok maradnak.
                out["pre_chain"] += c.execute(
                    "SELECT COUNT(*) FROM cursor_audit WHERE agent=? AND row_hash IS NULL", (ag,)).fetchone()[0]
                prev = _GENESIS
                for r in c.execute("SELECT * FROM cursor_audit WHERE agent=? AND row_hash IS NOT NULL ORDER BY id", (ag,)):
                    out["checked"] += 1
                    if r["prev_row_hash"] != prev:
                        out["problems"].append("%s seq=%s: lánc-törés (prev_row_hash≠előző) — beszúrt/törölt sor" % (ag, r["seq"]))
                        break
                    rh = _audit_row_hash(r["seq"], r["ts"], ag, r["op"], r["from_id"], r["to_id"], r["skipped_undelivered"], r["prev_row_hash"])
                    if rh != r["row_hash"]:
                        out["problems"].append("%s seq=%s: row_hash mismatch — átírt sor" % (ag, r["seq"]))
                        break
                    prev = r["row_hash"]
        finally:
            c.close()
    except sqlite3.Error as e:
        out["problems"].append("db: %s" % e)
    out["ok"] = not out["problems"]
    return out


def tail(agent=None, *, limit=20, db=None):
    init(db)
    c = _conn(db)
    if agent:
        rows = c.execute("SELECT * FROM messages WHERE recipient=? OR sender=? ORDER BY id DESC LIMIT ?",
                         (agent, agent, limit)).fetchall()
    else:
        rows = c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]


def thread(thread_id, db=None):
    init(db)
    c = _conn(db)
    rows = c.execute("SELECT * FROM messages WHERE thread_id=? ORDER BY id", (str(thread_id),)).fetchall()
    c.close()
    return [dict(r) for r in rows]


# ── BUS-TRANSPORT SEAM (remote-tiering, 2026-06-21) — a befagyasztott kontraktus (I1) FELETT ─────
# A tier-szegmentált AgentBus (Pro=offline / Enterprise=remote) varratja. A KONTRAKTUS VÁLTOZATLAN:
# a séma (MESSAGE_COLUMNS/CURSOR_COLUMNS), a CLI, a JSON-tükör és a kurzor-szemantika BYTE-AZONOS — CSAK a
# transport cserélődik alatta (a trust-provider seam mintára). A remote security-keret: az egyik kar DESIGN_remote_agentbus.md
# (I1–I8 + 2.3 go/no-go). A Local az alapértelmezés és SOHA nem nyit hálózatot (I7/I8: offline garancia sértetlen).
from abc import ABC, abstractmethod


class BusTransport(ABC):
    """A bus transport absztrakció. A módszerek a modul-szintű API-t tükrözik (a vendorolt kliensek erre építenek)."""
    @abstractmethod
    def send(self, sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None, mirror=True, sign_key=None, presigned=None): ...
    @abstractmethod
    def recv(self, agent, *, mark=False): ...
    @abstractmethod
    def ack(self, agent, upto): ...
    @abstractmethod
    def tail(self, agent=None, *, limit=20): ...
    @abstractmethod
    def thread(self, thread_id): ...
    @abstractmethod
    def verify_schema(self): ...


class LocalBusTransport(BusTransport):
    """Pro / DEFAULT — a mai közös-lemezes SQLite `bus.db` + JSON-tükör; viselkedés 1:1. SOHA nem nyit hálózatot.
    A tényleges logika a modul-szintű függvényekben él (ez a Local-implementáció); ez a facade csak a `db`-t köti."""
    def __init__(self, db=None, inbox_root=None):
        self.db = db
        self.inbox_root = inbox_root                        # előretartott seam-paraméter (ma a _mirror_json az INBOX_ROOT-ot használja)

    def send(self, sender, recipient, body, *, topic="", kind="msg", thread_id=None, in_reply_to=None, mirror=True, sign_key=None, presigned=None):
        return send(sender, recipient, body, topic=topic, kind=kind, thread_id=thread_id,
                    in_reply_to=in_reply_to, db=self.db, mirror=mirror, inbox_root=self.inbox_root, sign_key=sign_key,
                    presigned=presigned)  # D#6: tényleg bekötve

    def recv(self, agent, *, mark=False, limit=_RECV_LIMIT):
        return recv(agent, mark=mark, limit=limit, db=self.db)

    def ack(self, agent, upto):
        return ack(agent, upto, db=self.db)

    def tail(self, agent=None, *, limit=20):
        return tail(agent, limit=limit, db=self.db)

    def thread(self, thread_id):
        return thread(thread_id, db=self.db)

    def verify_schema(self):
        return verify_schema(db=self.db)


class RemoteBusTransport(BusTransport):
    """Enterprise (sovereign) — mTLS relay-kliens a CUSTOMER-oldali relay-hez (remote/home-office koordináció).
    MÉG NEM IMPLEMENTÁLVA: a security-keret véglegesítésére
    és operátori zöldre vár — node-admisszió a vendor control-plane-en (attesztáció + entitlement-gated,
    HSM-gyökér, fail-closed), E2E koordináció (a vendor nem fejt), per-küldő aláírt szekvencia. AMÍG NEM KÉSZ: NEM nyit
    hálózatot; a kliens a LocalBusTransportra esik vissza (I7 fail-safe degradáció)."""
    def __init__(self, *a, **k):
        raise NotImplementedError(
            "RemoteBusTransport: a remote AgentBus a security-keret véglegesítésére + operátori zöldre vár "
            "(2.3 go/no-go; distributed_bus vokabulár lockstep). Addig LocalBusTransport (Pro, offline, zéró háló).")

    def send(self, *a, **k): raise NotImplementedError
    def recv(self, *a, **k): raise NotImplementedError
    def ack(self, *a, **k): raise NotImplementedError
    def tail(self, *a, **k): raise NotImplementedError
    def thread(self, *a, **k): raise NotImplementedError
    def verify_schema(self): raise NotImplementedError


def default_transport():
    """A jelen (Pro) transport: LocalBusTransport. A tier-választás (Local/Remote) később a connected-SKU + entitlement
    dolga lesz (I5: érvényes Enterprise + distributed_bus → Remote; különben fail-safe Local). MA mindig Local, zéró háló."""
    return LocalBusTransport()


def _scrub(s):
    """R3-A3: a CLI-megjelenítésből KISZŰRJÜK a terminál-vezérlőket (ANSI ESC, CR, NL, egyéb C0/C1) — különben egy
    attacker-küldte body/sender/topic `\\x1b[…`/`\\r`-rel FELÜLÍRHATNÁ a `tail`/`recv`/`thread` sorát és HAMIS
    '[operator→… APPROVED]' bejegyzést forgolhatna az operátor terminálján (bus=ADAT, a megjelenítés nem mutálhat)."""
    return "".join(ch if (ch >= " " and ch != "\x7f" and not (0x80 <= ord(ch) <= 0x9f)) else "·"
                   for ch in (s or ""))


def _fmt(m):
    rd = "·read" if m.get("read_at") else ""
    if m.get("sds"):
        rd += " sds:" + _scrub(m["sds"])
    return "[#%s %s→%s %s/%s%s] %s" % (m["id"], _scrub(m["sender"]), _scrub(m["recipient"]),
                                        _scrub(m.get("topic")) or "-", _scrub(m.get("kind")) or "-", rd,
                                        _scrub((m["body"] or "")[:200]))


def main(argv=None):
    p = argparse.ArgumentParser(prog="agent_bus")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    s = sub.add_parser("send")
    s.add_argument("--from", dest="sender", required=True); s.add_argument("--to", dest="recipient", required=True)
    s.add_argument("--body", required=True); s.add_argument("--topic", default=""); s.add_argument("--kind", default="msg")
    s.add_argument("--thread", default=None); s.add_argument("--reply", type=int, default=None)
    s.add_argument("--no-mirror", action="store_true")
    s.add_argument("--sign-key", dest="sign_key", default=None, help="A2: 32-bájtos hex Ed25519 seed útvonala → a feladás aláírva (opcionális)")
    r = sub.add_parser("recv"); r.add_argument("--agent", required=True); r.add_argument("--mark", action="store_true")
    r.add_argument("--limit", type=int, default=_RECV_LIMIT)
    r.add_argument("--verify-sds", dest="verify_sds", action="store_true", help="v1.1: sds-envelope sorok ellenőrzése")
    r.add_argument("--strict-sds", dest="strict_sds", action="store_true", help="v1.1: csak a valid sds-envelope sorok (a többi kind marad)")
    r.add_argument("--sds-admission", dest="sds_admission", default=None, help="v1.1: helyi admission-fájl (vagy AGENT_BUS_SDS_ADMISSION)")
    a = sub.add_parser("ack"); a.add_argument("--agent", required=True); a.add_argument("--upto", type=int, required=True)
    t = sub.add_parser("tail"); t.add_argument("--agent", default=None); t.add_argument("--limit", type=int, default=20)
    th = sub.add_parser("thread"); th.add_argument("--id", required=True)
    v = sub.add_parser("verify"); v.add_argument("--json", action="store_true")
    au = sub.add_parser("audit"); au.add_argument("--agent", default=None); au.add_argument("--limit", type=int, default=50)
    sub.add_parser("doctor")                                   # v1.4: termék-profil állapota (hangos figyelmeztetés dev módban)
    avf = sub.add_parser("audit-verify"); avf.add_argument("--agent", default=None); avf.add_argument("--json", action="store_true")
    # a kikényszerített politika ("hiányos bizonyíték") eddig egy NEM LÉTEZŐ parancsra
    # küldte az üzemeltetőt — a `--bus-audit` fájlt semmi szállított parancs nem állította elő. Itt van.
    axp = sub.add_parser("audit-export", help="a busz hash-láncolt cursor_audit sorai JSONL-ben (bus_notary --bus-audit bemenete)")
    axp.add_argument("--agent", required=True)
    axp.add_argument("--from-seq", dest="from_seq", type=int, default=0)
    rc = sub.add_parser("reconcile"); rc.add_argument("--agent", required=True)  # A1-L2: kihagyott-kézbesítetlen listája
    rp = sub.add_parser("replay"); rp.add_argument("--agent", required=True)
    rp.add_argument("--commit", action="store_true", help="ténylegesen újrakézbesít (különben dry-run); OPERÁTOR-hívott")
    rp.add_argument("--limit", type=int, default=100)
    args = p.parse_args(argv)

    if args.cmd == "init":
        init(); print("bus init: %s" % DB)
    elif args.cmd == "send":
        try:                                                    # R3-I#3/D#1: a CLI never-throw — a kapu-ValueError sosem nyers traceback
            rid = send(args.sender, args.recipient, args.body, topic=args.topic, kind=args.kind,
                       thread_id=args.thread, in_reply_to=args.reply, mirror=not args.no_mirror, sign_key=args.sign_key)
        except ValueError as e:
            sys.stderr.write("send refused: %s\n" % e)
            return 2
        print("sent #%d (%s→%s)" % (rid, args.sender, args.recipient))
    elif args.cmd == "recv":
        for m in recv(args.agent, mark=args.mark, limit=args.limit, verify_sds=args.verify_sds,
                      strict_sds=args.strict_sds, sds_admission=args.sds_admission):
            print(_fmt(m))
    elif args.cmd == "ack":
        ack(args.agent, args.upto); print("ack %s → #%d" % (args.agent, args.upto))
    elif args.cmd == "tail":
        for m in tail(args.agent, limit=args.limit):
            print(_fmt(m))
    elif args.cmd == "thread":
        for m in thread(args.id):
            print(_fmt(m))
    elif args.cmd == "verify":
        res = verify_schema()
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
        else:
            tag = "OK" if res["ok"] else "DRIFT"
            print("[%s] schema v%s (db pinned: %s)" % (tag, res["schema_version"], res["pinned"]))
            for pr in res["problems"]:
                print("  ! " + pr)
            if res.get("added_columns"):
                print("  + additive columns: " + ", ".join(res["added_columns"]))
        return 0 if res["ok"] else 1
    elif args.cmd == "doctor":                                  # v1.4: kikényszerítés állapota
        bus_enforce = _enforce_module()
        if bus_enforce is None:
            sys.stderr.write("!!! bus_enforce modul hiányzik — a kikényszerítés nem elérhető (termék-jel: %s)\n"
                             % ("igen, a recv fail-closed" if _product_hint() else "nincs"))
            return 1
        ok, lines = bus_enforce.doctor()
        for ln in lines:
            (sys.stdout if ok else sys.stderr).write(ln + "\n")
        return 0 if ok else 1
    elif args.cmd == "audit":                                   # A1-L1: kurzor-mozgás napló
        for r in audit(args.agent, limit=args.limit):
            flag = "  ⚠ SKIPPED %d" % r["skipped_undelivered"] if r["skipped_undelivered"] else ""
            print("[#%s %s %s: #%s→#%s]%s" % (r["id"], _scrub(r["agent"]), r["op"], r["from_id"], r["to_id"], flag))
    elif args.cmd == "audit-export":                            # a MÁSODIK nyilvántartás gépi alakja
        rows = audit_export(args.agent, from_seq=max(0, args.from_seq))
        for r in rows:
            print(json.dumps(r, ensure_ascii=False, sort_keys=True))
        # a szelet horgonya a hívónak (a reconcile termék-módban horgonyzott szeletet követel): seq 0 + GENESIS
        # prev = teljes lánc; egyébként a hívónak csatornán kívül kell tudnia a kezdő row_hash-t.
        if rows and rows[0]["seq"] != 0:
            sys.stderr.write("audit-export: RÉSZSZELET a %d. sortól — a teljes lánc: --from-seq 0; a horgony a "
                             "megelőző sor row_hash-e: %s\n" % (rows[0]["seq"], rows[0]["prev_row_hash"]))
        return 0
    elif args.cmd == "audit-verify":                            # A1-L1: tamper-evidencia (hash-lánc)
        res = audit_verify(args.agent)
        if args.json:
            print(json.dumps(res, ensure_ascii=False))
        else:
            print("[%s] audit-chain (%d sor ellenőrizve)" % ("OK" if res["ok"] else "TAMPER", res["checked"]))
            for pr in res["problems"]:
                print("  ! " + pr)
        return 0 if res["ok"] else 1
    elif args.cmd == "reconcile":                               # A1-L2: mit kellene újrakézbesíteni
        rows = reconcile(args.agent)
        print("reconcile %s: %d kihagyott-kézbesítetlen jelölt" % (args.agent, len(rows)))
        for m in rows:
            print("  " + _fmt(m))
    elif args.cmd == "replay":                                  # A1-L2: újrakézbesítés (commit nélkül dry-run)
        res = replay(args.agent, commit=args.commit, limit=args.limit)
        if not res["committed"]:
            print("DRY-RUN — %d üzenet újrakézbesítésre jelölve (--commit a végrehajtáshoz):" % len(res["would_replay"]))
            for w in res["would_replay"]:
                print("  #%s (← %s)" % (w["orig"], w["from"]))
        else:
            print("REPLAY kész — %d üzenet újrakézbesítve:" % len(res["replayed"]))
            for d in res["replayed"]:
                print("  #%s → új #%s" % (d["orig"], d["new"]))


if __name__ == "__main__":
    sys.exit(main() or 0)
