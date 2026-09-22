#!/usr/bin/env python3
"""bus_enforce — KIKÉNYSZERÍTÉS. A támadási mátrix v0 fő lelete: a mai gyengeség NEM
kriptográfiai, hanem kikényszerítési — a busz annotál, a döntést a fogadóra bízza, és a default ezt megengedi. A támadó
nem az aláírást töri meg, hanem ELHAGYJA (unsigned-downgrade). Ez a modul a termék-profil kapuja.

Két üzemmód (egyetlen kapcsoló):
- **dev** (alapértelmezett, ha semmi nincs beállítva): a mai back-compat viselkedés — az élő flotta nem törik el.
- **product**: `AGENT_BUS_MODE=product` VAGY a `.product_mode.on` marker a busz könyvtárában. Ekkor a recv/verify
  ELUTASÍT (nem csak jelöl):
    * aláíratlan üzenet                              → `unsigned-downgrade`
    * érvénytelen aláírás / registry-kulcs eltérés    → `forged`
    * az aláírt `ts` az ablakon kívül (múlt / jövő)   → `stale-ts` / `future-ts`
    * ugyanaz az aláírt tartalom másodszor            → `replay` — tartós seen-tár,
      újraindítás után is
    * `attachment` kind, ha a leíró nem az aláírt body része / hiányos → `attachment-descriptor`
A termék-/kiadási profil a product módot állítja be; a `abus doctor` hangosan figyelmeztet, ha nincs bekapcsolva.

Semmi nem törlődik: az elutasított sor a DB-ben marad, az elutasítás oka a `rejected.jsonl` naplóba kerül.
A seen-tár append-only fájl (nem DB-séma) → NINCS SCHEMA_VERSION-bump.

javítások (2026-09-14):
- az ablak a feladási időre néz, a busz viszont alvó címzettre épül → alap ablak −7 nap/+300 s (a replay-
  tár fogja a duplikátumot ablak nélkül is), és az elutasított sor NEM emeli a delivered_id-t, `enforce_reject` audit-
  sort kap → a `reconcile`/`replay` látja (agent_bus.recv).
- a mód NEM kapcsolható vissza dev-be env-vel: a marker a DB MELLETT és /etc/agent-bus alatt is keresett, az env
  csak BEkapcsolhat; ismeretlen AGENT_BUS_MODE érték → product (fail-closed). Az ablak-env csak SZŰKÍTHET.
- /a kézbesítő recv seen-tára a DB-ben él (`enforce_seen` tábla, a kurzor-tranzakción belül, folyamatok
  közt atomi) — nincs külön, őrizetlen/másik UID-hez tartozó fájl. A `SeenStore` fájl-osztály megmarad (back-compat).
- rossz env → alapérték + doctor-figyelmeztetés, nem traceback; a napló-írás best-effort.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))
MODE_ENV = "AGENT_BUS_MODE"
MARKER = ".product_mode.on"
SYSTEM_MARKER = "/etc/agent-bus/product_mode.on"         # rendszerszintű, root-kezelt kapcsoló
DEFAULT_WINDOW_PAST_S = 7 * 24 * 3600                     # alvó címzett is megkapja (a replay-tár fogja a dupla)
DEFAULT_WINDOW_FUTURE_S = 300
WARNINGS = []                                             # a doctor mutatja (nem traceback)


def _env_window(name, default):
    """Ablak env-ből: CSAK szűkíthet. Érvénytelen / nem pozitív / tágító érték → alapérték + figyelmeztetés."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        WARNINGS.append("%s=%r érvénytelen → alapérték %ds" % (name, raw, default))
        return default
    if v <= 0 or v > default:
        WARNINGS.append("%s=%d figyelmen kívül (csak 1..%d szűkíthet) → %ds" % (name, v, default, default))
        return default
    return v


WINDOW_PAST_S = _env_window("AGENT_BUS_WINDOW_PAST_S", DEFAULT_WINDOW_PAST_S)
WINDOW_FUTURE_S = _env_window("AGENT_BUS_WINDOW_FUTURE_S", DEFAULT_WINDOW_FUTURE_S)


def state_dir():
    d = os.environ.get("AGENT_BUS_ENFORCE_DIR") or os.path.join(BRIDGE, "enforce")
    return d


def marker_paths(bus_dir=None, db=None):
    """A termék-mód markerének MINDEN keresési helye (unió). a DB-fájl melletti marker a döntő — egy env-vel
    átirányított AGENT_BRIDGE_DIR/AGENT_BUS_DIR csak TOVÁBBI helyet ad, a DB mellettit/rendszerszintűt nem veszi el."""
    import agent_bus as ab
    # (2026-09-17): az `abspath` a symlinket NEM oldja fel — egy marker nélküli könyvtárból a VALÓDI DB-re mutató
    # symlink dev módot adott, miközben ugyanazt a fájlt olvasta. A `realpath` a döntő hely; az abspath-os hely MARAD
    # mellette (unió: több hely = fail-closed a termék-mód felé, sosem kevesebb).
    dbp = db or ab.DB
    paths = [SYSTEM_MARKER,
             os.path.join(os.path.dirname(os.path.realpath(dbp)), MARKER),
             os.path.join(os.path.dirname(os.path.abspath(dbp)), MARKER)]
    for base in (bus_dir, os.environ.get("AGENT_BUS_DIR"), BRIDGE):
        if base:
            paths.append(os.path.join(os.path.realpath(base), MARKER))
            paths.append(os.path.join(base, MARKER))
    return list(dict.fromkeys(paths))


def mode(bus_dir=None, db=None):
    """'product' ha env vagy BÁRMELYIK marker mondja, különben 'dev' (back-compat). Az env csak BEkapcsolhat: ha marker
    van, `AGENT_BUS_MODE=dev` sem kapcsol vissza. Ismeretlen érték (pl. 'production', 'prod') → product.
    A NÉMA VISSZAESÉS elleni védelem NEM külön mechanizmus: a root-kezelt `SYSTEM_MARKER`
    (/etc/agent-bus/product_mode.on) pontosan ezt adja — azt csak root törölheti, a busz-melletti markert viszont
    bárki, aki a buszra ír. A „ragadós termék-mód" (a busz megjegyzi, hogy futott már termék-módban) MEGÉPÜLT és
    KÉTSZER VISSZAVONVA: mérve mindkétszer a TERMELŐ busz DB-jét olvasta/írta olyan hívásokból, amik csak mérésnek
    készültek (a modul-szintű út feloldása miatt), és 20 tesztet döntött be. A helyes lépés üzemeltetői: tedd ki a
    root-tulajdonú markert; ezt a `doctor()` hangosan meg is követeli."""
    raw = os.environ.get(MODE_ENV, "").strip().lower()
    if raw and raw != "dev":
        return "product"
    return "product" if any(os.path.exists(p) for p in marker_paths(bus_dir, db)) else "dev"


class DbSeenStore:
    """/a replay-tár a busz-DB-ben (`enforce_seen`), a HÍVÓ kapcsolatán/tranzakcióján → a kurzor-mozgással
    atomi, folyamatok közt szerializált (BEGIN IMMEDIATE), és pontosan annyira védett, mint maguk az üzenetek (aki ezt
    törölni tudja, az a messages-t is átírhatja). Lusta tábla (verify_schema csak a mag-táblákat nézi) → nincs séma-bump."""

    def __init__(self, conn, recipient):
        self.c, self.agent = conn, recipient

    def ensure(self):
        self.c.execute("CREATE TABLE IF NOT EXISTS enforce_seen(agent TEXT NOT NULL, k TEXT NOT NULL, "
                       "ts_s INTEGER NOT NULL, PRIMARY KEY(agent, k))")

    def seen(self, key):
        import sqlite3
        try:
            return self.c.execute("SELECT 1 FROM enforce_seen WHERE agent=? AND k=?", (self.agent, key)).fetchone() is not None
        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                return False                                  # még semmi nem volt kézbesítve termék-módban
            raise

    def add(self, key, ts_s):
        cur = self.c.execute("INSERT OR IGNORE INTO enforce_seen(agent,k,ts_s) VALUES(?,?,?)", (self.agent, key, int(ts_s)))
        return cur.rowcount == 1


def content_key(msg):
    """Az aláírt tartalom azonosítója a replay-tárhoz: sha256(aláírt bájtkép || sig). Az id NEM része (egy újra
    beszúrt, azonos tartalmú sor új id-t kap — pont ezt kell megfogni)."""
    import agent_bus as ab                                     # késői import: nincs körkörös betöltés
    h = hashlib.sha256(ab._a2_content_bytes(msg))
    h.update(b"|")
    h.update((msg.get("sig") or "").encode())
    return h.hexdigest()


class SeenStore:
    """Tartós, append-only seen-tár címzettenként (JSONL: {"k", "ts_s"}). Újraindítás után is megfogja a replayt.
    Tömörítés (compact): csak a frissességi ablakon + tartalékon KÍVÜLI, már biztosan elavult kulcsokat hagyja el —
    ablakon belüli bejegyzést SOSEM (az ablakon kívüli ts-t a freshness-kapu úgyis elutasítja)."""

    def __init__(self, recipient, base=None, window_past=None):
        self.path = os.path.join(base or state_dir(), "seen_%s.jsonl" % _safe(recipient))
        self.window_past = WINDOW_PAST_S if window_past is None else window_past
        self._lock = threading.Lock()
        self._keys = None

    def _load(self):
        if self._keys is None:
            self._keys = {}
            try:
                with open(self.path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                            self._keys[r["k"]] = r.get("ts_s", 0)
                        except (ValueError, KeyError):
                            continue
            except FileNotFoundError:
                pass
        return self._keys

    def seen(self, key):
        with self._lock:
            return key in self._load()

    def add(self, key, ts_s):
        with self._lock:
            keys = self._load()
            if key in keys:
                return False
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"k": key, "ts_s": int(ts_s)}) + "\n")
                f.flush()
                os.fsync(f.fileno())
            keys[key] = int(ts_s)
            return True

    def compact(self, now_s=None):
        """Az ablak kétszeresénél régebbi kulcsok elhagyása atomi cserével. Visszaadja a megtartott darabszámot."""
        now_s = time.time() if now_s is None else now_s
        with self._lock:
            keys = self._load()
            keep = {k: t for k, t in keys.items() if now_s - t <= 2 * self.window_past}
            tmp = self.path + ".tmp"
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                for k, t in keep.items():
                    f.write(json.dumps({"k": k, "ts_s": t}) + "\n")
            os.replace(tmp, self.path)
            self._keys = keep
            return len(keep)


def _safe(s):
    s = os.path.basename(str(s or ""))
    return s if s and s not in (".", "..") else "x"


def _ts_seconds(ts):
    """A busz ts-e nanoszekundum (time.time_ns); a teszt/kézi sorok másodpercet is adhatnak."""
    try:
        v = int(ts)
    except (TypeError, ValueError):
        return None
    return v / 1e9 if v > 10**12 else float(v)


def attachment_ok(msg):
    """Az attachment leíró az ALÁÍRT body-ban él (a body része az aláírt mezőknek, _A2_SIGNED_FIELDS), és a bus_attach
    zárt leíró-szerződésének megfelel — ugyanaz a validátor, amit a send is használ (nincs második, eltérő szabály)."""
    import bus_attach
    try:
        bus_attach.check_descriptor(msg.get("body") or "")
        return True
    except ValueError:
        return False


def check(msg, *, now_s=None, seen=None, record=False, keys_dir=None,
          window_past=None, window_future=None):
    """Egy recv-elt sor termék-módú ítélete → (ok: bool, ok_vagy_ok: str). `record=True` esetén (kézbesítő recv)
    az elfogadott tartalom bekerül a seen-tárba; peek-nél csak ellenőriz, nem fogyaszt."""
    import agent_bus as ab
    now_s = time.time() if now_s is None else now_s
    wp = WINDOW_PAST_S if window_past is None else window_past
    wf = WINDOW_FUTURE_S if window_future is None else window_future
    auth = ab.verify_sender(msg, keys_dir=keys_dir)
    if auth == "unsigned":
        return False, "unsigned-downgrade"
    if auth == "unsigned-pinned":
        # csupasz sor egy aláírásra képes (pinelt) név alatt — külön ok, nem olvad az unsigned-ba
        return False, "unsigned-pinned"
    if auth != "signed":
        return False, "forged"
    ts = _ts_seconds(msg.get("ts"))
    if ts is None:
        return False, "stale-ts"
    if now_s - ts > wp:
        return False, "stale-ts"
    if ts - now_s > wf:
        return False, "future-ts"
    if (msg.get("kind") or "") == "attachment" and not attachment_ok(msg):
        return False, "attachment-descriptor"
    if record and seen is None:
        # Saját a `record=True` FOGYASZTÁST jelent — seen-tár nélkül a replay-védelem némán kimarad.
        # A peek/osztályozó hívások `record=False`-szal jönnek; ez az ág programozói hiba, nem üzemi állapot.
        raise ValueError("record=True esetén kötelező a seen-tár (replay-védelem)")
    if seen is not None:
        key = content_key(msg)
        if seen.seen(key):
            return False, "replay"
        if record and not seen.add(key, ts):
            # Saját a `seen()` és az `add()` között versenyhelyzet van (két párhuzamos recv). Az
            # `add()` FALSE-a ("már bent volt") az egyetlen atomi jel — enélkül mindkét fél kézbesített volna.
            return False, "replay"
    return True, "ok"


def log_rejected(agent, msg, reason, base=None):
    """Az elutasítás naplója (append-only; a sor maga a DB-ben marad — semmi nem törlődik)."""
    # /best-effort — egy nem írható (más UID-é, nem könyvtár) napló-hely SOSEM dönti be a recv-et;
    # a mérvadó nyom az `enforce_reject` audit-sor a DB-ben. -> True ha íródott.
    try:
        p = os.path.join(base or state_dir(), "rejected.jsonl")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": int(time.time()), "agent": agent, "id": msg.get("id"),
                                "sender": msg.get("sender"), "kind": msg.get("kind"), "reason": reason}) + "\n")
        return True
    except (OSError, ValueError):
        return False


def doctor():
    """Állapot-jelentés a termék-profilhoz. -> (ok: bool, sorok: list[str])."""
    import agent_bus as ab
    lines, ok = [], True
    m = mode()
    if m != "product":
        ok = False
        lines.append("!!! FIGYELEM: a busz DEV módban fut — aláíratlan és elavult üzenetet is kézbesít. "
                     "Termék-profilhoz: AGENT_BUS_MODE=product vagy %s marker." % MARKER)
    else:
        lines.append("mode: product (aláírás kötelező, ts-ablak -%ds/+%ds, replay-tár: %s)" % (WINDOW_PAST_S, WINDOW_FUTURE_S, state_dir()))
    # (2026-09-17): a mód FOLYAMATONKÉNT dől el (env + fájl-létezés), a doctor a SAJÁT környezetében mér. Egy
    # másik folyamat ugyanabban a pillanatban dev-ben futhat. A verdikt hatóköre ezért KIMONDVA kisebb, mint a
    # termék-profil (flotta-szintű) ígérete; ami flotta-szinten áll, az a root-kezelt SYSTEM_MARKER léte.
    lines.append("scope: ez a verdikt ERRE a folyamatra áll (env %s=%r + marker-létezés); más folyamat más módban futhat. "
                 "Flotta-szintű állítást csak a root-kezelt %s ad%s."
                 % (MODE_ENV, os.environ.get(MODE_ENV, ""), SYSTEM_MARKER,
                    " — MEGVAN" if os.path.exists(SYSTEM_MARKER) else " — NINCS"))
    for w in WARNINGS:
        lines.append("! " + w)
    for p in marker_paths():
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_uid != 0 or (st.st_mode & 0o022):
            lines.append("! a marker (%s) nem root-tulajdonú vagy csoport/világ-írható — bárki törölheti; "
                         "javasolt: %s (root, 0644)" % (p, SYSTEM_MARKER))
    # Saját ha a termék-mód KIZÁRÓLAG egy busz-melletti markeren áll, akkor aki üzenetet tud
    # beszúrni, a markert is törölheti -> a kapu NÉMÁN dev-re esik, és onnantól aláíratlan sort is kézbesít.
    if m == "product" and not os.environ.get(MODE_ENV, "").strip() and not os.path.exists(SYSTEM_MARKER):
        ok = False
        lines.append("!!! a termék-mód CSAK busz-melletti markeren áll (%s nincs, env nincs) — aki a buszra írni tud, "
                     "a markert is törölheti, és a kapu némán dev-re esik. Tegyél root-tulajdonú markert: %s"
                     % (SYSTEM_MARKER, SYSTEM_MARKER))
    if not ab._A2_HAVE:
        ok = False
        lines.append("!!! a 'cryptography' csomag hiányzik — aláírás nem ellenőrizhető (product módban minden sor forged)")
    return ok, lines
