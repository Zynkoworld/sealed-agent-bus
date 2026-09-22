#!/usr/bin/env python3
"""bus_singleflight — strukturális collision-védelem a tmux-Claude agentekre (az üzemeltető 2026-06-25).

## A probléma, amit megold

A `bus_poke` egy MÁR FUTÓ tmux-session paneljébe injektál „nézd meg a postád" promptot. Ha
ugyanazon identitásból KÉT Claude-instancia fut (egy operátor-nyitott + egy
poke-hajtott), MINDKETTŐ ráfut ugyanarra az inbox-üzenetre és ugyanazt a munkát végzi el —
duplikált/elavult edit (2026-06-25: két az egyik kar ugyanazt a VERSION-bumpot csinálta, az egyik
beragadt egy elavult `old_string`-re). A busz hagyja üzengetni az agenteket, de NEM kényszerít
ki munka-claimet → a gyökér megoldatlan.

Ez a modul a strukturális kapu, két, determinista, stdlib-only mechanizmussal:

1. **Session-lock** (`SessionLock`): egy aktív worker / agent-identitás. Induláskor egy instancia
   atomian (`O_EXCL`) megfogja a `wake/<agent>.session.lock`-ot. Ha él egy másik tulajdonos, az
   új instancia tudja, hogy DUPLIKÁTUM → nem végez autonóm draint, az operátort kiszolgálja, de
   a buszt a tulajdonosra hagyja. Halott tulajdonos lockja stale → atomian visszaigényelhető
   (requeue-on-death). NINCS TÖRLÉS: a lock-fájl tartalma audit-olható, csak felülíródik.

2. **Üzenet-claim** (`MessageClaim`): defense-in-depth a tranziens átfedésre. Egy inbox-üzenet
   kezelése ELŐTT az instancia atomian (`os.rename`) átmozgatja a sajátjába
   (`inbox/<agent>/.claimed/<instance>/<name>`). A rename-t a POSIX pontosan egy hívónak engedi;
   a vesztes `FileNotFoundError`-t kap és kihagyja. Halott claimer üzenetei requeue-olódnak
   (vissza a `pending`-be — MOZGATÁS, nem törlés).

Mindkettő pid-liveness-re épül (`os.kill(pid, 0)`, box-lokális). A pid-újrahasznosítás ellen a védelem
ÁGANKÉNT MÁS, és itt kimondjuk:
  - SessionLock `ttl`-ág és a MessageClaim könyvtár-frissessége → TTL;
  - SessionLock `pid`-ág és a `target`+owner-ág → NINCS TTL (egy tartós owner-pid zárját egy óra nem
    járathatja le), helyette PID-SZÜLETÉS-AZONOSSÁG: az acquire eltárolja a pid indulási idejét
    (`/proc/<pid>/stat` starttime, `pid_birth`), és a tulajdonos csak akkor „él", ha UGYANAZ a folyamat
    él — egy újrakiosztott pid más születésű, tehát a zár stale. Régi (születés nélküli) rekord vagy
    olvashatatlan /proc → visszaesés a puszta pid-életjelre, KIMONDVA (nem csendben) — és a születés
    nélküli rekordnál IDŐBEN KORLÁTOSAN (LEGACY_GRACE_NS a rekord ts_ns-étől): maradéka szerint
    egy írható rekordból kitörölt `pid_birth` különben örök zárat adott volna; a tulajdonos heartbeatje
    a hiányzó születést pótolja, tehát az élő tulajdonos nem veszít;
  - MessageClaim pid-alakú claimer-név → csak pid-életjel (KIMONDOTT KORLÁT: a claim-könyvtár nem tárol
    születést; a requeue-nál a stale claim ára egy újrakézbesítés, nem duplikált worker).
A liveness, a születés és az óra injektálható → determinista teszt.

Alkotmány: a poke FIX szöveg, az üzenet ADAT marad; ez a réteg CSAK azt dönti el, MELYIK instancia
kezeli — sosem ad parancsot. Egy agent / repó invariáns kikényszerítése, nem tartalom-értelmezés.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))

# Liveness TTL: ennyi ideig tekintünk egy lock/claim-tulajdonost élőnek a friss időbélyege
# alapján, MÉG ha a pid él is (pid-újrahasznosítás elleni öv-és-nadrágtartó).
_LIVENESS_TTL_NS = 90 * 1_000_000_000  # 90 s — bőven a heartbeat fölött, de nem örök

_SAFE_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_name(s):
    """Fájlnév-biztos instance-id (a `local_bus._safe_name` szellemében): path-szeparátor,
    ctrl-char és egyéb meglepetés kiszűrve. Üresből 'anon'."""
    s = _SAFE_RE.sub("_", str(s)).strip("_.")
    return s or "anon"


def _pid_birth(pid):
    """A folyamat SZÜLETÉSE: a `/proc/<pid>/stat` 22. mezője (starttime, boot óta eltelt óraütés). Egy pid
    újrakiosztás után MÁS születést kap, ezért (pid, birth) a folyamat identitása, a puszta pid nem.
    None, ha nem mérhető (nem Linux, nincs /proc, a folyamat közben eltűnt) — a hívó ezt KIMONDVA kezeli."""
    try:
        pid = int(pid)
        if pid <= 0:
            return None
        with open("/proc/%d/stat" % pid, "rb") as f:
            raw = f.read()
        # a 2. mező (comm) zárójeles és szóközt/zárójelet is tartalmazhat → az UTOLSÓ ')' után számolunk
        rest = raw[raw.rindex(b")") + 2:].split()
        return int(rest[19])                                  # a 3. mezőtől számolva a 22. = rest[19]
    except (OSError, ValueError, TypeError, IndexError):
        return None


def _pid_alive(pid):
    """Box-lokális pid-liveness jel-0-val. True ha a pid létezik (akár más usgazdáé →
    EPERM is 'létezik'). 0/negatív → False."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _tmux_target_alive(target, *, run=None):
    """A `target` (tmux session vagy session:win.pane) ÉLŐ panelhez tartozik-e. Ez a tekintély
    egy tmux-session liveness-éhez (a pane léte = a worker él), MERT az `acquire`-t hívó CLI-pid
    efemer lehet (operátor-nyitott pts-session → a Bash-subprocess azonnal meghal). `run`
    injektálható a teszthez. Hibára/nincs-tmux → False (fail-closed: ne tartsunk halottnak hitt
    lockot élőnek)."""
    if not target:
        return False
    run = run or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=5))
    try:
        r = run(["tmux", "list-panes", "-a", "-F",
                 "#{session_name}:#{window_index}.#{pane_index}"])
    except Exception:
        return False
    if getattr(r, "returncode", 1) != 0:
        return False
    panes = set((r.stdout or "").split())
    if target in panes:
        return True
    # csak session-név adott (pl. 'az egyik kar') → bármely panel egyezése elég
    return any(p.split(":", 1)[0] == target for p in panes)


def default_instance_id():
    """Stabil instance-id a JELEN folyamatra. tmux-ban: `<session:win.pane>:<pid>` (a panel
    egyedi + a pid a liveness-hez); különben `<hostname>:<pid>`. A pid mindig a végén →
    `pid_of(instance_id)` ki tudja olvasni."""
    pid = os.getpid()
    pane = os.environ.get("TMUX_PANE")  # pl. '%3' — egyedi a tmux-szerveren belül
    if pane:
        return _safe_name("%s:%d" % (pane, pid))
    host = os.environ.get("HOSTNAME") or "host"
    return _safe_name("%s:%d" % (host, pid))


def session_instance_id(agent, *, instance=None, owner_pid=None, bridge=BRIDGE,
                        is_alive=_pid_alive):
    """A hívó SESSIONJÉHEZ kötött, hívások között STABIL instance-id.

    Miért kell: a `default_instance_id()` a HÍVÓ FOLYAMAT pid-jéből készül, egy Claude-agentnél
    viszont minden Bash-hívás új, efemer subprocess. Így minden alparancs MÁS identitást kapott:
    a `claim-pending` a `.claimed/<efemer-pid>/` alá tette az üzenetet, a következő hívás pedig
    már nem ismerte fel sajátjaként (`claimed_by_me=0`) — az üzenet ott ragadt, sosem jutott
    archive-ba. Ugyanez okozott ÖNKIZÁRÁST a session-lockon: a saját hívásaim `duplicate`-et
    kaptak és a `release` False-t adott.

    Feloldási sorrend — az első érvényes nyer:
      1. explicit `--instance`;
      2. `AGENT_BUS_INSTANCE` környezeti változó;
      3. explicit `--owner-pid` (a tartós, pl. Claude-session pid) → `host:<owner_pid>`;
      4. a MÁR MEGLÉVŐ session-lock tárolt pid-je, DE csak ha `liveness == "pid"` és a pid ÉL —
         így egy csupasz alparancs is vissza tudja nyerni a session identitását, anélkül hogy
         minden hívóhelyet át kellene írni. A `target`-liveness-ű (tmux) lockokat nem érinti,
         mert ott a tárolt pid nem a tulajdonos tartós azonosítója;
      5. visszaesés a régi viselkedésre (`default_instance_id()`), tehát aki nem ad meg semmit,
         pontosan úgy működik, mint eddig.
    """
    if instance:
        return _safe_name(instance)
    env = os.environ.get("AGENT_BUS_INSTANCE")
    if env:
        return _safe_name(env)
    if owner_pid:
        host = os.environ.get("HOSTNAME") or "host"
        return _safe_name("%s:%d" % (host, int(owner_pid)))
    try:
        with open(os.path.join(bridge, "wake", "%s.session.lock" % _safe_name(agent)),
                  encoding="utf-8") as f:
            d = json.load(f)
        # az identitást CSAK az a hívó nyerheti vissza, akinek a tulajdonosa (a szülő
        # folyamata) maga a tárolt owner — különben bármely más folyamat „already-own"-nal átvenné az élő zárat.
        if (isinstance(d, dict) and d.get("liveness") == "pid" and is_alive(d.get("pid"))
                and d.get("pid") == os.getppid()):
            return _safe_name(str(d.get("instance")))
    except (OSError, ValueError, TypeError):
        pass
    return default_instance_id()


def pid_of(instance_id):
    """Az instance-id végére kódolt pid (a `default_instance_id()` konvenciója). None, ha nincs."""
    tail = str(instance_id).rsplit(":", 1)[-1]
    try:
        return int(tail)
    except (TypeError, ValueError):
        return None


_CLOCK_SANITY_NS = 24 * 3600 * 10 ** 9                      # 24 óra: ennél távolabbi hívói órát nem fogadunk el
# születés nélküli (régi vagy KITÖRÖLT mezőjű) pid-ágú rekordnál a puszta pid-életjel csak ennyi ideig
# dönt a rekord ts_ns-étől; a tulajdonos heartbeatje közben pótolja a születést, a kitörölt mező nem ad örök zárat.
LEGACY_GRACE_NS = 24 * 3600 * 10 ** 9


def _now(now_ns):
    return now_ns if now_ns is not None else time.time_ns()


def _now_for_liveness(now_ns):
    """Az ÉLETRŐL döntő óra. Saját a hívó által adott `now_ns` eddig korlátlan volt, tehát egy
    `acquire(..., now_ns=2**62)` hívással bárki STALE-nek láthatott egy ÉLŐ, TTL-alapú zárat, és elvehette.
    A szimuláció (teszt, mérés) továbbra is működik — csak a valóságtól 24 óránál távolabbi érték nem dönthet."""
    real = time.time_ns()
    if now_ns is None:
        return real
    return now_ns if abs(int(now_ns) - real) <= _CLOCK_SANITY_NS else real


class SessionLock:
    """Egy aktív worker / agent-identitás. A lock-fájl tartalma JSON (audit):
    `{instance, pid, target, ts_ns}`. Az `is_alive` (pid→bool) és `now_ns` injektálható."""

    def __init__(self, agent, *, bridge=BRIDGE, is_alive=None, target_alive=None,
                 ttl_ns=_LIVENESS_TTL_NS, pid_birth=None):
        self.agent = _safe_name(agent)
        self.bridge = bridge
        self.is_alive = is_alive or _pid_alive
        self.pid_birth = pid_birth or _pid_birth              # pid → születés (injektálható)
        # None → a modul-szintű `_tmux_target_alive` (lusta feloldás, hogy a teszt monkeypatch-elhesse)
        self._target_alive = target_alive
        self.ttl_ns = ttl_ns
        self.dir = os.path.join(bridge, "wake")
        self.path = os.path.join(self.dir, "%s.session.lock" % self.agent)

    def holder(self):
        """A jelenlegi lock-tulajdonos dict-je, vagy None ha nincs/olvashatatlan."""
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _target_alive_fn(self):
        return self._target_alive if self._target_alive is not None else _tmux_target_alive

    def _holder_alive(self, d, now):
        """Él-e a lock-tulajdonos? A liveness-stratégia a `liveness` mezőtől függ (a `acquire`
        választja a rendelkezésre álló jelhez):
          - `target` → a tmux-pane léte a tekintély (operátor-nyitott session is helyes!);
          - `pid`    → a hívó által átadott PERZISZTENS owner-pid életjele (TTL nélkül, de
                       pid-születés-azonossággal — );
          - `ttl`    → derivált CLI-pid + frissesség (best-effort, efemer-hívás esetére).
        Visszafelé-kompatibilis: hiányzó `liveness` → `ttl`."""
        if not d:
            return False
        lv = d.get("liveness", "ttl")
        if lv == "target" and d.get("target"):
            if not self._target_alive_fn()(d["target"]):
                return False
            # ha a hívó EXPLICIT owner-pid-et adott, annak halála is a zár halála —
            # különben egy túlélő tmux-panel (a shell) örökre „élő"-nek mutatná a halott worker zárját.
            if d.get("pid_src") == "owner":
                return self._same_process_alive(d, now)
            return True
        if lv == "pid":
            return self._same_process_alive(d, now)
        ts = d.get("ts_ns")
        if not isinstance(ts, int) or (now - ts) >= self.ttl_ns:
            return False  # túl régi → stale akkor is, ha a (derivált) pid (újra)él
        pid = d.get("pid")
        # nem-pid alakú instance (pid=None) esetén a FRISS zár a TTL-ig él —
        # korábban `is_alive(None)` → False, vagyis a frissen írt zárat bárki azonnal elvihette.
        return True if pid is None else self._same_process_alive(d, now)

    def _same_process_alive(self, d, now):
        """UGYANAZ a folyamat él-e, amelyik a zárat írta — nem csak „valami él ezen a pid-en".
        (2026-09-17): a pid-ágon nem volt TTL, és a fejléc szerint az lett volna a pid-újrakiosztás
        elleni védelem. TTL ide nem való (egy tartós owner-pid zárja addig él, amíg a folyamat), a helyes jel a
        folyamat születése: a rekordban tárolt `pid_birth` == a pid MOSTANI születése. Kimondott visszaesések:
        régi rekord (nincs `pid_birth`) vagy most nem mérhető születés → a puszta pid-életjel dönt."""
        pid = d.get("pid")
        if not self.is_alive(pid):
            return False
        born = d.get("pid_birth")
        if born is None:
            # Régi (születés nélküli) rekord — VAGY egy írható rekordból kitörölt mező (enélkül a
            # visszaesés ára egy ÖRÖK zár volt, ha a rekord írható). Ezért a visszaesés IDŐBEN KORLÁTOS: a puszta
            # pid-életjel csak LEGACY_GRACE_NS-ig dönt a rekord `ts_ns`-étől; a tulajdonos heartbeatje/újra-acquire-je
            # közben pótolja a születést (lásd `_payload`), tehát egy élő tulajdonos nem veszít, a kitörölt mező viszont
            # nem ad örök zárat.
            ts = d.get("ts_ns")
            if not isinstance(ts, int) or (now - ts) >= LEGACY_GRACE_NS:
                return False
            return True
        now_born = self.pid_birth(pid)
        if now_born is None:
            return True                                       # nem mérhető: nem döntünk vakon (kimondva)
        return now_born == born

    @staticmethod
    def _liveness_of(instance, target, owner_pid):
        """A választott liveness-stratégia + a tárolt pid az elérhető jel alapján."""
        if target:
            return ("target", owner_pid if owner_pid else pid_of(instance))   # pid_src a _payload-ban
        if owner_pid:
            return ("pid", owner_pid)
        return ("ttl", pid_of(instance))

    def _payload(self, instance, target, now, *, owner_pid=None, liveness=None, pid=None, pid_src_keep=None,
                 caller_ts=None, pid_birth_keep=None):
        """(2026-09-16) az előző javítás CSAK az olvasó oldalt korlátozta — a fájlba
        továbbra is a nyers hívói óra került, tehát a hívó órája továbbra is ÉLETRŐL döntött, csak egy lépéssel
        később és MINDENKI MÁS számára (múltbeli bélyeg → két `acquired`; jövőbeli bélyeg + pid nélküli instance
        → ÖRÖK zár). Ezért: a `ts_ns` MINDIG a korlátozott, életről döntő érték; a hívó nyers bélyege külön
        `caller_ts_ns` mezőben marad meg auditnak, és semmilyen döntésbe nem folyik bele."""
        if liveness is None:
            liveness, pid = self._liveness_of(instance, target, owner_pid)
            pid_src = "owner" if owner_pid else "derived"
            birth = self.pid_birth(pid) if pid is not None else None   # a folyamat identitása
        else:
            pid_src = pid_src_keep
            # a MEGŐRZÖTT rekord születése marad; ha nincs (régi vagy kitörölt mező), a tulajdonos most PÓTOLJA (
            # maradék) — így egy élő tulajdonos rekordja a következő heartbeat/újra-acquire után születéssel áll
            birth = pid_birth_keep if pid_birth_keep is not None else (self.pid_birth(pid) if pid is not None else None)
        doc = {"instance": instance, "pid": pid, "target": target,
               "ts_ns": now, "liveness": liveness, "pid_src": pid_src, "pid_birth": birth}
        if caller_ts is not None and caller_ts != now:
            doc["caller_ts_ns"] = caller_ts                    # audit: a hívó ÁLLÍTOTT ideje, ha eltér
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))

    def acquire(self, instance, *, target=None, owner_pid=None, now_ns=None):
        """Megpróbálja megfogni a lockot ennek a példánynak. Visszaad: `(status, holder)`:
          - `('acquired', me)`     — mostantól ez a példány AZ aktív worker;
          - `('already-own', me)`  — már ez a példányé volt (idempotens újra-hívás/heartbeat);
          - `('duplicate', other)` — él egy MÁSIK tulajdonos → a hívó duplikátum, ne drain-eljen.
        `target` átadásakor a liveness a tmux-pane létéhez kötődik (operátor-nyitott session is
        helyes); `owner_pid` a perzisztens (Claude-)PID explicit átadására. Stale tulajdonos
        lockját atomian visszaigényli."""
        instance = _safe_name(instance)
        caller_ts = _now(now_ns)                              # amit a hívó ÁLLÍT (audit)
        now = _now_for_liveness(now_ns)                       # amivel DÖNTÜNK (korlátozott) — 
        os.makedirs(self.dir, exist_ok=True)
        # a „ki a tulajdonos? → stale → visszaigénylés" lépéssor atomi kell legyen.
        # Egy oldalfájlon tartott flock sorba rendezi a versengő acquire-okat (a lock-fájl tartalma
        # különben üres/félkész lehet, amit a másik hívó „nincs tulajdonos"-nak olvasott).
        import fcntl
        mfd = os.open(self.path + ".mutex", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(mfd, fcntl.LOCK_EX)
            return self._acquire_locked(instance, target, owner_pid, now, alive_now=now, caller_ts=caller_ts)
        finally:
            try:
                fcntl.flock(mfd, fcntl.LOCK_UN)
            finally:
                os.close(mfd)

    def _acquire_locked(self, instance, target, owner_pid, now, alive_now=None, caller_ts=None):
        # újramérés (B1-var): egy sosem-élő targettel írt zárat bárki más azonnal stale-nek lát
        # (a `_holder_alive` a pane-t nézi) → visszaigényli, miközben ez a hívó már `acquired`-et kapott →
        # két worker. Ezért target-liveness-t csak ÉLŐ panelre adunk: nem élő target → megtagadás, írás nélkül.
        if target and not self._target_alive_fn()(target):
            return ("target-not-live", {"instance": instance, "target": target, "liveness": "target"})
        # ugyanez az owner-ágon. Egy SOSEM ÉLT (vagy már halott) owner-pid-del
        # írt zárat a másik hívó azonnal stale-nek lát (a `_holder_alive` a pid-et nézi) és visszaigényli, miközben ez a
        # hívó már `acquired`-et kapott → két worker (mért: 7-9/15). Ezért: a megadott owner-pid — vagy owner és target
        # híján az instance-ből derivált pid (ttl-ág) — az acquire PILLANATÁBAN éljen; különben megtagadás, írás nélkül.
        if owner_pid is not None and not self.is_alive(owner_pid):
            return ("owner-not-live", {"instance": instance, "pid": owner_pid, "pid_src": "owner"})
        if not target and owner_pid is None:
            derived = pid_of(instance)
            if derived is not None and not self.is_alive(derived):
                return ("owner-not-live", {"instance": instance, "pid": derived, "pid_src": "derived"})
        payload = self._payload(instance, target, now, owner_pid=owner_pid, caller_ts=caller_ts)
        # 1) gyors út: atomi O_EXCL létrehozás
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            return ("acquired", json.loads(payload))
        except FileExistsError:
            pass
        # 2) létezik: kié?
        cur = self.holder()
        if cur and cur.get("instance") == instance:
            # Saját → frissít (heartbeat). A liveness-stratégiát MEGŐRIZZÜK, ha a hívó nem adott
            # újat: egy csupasz újra-`acquire` (amit a session-identitás visszanyerése óta bármely
            # alparancs kiválthat) különben `pid`-ről `ttl`-re rontaná a lockot egy már halott,
            # derivált pid-del — vagyis a saját, ÉLŐ lockunkat tenné stale-lé.
            if target is None and owner_pid is None:
                payload = self._payload(instance, cur.get("target"), now,
                                        liveness=cur.get("liveness", "ttl"), pid=cur.get("pid"),
                                        pid_src_keep=cur.get("pid_src"), caller_ts=caller_ts,
                                        pid_birth_keep=cur.get("pid_birth"))
            self._write_atomic(payload)
            return ("already-own", json.loads(payload))
        if self._holder_alive(cur, alive_now if alive_now is not None else now):
            return ("duplicate", cur)
        # 3) stale (halott v. lejárt) → atomi visszaigénylés
        self._write_atomic(payload)
        return ("acquired", json.loads(payload))

    def _write_atomic(self, payload):
        tmp = "%s.tmp.%d" % (self.path, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, self.path)  # atomi felülírás (no-deletion: a lock egy státusz-fájl)

    def _with_mutex(self, fn):
        """Saját az `acquire` sorba volt rendezve egy oldalfájl flockjával, a `heartbeat` és a
        `release` viszont NEM — így egy takeover és egy heartbeat/release közé beékelődve két fél is
        „tulajdonosnak" hihette magát, és az egyik vakon felülírhatta a másik zárát. Ugyanaz a zár, ugyanaz a
        sorbarendezés."""
        import fcntl
        os.makedirs(self.dir, exist_ok=True)
        mfd = os.open(self.path + ".mutex", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(mfd, fcntl.LOCK_EX)
            return fn()
        finally:
            try:
                fcntl.flock(mfd, fcntl.LOCK_UN)
            finally:
                os.close(mfd)

    def heartbeat(self, instance, *, target=None, owner_pid=None, now_ns=None):
        """Frissíti a lock időbélyegét, ha ez a példány a tulajdonos (a liveness-stratégiát és a
        pid-et megőrzi, hacsak nem adsz újat). True, ha sikerült."""
        return self._with_mutex(lambda: self._heartbeat_locked(instance, target, owner_pid, now_ns))

    def _heartbeat_locked(self, instance, target=None, owner_pid=None, now_ns=None):
        instance = _safe_name(instance)
        cur = self.holder()
        if not cur or cur.get("instance") != instance:
            return False
        tgt = target if target is not None else cur.get("target")
        if owner_pid is None and target is None:
            # változatlan stratégia: a meglévő liveness/pid megtartása, csak ts-frissítés
            self._write_atomic(self._payload(instance, tgt, _now_for_liveness(now_ns),
                                              liveness=cur.get("liveness", "ttl"),
                                              pid=cur.get("pid"), pid_src_keep=cur.get("pid_src"),
                                              caller_ts=_now(now_ns), pid_birth_keep=cur.get("pid_birth")))
        else:
            self._write_atomic(self._payload(instance, tgt, _now_for_liveness(now_ns), owner_pid=owner_pid,
                                             caller_ts=_now(now_ns)))
        return True

    def release(self, instance):
        """Elengedi a lockot, HA ez a példányé (idegen lockot nem bánt). True, ha elengedte.
        A fájlt eltávolítja — ez NEM adat-törlés, hanem egy efemer státusz-zár feloldása.

        KIMONDOTT KORLÁT: a `release` csak az `instance` STRING egyezését kéri, tehát
        aki a lock-fájlt olvasni tudja, egy ÉLŐ tulajdonos zárát is elengedheti. A zárás egy acquire-kor adott
        titkos tokennel lenne teljes — az viszont a vendorolt hívók szerződését változtatja (MAJOR-kapu),
        ezért nem egyoldalú lépés: a javaslat a PR-ben van. A mutex legalább a versenyt kizárja."""
        return self._with_mutex(lambda: self._release_locked(instance))

    def _release_locked(self, instance):
        instance = _safe_name(instance)
        cur = self.holder()
        if cur and cur.get("instance") == instance:
            try:
                os.unlink(self.path)
                return True
            except OSError:
                return False
        return False


class MessageClaim:
    """Atomi, rename-alapú per-üzenet claim a megosztott `inbox/<agent>/`-on. Egy üzenet
    kezelése ELŐTT a hívó megfogja; a párhuzamos vesztes kihagyja."""

    CLAIM_TTL_NS = int(os.environ.get("AGENT_BUS_CLAIM_TTL_S", str(3600))) * 10 ** 9   # a „még dolgozik" ablak

    def __init__(self, agent, instance, *, bridge=BRIDGE, is_alive=_pid_alive, claim_ttl_ns=None):
        self.agent = _safe_name(agent)
        self.instance = _safe_name(instance)
        self.is_alive = is_alive
        self.bridge = bridge
        self.claim_ttl_ns = claim_ttl_ns or self.CLAIM_TTL_NS
        self.inbox = os.path.join(bridge, "inbox", self.agent)
        self.claim_root = os.path.join(self.inbox, ".claimed")
        self.mine = os.path.join(self.claim_root, self.instance)

    def _pending(self):
        try:
            return sorted(f for f in os.listdir(self.inbox) if f.endswith(".json"))
        except OSError:
            return []

    def claim(self, name):
        """ATOMI: megfogja a `name` üzenetet ennek a példánynak. True, ha ELNYERTE (átmozgatva
        a saját claim-mappájába); False, ha valaki más vitte el (a rename ENOENT-tel bukott)."""
        if not name.endswith(".json") or "/" in name or name.startswith("."):
            return False
        os.makedirs(self.mine, exist_ok=True)
        src = os.path.join(self.inbox, name)
        dst = os.path.join(self.mine, name)
        try:
            os.rename(src, dst)  # POSIX: pontosan egy párhuzamos rename nyer
            return True
        except (FileNotFoundError, OSError):
            return False

    def claim_pending(self):
        """Megfogja az ÖSSZES jelenleg függő üzenetet, amit el tud nyerni. Visszaadja a
        ténylegesen elnyert nevek listáját (a vesztetteket kihagyja). Ezeken — és CSAK ezeken —
        dolgozzon a hívó."""
        won = []
        for name in self._pending():
            if self.claim(name):
                won.append(name)
        return won

    def claimed_paths(self):
        """A jelen példány által claimelt, még nem archivált üzenetek teljes útjai."""
        try:
            return [os.path.join(self.mine, f)
                    for f in sorted(os.listdir(self.mine)) if f.endswith(".json")]
        except OSError:
            return []

    def _claimer_state(self, inst, d, now):
        """„él" / „halott" / „nem tudni"-ból MÉRT döntés egy másik claimerről. -> True (él) | False (halott)

        (2026-09-16) itt a `pid_of(inst) -> is_alive(None) -> False` lánc a
        BIZONYÍTÉK HIÁNYÁT „halott"-nak vette, tehát egy ÉLŐ, stabil nevű worker (pl. `claude-alfa-session`)
        claimjeit bárki kirequeue-olhatta alóla — ugyanaz a hibaosztály, amit a SessionLock oldalán a B1-ben
        már bezártunk. A naiv javítás (`pid is None -> continue`) viszont a MÁSIK végén nyit lyukat: egy
        valóban halott, stabil nevű claimer üzenetei örökre bent ragadnának (ezt ők is megmérték).
        Ezért harmadik állapot, MÉRHETŐ jelhez kötve:
          1. pid-alakú név  -> a pid életjele dönt (mint eddig);
          2. nincs pid      -> ugyanennek az instance-nak az ÉLŐ session-lockja bizonyíték az életre;
          3. ha az sincs    -> a claim-könyvtár FRISSESSÉGE dönt (mtime + TTL): friss = még dolgozik,
                               elavult = elengedjük. Se az „él", se a „halott" oldalra nem esünk NÉMÁN.
        """
        pid = pid_of(inst)
        if pid is not None:
            return bool(self.is_alive(pid))
        try:                                                   # 2) él-e ugyanezzel a névvel session-lock?
            lock = SessionLock(self.agent, bridge=self.bridge, is_alive=self.is_alive)
            cur = lock.holder()
            if cur and cur.get("instance") == inst and lock._holder_alive(cur, now):
                return True
        except Exception:
            pass
        try:                                                   # 3) a claim-könyvtár frissessége
            newest = max([os.path.getmtime(os.path.join(d, f)) for f in os.listdir(d)] or
                         [os.path.getmtime(d)])
        except OSError:
            return True                                        # nem mérhető -> NEM nyúlunk hozzá
        return (now - int(newest * 10 ** 9)) < self.claim_ttl_ns

    def requeue_dead(self, *, now_ns=None):
        """Minden HALOTT claimer (`.claimed/<inst>/`) üzeneteit visszamozgatja a `pending`-be
        (requeue-on-death — MOZGATÁS, nem törlés). A jelen élő példányt sosem bántja.
        A „halott" ítélet MÉRT (lásd `_claimer_state`), nem a bizonyíték hiánya.
        Visszaadja a requeue-olt nevek listáját."""
        now = _now_for_liveness(now_ns)                        # a paramétert eddig elfogadtuk és eldobtuk
        requeued = []
        try:
            insts = sorted(os.listdir(self.claim_root))
        except OSError:
            return requeued
        for inst in insts:
            d = os.path.join(self.claim_root, inst)
            if not os.path.isdir(d):
                continue
            if inst == self.instance:
                continue  # a sajátunk: élünk, ne requeue-oljunk magunk alól
            if self._claimer_state(inst, d, now):
                continue  # MÉRTEN él (pid / session-lock / friss claim-könyvtár) → hagyjuk dolgozni
            try:
                files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
            except OSError:
                continue
            for name in files:
                back = os.path.join(self.inbox, name)
                if os.path.exists(back):
                    continue  # már van ilyen pending (ne írjunk felül) — no-deletion
                try:
                    os.rename(os.path.join(d, name), back)
                    requeued.append(name)
                except OSError:
                    pass
        return requeued


# --------------------------------------------------------------------------- CLI

def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="bus_singleflight",
                                description="session-lock + atomi üzenet-claim a tmux-Claude agentekre")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("acquire", help="session-lock megfogása (induláskor); kiírja a státuszt")
    pa.add_argument("--agent", required=True)
    pa.add_argument("--target", default=None,
                    help="a jelen tmux-target (session v. session:win.pane) → a liveness a PANE "
                         "létéhez kötődik (operátor-nyitott sessionre is helyes). Ajánlott forma "
                         "tmux-ban: --target \"$(tmux display-message -p "
                         "'#{session_name}:#{window_index}.#{pane_index}')\"")
    pa.add_argument("--instance", default=None,
                    help="stabil instance-id (alap: auto a folyamatból: TMUX_PANE:pid / host:pid)")
    pa.add_argument("--owner-pid", type=int, default=None,
                    help="perzisztens owner-PID (pl. a hosszú-életű Claude-session pid-je) — "
                         "akkor használd, ha nincs tmux-target, de tudod a tartós pid-et")

    # A session-scoped identitás MINDEN alparancsnak kell, nem csak az `acquire`-nek: enélkül a
    # `claim-pending` egy efemer névre claimel, amit a `status`/`release` már nem ismer fel.
    def _identity_args(sp):
        sp.add_argument("--instance", default=None,
                        help="stabil instance-id (alap: a session-lockból visszanyerve, "
                             "különben auto a folyamatból: TMUX_PANE:pid / host:pid)")
        sp.add_argument("--owner-pid", type=int, default=None,
                        help="perzisztens owner-PID (pl. a hosszú-életű Claude-session pid-je)")

    pr = sub.add_parser("release", help="session-lock elengedése (kilépéskor)")
    pr.add_argument("--agent", required=True)
    _identity_args(pr)

    ps = sub.add_parser("status", help="ki a session-lock tulajdonosa + függő/claimelt üzenetek")
    ps.add_argument("--agent", required=True)
    _identity_args(ps)

    pc = sub.add_parser("claim-pending", help="az ÖSSZES függő üzenet atomi megfogása; az elnyertek")
    pc.add_argument("--agent", required=True)
    _identity_args(pc)

    pq = sub.add_parser("requeue-dead", help="halott claimerek üzeneteinek visszamozgatása")
    pq.add_argument("--agent", required=True)
    _identity_args(pq)

    pg = sub.add_parser("guard", help="van-e már ÉLŐ worker ehhez az identitáshoz "
                                      "(launcher pre-check: exit 3 = ne indíts duplikátumot)")
    pg.add_argument("--agent", required=True)

    a = p.parse_args(argv)
    iid = session_instance_id(a.agent, instance=getattr(a, "instance", None),
                              owner_pid=getattr(a, "owner_pid", None))

    if a.cmd == "acquire":
        lock = SessionLock(a.agent)
        use_iid = iid
        owner = a.owner_pid
        if owner is None and not a.target:
            # az `acquire` CLI egyszeri, azonnal kilépő folyamat — a SAJÁT pid-je nem
            # tulajdonos. Alapból a HÍVÓ (a hosszú életű shell/agent) pid-je a tulajdonos; aki mást akar,
            # adja meg --owner-pid-del vagy --target-tel.
            owner = os.getppid()
        status, holder = lock.acquire(use_iid, target=a.target, owner_pid=owner)
        print("instance=%s status=%s holder=%s liveness=%s" % (
            use_iid, status, holder.get("instance"), holder.get("liveness")))
        # exit-kód a launcher/STARTUP-protokollnak: 0 = te vagy a worker; 3 = duplikátum; 4 = a --target nem élő panel
        # VAGY a megadott owner-pid nem él (B1var-2) — mindkettő: a zár NEM íródott, javítsd a hívást.
        if status in ("target-not-live", "owner-not-live"):
            return 4
        return 0 if status in ("acquired", "already-own") else 3

    if a.cmd == "release":
        lock = SessionLock(a.agent)
        print("released=%s" % lock.release(iid))
        return 0

    if a.cmd == "status":
        lock = SessionLock(a.agent)
        h = lock.holder()
        mc = MessageClaim(a.agent, iid)
        print("holder=%s pending=%d claimed_by_me=%d" % (
            (h or {}).get("instance"), len(mc._pending()), len(mc.claimed_paths())))
        return 0

    if a.cmd == "claim-pending":
        mc = MessageClaim(a.agent, iid)
        mc.requeue_dead()
        won = mc.claim_pending()
        for name in won:
            print(name)
        return 0

    if a.cmd == "requeue-dead":
        mc = MessageClaim(a.agent, iid)
        for name in mc.requeue_dead():
            print("requeued %s" % name)
        return 0

    if a.cmd == "guard":
        lock = SessionLock(a.agent)
        cur = lock.holder()
        if cur and lock._holder_alive(cur, time.time_ns()):
            print("LIVE-HOLDER instance=%s target=%s liveness=%s" % (
                cur.get("instance"), cur.get("target"), cur.get("liveness")))
            return 3  # él egy másik worker → a launcher NE indítson duplikátumot
        print("clear")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
