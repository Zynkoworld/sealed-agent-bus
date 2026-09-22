#!/usr/bin/env python3
"""bus_relay — ZERO-TRUST STORE-AND-FORWARD RELAY + SSE-értesítés gépek között (v1.2).

Mikor kell: ha a két gép között nincs közvetlen SSH (mindkettő NAT/tűzfal mögött). Ilyenkor egy relay közvetít —
de VAKON:

- **E2E titkosítás a feladónál** (`seal`): X25519 statikus ECDH → HKDF-SHA256 → ChaCha20-Poly1305. A routing-mezők
  (v/from/to/ts) AAD-ként hitelesek, a tartalom a relay számára OLVASHATATLAN. A relay csak opak borítékot tárol.
- **Aláírt lehúzás** (`/pickup`, a júliusi rés zárása): a kérés `{agent, ts, nonce, sig}`, ahol a sig Ed25519 a
  `agentbus-relay|<purpose>|<agent>|<ts>|<nonce>` bájtjai fölött, a relay REGISTRY-jében az agenthez kötött kulccsal.
  Aláíratlan, hamis, idősávon kívüli (±WINDOW s) vagy MÁR LÁTOTT nonce → 401. Így más nem húzhatja le (és nem
  archiválhatja el) valaki más sorát.
- **SSE** (`/events`, Server-Sent Events): hitelesített feliratkozás; a relay csak annyit küld, hogy
  `event: pending` / `data: {"count": N}` — TARTALMAT SOHA. A kliens erre azonnal lehúz; ha az SSE nem él, pollol.
- **Fail-closed:** `cryptography` nélkül a relay NEM indul (RuntimeError), üres registry-vel sem.
- **Nincs törlés:** a lehúzott boríték a `.picked/` alá mozog.

Ez nyílt hálózati felület, ezért éles kitétele operátor-döntés (TLS a relay elé, rate-limit a proxyn). A tesztek
csak 127.0.0.1-en futnak. a partner-kar nyitott HIGH-lelete a hálózati rétegen pontosan ezért kapott aláírt lehúzást és
fail-closed indulást."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidSignature, InvalidTag
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - a relay ekkor nem indul
    HAVE_CRYPTO = False

V = "abr1"
WINDOW = 120                                      # s: a lehúzási kérés ts-ablaka (replay-védelem a nonce-cache-sel együtt)
MAX_ENVELOPE = 1024 * 1024
# a /deliver hitelesítés nélküli (egy relay-nek ismeretlen feladótól is fogadnia kell) — ezért
# beépített, fail-closed korlátok MÉG a proxy/TLS előtt: csak ismert címzett, címzettenkénti várakozó-plafon,
# címzettenkénti percenkénti ráta és teljes spool-plafon. A proxy-oldali rate-limit ettől még kell a nyilvános kitételhez.
MAX_PENDING_PER_RECIPIENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_PENDING", "200"))
MAX_PER_MIN_PER_RECIPIENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_PER_MIN", "120"))
MAX_SPOOL_TOTAL = int(os.environ.get("AGENT_BUS_RELAY_MAX_SPOOL", "5000"))
# Saját a lehúzott boríték a `.picked/` alá kerül, a közjegyzői írás hibájánál pedig `.unnotarized`
# néven marad — EGYIKET SEM számolta a spool-limit (más könyvtár, illetve rejtett név). A „nincs törlés" elv miatt ez
# monoton nő: egy hitelesített fél ismételt küldés+lehúzás körrel megtöltheti a lemezt. Ezért KÜLÖN archív-kvóta:
# fölötte ÚJ kézbesítés nem fogadható (fail-closed 429), de semmit nem törlünk — a takarítás operátori döntés.
MAX_ARCHIVE_TOTAL = int(os.environ.get("AGENT_BUS_RELAY_MAX_ARCHIVE", "100000"))
MAX_SSE_PER_AGENT = int(os.environ.get("AGENT_BUS_RELAY_MAX_SSE", "2"))   # egyidejű SSE-kapcsolat agentenként
_ROUTING = ("v", "from", "to", "ts", "nonce", "ct", "alg")


def _need_crypto():
    if not HAVE_CRYPTO:
        raise RuntimeError("bus_relay requires the 'cryptography' package (fail-closed: no plaintext fallback)")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


# ── kulcsok ──────────────────────────────────────────────────────────────────
def x25519_keypair():
    """-> (privát nyers bájtok, publikus base64). A privát a SAJÁT gépen marad."""
    _need_crypto()
    k = X25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, _b64(pub)


def ed25519_keypair():
    """-> (32 bájtos seed, publikus hex) a lehúzási aláíráshoz."""
    _need_crypto()
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return seed, pub


# ── E2E borítékolás ──────────────────────────────────────────────────────────
def _aead_key(shared: bytes, sender: str, recipient: str) -> bytes:
    info = ("%s|%s|%s" % (V, sender, recipient)).encode()     # irány-kötés (anti-reflection)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal(body: str, sender: str, recipient: str, sender_x25519_priv: bytes, recipient_x25519_pub_b64: str,
         ts: int | None = None) -> dict:
    _need_crypto()
    ts = int(time.time()) if ts is None else int(ts)
    shared = X25519PrivateKey.from_private_bytes(sender_x25519_priv).exchange(
        X25519PublicKey.from_public_bytes(_unb64(recipient_x25519_pub_b64)))
    nonce = os.urandom(12)
    aad = ("%s|%s|%s|%d" % (V, sender, recipient, ts)).encode()
    ct = ChaCha20Poly1305(_aead_key(shared, sender, recipient)).encrypt(nonce, body.encode("utf-8"), aad)
    return {"v": V, "from": sender, "to": recipient, "ts": ts, "alg": "x25519-chacha20poly1305",
            "nonce": _b64(nonce), "ct": _b64(ct)}


def unseal(env: dict, recipient: str, recipient_x25519_priv: bytes, sender_x25519_pub_b64: str) -> str:
    """AEAD-ellenőrzött visszafejtés. Hamis / nem nekem szóló / rossz feladó → kivétel (fail-closed)."""
    _need_crypto()
    if env.get("v") != V:
        raise ValueError("unknown envelope version")
    if env.get("to") != recipient:
        raise ValueError("envelope is not addressed to this recipient")
    shared = X25519PrivateKey.from_private_bytes(recipient_x25519_priv).exchange(
        X25519PublicKey.from_public_bytes(_unb64(sender_x25519_pub_b64)))
    aad = ("%s|%s|%s|%d" % (V, env["from"], recipient, int(env["ts"]))).encode()
    try:
        return ChaCha20Poly1305(_aead_key(shared, env["from"], recipient)).decrypt(
            _unb64(env["nonce"]), _unb64(env["ct"]), aad).decode("utf-8")
    except InvalidTag:
        raise ValueError("envelope authentication failed")


# ── aláírt lehúzás ───────────────────────────────────────────────────────────
def _auth_bytes(purpose: str, agent: str, ts: int, nonce: str) -> bytes:
    return ("agentbus-relay|%s|%s|%d|%s" % (purpose, agent, ts, nonce)).encode()


def sign_request(purpose: str, agent: str, seed: bytes, ts: int | None = None, nonce: str | None = None) -> dict:
    _need_crypto()
    ts = int(time.time()) if ts is None else int(ts)
    nonce = nonce or os.urandom(12).hex()
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(_auth_bytes(purpose, agent, ts, nonce)).hex()
    return {"agent": agent, "ts": ts, "nonce": nonce, "sig": sig}


class _Auth:
    """Registry (agent → Ed25519 pub hex) + idősáv + nonce-cache. Szálbiztos."""

    def __init__(self, registry: dict, window: int = WINDOW, nonce_path: str | None = None):
        _need_crypto()
        if not registry:
            raise RuntimeError("relay registry is empty (fail-closed)")
        self.registry, self.window = dict(registry), window
        self._seen, self._lock = {}, threading.Lock()
        # v1.4: TARTÓS nonce-tár (append-only JSONL) — a v1.2 memória-cache újraindítás után egyszer visszajátszható
        # lehúzást engedett. Betöltéskor csak a még ablakon belüli (2×window) kulcsok
        # élnek; a tömörítés SOHA nem hagy el lejáratlan bejegyzést.
        self.nonce_path = nonce_path
        self.not_before = 0.0
        if nonce_path:
            now = time.time()
            # ha a tartós nonce-tár HIÁNYZIK (törölték, vagy első indulás), nem tudhatjuk, mit
            # láttunk már → az indulás ELŐTT aláírt kérést elutasítjuk (fail-closed). A kliens friss ts-sel újrapróbál.
            if not os.path.exists(nonce_path):
                self.not_before = now
            try:
                with open(nonce_path, encoding="utf-8") as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                            if now - float(r["t"]) <= 2 * self.window:
                                self._seen[(r["p"], r["a"], r["n"])] = float(r["t"])
                        except (ValueError, KeyError, TypeError):
                            continue
            except FileNotFoundError:
                pass
            self._compact_locked()

    def _compact_locked(self):
        """Atomi újraírás a még élő kulcsokkal (hívó tartja a lockot, vagy init-ben egyszálú)."""
        if not self.nonce_path:
            return
        tmp = self.nonce_path + ".tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.nonce_path)), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            for (p_, a_, n_), t_ in self._seen.items():
                f.write(json.dumps({"p": p_, "a": a_, "n": n_, "t": t_}) + "\n")
        os.replace(tmp, self.nonce_path)

    def check(self, purpose: str, req: dict) -> str | None:
        """-> az agent neve, ha a kérés hiteles; különben None."""
        try:
            agent, ts, nonce, sig = req["agent"], int(req["ts"]), str(req["nonce"]), bytes.fromhex(req["sig"])
        except (KeyError, TypeError, ValueError):
            return None
        pub = self.registry.get(agent)
        now = time.time()
        if not pub or abs(now - ts) > self.window or ts < int(self.not_before) or not (8 <= len(nonce) <= 64):
            return None
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(sig, _auth_bytes(purpose, agent, ts, nonce))
        except (InvalidSignature, ValueError):
            return None
        key = (purpose, agent, nonce)
        with self._lock:
            expired = [k for k, t in self._seen.items() if now - t > 2 * self.window]
            for k in expired:                                   # csak lejárt (ablakon kívüli) kulcs esik ki
                del self._seen[k]
            if key in self._seen:                              # REPLAY: ugyanaz az aláírt kérés másodszor
                return None
            self._seen[key] = now
            if self.nonce_path:
                if expired:
                    self._compact_locked()
                else:
                    with open(self.nonce_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"p": purpose, "a": agent, "n": nonce, "t": now}) + "\n")
                        f.flush()
                        os.fsync(f.fileno())
        return agent


# ── relay szerver ────────────────────────────────────────────────────────────
class Relay:
    def __init__(self, spool: str, registry: dict, host: str = "127.0.0.1", port: int = 0, window: int = WINDOW,
                 sse_interval: float = 0.5, nonce_path: str | None = None, notary=None):
        # v1.5: közjegyzői napló a határon (None → környezet szerint; termék-módban kötelező, fail-closed)
        if notary is None:
            import bus_notary
            notary = bus_notary.Notary.from_env()
        self.notary = notary or None
        # v1.4: a nonce-tár alapból a spool mellett él (tartós) → újraindítás után sem játszható vissza egy lehúzás
        nonce_path = nonce_path or os.path.join(spool, ".pickup_nonces.jsonl")
        self.spool, self.auth, self.sse_interval = spool, _Auth(registry, window, nonce_path), sse_interval
        self.max_pending_per_recipient = MAX_PENDING_PER_RECIPIENT
        self.max_per_min_per_recipient = MAX_PER_MIN_PER_RECIPIENT
        self.max_spool_total = MAX_SPOOL_TOTAL
        self.max_archive_total = MAX_ARCHIVE_TOTAL
        self.max_sse_per_agent = MAX_SSE_PER_AGENT
        self._sse, self._sse_lock = {}, threading.Lock()          # agentenként hány SSE-kapcsolat él
        self._rate, self._rate_lock = {}, threading.Lock()
        relay = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):                          # a relay tartalmat nem naplóz
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _body(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                if n <= 0 or n > MAX_ENVELOPE:
                    raise ValueError("bad length")
                return json.loads(self.rfile.read(n).decode())

            def do_POST(self):
                path = urlparse(self.path).path
                try:
                    obj = self._body()
                except (ValueError, OSError):
                    return self._json(400, {"error": "bad_request"})
                if path == "/deliver":
                    return self._json(*relay.deliver(obj))
                if path == "/pickup":
                    agent = relay.auth.check("pickup", obj)
                    if not relay._note(envelope=obj, sender_identity=agent or (str(obj.get("agent", ""))[:128] if isinstance(obj, dict) else ""),
                                       sender_auth="pickup-sig" if agent else "unauthenticated-claim",
                                       recipient="relay", kind="pickup", decision="accepted" if agent else "rejected",
                                       reason="" if agent else "unauthorized"):
                        return self._json(503, {"error": "notary unavailable"})
                    if not agent:
                        return self._json(401, {"error": "unauthorized"})
                    return self._json(200, {"envelopes": relay.pickup(agent)})
                return self._json(404, {"error": "not_found"})

            def do_GET(self):
                u = urlparse(self.path)
                if u.path == "/health":
                    return self._json(200, {"ok": True})
                if u.path != "/events":
                    return self._json(404, {"error": "not_found"})
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                agent = relay.auth.check("events", q)
                if not agent:
                    return self._json(401, {"error": "unauthorized"})
                try:
                    max_s = min(float(q.get("max_seconds", 300)), 3600.0)
                except ValueError:
                    max_s = 300.0
                if not relay.sse_slot(agent, True):                 # szál/fd-kimerítés agentenkénti korláttal
                    return self._json(429, {"error": "too many SSE connections for this agent"})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                last, t0 = -1, time.time()
                try:
                    while time.time() - t0 < max_s:
                        n = relay.count(agent)
                        if n != last:
                            self.wfile.write(("event: pending\ndata: %s\n\n" % json.dumps({"count": n})).encode())
                            last = n
                        else:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        time.sleep(relay.sse_interval)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    relay.sse_slot(agent, False)

        self.server = ThreadingHTTPServer((host, port), H)
        self.server.daemon_threads = True
        self.url = "http://%s:%d" % self.server.server_address[:2]

    def _dir(self, agent: str) -> str:
        import agent_bus as ab
        d = os.path.join(self.spool, ab._safe_name(agent))
        os.makedirs(os.path.join(d, ".picked"), exist_ok=True)
        return d

    def _note(self, **kw) -> bool:
        """Egy közjegyzői bejegyzés; False, ha a napló be van kapcsolva, de nem írható (→ a hívó fail-closed)."""
        if self.notary is None:
            return True
        try:
            self.notary.record(**kw)
            return True
        except Exception:
            return False

    def deliver(self, env: dict):
        """v1.5: minden elfogadott/elutasított boríték egy közjegyzői bejegyzés (a `from` itt NEM hitelesített → így címkézve;
        a sealed `ct` csak hash-ként kerül a naplóba). Napló-hiba → a boríték nem kerül a spoolba."""
        code, res = self._deliver(env)
        ok = code == 200
        e = env if isinstance(env, dict) else {}
        ts = e.get("ts")
        if not self._note(envelope=env if isinstance(env, (dict, list, str)) else repr(env),
                          sender_identity=str(e.get("from", ""))[:128], sender_auth="unauthenticated-claim",
                          recipient=str(e.get("to", ""))[:128], kind="sealed", decision="accepted" if ok else "rejected",
                          reason="" if ok else str(res.get("error", code)), claimed_ts=ts if isinstance(ts, int) else None):
            if ok:
                self._unwrite(env["to"], res["id"])
            return 503, {"error": "notary unavailable"}
        return code, res

    def _unwrite(self, agent: str, mid: str):
        try:
            os.replace(os.path.join(self._dir(agent), mid + ".json"), os.path.join(self._dir(agent), "." + mid + ".unnotarized"))
        except OSError:
            pass

    def _deliver(self, env: dict):
        if not isinstance(env, dict) or set(env) != set(_ROUTING) or env.get("v") != V:
            return 400, {"error": "malformed (only sealed envelopes are accepted)"}
        if not all(isinstance(env[k], str) and env[k] for k in ("from", "to", "nonce", "ct")):
            return 400, {"error": "malformed"}
        if env["to"] not in self.auth.registry:                      # csak ismert címzettnek van postafiókja
            return 404, {"error": "unknown recipient"}
        with self._rate_lock:                                          # a korlát-ellenőrzés + írás egy kritikus szakasz
            now = time.time()
            win = [x for x in self._rate.get(env["to"], []) if now - x < 60]
            if len(win) >= self.max_per_min_per_recipient:
                return 429, {"error": "rate limited (recipient)"}
            if self.count(env["to"]) >= self.max_pending_per_recipient:
                return 429, {"error": "recipient mailbox full"}
            if self._spool_total() >= self.max_spool_total:
                return 429, {"error": "relay spool full"}
            if self.archive_total() >= self.max_archive_total:
                return 429, {"error": "relay archive full (a lehúzott/naplózatlan borítékok takarítása operátori döntés)"}
            win.append(now)
            self._rate[env["to"]] = win
            return self._write(env)

    def _spool_total(self) -> int:
        n = 0
        try:
            for name in os.listdir(self.spool):
                d = os.path.join(self.spool, name)
                if os.path.isdir(d):
                    n += sum(1 for f in os.listdir(d) if f.endswith(".json"))
        except OSError:
            return self.max_spool_total                                # nem mérhető → fail-closed
        return n

    def archive_total(self) -> int:
        """A LEHÚZOTT (`.picked/`) és a naplózatlanul félbemaradt (`.unnotarized`) borítékok darabszáma.
        Semmit nem töröl: a szám a kvóta-kapuhoz és az operátornak kell (a takarítás az ő döntése)."""
        n = 0
        try:
            for name in os.listdir(self.spool):
                d = os.path.join(self.spool, name)
                if not os.path.isdir(d):
                    continue
                n += sum(1 for f in os.listdir(d) if f.endswith(".unnotarized"))
                pd = os.path.join(d, ".picked")
                if os.path.isdir(pd):
                    n += sum(1 for f in os.listdir(pd) if f.endswith(".json"))
        except OSError:
            return self.max_archive_total                          # nem mérhető → fail-closed
        return n

    def sse_slot(self, agent: str, take: bool) -> bool:
        """SSE-kapcsolat helyfoglalás agentenként. -> True ha van hely (take=True esetén le is foglalja).

        Saját egy hitelesített fél korlátlan `/events` kapcsolatot nyithatott, mindegyik egy szálat
        (és fd-t) tart akár egy órán át -> a relay a `/deliver`-re is megbénul. Agentenként korlátozzuk.
        """
        with self._sse_lock:
            cur = self._sse.get(agent, 0)
            if not take:
                self._sse[agent] = max(0, cur - 1)
                return True
            if cur >= self.max_sse_per_agent:
                return False
            self._sse[agent] = cur + 1
            return True

    def _write(self, env: dict):
        mid = "%d_%s" % (time.time_ns(), os.urandom(4).hex())
        d = self._dir(env["to"])
        tmp = os.path.join(d, "." + mid)
        with open(tmp, "w") as f:
            json.dump(env, f)
        os.replace(tmp, os.path.join(d, mid + ".json"))
        return 200, {"ok": True, "id": mid}

    def count(self, agent: str) -> int:
        return sum(1 for n in os.listdir(self._dir(agent)) if n.endswith(".json"))

    def pickup(self, agent: str) -> list:
        d, out = self._dir(agent), []
        for name in sorted(os.listdir(d)):
            if not name.endswith(".json"):
                continue
            p = os.path.join(d, name)
            try:
                with open(p) as f:
                    out.append(json.load(f))
                os.replace(p, os.path.join(d, ".picked", name))  # nincs törlés
            except (OSError, ValueError):
                continue
        return out

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ── kliens ───────────────────────────────────────────────────────────────────
class RelayClient:
    def __init__(self, url: str, agent: str, sign_seed: bytes, x25519_priv: bytes, peers_x25519: dict):
        _need_crypto()
        self.url, self.agent, self.seed, self.priv, self.peers = url.rstrip("/"), agent, sign_seed, x25519_priv, peers_x25519

    def _post(self, path: str, obj: dict, timeout: float = 15.0) -> dict:
        req = urllib.request.Request(self.url + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operátor által adott relay-URL
            return json.loads(r.read().decode())

    def deliver(self, recipient: str, body: str) -> dict:
        return self._post("/deliver", seal(body, self.agent, recipient, self.priv, self.peers[recipient]))

    def pickup(self) -> list:
        """-> [{"from", "ts", "body"}] — csak a hitelesen visszafejthetők; a többi kimarad (fail-closed)."""
        res = self._post("/pickup", sign_request("pickup", self.agent, self.seed))
        out = []
        for env in res.get("envelopes", []):
            try:
                out.append({"from": env["from"], "ts": env["ts"],
                            "body": unseal(env, self.agent, self.priv, self.peers[env["from"]])})
            except (KeyError, ValueError):
                continue
        return out

    def deliver_attachment(self, recipient: str, store, desc) -> int:
        """Csatolmány a relay-en át: minden darab KÜLÖN sealed boríték ({"attach": leíró, "chunk": darab}).
        -> az elküldött darabok száma. A fogadó `take_attachments()`-szel fűzi össze (hash-ellenőrzéssel)."""
        n = 0
        for ch in store.chunks(desc):
            self.deliver(recipient, json.dumps({"attach": desc, "chunk": ch}))
            n += 1
        return n

    @staticmethod
    def take_attachments(items: list, store) -> tuple:
        """A pickup() eredményéből a csatolmány-darabokat a tárba fűzi. -> (maradék üzenetek, [kész leírók], [hibák])."""
        import bus_attach
        rest, done, errors = [], [], []
        for it in items:
            try:
                obj = json.loads(it["body"])
            except (ValueError, TypeError):
                obj = None
            if not (isinstance(obj, dict) and set(obj) == {"attach", "chunk"}):
                rest.append(it)
                continue
            try:
                d = store.receive_chunk(obj["attach"], obj["chunk"])
                if d:
                    done.append(d)
            except bus_attach.AttachmentError as e:
                errors.append(str(e))
        return rest, done, errors

    def wait_pending(self, timeout: float = 30.0) -> int:
        """SSE: vár, amíg a relay >0 várakozó borítékot jelez. -> a darabszám (0 = lejárt). Ha az SSE nem érhető el,
        pollozásra esik vissza (count-ot nem lát, ezért lehúz: a visszatérés a lehúzható darabszám jelzése)."""
        q = sign_request("events", self.agent, self.seed)
        q["max_seconds"] = str(int(timeout) + 1)
        url = self.url + "/events?" + "&".join("%s=%s" % (k, v) for k, v in q.items())
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=timeout + 5) as r:  # noqa: S310
                for raw in r:
                    line = raw.decode("utf-8", "replace").strip()
                    if line.startswith("data:"):
                        n = int(json.loads(line[5:]).get("count", 0))
                        if n > 0:
                            return n
                    if time.time() - t0 > timeout:
                        return 0
        except (OSError, ValueError):
            return -1                                           # SSE nem él → a hívó pollozzon (pickup())
        return 0
