#!/usr/bin/env python3
"""bus_notary — KÖZJEGYZŐI NAPLÓ a szállítási határon (AgentBus v1.5).

Miért: a v1.4 maradék kockázatai közül kettőt a busz saját eszközei nem zárnak le:
  (a) a visszadátumozás AZ ABLAKON BELÜL (az aláíró választja a ts-t — a partner-kar B2-lelete; a kikényszerítés ablaka a
      kézbesítést védi, nem az időpontot bizonyítja), és
  (b) aki a busz-DB-t írni tudja, az a replay-nyomot is átírhatja — a hash-lánc ezt csak láthatóvá teszi.
A közjegyzői napló a FOGADÁS tényét rögzíti a határon (bus_ssh_exchange, bus_relay), a fogadó óráján, hash-láncban,
időnként a közjegyző Ed25519-kulcsával aláírt ellenőrzőponttal — és ezt MINDKÉT fél letöltheti és összevetheti.
Nem az üzenet igazát bizonyítja, hanem azt, hogy MIKOR és KITŐL (hitelesített identitás) ÉRKEZETT MI (hash).

Bejegyzés (egy JSONL-sor, `type: "entry"`):
    {seq, prev_hash, received_at_ms, envelope_sha256, sender_identity, sender_auth, recipient, kind,
     decision: "accepted"|"rejected"|"delivered", reason, claimed_ts_ms}
  - KIMENŐ irány az SSH-határon: `kind="ack"` (reason "cursor A->B (ack U)"), `kind="pickup"`
    kör-bejegyzés (decision accepted, reason "cursor=C replies=N") és válaszonként `kind="pickup"`, decision `delivered`
    (envelope_sha256 = a kiadott válasz-dict JCS-hash-e). Mind a mellékhatás ELŐTT íródik.
    entry_hash = sha256(JCS(bejegyzés entry_hash nélkül))
  - `sender_auth`: "ssh-key" (force-command identitás) · "pickup-sig" (aláírt lehúzás) · "unauthenticated-claim"
    (a relay /deliver `from` mezője — nem hitelesített, ezért így is címkézve)
  - SOSEM kerül bele titkosított boríték nyílt tartalma: csak hash + metaadat.
Ellenőrzőpont (`type: "checkpoint"`): {seq, head_hash, ts_ms, notary_pub, sig} — sig = Ed25519(JCS(a sig nélküli rész)).

Offline ellenőrzés (bármelyik fél): `verify` újraszámolja a láncot (átírás → hibás entry_hash az adott seq-nél;
törlés → seq-rés; átrendezés → nem növekvő seq / prev_hash-törés), ellenőrzi az ellenőrzőpontok aláírását és hogy a
head_hash egyezik-e; a `claimed_ts_ms`-t (a feladó állított ideje, ms-ra normálva) a `received_at_ms`-hez méri: ami régebbi, mint az ablak, az `backdated-claim`
(BIZONYÍTÉK, nem néma eldobás). `compare A B` két fél exportját veti össze a közös seq-tartományon, bájtra.
FONTOS: a seq-rés csak egy MÁR MEGÍRT bejegyzés törlését bizonyítja; egy meg sem írt bejegyzés nem hagy rést. A kihagyás
elleni védelem a feladó-oldali összevetés: `reconcile` (a távoli fél nyugta-listája — elküldött üzenetek, kapott
válaszok, küldött ack-ok — vs. a napló).

Mód: termék-módban (bus_enforce.mode()) alapból BE, és fail-closed: cryptography vagy közjegyzői kulcs nélkül a
naplózó nem indul → a határ elutasít. Dev-módban alapból KI (back-compat); `AGENT_BUS_NOTARY=on|off` felülírja
(termék-módban kikapcsolni NEM lehet). stdlib (+cryptography az aláíráshoz)."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sds_envelope  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except Exception:                                           # pragma: no cover - környezet-függő
    HAVE_CRYPTO = False

GENESIS = "0" * 64
DEFAULT_CHECKPOINT_EVERY = 50
DEFAULT_BACKDATE_WINDOW_S = 300
ENTRY_KEYS = ("seq", "prev_hash", "received_at_ms", "envelope_sha256", "sender_identity", "sender_auth",
              "recipient", "kind", "decision", "reason", "claimed_ts_ms")
SENDER_AUTH = ("ssh-key", "pickup-sig", "unauthenticated-claim")
DECISIONS = ("accepted", "rejected", "delivered")


class NotaryError(RuntimeError):
    pass


def jcs(v) -> bytes:
    return sds_envelope.jcs(v)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def envelope_hash(obj) -> str:
    """Kanonikus bájtok hash-e (JCS). Nem JCS-képes (pl. float) → a JSON-szerializált szöveg hash-e, jelölve."""
    try:
        return sha256_hex(jcs(obj))
    except ValueError:
        return "json:" + sha256_hex(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def to_ms(ts: int) -> int:
    """A kliens-ts egysége a nagyságrendből: s (relay) · ms · µs · ns (a busz time.time_ns-e)."""
    a = abs(ts)
    if a < 10 ** 11:
        return ts * 1000
    if a < 10 ** 14:
        return ts
    if a < 10 ** 17:
        return ts // 1000
    return ts // 1_000_000


def claimed_ts_of(msg) -> int | None:
    """A feladó által állított időpont: az üzenet `ts`-e, vagy egy SDS-keret rekordjának `ts`-e (ha van)."""
    if not isinstance(msg, dict):
        return None
    for cand in (msg.get("ts"),):
        if isinstance(cand, int) and not isinstance(cand, bool):
            return cand
    if msg.get("kind") == "sds-envelope" and isinstance(msg.get("body"), str):
        try:
            rec, _ = sds_envelope.parse_framed(msg["body"])
            ts = rec.get("ts")
            return ts if isinstance(ts, int) and not isinstance(ts, bool) else None
        except ValueError:
            return None
    return None


def entry_hash(entry: dict) -> str:
    d = {k: entry[k] for k in ENTRY_KEYS}
    if entry.get("cursor") is not None:                  # a kurzor-számok GÉPI, hash-elt mezőben is
        d["cursor"] = entry["cursor"]
    return sha256_hex(jcs(d))


def _ckpt_payload(c: dict) -> bytes:
    return jcs({"type": "checkpoint", "seq": c["seq"], "head_hash": c["head_hash"], "ts_ms": c["ts_ms"],
                "notary_pub": c["notary_pub"]})


# ── kulcs ────────────────────────────────────────────────────────────────────
def keypair():
    """-> (32 bájtos seed, publikus hex). A seed a közjegyző gépén marad."""
    if not HAVE_CRYPTO:
        raise NotaryError("cryptography missing")
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return seed, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def load_seed(path: str) -> bytes:
    raw = open(path, "rb").read().strip()
    try:
        b = bytes.fromhex(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        b = raw
    if len(b) != 32:
        raise NotaryError("notary key must be a 32-byte ed25519 seed (raw or hex)")
    return b


# ── mód ──────────────────────────────────────────────────────────────────────
def is_product(db=None) -> bool:
    try:
        import bus_enforce
        return bus_enforce.mode(db=db) == "product"
    except Exception:                                        # a mód nem dönthető el → a biztonságos oldal
        return True


def enabled(db=None) -> bool:
    if is_product(db):
        return True                                          # termék-módban nem kapcsolható ki
    return (os.environ.get("AGENT_BUS_NOTARY") or "").strip().lower() in ("1", "on", "true", "yes")


def default_log_path() -> str:
    base = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))
    return os.environ.get("AGENT_BUS_NOTARY_LOG") or os.path.join(base, "notary", "notary.jsonl")


# ── naplózó ──────────────────────────────────────────────────────────────────
class Notary:
    """Append-only, hash-láncolt napló. Folyamatok közt flock-kal szerializált; a head a fájl utolsó bejegyzéséből jön."""

    def __init__(self, path: str, seed: bytes | None = None, checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
                 require_signing: bool = False, clock=None, db=None):
        if require_signing and (not HAVE_CRYPTO or seed is None):
            raise NotaryError("product mode: notary needs cryptography and a signing key (fail-closed)")
        self.path, self.seed, self.every, self.db = path, seed, max(1, int(checkpoint_every)), db
        self.clock = clock or (lambda: int(time.time() * 1000))
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            os.close(fd)
        self._priv = Ed25519PrivateKey.from_private_bytes(seed) if (seed is not None and HAVE_CRYPTO) else None
        self.pub = (self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                    if self._priv else None)

    @classmethod
    def from_env(cls, db=None):
        """A határ-integráció belépője: None, ha ki van kapcsolva; termék-módban kulcs/crypto nélkül NotaryError."""
        if not enabled(db):
            return None
        kp = os.environ.get("AGENT_BUS_NOTARY_KEY")
        seed = load_seed(kp) if kp and os.path.exists(kp) else None
        return cls(default_log_path(), seed=seed, require_signing=is_product(db),
                   checkpoint_every=int(os.environ.get("AGENT_BUS_NOTARY_EVERY", DEFAULT_CHECKPOINT_EVERY)), db=db)

    def _tail(self, f):
        """(utolsó seq, utolsó entry_hash, bejegyzés-szám az utolsó ellenőrzőpont óta) — a fájlból, nem memóriából."""
        seq, head, since = 0, GENESIS, 0
        f.seek(0)
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") == "entry":
                seq, head, since = rec["seq"], rec["entry_hash"], since + 1
            elif rec.get("type") == "checkpoint":
                since = 0
        return seq, head, since

    def last_round_cursor(self, identity: str) -> int:
        """A legutóbb naplózott SSH kiadási kör kurzora ennek az identitásnak (0, ha még nincs) — a fájlból."""
        cur = 0
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if (rec.get("type") == "entry" and rec.get("kind") == "pickup" and rec.get("decision") == "accepted"
                            and rec.get("recipient") == identity):
                        cc = rec.get("cursor")                 # gépi mező előbb, csak utána a reason
                        if isinstance(cc, dict) and isinstance(cc.get("at"), int) and not isinstance(cc.get("at"), bool):
                            cur = cc["at"]
                        else:
                            c = _parse_round(rec.get("reason", ""))
                            if c is not None:
                                cur = c[0]
        except FileNotFoundError:
            pass
        return cur

    def record(self, *, envelope, sender_identity: str, sender_auth: str, recipient: str, kind: str,
               decision: str, reason: str = "", claimed_ts=None, cursor: dict | None = None) -> dict:
        if sender_auth not in SENDER_AUTH:
            raise NotaryError("unknown sender_auth")
        if decision not in DECISIONS:
            raise NotaryError("decision must be accepted|rejected|delivered")
        env_sha = envelope if (isinstance(envelope, str) and len(envelope) == 64) else envelope_hash(envelope)
        with open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, head, since = self._tail(f)
                e = {"seq": seq + 1, "prev_hash": head, "received_at_ms": int(self.clock()), "envelope_sha256": env_sha,
                     "sender_identity": str(sender_identity or ""), "sender_auth": sender_auth,
                     "recipient": str(recipient or ""), "kind": str(kind or ""), "decision": decision,
                     "reason": str(reason or "")[:200],
                     "claimed_ts_ms": to_ms(claimed_ts) if (isinstance(claimed_ts, int) and not isinstance(claimed_ts, bool)) else None}
                # a kör-bejegyzés KÖTELEZZE EL MAGÁT a busz audit-láncának fejére.
                # Ezt a KÖZJEGYZŐ teszi, nem az írófél: így egyetlen író sem "felejtheti el" (az `audit_head()` eddig
                # holt kód volt). A horgony a `cursor`-ban utazik, tehát az `entry_hash` köti.
                # A horgony a KÖZJEGYZŐÉ: FELÜLÍRJA az író fél által beírtat is. (Mérve 2026-09-16: a valódi
                # író maga számolta bele, ezért a közjegyzői ág soha nem futott le — és vele a `closes`
                # vállalás sem került be. A horgony értéke így az írófél szava volt, nem a közjegyzőé.)
                if (isinstance(cursor, dict) and kind == "pickup" and decision == "accepted"
                        and ("pending" in cursor or "pending_unknown" in cursor)):
                    try:
                        import agent_bus as _ab
                        _aseq, _ahash = _ab.audit_head(recipient, db=self.db)
                        # üres lánc: a horgony a GENEZIS — „amikor ezt írtam, a busz láncában még nem volt sor".
                        # Ez is állítás, és az összevetés számon kérheti (a 0. sornak meg kell lennie az exportban).
                        # `closes: 1` — a kör VÁLLALJA a záró horgonyt (2.7). Ezt is a KÖZJEGYZŐ írja, nem az
                        # író fél: különben a busz-gép egyszerűen „nem vállalna", és a záratlan kör néma
                        # maradna (a nem-Claude kar ezt a menekülő ajtót mérte ki, miután tévesen azt hitte,
                        # már itt van — a tévedése volt a lelet). A régi naplókban nincs `closes`, tehát
                        # rájuk semmit nem kérünk számon; a vállalás a napló VERZIÓJÁNAK tulajdonsága.
                        cursor = dict(cursor, audit_seq=int(_aseq or 0), audit_hash=_ahash or _ab._GENESIS,
                                      closes=1)
                    except Exception:
                        pass                              # a horgony hiánya nem dönti be a naplózást (fail-open CSAK itt:
                                                          # a bejegyzés maga fontosabb; a hiányát a reconcile látja)
                # TÁMADÁSI MÁTRIX 2.7 (nyitott sor, 2026-09-16): a NYITÓ horgony a kör ELEJÉN íródik, tehát a kör
                # SAJÁT ack-/kiadás-sorait nem köti — egykörös szeleten a második nyilvántartás következetesen
                # újraláncolható volt. A ZÁRÓ horgony a mellékhatások UTÁN íródik, és ugyanúgy a KÖZJEGYZŐ számolja:
                # az író fél nem tudja hamisítani, és nem tudja „elfelejteni" (a hiánya a reconcile-ban látszik).
                if (isinstance(cursor, dict) and kind == "round_close" and decision == "accepted"
                        and "audit_end_seq" not in cursor):
                    try:
                        import agent_bus as _ab
                        _eseq, _ehash = _ab.audit_head(recipient, db=self.db)
                        cursor = dict(cursor, audit_end_seq=int(_eseq or 0), audit_end_hash=_ehash or _ab._GENESIS)
                    except Exception:
                        pass
                if cursor is not None:                    # A4: szigorú típus, nincs int()-mosás
                    # (1a): az EGYETLEN nem-szám mező a busz audit-láncának feje (`audit_hash`,
                    # 64 hex) — a horgony, amire a napló elkötelezi magát. Minden más érték nem-negatív int marad.
                    if not isinstance(cursor, dict):
                        raise NotaryError("cursor must be a dict")
                    for _k, _v in cursor.items():
                        if _k in ("audit_hash", "audit_end_hash"):
                            if not (isinstance(_v, str) and re.fullmatch(r"[0-9a-f]{64}", _v)):
                                raise NotaryError("cursor audit_hash must be 64 hex characters")
                            continue
                        if not (isinstance(_v, int) and not isinstance(_v, bool) and _v >= 0):
                            raise NotaryError("cursor values must be non-negative int")
                    e["cursor"] = dict(cursor)
                e["entry_hash"] = entry_hash(e)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(dict(type="entry", **e), ensure_ascii=False, sort_keys=True) + "\n")
                if self._priv is not None and since + 1 >= self.every:
                    f.write(json.dumps(self._checkpoint(e["seq"], e["entry_hash"]), sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return e
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _checkpoint(self, seq: int, head: str) -> dict:
        c = {"type": "checkpoint", "seq": seq, "head_hash": head, "ts_ms": int(self.clock()), "notary_pub": self.pub}
        c["sig"] = self._priv.sign(_ckpt_payload(c)).hex()
        return c

    def checkpoint(self) -> dict:
        if self._priv is None:
            raise NotaryError("no signing key")
        with open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, head, _ = self._tail(f)
                c = self._checkpoint(seq, head)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(c, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return c
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


# ── export / verify / compare (offline, bármelyik fél) ───────────────────────
def _no_evidence(recs):
    """A napló akkor ÜRES, ha nincs benne BIZONYÍTÉK — nem akkor, ha nincs benne SOR.

    a mai `if not _recs:` kikötés a `read_lines` SORAINAK számára szólt.
    Egyetlen érvényes JSON-objektum (`{}` vagy `{"kind": "valami"}`) nem-üressé teszi a listát, a BEJEGYZÉSEK
    száma viszont marad nulla — és a `verify()` a nem-`entry`/nem-`checkpoint` rekordot némán átugorja. Tehát
    ZÖLD bizonyítvány nulla bejegyzés fölött, egy órával azután, hogy ugyanezt az állapotot nevesített
    elutasításra tettük. Nem kell hozzá rosszindulat: egy gördülő verziófrissítés ismeretlen rekordtípusa
    pontosan így néz ki. -> (üres-e, hány entry, hány checkpoint)
    """
    n_e = sum(1 for r in recs if isinstance(r, dict) and r.get("type") == "entry")
    n_c = sum(1 for r in recs if isinstance(r, dict) and r.get("type") == "checkpoint")
    return (n_e == 0 and n_c == 0), n_e, n_c


def _reject_no_evidence(recs, cmd):
    """-> True, ha elutasítottuk (a hívó ilyenkor rc=1-gyel áll meg)."""
    empty, n_e, n_c = _no_evidence(recs)
    if not empty:
        return False
    print(json.dumps({"ok": False, "reason": "empty_log", "records": len(recs),
                      "entries": n_e, "checkpoints": n_c}, ensure_ascii=False, indent=1))
    print("bus_notary %s: REJECT — a napló %d rekordot tartalmaz, de ebből 0 bejegyzés és 0 ellenőrzőpont. "
          "Ez nem hibátlan napló, hanem NULLA BIZONYÍTÉK: nincs mit ellenőrizni, tehát nincs mit igazolni."
          % (cmd, len(recs)), file=sys.stderr)
    return True


def read_lines(path: str) -> list:
    """A MÁSIK fél exportja FÁJLKÉNT — megbízhatatlan bemenet, nevesített elutasítással.

    Mérve 2026-09-16 (a capsule2-oldalon ugyanezt az osztályt zártam, aztán megnéztem itt is):
      * `5` egy sorban   -> `AttributeError: 'int' object has no attribute 'get'` — NYERS TRACEBACK
      * `[1,2,3]`        -> `AttributeError: 'list' object …`                     — NYERS TRACEBACK
      * ÜRES fájl        -> **rc=0, ZÖLD** — a legüresebb lehetséges bemenet átment a `verify`-on
    A `type: garbage` sor jó ötlet volt (a nem-JSON sor nem száll el), de csak a JSON-hibát fedte: ami
    JSON-ként érvényes, de nem OBJEKTUM, az egyenesen a `.get()`-be futott. Az üres fájl pedig nem
    „hibátlan napló", hanem NULLA BIZONYÍTÉK — a mérés hiánya nem zöld.
    """
    out = []
    with open(path, encoding="utf-8-sig") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                out.append({"type": "garbage", "line": n})
                continue
            if not isinstance(rec, dict):
                # érvényes JSON, de nem bejegyzés: ugyanaz az osztály, nevesítve
                out.append({"type": "garbage", "line": n, "parsed_as": type(rec).__name__})
                continue
            out.append(rec)
    return out


def export(path: str, from_seq: int = 1) -> list:
    """A from_seq-től kezdődő bejegyzések + a LEGUTOLSÓ aláírt ellenőrzőpont (a sorrend megmarad)."""
    recs = read_lines(path)
    entries = [r for r in recs if r.get("type") == "entry" and r.get("seq", 0) >= from_seq]
    ckpts = [r for r in recs if r.get("type") == "checkpoint"]
    return entries + ([ckpts[-1]] if ckpts else [])


def verify(records: list, trusted_pub: str | None = None, backdate_window_s: int = DEFAULT_BACKDATE_WINDOW_S,
           start_prev_hash: str | None = None) -> dict:
    """-> {ok, errors:[{seq, error}], checkpoints:[{seq, ok, error?}], backdated:[{seq, claimed_ts, received_at_ms}], head}.
    Egy export a from_seq-től is ellenőrizhető: az első bejegyzés prev_hash-ét elfogadja (vagy start_prev_hash-hez köti)."""
    errors, ckpts, backdated = [], [], []
    computed = {}
    last_seq, last_hash = None, None
    for r in records:
        t = r.get("type")
        if t == "garbage":
            errors.append({"seq": None, "error": "unparseable line %s" % r.get("line")})
            continue
        if t == "entry":
            try:
                h = entry_hash(r)
            except (KeyError, ValueError, TypeError):
                errors.append({"seq": r.get("seq"), "error": "malformed entry"})
                continue
            seq = r.get("seq")
            if h != r.get("entry_hash"):
                errors.append({"seq": seq, "error": "entry rewritten (hash mismatch)"})
            if last_seq is None:
                if start_prev_hash is not None and r.get("prev_hash") != start_prev_hash:
                    errors.append({"seq": seq, "error": "chain does not continue from the given prev_hash"})
                if seq == 1 and r.get("prev_hash") != GENESIS:
                    errors.append({"seq": seq, "error": "first entry must start at genesis"})
            else:
                if not isinstance(seq, int) or seq <= last_seq:
                    errors.append({"seq": seq, "error": "reordered (seq %s after %s)" % (seq, last_seq)})
                elif seq != last_seq + 1:
                    errors.append({"seq": seq, "error": "gap: entries %d..%d missing" % (last_seq + 1, seq - 1)})
                if r.get("prev_hash") != last_hash:
                    errors.append({"seq": seq, "error": "chain broken (prev_hash does not match previous entry)"})
            ct = r.get("claimed_ts_ms")
            if isinstance(ct, int) and not isinstance(ct, bool):
                if ct < r.get("received_at_ms", 0) - backdate_window_s * 1000:
                    backdated.append({"seq": seq, "claimed_ts_ms": ct, "received_at_ms": r.get("received_at_ms")})
            computed[seq] = r.get("entry_hash")
            if isinstance(seq, int) and (last_seq is None or seq > last_seq):
                last_seq, last_hash = seq, r.get("entry_hash")
        elif t == "checkpoint":
            # a report megmutatja, MELYIK kulcs írta alá; „trusted" csak csatornán kívül rögzített --pub-bal
            c = {"seq": r.get("seq"), "ok": True, "notary_pub": r.get("notary_pub"),
                 "trusted": bool(trusted_pub) and r.get("notary_pub") == trusted_pub}
            if not HAVE_CRYPTO:
                c.update(ok=False, error="cannot verify signature: cryptography missing")
            elif trusted_pub and r.get("notary_pub") != trusted_pub:
                c.update(ok=False, error="checkpoint signed by an untrusted key")
            else:
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["notary_pub"])).verify(bytes.fromhex(r["sig"]),
                                                                                                _ckpt_payload(r))
                except (InvalidSignature, KeyError, ValueError, TypeError):
                    c.update(ok=False, error="forged checkpoint signature")
            if c["ok"] and r.get("seq") in computed and computed[r["seq"]] != r.get("head_hash"):
                c.update(ok=False, error="checkpoint head_hash does not match the chain")
            if c["ok"] and r.get("seq") not in computed and r.get("seq", 0) > (last_seq or 0):
                c.update(ok=False, error="checkpoint points beyond the exported chain")
            if not c["ok"]:
                c["trusted"] = False
                errors.append({"seq": r.get("seq"), "error": c["error"]})
            ckpts.append(c)
    # `ok` = a lánc és az aláírások belső konzisztenciája; `trusted` = ÉS a szeletben legalább egy ellenőrzőpont a megadott,
    # megbízott kulccsal TÉNYLEGESEN ellenőrződött, és egy exportált bejegyzés head_hash-éhez kötődik.
    # --pub nélkül egy bárki által generált kulccsal aláírt, kitalált lánc is `ok` — ezért ott `trusted` sosem igaz.
    # ellenőrzőpont nélküli szelet (friss napló <N bejegyzése, vagy a következő ellenőrzőpont
    # előtti export) a helyes --pub-bal sem „megbízható": ott egyetlen aláírás sem ellenőrződött, csak a hash-lánc.
    verified = [c for c in ckpts if c["ok"] and c["trusted"] and c["seq"] in computed]
    covered_to = max((c["seq"] for c in verified), default=None)
    entry_seqs = [s for s in computed if isinstance(s, int)]
    unverified_tail = len([s for s in entry_seqs if covered_to is None or s > covered_to])
    # a `trusted` a SZELETRE vonatkozó állítás — csak akkor igaz, ha a szelet
    # MINDEN bejegyzését lefedi egy ellenőrzött ellenőrzőpont (unverified_tail == 0). Az utolsó ellenőrzőpont utáni
    # farok (átírt vagy kitalált, újraláncolt bejegyzések) csak a hash-láncon áll, aláírás nem köti → trusted:false.
    trusted = (not errors) and bool(trusted_pub) and bool(verified) and unverified_tail == 0
    # a "cursor F->T (ack U)" bejegyzés belső konzisztenciája a naplóból, a fél nélkül is
    # ellenőrizhető — a becsületes clamp T = max(F, min(U, cap)), tehát T <= max(F, U). Külön mező (nem lánc-hiba: a
    # szelet lehet aláírtan ép és mégis hazug); a CLI rc=1-gyel jelzi.
    ack_violations = []
    for r in records:
        if r.get("type") == "entry" and r.get("kind") == "ack" and r.get("decision") == "accepted":
            c = r.get("cursor")                                # a verify is a GÉPI mezőt olvassa előbb
            if isinstance(c, dict) and all(isinstance(c.get(k), int) and not isinstance(c.get(k), bool) for k in ("from", "to", "ack")):
                frm, to, up = c["from"], c["to"], c["ack"]
            else:
                m = _ACK_RE.match(r.get("reason", "") or "")
                frm, to, up = (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (None, None, None)
            if to is not None and to > max(frm, up):
                ack_violations.append({"seq": r.get("seq"), "recipient": r.get("recipient"), "reason": r.get("reason"),
                                       "cursor_from": frm, "cursor_to": to, "ack": up})
    # Saját a `trusted` eddig CSAK a szelet farkát mérte. A szelet ELEJE ugyanígy állítás:
    # egy `export --from-seq 11` szelet belsőleg ép és aláírt lehet, miközben az 1..10 bejegyzés hiányzik. A hiányt a
    # napló önmagában nem mutatja — ezért a jelentés kimondja, hol kezdődik a szelet, és hogy HORGONYZOTT-e
    # (genesis-től indul, vagy a hívó megadott egy csatornán kívül ismert `start_prev_hash`-t).
    slice_start = min(entry_seqs) if entry_seqs else None
    anchored = bool(start_prev_hash) or slice_start == 1
    return {"ok": not errors, "trusted": trusted and anchored, "signer_unverified": not verified,
            "slice_start_seq": slice_start, "anchored": anchored,
            "ack_target_violations": ack_violations,
            "checkpoint_count": len(ckpts), "verified_checkpoint_count": len(verified),
            "no_checkpoint_in_range": not verified, "covered_to_seq": covered_to, "unverified_tail": unverified_tail,
            "signers": sorted({c["notary_pub"] for c in ckpts if c.get("notary_pub")}),
            "errors": errors, "checkpoints": ckpts, "backdated": backdated,
            "head": {"seq": last_seq, "hash": last_hash}}


def compare(a: list, b: list) -> dict:
    """Két fél exportja ugyanarról a láncról szól-e. -> {same, fork, reason, overlap, compared, first_diff}.

    37Z): a korábbi változat CSAK a közös seq-ű bejegyzéseket vetette össze, és
    közös seq híján same:true-t adott — egy fork két, egymás mellé exportált ága így „ugyanaz" volt, a checkpointok
    pedig ki sem értékelődtek. Most minden, ami a két export közt ÖSSZEVETHETŐ, összevetődik:
      1. azonos seq-ű bejegyzések kanonikus bájtjai;
      2. azonos seq-ű ellenőrzőpontok head_hash-e (eltérés = fork);
      3. ellenőrzőpont az egyik, bejegyzés a másik oldalon ugyanazon a seq-en (head_hash != entry_hash = fork);
      4. határ-láncolás: az egyik oldal s-edik bejegyzése után a másik oldal s+1-edikének prev_hash-e (eltérés = fork).
    Ha EGYIK sem volt összevethető: same=None, reason="no_overlap" — ez NEM „rendben"."""
    def entries(x):
        return {r["seq"]: r for r in x if r.get("type") == "entry" and isinstance(r.get("seq"), int)}

    def ckpts(x):
        return {r["seq"]: r.get("head_hash") for r in x if r.get("type") == "checkpoint" and isinstance(r.get("seq"), int)}
    ea, eb, ca, cb = entries(a), entries(b), ckpts(a), ckpts(b)
    compared, seqs = 0, set()

    def verdict(same, reason, s=None):
        rng = [min(seqs), max(seqs)] if seqs else None
        return {"same": same, "fork": same is False, "reason": reason, "overlap": rng, "compared": compared,
                "first_diff": s}

    checks = []
    for s in sorted(set(ea) & set(eb)):
        checks.append((s, "entry_differs", jcs(ea[s]) == jcs(eb[s])))
    for s in sorted(set(ca) & set(cb)):
        checks.append((s, "checkpoint_head_differs", ca[s] == cb[s]))
    for side_c, side_e in ((ca, eb), (cb, ea)):
        for s in sorted(set(side_c) & set(side_e)):
            checks.append((s, "checkpoint_vs_entry_differs", side_c[s] == side_e[s].get("entry_hash")))
    for left, right in ((ea, eb), (eb, ea)):
        for s in sorted(left):
            if s + 1 in right and s + 1 not in left:
                checks.append((s + 1, "chain_link_differs", right[s + 1].get("prev_hash") == left[s].get("entry_hash")))
    for s, reason, ok in sorted(checks, key=lambda c: c[0]):
        compared += 1
        seqs.add(s)
        if not ok:
            return verdict(False, reason, s)
    if not compared:
        return verdict(None, "no_overlap")
    return verdict(True, "consistent")


# ── reconcile: a távoli fél nyugtái vs. a napló ─────────────────────────────
_ROUND_RE = re.compile(r"^cursor=(\d+) replies=(\d+)$")
_ACK_RE = re.compile(r"^cursor (\d+)->(\d+) \(ack (\d+)\)$")


def _parse_round(reason):
    m = _ROUND_RE.match(reason or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


PROVEN_ARRIVED = ("delivered", "reached")   # a kliens-kimenetel, ami bizonyítja, hogy a kérés odaért


_GENESIS_HASH = "0" * 64                                   # üres lánc horgonya (agent_bus._GENESIS)


def _audit_cross(entries, identity, bus_audit, entries_all=None):
    """54Z nyitott tétele: a kör-bejegyzés ÖNBEVALLOTT számait a busz SAJÁT, hash-láncolt
    cursor_audit exportjához mérjük. A napló önmagában nem cáfolja a hazug `pending`/`next_id`-t — a két
    nyilvántartás ellentmondása viszont bizonyíték. -> eltérés-lista (hard)."""
    out = []
    # az `agent: None` elfogadásának nincs jó oka (ma csak hamisítással érhető el),
    # és egy IDEGEN agent exportja eddig NÉMÁN 0 vizsgálandó sorra szűkült — a fájl nem volt üres, tehát a
    # „hiányos bizonyíték" kapun is átment. Mindkettő kimondva.
    given = [r for r in (bus_audit or []) if isinstance(r, dict)]
    rows = [r for r in given if r.get("agent") == identity]
    # a kör-bejegyzések horgonyai: a napló ELKÖTELEZTE magát, meddig kell érnie az exportnak
    anchored_rounds = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "pickup"
                       and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)
                       and ("pending" in e["cursor"] or "pending_unknown" in e["cursor"])]
    # A KONZISZTENS ÍRÓ (MEDIUM (b), mérve): aki a naplót írja, a láncot is maga számolja,
    # tehát a hash-guard NEM véd a mezői ellen. A `cursor` almezőinek söprése ezt számszerűen mutatja: a te
    # szeletedben (aláírt checkpoint NÉLKÜL) 68 hamisításból 42 néma marad; UGYANAZ a söprés egy olyan
    # exporton, ami tartalmaz ALÁÍRT checkpointot, 0 némát ad. A különbséget nem az adja, hogy bárki OLVASSA
    # azokat a mezőket, hanem az ALÁÍRÁS: az író újraláncolhat, de a közjegyző checkpointját nem tudja újra
    # aláírni. Egy checkpoint NÉLKÜLI szelet fölött tehát az író szava az egyetlen fedezet — és ezt eddig
    # semmi nem mondta ki. (Harmadik csatorna: kimondva, nem verdikt — `soft`-ba téve minden olyan teszt
    # pirosra váltana, ami ritka checkpointtal dolgozik.)
    if anchored_rounds and not any(r.get("type") == "checkpoint" for r in entries_all or []):
        out.append({"type": "slice_without_signed_checkpoint", "rounds": [e.get("seq") for e in anchored_rounds][:4],
                    "note_only": True,
                    "why": "ebben a szeletben NINCS aláírt ellenőrzőpont, ezért a benne szereplő önbevallott "
                           "számok mögött csak az ÍRÓ szava áll: aki a naplót írja, a hash-láncot is "
                           "újraszámolhatja"})
    if bus_audit is None and anchored_rounds:
        # A NEGYEDIK kísérlet ugyanarra a tételre (az egyik kar két nyitott `test_joint_delivery_outcome`
        # szondája), most MÉRVE, nem emlékezetből. A `soft` (= `unresolved`) csatornába téve a jelzés strict
        # módban `ok:false`-ot ad, és ez HÁROM becsületes KONTROLL-tesztet tesz pirossá — kettő az övé:
        #   test_joint_clamp_optout::test_control_honest_round_is_not_accused
        #   test_joint_cursor_skips_undelivered::test_control_honest_full_round_is_not_accused
        #   test_log_shape_20260916::test_control_the_untouched_export_is_green
        # Ezek azt kötik, hogy a BECSÜLETES kört ne vádoljuk — és igazuk van. A hiányzó második nyilvántartás
        # viszont NÉMA sem maradhat: `reconcile` MÁSODIK NYILVÁNTARTÁS NÉLKÜL nem tudja megmérni, hogy a kurzor
        # átlépett-e kiadatlan posta fölött, tehát a „nem hagytam ki semmit" állítás itt ELLENŐRIZETLEN.
        # Ezért a ma bevezetett HARMADIK csatornára megy (`notes` + számláló): kimondva, de nem verdikt.
        out.append({"type": "audit_register_absent", "rounds": [e.get("seq") for e in anchored_rounds][:4],
                    "note_only": True,
                    "why": "a `bus_audit` második nyilvántartás nélkül a kör önbevallott számai "
                           "ELLENŐRIZETLENEK — ez nem vád és nem zöld pipa, hanem hiányzó mérés"})
    if bus_audit is not None and not given and anchored_rounds:
        # 9/4: az ÜRESEN átadott export a könyvtári úton eddig némán 0 vizsgálandó sorra szűkült
        out.append({"type": "audit_evidence_absent", "rounds": [e.get("seq") for e in anchored_rounds]})
        return out
    if given and not rows:
        out.append({"type": "audit_identity_mismatch", "identity": identity,
                    "export_agents": sorted({str(r.get("agent")) for r in given})})
        return out
    if not rows:
        return out
    # 9/2: a könyvtári út eddig NEM futtatta a lánc-önellenőrzést (csak a CLI), így egy seq-hézagos
    # („0..5 és 10..12") export átment. A hézag pont az, amivel a bizonyíték kioltható.
    try:
        import agent_bus as _ab
        _chk = _ab.audit_chain_verify(rows)
        # a LÁNC épsége a kérdés itt; a horgonyt a kör-bejegyzések `audit_seq`/`audit_hash` mezője köti
        # (`audit_head_not_covered` / `audit_head_hash_mismatch`), ezért a `chain_ok`-ot olvassuk, nem az `ok`-ot
        if not _chk.get("chain_ok", _chk.get("ok")):
            out.append({"type": "audit_chain_broken", "errors": _chk.get("errors", [])[:4]})
            return out
    except Exception as _e:
        # Saját rendszeres felmérés (2026-09-16): ez az ág `except Exception: pass` volt, tehát ha a
        # lánc-önellenőrzés BÁRMIÉRT dob (hiányzó mező, rossz típus a másik fél exportjában), a
        # `audit_chain_broken` NÉMÁN eltűnt — a mérés HIÁNYA zöldnek látszott. Ez ugyanaz az osztály, amit a
        # korpusz-oldalon a B-kar háromszor kimondott: a hiányzó mérés HARMADIK ÁLLAPOT, nem zöld.
        out.append({"type": "audit_chain_unverifiable", "error": _e.__class__.__name__, "soft": True})
    acks = [r for r in rows if str(r.get("op", "")).startswith("ack")]
    # 1) a naplózott ack-ok kurzor-lépései egyezzenek a busz audit-soraival (from_id -> to_id)
    logged = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "ack"
              and e.get("decision") == "accepted"]
    # (2026-09-17): a két nyilvántartás párosítása POZÍCIÓ szerint ment (`zip`), ezért egy kieső napló-ack után
    # minden további pár ELCSÚSZOTT, és a vád BECSÜLETES bejegyzésre mutatott (mérve: a 3. napló-ack 20→30 és a 3. audit-
    # sor ugyanezt mondja, mégis mismatch, mert a zip a 2. audit-sorral párosította). Most KULCSRA párosítunk: az audit-sor
    # (from_id, to_id) lépése ↔ a napló-ack (cursor.from, cursor.to) lépése, napló-sorrendben, egy sor legfeljebb egyszer.
    def _step_a(a):
        return (a.get("from_id"), a.get("to_id"))

    def _step_e(e):
        c = e.get("cursor") if isinstance(e.get("cursor"), dict) else {}
        return (c.get("from"), c.get("to"))

    _free = list(range(len(logged)))
    _pair = {}                                                   # audit index -> napló-ack index
    for _ai, _a in enumerate(acks):
        for _li in _free:
            if _step_e(logged[_li]) == _step_a(_a):
                _pair[_ai] = _li
                _free.remove(_li)
                break
    _unpaired_audit = [a for _ai, a in enumerate(acks) if _ai not in _pair]
    for _li in _free:
        # naplózott ack, amelyikhez NINCS azonos lépésű audit-sor: a vád a napló-bejegyzésre mutat, és a párosítatlan
        # audit-lépéseket mutatja mellé (nem egy pozíció szerint kisorsolt, esetleg becsületes sort)
        e = logged[_li]
        frm, to = _step_e(e)
        if isinstance(frm, int) and isinstance(to, int):
            out.append({"type": "audit_cursor_mismatch", "seq": e.get("seq"), "log": [frm, to],
                        "bus_audit": [[a.get("from_id"), a.get("to_id")] for a in _unpaired_audit][:4],
                        "audit_seq": [a.get("seq") for a in _unpaired_audit][:4]})
    # MÁSODIK menet, sorrendben: ami kulcsra nem párosult (pl. a napló-ack `to` NÉLKÜL — a kvantor-vállalás teszt szerint
    # egy hiányzó ack-cél nem vásárolhat csendet), azt a VÁD-ATTRIBÚCIÓHOZ pozíció szerint párosítjuk. Az eltérés-jelentés
    # (fent) és a fedettség (`audit_row_unlogged`, lent) a kulcs-menet eredményén áll — az elcsúszás oda nem ér el.
    for _ai, _li in zip([ai for ai in range(len(acks)) if ai not in _pair], list(_free)):
        _pair[_ai] = _li
    # 2) a busz audit-sora tudja, hány kiadatlan fölött lépett a kurzor (skipped_undelivered) — a napló „nincs
    #    kiadatlan" (next_id=0 / pending==replies) állítása ezzel ellentmondásba kerül
    skipped = sum(int(a.get("skipped_undelivered") or 0) for a in acks)
    rounds = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "pickup"
              and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)]
    # a napló ack-jainak legmagasabb célja: eddig mozdult a kurzor a napló szerint
    ack_top = max([c.get("to") for c in (e.get("cursor") for e in logged)
                   if isinstance(c, dict) and isinstance(c.get("to"), int)] or [0])

    def _claims_no_skip(cur, ack_top=ack_top):
        """A kör-bejegyzés azt állítja, hogy az ack alatt NEM maradt kiadatlan?

        Az `ack_top` mostantól ANNAK a körnek az ack-célja, amelyikről szó van,
        nem a napló globális maximuma: a vádat körhöz kell rendelni, különben egy MÁSIK kör adata dönt róla.
        """
        if cur.get("pending") == cur.get("replies"):
            return True                                        # „annyit adtam ki, amennyi volt"
        nid = cur.get("next_id")
        if not nid:
            return True                                        # „nincs első kiadatlan"
        # utáni kör: a hazug `next_id` az ack CÉLJA FÖLÉ tolható — ez ugyanúgy „nem hagytam ki
        # semmit az ack alatt" állítás, tehát a busz skipped_undelivered sorával ellentmondásba kerül.
        # 8/3: CSAK akkor, ha tényleg LÁTTUNK naplózott ack-célt. `ack_top == 0` (régi/idegen
        # formátum, hiányzó `to`) esetén ez a fallback minden becsületes csonkolt kört megvádolna — a
        # hallgatás nem bizonyíték, a hiányzó ack-cél pedig hiányos bizonyíték, nem vád.
        return bool(ack_top) and isinstance(nid, int) and nid > ack_top
    # BLOCKER (mérve, reprodukálva): a vád GLOBÁLIS ÉS-kapcsolaton állt —
    #   `claimed_all = all(_claims_no_skip(r["cursor"]) for r in rounds)`
    # — a `skipped` az EGÉSZ naplóra összegezve, a kvantor viszont MINDEN kör-bejegyzésre. Elég volt egyetlen
    # további, ÖNMAGÁBAN BECSÜLETES kör (ami bevall egy kiadatlant az ack-célja alatt), és a vád VISSZAMENŐLEG
    # lekerült az ÖSSZES körről — arról is, amelyik hazudott, miközben a busz hash-láncolt audit-sora
    # változatlanul tudta, hogy 4 üzenet véglegesen elveszett. A megkerüléshez nem kell kriptográfia, nem törik
    # a lánc, nem hamisít semmit: egy szabályos sort ír hozzá, amilyet a rendes működés amúgy is termel.
    # Javítva a MEGLÉVŐ párosításra építve (`zip(logged, acks)`): a kihagyás ahhoz a körhöz tartozik, amelyiknek
    # az ACK-je hozta a `skipped_undelivered > 0`-t, és az állítást ANNAK a körnek a bejegyzésén mérjük.
    _accused, _unattributable = [], []
    for _i, _a in enumerate(acks):
        _sk = int(_a.get("skipped_undelivered") or 0)
        if _sk <= 0:
            continue
        _li = _pair.get(_i)                                      # kulcsra párosított napló-ack, nem pozíció
        _e = logged[_li] if _li is not None else None
        if _e is None:
            # Az audit-sor tud egy kihagyásról, amihez a naplóban NINCS ack. Ez nem vád (a fedettséget a
            # `audit_row_missing` méri a másik irányban), de nem is zöld: a mérés HIÁNYZIK.
            _unattributable.append({"type": "audit_skip_unattributable", "audit_seq": _a.get("seq"),
                                    "skipped_undelivered": _sk, "soft": True})
            continue
        _c = _e.get("cursor") if isinstance(_e.get("cursor"), dict) else {}
        _ack_to = _c.get("to") if isinstance(_c.get("to"), int) and not isinstance(_c.get("to"), bool) else 0
        _eseq = _e.get("seq") if isinstance(_e.get("seq"), int) and not isinstance(_e.get("seq"), bool) else None
        # BLOCKER (mérve, reprodukálva a szondájával: 2 piros / 3 zöld kontroll).
        # A felelős kört eddig az ack ELŐTTI UTOLSÓ `pickup` adta (`_cand[-1]`) — csakhogy a naplót AZ írja,
        # akit ellenőrzünk, tehát a támadó MEGVÁLASZTHATTA, ki feleljen: elég egy további `pickup`-ot a hazug
        # kör és a SAJÁT ack-je KÖZÉ írni, ami a `cursor`-jából KIHAGYJA a `pending`-et. Az ilyen bejegyzés
        # semmit nem állít („nem én mondtam, hogy nem hagytam ki semmit"), a vád mégis rá szállt — és eltűnt.
        # Dev-módban (a CLI alapértelmezése) ettől rc=0, ok:true lett NÉGY véglegesen elveszett üzenet fölött.
        # Ez a saját „opcionális gépi mező = néma opt-out" osztályunk, harmadik szabadságfokon: előbb a
        # KVANTOR (b66bac3), aztán a SORREND (40396fc), most az, hogy KI FELEL.
        #
        # A javítás az ő javaslata, mérve: a felelős nem egy kiszemelhető bejegyzés, hanem az ACK-ABLAK —
        # az előző naplózott ack és EZ az ack között nyitott MINDEN kör —, és az ablakon belül az felel,
        # aki ÁLLÍTJA, hogy nem hagyott ki semmit. Aki hallgat, az nem felel, de nem is MENTESÍT mást.
        _pseq = None
        if _li > 0:                                              # az ack-ablak határa: a NAPLÓBAN előző ack (kulcs szerinti pár)
            _p = logged[_li - 1].get("seq")
            _pseq = _p if isinstance(_p, int) and not isinstance(_p, bool) else None
        _cand = [r for r in rounds if isinstance(r.get("seq"), int)
                 and (_eseq is None or r["seq"] < _eseq)
                 and (_pseq is None or r["seq"] > _pseq)]
        _claimers = [r for r in _cand if _claims_no_skip(r["cursor"], _ack_to)]
        _gov = _claimers[-1] if _claimers else (_cand[-1] if _cand else None)
        if _gov is None:
            # A nem-Claude kar köre a kvantor-javításra (és IGAZ): ha a kör-bejegyzés az
            # ack UTÁN áll a naplóban, nincs „előtte" kör, és a KEMÉNY vád némán SOFT-ra gyengült — a támadó
            # tehát pusztán a SORRENDDEL bizonyítékot minősít le. A sorrend maga viszont protokoll-sértés:
            # a kört megnyitó `pickup` nem állhat a saját ack-je mögött. Ezért a vádat az ack UTÁNI legelső
            # körre kötjük, és a rendellenes sorrendet KIMONDJUK.
            _after = [r for r in rounds if isinstance(r.get("seq"), int)
                      and _eseq is not None and r["seq"] > _eseq]
            if _after:
                _gov = _after[0]
                out.append({"type": "round_entry_after_its_ack", "round_seq": _gov.get("seq"),
                            "ack_seq": _e.get("seq"),
                            "note": "a kört megnyitó bejegyzés a saját ack-je MÖGÖTT áll a naplóban"})
        if _gov is None:
            # SAJÁT KÖR: a partner három
            # szabadságfokot talált (kvantor, sorrend, ki felel), és mindháromra kapu került. Azt
            # állítottam, hogy a gyökér nem a kapuk hiánya, hanem az, hogy az ELLENŐRZÖTT FÉL ÍRJA A
            # BIZONYÍTÉKOT SZABAD ALAKBAN — és ezt meg is kell mérnem, nem elég állítani. Mérve:
            #
            #   a `rounds` szűrő NÉGY mezőn áll (`recipient`, `kind`, `decision`, `cursor` típusa),
            #   és MIND A NÉGY a támadó kezében van. Bármelyiket elrontva a hazug kör KIESIK a
            #   szűrőből, a KEMÉNY vád pedig némán `audit_skip_unattributable`-re (soft) gyengül —
            #   dev-módban `ok=true` NÉGY véglegesen elveszett üzenet fölött.
            #
            # A javítás ezért NEM ötödik kapu. A különbségtétel a lényeg:
            #   * az ablakban EGYÁLTALÁN NINCS bejegyzés  -> tényleg nem mérhető (soft, marad)
            #   * az ablakban VAN bejegyzés, de egyik sem ILLIK a kör alakjára -> ez nem a bizonyíték
            #     HIÁNYA, hanem a bizonyíték KIKERÜLÉSE: a napló épp azon a helyen tartalmaz sorokat,
            #     ahol felelnie kellene, csak olyan alakban, amit a szűrő nem vesz kézbe. Ez VÁD.
            # BLOCKER — AZ ÖTÖDIK szabadságfok, pontosan ott, ahol a 3. pontom megjósolta:
            # ez az ablak a `kind != "ack"` CÍMKÉRE szűrt, és a címkét az írja, akit vizsgálunk. A hazug kört
            # `kind="ack"`-ra átcímkézve kiesett a `rounds`-ból (nincs kit vádolni), a `logged`-ból (nincs
            # audit_row_missing) ÉS ebből az ablakból is -> maradt a néma soft, dev-módban rc=0 HAT véglegesen
            # elveszett üzenet fölött. A `kind` fehérlistázása NEM segít (mérte): az "ack" szabályos érték.
            # A javítás az ő javaslata, mérve: a kizárás ne a CÍMKÉN álljon, hanem azon a halmazon, amelyik az
            # ablak HATÁRÁT adja — a naplózott ack-ok seq-jein. Aki nem határ, az bent van az ablakban.
            _ack_seqs = {e.get("seq") for e in logged}
            _win = [e for e in entries
                    if isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool)
                    and (_eseq is None or e["seq"] < _eseq) and (_pseq is None or e["seq"] > _pseq)
                    and e.get("seq") not in _ack_seqs]
            if _win:
                out.append({"type": "round_shape_dodges_attribution", "audit_seq": _a.get("seq"),
                            "skipped_undelivered": _sk, "ack_seq": _e.get("seq"),
                            "entries_in_window": [e.get("seq") for e in _win][:4],
                            "note": "a busz audit-sora kihagyást mond, az ack-ablakban VANNAK bejegyzések, "
                                    "de egyik sem a kör alakjában — a felelős nem hiányzik, hanem kikerül"})
            else:
                _unattributable.append({"type": "audit_skip_unattributable", "audit_seq": _a.get("seq"),
                                        "skipped_undelivered": _sk, "ack_seq": _e.get("seq"), "soft": True})
            continue
        if _claims_no_skip(_gov["cursor"], _ack_to):
            _accused.append({"round_seq": _gov.get("seq"), "audit_seq": _a.get("seq"),
                             "skipped_undelivered": _sk})
    if _accused:
        out.append({"type": "audit_skipped_contradicts_log",
                    "skipped_undelivered": sum(x["skipped_undelivered"] for x in _accused),
                    "rounds": [x["round_seq"] for x in _accused], "per_round": _accused[:4]})
    out.extend(_unattributable[:4])
    # 3) FEDETTSÉG (BLOCKER): egy RÖVIDEBB, de belsőleg ép export nem hazugság és nem hamisítás — mégis
    #    kioltja a bizonyítékot. Két kötés zárja: (a) a naplóban lévő minden ack-hoz kell audit-sor; (b) ha a
    #    kör-bejegyzés elkötelezte magát a lánc fejére (audit_seq), az exportnak EL KELL ÉRNIE odáig.
    if len(logged) > len(acks):
        out.append({"type": "audit_row_missing", "logged_acks": len(logged), "audit_ack_rows": len(acks)})
    if len(acks) > len(logged):
        # (a): a kapu EGYIRÁNYÚ volt — csak azt nézte, ha a napló TÖBBET mond, mint a busz audit. A fordított
        # irány pont az ELREJTÉS iránya (a független nyilvántartás többet tud, mint az önbevallás): 2 napló-ack / 3 audit-
        # sor, sőt 0 / 3 is NÉMA volt. Most saját neve van, és megnevezi, MELYIK audit-sorhoz nincs napló-ack.
        out.append({"type": "audit_row_unlogged", "logged_acks": len(logged), "audit_ack_rows": len(acks),
                    "audit_seq": [a.get("seq") for a in _unpaired_audit][:8],
                    "steps": [[a.get("from_id"), a.get("to_id")] for a in _unpaired_audit][:8]})
    for r in anchored_rounds:
        if r["cursor"].get("strict_ack_unknown") == 1:
            # A kör NEM tudta megmérni, hogy a clamp menekülő ajtaja nyitva volt-e. Ez harmadik állapot: nem
            # vád (a mérés dobhat legitim okból is), de nem is zöld — épp az a tény hiányzik, ami a kört
            # szigorúnak minősítené.
            out.append({"type": "strict_ack_unknown", "round_seq": r.get("seq"), "soft": True})
        if r["cursor"].get("strict_ack") == 0:
            # A kör KIMONDTA, hogy a clamp ki volt kapcsolva: nem vád (lehet legitim üzemeltetői döntés), de
            # strict/termék-módban nem zöld — a kurzor ilyenkor átléphetett kiadatlan posta fölött.
            out.append({"type": "strict_ack_disabled", "round_seq": r.get("seq"), "soft": True})
    top = max([r.get("seq") for r in rows if isinstance(r.get("seq"), int)] or [-1])
    by_seq = {r.get("seq"): r for r in rows if isinstance(r.get("seq"), int)}
    for r in anchored_rounds:
        want = r["cursor"].get("audit_seq")
        want_hash = r["cursor"].get("audit_hash")
        if not (isinstance(want, int) and not isinstance(want, bool)):
            # 9/1: a horgony KIMARADÁSA volt a menekülő ajtó (az írás fail-open). A hiány harmadik
            # állapot: nem vád, de nem is zöld — strict/termék-módban ok:false.
            out.append({"type": "audit_anchor_absent", "round_seq": r.get("seq"), "soft": True})
            continue
        if top < want:
            out.append({"type": "audit_head_not_covered", "round_seq": r.get("seq"),
                        "committed_audit_seq": want, "export_top_seq": top})
            continue
        # 9/3: eddig CSAK a seq-számot kértük, a HASH-t nem — a tartalom kicserélhető volt úgy, hogy a
        # lánc belsőleg ép marad. A horgony a sor row_hash-éhez köt; a GENEZIS-horgony (üres lánc) azt jelenti, hogy
        # az exportnak a 0. sortól kell indulnia.
        if want_hash == _GENESIS_HASH:
            if by_seq and min(by_seq) != 0:
                out.append({"type": "audit_head_hash_mismatch", "round_seq": r.get("seq"),
                            "committed": "genesis", "export_start_seq": min(by_seq)})
        elif isinstance(want_hash, str) and want in by_seq and by_seq[want].get("row_hash") != want_hash:
            out.append({"type": "audit_head_hash_mismatch", "round_seq": r.get("seq"), "committed_audit_seq": want,
                        "committed": want_hash[:12], "export": str(by_seq[want].get("row_hash"))[:12]})
    # TÁMADÁSI MÁTRIX 2.7: a NYITÓ horgony a kör saját sorait nem köti. A ZÁRÓ horgony (a mellékhatások után
    # írt `round_close`) igen — ha megvan. A hiánya HARMADIK ÁLLAPOT: nem vád (a záró írás megszakadhatott),
    # de nem is zöld; strict/termék-módban ok:false, mert épp az a szelet marad kötetlen, amit vizsgálunk.
    closes = [e for e in entries if e.get("recipient") == identity and e.get("kind") == "round_close"
              and e.get("decision") == "accepted" and isinstance(e.get("cursor"), dict)
              and isinstance(e["cursor"].get("audit_end_seq"), int)]
    # HIGH (mérve a VALÓDI 40bb502-naplóval, nem konstruálva): a számonkérést az
    # ELLENŐRZÖTT fél saját mezőjének KIHAGYÁSA kapcsolja ki. A `closes` a naplóban utazik, tehát annak a
    # szava, akit vizsgálunk — és a jelentés ezt eddig SEHOL nem mondta ki: a délelőtti (vállalás nélküli) és
    # az esti napló között CSAK egy számláló különbözött (`rounds_pledged` 0 vs 2), amit semmi nem minősített.
    # A testvér-mezőnél (`audit_seq`, a nyitó horgony) ugyanez a kimaradás már harmadik állapotot ad — a kód
    # ismerte a mintát, itt nem alkalmazta. Nem kell rosszindulat: egy nem frissített partner-gép régi
    # közjegyzője belsőleg tökéletesen ép, ALÁÍRT láncot ír. A hash-lánc a HAMISÍTÁS ellen véd, a
    # VERZIÓ-ELTÉRÉS ellen nem.
    # NEM vád, és NEM körönként (az ő szondája sem vádat kér, és a saját `test_old_round_without_the_pledge_
    # is_not_accused` tesztünk is azt köti, hogy a régi kör ne kapjon `audit_close_missing`-et): a jelzés a
    # NAPLÓ egészére szól, és csak akkor, ha EGYETLEN kör sem vállal — a vegyes napló (gördülő frissítés)
    # csak számlálót kap.
    _unpledged = [r for r in anchored_rounds if r["cursor"].get("closes") != 1]
    if _unpledged and len(_unpledged) == len(anchored_rounds):
        out.append({"type": "audit_close_pledge_absent", "rounds_unpledged": len(_unpledged),
                    "note": "a napló EGYETLEN köre sem vállalja a záró horgonyt (`closes`), ezért a "
                            "kör-záró ellenőrzésnek nincs mit számon kérnie — ez nem vád, de nem is zöld",
                    "soft": True})
    for r in anchored_rounds:
        if r["cursor"].get("closes") != 1:
            continue                                  # a régi, zárást NEM vállaló kör: nincs mit számon kérni
        rseq = r.get("seq")
        # A párosítás SORREND szerint megy, nem a kurzor-érték egyezésére: a kurzor a kör közben mozdulhat
        # (ack), és egy érték-egyezésre épülő párosítást ez elrontana — ráadásul két azonos `at`-ú kör között
        # egy RÉGI zárás „lezártnak" mutathatna egy záratlan kört. A záráshoz az a kör tartozik, ami
        # KÖZVETLENÜL megelőzi: a következő kör-bejegyzés előtti első `round_close`.
        nxt = min([x.get("seq") for x in anchored_rounds
                   if isinstance(x.get("seq"), int) and isinstance(rseq, int) and x["seq"] > rseq] or [None]) \
            if isinstance(rseq, int) else None
        mine = [c for c in closes if isinstance(c.get("seq"), int) and isinstance(rseq, int)
                and c["seq"] > rseq and (nxt is None or c["seq"] < nxt)]
        # …és ha a zárás MEGNEVEZI a körét (`round_seq`), akkor annak egyeznie kell: a sorrend csak visszatartó,
        # a megnevezés köt. (Régi zárásokban nincs `round_seq` — azokra a sorrend marad.)
        named = [c for c in mine if isinstance(c["cursor"].get("round_seq"), int)]
        if named:
            mine = [c for c in named if c["cursor"]["round_seq"] == rseq]
        if not mine:
            # A kör a hash-láncolt bejegyzésében VÁLLALTA a zárást, mégsincs záró horgony: vagy megszakadt a
            # kör (a válasz `round_close: "failed"`-et mondott), vagy valaki levágta a napló végét. Mindkettő
            # azt jelenti, hogy ÉPP EZ a szelet marad kötetlen -> nem zöld.
            # HARMADIK ÁLLAPOT (soft): a megszakadt kör LEGITIM is lehet (a záró írás fail-open), tehát ez nem
            # vád — de nem is zöld, mert épp a vizsgált szelet vége marad kötetlen. Így a meglévő kemény
            # eltérés-listák változatlanok maradnak, a strict/termék-mód viszont
            # ok:false-t ad.
            out.append({"type": "audit_close_missing", "round_seq": rseq, "soft": True})
            continue
        c = min(mine, key=lambda x: x["seq"])
        end = c["cursor"]["audit_end_seq"]
        end_hash = c["cursor"].get("audit_end_hash")
        # A nem-Claude kar (1): a záró horgony RÉGI láncfejre mutatna, ha a zárás a mellékhatások ELŐTT
        # íródna. A horgony MONOTON: a kör végi láncfej nem lehet a kör eleji ELŐTT.
        open_seq = r["cursor"].get("audit_seq")            # EBBŐL a körből, nem az előző ciklus maradékából
        if isinstance(open_seq, int) and not isinstance(open_seq, bool) and end < open_seq:
            out.append({"type": "audit_close_before_open", "round_seq": rseq, "open_audit_seq": open_seq,
                        "close_audit_seq": end})
            continue
        if top < end:
            out.append({"type": "audit_close_not_covered", "round_seq": rseq, "close_seq": c.get("seq"),
                        "committed_audit_seq": end, "export_top_seq": top})
            continue
        if end_hash == _GENESIS_HASH:
            if by_seq and min(by_seq) != 0:
                out.append({"type": "audit_close_hash_mismatch", "round_seq": rseq, "committed": "genesis",
                            "export_start_seq": min(by_seq)})
        elif isinstance(end_hash, str) and end in by_seq and by_seq[end].get("row_hash") != end_hash:
            out.append({"type": "audit_close_hash_mismatch", "round_seq": rseq, "committed_audit_seq": end,
                        "committed": end_hash[:12], "export": str(by_seq[end].get("row_hash"))[:12]})
    return out


def reconcile(records: list, identity: str, receipts: list, start_cursor: int = 0, trusted_pub: str | None = None,
              strict: bool | None = None, bus_audit: list | None = None) -> dict:
    """A kihagyás elleni védelem (a seq-rés csak törlést bizonyít): a távoli fél SAJÁT nyugta-listája vs. egy export.
    receipts: körönként {"sent": [elküldött üzenet-dictek], "ack": küldött ack (0 = nincs), "received": [kapott válasz-dictek]}.
    -> {ok, verify_ok, trusted, discrepancies: [...], unconfirmed_deliveries: [...], counts}.
    Eltérés-típusok:
      sent_not_logged            — elküldtem, a napló nem tud róla (kihagyott bejövő bejegyzés)
      received_not_logged        — megkaptam, a napló nem rögzítette a kiadást
      ack_sent_not_logged        — ack-ot küldtem, nincs róla bejegyzés
      cursor_moved_without_logged_ack — a naplózott kurzor elmozdult úgy, hogy nincs hozzá naplózott ack
                                    (a busz-gépen, napló nélkül előreugratott kurzor = elnyelt posta)
      ack_logged_not_sent        — a napló ack-ot állít, amit a fél nem küldött (kitalált ack fedezhetne elnyelést)
      cursor_target_exceeds_ack  — "cursor F->T (ack U)" T > max(F, U): a becsületes clamp csak lefelé mozgat, tehát ez
                                   a fél nélkül, a naplóból is hamis kurzor-cél (a verify is hibaként jelzi)
      delivered_not_received     — a napló kiadást állít, a fél nem kapta meg (túl-naplózás VAGY hazug kiadás; a
                                   fél nyugtája nélkül nem dönthető el) — a CLI-n termék-módban / --strict-tel rc=1
    unconfirmed_deliveries: ugyanezek a tételek listaként (kompatibilitás). A két fordított irány a nyugták
    TELJESSÉGÉRE támaszkodik: a nyugta-fájl ugyanazt az időszakot fedje, mint az export.
    Kör-kimenetel: a kliens kérés-sora `round` azonosítót visz, a kör végén egy `phase:
    "outcome"` sor mondja meg: `delivered` (vádolhat), `unknown` (kimehetett, a válasz nem jött -> `unresolved` lista,
    ok:false csak strict/termék-módban), `not-sent` (nem vád, és az ack-ja sem fedez), `reached` (érvényes JSON-válasz jött, akár hibaüzenet: a kérés bizonyítottan odaért -> úgy vádol, mint `delivered`). Kör-azonosító nélküli sor = régi formátum = delivered.
    `strict=None` -> termék-módban strict."""
    from collections import Counter
    entries = [r for r in records if r.get("type") == "entry"]
    # ALAK-KAPU A NAPLÓRA (saját söprés, 2026-09-16): a MÁSIK fél exportja megbízhatatlan bemenet. Egy hiányzó
    # `envelope_sha256` eddig KeyError-ral szállt el az összevetés közepén — a traceback nem diagnózis, és egy
    # összeomlott `reconcile` semmit nem mond arról, hogy a napló hazudott-e. Ugyanaz az elv, amit a
    # konformancia-korpusz oldalán a típus-kapunál alkalmaztunk: a rossz alak NEVESÍTETT elutasítás.
    _ENTRY_SHAPE = {"seq": int, "prev_hash": str, "received_at_ms": int, "envelope_sha256": str,
                    "sender_identity": str, "sender_auth": str, "recipient": str, "kind": str,
                    "decision": str, "reason": str, "entry_hash": str}
    # A NÉV-dimenzió (2026-09-16, saját kör a nem-Claude karral): az alak-kapu eddig a kötelező mezők
    # JELENLÉTÉT és TÍPUSÁT kötötte, FEHÉRLISTÁT nem. Mérve: nyolc bejegyzéshez adott `operator_note` mező
    # ok=true, 0 eltérés — és `entry_hash(e) == entry_hash(e + ismeretlen mező)`, mert a hash a FIX
    # `ENTRY_KEYS`-t hasheli. Vagyis egy hash-LÁNCOLT naplóban hordozható tartalom, amit a lánc NEM hitelesít.
    # Ugyanez igaz az ALÁÍRT `checkpoint` sorra is, amire eddig semmilyen alak-kapu nem futott.
    _CKPT_SHAPE = {"seq": int, "head_hash": str, "ts_ms": int, "notary_pub": str, "sig": str}
    _SHAPES = {"entry": _ENTRY_SHAPE, "checkpoint": _CKPT_SHAPE}
    # Amit a lánc/az aláírás VALÓBAN fed (ezeken kívül minden kulcs hitelesítetlen)
    _COVERED = {"entry": set(ENTRY_KEYS) | {"cursor", "type", "entry_hash"},
                "checkpoint": {"type", "seq", "head_hash", "ts_ms", "notary_pub", "sig"}}

    def _norm(k):
        """Egy kulcsnév „összelapítva": kisbetű, csak betű/szám. `entry_hash ` és `Entry_hash` ugyanaz lesz."""
        return "".join(ch for ch in str(k).lower() if ch.isalnum())

    _unauth, _shadow, _rowtype = [], [], []
    for _r in records:
        if not isinstance(_r, dict):
            _rowtype.append({"type": "malformed_row", "problem": "not an object",
                             "row": repr(_r)[:48]})
            continue
        _ty = _r.get("type")
        # A SOR TÍPUSA maga is mező, és eddig senki nem kötötte. A saját söprésem mérte ki (2026-09-16):
        #   * `type` TÖRÖLVE / `null` / `0` egy checkpoint soron -> a sor megszűnik checkpointnak látszani,
        #     vagyis a KÖZJEGYZŐ ALÁÍRT HORGONYA némán eltűnik a jelentésből, és az `ok` zöld marad;
        #   * `type: []` -> `TypeError` a típus-kikeresésnél (ezt épp ez a mostani kódom hozta be) — és a
        #     traceback nem diagnózis.
        # Minden sornak ki KELL mondania, mi ő. Egy ISMERETLEN, de szabályos nevű típus viszont lehet egy
        # újabb közjegyző-verzió sora: az nem vád, csak nem hitelesített.
        if not isinstance(_ty, str) or not _ty:
            _rowtype.append({"type": "row_type_missing", "seq": repr(_r.get("seq"))[:32],
                             "declared": repr(_ty)[:32],
                             "note": "a sor nem mondja meg, mi ő — egy típus nélküli sor az aláírt horgonyt "
                                     "is eltüntetheti a jelentésből"})
            continue
        if _ty not in _COVERED:
            _unauth.append({"type": "unknown_row_type", "row_type": _ty[:32],
                            "seq": repr(_r.get("seq"))[:32]})
            continue
        _ok_names = {_norm(k): k for k in _COVERED[_ty]}
        for _k in _r:
            if _k in _COVERED[_ty]:
                continue
            _n = _norm(_k)
            if _n in _ok_names:
                # Egy kulcs, ami egy LÁNCOLT kulcstól csak kis/nagybetűben, szóközben vagy írásjelben tér el,
                # nem előre-kompatibilitás: az olvasó szemének szól. Ez VÁD-értékű, tehát HARD.
                _shadow.append({"type": "shadowing_field", "row_type": _ty, "seq": repr(_r.get("seq"))[:32],
                                "field": repr(_k)[:48], "shadows": _ok_names[_n]})
            else:
                # Valódi új név: egy ÚJABB közjegyző-verzió jogosan tehet bele mezőt. A baj nem a mező, hanem
                # hogy eddig SENKI nem mondta ki, hogy a lánc nem fedi. Ezért NEVESÍTVE, de NEM verdikt:
                # a nem-Claude kar köre jogosan mutatott rá, hogy fehérlistás elutasítással egy frissített
                # partner naplója EGÉSZÉBEN pirosra váltana, és senki nem merne verziót emelni.
                _unauth.append({"type": "unauthenticated_field", "row_type": _ty,
                                "seq": repr(_r.get("seq"))[:32], "field": repr(_k)[:48]})
    _malformed, _bad_entries = [], []
    for _r in records:                       # az ALÁÍRT checkpoint sorra eddig SEMMILYEN alak-kapu nem futott
        if _r.get("type") != "checkpoint":
            continue
        for _k, _ty2 in _CKPT_SHAPE.items():
            if _k not in _r:
                _malformed.append({"row_type": "checkpoint", "seq": repr(_r.get("seq"))[:32], "field": _k,
                                   "problem": "missing"})
            elif not isinstance(_r[_k], _ty2) or isinstance(_r[_k], bool):
                _malformed.append({"row_type": "checkpoint", "seq": repr(_r.get("seq"))[:32], "field": _k,
                                   "problem": "not %s" % _ty2.__name__})
    for _e in entries:
        _hit = False
        for _k, _ty in _ENTRY_SHAPE.items():
            if _k not in _e:
                _malformed.append({"seq": repr(_e.get("seq"))[:32], "field": _k, "problem": "missing"})
                _hit = True
            elif not isinstance(_e[_k], _ty) or isinstance(_e[_k], bool):
                _malformed.append({"seq": repr(_e.get("seq"))[:32], "field": _k,
                                   "problem": "not %s" % _ty.__name__})
                _hit = True
        if _hit:
            _bad_entries.append(id(_e))       # OBJEKTUM szerint, nem a (esetleg hibás típusú) `seq` szerint
    # A nem-Claude kar köre EZEN a javításon (2026-09-16, elfogadva): a korai `return` „ne nézz ide" gombbá
    # tette az alak-kaput — egy szándékos `seq: []` szeméttel a MÉLYEBB ellenőrzés (aláírás, backdate, hash-lánc)
    # SOHA nem futott le, és a válasz ártatlan formai hibának látszott. Ezért mostantól MINDKETTŐ fut: a rossz
    # alakú bejegyzéseket kimondjuk, ÉS a maradékon lefuttatjuk a `verify`-t — a szennyezés nem takarhatja el a
    # lánc-törést. (A tracebacket továbbra is elkerüljük: a rossz alakú sorokat kiszűrjük a verify elől.)
    if _malformed:
        _clean = [r for r in records if id(r) not in set(_bad_entries)]
        rep = verify(_clean, trusted_pub=trusted_pub)
        _chain = [e for e in rep.get("errors", []) if "chain" in str(e.get("error", ""))
                  or "gap" in str(e.get("error", "")) or "rewritten" in str(e.get("error", ""))]
        return {"ok": False, "verify_ok": False, "verify_partial_ok": rep["ok"],
                "trusted": rep.get("trusted", False),
                "discrepancies": [{"type": "malformed_entry", **m} for m in _malformed[:8]]
                                 + [{"type": "chain_error_behind_the_malformed", **e} for e in _chain[:4]]
                                 + _shadow[:4] + _rowtype[:4],
                "unresolved": [], "unconfirmed_deliveries": [], "notes": _unauth[:8],
                "counts": {"entries": len(entries), "malformed": len(_malformed),
                           "shadowing_fields": len(_shadow), "unauthenticated_fields": len(_unauth),
                           "rows_without_type": len(_rowtype),
                           "verified_without_the_malformed": len(_clean)}}
    rep = verify(records, trusted_pub=trusted_pub)
    mine_in = Counter(e["envelope_sha256"] for e in entries
                      if e.get("sender_identity") == identity and e.get("kind") not in ("ack", "pickup")
                      and not (e.get("decision") == "rejected" and e.get("reason") in ("send_failed", "store_failed")))
    delivered = Counter(e["envelope_sha256"] for e in entries
                        if e.get("kind") == "pickup" and e.get("decision") == "delivered" and e.get("recipient") == identity)
    disc, unresolved = [], []
    strict = is_product() if strict is None else strict
    claimed_rounds = {r["round"] for r in receipts if r.get("phase") == "outcome" and r.get("round") and r.get("peer_claimed_unprocessed")}
    outcomes, outcome_conflicts = {}, []                          # C2: az ELSŐ kimenetel-sor számít (append-only);
    for r in receipts:                                            # egy körhöz eltérő második sor = jelzett ütközés, nem csendes felülírás
        if r.get("phase") == "outcome" and r.get("round"):
            if r["round"] not in outcomes:
                o = r.get("outcome")
                # a not-sent csak OSError-nál KIZÁRT (rc nélküli sor); az rc 255-ös not-sent
                # a kérés kiírása után is jöhetett -> feltételezett, a reconcile-ban unknown-ként kezeljük
                outcomes[r["round"]] = "unknown" if (o == "not-sent" and r.get("rc") is not None) else o
            elif outcomes[r["round"]] != r.get("outcome") and not (r.get("outcome") == "not-sent" and outcomes[r["round"]] == "unknown"):
                outcome_conflicts.append({"type": "outcome_conflict", "round": r["round"],
                                          "first": outcomes[r["round"]], "later": r.get("outcome")})

    def outcome(rc):
        if rc.get("phase") == "outcome":
            return "outcome-row"
        if rc.get("phase") == "request" and rc.get("round"):
            return outcomes.get(rc["round"]) or "unknown"          # a kör vége nem íródott meg -> nem tudni
        return "delivered"                                         # régi, kör-azonosító nélküli sor
    rows = [(outcome(rc), rc) for rc in receipts]
    sent = Counter(envelope_hash(m) for o, rc in rows if o in PROVEN_ARRIVED for m in (rc.get("sent") or []))
    for h, n in sent.items():
        if mine_in[h] < n:
            disc.append({"type": "sent_not_logged", "envelope_sha256": h, "sent": n, "logged": mine_in[h]})
    left = Counter({h: max(0, mine_in[h] - sent[h]) for h in mine_in})
    for o, rc in rows:
        if o == "unknown":
            for m in rc.get("sent") or []:
                h = envelope_hash(m)
                if left[h] > 0:
                    left[h] -= 1
                else:
                    unresolved.append({"type": "peer_claimed_unprocessed" if rc.get("round") in claimed_rounds else "sent_outcome_unknown",
                                       "round": rc.get("round"), "envelope_sha256": h})
    got = Counter(envelope_hash(m) for rc in receipts for m in (rc.get("received") or []))
    for h, n in got.items():
        if delivered[h] < n:
            disc.append({"type": "received_not_logged", "envelope_sha256": h, "received": n, "logged": delivered[h]})
    unconfirmed = [{"envelope_sha256": h, "logged": n, "received": got[h]} for h, n in delivered.items() if got[h] < n]
    # KÉTIRÁNYÚ: a napló állításait a fél nyugtájához is mérjük — a közjegyző által írt,
    # aláíratlan `delivered`/`ack` ÖNMAGÁBAN nem bizonyíték, a kliens nyugtája a fél igazsága.
    # a háromfokú modell a KIADÁS oldalán is. Ha a szeletben van FELTÉTELEZETT kimenetelű
    # kör (unknown / not-sent: a válasz elveszett, a fél újrapróbál, a közjegyző helyesen ugyanazt adja ki újra), akkor a
    # többlet-kiadás NEM hard vád, hanem unresolved. Hard csak ott, ahol minden kört bizonyított kimenetel zár.
    # a leminősítés NE legyen szelet-globális, és ne lehessen egy kimenetel-sor
    # ELHAGYÁSÁVAL bekapcsolni. Csak az ÚJRAPRÓBÁLT kiadás enyhül: az a boríték, amelyet a fél EGYSZER MÁR megkapott
    # (szerepel a nyugtájában), és van feltételezett kimenetelű kör. Amit soha nem kapott meg -> hard vád.
    presumed_round = any(o in ("unknown", "not-sent") for o, rc in rows if o != "outcome-row")
    for u in unconfirmed:
        if presumed_round and got[u["envelope_sha256"]] > 0:
            unresolved.append(dict(u, type="delivery_outcome_unknown"))
        else:
            disc.append(dict(u, type="delivered_not_received"))
    logged_acks = []
    expected = start_cursor
    ack_from = None                                              # az utolsó accepted ack kiinduló kurzora
    round_open = False                                           # delivered csak elemezhető kör-bejegyzés mögött állhat
    round_seq, round_replies, round_delivered = None, 0, 0
    round_pending, round_max_id, round_next_id, last_round = 0, None, None, None
    round_pending_unknown, round_next_zero_conflict, any_round = False, False, False      # a csonkolt kör maradéka fölé nem ugorhat a kurzor

    def flag(item):                                              # legalább egy unresolved, strict/termék-módban hard
        (disc if strict else unresolved).append(item)

    def close_round():
        nonlocal last_round
        if round_seq is not None:
            if round_delivered != round_replies:                 # a kör válaszszáma kötött
                item = {"type": "round_replies_mismatch", "seq": round_seq, "replies": round_replies,
                        "delivered": round_delivered}
                if presumed_round:                               # ugyanaz a gyökér-ok: újrapróbált kör 
                    unresolved.append(dict(item, type="round_replies_outcome_unknown"))
                else:
                    flag(item)
            if round_next_zero_conflict:                          # „nincs kiadatlan", pedig pending > replies -> ellentmondás
                disc.append({"type": "round_next_id_contradicts_pending", "seq": round_seq,
                             "pending": round_pending, "replies": round_replies})
            r = {"seq": round_seq, "pending": round_pending, "replies": round_replies, "max_id": round_max_id,
                 "next_id": round_next_id, "unknown": round_pending_unknown}
            if last_round is None:                                # a körök NEM írják felül egymást az ack-ig
                last_round = r
            else:                                                 # a legszigorúbb korlát marad: a legkisebb next_id
                last_round = {"seq": last_round["seq"], "pending": last_round["pending"] + r["pending"],
                              "replies": last_round["replies"] + r["replies"],
                              "max_id": max([x for x in (last_round["max_id"], r["max_id"]) if x is not None], default=None),
                              "next_id": min([x for x in (last_round["next_id"], r["next_id"]) if x], default=None),
                              "unknown": last_round["unknown"] or r["unknown"]}

    def _ints(c, keys):                                          # a vádlott írta -> nem-negatív int, mint a record()
        return isinstance(c, dict) and all(isinstance(c.get(k), int) and not isinstance(c.get(k), bool) and c[k] >= 0
                                           for k in keys)

    for e in entries:
        if e.get("recipient") != identity:
            continue
        if e.get("kind") == "ack" and e.get("decision") == "accepted":
            close_round()                                        # a kör lezárul, mielőtt az ack a kurzort mozdítja
            round_open, round_seq = False, None
            c = e.get("cursor")
            if _ints(c, ("from", "to", "ack")):
                frm, to, up = c["from"], c["to"], c["ack"]
            else:
                m = _ACK_RE.match(e.get("reason", ""))
                if not m:                                        # az egyik kar elemezhetetlen = tétel, nem kihagyás
                    flag({"type": "unparsable_cursor_entry", "seq": e.get("seq"), "kind": "ack"})
                    close_round(); round_open, round_seq = False, None
                    continue
                frm, to, up = int(m.group(1)), int(m.group(2)), int(m.group(3))
            mr = _ACK_RE.match(e.get("reason", ""))
            if c is not None and mr and (int(mr.group(1)), int(mr.group(2)), int(mr.group(3))) != (frm, to, up):
                disc.append({"type": "cursor_reason_mismatch", "seq": e.get("seq"), "kind": "ack"})   # 
            logged_acks.append(up)
            if to > max(frm, up):                                # a kurzor CÉLJA is kötött
                disc.append({"type": "cursor_target_exceeds_ack", "seq": e["seq"], "cursor_from": frm, "cursor_to": to,
                             "ack": up})
            if frm != expected:
                disc.append({"type": "cursor_moved_without_logged_ack", "seq": e["seq"], "cursor": frm, "expected": expected})
            # csonkolt körnél (pending > replies) a kurzor CSAK a kiadott postáig mehet;
            # a maradék a kurzor FÖLÖTT marad. Ha fölé ugrik, a kiadatlan posta véglegesen elveszett.
            if last_round and last_round.get("unknown") and to > frm:   # + mért/mezőhiány -> nem néma
                unresolved.append({"type": "round_pending_unknown", "seq": last_round["seq"], "cursor_to": to})
            if not any_round and to > frm:                        # kör-bejegyzés nélkül mozduló kurzor — a szelet
                unresolved.append({"type": "cursor_moved_without_round", "seq": e["seq"],   # kezdhet ack-kal, ezért nem hard
                                   "cursor_from": frm, "cursor_to": to})
            if last_round and last_round["pending"] > last_round["replies"]:
                # a kurzor CSAK az első KI NEM ADOTT üzenet alá mehet (next_id); régi bejegyzésnél a kiadott maximum a korlát
                limit = (last_round["next_id"] - 1) if last_round.get("next_id") else (
                    last_round["max_id"] if last_round["max_id"] is not None else frm)
                if to > limit:
                    disc.append({"type": "cursor_skips_undelivered", "seq": e["seq"], "round_seq": last_round["seq"],
                                 "cursor_to": to, "limit": limit, "next_undelivered_id": last_round.get("next_id"),
                                 "pending": last_round["pending"], "replies": last_round["replies"]})
            last_round, any_round = None, False
            expected, ack_from = to, frm
        elif e.get("kind") == "ack" and e.get("decision") == "rejected":
            if ack_from is not None:                             # ack_failed / ack_refused: a kurzor NEM mozdult
                expected, ack_from = ack_from, None
            close_round(); round_open, round_seq = False, None
        elif e.get("kind") == "pickup" and e.get("decision") == "accepted":
            c = e.get("cursor")
            close_round()
            if _ints(c, ("at", "replies")):
                at, nrep = c["at"], c["replies"]
                r = _parse_round(e.get("reason", ""))
                if r is not None and r != (at, nrep):
                    disc.append({"type": "cursor_reason_mismatch", "seq": e.get("seq"), "kind": "pickup"})   # 
            else:
                r = _parse_round(e.get("reason", ""))
                if r is None:
                    flag({"type": "unparsable_cursor_entry", "seq": e.get("seq"), "kind": "pickup"})
                    round_open, round_seq = False, None
                    continue
                at, nrep = r
            round_open, round_seq, round_replies, round_delivered = True, e.get("seq"), nrep, 0
            round_pending = c["pending"] if (_ints(c, ("pending",))) else nrep
            round_next_id = c["next_id"] if _ints(c, ("next_id",)) and c["next_id"] > 0 else None
            # a hiányzó mező HARMADIK állapot (nem néma visszaesés a régi korlátra)
            # Saját a CSONKOLT mérés (`pending_truncated`) ugyanaz a harmadik állapot, mint a hiányzó
            round_pending_unknown = bool(isinstance(c, dict) and (c.get("pending_unknown") or c.get("pending_truncated"))) \
                or not _ints(c, ("pending",)) \
                or (not _ints(c, ("next_id",)) if _ints(c, ("pending", "replies")) and c["pending"] > c["replies"] else False)
            round_next_zero_conflict = bool(_ints(c, ("pending", "replies", "next_id")) and c["pending"] > c["replies"]
                                            and c["next_id"] == 0)
            round_max_id = None
            any_round = True
            if at != expected:
                disc.append({"type": "cursor_moved_without_logged_ack", "seq": e["seq"], "cursor": at, "expected": expected})
                expected = at
        elif e.get("kind") == "pickup" and e.get("decision") == "delivered":
            if not round_open:                                   # a kör-bejegyzés elhagyása sem néma
                flag({"type": "delivered_without_round", "seq": e.get("seq")})
            else:
                round_delivered += 1
                cid = e.get("cursor")
                if _ints(cid, ("id",)):
                    round_max_id = cid["id"] if round_max_id is None else max(round_max_id, cid["id"])
    close_round()
    def acks(which):
        return Counter(int(rc["ack"]) for o, rc in rows if o in which and isinstance(rc.get("ack"), int) and rc["ack"] > 0)
    # a `not-sent` kör ack-ja NEM fedez (a fél bizonyosan nem kaphatta meg)
    sent_acks, unknown_acks = acks(PROVEN_ARRIVED), acks(("unknown",))
    claimed_acks = Counter(int(rc["ack"]) for o, rc in rows if o == "unknown" and rc.get("round") in claimed_rounds
                           and isinstance(rc.get("ack"), int) and rc["ack"] > 0)
    any_acks = sent_acks                                         # csak a BIZONYÍTOTT kör fedez hallgatás nélkül
    have = Counter(logged_acks)
    for a, n in sent_acks.items():
        if have[a] < n:
            disc.append({"type": "ack_sent_not_logged", "ack": a, "sent": n, "logged": have[a]})
    for a, n in unknown_acks.items():
        if have[a] - sent_acks[a] < n:
            unresolved.append({"type": "ack_outcome_unknown", "ack": a})
    for a, n in have.items():                                    # a fordított irány: naplózott ack, amit a fél nem küldött
        if sent_acks[a] >= n:
            continue
        if sent_acks[a] + unknown_acks[a] >= n:                  # feltételezett fedezet: se hard vád, se némaság
            unresolved.append({"type": "ack_cover_unknown", "ack": a, "logged": n, "proven": sent_acks[a],
                               "claimed": claimed_acks[a] > 0})   # látszik, ha a vádlott szavára épül
        else:                                                    # kizárt (OSError not-sent) vagy semmi: hard vád
            disc.append({"type": "ack_logged_not_sent", "ack": a, "logged": n, "sent": sent_acks[a]})
    unresolved.extend(outcome_conflicts)
    _cross = _audit_cross(entries, identity, bus_audit, entries_all=records)
    # a `soft: True` tételek HARMADIK ÁLLAPOTOK (nem vád): a hiányzó horgony nem bizonyít hazugságot, de nem is zöld
    disc.extend([d for d in _cross if not d.get("soft") and not d.get("note_only")])
    unresolved.extend([dict(d) for d in _cross if d.get("soft") and not d.get("note_only")])
    # HARMADIK CSATORNA: kimondva, de NEM verdikt. A jelző neve szándékosan `note_only` és nem `note`: az
    # `audit_close_pledge_absent` magyarázó mezője történetesen `note` volt, és a szűrőm a SZÖVEGET olvasta
    # csatorna-jelzőnek — a saját tételemet tettem vele némává. (Ugyanaz a NÉV-dimenzió, amit ma zártam.)
    _unauth.extend([dict(d) for d in _cross if d.get("note_only")])
    # NÉV-ÜTKÖZÉS: vád-értékű, tehát a verdiktbe megy (lásd `_shadow` fent).
    disc.extend(_shadow[:4])
    disc.extend(_rowtype[:4])
    # NÉMA PIROS VERDIKT (mérve 2026-09-16): a `checkpoint` sor `seq`-jét vagy ALÁÍRÁSÁT törölve a jelentés
    # `ok=false, verify_ok=false, trusted=false` lett, de `discrepancies: []` és `errors: null` — piros verdikt
    # MEGNEVEZETT OK NÉLKÜL, épp azon a soron, ami a közjegyző aláírását hordozza. A `verify()` tudta az okot,
    # a `reconcile` viszont eldobta. A verdikt NEM változik (az `ok` eddig is `rep["ok"]`-tól függött) — csak
    # innentől MEGMONDJUK, miért.
    if not rep["ok"]:
        disc.extend([{"type": "verify_error", **e} for e in (rep.get("errors") or [])[:6]])
    return {"ok": not disc and rep["ok"] and not (unresolved and strict), "verify_ok": rep["ok"],
            "trusted": rep.get("trusted", False), "discrepancies": disc, "unresolved": unresolved,
            "unconfirmed_deliveries": unconfirmed,
            # A HITELESÍTETLEN MEZŐK nem verdikt, hanem RIPORT-OSZLOP: egy fehérlistás elutasítás a frissített
            # partner naplóját EGÉSZÉBEN pirosra váltaná (előre-kompatibilitás, gördülő verziófrissítés, külső
            # korrelációs azonosítók), és senki nem merne verziót emelni. De néma sem maradhat: a lánc nem fedi.
            "notes": _unauth[:8],
            # A nem-Claude kar (3): ha MINDEN kör záratlan marad, a sok `soft` „normális zaj"-nak tűnhet. Ezért
            # a soft nem szám nélkül áll: a záratlan/vállalt arány MÉRHETŐ jel — egészséges üzemben ~0, tartós
            # magas érték azt jelenti, hogy a záró írás rendszeresen elmarad (kód-csere vagy tartós megszakítás).
            "counts": {"entries": len(entries), "sent": sum(sent.values()), "received": sum(got.values()),
                       "acks_sent": sum(any_acks.values()), "delivered_logged": sum(delivered.values()),
                       "unauthenticated_fields": len(_unauth), "shadowing_fields": len(_shadow),
                       "rows_without_type": len(_rowtype),
                       "rounds_pledged": sum(1 for e in entries
                                             if e.get("recipient") == identity and e.get("kind") == "pickup"
                                             and e.get("decision") == "accepted"
                                             and isinstance(e.get("cursor"), dict)
                                             and e["cursor"].get("closes") == 1),
                       "rounds_unclosed": sum(1 for d in _cross if d.get("type") == "audit_close_missing"),
                       # a VÁLLALÁS hiánya eddig sehol nem látszott a jelentésben.
                       "rounds_unpledged": sum(1 for e in entries
                                               if e.get("recipient") == identity and e.get("kind") == "pickup"
                                               and e.get("decision") == "accepted"
                                               and isinstance(e.get("cursor"), dict)
                                               and e["cursor"].get("closes") != 1),
                       "skips_unattributable": sum(1 for d in _cross
                                                   if d.get("type") == "audit_skip_unattributable"),
                       # a nem-Claude kar (1)/(2): a harmadik állapotok egyedi eseményként „zajnak" tűnnek —
                       # a SZÁM az, amiből egy tartós, szándékos minta látszik
                       "strict_ack_unknown": sum(1 for d in _cross if d.get("type") == "strict_ack_unknown"),
                       "chain_unverifiable": sum(1 for d in _cross
                                                 if d.get("type") == "audit_chain_unverifiable")}}


def _pub_misuse(pub, cmd) -> bool:
    """a --pub a kulcs ÉRTÉKE (64 hex), nem fájl-út — különben néma verify_ok:false."""
    if pub and not re.fullmatch(r"[0-9a-f]{64}", pub):
        print("bus_notary %s: a --pub a közjegyző publikus kulcsának ÉRTÉKE (64 hex karakter), nem fájl-út: %r" % (cmd, pub),
              file=sys.stderr)
        return True
    return False


# ── CLI ──────────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bus_notary", description="AgentBus közjegyzői napló")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export"); e.add_argument("--log", default=None); e.add_argument("--from", dest="from_seq", type=int, default=1)
    v = sub.add_parser("verify"); v.add_argument("file"); v.add_argument("--pub"); v.add_argument("--window", type=int, default=DEFAULT_BACKDATE_WINDOW_S)
    v.add_argument("--start-prev-hash", dest="start_prev_hash", default=None,
                   help="a szelet első bejegyzésének ehhez kell láncolódnia (az előző szelet head.hash-e) — fork-ellenőrzés")
    c = sub.add_parser("compare"); c.add_argument("a"); c.add_argument("b")
    k = sub.add_parser("checkpoint"); k.add_argument("--log", default=None); k.add_argument("--key", required=True)
    g = sub.add_parser("keygen"); g.add_argument("--out", required=True)
    r = sub.add_parser("reconcile", help="a távoli fél nyugta-listája (JSONL, körönként sent/ack/received) vs. egy export")
    r.add_argument("--bus-audit", help="a busz cursor_audit exportja (JSONL, agent_bus.audit_export) — a napló ÖNBEVALLOTT "
                                       "pending/next_id számait ezzel vetjük össze")
    r.add_argument("file"); r.add_argument("--identity", required=True); r.add_argument("--receipts", required=True)
    r.add_argument("--pub"); r.add_argument("--start-cursor", dest="start_cursor", type=int, default=0)
    r.add_argument("--bus-audit-anchor", dest="bus_audit_anchor", default=None,
                   help="a --bus-audit részszelet horgonya: a megelőző audit-sor row_hash-e (csatornán kívül ismert)")
    r.add_argument("--strict", action="store_true", help="dev-módban is rc=1 a delivered_not_received-re (termék-módban mindig)")
    args = p.parse_args(argv)
    if args.cmd == "export":
        # NIT-ből: az `export` eddig MINDEN hibás naplóra rc=0-t adott, üres kimenettel —
        # ő maga nem minősítette leletnek („transzformáció, nem verdikt"), de a SAJÁT szabályunk rááll:
        # egyetlen belépő pont sem mondhat rc=0-t hibás fájlra. A következmény konkrét: egy csupa-szemét
        # naplóból ÜRES export lesz, abból a másik gépen „0 bejegyzés" — és aki azt kapja, nem tudja, hogy
        # a forrás volt szemét. A saját osztály-őrszemünk (`test_belepo_pont_osztaly_20260916.py`) fogta meg,
        # miután a NIT nyomán tényleg lefuttatta az al-parancsokat.
        _src = read_lines(args.log or default_log_path())
        _garbage = [r for r in _src if isinstance(r, dict) and r.get("type") == "garbage"]
        if _reject_no_evidence(_src, "export"):
            return 1
        if _garbage:
            print("bus_notary export: REJECT — a FORRÁS napló %d értelmezhetetlen sort tartalmaz (első: %s. sor). "
                  "Egy ilyen naplóból csendben készített szelet a másik gépen hibátlannak látszana."
                  % (len(_garbage), _garbage[0].get("line")), file=sys.stderr)
            return 1
        recs = export(args.log or default_log_path(), args.from_seq)
        first = next((r for r in recs if r.get("type") == "entry"), None)
        if first is not None:                                   # a láncoláshoz: a következő szelet ehhez kötődik
            print("bus_notary export: from_seq=%s prev_hash=%s (a láncoláshoz: verify --start-prev-hash %s)"
                  % (first.get("seq"), first.get("prev_hash"), first.get("prev_hash")), file=sys.stderr)
        for r in recs:
            print(json.dumps(r, sort_keys=True, ensure_ascii=False))
        return 0
    if args.cmd == "verify":
        if _pub_misuse(args.pub, "verify"):
            return 2
        if not args.pub:
            if is_product():
                print("bus_notary verify: product mode — --pub (a csatornán kívül rögzített közjegyzői kulcs) kötelező",
                      file=sys.stderr)
                return 2
            print("bus_notary verify: FIGYELEM — --pub nélkül az aláíró kulcs NINCS ellenőrizve; egy bárki által "
                  "generált kulccsal aláírt, kitalált lánc is ok:true. A report `trusted` mezője ezért false.",
                  file=sys.stderr)
        _recs = read_lines(args.file)
        # Az ÜRES napló elutasítása. Egy üres fájlra a `verify` egyszer rc=0-t adott: a legüresebb lehetséges
        # bemenet ZÖLD bizonyítványt kapott. Nulla bejegyzésen nincs hazugság, de bizonyíték sincs — a mérés
        # HIÁNYA nem zöld. (Ugyanaz az osztály, mint a hiányzó horgony és a hiányzó második nyilvántartás,
        # csak a legkorábbi ponton.) A javítás korábbi, szűkebb változata sokáig egy mindig-hamis ág mögött állt itt,
        # holt kódként: működött helyette ez a bővebb őr, de aki a forrást AUDITÁLJA, egy kikapcsolt
        # biztonsági blokkot látott egy biztonság-kritikus fájlban. Egy source-available terméknél ez
        # önmagában lelet, ezért a holt ág törölve, a magyarázata pedig ide, az ÉLŐ őr mellé került.
        if _reject_no_evidence(_recs, "verify"):
            return 1
        rep = verify(_recs, trusted_pub=args.pub, backdate_window_s=args.window,
                     start_prev_hash=args.start_prev_hash)
        print(json.dumps(rep, ensure_ascii=False, indent=1))
        if rep["ok"] and not rep["anchored"]:
            msg = ("a szelet a %s. bejegyzéstől indul, HORGONY nélkül — az előtte lévő bejegyzések hiánya a szeletből "
                   "nem látszik. Add meg a csatornán kívül ismert --start-prev-hash értéket, vagy exportálj seq=1-től."
                   % rep["slice_start_seq"])
            if is_product():
                print("bus_notary verify: product mode — megtagadva: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: FIGYELEM — " + msg + " A report `trusted` mezője ezért false.", file=sys.stderr)
        if args.pub and rep["ok"] and rep["no_checkpoint_in_range"]:
            msg = ("a szeletben NINCS a megbízott kulccsal ellenőrzött ellenőrzőpont — csak a hash-lánc konzisztens, "
                   "aláírás nem fedi (%d bejegyzés). Várd ki a következő ellenőrzőpontot, vagy exportálj egy korábbi seq-től."
                   % rep["unverified_tail"])
            if is_product():
                print("bus_notary verify: product mode — megtagadva: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: FIGYELEM — " + msg + " A report `trusted` mezője ezért false.", file=sys.stderr)
        elif rep["ok"] and rep["unverified_tail"]:
            msg = ("az utolsó ellenőrzött ellenőrzőpont (seq %s) utáni %d bejegyzést csak a hash-lánc köti, aláírás nem "
                   "— a szelet NEM megbízható (trusted:false). Várd ki a következő ellenőrzőpontot, vagy készíts egyet "
                   "(bus_notary checkpoint), és exportálj újra." % (rep["covered_to_seq"], rep["unverified_tail"]))
            if args.pub and is_product():                       # kör-zárás termék-módban a méretétől függetlenül
                print("bus_notary verify: product mode — megtagadva: " + msg, file=sys.stderr)
                return 3
            print("bus_notary verify: FIGYELEM — " + msg, file=sys.stderr)
        if rep["ack_target_violations"]:
            print("bus_notary verify: %d ack-bejegyzés kurzor-célja nagyobb, mint max(kiinduló kurzor, ack) — a becsületes "
                  "clamp ezt nem írhatja (hamis kurzor-cél, elnyelt posta)" % len(rep["ack_target_violations"]), file=sys.stderr)
            return 1
        return 0 if rep["ok"] else 1
    if args.cmd == "compare":
        rep = compare(read_lines(args.a), read_lines(args.b))
        print(json.dumps(rep))
        if rep["same"] is None:                                 # nincs mit összevetni ≠ rendben
            print("bus_notary compare: a két exportban NINCS összevethető pont (se közös seq, se ellenőrzőpont, se "
                  "szomszédos lánc-szem) — ez nem egyezés. Exportálj átfedő tartományt.", file=sys.stderr)
            return 3
        return 0 if rep["same"] else 1
    if args.cmd == "checkpoint":
        n = Notary(args.log or default_log_path(), seed=load_seed(args.key))
        print(json.dumps(n.checkpoint(), sort_keys=True))
        return 0
    if args.cmd == "reconcile":
        # a testvér al-parancsban NINCS ilyen elutasítás — pedig épp ez az,
        # amelyik a MÁSODIK NYILVÁNTARTÁSSAL vet össze, tehát a v1.5 ígérete ezen áll.
        #
        # DE: a `verify` alakjában átvéve ez elbuktatja a saját `test_unknown_outcome_is_unresolved_not_an_
        # accusation` kontrollunkat — azt, ami az Ő OSZTÁLYÁT köti (ismeretlen kimenetel = harmadik állapot,
        # nem vád). Ott a napló üres, a nyugta viszont `outcome: unknown`-t állít, és a helyes válasz
        # ÉPPEN a soft `sent_outcome_unknown`, dev-módban rc=0. A `reconcile` tehát nem ugyanaz az eset,
        # mint a `verify`: ott a napló AZ EGYETLEN bizonyíték, itt a nyugta a másik oldal.
        # Ezért: strict/termék-módban ELUTASÍTÁS (az ő kérése), dev-módban NEVESÍTVE a harmadik csatornán.
        # A szerződés-kérdést a PR-ben felvetem, nem döntöm el egyoldalúan.
        _rec_src = read_lines(args.file)
        _rec_garbage = [r for r in _rec_src if isinstance(r, dict) and r.get("type") == "garbage"]
        if _rec_garbage:
            # A HIBÁS FÁJL és az ÜRES FÁJL két különböző eset: az első a másik fél exportjának a hibája,
            # és arra minden módban nevesített elutasítás jár.
            print("bus_notary reconcile: REJECT — a napló %d értelmezhetetlen sort tartalmaz (első: %s. sor)."
                  % (len(_rec_garbage), _rec_garbage[0].get("line")), file=sys.stderr)
            return 1
        _rec_empty, _rec_ne, _rec_nc = _no_evidence(_rec_src)
        if _rec_empty:
            _strict_mode = bool(getattr(args, "strict", False)) or is_product()
            if _strict_mode:
                _reject_no_evidence(_rec_src, "reconcile")
                return 1
            print("bus_notary reconcile: KIMONDVA (nem vád, nem zöld pipa) — a napló %d rekordot tartalmaz, "
                  "de 0 bejegyzést és 0 ellenőrzőpontot: az összevetés a nyugták EGYOLDALÚ állításain áll. "
                  "Strict/termék-módban ez rc=1." % len(_rec_src), file=sys.stderr)
        rcpts = [x for x in read_lines(args.receipts) if x.get("type") != "garbage"]
        if _pub_misuse(args.pub, "reconcile"):
            return 2
        audit = read_lines(args.bus_audit) if getattr(args, "bus_audit", None) else None
        if audit is not None:                                  # a busz saját, hash-láncolt naplója: előbb ÖNELLENŐRZÉS
            try:
                import agent_bus as _ab
                chk = _ab.audit_chain_verify(audit, start_row_hash=getattr(args, "bus_audit_anchor", None))
            except Exception as e:
                chk = {"ok": False, "errors": [{"error": str(e)[:120]}]}
            if not chk["ok"]:
                print(json.dumps({"bus_audit_chain": chk}, ensure_ascii=False, indent=1))
                print("bus_notary reconcile: a busz audit-lánca SÉRÜLT — az összevetés nem megbízható", file=sys.stderr)
                return 1
            # a HORGONYTALAN (nem a genezisből induló, horgony nélkül átadott) export
            # belsőleg ép lehet, mégsem állítás a teljes láncról — ugyanaz az alak, mint a napló-szeletnél.
            if not chk.get("anchored"):
                msg = ("a busz audit-exportja a %s. sortól indul, HORGONY nélkül — az előtte lévő sorok hiánya "
                       "belőle nem látszik. Teljes lánc: `agent_bus.py audit-export --agent <agent>` (--from-seq 0), "
                       "vagy add meg a --bus-audit-anchor <row_hash> értéket." % chk.get("slice_start_seq"))
                if bool(args.strict or is_product()):
                    print("bus_notary reconcile: MEGTAGADVA — " + msg, file=sys.stderr)
                    return 1
                print("bus_notary reconcile: FIGYELEM — " + msg, file=sys.stderr)
        strict = bool(args.strict or is_product())
        entries = read_lines(args.file)                    # 8/4: EGYSZER olvasunk (a kétszeri
        rep = reconcile(entries, args.identity, rcpts, start_cursor=args.start_cursor, trusted_pub=args.pub,
                        strict=strict, bus_audit=audit)    # olvasás közben cserélt fájl deszinkron rc-t adna)
        print(json.dumps(rep, ensure_ascii=False, indent=1))
        # A ClampLiedFields kimondott korlátja POLITIKÁVÁ téve: a kör-bejegyzés `pending`/`next_id` mezője a vádlott
        # önbevallása. Egy kör NEM kap vádat attól, hogy nincs mellette a másik nyilvántartás (az hamis vád lenne) —
        # de strict/termék-módban a CLI nem ad ZÖLD lámpát a busz saját, hash-láncolt naplója nélkül: hiányos bizonyíték.
        if strict and not audit and any(
                e.get("recipient") == args.identity and e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict)
                and any(k in e["cursor"] for k in ("pending", "next_id")) for e in entries):
            print("bus_notary reconcile: HIÁNYOS BIZONYÍTÉK — a szelet önbevallott kurzor-számokat (pending/next_id) "
                  "tartalmaz, a busz saját audit-exportja nélkül. Termék-módban ez nem zöld: add meg a "
                  "--bus-audit <fájl>-t (agent_bus.py audit-export <agent>).", file=sys.stderr)
            return 1
        if rep["ok"] and not rep["trusted"]:
            print("bus_notary reconcile: FIGYELEM — nincs eltérés, de a szelet nem megbízható (trusted:false; --pub nélkül "
                  "vagy ellenőrizetlen farokkal)", file=sys.stderr)
        hard = [d for d in rep["discrepancies"] if d["type"] != "delivered_not_received"]
        soft = len(rep["discrepancies"]) - len(hard) + len(rep["unresolved"])
        # A nem-Claude kar köre a HARMADIK CSATORNÁRA (2026-09-16), és igaza van abban, ami számít: egy jelzés,
        # ami nem változtat verdiktet, csak akkor ér valamit, ha eljut EMBERHEZ. A fogyasztó (CI, monitor)
        # az `ok`-ra szűr, a `notes` pedig a JSON mélyén marad — „csendes zöld más néven". Ugyanaz a szabály,
        # amit az egyik kar ma reggel mondott ki a `state_dir_warnings()`-ra: egy verdikt, amit senki nem kérdez
        # meg, nem jelzés. Ezért a NOTES a parancssoron az ÜZEMELTETŐHÖZ megy (stderr), akkor is, ha rc=0.
        for _n in (rep.get("notes") or [])[:8]:
            print("bus_notary reconcile: KIMONDVA (nem vád, nem zöld pipa) — %s: %s"
                  % (_n.get("type"), _n.get("why") or _n.get("note") or ""), file=sys.stderr)
        if hard or not rep["verify_ok"]:
            return 1
        if soft:
            if args.strict or is_product():
                return 1
            print("bus_notary reconcile: FIGYELEM — %d tétel nem dönthető el (delivered_not_received / unresolved: a kör "
                  "kimenetele ismeretlen). Termék-módban vagy --strict-tel rc=1." % soft, file=sys.stderr)
        return 0
    if args.cmd == "keygen":
        seed, pub = keypair()
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed.hex())
        print(pub)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
