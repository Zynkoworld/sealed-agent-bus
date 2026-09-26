#!/usr/bin/env python3
"""bus_enforce — ENFORCEMENT. The main finding of attack matrix v0: today's weakness is NOT
cryptographic but one of enforcement — the bus annotates, leaves the decision to the receiver, and the default allows that. The attacker
does not break the signature, it OMITS it (unsigned-downgrade). This module is the product profile's gate.

Two operating modes (a single switch):
- **dev** (the default, if nothing is set): today's back-compat behaviour — the live fleet does not break.
- **product**: `AGENT_BUS_MODE=product` OR the `.product_mode.on` marker in the bus directory. Then recv/verify
  REJECTS (not just marks):
    * an unsigned message                              → `unsigned-downgrade`
    * an invalid signature / registry key mismatch     → `forged`
    * the signed `ts` outside the window (past / future) → `stale-ts` / `future-ts`
    * the same signed content a second time            → `replay` — durable seen-store,
      also after a restart
    * `attachment` kind, if the descriptor is not part of the signed body / incomplete → `attachment-descriptor`
The product/release profile sets product mode; `abus doctor` warns loudly if it is not on.

Nothing is deleted: the rejected row stays in the DB, the reason for rejection goes into the `rejected.jsonl` log.
The seen-store is an append-only file (not the DB schema) → NO SCHEMA_VERSION bump.

fixes (2026-09-14):
- the window looks at the send time, but the bus builds on sleeping recipients → default window −7 days/+300 s (the replay
  store catches the duplicate even without a window), and a rejected row does NOT raise delivered_id, it gets an `enforce_reject` audit
  row → `reconcile`/`replay` sees it (agent_bus.recv).
- the mode CANNOT be switched back to dev with env: the marker is looked up NEXT TO the DB and under /etc/agent-bus too, env
  can only switch it ON; an unknown AGENT_BUS_MODE value → product (fail-closed). The window env can only NARROW.
- /the delivering recv's seen-store lives in the DB (`enforce_seen` table, inside the cursor transaction, atomic across
  processes) — no separate, unguarded file belonging to another UID. The `SeenStore` file class remains (back-compat).
- a bad env → default + doctor warning, not a traceback; log writing is best-effort.
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
SYSTEM_MARKER = "/etc/agent-bus/product_mode.on"         # system-level, root-managed switch
DEFAULT_WINDOW_PAST_S = 7 * 24 * 3600                     # a sleeping recipient gets it too (the replay store catches duplicates)
DEFAULT_WINDOW_FUTURE_S = 300
WARNINGS = []                                             # shown by doctor (not a traceback)


def _env_window(name, default):
    """Window from env: can ONLY narrow. An invalid / non-positive / widening value → default + warning."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        WARNINGS.append("%s=%r invalid → default %ds" % (name, raw, default))
        return default
    if v <= 0 or v > default:
        WARNINGS.append("%s=%d ignored (only 1..%d can narrow) → %ds" % (name, v, default, default))
        return default
    return v


WINDOW_PAST_S = _env_window("AGENT_BUS_WINDOW_PAST_S", DEFAULT_WINDOW_PAST_S)
WINDOW_FUTURE_S = _env_window("AGENT_BUS_WINDOW_FUTURE_S", DEFAULT_WINDOW_FUTURE_S)


def state_dir():
    d = os.environ.get("AGENT_BUS_ENFORCE_DIR") or os.path.join(BRIDGE, "enforce")
    return d


def marker_paths(bus_dir=None, db=None):
    """EVERY search location of the product-mode marker (union). The marker next to the DB file is decisive — an env-
    redirected AGENT_BRIDGE_DIR/AGENT_BUS_DIR only ADDS locations, it does not take away the one next to the DB/the system one."""
    import agent_bus as ab
    # (2026-09-17): `abspath` does NOT resolve a symlink — a symlink from a marker-less directory pointing to the REAL DB
    # gave dev mode while reading the same file. `realpath` is the decisive location; the abspath location STAYS
    # beside it (union: more locations = fail-closed towards product mode, never fewer).
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
    """'product' if env or ANY marker says so, otherwise 'dev' (back-compat). Env can only switch it ON: if there is a marker,
    even `AGENT_BUS_MODE=dev` does not switch back. An unknown value (e.g. 'production', 'prod') → product.
    The protection against SILENT FALLBACK is NOT a separate mechanism: the root-managed `SYSTEM_MARKER`
    (/etc/agent-bus/product_mode.on) gives exactly that — only root can delete it, while the marker next to the bus
    can be deleted by anyone who writes to the bus. A "sticky product mode" (the bus remembers it has run in product mode) WAS BUILT and
    WITHDRAWN TWICE: measured, both times it read/wrote the PRODUCTION bus DB from calls meant only as
    measurement (because of the module-level path resolution), and it failed 20 tests. The correct step is operational: put down the
    root-owned marker; `doctor()` loudly demands this too."""
    raw = os.environ.get(MODE_ENV, "").strip().lower()
    if raw and raw != "dev":
        return "product"
    return "product" if any(os.path.exists(p) for p in marker_paths(bus_dir, db)) else "dev"


class DbSeenStore:
    """/the replay store in the bus DB (`enforce_seen`), on the CALLER's connection/transaction → atomic with the
    cursor move, serialized across processes (BEGIN IMMEDIATE), and exactly as protected as the messages themselves (whoever
    can delete it can also rewrite messages). A lazy table (verify_schema only looks at the core tables) → no schema bump."""

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
                return False                                  # nothing has been delivered in product mode yet
            raise

    def add(self, key, ts_s):
        cur = self.c.execute("INSERT OR IGNORE INTO enforce_seen(agent,k,ts_s) VALUES(?,?,?)", (self.agent, key, int(ts_s)))
        return cur.rowcount == 1


def content_key(msg):
    """The signed content's identifier for the replay store: sha256(signed byte image || sig). The id is NOT part of it (a re-
    inserted row with identical content gets a new id — exactly that must be caught)."""
    import agent_bus as ab                                     # late import: no circular loading
    h = hashlib.sha256(ab._a2_content_bytes(msg))
    h.update(b"|")
    h.update((msg.get("sig") or "").encode())
    return h.hexdigest()


class SeenStore:
    """A durable, append-only seen-store per recipient (JSONL: {"k", "ts_s"}). Catches replay even after a restart.
    Compaction (compact): drops only keys OUTSIDE the freshness window + margin, which are certainly stale —
    NEVER an entry inside the window (the freshness gate rejects a ts outside the window anyway)."""

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
        """Drop keys older than twice the window, with an atomic swap. Returns the number kept."""
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
    """The bus ts is in nanoseconds (time.time_ns); test/manual rows may give seconds."""
    try:
        v = int(ts)
    except (TypeError, ValueError):
        return None
    return v / 1e9 if v > 10**12 else float(v)


def attachment_ok(msg):
    """The attachment descriptor lives in the SIGNED body (the body is one of the signed fields, _A2_SIGNED_FIELDS), and conforms to
    bus_attach's closed descriptor contract — the same validator send uses (no second, different rule)."""
    import bus_attach
    try:
        bus_attach.check_descriptor(msg.get("body") or "")
        return True
    except ValueError:
        return False


def check(msg, *, now_s=None, seen=None, record=False, keys_dir=None,
          window_past=None, window_future=None):
    """The product-mode verdict on a recv'd row → (ok: bool, reason: str). With `record=True` (delivering recv)
    the accepted content goes into the seen-store; on peek it only checks, does not consume."""
    import agent_bus as ab
    now_s = time.time() if now_s is None else now_s
    wp = WINDOW_PAST_S if window_past is None else window_past
    wf = WINDOW_FUTURE_S if window_future is None else window_future
    auth = ab.verify_sender(msg, keys_dir=keys_dir)
    if auth == "unsigned":
        return False, "unsigned-downgrade"
    if auth == "unsigned-pinned":
        # a bare row under a name able to sign (pinned) — a separate reason, does not blend into unsigned
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
        # `record=True` means CONSUMPTION — without a seen-store replay protection is silently skipped.
        # Peek/classifier calls come with `record=False`; this branch is a programming error, not an operational state.
        raise ValueError("record=True requires a seen-store (replay protection)")
    if seen is not None:
        key = content_key(msg)
        if seen.seen(key):
            return False, "replay"
        if record and not seen.add(key, ts):
            # There is a race between `seen()` and `add()` (two concurrent recvs). The
            # `add()` returning FALSE ("was already in") is the only atomic signal — without it both sides would have delivered.
            return False, "replay"
    return True, "ok"


def log_rejected(agent, msg, reason, base=None):
    """The rejection log (append-only; the row itself stays in the DB — nothing is deleted)."""
    # /best-effort — an unwritable log location (another UID's, not a directory) NEVER fails the recv;
    # the authoritative trace is the `enforce_reject` audit row in the DB. -> True if written.
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
    """Status report for the product profile. -> (ok: bool, lines: list[str])."""
    import agent_bus as ab
    lines, ok = [], True
    m = mode()
    if m != "product":
        ok = False
        lines.append("!!! WARNING: the bus runs in DEV mode — it delivers unsigned and stale messages too. "
                     "For the product profile: AGENT_BUS_MODE=product or the %s marker." % MARKER)
    else:
        lines.append("mode: product (signature required, ts window -%ds/+%ds, replay store: %s)" % (WINDOW_PAST_S, WINDOW_FUTURE_S, state_dir()))
    # (2026-09-17): the mode is decided PER PROCESS (env + file existence); doctor measures in ITS OWN environment. Another
    # process may run in dev at the same moment. So the verdict's scope is STATED as smaller than the
    # product profile's (fleet-level) promise; what stands at fleet level is the existence of the root-managed SYSTEM_MARKER.
    lines.append("scope: this verdict holds for THIS process (env %s=%r + marker existence); another process may run in another mode. "
                 "Only the root-managed %s gives a fleet-level claim%s."
                 % (MODE_ENV, os.environ.get(MODE_ENV, ""), SYSTEM_MARKER,
                    " — PRESENT" if os.path.exists(SYSTEM_MARKER) else " — ABSENT"))
    for w in WARNINGS:
        lines.append("! " + w)
    for p in marker_paths():
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_uid != 0 or (st.st_mode & 0o022):
            lines.append("! the marker (%s) is not root-owned or is group/world-writable — anyone can delete it; "
                         "recommended: %s (root, 0644)" % (p, SYSTEM_MARKER))
    # if product mode rests SOLELY on a marker next to the bus, then whoever can
    # insert a message can also delete the marker -> the gate SILENTLY falls to dev, and from then on delivers unsigned rows too.
    if m == "product" and not os.environ.get(MODE_ENV, "").strip() and not os.path.exists(SYSTEM_MARKER):
        ok = False
        lines.append("!!! product mode rests ONLY on a marker next to the bus (%s absent, env absent) — whoever can write to the bus "
                     "can also delete the marker, and the gate silently falls to dev. Put down a root-owned marker: %s"
                     % (SYSTEM_MARKER, SYSTEM_MARKER))
    if not ab._A2_HAVE:
        ok = False
        lines.append("!!! the 'cryptography' package is missing — signatures cannot be checked (in product mode every row is forged)")
    return ok, lines
