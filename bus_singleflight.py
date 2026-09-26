#!/usr/bin/env python3
"""bus_singleflight — structural collision protection for tmux-Claude agents (the operator, 2026-06-25).

## The problem it solves

`bus_poke` injects a "check your mail" prompt into the pane of an ALREADY RUNNING tmux session. If
TWO Claude instances run under the same identity (one operator-opened + one
poke-driven), BOTH pick up the same inbox message and do the same work —
duplicated/stale edits (2026-06-25: two instances of one arm did the same VERSION bump, one of them
got stuck on a stale `old_string`). The bus lets agents message each other, but does NOT enforce
a work claim → the root cause was unsolved.

This module is the structural gate, with two deterministic, stdlib-only mechanisms:

1. **Session lock** (`SessionLock`): one active worker / agent identity. At start an instance
   atomically (`O_EXCL`) grabs `wake/<agent>.session.lock`. If another owner is alive, the
   new instance knows it is a DUPLICATE → it does no autonomous drain, it serves the operator, but
   leaves the bus to the owner. A dead owner's lock is stale → can be reclaimed atomically
   (requeue-on-death). NO DELETION: the lock file's content is auditable, it is only overwritten.

2. **Message claim** (`MessageClaim`): defense-in-depth against transient overlap. BEFORE handling an inbox
   message the instance atomically (`os.rename`) moves it into its own
   (`inbox/<agent>/.claimed/<instance>/<name>`). POSIX allows the rename to exactly one caller;
   the loser gets `FileNotFoundError` and skips it. A dead claimer's messages are requeued
   (back into `pending` — a MOVE, not a deletion).

Both rely on pid liveness (`os.kill(pid, 0)`, box-local). The protection against pid reuse
DIFFERS PER BRANCH, and we state it here:
  - SessionLock `ttl` branch and MessageClaim directory freshness → TTL;
  - SessionLock `pid` branch and the `target`+owner branch → NO TTL (a clock must not expire the lock of a
    long-lived owner pid), instead PID BIRTH IDENTITY: acquire stores the pid's start time
    (`/proc/<pid>/stat` starttime, `pid_birth`), and the owner is "alive" only if THE SAME process
    is alive — a reassigned pid has a different birth, so the lock is stale. An old (birthless) record or
    unreadable /proc → fallback to the bare pid liveness signal, STATED (not silent) — and for a birthless
    record LIMITED IN TIME (LEGACY_GRACE_NS from the record's ts_ns): per the residual,
    a `pid_birth` deleted from a writable record would otherwise have given an eternal lock; the owner's heartbeat
    fills in the missing birth, so a live owner loses nothing;
  - MessageClaim pid-shaped claimer name → pid liveness only (STATED LIMIT: the claim directory stores no
    birth; on requeue the cost of a stale claim is one redelivery, not a duplicated worker).
Liveness, birth and the clock are injectable → deterministic tests.

Constitution: the poke is FIXED text, the message stays DATA; this layer ONLY decides WHICH instance
handles it — it never gives commands. Enforcing a per-agent / per-repo invariant, not content interpretation.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time

BRIDGE = os.environ.get("AGENT_BRIDGE_DIR", os.path.expanduser("~/.agentbus"))

# Liveness TTL: for this long we consider a lock/claim owner alive based on its fresh timestamp,
# EVEN if the pid is alive (belt-and-braces against pid reuse).
_LIVENESS_TTL_NS = 90 * 1_000_000_000  # 90 s — well above the heartbeat, but not eternal

_SAFE_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_name(s):
    """Filename-safe instance id (in the spirit of `local_bus._safe_name`): path separators,
    control chars and other surprises filtered out. Empty becomes 'anon'."""
    s = _SAFE_RE.sub("_", str(s)).strip("_.")
    return s or "anon"


def _pid_birth(pid):
    """The process's BIRTH: field 22 of `/proc/<pid>/stat` (starttime, clock ticks since boot). After reassignment a pid
    gets a DIFFERENT birth, so (pid, birth) is the process identity, the bare pid is not.
    None if not measurable (not Linux, no /proc, the process vanished meanwhile) — the caller handles this as STATED."""
    try:
        pid = int(pid)
        if pid <= 0:
            return None
        with open("/proc/%d/stat" % pid, "rb") as f:
            raw = f.read()
        # field 2 (comm) is parenthesized and may contain spaces/parentheses → we count after the LAST ')'
        rest = raw[raw.rindex(b")") + 2:].split()
        return int(rest[19])                                  # counting from field 3, field 22 = rest[19]
    except (OSError, ValueError, TypeError, IndexError):
        return None


def _pid_alive(pid):
    """Box-local pid liveness via signal 0. True if the pid exists (even if owned by another user →
    EPERM also means 'exists'). 0/negative → False."""
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
    """Whether `target` (tmux session or session:win.pane) belongs to a LIVE pane. This is the authority
    for a tmux session's liveness (pane exists = the worker is alive), BECAUSE the CLI pid calling `acquire`
    may be ephemeral (operator-opened pts session → the Bash subprocess dies immediately). `run`
    is injectable for tests. On error/no tmux → False (fail-closed: do not keep a lock believed dead
    as alive)."""
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
    # only a session name given (e.g. 'one-arm') → any matching pane is enough
    return any(p.split(":", 1)[0] == target for p in panes)


def default_instance_id():
    """A stable instance id for THIS process. In tmux: `<session:win.pane>:<pid>` (the pane is
    unique + the pid for liveness); otherwise `<hostname>:<pid>`. The pid always comes last →
    `pid_of(instance_id)` can read it back."""
    pid = os.getpid()
    pane = os.environ.get("TMUX_PANE")  # e.g. '%3' — unique within the tmux server
    if pane:
        return _safe_name("%s:%d" % (pane, pid))
    host = os.environ.get("HOSTNAME") or "host"
    return _safe_name("%s:%d" % (host, pid))


def session_instance_id(agent, *, instance=None, owner_pid=None, bridge=BRIDGE,
                        is_alive=_pid_alive):
    """An instance id bound to the caller's SESSION, STABLE across calls.

    Why it is needed: `default_instance_id()` is built from the CALLING PROCESS's pid, but for a Claude agent
    every Bash call is a new, ephemeral subprocess. So every sub-command got a DIFFERENT identity:
    `claim-pending` put the message under `.claimed/<ephemeral-pid>/`, and the next call
    no longer recognized it as its own (`claimed_by_me=0`) — the message got stuck there, never reaching
    the archive. The same caused SELF-EXCLUSION on the session lock: my own calls got `duplicate`
    and `release` returned False.

    Resolution order — the first valid one wins:
      1. explicit `--instance`;
      2. the `AGENT_BUS_INSTANCE` environment variable;
      3. an explicit `--owner-pid` (the long-lived, e.g. Claude session, pid) → `host:<owner_pid>`;
      4. the stored pid of the ALREADY EXISTING session lock, BUT only if `liveness == "pid"` and the pid IS ALIVE —
         so even a bare sub-command can recover the session identity without
         rewriting every call site. It does not affect `target`-liveness (tmux) locks,
         because there the stored pid is not the owner's long-lived id;
      5. fallback to the old behaviour (`default_instance_id()`), so whoever gives nothing
         works exactly as before.
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
        # the identity can be recovered ONLY by a caller whose owner (its parent
        # process) is the stored owner itself — otherwise any other process would take over the live lock with "already-own".
        if (isinstance(d, dict) and d.get("liveness") == "pid" and is_alive(d.get("pid"))
                and d.get("pid") == os.getppid()):
            return _safe_name(str(d.get("instance")))
    except (OSError, ValueError, TypeError):
        pass
    return default_instance_id()


def pid_of(instance_id):
    """The pid encoded at the end of the instance id (the `default_instance_id()` convention). None if absent."""
    tail = str(instance_id).rsplit(":", 1)[-1]
    try:
        return int(tail)
    except (TypeError, ValueError):
        return None


_CLOCK_SANITY_NS = 24 * 3600 * 10 ** 9                      # 24 hours: a caller clock further away than this is not accepted
# for a birthless (old or DELETED-field) pid-branch record the bare pid liveness signal decides only for this long
# from the record's ts_ns; meanwhile the owner's heartbeat fills in the birth, and a deleted field does not give an eternal lock.
LEGACY_GRACE_NS = 24 * 3600 * 10 ** 9


def _now(now_ns):
    return now_ns if now_ns is not None else time.time_ns()


def _now_for_liveness(now_ns):
    """The clock that decides LIFE. The caller-supplied `now_ns` used to be unbounded, so with an
    `acquire(..., now_ns=2**62)` call anyone could see a LIVE, TTL-based lock as STALE and take it.
    Simulation (tests, measurement) still works — only a value more than 24 hours from reality cannot decide."""
    real = time.time_ns()
    if now_ns is None:
        return real
    return now_ns if abs(int(now_ns) - real) <= _CLOCK_SANITY_NS else real


class SessionLock:
    """One active worker / agent identity. The lock file's content is JSON (audit):
    `{instance, pid, target, ts_ns}`. `is_alive` (pid→bool) and `now_ns` are injectable."""

    def __init__(self, agent, *, bridge=BRIDGE, is_alive=None, target_alive=None,
                 ttl_ns=_LIVENESS_TTL_NS, pid_birth=None):
        self.agent = _safe_name(agent)
        self.bridge = bridge
        self.is_alive = is_alive or _pid_alive
        self.pid_birth = pid_birth or _pid_birth              # pid → birth (injectable)
        # None → the module-level `_tmux_target_alive` (lazy resolution, so tests can monkeypatch it)
        self._target_alive = target_alive
        self.ttl_ns = ttl_ns
        self.dir = os.path.join(bridge, "wake")
        self.path = os.path.join(self.dir, "%s.session.lock" % self.agent)

    def holder(self):
        """The current lock owner's dict, or None if none/unreadable."""
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _target_alive_fn(self):
        return self._target_alive if self._target_alive is not None else _tmux_target_alive

    def _holder_alive(self, d, now):
        """Is the lock owner alive? The liveness strategy depends on the `liveness` field (`acquire`
        picks it for the available signal):
          - `target` → the tmux pane's existence is the authority (an operator-opened session is correct too!);
          - `pid`    → the liveness signal of the PERSISTENT owner pid passed by the caller (no TTL, but
                       with pid birth identity — );
          - `ttl`    → derived CLI pid + freshness (best-effort, for ephemeral calls).
        Backward compatible: missing `liveness` → `ttl`."""
        if not d:
            return False
        lv = d.get("liveness", "ttl")
        if lv == "target" and d.get("target"):
            if not self._target_alive_fn()(d["target"]):
                return False
            # if the caller gave an EXPLICIT owner pid, its death is the lock's death too —
            # otherwise a surviving tmux pane (the shell) would show a dead worker's lock as "alive" forever.
            if d.get("pid_src") == "owner":
                return self._same_process_alive(d, now)
            return True
        if lv == "pid":
            return self._same_process_alive(d, now)
        ts = d.get("ts_ns")
        if not isinstance(ts, int) or (now - ts) >= self.ttl_ns:
            return False  # too old → stale even if the (derived) pid is alive (again)
        pid = d.get("pid")
        # for a non-pid-shaped instance (pid=None) a FRESH lock lives until the TTL —
        # previously `is_alive(None)` → False, i.e. anyone could immediately take a freshly written lock.
        return True if pid is None else self._same_process_alive(d, now)

    def _same_process_alive(self, d, now):
        """Is THE SAME process alive that wrote the lock — not just "something is alive on this pid".
        (2026-09-17): the pid branch had no TTL, and per the header that would have been the protection against pid
        reassignment. A TTL does not belong here (a long-lived owner pid's lock lives as long as the process), the correct signal is the
        process's birth: the `pid_birth` stored in the record == the pid's CURRENT birth. Stated fallbacks:
        an old record (no `pid_birth`) or a birth not measurable now → the bare pid liveness signal decides."""
        pid = d.get("pid")
        if not self.is_alive(pid):
            return False
        born = d.get("pid_birth")
        if born is None:
            # An old (birthless) record — OR a field deleted from a writable record (without this the
            # cost of the fallback was an ETERNAL lock if the record is writable). So the fallback is LIMITED IN TIME: the bare
            # pid liveness signal decides only up to LEGACY_GRACE_NS from the record's `ts_ns`; the owner's heartbeat/re-acquire
            # fills in the birth meanwhile (see `_payload`), so a live owner loses nothing, while a deleted field
            # does not give an eternal lock.
            ts = d.get("ts_ns")
            if not isinstance(ts, int) or (now - ts) >= LEGACY_GRACE_NS:
                return False
            return True
        now_born = self.pid_birth(pid)
        if now_born is None:
            return True                                       # not measurable: we do not decide blindly (stated)
        return now_born == born

    @staticmethod
    def _liveness_of(instance, target, owner_pid):
        """The chosen liveness strategy + the stored pid, based on the available signal."""
        if target:
            return ("target", owner_pid if owner_pid else pid_of(instance))   # pid_src a _payload-ban
        if owner_pid:
            return ("pid", owner_pid)
        return ("ttl", pid_of(instance))

    def _payload(self, instance, target, now, *, owner_pid=None, liveness=None, pid=None, pid_src_keep=None,
                 caller_ts=None, pid_birth_keep=None):
        """(2026-09-16) the previous fix bounded ONLY the reading side — the raw caller clock
        still went into the file, so the caller's clock still decided LIFE, just one step
        later and for EVERYONE ELSE (past stamp → two `acquired`; future stamp + pid-less instance
        → ETERNAL lock). So: `ts_ns` is ALWAYS the bounded, life-deciding value; the caller's raw stamp is kept in a separate
        `caller_ts_ns` field for audit, and it feeds into no decision."""
        if liveness is None:
            liveness, pid = self._liveness_of(instance, target, owner_pid)
            pid_src = "owner" if owner_pid else "derived"
            birth = self.pid_birth(pid) if pid is not None else None   # the process identity
        else:
            pid_src = pid_src_keep
            # the PRESERVED record's birth stays; if there is none (old or deleted field), the owner FILLS IT IN now (
            # residual) — so a live owner's record has a birth after the next heartbeat/re-acquire
            birth = pid_birth_keep if pid_birth_keep is not None else (self.pid_birth(pid) if pid is not None else None)
        doc = {"instance": instance, "pid": pid, "target": target,
               "ts_ns": now, "liveness": liveness, "pid_src": pid_src, "pid_birth": birth}
        if caller_ts is not None and caller_ts != now:
            doc["caller_ts_ns"] = caller_ts                    # audit: the caller's CLAIMED time, if it differs
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))

    def acquire(self, instance, *, target=None, owner_pid=None, now_ns=None):
        """Try to grab the lock for this instance. Returns `(status, holder)`:
          - `('acquired', me)`     — from now on this instance is THE active worker;
          - `('already-own', me)`  — it already belonged to this instance (idempotent re-call/heartbeat);
          - `('duplicate', other)` — ANOTHER owner is alive → the caller is a duplicate, it must not drain.
        When `target` is given, liveness is bound to the tmux pane's existence (an operator-opened session is
        correct too); `owner_pid` is for explicitly passing the persistent (Claude) PID. A stale owner's
        lock is reclaimed atomically."""
        instance = _safe_name(instance)
        caller_ts = _now(now_ns)                              # what the caller CLAIMS (audit)
        now = _now_for_liveness(now_ns)                       # what we DECIDE with (bounded) — 
        os.makedirs(self.dir, exist_ok=True)
        # the "who is the owner? → stale → reclaim" sequence must be atomic.
        # A flock held on a side file serializes competing acquires (the lock file's content
        # could otherwise be empty/half-written, which the other caller read as "no owner").
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
        # re-measurement (B1-var): a lock written with a never-live target is seen as stale immediately by anyone else
        # (`_holder_alive` looks at the pane) → reclaimed, while this caller has already got `acquired` →
        # two workers. So target liveness is only given for a LIVE pane: a non-live target → refusal, with no write.
        if target and not self._target_alive_fn()(target):
            return ("target-not-live", {"instance": instance, "target": target, "liveness": "target"})
        # the same on the owner branch. A lock written with a NEVER-LIVE (or already dead) owner pid
        # is seen as stale immediately by the other caller (`_holder_alive` looks at the pid) and reclaimed, while this
        # caller has already got `acquired` → two workers (measured: 7-9/15). So: the given owner pid — or, lacking owner and target,
        # the pid derived from the instance (ttl branch) — must be alive AT THE MOMENT of acquire; otherwise refusal, with no write.
        if owner_pid is not None and not self.is_alive(owner_pid):
            return ("owner-not-live", {"instance": instance, "pid": owner_pid, "pid_src": "owner"})
        if not target and owner_pid is None:
            derived = pid_of(instance)
            if derived is not None and not self.is_alive(derived):
                return ("owner-not-live", {"instance": instance, "pid": derived, "pid_src": "derived"})
        payload = self._payload(instance, target, now, owner_pid=owner_pid, caller_ts=caller_ts)
        # 1) fast path: atomic O_EXCL creation
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            return ("acquired", json.loads(payload))
        except FileExistsError:
            pass
        # 2) it exists: whose is it?
        cur = self.holder()
        if cur and cur.get("instance") == instance:
            # Ours → refresh (heartbeat). We PRESERVE the liveness strategy if the caller gave no
            # new one: a bare re-`acquire` (which any sub-command can trigger since session identity recovery)
            # would otherwise degrade the lock from `pid` to `ttl` with an already dead,
            # derived pid — i.e. it would make our own, LIVE lock stale.
            if target is None and owner_pid is None:
                payload = self._payload(instance, cur.get("target"), now,
                                        liveness=cur.get("liveness", "ttl"), pid=cur.get("pid"),
                                        pid_src_keep=cur.get("pid_src"), caller_ts=caller_ts,
                                        pid_birth_keep=cur.get("pid_birth"))
            self._write_atomic(payload)
            return ("already-own", json.loads(payload))
        if self._holder_alive(cur, alive_now if alive_now is not None else now):
            return ("duplicate", cur)
        # 3) stale (dead or expired) → atomic reclaim
        self._write_atomic(payload)
        return ("acquired", json.loads(payload))

    def _write_atomic(self, payload):
        tmp = "%s.tmp.%d" % (self.path, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, self.path)  # atomic overwrite (no-deletion: the lock is a status file)

    def _with_mutex(self, fn):
        """`acquire` was serialized with a side file's flock, but `heartbeat` and
        `release` were NOT — so wedged between a takeover and a heartbeat/release, two parties could
        both believe they were "the owner", and one could blindly overwrite the other's lock. The same lock, the same
        serialization."""
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
        """Refresh the lock's timestamp if this instance is the owner (preserves the liveness strategy and the
        pid unless you give new ones). True on success."""
        return self._with_mutex(lambda: self._heartbeat_locked(instance, target, owner_pid, now_ns))

    def _heartbeat_locked(self, instance, target=None, owner_pid=None, now_ns=None):
        instance = _safe_name(instance)
        cur = self.holder()
        if not cur or cur.get("instance") != instance:
            return False
        tgt = target if target is not None else cur.get("target")
        if owner_pid is None and target is None:
            # unchanged strategy: keep the existing liveness/pid, only refresh ts
            self._write_atomic(self._payload(instance, tgt, _now_for_liveness(now_ns),
                                              liveness=cur.get("liveness", "ttl"),
                                              pid=cur.get("pid"), pid_src_keep=cur.get("pid_src"),
                                              caller_ts=_now(now_ns), pid_birth_keep=cur.get("pid_birth")))
        else:
            self._write_atomic(self._payload(instance, tgt, _now_for_liveness(now_ns), owner_pid=owner_pid,
                                             caller_ts=_now(now_ns)))
        return True

    def release(self, instance):
        """Release the lock IF it belongs to this instance (a foreign lock is left alone). True if released.
        It removes the file — this is NOT data deletion, but releasing an ephemeral status lock.

        STATED LIMIT: `release` only requires the `instance` STRING to match, so
        whoever can read the lock file can also release a LIVE owner's lock. Closing it would take a secret token
        issued at acquire — but that changes the vendored callers' contract (MAJOR gate),
        so it is not a unilateral step: the proposal is in the PR. The mutex at least rules out the race."""
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
    """Atomic, rename-based per-message claim on the shared `inbox/<agent>/`. BEFORE handling a
    message the caller grabs it; a concurrent loser skips it."""

    CLAIM_TTL_NS = int(os.environ.get("AGENT_BUS_CLAIM_TTL_S", str(3600))) * 10 ** 9   # the "still working" window

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
        """ATOMIC: grab message `name` for this instance. True if WON (moved into
        its own claim folder); False if someone else took it (the rename failed with ENOENT)."""
        if not name.endswith(".json") or "/" in name or name.startswith("."):
            return False
        os.makedirs(self.mine, exist_ok=True)
        src = os.path.join(self.inbox, name)
        dst = os.path.join(self.mine, name)
        try:
            os.rename(src, dst)  # POSIX: exactly one concurrent rename wins
            return True
        except (FileNotFoundError, OSError):
            return False

    def claim_pending(self):
        """Grab ALL currently pending messages that can be won. Returns the list of
        names actually won (the lost ones are skipped). The caller works on these — and ONLY
        these."""
        won = []
        for name in self._pending():
            if self.claim(name):
                won.append(name)
        return won

    def claimed_paths(self):
        """Full paths of the messages claimed by this instance and not yet archived."""
        try:
            return [os.path.join(self.mine, f)
                    for f in sorted(os.listdir(self.mine)) if f.endswith(".json")]
        except OSError:
            return []

    def _claimer_state(self, inst, d, now):
        """A MEASURED decision about another claimer from "alive" / "dead" / "unknown". -> True (alive) | False (dead)

        (2026-09-16) here the `pid_of(inst) -> is_alive(None) -> False` chain took the
        ABSENCE OF EVIDENCE as "dead", so anyone could requeue the claims of a LIVE worker with a stable name (e.g. `claude-alfa-session`)
        out from under it — the same class of error we already closed on the SessionLock side in B1.
        The naive fix (`pid is None -> continue`), however, opens a hole at the OTHER end: the messages of a
        truly dead claimer with a stable name would be stuck forever (they measured this too).
        So a third state, bound to a MEASURABLE signal:
          1. pid-shaped name -> the pid's liveness decides (as before);
          2. no pid         -> a LIVE session lock of the same instance is evidence of life;
          3. if not that either -> the claim directory's FRESHNESS decides (mtime + TTL): fresh = still working,
                               stale = released. We fall SILENTLY on neither the "alive" nor the "dead" side.
        """
        pid = pid_of(inst)
        if pid is not None:
            return bool(self.is_alive(pid))
        try:                                                   # 2) is there a live session lock with the same name?
            lock = SessionLock(self.agent, bridge=self.bridge, is_alive=self.is_alive)
            cur = lock.holder()
            if cur and cur.get("instance") == inst and lock._holder_alive(cur, now):
                return True
        except Exception:
            pass
        try:                                                   # 3) the claim directory's freshness
            newest = max([os.path.getmtime(os.path.join(d, f)) for f in os.listdir(d)] or
                         [os.path.getmtime(d)])
        except OSError:
            return True                                        # not measurable -> we do NOT touch it
        return (now - int(newest * 10 ** 9)) < self.claim_ttl_ns

    def requeue_dead(self, *, now_ns=None):
        """Move the messages of every DEAD claimer (`.claimed/<inst>/`) back into `pending`
        (requeue-on-death — a MOVE, not a deletion). It never touches the live current instance.
        The "dead" verdict is MEASURED (see `_claimer_state`), not the absence of evidence.
        Returns the list of requeued names."""
        now = _now_for_liveness(now_ns)                        # we used to accept the parameter and discard it
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
                continue  # our own: we are alive, do not requeue from under ourselves
            if self._claimer_state(inst, d, now):
                continue  # MEASURABLY alive (pid / session lock / fresh claim directory) → let it work
            try:
                files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
            except OSError:
                continue
            for name in files:
                back = os.path.join(self.inbox, name)
                if os.path.exists(back):
                    continue  # such a pending already exists (do not overwrite) — no-deletion
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
                                description="session lock + atomic message claim for tmux-Claude agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("acquire", help="grab the session lock (at start); prints the status")
    pa.add_argument("--agent", required=True)
    pa.add_argument("--target", default=None,
                    help="the current tmux target (session or session:win.pane) → liveness is bound to the PANE's "
                         "existence (correct for an operator-opened session too). Recommended form "
                         "in tmux: --target \"$(tmux display-message -p "
                         "'#{session_name}:#{window_index}.#{pane_index}')\"")
    pa.add_argument("--instance", default=None,
                    help="stable instance id (default: auto from the process: TMUX_PANE:pid / host:pid)")
    pa.add_argument("--owner-pid", type=int, default=None,
                    help="persistent owner PID (e.g. the pid of the long-lived Claude session) — "
                         "use it if there is no tmux target but you know the long-lived pid")

    # The session-scoped identity is needed by EVERY sub-command, not just `acquire`: without it
    # `claim-pending` claims under an ephemeral name that `status`/`release` no longer recognize.
    def _identity_args(sp):
        sp.add_argument("--instance", default=None,
                        help="stable instance id (default: recovered from the session lock, "
                             "otherwise auto from the process: TMUX_PANE:pid / host:pid)")
        sp.add_argument("--owner-pid", type=int, default=None,
                        help="persistent owner PID (e.g. the pid of the long-lived Claude session)")

    pr = sub.add_parser("release", help="release the session lock (on exit)")
    pr.add_argument("--agent", required=True)
    _identity_args(pr)

    ps = sub.add_parser("status", help="who owns the session lock + pending/claimed messages")
    ps.add_argument("--agent", required=True)
    _identity_args(ps)

    pc = sub.add_parser("claim-pending", help="atomically grab ALL pending messages; the won ones")
    pc.add_argument("--agent", required=True)
    _identity_args(pc)

    pq = sub.add_parser("requeue-dead", help="move the messages of dead claimers back")
    pq.add_argument("--agent", required=True)
    _identity_args(pq)

    pg = sub.add_parser("guard", help="is there already a LIVE worker for this identity "
                                      "(launcher pre-check: exit 3 = do not start a duplicate)")
    pg.add_argument("--agent", required=True)

    a = p.parse_args(argv)
    iid = session_instance_id(a.agent, instance=getattr(a, "instance", None),
                              owner_pid=getattr(a, "owner_pid", None))

    if a.cmd == "acquire":
        lock = SessionLock(a.agent)
        use_iid = iid
        owner = a.owner_pid
        if owner is None and not a.target:
            # the `acquire` CLI is a one-shot, immediately exiting process — its OWN pid is not
            # the owner. By default the CALLER's (the long-lived shell/agent) pid is the owner; whoever wants otherwise
            # passes --owner-pid or --target.
            owner = os.getppid()
        status, holder = lock.acquire(use_iid, target=a.target, owner_pid=owner)
        print("instance=%s status=%s holder=%s liveness=%s" % (
            use_iid, status, holder.get("instance"), holder.get("liveness")))
        # exit code for the launcher/STARTUP protocol: 0 = you are the worker; 3 = duplicate; 4 = --target is not a live pane
        # OR the given owner pid is not alive (B1var-2) — both: the lock was NOT written, fix the call.
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
            return 3  # another worker is alive → the launcher must NOT start a duplicate
        print("clear")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
