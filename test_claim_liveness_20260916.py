"""The claim-side liveness signal and the WRITING side of the caller clock — (2026-09-16 afternoon) + our own measurement.

Two HIGH findings from their round, both measured and fixed:

  — `MessageClaim.requeue_dead`: the `pid_of(inst) -> is_alive(None) -> False` chain took the ABSENCE
           OF EVIDENCE as "dead", so anyone could requeue the claims of a LIVE worker with a stable name (`claude-alfa-session`)
           out from under it. The naive fix (`pid is None -> continue`), however, opens a hole at the other end:
           the messages of a truly dead claimer with a stable name would be stuck FOREVER — they measured
           this too. So a THIRD STATE, bound to a measurable signal: pid -> session lock -> the claim directory's
           freshness (TTL).
  — the earlier clock fix bounded ONLY the reading side: the RAW caller clock went into the file, so
           the caller's clock still decided life, just for EVERYONE ELSE. A past stamp -> TWO
           `acquired`; a future stamp + a pid-less instance -> an ETERNAL lock. From now on `ts_ns` is the bounded,
           life-deciding value, and the caller's raw stamp stays in the `caller_ts_ns` audit field.

stdlib unittest.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_singleflight as sf  # noqa: E402


class ClaimLiveness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name
        self.inbox = os.path.join(self.bridge, "inbox", "alfa")
        os.makedirs(self.inbox)
        for i in range(1, 4):
            with open(os.path.join(self.inbox, "m00%d.json" % i), "w", encoding="utf-8") as f:
                json.dump({"from": "hub", "to": "alfa", "note": "munka-%d" % i}, f)

    def tearDown(self):
        self.tmp.cleanup()

    def claim(self, instance, *, alive=True, ttl_ns=None):
        # IMPORTANT: the real `_pid_alive` gives FALSE for None — exactly that was the root of the finding. The fixture
        # imitates this (None -> dead), otherwise the probe would be blindly green.
        return sf.MessageClaim("alfa", instance, bridge=self.bridge,
                               is_alive=lambda pid: (pid is not None) and alive, claim_ttl_ns=ttl_ns)

    # ── the claims of a LIVE worker with a stable name cannot be taken ─────────
    def test_live_stable_named_worker_keeps_its_claims(self):
        a = self.claim("claude-alfa-session")
        self.assertEqual(len(a.claim_pending()), 3, "precondition: A grabbed all three")
        b = self.claim("claude-beta-session")
        self.assertEqual(b.requeue_dead(), [], "the claims of a LIVE worker with a stable name were taken from under it")
        self.assertEqual(len(a.claimed_paths()), 3, "A must keep all three")

    # ── the other end: the messages of a truly dead claimer come back ───
    def test_stale_stable_named_claimer_is_released(self):
        a = self.claim("halott-worker")
        a.claim_pending()
        past = time.time() - 7200                              # the claim directory is OLD (2 hours)
        d = os.path.join(self.inbox, ".claimed", "halott-worker")
        for f in os.listdir(d):
            os.utime(os.path.join(d, f), (past, past))
        os.utime(d, (past, past))
        b = self.claim("uj-worker", ttl_ns=3600 * 10 ** 9)
        self.assertEqual(len(b.requeue_dead()), 3,
                         "the messages of a truly dead claimer with a stable name would have been stuck forever")

    # ── control: for a pid-shaped name the pid decides (the old path) ───────────────
    def test_pid_shaped_name_still_uses_the_pid(self):
        a = self.claim("host:%d" % os.getpid())
        a.claim_pending()
        live = self.claim("host:1", alive=True)
        self.assertEqual(live.requeue_dead(), [], "live pid: we do not touch it")
        dead = self.claim("host:1", alive=False)
        self.assertEqual(len(dead.requeue_dead()), 3, "dead pid: back into the queue")

    # ── the WRITING side also uses a bounded clock ────────────────────
    def test_written_timestamp_is_clamped_and_caller_value_is_kept(self):
        lock = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st, holder = lock.acquire("ragadt-worker", now_ns=2 ** 62)
        self.assertEqual(st, "acquired")
        self.assertLess(holder["ts_ns"], time.time_ns() + 10 ** 12,
                        "the caller clock set into the future went into the file -> the lock would live forever")
        self.assertEqual(holder.get("caller_ts_ns"), 2 ** 62, "the caller's raw stamp is kept as audit")

    def test_future_written_lock_does_not_become_eternal(self):
        lock = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        lock.acquire("ragadt-worker", now_ns=2 ** 62)
        later = sf.time.time_ns() + lock.ttl_ns + 10 ** 9
        st, _ = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True).acquire("uj", now_ns=later)
        self.assertEqual(st, "acquired", "a stamp written into the future could never have been aged out")

    def test_past_caller_clock_does_not_yield_two_acquired(self):
        a = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st_a, _ = a.acquire("A:2000", now_ns=int(time.time()))   # a classic unit error: s instead of ns
        b = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st_b, holder = b.acquire("B:2000")
        self.assertFalse(st_a == "acquired" and st_b == "acquired",
                         "TWO 'acquired' for the same identity (A=%s, B=%s)" % (st_a, st_b))


if __name__ == "__main__":
    unittest.main()
