"""An attack on the single-flight lock — our own.

The module's main promise: ONE instance works per agent identity. The non-Claude arm found four ways; two we
close here, two we STATE (because it would change the vendored callers' contract, so it is not a unilateral step):

  CLOSED 1 — an injectable clock: the caller-supplied `now_ns` used to be unbounded, so with an
            `acquire(..., now_ns=2**62)` call anyone could see a LIVE, TTL-based lock as STALE, and
            take it. From now on the clock that decides LIFE accepts only a caller value within 24 hours of reality
            (so simulation still works).
  CLOSED 2 — `heartbeat` and `release` did not take the mutex, only `acquire` did -> wedged between a takeover and a
            heartbeat, two parties could both believe they were "the owner". Now the same serialization.

  STATED 3 — `release` only requires the `instance` STRING to match: whoever reads the lock file can release a LIVE
            owner's lock too. Full closure: a secret token issued at acquire — a MAJOR gate.
  STATED 4 — `target` liveness without `owner_pid`: a lock bound to a live pane is "alive" even if the worker
            died long ago (an availability attack, NOT a duplicate).

stdlib unittest.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_singleflight as sf  # noqa: E402


class LockUnderAttack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def lock(self, alive=True):
        return sf.SessionLock("peer", bridge=self.bridge, is_alive=lambda pid: alive,
                              target_alive=lambda t: True)

    # ── control: the second instance is a duplicate ──────────────────────────────
    def test_control_second_instance_is_duplicate(self):
        self.assertEqual(self.lock().acquire("A", owner_pid=os.getpid())[0], "acquired")
        self.assertEqual(self.lock().acquire("B", owner_pid=os.getpid())[0], "duplicate")

    # ── 1: a caller clock from the future cannot make a live lock stale ──────
    def test_far_future_clock_cannot_steal_a_live_ttl_lock(self):
        st, _ = self.lock().acquire("A")                      # a TTL-based lock (no target, no owner_pid)
        self.assertEqual(st, "acquired")
        st2, holder = self.lock().acquire("B", now_ns=2 ** 62)
        self.assertEqual(st2, "duplicate",
                         "a live lock could be taken with a caller clock set into the future (holder=%r)" % (holder,))

    def test_control_realistic_clock_simulation_still_works(self):
        lk = self.lock()
        st, _ = lk.acquire("A")
        self.assertEqual(st, "acquired")
        later = sf.time.time_ns() + lk.ttl_ns + 10 ** 9        # the TTL really expired (a realistic simulation)
        self.assertEqual(self.lock().acquire("B", now_ns=later)[0], "acquired",
                         "realistic time simulation must still work")

    # ── 2: heartbeat and release are also inside the mutex ──────────────────
    def test_heartbeat_and_release_take_the_mutex(self):
        lk = self.lock()
        lk.acquire("A", owner_pid=os.getpid())
        seen = []
        real = lk._with_mutex

        def spy(fn):
            seen.append(True)
            return real(fn)

        lk._with_mutex = spy
        self.assertTrue(lk.heartbeat("A"))
        self.assertTrue(lk.release("A"))
        self.assertEqual(len(seen), 2, "heartbeat and release did not go through the mutex")

    def test_release_still_refuses_a_foreign_instance(self):
        lk = self.lock()
        lk.acquire("A", owner_pid=os.getpid())
        self.assertFalse(lk.release("B"), "the lock cannot be released with a foreign instance name")
        self.assertTrue(lk.holder(), "the lock stayed")

    # ── 3: a STATED limit — release asks only for a name (a measurement, not an accusation) ─────
    def test_release_only_checks_the_instance_string(self):
        lk = self.lock()
        lk.acquire("A", owner_pid=os.getpid())
        name = lk.holder()["instance"]                         # the lock file is readable
        other = sf.SessionLock("peer", bridge=self.bridge, is_alive=lambda pid: True,
                               target_alive=lambda t: True)
        self.assertTrue(other.release(name),
                        "MEASUREMENT: knowing the name is enough to release today — this is the stated limit")
        self.assertIsNone(lk.holder())


if __name__ == "__main__":
    unittest.main()
