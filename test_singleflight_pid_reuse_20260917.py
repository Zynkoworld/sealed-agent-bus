"""The pid branch's protection against pid reassignment — (2026-09-17, low-medium, latent).

The finding: the module header promised "pid liveness + TTL" against pid reuse, but the pid branch of `_holder_alive`
returned the value of `is_alive` immediately, with no TTL or anything else. The owner died, its
pid was reassigned → the other instance still gets `duplicate` TEN YEARS later, the lock is ETERNAL. Control: the ttl branch
gives `acquired` after 90 s in the same situation (the probe discriminates).

The fix is NOT a TTL (a clock must not expire a long-lived owner pid's lock), but the PROCESS IDENTITY: acquire
stores the pid's birth (`/proc/<pid>/stat` starttime, `pid_birth`), and the owner is alive only if a process of THE SAME
birth is alive. Stated fallbacks (an old record without a birth; an unmeasurable birth) → the bare pid liveness signal.

Mutant probe: without the birth comparison in `_same_process_alive`, `test_A_pid_branch_reused_pid_is_stale` and
`test_target_owner_branch_reused_pid_is_stale` fail; the rest are controls.

stdlib unittest; an isolated /tmp bridge, it does not touch the live wake directory.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_singleflight as sf  # noqa: E402

TEN_YEARS_NS = 10 * 365 * 24 * 3600 * 10 ** 9
OWNER = 4242


class PidReuse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def lock(self, *, birth, alive=True, target_alive=True):
        """`birth`: pid → birth (int | None) — the value measured NOW. `alive`: everyone is alive (the pid is reassigned)."""
        return sf.SessionLock("peer", bridge=self.bridge, is_alive=lambda pid: alive,
                              target_alive=lambda t: target_alive, pid_birth=lambda pid: birth)

    def holder(self):
        return json.load(open(os.path.join(self.bridge, "wake", "peer.session.lock"), encoding="utf-8"))

    # ── one arm's A: pid branch, the owner died, its pid was reassigned ─────────────────────────
    def test_A_pid_branch_reused_pid_is_stale(self):
        st, me = self.lock(birth=100).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertEqual(me["liveness"], "pid")
        self.assertEqual(me["pid_birth"], 100)
        # another process sits on the pid (birth 200), `is_alive` is still True → the lock is STALE, can be taken
        st, _ = self.lock(birth=200).acquire("B", owner_pid=OWNER, now_ns=sf.time.time_ns() + TEN_YEARS_NS)
        self.assertEqual(st, "acquired")

    def test_control_same_process_stays_owner_forever_no_ttl(self):
        # the same birth → duplicate, even ten years later: the pid branch has NO TTL, and that is correct
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        st, cur = self.lock(birth=100).acquire("B", owner_pid=OWNER, now_ns=sf.time.time_ns() + TEN_YEARS_NS)
        self.assertEqual(st, "duplicate")
        self.assertEqual(cur["instance"], "A")

    def test_control_C_dead_pid_is_refused_at_acquire(self):
        # one arm's C: the pid is REALLY dead → owner-not-live, the lock is not even written (the B1var-2 gate unchanged)
        st, _ = self.lock(birth=100, alive=False).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "owner-not-live")
        self.assertFalse(os.path.exists(os.path.join(self.bridge, "wake", "peer.session.lock")))

    # ── the same class on the target+owner branch ────────────────────────────────────────────
    def test_target_owner_branch_reused_pid_is_stale(self):
        st, me = self.lock(birth=100).acquire("A", target="peer:0.0", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertEqual((me["liveness"], me["pid_src"], me["pid_birth"]), ("target", "owner", 100))
        st, _ = self.lock(birth=200).acquire("B", target="peer:0.0", owner_pid=OWNER)
        self.assertEqual(st, "acquired")

    def test_control_target_owner_same_process_is_duplicate(self):
        self.assertEqual(self.lock(birth=100).acquire("A", target="peer:0.0", owner_pid=OWNER)[0], "acquired")
        self.assertEqual(self.lock(birth=100).acquire("B", target="peer:0.0", owner_pid=OWNER)[0], "duplicate")

    # ── stated fallbacks ─────────────────────────────────────────────────────────────────────
    def _legacy_record(self, ts_ns):
        os.makedirs(os.path.join(self.bridge, "wake"), exist_ok=True)
        with open(os.path.join(self.bridge, "wake", "peer.session.lock"), "w", encoding="utf-8") as f:
            json.dump({"instance": "A", "pid": OWNER, "target": None, "ts_ns": ts_ns, "liveness": "pid",
                       "pid_src": "owner"}, f)

    def test_old_record_without_birth_falls_back_to_pid_liveness_within_grace(self):
        self._legacy_record(sf.time.time_ns())
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER)[0], "duplicate")
        self.assertEqual(self.lock(birth=200, alive=False).acquire("B", owner_pid=OWNER)[0], "owner-not-live")

    def test_deleted_birth_field_does_not_give_an_eternal_lock(self):
        # a pid_birth deleted from a writable record → previously duplicate even after ten years. Now the
        # fallback lasts until LEGACY_GRACE_NS from the record's ts_ns, after that the lock is stale — even if "something is alive" on the pid.
        t0 = sf.time.time_ns()
        self._legacy_record(t0)
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER,
                                                      now_ns=t0 + sf.LEGACY_GRACE_NS // 2)[0], "duplicate")
        # the deciding clock can be moved at most 24 hours from reality, so we measure the expiry by AGEING the record
        self._legacy_record(t0 - sf.LEGACY_GRACE_NS - 1)
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER)[0], "acquired")

    def test_owner_heartbeat_restores_a_missing_birth(self):
        self._legacy_record(sf.time.time_ns())
        self.assertTrue(self.lock(birth=100).heartbeat("A"))
        self.assertEqual(self.holder()["pid_birth"], 100)                    # filled in → from now on identity protects it
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER)[0], "acquired")   # another process: stale
        self.assertEqual(self.lock(birth=200).acquire("C", owner_pid=OWNER)[0], "duplicate")  # B's record is alive (200)

    def test_unmeasurable_birth_now_falls_back_to_pid_liveness(self):
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        self.assertEqual(self.lock(birth=None).acquire("B", owner_pid=OWNER)[0], "duplicate")

    def test_unmeasurable_birth_at_acquire_is_stored_as_null_and_stated(self):
        st, me = self.lock(birth=None).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertIsNone(me["pid_birth"])

    # ── the birth survives the heartbeat and a bare re-acquire ───────────────────────────
    def test_heartbeat_and_reacquire_keep_the_birth(self):
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        self.assertTrue(self.lock(birth=999).heartbeat("A"))          # a bare heartbeat: does not re-measure
        self.assertEqual(self.holder()["pid_birth"], 100)
        st, me = self.lock(birth=999).acquire("A")                     # a bare re-acquire: already-own
        self.assertEqual(st, "already-own")
        self.assertEqual(me["pid_birth"], 100)
        self.assertEqual(me["liveness"], "pid")

    # ── the real meter: /proc ─────────────────────────────────────────────────────────────────
    def test_real_birth_is_measured_and_stable_for_this_process(self):
        if not os.path.exists("/proc/self/stat"):
            self.skipTest("no /proc")
        b1, b2 = sf._pid_birth(os.getpid()), sf._pid_birth(os.getpid())
        self.assertIsInstance(b1, int)
        self.assertEqual(b1, b2)
        self.assertIsNone(sf._pid_birth(0))
        self.assertIsNone(sf._pid_birth("x"))
        self.assertIsNone(sf._pid_birth(2 ** 31 - 1))               # no such process


if __name__ == "__main__":
    unittest.main()
