"""A pid-ág pid-újrakiosztás elleni védelme — (2026-09-17, alacsony-közepes, latens).

A lelet: a modul fejléce „pid-liveness + TTL"-t ígért a pid-újrahasznosítás ellen, a `_holder_alive` pid-ága
viszont azonnal az `is_alive` értékével tért vissza, TTL és bármi más nélkül. az owner meghalt, a
pid-jét újrakiosztották → a másik példány TÍZ ÉVVEL később is `duplicate`-et kap, a zár ÖRÖK. Kontroll: a ttl-ág
ugyanerre a helyzetre 90 s után `acquired`-et ad (a szonda diszkriminál).

A javítás NEM TTL (egy tartós owner-pid zárját egy óra nem járathatja le), hanem a FOLYAMAT IDENTITÁSA: az acquire
eltárolja a pid születését (`/proc/<pid>/stat` starttime, `pid_birth`), és a tulajdonos csak akkor él, ha UGYANAZ a
születésű folyamat él. Kimondott visszaesések (régi rekord születés nélkül; nem mérhető születés) → puszta pid-életjel.

Mutáns-próba: a `_same_process_alive` születés-összevetése nélkül `test_A_pid_branch_reused_pid_is_stale` és
`test_target_owner_branch_reused_pid_is_stale` bukik; a többi kontroll.

stdlib unittest; izolált /tmp bridge, az éles wake könyvtárat nem érinti.
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
        """`birth`: pid → születés (int | None) — a MOST mért érték. `alive`: mindenki él (a pid újra ki van osztva)."""
        return sf.SessionLock("peer", bridge=self.bridge, is_alive=lambda pid: alive,
                              target_alive=lambda t: target_alive, pid_birth=lambda pid: birth)

    def holder(self):
        return json.load(open(os.path.join(self.bridge, "wake", "peer.session.lock"), encoding="utf-8"))

    # ── az egyik kar A: pid-ág, az owner meghalt, a pid-jét újrakiosztották ─────────────────────────
    def test_A_pid_branch_reused_pid_is_stale(self):
        st, me = self.lock(birth=100).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertEqual(me["liveness"], "pid")
        self.assertEqual(me["pid_birth"], 100)
        # más folyamat ül a pid-en (születés 200), az `is_alive` továbbra is True → a zár STALE, elvihető
        st, _ = self.lock(birth=200).acquire("B", owner_pid=OWNER, now_ns=sf.time.time_ns() + TEN_YEARS_NS)
        self.assertEqual(st, "acquired")

    def test_control_same_process_stays_owner_forever_no_ttl(self):
        # ugyanaz a születés → duplicate, tíz évvel később is: a pid-ágon NINCS TTL, és ez helyes
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        st, cur = self.lock(birth=100).acquire("B", owner_pid=OWNER, now_ns=sf.time.time_ns() + TEN_YEARS_NS)
        self.assertEqual(st, "duplicate")
        self.assertEqual(cur["instance"], "A")

    def test_control_C_dead_pid_is_refused_at_acquire(self):
        # az egyik kar C: a pid TÉNYLEG halott → owner-not-live, a zár meg sem íródik (B1var-2 kapu változatlan)
        st, _ = self.lock(birth=100, alive=False).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "owner-not-live")
        self.assertFalse(os.path.exists(os.path.join(self.bridge, "wake", "peer.session.lock")))

    # ── ugyanaz az osztály a target+owner ágon ────────────────────────────────────────────────
    def test_target_owner_branch_reused_pid_is_stale(self):
        st, me = self.lock(birth=100).acquire("A", target="peer:0.0", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertEqual((me["liveness"], me["pid_src"], me["pid_birth"]), ("target", "owner", 100))
        st, _ = self.lock(birth=200).acquire("B", target="peer:0.0", owner_pid=OWNER)
        self.assertEqual(st, "acquired")

    def test_control_target_owner_same_process_is_duplicate(self):
        self.assertEqual(self.lock(birth=100).acquire("A", target="peer:0.0", owner_pid=OWNER)[0], "acquired")
        self.assertEqual(self.lock(birth=100).acquire("B", target="peer:0.0", owner_pid=OWNER)[0], "duplicate")

    # ── kimondott visszaesések ────────────────────────────────────────────────────────────────
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
        # egy írható rekordból kitörölt pid_birth → korábban tíz év után is duplicate. Most a
        # visszaesés LEGACY_GRACE_NS-ig tart a rekord ts_ns-étől, utána a zár stale — akkor is, ha „valami él" a pid-en.
        t0 = sf.time.time_ns()
        self._legacy_record(t0)
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER,
                                                      now_ns=t0 + sf.LEGACY_GRACE_NS // 2)[0], "duplicate")
        # a döntő óra a valóságtól legfeljebb 24 órára vihető, ezért a lejáratot a rekord KOROSÍTÁSÁVAL mérjük
        self._legacy_record(t0 - sf.LEGACY_GRACE_NS - 1)
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER)[0], "acquired")

    def test_owner_heartbeat_restores_a_missing_birth(self):
        self._legacy_record(sf.time.time_ns())
        self.assertTrue(self.lock(birth=100).heartbeat("A"))
        self.assertEqual(self.holder()["pid_birth"], 100)                    # pótolva → innentől identitás védi
        self.assertEqual(self.lock(birth=200).acquire("B", owner_pid=OWNER)[0], "acquired")   # más folyamat: stale
        self.assertEqual(self.lock(birth=200).acquire("C", owner_pid=OWNER)[0], "duplicate")  # B rekordja él (200)

    def test_unmeasurable_birth_now_falls_back_to_pid_liveness(self):
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        self.assertEqual(self.lock(birth=None).acquire("B", owner_pid=OWNER)[0], "duplicate")

    def test_unmeasurable_birth_at_acquire_is_stored_as_null_and_stated(self):
        st, me = self.lock(birth=None).acquire("A", owner_pid=OWNER)
        self.assertEqual(st, "acquired")
        self.assertIsNone(me["pid_birth"])

    # ── a születés túléli a heartbeatet és a csupasz újra-acquire-t ───────────────────────────
    def test_heartbeat_and_reacquire_keep_the_birth(self):
        self.assertEqual(self.lock(birth=100).acquire("A", owner_pid=OWNER)[0], "acquired")
        self.assertTrue(self.lock(birth=999).heartbeat("A"))          # csupasz heartbeat: nem mér újra
        self.assertEqual(self.holder()["pid_birth"], 100)
        st, me = self.lock(birth=999).acquire("A")                     # csupasz újra-acquire: already-own
        self.assertEqual(st, "already-own")
        self.assertEqual(me["pid_birth"], 100)
        self.assertEqual(me["liveness"], "pid")

    # ── a valódi mérő: /proc ──────────────────────────────────────────────────────────────────
    def test_real_birth_is_measured_and_stable_for_this_process(self):
        if not os.path.exists("/proc/self/stat"):
            self.skipTest("nincs /proc")
        b1, b2 = sf._pid_birth(os.getpid()), sf._pid_birth(os.getpid())
        self.assertIsInstance(b1, int)
        self.assertEqual(b1, b2)
        self.assertIsNone(sf._pid_birth(0))
        self.assertIsNone(sf._pid_birth("x"))
        self.assertIsNone(sf._pid_birth(2 ** 31 - 1))               # nincs ilyen folyamat


if __name__ == "__main__":
    unittest.main()
