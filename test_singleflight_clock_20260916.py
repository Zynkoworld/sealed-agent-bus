"""A single-flight zár támadása — saját.

A modul fő ígérete: EGY agent-identitásra EGY példány dolgozik. A nem-Claude kar négy utat talált; kettőt
itt zárunk, kettőt KIMONDUNK (mert a vendorolt hívók szerződését változtatná, tehát nem egyoldalú lépés):

  ZÁRVA 1 — injektálható óra: a hívó által adott `now_ns` eddig korlátlan volt, tehát egy
            `acquire(..., now_ns=2**62)` hívással bárki STALE-nek láthatott egy ÉLŐ, TTL-alapú zárat, és
            elvehette. Mostantól az ÉLETRŐL döntő óra csak a valóságtól 24 órán belüli hívói értéket fogadja
            el (a szimuláció így továbbra is működik).
  ZÁRVA 2 — a `heartbeat` és a `release` nem fogta a mutexet, csak az `acquire` -> egy takeover és egy
            heartbeat közé beékelődve két fél is „tulajdonosnak" hihette magát. Most ugyanaz a sorbarendezés.

  KIMONDVA 3 — a `release` csak az `instance` STRING egyezését kéri: aki a lock-fájlt olvassa, egy ÉLŐ
            tulajdonos zárát is elengedheti. Teljes zárás: acquire-kor adott titkos token — MAJOR-kapu.
  KIMONDVA 4 — `target` liveness `owner_pid` nélkül: egy élő panelhez kötött zár akkor is „él", ha a worker
            rég halott (rendelkezésre-állási támadás, NEM duplikátum).

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

    # ── kontroll: a második példány duplikátum ──────────────────────────────
    def test_control_second_instance_is_duplicate(self):
        self.assertEqual(self.lock().acquire("A", owner_pid=os.getpid())[0], "acquired")
        self.assertEqual(self.lock().acquire("B", owner_pid=os.getpid())[0], "duplicate")

    # ── 1: a jövőből érkező hívói óra nem tehet stale-lé egy élő zárat ──────
    def test_far_future_clock_cannot_steal_a_live_ttl_lock(self):
        st, _ = self.lock().acquire("A")                      # TTL-alapú zár (nincs target, nincs owner_pid)
        self.assertEqual(st, "acquired")
        st2, holder = self.lock().acquire("B", now_ns=2 ** 62)
        self.assertEqual(st2, "duplicate",
                         "a jövőbe állított hívói órával elvehető volt egy élő zár (holder=%r)" % (holder,))

    def test_control_realistic_clock_simulation_still_works(self):
        lk = self.lock()
        st, _ = lk.acquire("A")
        self.assertEqual(st, "acquired")
        later = sf.time.time_ns() + lk.ttl_ns + 10 ** 9        # a TTL tényleg letelt (valósághű szimuláció)
        self.assertEqual(self.lock().acquire("B", now_ns=later)[0], "acquired",
                         "a valósághű idő-szimulációnak továbbra is működnie kell")

    # ── 2: a heartbeat és a release is a mutexen belül van ──────────────────
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
        self.assertEqual(len(seen), 2, "a heartbeat és a release nem ment át a mutexen")

    def test_release_still_refuses_a_foreign_instance(self):
        lk = self.lock()
        lk.acquire("A", owner_pid=os.getpid())
        self.assertFalse(lk.release("B"), "idegen instance-névvel nem engedhető el a zár")
        self.assertTrue(lk.holder(), "a zár megmaradt")

    # ── 3: KIMONDOTT korlát — a release csak nevet kér (mérés, nem vád) ─────
    def test_release_only_checks_the_instance_string(self):
        lk = self.lock()
        lk.acquire("A", owner_pid=os.getpid())
        name = lk.holder()["instance"]                         # a lock-fájl olvasható
        other = sf.SessionLock("peer", bridge=self.bridge, is_alive=lambda pid: True,
                               target_alive=lambda t: True)
        self.assertTrue(other.release(name),
                        "MÉRÉS: a név ismerete ma elég az elengedéshez — ez a kimondott korlát")
        self.assertIsNone(lk.holder())


if __name__ == "__main__":
    unittest.main()
