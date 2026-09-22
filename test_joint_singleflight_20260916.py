# -*- coding: utf-8 -*-
"""Joint-szonda a 0ffe5d2 (single-flight) körhöz — 2026-09-16.

Két állítást mér, mindkettő a modul SAJÁT, kimondott ígéretére:
  1. `MessageClaim`: "a párhuzamos vesztes kihagyja" — egy ÉLŐ worker claimjeit
     nem szabad kirequeue-olni alóla. A `B1`-ben a `SessionLock` oldalán már
     javítva lett a pid-nélküli instance esete; a `MessageClaim` oldalán nem.
  2. `SessionLock.acquire`: a `0ffe5d2` az ÉLETRŐL döntő órát 24 órára korlátozta —
     de a fájlba a KORLÁTOZATLAN hívói órát írja, így a hívói óra továbbra is
     életről dönt, csak egy lépéssel később, MINDENKI MÁS számára.
"""
import os
import tempfile
import time
import unittest

import bus_singleflight as sf


class ClaimStealFromLiveWorker(unittest.TestCase):
    """A dokumentált `--instance` / `AGENT_BUS_INSTANCE` stabil névvel a claim elvehető."""

    def setUp(self):
        self.bridge = tempfile.mkdtemp(prefix="peer-sf-claim-")
        self.inbox = os.path.join(self.bridge, "inbox", "alfa")
        os.makedirs(self.inbox)
        for n in ("001", "002", "003"):
            with open(os.path.join(self.inbox, "m%s.json" % n), "w") as f:
                f.write('{"id":"%s"}' % n)

    def _claim(self, instance):
        mc = sf.MessageClaim("alfa", instance, bridge=self.bridge)
        mc.requeue_dead()
        return mc, mc.claim_pending()

    def test_live_worker_with_stable_name_keeps_its_claims(self):
        a, won_a = self._claim("alfa-worker-1")          # stabil, nem pid-alakú név
        self.assertEqual(len(won_a), 3, "A-nak mind a 3-at el kell nyernie")
        b, won_b = self._claim("alfa-worker-2")          # másik példány indul
        self.assertEqual(won_b, [], "B nem nyerhet el semmit egy ÉLŐ A mellől; kapott: %r" % won_b)
        self.assertEqual(len(a.claimed_paths()), 3, "A claimjei eltűntek alóla")

    def test_requeue_dead_must_not_touch_a_live_stable_named_claimer(self):
        a, _ = self._claim("claude-alfa-session")
        other = sf.MessageClaim("alfa", "host:1", bridge=self.bridge)   # pid 1 él
        self.assertEqual(other.requeue_dead(), [],
                         "egy idegen requeue-dead elvette az ÉLŐ A claimjeit")

    def test_control_pid_shaped_name_is_protected(self):
        """Kontroll: ugyanez PID-alakú névvel MA IS helyes (a szonda nem vakon piros)."""
        a, won_a = self._claim("host:%d" % os.getpid())
        self.assertEqual(len(won_a), 3)
        other = sf.MessageClaim("alfa", "host:1", bridge=self.bridge)
        self.assertEqual(other.requeue_dead(), [])
        self.assertEqual(len(a.claimed_paths()), 3)


class CallerClockIsWrittenUnclamped(unittest.TestCase):
    """A 0ffe5d2 az OLVASÓ oldalt korlátozta; az ÍRÓ oldalt nem."""

    def setUp(self):
        self.bridge = tempfile.mkdtemp(prefix="peer-sf-clock-")
        self.real = time.time_ns()

    def _lock(self, **kw):
        return sf.SessionLock("alfa", bridge=self.bridge, **kw)

    def test_past_caller_clock_must_not_produce_two_acquired(self):
        """Egység-hiba (time.time() ns helyett) → a zár azonnal stale mindenki másnak."""
        a = self._lock(is_alive=lambda p: True)
        st_a, _ = a.acquire("A:1000", now_ns=int(time.time()))   # másodperc, nem ns
        b = self._lock(is_alive=lambda p: True)
        st_b, _ = b.acquire("B:2000")                            # helyes, valós óra
        self.assertFalse(st_a == "acquired" and st_b == "acquired",
                         "két 'acquired' ugyanarra az agent-identitásra (A=%s, B=%s)" % (st_a, st_b))

    def test_future_caller_clock_must_not_make_the_lock_immortal(self):
        """Jövőbeli hívói óra + pid-nélküli instance → a zár sosem jár le."""
        far = self.real + 3650 * 24 * 3600 * 10 ** 9
        c = self._lock(is_alive=lambda p: False)
        self.assertEqual(c.acquire("ragadt-worker", now_ns=far)[0], "acquired")
        d = self._lock(is_alive=lambda p: False)
        st, _ = d.acquire("mas-worker", now_ns=self.real + 10 * sf._LIVENESS_TTL_NS)
        self.assertEqual(st, "acquired",
                         "a 10*TTL-lel későbbi hívó sem tudja visszaigényelni a zárat (%s)" % st)

    def test_control_real_clock_reclaim_still_works(self):
        """Kontroll: valós órával írt zárat a TTL után vissza LEHET igényelni."""
        j = self._lock(is_alive=lambda p: False)
        self.assertEqual(j.acquire("ragadt-worker", now_ns=self.real)[0], "acquired")
        k = self._lock(is_alive=lambda p: False)
        self.assertEqual(k.acquire("mas-worker", now_ns=self.real + 10 * sf._LIVENESS_TTL_NS)[0],
                         "acquired")


if __name__ == "__main__":
    unittest.main()
