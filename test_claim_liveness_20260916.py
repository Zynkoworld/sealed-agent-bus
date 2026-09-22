"""A claim-oldali életjel és a hívói óra ÍRÓ oldala — (2026-09-16 délután) + saját mérés.

Két HIGH az ő köréből, mindkettő mérve és javítva:

  — `MessageClaim.requeue_dead`: a `pid_of(inst) -> is_alive(None) -> False` lánc a BIZONYÍTÉK
           HIÁNYÁT „halott"-nak vette, tehát egy ÉLŐ, stabil nevű worker (`claude-alfa-session`) claimjeit
           bárki kirequeue-olhatta alóla. A naiv javítás (`pid is None -> continue`) viszont a másik végén
           nyit lyukat: a valóban halott, stabil nevű claimer üzenetei ÖRÖKRE bent ragadnának — ezt ők is
           megmérték. Ezért HARMADIK ÁLLAPOT, mérhető jelhez kötve: pid -> session-lock -> a claim-könyvtár
           frissessége (TTL).
  — a korábbi óra-javítás CSAK az olvasó oldalt korlátozta: a fájlba a NYERS hívói óra került, tehát
           a hívó órája továbbra is életről döntött, csak mindenki MÁS számára. Múltbeli bélyeg -> KÉT
           `acquired`; jövőbeli bélyeg + pid nélküli instance -> ÖRÖK zár. Mostantól a `ts_ns` a korlátozott,
           életről döntő érték, a hívó nyers bélyege pedig `caller_ts_ns` audit-mezőben marad.

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
        # FONTOS: a valódi `_pid_alive` a None-ra FALSE-t ad — épp ez volt a lelet gyökere. A fixture ezt
        # utánozza (None -> halott), különben a szonda vakon zöld lenne.
        return sf.MessageClaim("alfa", instance, bridge=self.bridge,
                               is_alive=lambda pid: (pid is not None) and alive, claim_ttl_ns=ttl_ns)

    # ── ÉLŐ, stabil nevű worker claimjeit nem lehet elvenni ─────────
    def test_live_stable_named_worker_keeps_its_claims(self):
        a = self.claim("claude-alfa-session")
        self.assertEqual(len(a.claim_pending()), 3, "előfeltétel: A megfogta mind a hármat")
        b = self.claim("claude-beta-session")
        self.assertEqual(b.requeue_dead(), [], "egy ÉLŐ, stabil nevű worker claimjeit elvették alóla")
        self.assertEqual(len(a.claimed_paths()), 3, "A-nál maradnia kell mind a háromnak")

    # ── másik vége: a valóban halott claimer üzenetei visszajönnek ───
    def test_stale_stable_named_claimer_is_released(self):
        a = self.claim("halott-worker")
        a.claim_pending()
        past = time.time() - 7200                              # a claim-könyvtár RÉGI (2 óra)
        d = os.path.join(self.inbox, ".claimed", "halott-worker")
        for f in os.listdir(d):
            os.utime(os.path.join(d, f), (past, past))
        os.utime(d, (past, past))
        b = self.claim("uj-worker", ttl_ns=3600 * 10 ** 9)
        self.assertEqual(len(b.requeue_dead()), 3,
                         "a valóban halott, stabil nevű claimer üzenetei örökre bent ragadtak volna")

    # ── kontroll: pid-alakú név esetén a pid dönt (a régi út) ───────────────
    def test_pid_shaped_name_still_uses_the_pid(self):
        a = self.claim("host:%d" % os.getpid())
        a.claim_pending()
        live = self.claim("host:1", alive=True)
        self.assertEqual(live.requeue_dead(), [], "élő pid: nem nyúlunk hozzá")
        dead = self.claim("host:1", alive=False)
        self.assertEqual(len(dead.requeue_dead()), 3, "halott pid: vissza a sorba")

    # ── az ÍRÓ oldal is korlátozott órát használ ────────────────────
    def test_written_timestamp_is_clamped_and_caller_value_is_kept(self):
        lock = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st, holder = lock.acquire("ragadt-worker", now_ns=2 ** 62)
        self.assertEqual(st, "acquired")
        self.assertLess(holder["ts_ns"], time.time_ns() + 10 ** 12,
                        "a jövőbe állított hívói óra bekerült a fájlba -> a zár örökké élne")
        self.assertEqual(holder.get("caller_ts_ns"), 2 ** 62, "a hívó nyers bélyege auditként megmarad")

    def test_future_written_lock_does_not_become_eternal(self):
        lock = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        lock.acquire("ragadt-worker", now_ns=2 ** 62)
        later = sf.time.time_ns() + lock.ttl_ns + 10 ** 9
        st, _ = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True).acquire("uj", now_ns=later)
        self.assertEqual(st, "acquired", "a jövőbe írt bélyeget sosem lehetett volna kiöregíteni")

    def test_past_caller_clock_does_not_yield_two_acquired(self):
        a = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st_a, _ = a.acquire("A:2000", now_ns=int(time.time()))   # klasszikus egység-hiba: s a ns helyett
        b = sf.SessionLock("alfa", bridge=self.bridge, is_alive=lambda pid: True)
        st_b, holder = b.acquire("B:2000")
        self.assertFalse(st_a == "acquired" and st_b == "acquired",
                         "KÉT 'acquired' ugyanarra az identitásra (A=%s, B=%s)" % (st_a, st_b))


if __name__ == "__main__":
    unittest.main()
