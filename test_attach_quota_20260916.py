"""A csatolmány-tár munkafájl-kvótája — saját.

A tár SOSEM töröl: a félbehagyott `.partial` és a hash-hibás `.rejected.*` munkafájlok szándékosan
megmaradnak (vizsgálatra, a no-deletion elv miatt). A nem-Claude kar erre mutatott rá: egy
rosszindulatú küldő ismételt, félbehagyott vagy hash-hibás átvitellel **korlátlanul** fogyaszthatja
a lemezt — a limit csak EGY csatolmány méretét fogta, a felhalmozódást nem.

Javítás a ház szabálya szerint (semmit nem törlünk, inkább bezárjuk a kaput): kvóta a
munkafájlokra. Fölötte **új** átvitel nem indul (fail-closed), a futóban lévő befejezhető, és a
takarítás operátori döntés marad — a `work_stats()` megmutatja, mi fekszik ott.

stdlib unittest.
"""
import base64
import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_attach as at  # noqa: E402


class AttachmentWorkQuota(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = at.Store(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def desc(self, payload: bytes, name="a.bin"):   # a `name` csak olvashatóság, a leíró zárt szerkezetű
        return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                "media_type": "application/octet-stream",
                "locator": "sha256:" + hashlib.sha256(payload).hexdigest()}

    def chunk(self, d, payload, seq=0, last=True):
        return {"sha256": d["sha256"], "seq": seq, "last": last,
                "data": base64.b64encode(payload).decode()}

    # ── kontroll: a rendes átvitel megy ─────────────────────────────────────
    def test_control_normal_transfer_completes(self):
        p = b"szia" * 10
        d = self.desc(p)
        self.assertEqual(self.store.receive_chunk(d, self.chunk(d, p))["sha256"], d["sha256"])
        self.assertTrue(self.store.has(d))
        self.assertEqual(self.store.work_stats()["bytes"], 0, "sikeres átvitel után nem marad munkafájl")

    # ── a félbehagyott átvitel munkafájlt hagy, és ezt MEGMUTATJUK ───────────
    def test_abandoned_partial_is_visible(self):
        p = b"x" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:50], seq=0, last=False))     # félbehagyva
        st = self.store.work_stats()
        self.assertEqual(st["bytes"], 50)
        self.assertEqual(st["files"], 1)

    # ── a hash-hibás átvitel `.rejected` fájlt hagy ─────────────────────────
    def test_rejected_transfer_is_kept_but_counted(self):
        p = b"y" * 40
        d = self.desc(p)
        with self.assertRaises(at.AttachmentError):
            self.store.receive_chunk(d, self.chunk(d, b"z" * 40))                 # jó méret, ROSSZ tartalom
        self.assertGreaterEqual(self.store.work_stats()["bytes"], 40, "a bűnjel megmarad")

    # ── LELET: a felhalmozódás ellen kvóta — ÚJ átvitel nem indul fölötte ────
    def test_quota_blocks_a_new_transfer(self):
        p = b"q" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:60], seq=0, last=False))     # 60 bájt munkafájl
        p2 = b"w" * 100
        d2 = self.desc(p2, name="b.bin")
        with mock.patch.object(at, "MAX_WORK_BYTES", 100):
            with self.assertRaises(at.AttachmentError) as cm:
                self.store.receive_chunk(d2, self.chunk(d2, p2))
            self.assertIn("work quota", str(cm.exception))

    # ── a FUTÓ átvitel viszont befejezhető a kvóta fölött is ────────────────
    def test_running_transfer_may_finish_above_the_quota(self):
        p = b"r" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:60], seq=0, last=False))
        with mock.patch.object(at, "MAX_WORK_BYTES", 1):
            done = self.store.receive_chunk(d, self.chunk(d, p[60:], seq=1, last=True))
        self.assertEqual(done["sha256"], d["sha256"], "a már futó átvitelt a kvóta nem szakíthatja félbe")

    # ── MEGCÁFOLT lelet: a hazug `last` nem ad hamis „kész" jelzést ──────────
    def test_lying_last_flag_does_not_fake_completion(self):
        p = b"s" * 80
        d = self.desc(p)
        with self.assertRaises(at.AttachmentError):
            self.store.receive_chunk(d, self.chunk(d, p[:40], seq=0, last=True))  # „kész", de hiányos
        self.assertFalse(self.store.has(d), "hiányos tartalom nem kerülhet a tárba")


if __name__ == "__main__":
    unittest.main()
