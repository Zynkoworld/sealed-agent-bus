"""The attachment store's work-file quota — our own.

The store NEVER deletes: the abandoned `.partial` and the hash-failed `.rejected.*` work files deliberately
remain (for inspection, because of the no-deletion principle). The non-Claude arm pointed out: a
malicious sender could consume the disk **without limit** through repeated abandoned or hash-failed
transfers — the limit only caught the size of ONE attachment, not the accumulation.

Fix per the house rule (we delete nothing, we would rather close the gate): a quota on the
work files. Above it no **new** transfer starts (fail-closed), the one in progress can finish, and
cleanup stays an operator decision — `work_stats()` shows what lies there.

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

    def desc(self, payload: bytes, name="a.bin"):   # `name` is only for readability, the descriptor has a closed structure
        return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                "media_type": "application/octet-stream",
                "locator": "sha256:" + hashlib.sha256(payload).hexdigest()}

    def chunk(self, d, payload, seq=0, last=True):
        return {"sha256": d["sha256"], "seq": seq, "last": last,
                "data": base64.b64encode(payload).decode()}

    # ── control: a normal transfer works ─────────────────────────────────────
    def test_control_normal_transfer_completes(self):
        p = b"szia" * 10
        d = self.desc(p)
        self.assertEqual(self.store.receive_chunk(d, self.chunk(d, p))["sha256"], d["sha256"])
        self.assertTrue(self.store.has(d))
        self.assertEqual(self.store.work_stats()["bytes"], 0, "no work file remains after a successful transfer")

    # ── an abandoned transfer leaves a work file, and we SHOW it ───────────
    def test_abandoned_partial_is_visible(self):
        p = b"x" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:50], seq=0, last=False))     # abandoned
        st = self.store.work_stats()
        self.assertEqual(st["bytes"], 50)
        self.assertEqual(st["files"], 1)

    # ── a hash-failed transfer leaves a `.rejected` file ─────────────────────────
    def test_rejected_transfer_is_kept_but_counted(self):
        p = b"y" * 40
        d = self.desc(p)
        with self.assertRaises(at.AttachmentError):
            self.store.receive_chunk(d, self.chunk(d, b"z" * 40))                 # right size, WRONG content
        self.assertGreaterEqual(self.store.work_stats()["bytes"], 40, "the evidence stays")

    # ── FINDING: a quota against accumulation — NO NEW transfer starts above it ────
    def test_quota_blocks_a_new_transfer(self):
        p = b"q" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:60], seq=0, last=False))     # 60-byte work file
        p2 = b"w" * 100
        d2 = self.desc(p2, name="b.bin")
        with mock.patch.object(at, "MAX_WORK_BYTES", 100):
            with self.assertRaises(at.AttachmentError) as cm:
                self.store.receive_chunk(d2, self.chunk(d2, p2))
            self.assertIn("work quota", str(cm.exception))

    # ── the RUNNING transfer, however, can finish even above the quota ────────────────
    def test_running_transfer_may_finish_above_the_quota(self):
        p = b"r" * 100
        d = self.desc(p)
        self.store.receive_chunk(d, self.chunk(d, p[:60], seq=0, last=False))
        with mock.patch.object(at, "MAX_WORK_BYTES", 1):
            done = self.store.receive_chunk(d, self.chunk(d, p[60:], seq=1, last=True))
        self.assertEqual(done["sha256"], d["sha256"], "the quota cannot interrupt an already running transfer")

    # ── REFUTED finding: a lying `last` does not give a false "done" signal ──────────
    def test_lying_last_flag_does_not_fake_completion(self):
        p = b"s" * 80
        d = self.desc(p)
        with self.assertRaises(at.AttachmentError):
            self.store.receive_chunk(d, self.chunk(d, p[:40], seq=0, last=True))  # "done", but incomplete
        self.assertFalse(self.store.has(d), "incomplete content cannot enter the store")


if __name__ == "__main__":
    unittest.main()
