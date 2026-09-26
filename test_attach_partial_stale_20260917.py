"""An orphaned half-finished attachment transfer — (2026-09-17, MEDIUM).

The finding: the half-finished state of `receive_chunk` is addressed only by the content's sha256 (not bound to a sender), the next
chunk's number comes from a shared counter, and there was no way back: no TTL, expiry, or reset/abort API. After a
half-finished state LEFT UNFINISHED (exactly a broken SSH round, which the v1.2 header promises to tolerate)
EVERY later upload of the same content failed with `chunk out of order: expected seq 1, got 0` — the
honest sender could not recover on its own. One arm's clarification: a parallel, interleaved honest
upload DOES RECOVER (the dedupe branch gives success for the closing chunk); the lasting block comes only from the orphaned state.

The fix: a seq-0 chunk restarts the transfer if the half-finished state is ORPHANED (`PARTIAL_STALE_S` of inactivity
since the last chunk). A seq-0 does not sweep away a live transfer (two honest senders do not push each other). No-deletion:
the orphaned work file is moved aside as `.partial.abandoned.<ts>`, and counts towards the quota.

Mutant probe: without the restarting branch `test_stale_partial_is_restarted_by_seq0` fails. stdlib unittest, an isolated store.
"""
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_attach as att  # noqa: E402


class AbandonedPartial(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src = att.Store(os.path.join(self.tmp.name, "src"))
        self.dst = att.Store(os.path.join(self.tmp.name, "dst"))
        self.data = b"z" * (2 * att.CHUNK_BYTES + 17)
        self.desc = self.src.put(self.data)
        self.chunks = list(self.src.chunks(self.desc))
        self.assertEqual(len(self.chunks), 3)

    def tearDown(self):
        self.tmp.cleanup()

    def _meta(self):
        return self.dst._path(self.desc["sha256"]) + ".partial.json"

    def _age(self, seconds):
        old = time.time() - seconds
        os.utime(self._meta(), (old, old))

    def _abandon(self):
        self.assertIsNone(self.dst.receive_chunk(self.desc, self.chunks[0]))      # seq 0 arrived, then nothing

    # ── the finding: an orphaned half-finished state → previously an eternal block ──────────────────────────────
    def test_fresh_partial_is_not_swept_by_a_seq0(self):
        self._abandon()
        with self.assertRaises(att.AttachmentError) as cm:
            self.dst.receive_chunk(self.desc, self.chunks[0])
        self.assertIn("in progress", str(cm.exception))
        self.assertIn("expected seq 1, got 0", str(cm.exception))
        self.assertIn("idle", str(cm.exception))                                 # the way back STATED in the error

    def test_stale_partial_is_restarted_by_seq0(self):
        self._abandon()
        self._age(att.PARTIAL_STALE_S + 1)
        # it failed three times in a row; now the seq-0 restarts, and the whole transfer is STORED
        self.assertIsNone(self.dst.receive_chunk(self.desc, self.chunks[0]))
        self.assertIsNone(self.dst.receive_chunk(self.desc, self.chunks[1]))
        self.assertEqual(self.dst.receive_chunk(self.desc, self.chunks[2]), self.desc)
        self.assertEqual(self.dst.get(self.desc), self.data)

    def test_abandoned_workfile_is_kept_and_counted_not_deleted(self):
        self._abandon()
        self._age(att.PARTIAL_STALE_S + 1)
        self.dst.receive_chunk(self.desc, self.chunks[0])
        d = os.path.dirname(self.dst._path(self.desc["sha256"]))
        names = sorted(os.listdir(d))
        aband = [n for n in names if ".partial.abandoned." in n and not n.endswith(".json") and ".json." not in n]
        self.assertEqual(len(aband), 1, names)
        st = self.dst.work_stats()
        self.assertEqual(st["files"], 2, st)                                     # the orphaned + the live .partial
        self.assertEqual(st["bytes"], 2 * att.CHUNK_BYTES, st)                   # each is one chunk

    def test_control_honest_transfer_and_interleaving_recover(self):
        # the undisturbed path: 3 chunks → STORED (the probe is not blind)
        for c in self.chunks[:2]:
            self.assertIsNone(self.dst.receive_chunk(self.desc, c))
        self.assertEqual(self.dst.receive_chunk(self.desc, self.chunks[2]), self.desc)
        # already present: a second uploader's closing chunk gets success on the dedupe branch
        self.assertEqual(self.dst.receive_chunk(self.desc, self.chunks[2]), self.desc)

    def test_control_exactly_at_threshold_is_still_live(self):
        self._abandon()
        self._age(att.PARTIAL_STALE_S - 5)
        with self.assertRaises(att.AttachmentError):
            self.dst.receive_chunk(self.desc, self.chunks[0])

    def test_env_threshold_cannot_disable_the_protection(self):
        # external validation: env=0 used to disable the protection; now it cannot be taken below the floor (60 s), only above
        import importlib, os
        old = os.environ.get("AGENT_BUS_ATTACH_PARTIAL_STALE_S")
        try:
            for raw, want in (("0", att.PARTIAL_STALE_FLOOR_S), ("-5", att.PARTIAL_STALE_FLOOR_S), ("x", 600),
                              ("59", att.PARTIAL_STALE_FLOOR_S), ("61", 61), ("3600", 3600)):
                os.environ["AGENT_BUS_ATTACH_PARTIAL_STALE_S"] = raw
                self.assertEqual(att._stale_s(), want, raw)
        finally:
            if old is None:
                os.environ.pop("AGENT_BUS_ATTACH_PARTIAL_STALE_S", None)
            else:
                os.environ["AGENT_BUS_ATTACH_PARTIAL_STALE_S"] = old
        self.assertGreaterEqual(att.PARTIAL_STALE_S, att.PARTIAL_STALE_FLOOR_S)



if __name__ == "__main__":
    unittest.main()
