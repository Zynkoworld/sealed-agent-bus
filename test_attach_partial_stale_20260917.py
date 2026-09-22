"""Elárvult félkész csatolmány-átvitel — (2026-09-17, KÖZEPES).

A lelet: a `receive_chunk` félkész állapotát csak a tartalom sha256-a címzi (feladóhoz nem kötött), a következő
darab sorszámát egy közös számláló adja, és nem volt belőle visszaút: TTL, lejárat, reset/abort API egyik sem. Egy
BEFEJEZETLENÜL hagyott félkész állapot (pont egy megszakadt SSH-kör, amit a v1.2 fejléce elviselni ígér) után
ugyanannak a tartalomnak MINDEN későbbi feltöltése `chunk out of order: expected seq 1, got 0`-val bukott — a
becsületes feladó önerőből nem tudott visszaállni. az egyik kar pontosítása: a párhuzamos, egymásba fonódó becsületes
feltöltés HELYREÁLL (a dedupe-ág a lezáró darabra sikert ad); a tartós blokk kizárólag az elárvult állapotból jön.

A javítás: egy seq-0 darab újraindítja az átvitelt, ha a félkész állapot ELÁRVULT (az utolsó darab óta
`PARTIAL_STALE_S` tétlenség). Élő átvitelt seq-0 nem söpör el (két becsületes feladó nem lökdösi egymást). No-deletion:
az elárvult munkafájl `.partial.abandoned.<ts>` néven félre kerül, és a kvótába beleszámít.

Mutáns-próba: az újraindító ág nélkül `test_stale_partial_is_restarted_by_seq0` bukik. stdlib unittest, izolált tár.
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
        self.assertIsNone(self.dst.receive_chunk(self.desc, self.chunks[0]))      # seq 0 megjött, aztán semmi

    # ── a lelet: elárvult félkész állapot → korábban örök blokk ──────────────────────────────
    def test_fresh_partial_is_not_swept_by_a_seq0(self):
        self._abandon()
        with self.assertRaises(att.AttachmentError) as cm:
            self.dst.receive_chunk(self.desc, self.chunks[0])
        self.assertIn("in progress", str(cm.exception))
        self.assertIn("expected seq 1, got 0", str(cm.exception))
        self.assertIn("idle", str(cm.exception))                                 # a visszaút KIMONDVA a hibában

    def test_stale_partial_is_restarted_by_seq0(self):
        self._abandon()
        self._age(att.PARTIAL_STALE_S + 1)
        # háromszor egymás után bukott; most a seq-0 újraindít, és a teljes átvitel TÁROLVA
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
        self.assertEqual(st["files"], 2, st)                                     # az elárvult + az élő .partial
        self.assertEqual(st["bytes"], 2 * att.CHUNK_BYTES, st)                   # mindkettő egy-egy darab

    def test_control_honest_transfer_and_interleaving_recover(self):
        # bolygatatlan út: 3 darab → TÁROLVA (a szonda nem vak)
        for c in self.chunks[:2]:
            self.assertIsNone(self.dst.receive_chunk(self.desc, c))
        self.assertEqual(self.dst.receive_chunk(self.desc, self.chunks[2]), self.desc)
        # már megvan: egy második feltöltő lezáró darabja a dedupe-ágon sikert ad
        self.assertEqual(self.dst.receive_chunk(self.desc, self.chunks[2]), self.desc)

    def test_control_exactly_at_threshold_is_still_live(self):
        self._abandon()
        self._age(att.PARTIAL_STALE_S - 5)
        with self.assertRaises(att.AttachmentError):
            self.dst.receive_chunk(self.desc, self.chunks[0])

    def test_env_threshold_cannot_disable_the_protection(self):
        # külső validáció: env=0 korábban kikapcsolta a védelmet; most a padló (60 s) alá nem vihető, csak fölé
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
