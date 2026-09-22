"""(2026-09-16, ) — az `e8d9370` `mark_delivered` prefix-vízszintjének támadása.

A -re a javítás az ÉN javaslatom lett: a `delivered_id` már nem `MAX(ids)`, hanem az
ÖSSZEFÜGGŐ kézbesített prefix teteje (`MIN(id) WHERE read_at IS NULL` − 1). A javaslatom mellé adott
kontrollom CSAK azt mérte, hogy a becsületes kör nem romlik el — azt NEM, hogy mi történik, ha a
címzettnek van egy VÉGLEGESEN kiadhatatlan sora a prefix alatt.

Termék-módban pontosan ilyen sor keletkezik: a `bus_enforce.check` a 7 napnál régebbi `ts`-ű, egyébként
legitim és aláírt postát `stale-ts`-szel elutasítja. Az elutasított sor a
DB-ben marad, `read_at` NULL-lal, és a `recv` kikényszerítés-szűrője SOSEM adja ki — de a `mark_delivered`
nyers SQL-je (`MIN(id) WHERE read_at IS NULL`) NEM alkalmazza ezt a szűrőt, ezért a vízszint örökre
alá esik.

Következmény `AGENT_BUS_STRICT_ACK=1` mellett (ez az a kapcsoló, amire a v1.5 clamp-védelme épül):
a távoli kurzor 0→0 marad minden körben, a kiadott halmaz körönként NŐ — végtelen újrakiadás.

A gépen a registry-guard root-tulajdont követel; a szonda ezt EXPLICIT kikerüli (`_a2_guarded_read`),
hogy root és nem-root futtatónál BETŰRE ugyanazt mérje. A mért logika a KURZOR, nem a kulcs-guard.
stdlib unittest + cryptography. Hálózat nincs, minden út /tmp alá.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_enforce as enf  # noqa: E402

STALE_AGE_S = 8 * 24 * 3600          # a 7 napos WINDOW_PAST_S-en kívül -> stale-ts, VÉGLEG


@unittest.skipUnless(ab._A2_HAVE, "cryptography szükséges")
@unittest.skipUnless(hasattr(ab, "mark_delivered"), "mark_delivered (52ad412+) szükséges")
class PrefixStall(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.keys = os.path.join(t, "keys")
        os.makedirs(self.keys, mode=0o700)
        self.db = os.path.join(t, "bus.db")
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.kp = os.path.join(self.keys, "hub.ed25519.key")
        with open(os.path.join(self.keys, "hub.pub"), "w") as f:
            f.write(pub)
        with open(self.kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        self.p = [
            mock.patch.dict(os.environ, {
                "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": self.keys,
                "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_ENFORCE_DIR": os.path.join(t, "enf"),
                "AGENT_BUS_MODE": "product"}, clear=False),
            mock.patch.object(ab, "KEYS_DIR", self.keys),
            # a registry-guard root-tulajdont ellenőriz; a szonda determinizmusához kikerüljük (nem ezt mérjük)
            mock.patch.object(ab, "_a2_guarded_read",
                              lambda p: (open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None)),
        ]
        for x in self.p:
            x.start()
        os.environ.pop("AGENT_BUS_STRICT_ACK", None)

    def tearDown(self):
        for x in self.p:
            x.stop()
        self.tmp.cleanup()

    def send_stale(self):
        old = int((time.time() - STALE_AGE_S) * 1e9)
        with mock.patch.object(ab.time, "time_ns", lambda: old):
            ab.send("hub", "peer", "regi-de-legitim", db=self.db, mirror=False, sign_key=self.kp)

    def send_fresh(self, tag):
        ab.send("hub", "peer", "friss-%s" % tag, db=self.db, mirror=False, sign_key=self.kp)

    def rounds(self, n, *, strict):
        """A VALÓDI kiadási út magja (bus_ssh_exchange.py:161-196): peek -> mark_delivered -> a fél ack-ja."""
        out = []
        for k in range(n):
            self.send_fresh(k)
            rows = ab.recv("peer", mark=False, limit=200, db=self.db, verify_sds=True)
            ids = [r["id"] for r in rows]
            if not ids:
                out.append((ids, None))
                continue
            pend = [r["id"] for r in ab.recv("peer", mark=False, limit=10000, db=self.db, verify_sds=True)]
            left = [i for i in pend if i not in set(ids)]
            try:
                ab.mark_delivered("peer", ids, db=self.db, next_undelivered=(min(left) if left else 0))
            except TypeError:
                ab.mark_delivered("peer", ids, db=self.db)
            env = {"AGENT_BUS_STRICT_ACK": "1"} if strict else {}
            with mock.patch.dict(os.environ, env, clear=False):
                if not strict:
                    os.environ.pop("AGENT_BUS_STRICT_ACK", None)
                mv = ab.ack_preview("peer", max(ids), db=self.db)
                ab.ack("peer", max(ids), db=self.db)
            out.append((ids, mv))
        return out

    # ── kontroll: a szonda előfeltétele tényleg fennáll ────────────────────────
    def test_control_the_stale_row_is_really_rejected_forever(self):
        self.send_stale()
        self.send_fresh("a")
        self.assertEqual(enf.mode(db=self.db), "product")
        ids = [r["id"] for r in ab.recv("peer", mark=False, limit=200, db=self.db, verify_sds=True)]
        self.assertEqual(ids, [2], "a régi sor nem adható ki, a friss igen")
        c = ab._conn(self.db)
        try:
            unread = [r[0] for r in c.execute("SELECT id FROM messages WHERE recipient='peer' AND read_at IS NULL")]
        finally:
            c.close()
        self.assertIn(1, unread, "az elutasított sor read_at-je NULL marad (no-deletion)")

    # ── kontroll: elutasított sor NÉLKÜL a javítás helyes (a célja megmarad) ──
    def test_control_honest_mailbox_advances_under_strict(self):
        got = self.rounds(3, strict=True)
        self.assertEqual([g[0] for g in got], [[1], [2], [3]], "minden kör pontosan az új postát adja ki")
        self.assertEqual([g[1] for g in got], [(0, 1), (1, 2), (2, 3)], "a kurzor lépésenként halad")

    # ── kontroll: nem-strict módban nincs változás ─────────────────────────────
    def test_control_non_strict_is_unaffected(self):
        self.send_stale()
        got = self.rounds(3, strict=False)
        self.assertEqual([g[1] for g in got], [(0, 2), (2, 3), (3, 4)], "nem-strict: a kurzor halad")

    # ── LELET-1: egyetlen véglegesen elutasított sor befagyasztja a strict kurzort ──
    def test_rejected_row_must_not_freeze_the_strict_cursor(self):
        self.send_stale()
        got = self.rounds(3, strict=True)
        moves = [g[1] for g in got]
        self.assertNotEqual(moves, [(0, 0), (0, 0), (0, 0)],
                            "a kurzor MINDEN körben 0->0: egy kiadhatatlan sor véglegesen megállította a postát")
        c = ab._conn(self.db)
        try:
            cur = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent='peer'").fetchone()
        finally:
            c.close()
        self.assertGreater(cur["delivered_id"], 0,
                           "a vízszint 0 marad, pedig 3 friss üzenet bizonyítottan kiadásra került")

    # ── LELET-2: a befagyott kurzor miatt a kiadás körönként HALMOZÓDIK ────────
    def test_frozen_cursor_must_not_amplify_redelivery(self):
        self.send_stale()
        got = self.rounds(3, strict=True)
        sizes = [len(g[0]) for g in got]
        self.assertEqual(sizes, [1, 1, 1],
                         "a kiadott halmaz körönként nő (%s): ugyanaz a posta újra és újra kimegy" % (
                             [g[0] for g in got],))


if __name__ == "__main__":
    unittest.main()
