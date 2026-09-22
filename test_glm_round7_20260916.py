"""7 (2026-09-16) — a 52Z javításának ELLENSÉGES újramérése.

A javításokat (átmeneti/végleges elutasítás, per-id `remote_delivered`, aláírt-másolat replay) egy
NEM Claude-alapú kar támadta meg feltöltés előtt. Öt lelet jött vissza; ez a fájl a
regresszió mindegyikre — hogy a javítás javítása se csússzon vissza.

  7/1  a `forged` kegyelmi idő a FELADÓ `ts`-éből számolt -> jövőbeli ts = örök kegyelem = örök
       vízszint-beragadás (DoS). Javítás: jövőbeli/értelmezhetetlen ts -> NEM friss (végleges).
  7/2  `enf.check` kivétel -> a fail-closed ág MINDEN sort blokkolónak vett, a véglegeseket is ->
       egyetlen értelmezhetetlen sorral örökre megállítható a vízszint. Javítás: per-sor kezelés.
  7/3  a replay aláírt MÁSOLATA maga is mentőöv-jelölt maradt -> másolat másolata (flood), és a
       kandidátus-olvasás + beszúrás között TOCTOU. Javítás: a `to_id` is kizár + IMMEDIATE txn +
       `ux_replay_once` egyedi index.
  7/4  a `mark_delivered` bármely id-re írt `remote_delivered`-t -> a távoli oldal hazug ackja
       LEZÁRHATTA a nyitott `enforce_reject` nyomot (hamis némaság). Javítás: a véglegesen
       elutasított id kimarad, és külön `remote_delivered_refused` sorba kerül.
  7/5  `got[sha]` -> KeyError egy hiányzó envelope-nál (audit-DoS). Javítás: `got.get(sha, 0)`.

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


@unittest.skipUnless(ab._A2_HAVE, "cryptography szükséges")
class Glm7Round(unittest.TestCase):
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

    # ── segédek ──────────────────────────────────────────────────────────────
    def unknown_key(self, name="idegen"):
        """Aláírt üzenet olyan kulccsal, ami NINCS a registryben -> `forged`."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        kp = os.path.join(self.keys, "%s.ed25519.key" % name)
        with open(kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        return kp

    def fresh(self, tag="a"):
        return ab.send("hub", "peer", "friss-%s" % tag, db=self.db, mirror=False, sign_key=self.kp)

    def delivered_id(self):
        c = ab._conn(self.db)
        try:
            r = c.execute("SELECT delivered_id FROM cursors WHERE agent='peer'").fetchone()
            return r["delivered_id"] if r else 0
        finally:
            c.close()

    def audit_ops(self):
        c = ab._conn(self.db)
        try:
            return [(a["op"], a["from_id"]) for a in c.execute(
                "SELECT op, from_id FROM cursor_audit WHERE agent='peer' ORDER BY id")]
        finally:
            c.close()

    # ── 7/1 ──────────────────────────────────────────────────────────────────
    def test_future_dated_forged_row_gets_no_endless_grace(self):
        """Jövőbeli `ts`-ű hamis sor NEM kap végtelen kegyelmi időt (különben örökre lefogja a vízszintet)."""
        kp = self.unknown_key()
        far = int((time.time() + 10 * 365 * 24 * 3600) * 1e9)         # 10 év a jövőben
        with mock.patch.object(ab.time, "time_ns", lambda: far):
            ab.send("idegen", "peer", "10-ev-mulva-hamis", db=self.db, mirror=False, sign_key=kp)
        good = self.fresh("a")
        self.assertNotIn(1, ab.pending_blocking_ids("peer", db=self.db),
                         "a jövőből dátumozott `forged` sor blokkolónak számít -> a támadó megállítja a vízszintet")
        ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), good, "a vízszint a friss soron áll, nem ragad a szemét sor alatt")

    def test_fresh_forged_row_is_still_transient(self):
        """Kontroll: a FRISS `forged` sor továbbra is átmeneti (kulcs-rollout védve marad)."""
        kp = self.unknown_key("ops")
        ab.send("ops", "peer", "most-erkezett-bejegyzes-elott", db=self.db, mirror=False, sign_key=kp)
        good = self.fresh("a")
        self.assertIn(1, ab.pending_blocking_ids("peer", db=self.db), "a friss `forged` sor blokkol (rollout-ablak)")
        ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), 0, "a vízszint nem léphet át a még feloldható soron")

    # ── 7/2 ──────────────────────────────────────────────────────────────────
    def test_unparseable_row_must_not_block_forever(self):
        """Ha az `enf.check` egy soron KIVÉTELT dob, az a sor sosem adható ki -> nem blokkolhat."""
        self.fresh("a")
        good = self.fresh("b")
        real = enf.check

        def boom(m, **kw):
            if m["id"] == 1:
                raise ValueError("ertelmezhetetlen fejlec")
            return real(m, **kw)

        with mock.patch.object(enf, "check", boom):
            self.assertNotIn(1, ab.pending_blocking_ids("peer", db=self.db))
            ab.mark_delivered("peer", [good], db=self.db)
        self.assertEqual(self.delivered_id(), good,
                         "egyetlen értelmezhetetlen sorral megállítható a vízszint (tartós elnémítás)")

    # ── 7/4 ──────────────────────────────────────────────────────────────────
    def test_remote_ack_cannot_close_a_permanent_reject(self):
        """A távoli oldal ackja NEM zárhatja le a végleges elutasítás nyomát (hamis némaság)."""
        old = int((time.time() - 30 * 24 * 3600) * 1e9)               # 30 napos -> `stale-ts` (VÉGLEGES)
        with mock.patch.object(ab.time, "time_ns", lambda: old):
            ab.send("hub", "peer", "regi-sor", db=self.db, mirror=False, sign_key=self.kp)
        n = ab.mark_delivered("peer", [1], db=self.db)
        self.assertEqual(n, 0, "a véglegesen elutasított id-t nem jelölhetjük kézbesítettnek")
        ops = self.audit_ops()
        self.assertIn(("remote_delivered_refused", 1), ops, "a visszautasított ack külön, hash-láncolt sorba kerül")
        self.assertNotIn(("remote_delivered", 1), ops, "a hazug ack NEM gyárthat `remote_delivered` sort")
        c = ab._conn(self.db)
        try:
            self.assertIsNone(c.execute("SELECT read_at FROM messages WHERE id=1").fetchone()["read_at"],
                              "a sor olvasatlan marad (a `read_at` az igazság)")
        finally:
            c.close()

    def test_honest_ack_still_closes(self):
        """Kontroll: a becsületes ack változatlanul működik."""
        good = self.fresh("a")
        self.assertEqual(ab.mark_delivered("peer", [good], db=self.db), 1)
        self.assertIn(("remote_delivered", good), self.audit_ops())

    # ── 7/3 ──────────────────────────────────────────────────────────────────
    def test_signed_copy_is_not_replayed_again(self):
        """A replay aláírt MÁSOLATA nem lehet újabb replay alapja (különben másolat-lavina).

        MÉRT KORLÁT: közvetlenül a replay után a másolat a kurzor FÖLÖTT van, tehát még nem is jelölt
        (`reconcile` tartománya: delivered < id <= cursor). A lavina akkor indulna, ha egy KÉSŐBBI
        kurzor-ugrás kézbesítés nélkül átlép a másolat fölött — ezt a helyzetet állítja elő a teszt.
        """
        self.fresh("a")
        self.fresh("b")
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 2, db=self.db)                              # kurzor kézbesítés NÉLKÜL ugrik: 2 kihagyott sor
        first = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(len(first["replayed"]), 2, "előfeltétel: a két kihagyott sor másolata elkészül")
        self.assertTrue(all(r.get("mode") == "signed-copy" for r in first["replayed"]))
        copies = {r["new"] for r in first["replayed"]}
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", max(copies), db=self.db)                    # a kurzor a MÁSOLATOK fölé is ugrik kézbesítés nélkül
        life = {m["id"] for m in ab.reconcile("peer", db=self.db)}
        self.assertTrue(copies & life, "előfeltétel: most a másolatok maguk is mentőöv-jelöltek")
        second = ab.replay("peer", commit=True, db=self.db)
        self.assertEqual(second["replayed"], [],
                         "a másolat másolatot szült (%s): replay-lavina" % (second["replayed"],))

    def test_unique_index_blocks_a_second_replay_row(self):
        """Verseny esetére: az `ux_replay_once` index a DB-ben tiltja a második replay-sort ugyanarra az eredetire."""
        self.fresh("a")
        # 2026-09-16: a strict ack clamp TERMÉK-MÓDBAN ALAPÉRTELMEZÉS lett — a kurzor nem tud
        # kiadatlan posta fölött átlépni. Ez a szonda épp azt a KÁRT állítja elő, amit a clamp megelőz, ezért a
        # kár-forgatókönyvhöz itt KI KELL MONDANI a menekülő ajtót.
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 1, db=self.db)
        ab.replay("peer", commit=True, db=self.db)
        c = ab._conn(self.db)
        try:
            with self.assertRaises(ab.sqlite3.IntegrityError):
                with c:
                    ab._append_audit(c, "peer", 1, 99, "replay", 0)
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
