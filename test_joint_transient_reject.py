"""(2026-09-16, ) — a `6115966` "kiadható prefix" vízszintjének támadása.

A BLOCKER-re a javítás az ÉN javaslatom volt: a `mark_delivered` vízszintje a KIADHATÓ
(a `recv` szűrőjén átmenő) és még olvasatlan sorok közül veszi az első id-t. A javaslatom
indoklásában EGY esetre hivatkoztam: a `stale-ts` — ami VÉGLEGES (a 7 napos ablak már sosem nyílik
ki újra). A javítás viszont NEM tesz különbséget végleges és ÁTMENETI elutasítás között.

Átmeneti elutasítás a `bus_enforce.check` szerint legalább kettő van:
  - `future-ts`  — a feladó órája előre jár; a `WINDOW_FUTURE_S` (300 s) letelte után a sor
                   MAGÁTÓL legitimmé válik. Nincs benne semmi ellenséges: óracsúszás.
  - `forged`     — ismeretlen sender: a registry-kulcs (root-tulajdonú) még nincs bejegyezve;
                   a kulcs-rollout befejeztével a sor legitimmé válik.

Ez a szonda a `future-ts`-t méri, mert az MAGÁTÓL oldódik fel, tehát nem kell hozzá operátori
beavatkozást feltételezni.

A mért lánc (a VALÓDI kiadási út, `bus_ssh_exchange.py:161-196`):
  peek -> mark_delivered -> ack_preview -> ack, `AGENT_BUS_STRICT_ACK=1` + termék-mód.
A kérdés nem az, hogy a kurzor mozdul-e (mozdulnia KELL — ezt kértem), hanem hogy az átmenetileg
kiadhatatlan sor a kurzor ALÁ kerül-e, és ha igen, van-e még út, amin kimegy.

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

SKEW_S = 400          # > WINDOW_FUTURE_S (300) -> future-ts, de 400 s múlva MAGÁTÓL legitim


@unittest.skipUnless(ab._A2_HAVE, "cryptography szükséges")
@unittest.skipUnless(hasattr(ab, "mark_delivered"), "mark_delivered (52ad412+) szükséges")
class TransientRejectLoss(unittest.TestCase):
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
            # a registry-guard root-tulajdont ellenőriz; a determinizmushoz kikerüljük (nem ezt mérjük)
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

    def send_future(self):
        """Egy LEGITIM, aláírt üzenet előre járó órájú feladótól -> most future-ts, 400 s múlva rendben."""
        fut = int((time.time() + SKEW_S) * 1e9)
        with mock.patch.object(ab.time, "time_ns", lambda: fut):
            ab.send("hub", "peer", "ora-elore-de-legitim", db=self.db, mirror=False, sign_key=self.kp)

    def send_fresh(self, tag):
        ab.send("hub", "peer", "friss-%s" % tag, db=self.db, mirror=False, sign_key=self.kp)

    def cursors(self):
        c = ab._conn(self.db)
        try:
            r = c.execute("SELECT last_seen_id, delivered_id FROM cursors WHERE agent='peer'").fetchone()
            return (r["last_seen_id"], r["delivered_id"]) if r else (0, 0)
        finally:
            c.close()

    def one_round(self, *, strict):
        """A valódi kiadási út magja: peek -> mark_delivered -> ack (strict clamp)."""
        rows = ab.recv("peer", mark=False, limit=200, db=self.db, verify_sds=True)
        ids = [r["id"] for r in rows]
        if ids:
            ab.mark_delivered("peer", ids, db=self.db)
            env = {"AGENT_BUS_STRICT_ACK": "1"} if strict else {}
            with mock.patch.dict(os.environ, env, clear=False):
                if not strict:
                    os.environ.pop("AGENT_BUS_STRICT_ACK", None)
                ab.ack("peer", max(ids), db=self.db)
        return ids

    def after_skew(self):
        """A jövő-ablak letelt: a `future-ts` ok MEGSZŰNT. Mit lát még a busz?"""
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            reach = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
        return reach, life

    # ── kontroll: az előfeltétel fennáll, és ÁTMENETI (nem végleges) ──────────
    def test_control_future_ts_is_rejected_now_and_valid_later(self):
        self.send_future()
        self.assertEqual(enf.mode(db=self.db), "product")
        now_ids = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(now_ids, [], "most future-ts -> nem kiadható")
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            later_ids = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(later_ids, [1], "a jövő-ablak letelte után UGYANAZ a sor legitim (ÁTMENETI elutasítás)")

    # ── kontroll: átmeneti sor NÉLKÜL a becsületes postafiók halad ────────────
    def test_control_honest_mailbox_advances(self):
        self.send_fresh("a")
        self.assertEqual(self.one_round(strict=True), [1])
        self.assertEqual(self.cursors(), (1, 1), "a becsületes kör kurzora és vízszintje is 1")

    # ── LELET: az átmenetileg kiadhatatlan sor a kurzor ALÁ kerül ────────────
    def test_transient_reject_must_not_be_skipped_by_the_cursor(self):
        self.send_future()
        self.send_fresh("a")
        given = self.one_round(strict=True)
        self.assertEqual(given, [2], "csak a friss sor adható ki")
        cur, dl = self.cursors()
        self.assertLess(cur, 1,
                        "a kurzor %d-re ugrott, a vízszint %d: az ÁTMENETILEG elutasított id=1 a kurzor ALÁ került, "
                        "pedig 400 s múlva legitim lett volna" % (cur, dl))

    # ── LELET: a kurzor-ugrás után a sor a `recv` úton NEM érhető el ─────────
    def test_transient_reject_must_stay_reachable_after_the_window(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        reach, life = self.after_skew()
        self.assertIn(1, reach,
                      "a jövő-ablak letelte után a legitim id=1 a recv úton nem jön ki (reach=%s); "
                      "a mentőöv %s-t listáz" % (reach, life))

    # ── ATTRIBÚCIÓ-kontroll: a replay termék-módú halottsága NEM ebből a diffből jön ──
    # Ugyanaz a kérdés a 6115966 új kódútja NÉLKÜL: kézi (nem-strict) kurzor-ugrás kihagy egy
    # kézbesítetlen sort, a mentőöv látja -> kijut-e a replay? Ez az ALAPON is futtatható.
    def test_control_replay_is_dead_in_product_mode_on_both_trees(self):
        self.send_fresh("a")
        self.send_fresh("b")
        # 2026-09-16: a strict ack clamp TERMÉK-MÓDBAN ALAPÉRTELMEZÉS
        # lett (az üzemeltető „igen mehet" + a ti mért véleményetek). Ez a kontroll a RÉGI default kár-forgatókönyvét
        # állítja elő, ezért a menekülő ajtót itt ki kell mondani — a ti mondatotok szerint: „a fixture-ben, nem a
        # termék-kódban van munka". A szonda LOGIKÁJA változatlan.
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "0"}, clear=False):
            ab.ack("peer", 2, db=self.db)             # nem-strict: a kurzor kézbesítés NÉLKÜL ugrik 0->2
        life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
        self.assertEqual(life, [1, 2], "előfeltétel: a mentőöv a két kézbesítetlen sort látja")
        done = ab.replay("peer", commit=True, db=self.db)
        reach = ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)
        self.assertTrue(reach,
                        "a replay lefutott (%s), de a termék-módú recv semmit nem ad ki: a `system` feladós, "
                        "ALÁÍRATLAN replay-üzenetet a kikényszerítés `unsigned-downgrade`-del eldobja" % (done,))

    # ── LELET: a mentőöv MEGNEVEZI a sort, de a replay termék-módban nem jut ki ──
    def test_lifeboat_replay_must_actually_deliver(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
            self.assertEqual(life, [1], "előfeltétel: a mentőöv megnevezi az elveszett sort")
            done = ab.replay("peer", commit=True, db=self.db)
            reach = ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)
        self.assertTrue(reach,
                        "a mentőöv %s-t nevezte meg, a replay lefutott (%s), de a termék-módú recv "
                        "SEMMIT nem ad ki: a helyreállítási út nem jut át a kikényszerítésen" % (life, done))

    # ── LELET: a peek-kori audit-sor ÖRÖKRE vádol, a SIKERES kézbesítés után is ──
    # A -em pontosan a HAMIS VÁD ellen szólt. A javítás a mentőöv `extra` ágából
    # kivette a `read_at IS NULL` szűrőt ("az audit-sor a jel"), de az audit-sor a PEEK-kor íródik,
    # amikor az elutasítás még fennállt. Ha az ok ÁTMENETI volt és a sor később rendben kimegy,
    # a vád megmarad -> a replay DUPLIKÁLNA egy már kézbesített üzenetet.
    def test_delivered_row_must_leave_the_lifeboat(self):
        self.send_future()
        self.send_fresh("a")
        peek = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(peek, [2], "előfeltétel: a peek elutasítja az id=1-et (audit-sor íródik)")
        later = time.time() + SKEW_S + 10
        with mock.patch.object(enf.time, "time", lambda: later):
            given = self.one_round(strict=True)          # a jövő-ablak letelt: MINDEN sor kimegy
            self.assertEqual(given, [1, 2], "előfeltétel: a sor most bizonyítottan KIADÁSRA került")
            life = [m["id"] for m in ab.reconcile("peer", db=self.db)]
            would = ab.replay("peer", commit=False, db=self.db)["would_replay"]
        self.assertEqual(life, [],
                         "a mentőöv a SIKERESEN kézbesített id=1-et még vádolja (life=%s); a replay "
                         "duplikálná: %s" % (life, would))

    # ── a MÁSODIK átmeneti ok: kulcs-rollout (`forged`), operátori beavatkozással ──
    def test_key_rollout_reject_must_not_be_skipped_by_the_cursor(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        kp = os.path.join(self.keys, "ops.ed25519.key")
        with open(kp, "w") as f:
            f.write(priv.private_bytes_raw().hex())
        # a registry-bejegyzés MÉG NINCS meg (a kulcs-tár root-tulajdonú, az operátor írja)
        ab.send("ops", "peer", "legitim-de-meg-nem-bejegyzett-kulcs", db=self.db, mirror=False, sign_key=kp)
        self.send_fresh("a")
        peek = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertEqual(peek, [2], "előfeltétel: bejegyzés nélkül a sor `forged` -> nem kiadható")
        self.one_round(strict=True)
        with open(os.path.join(self.keys, "ops.pub"), "w") as f:   # az operátor BEJEGYZI a kulcsot
            f.write(pub)
        reach = [r["id"] for r in ab.recv("peer", mark=False, limit=99, db=self.db, verify_sds=True)]
        self.assertIn(1, reach,
                      "a kulcs bejegyzése után a legitim id=1 nem jön ki (reach=%s): a kurzor már fölötte van" % reach)

    # ── MÉRÉS (nem assert): mi marad a mentőövön? ────────────────────────────
    def test_report_lifeboat_state(self):
        self.send_future()
        self.send_fresh("a")
        self.one_round(strict=True)
        reach, life = self.after_skew()
        cur, dl = self.cursors()
        c = ab._conn(self.db)
        try:
            aud = [(a["op"], a["from_id"], a["to_id"], a["skipped_undelivered"]) for a in c.execute(
                "SELECT op, from_id, to_id, skipped_undelivered FROM cursor_audit WHERE agent='peer' ORDER BY id")]
            unread = [r[0] for r in c.execute("SELECT id FROM messages WHERE recipient='peer' AND read_at IS NULL")]
        finally:
            c.close()
        sys.stderr.write("\n[MÉRÉS] kurzor=%d vízszint=%d recv_után=%s mentőöv=%s olvasatlan=%s audit=%s\n"
                         % (cur, dl, reach, life, unread, aud))


if __name__ == "__main__":
    unittest.main()
