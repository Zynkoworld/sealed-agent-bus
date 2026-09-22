"""(2026-09-16, ) — a `687915f` támadása: a kurzor LEGITIM ack-kal is átugorhat
kézbesítetlen postát, és erről SEM a közjegyzői napló, SEM a busz helyi mentőöve nem tud.

🔴 A LELET. A `687915f` gépi kurzor-mezője a napló ÁLLÍTÁSAIT kötötte meg (a `reason`-elemzés helyett), és
   ez helyes volt. De a kötés VÉGPONTJA a fél ack-ja: `to <= max(from, ack)` (`bus_notary.py:571`) és
   `ack_logged_not_sent` (:628) — az ack-ot pedig a kliens a SAJÁT `stored_max`-jából számolja
   (`bus_ssh_client.py:62`). Ezért a kurzor-ablak FELSŐ végét a fél igazolja, a KÖZE nem:

     a vádlott 6 üzenetből (id 1..6, mind `peer`-nek) csak az 5-öt és a 6-ot adja ki, a naplóba
     becsületes alakú kört ír (`cursor=0 replies=2` + 2 `delivered`), a kliens a saját maximumát
     (6) nyugtázza, a vádlott ezt naplózza (`cursor 0->6 (ack 6)`) és a kurzort 0->6-ra állítja.

   Az 1..4 posta ezzel VÉGLEGESEN elfogyott (`read_at` beállítva, a kurzor felette), és a közjegyzői
   jelentés BETŰRE ugyanaz, mint a becsületes, 6/6-ot kiadó körben: `ok:true`, `discrepancies:[]`,
   `unresolved:[]`, `verify_ok:true`, **`trusted:true`** — termék-/strict-módban is. Nem „nem tudni",
   hanem „rendben": ez a auditunk óta vitt hibaosztály, most a kurzor-ablak belsejében.

   A rés oka szerkezeti: a napló csak azt tudja, MIT adtak ki, azt nem, MENNYI VÁRT kiadásra. A kiadás
   előtti `recv(mark=False)` (`bus_ssh_exchange.py:161`) PEEK, ezért:
     · a `delivered_id` nem emelkedik  -> az A1-L3 clamp (`AGENT_BUS_STRICT_ACK=1`) a kurzort SOSEM
       engedi mozdulni a távoli úton (mérve: 0->0, mind a 6 újra kiadásra vár) — tehát a meglévő
       védelem ezen az úton nem bekapcsolható;
     · a `read_at` NULL marad -> a `cursor_audit.skipped_undelivered` és az A1-L2 mentőöv
       (`agent_bus.reconcile`) a BECSÜLETES körre is a teljes ablakot jelenti (mérve: 6/6 mindkét
       esetben) — a helyi tamper-evidens jelzés a távoli úton telítve van, nem különböztet.

   Javaslat (a `687915f` gépi-mező vonalának folytatása): a kör-bejegyzés gépi mezője vigye a kiadásra
   VÁRÓ darabszámot is (`{"at": C, "replies": N, "pending": P}` — a busz ezt a peek-ből tudja), a
   `delivered` bejegyzés pedig a `{"id":...}`-t gépi mezőben (ma csak a `reason`-ben van). Ekkor a
   `reconcile` eldöntheti a ma megkülönböztethetetlen két esetet:
     · becsületes CSONKOLÁS (`pending > replies`, de a maradék a kurzor FÖLÖTT marad) -> nincs vád;
     · ELNYELÉS (a kurzor a kiadatlan maradék FÖLÉ mozdul) -> hard `cursor_skips_undelivered`.
   Ez nem teszi lehetetlenné a hazug buszt: a hamis `pending` viszont a busz SAJÁT hash-láncolt
   `cursor_audit` sorával kerül ellentmondásba, azaz bizonyíthatóvá válik — ma nincs MIVEL szembesíteni.

A KONTROLLOK ma zöldek (a szonda nem vak): a becsületes kör nem kap vádat, a fedezetlen kurzor-ugrást és
a túl-naplózott kiadást a mai kód MEGFOGJA. Hálózat nincs, minden út /tmp alá írva.
stdlib unittest + cryptography.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402

N_MAIL = 6          # id 1..6, mind a távoli `peer`-nek
N_GIVEN = 2         # a vádlott csak az utolsó kettőt adja ki


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class CursorSkipsUndelivered(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    # ── a kör: a VALÓDI kiadási út lépései (bus_ssh_exchange.py:161-175 + 99-110) ──────────
    def round(self, *, given=N_MAIL, forge_round_cursor=None, extra_delivered=False):
        """given = ennyi választ ad ki a vádlott a kiadásra várókból (a legnagyobb id-ket).
        -> (export, nyugták, ack, kurzor_után)"""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)   # aláírt ellenőrzőpont: trusted:true legyen
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)   # PEEK
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        self.assertEqual(len(allr), N_MAIL)
        out = allr[N_MAIL - given:]
        cur = ab.cursor_of("peer", db=self.db)
        # az egyik kar 2026-09-16: a fixtúra a VALÓDI íróhoz igazítva (bus_ssh_exchange 687915f után): a kör-bejegyzés
        # gépi mezője viszi a `pending`-et és az első ki NEM adott id-t, a `delivered` az id-t, és a kiadás
        # KÉZBESÍTÉS-jelölést kap (ab.mark_delivered) — a kurzort továbbra is csak az ack mozdítja.
        _given_ids = {x.get("id") for x in out}
        _left = [x.get("id") for x in allr if x.get("id") not in _given_ids]
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted",
            reason="cursor=%d replies=%d" % (forge_round_cursor if forge_round_cursor is not None else cur, len(out)),
            cursor={"at": forge_round_cursor if forge_round_cursor is not None else cur, "replies": len(out),
                    "pending": len(allr), "next_id": min(_left) if _left else 0})
        for x in out + ([allr[0]] if extra_delivered else []):
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x.get("id"),
                cursor={"id": int(x["id"])} if isinstance(x.get("id"), int) else None)
        ab.mark_delivered("peer", [x.get("id") for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)                            # a kliens a SAJÁT maximumát nyugtázza
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        return bn.export(self.log, 1), receipts, ack_to, ab.cursor_of("peer", db=self.db)

    def report(self, recs, receipts, strict=True):
        return bn.reconcile(recs, "peer", receipts, start_cursor=0, trusted_pub=self.pub, strict=strict)

    def types(self, rep):
        return sorted([d["type"] for d in rep["discrepancies"]] + [u["type"] for u in rep["unresolved"]])

    def reachable(self):
        return [m["id"] for m in ab.recv("peer", mark=False, limit=50, db=self.db)]

    # ── KONTROLLOK (ma zöldek) ────────────────────────────────────────────────
    def test_control_honest_full_round_is_not_accused(self):
        recs, rcpts, ack, cur = self.round(given=N_MAIL)
        rep = self.report(recs, rcpts)
        self.assertEqual(self.types(rep), [])
        self.assertTrue(rep["ok"] and rep["verify_ok"] and rep["trusted"])
        self.assertEqual((ack, cur), (N_MAIL, N_MAIL))

    def test_control_unbacked_cursor_jump_is_caught(self):
        """A kurzor-detektor ÉL ebben a fixtúrában: fedezetlen kör-kurzor -> hard vád."""
        recs, rcpts, _, _ = self.round(given=N_MAIL, forge_round_cursor=2)
        self.assertIn("cursor_moved_without_logged_ack", self.types(self.report(recs, rcpts)))

    def test_control_overlogged_delivery_is_caught(self):
        """A kiadási oldal is ÉL: a fél nyugtájában nem szereplő `delivered` -> hard vád."""
        recs, rcpts, _, _ = self.round(given=N_GIVEN, extra_delivered=True)
        self.assertIn("delivered_not_received", self.types(self.report(recs, rcpts)))

    def test_control_the_swallowed_mail_is_really_gone(self):
        """A veszteség VALÓDI és VÉGLEGES: az 1..4 az elnyelő kör után elérhetetlen."""
        recs, rcpts, ack, cur = self.round(given=N_GIVEN)
        self.assertEqual((ack, cur), (N_MAIL, N_MAIL))
        self.assertEqual(self.reachable(), [])

    # ── A LELET ───────────────────────────────────────────────────────────────
    def test_swallowing_round_must_not_report_identically_to_the_honest_one(self):
        """🔴 A 2/6-ot kiadó, 6-ig ugró kör jelentése BETŰRE azonos a becsületes 6/6-os körrel."""
        recs, rcpts, _, _ = self.round(given=N_GIVEN)
        rep = self.report(recs, rcpts, strict=True)
        self.assertTrue(
            self.types(rep),
            "a vádlott 6 üzenetből 2-t adott ki, a kurzort mégis 6-ra állította (1..4 véglegesen elfogyott), "
            "a jelentés mégis: ok=%r verify_ok=%r trusted=%r discrepancies=[] unresolved=[] — strict/termék-módban is"
            % (rep["ok"], rep["verify_ok"], rep["trusted"]))

    def test_local_lifeboat_must_distinguish_the_swallow_from_an_honest_round(self):
        """🔴 A helyi A1-L2 mentőöv és a `skipped_undelivered` a peek-kiadás miatt TELÍTVE van:
        a becsületes körre is a teljes ablakot jelenti, tehát nem különböztet."""
        self.round(given=N_MAIL)                                  # BECSÜLETES kör: 6/6 kiadva
        honest = [m["id"] for m in ab.reconcile("peer", db=self.db)]
        c = ab._conn(self.db)
        skipped = [dict(r)["skipped_undelivered"] for r in
                   c.execute("SELECT skipped_undelivered FROM cursor_audit WHERE agent='peer' AND op='ack'")]
        c.close()
        self.assertEqual((honest, skipped), ([], [0]),
                         "a becsületes, 6/6-ot kiadó kör után a mentőöv %r üzenetet és %r átugrottat jelent — "
                         "a `recv(mark=False)` peek nem emeli a `read_at`/`delivered_id`-t, ezért a jelzés a "
                         "távoli úton az elnyelő körtől megkülönböztethetetlen" % (honest, skipped))

    def test_strict_ack_clamp_must_not_freeze_the_remote_cursor(self):
        """🔴 A meglévő védelem (A1-L3, `AGENT_BUS_STRICT_ACK=1`) a távoli úton nem bekapcsolható:
        a peek nem emeli a `delivered_id`-t, ezért a kurzor SOSEM mozdul -> végtelen újrakiadás."""
        with mock.patch.dict(os.environ, {"AGENT_BUS_STRICT_ACK": "1"}, clear=False):
            _, _, ack, cur = self.round(given=N_MAIL)
            reach = self.reachable()
        self.assertEqual((ack, cur), (N_MAIL, N_MAIL),
                         "strict ack mellett a kliens ack-ja (%d) nem mozdítja a kurzort (%d marad), és mind a "
                         "%d üzenet újra kiadásra vár (%r) — a kiadási kör soha nem zárható le" % (ack, cur, len(reach), reach))


if __name__ == "__main__":
    unittest.main(verbosity=2)
