"""A `ClampLiedFields` kimondott korlátjának LEZÁRÁSA.

az egyik kar `test_joint_delivery_outcome.py::ClampLiedFields` két szondája ma SZÁNDÉKOSAN bukik: a
kör-bejegyzés `pending`/`next_id` mezője a vádlott ÖNBEVALLÁSA, és a közjegyzői napló önmagában nem
cáfolja. Ezt a korlátot kimondtuk — de nem hagyjuk állni.

Ez a fájl UGYANAZT a forgatókönyvet futtatja (a szonda szerkezetét átvéve), egyetlen különbséggel:
a `reconcile` megkapja a busz SAJÁT, hash-láncolt `cursor_audit` exportját (`bus_audit=`). A két
nyilvántartás ellentmondása a bizonyíték:
  - `pending_down` („nem is maradt kiadatlan")  -> a busz audit-sora 4 kiadatlan fölötti lépést rögzít;
  - `next_id_up`  („az első kiadatlan az ack FÖLÖTT van") -> ugyanaz az állítás más szavakkal.
Mindkettő `audit_skipped_contradicts_log` (hard) — a clamp NEM kapcsolható ki egyetlen hazug számmal,
ha az összevetés fut.

KORLÁT, amit ez sem old meg: ha ugyanaz a fél írja MINDKÉT nyilvántartást, az egyidejű hazugság nem
zárható ki — de már két helyen kell hazudnia, és a két lánc ellentmondása bizonyíték.

stdlib unittest. Hálózat nincs, minden út /tmp alá.
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

N_MAIL = 6          # ennyi üzenet vár
N_GIVEN = 2         # ennyit ad ki a vádlott (4 elveszne)


@unittest.skipUnless(hasattr(ab, "audit_export"), "audit_export (67b050e+) szükséges")
class ClampLieMeetsBusAudit(unittest.TestCase):
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

    def report(self, lie=None, *, cross=True, round_cursor=True, ack_target=True):
        """A valódi kiadási út; `cross=True` esetén a busz audit-exportja is a reconcile elé kerül.

        `round_cursor=False` — a kör-bejegyzésben NINCS gépi mező.
        `ack_target=False`  — az ack-bejegyzés kurzor-mezőjéből hiányzik a `to`.
        """
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[N_MAIL - N_GIVEN:]                       # a vádlott csak a LEGFELSŐ kettőt adja ki
        cur = ab.cursor_of("peer", db=self.db)
        given = {x["id"] for x in out}
        left = [x["id"] for x in allr if x["id"] not in given]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if lie == "next_id_up":
            c["next_id"] = max(given) + 1
        if lie == "pending_down":
            c["pending"], c["next_id"] = len(out), 0
        if lie == "next_id_at_ack":                         # bevallja a kihagyást, de az ack CÉLJA ALÁ tolja
            c["next_id"] = max(given)
        kw = {"cursor": c} if round_cursor else {}
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)), **kw)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(given)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        ac = {"from": base, "to": tgt, "ack": ack_to} if ack_target else {"from": base, "ack": ack_to}
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor=ac)
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = bn.export(self.log, 1)
        audit = ab.audit_export("peer", db=self.db) if cross else None
        r = bn.reconcile(exp, "peer", receipts, strict=True, bus_audit=audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "skipped": sum(int(a.get("skipped_undelivered") or 0) for a in (audit or []))}

    # ── kontroll: az összevetés bemenete ép (a busz saját lánca önellenőrzött) ──
    def test_control_bus_audit_chain_verifies(self):
        self.report(None)
        rows = ab.audit_export("peer", db=self.db)
        self.assertTrue(ab.audit_chain_verify(rows)["ok"], "a busz audit-lánca önellenőrzésen átmegy")

    # ── kontroll: a becsületes csonkolt kör az összevetés MELLETT is bukik ────
    def test_control_honest_truncated_round_still_caught(self):
        r = self.report(None, cross=True)
        self.assertIn("cursor_skips_undelivered", r["hard"])
        self.assertFalse(r["ok"])

    # ── kontroll: összevetés NÉLKÜL a hazugság tényleg átmegy (ez a kimondott korlát) ──
    def test_control_without_cross_check_the_lie_wins(self):
        for lie in ("pending_down", "next_id_up"):
            with self.subTest(lie=lie):
                r = self.report(lie, cross=False)
                self.assertEqual(r["hard"], [], "összevetés nélkül a hazug szám tisztára mossa a jelentést")
            self.tearDown()
            self.setUp()

    # ── LEZÁRÁS: a busz saját naplójával összevetve MINDKÉT hazugság megbukik ──
    def test_lied_fields_are_contradicted_by_the_bus_audit(self):
        for lie in ("pending_down", "next_id_up"):
            with self.subTest(lie=lie):
                r = self.report(lie, cross=True)
                self.assertEqual(r["skipped"], N_MAIL - N_GIVEN,
                                 "előfeltétel: a busz audit-sora tudja, hány kiadatlan fölött lépett a kurzor")
                self.assertIn("audit_skipped_contradicts_log", r["hard"],
                              "a hazug %s mező a busz saját naplójával nem került ellentmondásba" % lie)
                self.assertFalse(r["ok"])
            self.tearDown()
            self.setUp()


    # ── 8: három megkerülési kísérlet az összevetés ellen ──────
    def test_glm8_admitted_skip_below_the_ack_is_already_hard(self):
        """MEGCÁFOLT lelet: „valljon be kihagyást, de tolja a next_id-t az ack alá" — ezt a RÉGI szabály fogja."""
        r = self.report("next_id_at_ack", cross=True)
        self.assertIn("cursor_skips_undelivered", r["hard"],
                      "a bevallott kihagyás az ack alatt: az ack csak next_id-1-ig vihette volna a kurzort")
        self.assertFalse(r["ok"])

    def test_glm8_missing_cursor_field_is_not_silent(self):
        """MEGCÁFOLT lelet: „ne írj gépi mezőt" — a hiányzó mérés harmadik állapot, nem zöld."""
        r = self.report(None, cross=True, round_cursor=False)
        self.assertIn("round_pending_unknown", r["soft"], "a gépi mező hiánya nem eshet némán vissza")
        self.assertFalse(r["ok"])

    def test_glm8_missing_ack_target_must_not_manufacture_a_contradiction(self):
        """VALÓS lelet javítva: naplózott ack-cél nélkül (`ack_top == 0`) nem gyárthatunk ellentmondást.

        A hallgatás nem bizonyíték: a `next_id > ack_top` ág csak akkor szólhat, ha tényleg láttunk ack-célt —
        különben minden BECSÜLETES csonkolt kör hamis `audit_skipped_contradicts_log` vádat kapna.
        """
        r = self.report(None, cross=True, ack_target=False)
        self.assertNotIn("audit_skipped_contradicts_log", r["hard"],
                         "ack-cél nélkül a becsületes kör HAMIS ellentmondás-vádat kapott")
        self.assertIn("cursor_skips_undelivered", r["hard"], "a valódi kihagyást viszont továbbra is kimondjuk")


class CliRefusesGreenWithoutTheSecondRegister(ClampLieMeetsBusAudit):
    """A korlát POLITIKÁVÁ téve: egy kör nem kap vádat attól, hogy nincs mellette a másik nyilvántartás
    (az hamis vád lenne) — de a CLI strict/termék-módban nem ad ZÖLD lámpát nélküle."""

    def files(self):
        """Lefuttat egy BECSÜLETES, teljes kört, és kiírja a szelet + nyugták + busz-audit fájlokat."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, 3):
            ab.send("hub", "peer", "level-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        out = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        cur = ab.cursor_of("peer", db=self.db)
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)),
            cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        # A kör ZÁRÓ horgonya (támadási mátrix 2.7, 2026-09-16): a valódi írófél minden mellékhatás UTÁN
        # kiírja — a fixture ezt utánozza, különben nem a becsületes kört modellezné, hanem egy megszakadtat.
        rec(envelope={"identity": "peer", "round_close": 1}, kind="round_close", decision="accepted",
            reason="close replies=%d" % len(out), cursor={"at": ab.cursor_of("peer", db=self.db),
                                                          "replies": len(out)})
        t = self.tmp.name
        exp, rp, au = os.path.join(t, "exp.jsonl"), os.path.join(t, "r.jsonl"), os.path.join(t, "audit.jsonl")
        with open(exp, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 1):
                f.write(bn.json.dumps(e, ensure_ascii=False) + "\n")
        with open(rp, "w", encoding="utf-8") as f:
            for r in ({"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                      {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}):
                f.write(bn.json.dumps(r, ensure_ascii=False) + "\n")
        with open(au, "w", encoding="utf-8") as f:
            for a in ab.audit_export("peer", db=self.db):
                f.write(bn.json.dumps(a, ensure_ascii=False) + "\n")
        return exp, rp, au

    def test_strict_cli_needs_the_bus_audit(self):
        exp, rp, au = self.files()
        args = ["reconcile", exp, "--identity", "peer", "--receipts", rp, "--pub", self.pub]
        self.assertEqual(bn.main(args), 0, "dev-módban (nem strict) a becsületes kör zöld")
        self.assertEqual(bn.main(args + ["--strict"]), 1,
                         "strict-ben a busz audit-exportja NÉLKÜL nem járhat zöld lámpa (hiányos bizonyíték)")
        self.assertEqual(bn.main(args + ["--strict", "--bus-audit", au]), 0,
                         "a második nyilvántartással a becsületes kör strict-ben is zöld")


if __name__ == "__main__":
    unittest.main()
