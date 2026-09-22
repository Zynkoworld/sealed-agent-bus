"""(2026-09-16) — az ÖTÖDIK szabadságfok: a kör-bejegyzés ACK-NAK ÁLCÁZVA.

A `bf8f8ec` a NEGYEDIK szabadságfokot zárta, és jól: ha a hazug kör-bejegyzés kiesik a `rounds`
szűrőből (`recipient` / `kind` / `decision` / a `cursor` típusa), akkor az ack-ablakban VAN bejegyzés,
tehát ez nem a bizonyíték HIÁNYA, hanem a KIKERÜLÉSE -> `round_shape_dodges_attribution` (kemény vád).

A javítás viszont az ablakot MAGÁT is egy ÖNBEVALLOTT MEZŐRE szűri:

    _win = [... and e.get("kind") != "ack"]                       # bus_notary.py:751

Az ablak-szkennelés tehát semmilyen `kind == "ack"` bejegyzést nem vesz kézbe — pedig a `kind` string
NINCS fehérlistázva (`Notary.record` csak a `decision`-t köti, `DECISIONS`, bus_notary.py:63), vagyis a
vizsgált fél SZABADON ráírhatja a saját kör-bejegyzésére. Egyetlen mező átírásával a bejegyzés

  * kiesik a `rounds` szűrőből   (`kind != "pickup"`)        -> nincs kit vádolni,
  * kiesik a `logged` listából   (`decision != "accepted"`)  -> nincs `audit_row_missing`,
  * kiesik a `_win` ablakból     (`kind == "ack"`)           -> nincs `round_shape_dodges_attribution`.

Marad a NÉMA `audit_skip_unattributable` (soft) — dev-módban (a CLI alapértelmezése) `ok=true, rc=0`
HAT véglegesen elveszett üzenet fölött, ép hash-lánccal és ép aláírással.

MÉRT KORLÁT, amit kimondunk: ha a kör SORÁN történt valódi kiadás, a kiadás-bejegyzések bent maradnak az
ablakban (nem `kind="ack"`), és a kikerülés-vád KIJÖN; ha a támadó azokat is átalakítja, egy MÁSIK réteg
(`received_not_logged`, a másik fél nyugta-listáján állva) elkapja. A rés ott nyílik, ahol a kurzor
ÚGY lép át kiadatlan posta fölött, hogy közben SEMMIT nem ad ki — vagyis épp a legsúlyosabb esetben,
mert akkor nincs mit nyugtázni, és a másik réteg sem szólal meg.

Ez a fájl a `test_clamp_lied_with_audit_20260916.py` VALÓDI e2e útját veszi át: valódi busz, valódi
`recv`/`ack`, valódi aláírt közjegyzői napló, valódi `cursor_audit` export. stdlib unittest, hálózat
nincs, minden út /tmp alá.
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

N_MAIL = 6          # ennyi üzenet vár a buszon


class RoundEntryMasqueradedAsAnAck(unittest.TestCase):
    """A kurzor MIND A HAT kiadatlan fölött átlép, a kör-bejegyzés pedig `kind="ack"` alakban áll."""

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

    def report(self, *, round_kind="pickup", strict=True):
        """Egyetlen változó: a kör-bejegyzés `kind` mezője. Minden más azonos."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r}
                for r in ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)]
        cur = ab.cursor_of("peer", db=self.db)
        # HAZUG kör-bejegyzés: „nem is volt kiadatlan, nem is adtam ki semmit"
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": []},
            kind=round_kind, decision=("accepted" if round_kind == "pickup" else "delivered"),
            reason="cursor=%d replies=0" % cur,
            cursor={"at": cur, "replies": 0, "pending": 0, "next_id": 0})
        ack_to = max(x["id"] for x in allr)                  # a kurzor MIND A HAT fölé megy
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack",
            decision="accepted", reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to),
            cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": [], "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        audit = ab.audit_export("peer", db=self.db)
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=strict, bus_audit=audit)
        return {"ok": r["ok"], "verify_ok": r["verify_ok"],
                "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "skipped": sum(int(a.get("skipped_undelivered") or 0) for a in audit)}

    # ── ELŐFELTÉTELEK: a kár VALÓDI, és a támadás NEM kriptográfiai ─────────
    def test_precondition_the_bus_audit_knows_six_were_skipped(self):
        r = self.report(round_kind="ack")
        self.assertEqual(r["skipped"], N_MAIL,
                         "előfeltétel: a busz hash-láncolt audit-sora 6 kiadatlan fölötti lépést rögzít")
        self.assertTrue(r["verify_ok"],
                        "előfeltétel: a napló lánca ÉS az aláírás ép — nem hamisítunk, csak CÍMKÉZÜNK")

    # ── KONTROLL: szabályos alakban a mai kód KEMÉNY vádat mond ────────────
    def test_control_the_same_lie_in_the_regular_shape_is_a_hard_accusation(self):
        r = self.report(round_kind="pickup")
        self.assertIn("audit_skipped_contradicts_log", r["hard"],
                      "előfeltétel: a szabályos alakú hazugságot a `bf8f8ec` kódja elkapja: %r" % r)
        self.assertFalse(r["ok"])

    # ── A LELET: az ablak-szkennelés maga is a `kind` mezőre szűr ──────────
    def test_the_window_scan_must_not_be_dodged_by_labelling_the_entry_an_ack(self):
        r = self.report(round_kind="ack")
        self.assertIn("round_shape_dodges_attribution", r["hard"] + r["soft"],
                      "ÖTÖDIK SZABADSÁGFOK: a `_win` (bus_notary.py:751) a `kind != \"ack\"` önbevallott "
                      "mezőre szűr, ezért az ACK-NAK CÍMKÉZETT hazug kör-bejegyzés az ablak-szkennelésből "
                      "is kiesik — a kikerülés `audit_skip_unattributable`-ként NEM MÉRHETŐ-nek látszik. "
                      "Jelentés: %r" % r)

    # ── A KÖVETKEZMÉNY: dev-módban (a CLI alapértelmezése) ZÖLD ────────────
    def test_dev_mode_must_not_be_green_over_six_permanently_lost_messages(self):
        r = self.report(round_kind="ack", strict=False)
        self.assertFalse(r["ok"],
                         "dev-módban `ok=true` (CLI: rc=0) HAT véglegesen elveszett üzenet fölött, "
                         "ép lánccal és ép aláírással: %r" % r)

    # ── KONTROLL: a különbségtétel másik fele nem sérülhet ─────────────────
    def test_control_a_genuinely_empty_window_stays_a_third_state(self):
        """Ahol tényleg NINCS bejegyzés az ack-ablakban, ott marad a harmadik állapot (soft)."""
        ents = [{"type": "entry", "seq": 1, "recipient": "peer", "kind": "ack", "decision": "accepted",
                 "cursor": {"from": 0, "to": 6, "ack": 6}}]
        from test_joint_kvantor_valalas_20260916 import _audit_rows
        t = {d["type"] for d in bn._audit_cross(ents, "peer", _audit_rows((0, 6, 4)))}
        self.assertIn("audit_skip_unattributable", t)
        self.assertNotIn("round_shape_dodges_attribution", t, "hamis kikerülés-vád üres ablakon: %r" % t)

    def test_control_an_honest_full_round_is_not_accused(self):
        """Fordított irány: ha a busz NEM tud kihagyásról, semmilyen alak nem szülhet vádat."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, 3):
            ab.send("hub", "peer", "level-%d" % i, db=self.db, mirror=False)
        out = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r}
               for r in ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)]
        cur = ab.cursor_of("peer", db=self.db)
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="teljes kör",
            cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0, "closes": 1})
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"],
                cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack",
            decision="accepted", reason="ack", cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=True,
                         bus_audit=ab.audit_export("peer", db=self.db))
        t = {d["type"] for d in r["discrepancies"]} | {u["type"] for u in r["unresolved"]}
        self.assertNotIn("round_shape_dodges_attribution", t, "hamis vád a becsületes körön: %r" % r)
        self.assertNotIn("audit_skipped_contradicts_log", t, "hamis vád a becsületes körön: %r" % r)


if __name__ == "__main__":
    unittest.main()

