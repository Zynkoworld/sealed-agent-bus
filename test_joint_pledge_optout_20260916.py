"""(2026-09-16, ) — a bizonyíték-réteg két NÉMA OPT-OUT-ja."""
import os, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab            # noqa: E402
import bus_notary as bn           # noqa: E402
import bus_ssh_exchange as ex     # noqa: E402

GENESIS = "0" * 64


def rechain(entries):
    """A KONZISZTENS író modellje: aki a naplót írja, a láncot is maga számolja."""
    prev, seq = GENESIS, 0
    for e in entries:
        if e.get("type") != "entry":
            continue
        seq += 1
        e["seq"], e["prev_hash"] = seq, prev
        e["entry_hash"] = bn.entry_hash({k: v for k, v in e.items() if k not in ("type", "entry_hash")})
        prev = e["entry_hash"]
    return entries


class _Round(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log, self.db = os.path.join(t, "notary.jsonl"), os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        import unittest.mock as mock
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class PledgeOptOut(_Round):
    """A) a `closes` KIHAGYÁSA kapcsolja ki a kör-záró horgony számonkérését."""

    def round_trip(self):
        t = self.tmp.name
        notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50, db=self.db)
        for i in range(3):
            ab.send("hub", "remote1", "ki-%d" % i, db=self.db, mirror=False)
        r1 = ex.exchange("remote1", '{}', db=self.db, attach_root=os.path.join(t, "att"), notary=notary)
        top = max(m["id"] for m in r1["replies"])
        ex.exchange("remote1", '{"ack": %d}' % top, db=self.db, attach_root=os.path.join(t, "att"), notary=notary)
        self.receipts = [{"phase": "request", "sent": [], "ack": top, "received": r1["replies"], "round": "r1"},
                         {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        return bn.export(self.log, 1)

    def rows(self):
        c = ab._conn(self.db)
        try:
            return [dict(x) for x in c.execute(
                "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
                "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
        finally:
            c.close()

    def report(self, entries):
        return bn.reconcile(entries, "remote1", self.receipts, strict=True, bus_audit=self.rows())

    @staticmethod
    def _drop_close(entries, pledge):
        out = []
        for e in entries:
            if e.get("type") == "entry" and e.get("kind") == "round_close":
                continue                                        # a záró horgony nincs meg
            if (not pledge and e.get("type") == "entry" and isinstance(e.get("cursor"), dict)
                    and "closes" in e["cursor"]):
                e = dict(e, cursor={k: v for k, v in e["cursor"].items() if k != "closes"})
            out.append(dict(e))
        return rechain(out)

    def _report_unpledged(self, exp):
        return self.report(self._drop_close([dict(e) for e in exp], pledge=False))

    # ── kontroll: az érintetlen kör zöld, és az újraláncolás nem ront el semmit ──
    def test_control_untouched_and_rechained_are_both_green(self):
        exp = self.round_trip()
        a = self.report([dict(e) for e in exp])
        b = self.report(rechain([dict(e) for e in exp]))
        self.assertTrue(a["ok"] and a["verify_ok"], "az érintetlen kör nem zöld: %r" % a)
        self.assertTrue(b["ok"] and b["verify_ok"],
                        "az ÚJRALÁNCOLÁS önmagában elrontotta a mérést (a szonda így nem mérne): %r" % b)
        self.assertGreaterEqual(a["counts"]["rounds_pledged"], 1)

    # ── kontroll: a VÁLLALÁS mellett a hiányzó zárás ma is kijön ─────────────────
    def test_control_missing_close_with_the_pledge_is_named(self):
        exp = self.round_trip()
        r = self.report(self._drop_close([dict(e) for e in exp], pledge=True))
        self.assertIn("audit_close_missing", {u["type"] for u in r["unresolved"]},
                      "a vállalt, de hiányzó zárás nem jött ki: %r" % r)
        self.assertFalse(r["ok"])

    # ── kontroll: a TESTVÉR-mező (nyitó horgony) kimaradása NEM néma ─────────────
    def test_control_the_sibling_field_absence_is_a_third_state(self):
        exp = self.round_trip()
        ents = []
        for e in exp:
            if e.get("type") == "entry" and isinstance(e.get("cursor"), dict) and "audit_seq" in e["cursor"]:
                e = dict(e, cursor={k: v for k, v in e["cursor"].items() if k not in ("audit_seq", "audit_hash")})
            ents.append(dict(e))
        r = self.report(rechain(ents))
        self.assertIn("audit_anchor_absent", {u["type"] for u in r["unresolved"]},
                      "a NYITÓ horgony kimaradására van harmadik állapot — ehhez mérjük a zárót: %r" % r)

    # ── LELET: a vállalás kihagyása némán kikapcsolja a záró horgonyt ───────────
    def test_a_log_that_never_pledges_must_not_look_identical_to_a_closed_one(self):
        r = self._report_unpledged(self.round_trip())
        self.assertTrue(
            r["unresolved"] or r["discrepancies"] or r["counts"].get("rounds_unpledged"),
            "a `closes` nélküli napló a záró horgony NÉLKÜL is hibátlannak látszik "
            "(ok=%s, hard=[], soft=[], rounds_pledged=%s) — a garanciát az ellenőrzött fél mezője kapcsolja ki"
            % (r["ok"], r["counts"]["rounds_pledged"]))

    def test_the_unpledged_log_must_not_be_ok_in_strict_mode(self):
        """Strict/termék-mód: ugyanaz a szigor, mint a nyitó horgony hiányánál."""
        r = self._report_unpledged(self.round_trip())
        self.assertFalse(r["ok"],
                         "strict módban zöld egy olyan napló, aminek EGYETLEN köre sincs záró horgonnyal kötve: %r"
                         % r["counts"])


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class SkippedContradictionQuantifier(_Round):
    """B) egyetlen további kör kioltja a `audit_skipped_contradicts_log` vádat az ÖSSZES körre."""

    N_MAIL, N_GIVEN = 6, 2

    def report(self, extra_round=None):
        """6 üzenetből 2 megy ki, a kurzor 6-ra ugrik → 4 VÉGLEGESEN elvész; a kör hazudik, és le van zárva."""
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(1, self.N_MAIL + 1):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[self.N_MAIL - self.N_GIVEN:]
        cur = ab.cursor_of("peer", db=self.db)
        given = {x["id"] for x in out}
        e1 = rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
                 kind="pickup", decision="accepted", reason="cursor=%d" % cur,
                 cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})   # HAZUG
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"],
                cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(given)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d" % (base, tgt), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        rec(envelope={"identity": "peer", "round_close": 1, "cursor": ab.cursor_of("peer", db=self.db)},
            kind="round_close", decision="accepted", reason="zarva", cursor={"round_seq": e1["seq"]})
        if extra_round is not None:                  # EGY további kör-bejegyzés + a saját zárása
            e2 = rec(envelope={"identity": "peer", "cursor": tgt, "note": "round2"}, kind="pickup",
                     decision="accepted", reason="round2", cursor=extra_round)
            rec(envelope={"identity": "peer", "round_close": 1, "cursor": ab.cursor_of("peer", db=self.db)},
                kind="round_close", decision="accepted", reason="zarva2", cursor={"round_seq": e2["seq"]})
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        exp = bn.export(self.log, 1)
        audit = ab.audit_export("peer", db=self.db)
        r = bn.reconcile(exp, "peer", receipts, strict=True, bus_audit=audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]}),
                "trusted": bn.verify(exp, trusted_pub=self.pub).get("trusted"),
                "skipped": sum(int(a.get("skipped_undelivered") or 0) for a in audit),
                "still_reachable": [m["id"] for m in ab.recv("peer", mark=False, limit=99, db=self.db)]}

    # ── kontroll: a hazug kör egyedül lelepleződik, és a kár valódi ─────────────
    def test_control_the_lie_alone_is_caught(self):
        r = self.report(None)
        self.assertEqual(r["skipped"], self.N_MAIL - self.N_GIVEN, "a busz audit-sora tudja, hány posta veszett el")
        self.assertEqual(r["still_reachable"], [], "a posta tényleg elfogyott")
        self.assertIn("audit_skipped_contradicts_log", r["hard"], "a kontroll-vád nem jött ki: %r" % r)

    # ── kontroll: az EXTRA kör önmagában nem indok a kioltásra ──────────────────
    def test_control_an_extra_round_above_the_ack_keeps_the_accusation(self):
        r = self.report({"at": 6, "pending": 1, "replies": 0, "next_id": 9})
        self.assertIn("audit_skipped_contradicts_log", r["hard"],
                      "egy MÁSIK extra kör mellett a vád megmarad — tehát nem a bejegyzés léte számít: %r" % r)

    # ── LELET: egy becsületes kör visszamenőleg mentesíti a hazug kört ──────────
    def test_one_more_round_must_not_clear_the_earlier_one(self):
        r = self.report({"at": 6, "pending": 1, "replies": 0, "next_id": 1})
        self.assertTrue(r["hard"] or r["soft"],
                        "egyetlen további, ÖNMAGÁBAN BECSÜLETES kör-bejegyzés kioltotta a vádat: "
                        "ok=%s, hard=[], soft=[], trusted=%s — közben %d üzenet véglegesen elveszett"
                        % (r["ok"], r["trusted"], r["skipped"]))


if __name__ == "__main__":
    unittest.main()
