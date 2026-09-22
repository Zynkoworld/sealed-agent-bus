"""`_audit_cross`: kulcsra párosítás és kétirányú fedettségi kapu — (2026-09-17, ALACSONY-KÖZEPES).

A lelet két része, mindkettő mérve, valódi buszon:
  (a) a hossz-kapu EGYIRÁNYÚ volt: csak „a napló többet mond, mint az audit" (audit_row_missing) tüzelt; a fordított
      irány — 2 napló-ack / 3 audit-sor, sőt 0 / 3 — NÉMA maradt. Pedig az ELREJTÉS iránya épp ez: a független
      nyilvántartás többet tud, mint az önbevallás.
  (b) a két nyilvántartást POZÍCIÓ szerint párosította (`zip`): ha a naplóból kiesik egy ack, minden további pár
      elcsúszik, és a vád (audit_cursor_mismatch) BECSÜLETES bejegyzésre mutat — a megvádolt fél joggal mutatja meg,
      hogy az ő sora rendben van, és a kereszt-ellenőrzés hitele sérül, pedig a rendszernek igaza volt, hogy baj van.

Javítás: párosítás KULCSRA (audit from_id/to_id ↔ napló cursor.from/to, napló-sorrendben, egy sor egyszer), és a
fordított irány saját neve: `audit_row_unlogged`, a hiányzó audit-sorok seq-jével. az egyik kar erős cáfolata áll tovább
(a skipped-jel nem tüntethető el), ezt itt nem mérjük újra.

Mutáns-próba: pozíció-párosítással `test_dropped_middle_ack_does_not_accuse_the_honest_third` bukik; a fordított kapu
nélkül `test_audit_rows_without_log_ack_are_named` bukik. stdlib unittest; valódi busz + valódi audit-export, /tmp.
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


class KeyPairedAuditCross(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, _ = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
            "AGENT_BUS_AUTO_SIGN": "0"}, clear=False)
        self.p.start()
        # HÁROM becsületes kör: 2 üzenet → kiadás → ack, minden ack a naplóban ÉS a busz audit-táblájában
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        self.steps = []
        for r in range(3):
            for i in range(2):
                ab.send("hub", "peer", "m-%d-%d" % (r, i), db=self.db, mirror=False)
            rows = ab.recv("peer", mark=False, db=self.db)
            cur = ab.cursor_of("peer", db=self.db)
            rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": []}, kind="pickup", decision="accepted",
                reason="cursor=%d replies=%d" % (cur, len(rows)),
                cursor={"at": cur, "replies": len(rows), "pending": len(rows), "next_id": 0})
            ack_to = max(x["id"] for x in rows)
            base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
            rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
                reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
            ab.ack("peer", ack_to, db=self.db)
            self.steps.append((base, tgt))
        self.entries = bn.export(self.log, 1)
        self.audit = ab.audit_export("peer", db=self.db)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def cross(self, entries):
        out = bn._audit_cross(entries, "peer", self.audit, entries_all=entries)
        return {d["type"]: d for d in out}

    def _without_ack(self, which):
        """A naplóból a `which`-edik (0-alapú) ack-bejegyzés kiesik — minden más marad."""
        drop_to = self.steps[which][1]
        return [e for e in self.entries
                if not (e.get("kind") == "ack" and isinstance(e.get("cursor"), dict) and e["cursor"].get("to") == drop_to)]

    def test_precondition_three_audit_ack_rows(self):
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(len(acks), 3)
        self.assertEqual([(a["from_id"], a["to_id"]) for a in acks], self.steps)

    def test_control_honest_export_is_silent_on_pairing_and_coverage(self):
        r = self.cross(self.entries)
        for t in ("audit_cursor_mismatch", "audit_row_missing", "audit_row_unlogged"):
            self.assertNotIn(t, r, r)

    def test_dropped_middle_ack_does_not_accuse_the_honest_third(self):
        # az egyik kar (b): a 2. napló-ack kiesik; a 3. napló-ack lépése (pl. 20→30) BÁJTRA egyezik a 3. audit-sorral
        r = self.cross(self._without_ack(1))
        self.assertNotIn("audit_cursor_mismatch", r, r)          # a becsületes 3. ack NEM kap vádat
        self.assertIn("audit_row_unlogged", r, r)
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(r["audit_row_unlogged"]["audit_seq"], [acks[1]["seq"]])   # a HIÁNYZÓ sor a néven nevezve
        self.assertEqual(r["audit_row_unlogged"]["steps"], [list(self.steps[1])])

    def test_audit_rows_without_log_ack_are_named(self):
        # az egyik kar (a): 2/3, 1/3 és 0/3 — mind néma volt
        for drop in ([1], [0, 1], [0, 1, 2]):
            ents = self.entries
            for w in drop:
                to = self.steps[w][1]
                ents = [e for e in ents if not (e.get("kind") == "ack" and isinstance(e.get("cursor"), dict)
                                                and e["cursor"].get("to") == to)]
            r = self.cross(ents)
            self.assertIn("audit_row_unlogged", r, (drop, r))
            self.assertEqual(r["audit_row_unlogged"]["audit_ack_rows"], 3)
            self.assertEqual(r["audit_row_unlogged"]["logged_acks"], 3 - len(drop))
            self.assertEqual(len(r["audit_row_unlogged"]["audit_seq"]), len(drop))

    def test_control_the_other_direction_still_fires(self):
        # napló TÖBBET mond: egy negyedik, hazug ack-bejegyzés → audit_row_missing (a régi kapu változatlan)
        extra = dict(self.entries[-1]); extra = {**extra, "kind": "ack", "decision": "accepted",
                                                "cursor": {"from": 99, "to": 120, "ack": 120}, "recipient": "peer"}
        r = self.cross(self.entries + [extra])
        self.assertIn("audit_row_missing", r, r)
        self.assertIn("audit_cursor_mismatch", r, r)              # a hazug lépéshez nincs audit-sor: a VÁD RÁ mutat
        self.assertEqual(r["audit_cursor_mismatch"]["log"], [99, 120])

    def test_lying_step_is_accused_by_its_own_entry_not_by_position(self):
        # a 2. napló-ack lépését átírjuk: a vád a 2.-ra mutat, a 3. érintetlen marad
        ents = []
        for e in self.entries:
            if e.get("kind") == "ack" and isinstance(e.get("cursor"), dict) and e["cursor"].get("to") == self.steps[1][1]:
                e = {**e, "cursor": {**e["cursor"], "to": e["cursor"]["to"] + 7}}
            ents.append(e)
        r = self.cross(ents)
        self.assertIn("audit_cursor_mismatch", r, r)
        self.assertEqual(r["audit_cursor_mismatch"]["log"], [self.steps[1][0], self.steps[1][1] + 7])
        acks = [a for a in self.audit if str(a.get("op", "")).startswith("ack")]
        self.assertEqual(r["audit_cursor_mismatch"]["audit_seq"], [acks[1]["seq"]])   # a párosítatlan audit-sor
        self.assertNotIn("audit_row_unlogged", r, r)              # a darabszám egyezik: ez eltérés, nem elrejtés


if __name__ == "__main__":
    unittest.main()
