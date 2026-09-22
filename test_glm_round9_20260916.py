"""A partner-kar blokkoló javításának ellenséges újramérése.

A javítás: a kör-bejegyzésbe a KÖZJEGYZŐ írja a busz audit-láncának fejét (`audit_seq` + `audit_hash`), és az
összevetés megköveteli, hogy a MÁSODIK NYILVÁNTARTÁS exportja elérjen odáig. A nem-Claude kar négy utat talált,
amin a rövidebb/hamis export MÉGIS zöldet adott volna:

  9/1  a horgony ÍRÁSA fail-open (kivételnél kimarad) -> horgony nélkül nincs mit számon kérni.
       Javítás: a horgony hiánya HARMADIK ÁLLAPOT (`audit_anchor_absent`, unresolved -> strict-ben ok:false).
  9/2  a könyvtári út nem futtatta a lánc-önellenőrzést (csak a CLI) -> egy seq-HÉZAGOS export átment.
       Javítás: `audit_chain_broken`.
  9/3  a horgonyból csak a seq-et kértük, a HASH-t nem -> a sorok tartalma kicserélhető volt újraláncolással.
       Javítás: `audit_head_hash_mismatch` (a genezis-horgony esetén: az exportnak a 0. sortól kell indulnia).
  9/4  az ÜRESEN átadott export a könyvtári úton némán 0 vizsgálandó sorra szűkült.
       Javítás: `audit_evidence_absent`.

A forgatókönyv az egyik kar `test_joint_audit_anchor_20260916.py`-jéé: 6 üzenetből 2 megy ki, a kör letagadja a
kihagyást (`pending_down`), a busz audit-sora viszont tudja az igazságot.

stdlib unittest + cryptography. Hálózat nincs, minden út /tmp alá.
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

N_MAIL, N_GIVEN = 6, 2


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography szükséges")
class AnchorUnderAttack(unittest.TestCase):
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
        self.out, self.ack_to = self._round()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def _round(self):
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(N_MAIL):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[len(allr) - N_GIVEN:]
        cur = ab.cursor_of("peer", db=self.db)
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)),
            cursor={"at": cur, "replies": len(out), "pending": len(out), "next_id": 0})   # a HAZUGSÁG
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(x["id"] for x in out)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        return out, ack_to

    def verdict(self, bus_audit):
        receipts = [{"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=True, trusted_pub=self.pub,
                         bus_audit=bus_audit)
        return {"ok": r["ok"], "hard": sorted({d["type"] for d in r["discrepancies"]}),
                "soft": sorted({u["type"] for u in r["unresolved"]})}

    # ── kontroll: a teljes export elkapja a hazugságot, és a horgony ott van ──
    def test_control_full_export_contradicts_the_lie(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertIn("audit_skipped_contradicts_log", self.verdict(rows)["hard"])
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]]
        self.assertIn("audit_hash", rounds[-1]["cursor"], "a közjegyző beírta a lánc-fejet")

    # ── 9/4: üres export ────────────────────────────────────────────────────
    def test_empty_export_is_absent_evidence(self):
        v = self.verdict([])
        self.assertIn("audit_evidence_absent", v["hard"], "az üresen átadott export némán 0 sorra szűkült")
        self.assertFalse(v["ok"])

    # ── 9/2: seq-hézagos export ─────────────────────────────────────────────
    def test_seq_gap_export_is_caught_on_the_library_path(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertGreaterEqual(len(rows), 3, "előfeltétel: van legalább 3 audit-sor")
        gapped = [rows[0]] + rows[2:]                    # a KÖZÉPSŐ sor kihagyva: a lánc hézagos
        v = self.verdict(gapped)
        self.assertIn("audit_chain_broken", v["hard"], "a hézagos export a könyvtári úton átment")
        self.assertFalse(v["ok"])

    # ── 9/3: újraláncolt, KICSERÉLT tartalom — a KÉSŐBBI kör horgonya köti ──
    def test_rechained_content_is_caught_by_a_later_round_anchor(self):
        """A horgony a kör ELEJÉN íródik, tehát a saját köre ack-sorát még nem köti — a KÖVETKEZŐ köré igen.

        MÉRT KORLÁT (kimondva): egy EGYKÖRÖS szeletben a második nyilvántartás következetes újraláncolása nem
        bukik le — ez ugyanaz a kimondott korlát, hogy mindkét nyilvántartást ugyanaz a fél írja. Amint van egy
        KÉSŐBBI kör-bejegyzés, annak horgonya (`audit_seq` + `audit_hash`) a korábbi sorok tartalmát is köti.
        """
        n = bn.Notary(self.log, seed=self.seed, checkpoint_every=1, db=self.db)   # második, becsületes kör
        cur = ab.cursor_of("peer", db=self.db)
        n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer",
                 envelope={"identity": "peer", "cursor": cur, "reply_sha256": []}, kind="pickup",
                 decision="accepted", reason="cursor=%d replies=0" % cur,
                 cursor={"at": cur, "replies": 0, "pending": 0, "next_id": 0})
        rows = [dict(r) for r in ab.audit_export("peer", db=self.db)]
        anchored = [e for e in bn.export(self.log, 1) if e.get("kind") == "pickup"
                    and isinstance(e.get("cursor"), dict) and "audit_seq" in e["cursor"]]
        want = anchored[-1]["cursor"]["audit_seq"]
        self.assertTrue(any(r["seq"] == want for r in rows), "előfeltétel: a horgony egy LÉTEZŐ sorra mutat")
        rows[-1]["skipped_undelivered"] = 0               # a BIZONYÍTÉK eltüntetése
        prev = rows[0]["prev_row_hash"]
        for r in rows:                                    # újraláncolás: a lánc belsőleg ÉP lesz
            r["prev_row_hash"] = prev
            r["row_hash"] = ab._audit_row_hash(r["seq"], r["ts"], r["agent"], r["op"], r["from_id"], r["to_id"],
                                               r["skipped_undelivered"], prev)
            prev = r["row_hash"]
        self.assertTrue(ab.audit_chain_verify(rows)["ok"], "előfeltétel: az újraláncolt export belsőleg ÉP")
        v = self.verdict(rows)
        self.assertIn("audit_head_hash_mismatch", v["hard"],
                      "az újraláncolt export a KÉSŐBBI kör horgonyával sem került ellentmondásba: %r" % (v,))
        self.assertFalse(v["ok"])

    # ── 9/1: a horgony KIMARADÁSA harmadik állapot ──────────────────────────
    def test_missing_anchor_is_a_third_state(self):
        entries = []
        for e in bn.export(self.log, 1):
            if (e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]):
                c = {k: v for k, v in e["cursor"].items() if k not in ("audit_seq", "audit_hash")}
                e = dict(e, cursor=c)                     # a horgony „kimaradt" (fail-open írás)
            entries.append(e)
        receipts = [{"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(entries, "peer", receipts, strict=True, bus_audit=ab.audit_export("peer", db=self.db))
        self.assertIn("audit_anchor_absent", {u["type"] for u in r["unresolved"]},
                      "horgony nélkül nincs mit számon kérni, és ez nem látszott")
        self.assertFalse(r["ok"], "strict módban a hiányzó horgony nem lehet zöld")


if __name__ == "__main__":
    unittest.main()
