"""szonda (2026-09-16 dél) — a MÁSODIK NYILVÁNTARTÁS (`--bus-audit`) HORGONYTALAN.

Az `af50521` óta a `verify` a napló-szelet farkát (`unverified_tail`), a `9838cf7` óta a szelet ELEJÉT
(`slice_start_seq` / `anchored`) is megköveteli — mert egy belsőleg ép szelet önmagában nem állítás a
teljes naplóról. A `d03d2eb` politikája pedig kimondja: strict/termék-módban a busz saját, hash-láncolt
`cursor_audit` exportja NÉLKÜL nincs zöld lámpa (rc=1, „hiányos bizonyíték").

Ez a fájl azt méri, hogy ugyanez a horgony-követelés a MÁSIK nyilvántartáson HIÁNYZIK:
  * `agent_bus.audit_chain_verify` nem néz genezist és nem néz szelet-kezdetet (az EGY FÜGGVÉNNYEL
    FELJEBB lévő, DB-beli `audit_verify` viszont `_GENESIS`-ből indul — a kettő nem ugyanazt követeli);
  * a naplóba semmi nem köti a lánc fejét (`audit_head` a termék-kódban SEHOL nem hívódik);
  * a `_audit_cross` nem ellenőrzi, hogy az export tényleg a vádlott agenté és hogy a kör ack-sorát
    tartalmazza-e.

Következmény (mérve): a vádlott nem hazudik és nem hamisít — csak RÖVIDEBB, belsőleg ép exportot ad át,
és a `pending_down` hazugság `audit_skipped_contradicts_log` (hard, rc=1) helyett ZÖLDET (rc=0) kap.

A forgatókönyv szó szerint a gyártó saját `test_clamp_lied_with_audit_20260916.py`-jéé; az egyetlen
különbség a `bus_audit=` bemenet alakja. stdlib unittest, hálózat nincs, minden út /tmp alá.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402
import bus_ssh_exchange as ex  # noqa: E402

N_MAIL = 6          # ennyi üzenet vár
N_GIVEN = 2         # ennyit ad ki a vádlott (4 elveszne)


class _Scenario(unittest.TestCase):
    """A vádlott kiad 2-t a 6-ból, a kör-bejegyzésben letagadja a kihagyást (`pending_down`)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp", prefix="ab6-anchor-")
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.p = mock.patch.dict(os.environ, {
            "AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
            "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
            "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_WAKE_STATE_DIR": os.path.join(t, "wakestate"),
            "AGENT_BUS_NOTARY_LOG": self.log, "AGENT_BUS_ENFORCE_DIR": t, "AGENT_DUTY_STATE": os.path.join(t, "duty"),
            "AGENT_BUS_ATTACH_DIR": os.path.join(t, "att"), "AGENT_BUS_AUTO_SIGN": "0", "TMPDIR": t}, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def round(self, lie="pending_down", mail=N_MAIL, given=N_GIVEN, notary=None):
        """Egy kör a VALÓDI kiadási úton; -> (kiadott sorok, ack cél)."""
        n = notary or bn.Notary(self.log, seed=self.seed, checkpoint_every=1)
        rec = lambda **kw: n.record(sender_identity="peer", sender_auth="ssh-key", recipient="peer", **kw)
        for i in range(mail):
            ab.send("hub", "peer", "titkos-%d" % i, db=self.db, mirror=False)
        rows = ab.recv("peer", mark=False, limit=ex.MAX_REPLIES, db=self.db, verify_sds=True)
        allr = [{k: r.get(k) for k in ex._REPLY_KEYS if k in r} for r in rows]
        out = allr[len(allr) - given:]                      # csak a LEGFELSŐ `given` darabot adja ki
        cur = ab.cursor_of("peer", db=self.db)
        gid = {x["id"] for x in out}
        left = [x["id"] for x in allr if x["id"] not in gid]
        c = {"at": cur, "replies": len(out), "pending": len(allr), "next_id": min(left) if left else 0}
        if lie == "pending_down":                           # „nem is maradt kiadatlan"
            c["pending"], c["next_id"] = len(out), 0
        rec(envelope={"identity": "peer", "cursor": cur, "reply_sha256": [bn.envelope_hash(x) for x in out]},
            kind="pickup", decision="accepted", reason="cursor=%d replies=%d" % (cur, len(out)), cursor=c)
        for x in out:
            rec(envelope=x, kind="pickup", decision="delivered", reason="id=%s" % x["id"], cursor={"id": int(x["id"])})
        ab.mark_delivered("peer", [x["id"] for x in out], db=self.db)
        ack_to = max(gid)
        base, tgt = ab.ack_preview("peer", ack_to, db=self.db)
        rec(envelope={"ack": ack_to, "cursor_from": base, "cursor_to": tgt}, kind="ack", decision="accepted",
            reason="cursor %d->%d (ack %d)" % (base, tgt, ack_to), cursor={"from": base, "to": tgt, "ack": ack_to})
        ab.ack("peer", ack_to, db=self.db)
        return out, ack_to

    def verdict(self, bus_audit):
        out, ack_to = self.out, self.ack_to
        receipts = [{"phase": "request", "sent": [], "ack": ack_to, "received": out, "round": "r1"},
                    {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]
        r = bn.reconcile(bn.export(self.log, 1), "peer", receipts, strict=True, trusted_pub=self.pub,
                         bus_audit=bus_audit)
        return {"hard": sorted({d["type"] for d in r["discrepancies"]}), "ok": r["ok"],
                "chain_ok": ab.audit_chain_verify(bus_audit)["ok"] if bus_audit is not None else None}


class AuditSliceIsUnanchored(_Scenario):
    def setUp(self):
        super().setUp()
        self.out, self.ack_to = self.round()
        self.audit = ab.audit_export("peer", db=self.db)

    # ── KONTROLL 1: a TELJES exporttal a hazugság megbukik (a gyártó állítása, reprodukálva) ──
    def test_control_full_export_contradicts_the_lie(self):
        v = self.verdict(self.audit)
        self.assertEqual(v["hard"], ["audit_skipped_contradicts_log"])
        self.assertFalse(v["ok"])

    # ── KONTROLL 2: az előfeltétel — a kihagyást EGYETLEN sor (az ack) hordozza ──
    def test_control_the_evidence_sits_in_one_row(self):
        carry = [a for a in self.audit if int(a.get("skipped_undelivered") or 0)]
        self.assertEqual(len(carry), 1, "a bizonyíték egyetlen sorban van: %s" % json.dumps(self.audit))
        self.assertEqual(carry[0]["seq"], self.audit[-1]["seq"], "és ez a lánc UTOLSÓ sora")

    # ── LELET A: a farok-csonkolt export belsőleg ÉP, és elnémítja az összevetést ──
    def test_tail_truncated_export_must_not_pass_as_evidence(self):
        v = self.verdict(self.audit[:-1])
        self.assertTrue(v["chain_ok"], "előfeltétel: a csonkolt lánc önellenőrzésen ÁTMEGY (nincs hamisítás)")
        self.assertNotEqual(v["hard"], [], "a rövidebb export némán tisztára mosta a hazug kört")

    # ── LELET B: a szelet ELEJE sincs horgonyozva (a DB-beli audit_verify viszont genezisből indul) ──
    def test_chain_verify_must_anchor_the_slice_start(self):
        self.assertTrue(ab.audit_verify("peer", db=self.db)["ok"], "előfeltétel: a DB-lánc ép")
        chk = ab.audit_chain_verify(self.audit[1:])
        self.assertFalse(chk["ok"], "a genezis nélkül induló szelet ÖNMAGÁBAN nem lehet 'ok' (vö. audit_verify)")

    # ── LELET C: a `from_seq` a TÁMOGATOTT API — egy hívással eltüntethető a régi kör bizonyítéka ──
    def test_supported_from_seq_slice_must_not_hide_an_older_round(self):
        first_head = ab.audit_head("peer", db=self.db)[0]
        self.round(lie=None, mail=2, given=2)                 # második, BECSÜLETES kör
        later = ab.audit_export("peer", from_seq=first_head + 1, db=self.db)
        # SZERZŐDÉS-VÁLTOZÁS (2026-09-16, az ő MÁSIK szondája miatt): az `ok` mostantól a SZIGORÚBB
        # jelentést hordozza (ép ÉS horgonyzott), a szelet épségét a `chain_ok` mondja. Ez az ELŐFELTÉTEL
        # az épségre kérdez — a szonda LELETE (a késői szelet ne rejtsen el egy korábbi kört) változatlan.
        self.assertTrue(later and ab.audit_chain_verify(later)["chain_ok"], "előfeltétel: a késői szelet ép")
        v = self.verdict(later)
        self.assertNotEqual(v["hard"], [], "a `from_seq` szelet eltüntette az ELSŐ kör kihagyását")

    # ── LELET D: az export IDENTITÁSA nincs ellenőrizve — idegen agent naplója zöld lámpát ad ──
    def test_foreign_agent_export_must_not_count_as_the_second_register(self):
        ab.send("hub", "other", "x", db=self.db, mirror=False)
        ab.recv("other", mark=False, db=self.db)
        ab.ack("other", 1, db=self.db)
        foreign = ab.audit_export("other", db=self.db)
        self.assertTrue(foreign, "előfeltétel: az idegen agentnek van saját lánca")
        v = self.verdict(foreign)
        self.assertNotEqual(v["hard"], [], "egy IDEGEN agent audit-exportja teljes értékű bizonyítéknak számított")

    # ── LELET E: a naplóban nincs horgony a lánc fejére (audit_head a termék-kódban holt) ──
    def test_round_entry_should_anchor_the_audit_head(self):
        seq, rh = ab.audit_head("peer", db=self.db)
        self.assertTrue(rh, "előfeltétel: van lánc-fej")
        rounds = [e for e in bn.export(self.log, 1)
                  if e.get("kind") == "pickup" and isinstance(e.get("cursor"), dict) and "pending" in e["cursor"]]
        self.assertTrue(rounds, "előfeltétel: van gépi mezős kör-bejegyzés")
        self.assertTrue(any(k in rounds[-1]["cursor"] for k in ("audit_seq", "audit_hash")),
                        "a kör-bejegyzés nem köti meg a busz audit-láncának fejét: %s" % json.dumps(rounds[-1]["cursor"]))


class CliVerdictFlipsWithAShorterFile(_Scenario):
    """Ugyanez a CLI rc-jén — ez a szám, amit az üzemeltető lát."""

    def setUp(self):
        super().setUp()
        self.out, self.ack_to = self.round()
        t = self.tmp.name
        self.exp, self.rp = os.path.join(t, "exp.jsonl"), os.path.join(t, "r.jsonl")
        with open(self.exp, "w", encoding="utf-8") as f:
            for e in bn.export(self.log, 1):
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        with open(self.rp, "w", encoding="utf-8") as f:
            for r in ({"phase": "request", "sent": [], "ack": self.ack_to, "received": self.out, "round": "r1"},
                      {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def audit_file(self, rows, name):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", encoding="utf-8") as f:
            for a in rows:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
        return p

    def rc(self, audit_path=None):
        args = ["reconcile", self.exp, "--identity", "peer", "--receipts", self.rp, "--pub", self.pub, "--strict"]
        if audit_path:
            args += ["--bus-audit", audit_path]
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = bn.main(args)
        return code, err.getvalue()

    def test_control_full_file_is_red_and_missing_file_is_red(self):
        rows = ab.audit_export("peer", db=self.db)
        self.assertEqual(self.rc(self.audit_file(rows, "full.jsonl"))[0], 1, "teljes export: rc=1 (ellentmondás)")
        self.assertEqual(self.rc(None)[0], 1, "export nélkül: rc=1 (hiányos bizonyíték)")

    def test_shorter_file_must_not_turn_the_light_green(self):
        rows = ab.audit_export("peer", db=self.db)
        code, err = self.rc(self.audit_file(rows[:-1], "short.jsonl"))
        self.assertEqual(code, 1, "egy sorral rövidebb, ÉP láncú export → rc=%d, stderr=%r" % (code, err.strip()))


class TheDocumentedProducerDoesNotExist(unittest.TestCase):
    """A kikényszerített politika (`rc=1, hiányos bizonyíték`) egy NEM LÉTEZŐ parancsra küldi az üzemeltetőt."""

    def test_agent_bus_audit_export_subcommand_exists(self):
        self.assertIn("audit-verify", _subcommands(), "kontroll: a létező alparancsot a szonda megtalálja")
        self.assertIn("audit-export", _subcommands(),
                      "a --bus-audit súgója és a strict rc=1 üzenete is 'agent_bus.py audit-export <agent>'-re küld")


def _subcommands():
    import argparse
    seen = []
    real = argparse._SubParsersAction.add_parser

    def spy(self, name, **kw):
        seen.append(name)
        return real(self, name, **kw)
    with mock.patch.object(argparse._SubParsersAction, "add_parser", spy), \
            mock.patch.object(sys, "argv", ["agent_bus.py", "--help"]):
        try:
            ab.main([])
        except SystemExit:
            pass
    return seen


if __name__ == "__main__":
    unittest.main()
