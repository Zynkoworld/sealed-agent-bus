"""v1.5 — a közjegyzői napló KIMENŐ iránya az SSH-határon + reconcile.

a partner-kar 3 piros tesztje (test_joint_outbound_notary.py) azt kéri, hogy a kiadott válaszokról és az ack-ról legyen
bejegyzés, és hogy az elnyelt posta lássék. Ezek a tesztek a megoldás tulajdonságait rögzítik: naplózás-előbb (naplóhiba
-> nincs kiadás, nincs kurzor-mozgás), napló-horgony a válaszban, üres kör nem ír zajt, és a `reconcile` a távoli fél
nyugtáiból kimutatja a kihagyást, amit a seq-rés nem mutat. stdlib unittest + cryptography."""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_notary as bn  # noqa: E402


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.log = os.path.join(t, "notary.jsonl")
        self.db = os.path.join(t, "bus.db")
        self.seed, self.pub = bn.keypair()
        self.notary = bn.Notary(self.log, seed=self.seed, checkpoint_every=50)
        self.env = {"AGENT_BUS_DB": self.db, "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t, "AGENT_BUS_MODE": "dev",
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_NOTARY_LOG": self.log,
                    "AGENT_BUS_AUTO_SIGN": "0"}
        self.p = mock.patch.dict(os.environ, self.env, clear=False)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def x(self, payload, notary=None):
        import bus_ssh_exchange as ex
        return ex.exchange("remote1", json.dumps(payload), db=self.db, attach_root=os.path.join(self.tmp.name, "att"),
                           notary=notary or self.notary)

    def queue(self, n, prefix="ki"):
        for i in range(n):
            ab.send("hub", "remote1", "%s-%d" % (prefix, i), db=self.db, mirror=False)

    def entries(self):
        return [r for r in bn.read_lines(self.log) if r.get("type") == "entry"]


class OutboundLogFirst(_Base):
    def test_replies_and_ack_are_logged_with_hashes_the_receiver_can_recompute(self):
        self.queue(2)
        res = self.x({})
        ents = self.entries()
        # A ZÁRÓ horgony (támadási mátrix 2.7) a mellékhatások UTÁN, a kör végén íródik — a naplózás-előbb
        # sorrend változatlan: a kiadás-bejegyzések a kiadás ELŐTT, a zárás az egész UTÁN.
        self.assertEqual([(e["kind"], e["decision"], e["reason"]) for e in ents],
                         [("pickup", "accepted", "cursor=0 replies=2")] +
                         [("pickup", "delivered", "id=%d" % m["id"]) for m in res["replies"]] +
                         [("round_close", "accepted", "close replies=2")])
        self.assertEqual([e["envelope_sha256"] for e in ents[1:3]], [bn.envelope_hash(m) for m in res["replies"]])
        n0 = len(ents)
        top = max(m["id"] for m in res["replies"])
        self.x({"ack": top})
        self.assertEqual([(e["kind"], e["reason"]) for e in self.entries()[n0:]],
                         [("ack", "cursor 0->%d (ack %d)" % (top, top)), ("pickup", "cursor=%d replies=0" % top),
                          ("round_close", "close replies=0")])
        self.assertTrue(bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)["ok"])

    def test_response_carries_the_notary_anchor_of_the_round(self):
        self.queue(1)
        res = self.x({})
        last = self.entries()[-1]
        self.assertEqual(res["notary"], {"seq": last["seq"], "head_hash": last["entry_hash"]})

    def test_notary_failure_hands_out_nothing_and_moves_no_cursor(self):
        self.queue(2)
        with mock.patch.object(self.notary, "record", side_effect=OSError(28, "No space left on device")):
            res = self.x({})
            self.assertEqual(res["error"], "notary write failed (fail-closed)")
            self.assertEqual(res["replies"], [])
            res2 = self.x({"ack": 2})
            self.assertEqual(res2["error"], "notary write failed (fail-closed)")
        self.assertEqual(ab.cursor_of("remote1", db=self.db), 0)
        self.assertEqual(self.entries(), [])

    def test_partial_failure_logs_before_hand_out_never_after(self):
        """Az első `delivered` után bukik a napló: túl-naplózás (1 bejegyzés, 0 kiadás) megengedett, fordítva nem."""
        self.queue(3)
        real, n = self.notary.record, {"i": 0}

        def flaky(**kw):
            n["i"] += 1
            if n["i"] > 2:
                raise OSError("disk full")
            return real(**kw)
        with mock.patch.object(self.notary, "record", side_effect=flaky):
            res = self.x({})
        self.assertEqual(res["replies"], [])
        self.assertEqual([e["decision"] for e in self.entries()], ["accepted", "delivered"])

    def test_ack_failure_after_logging_adds_a_rejected_entry(self):
        self.queue(1)
        with mock.patch.object(ab, "ack", side_effect=RuntimeError("database is locked")):
            self.x({"ack": 1})
        acks = [(e["decision"], e["reason"]) for e in self.entries() if e["kind"] == "ack"]
        self.assertEqual(acks, [("accepted", "cursor 0->1 (ack 1)"), ("rejected", "ack_failed")])
        self.assertEqual(ab.cursor_of("remote1", db=self.db), 0)

    def test_empty_poll_with_unchanged_cursor_writes_no_entry(self):
        for _ in range(3):
            self.x({})
        self.assertEqual(self.entries(), [])


class Reconcile(_Base):
    def rounds(self, *payloads):
        out = []
        for p in payloads:
            res = self.x(p)
            out.append({"sent": p.get("messages", []), "ack": p.get("ack", 0), "received": res["replies"]})
        return out

    def test_clean_rounds_reconcile(self):
        self.queue(2)
        r1 = self.rounds({"messages": [{"to": "hub", "body": "hello", "sig": "ignored-by-exchange"}]})
        top = max(m["id"] for m in r1[0]["received"])
        r2 = self.rounds({"ack": top})
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", r1 + r2, trusted_pub=self.pub)
        self.assertEqual((rep["ok"], rep["discrepancies"], rep["unconfirmed_deliveries"]), (True, [], []))

    def test_reconcile_detects_omitted_inbound(self):
        """A kihagyás NEM ad seq-rést (verify ok) — a reconcile igen."""
        real, n = self.notary.record, {"i": 0}

        def skip_second(**kw):
            n["i"] += 1
            return {} if n["i"] == 2 else real(**kw)
        sent = [{"to": "hub", "body": "u-%d" % i} for i in range(3)]
        with mock.patch.object(self.notary, "record", side_effect=skip_second):
            res = self.x({"messages": sent})
        self.assertEqual(len(res["accepted"]), 3)
        recs = bn.export(self.log, 1)
        self.assertTrue(bn.verify(recs, trusted_pub=self.pub)["ok"])
        rep = bn.reconcile(recs, "remote1", [{"sent": sent, "ack": 0, "received": res["replies"]}])
        self.assertFalse(rep["ok"])
        self.assertEqual([(d["type"], d["envelope_sha256"]) for d in rep["discrepancies"]],
                         [("sent_not_logged", bn.envelope_hash(sent[1]))])

    def test_reconcile_detects_withheld_outbound(self):
        self.queue(4, "soha")
        ab.ack("remote1", 4, db=self.db)                        # a busz-gép napló nélkül elnyeli a postát
        res = self.x({})
        self.assertEqual(res["replies"], [])
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", [{"sent": [], "ack": 0, "received": []}])
        self.assertEqual(rep["discrepancies"],
                         [{"type": "cursor_moved_without_logged_ack", "seq": 1, "cursor": 4, "expected": 0}])

    def test_reconcile_failed_ack_does_not_count_as_a_cursor_move(self):
        """ack_failed után a kurzor nem mozdult: a következő kör kurzora a régi, és ez NEM eltérés."""
        self.queue(2)
        r1 = self.rounds({})
        with mock.patch.object(ab, "ack", side_effect=RuntimeError("database is locked")):
            r2 = self.rounds({"ack": 2})
        r3 = self.rounds({})
        self.assertEqual([e["reason"] for e in self.entries() if e["kind"] == "ack"], ["cursor 0->2 (ack 2)", "ack_failed"])
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", r1 + r2 + r3)
        self.assertEqual(rep["discrepancies"], [])
        self.assertTrue(rep["unconfirmed_deliveries"] == [] or all(u["received"] > 0 for u in rep["unconfirmed_deliveries"]))

    def test_two_way_forged_ack_and_unreceived_delivery_are_discrepancies(self):
        """36Z: a napló állításai a nyugtához is mérve (ack_logged_not_sent, delivered_not_received)."""
        self.queue(1)
        res = self.x({})                                        # 1 válasz kiadva és naplózva
        self.notary.record(envelope={"ack": 1}, sender_identity="remote1", sender_auth="ssh-key", recipient="remote1",
                           kind="ack", decision="accepted", reason="cursor 0->1 (ack 1)")   # kitalált ack
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", [{"sent": [], "ack": 0, "received": []}])
        self.assertFalse(rep["ok"])
        self.assertEqual(sorted(d["type"] for d in rep["discrepancies"]), ["ack_logged_not_sent", "delivered_not_received"])
        self.assertEqual(len(res["replies"]), 1)

    def test_cli_delivered_not_received_rc_dev_warns_strict_and_product_fail(self):
        self.queue(1)
        self.x({})
        t = self.tmp.name
        exp, rcp = os.path.join(t, "e.jsonl"), os.path.join(t, "r.jsonl")
        with open(exp, "w") as f:
            f.write("\n".join(json.dumps(r) for r in bn.export(self.log, 1)) + "\n")
        with open(rcp, "w") as f:
            f.write(json.dumps({"sent": [], "ack": 0, "received": []}) + "\n")

        def run(mode, *extra):
            return subprocess.run([sys.executable, os.path.join(HERE, "bus_notary.py"), "reconcile", exp, "--identity",
                                   "remote1", "--receipts", rcp] + list(extra),
                                  capture_output=True, text=True, env=dict(os.environ, AGENT_BUS_MODE=mode))
        dev = run("dev")
        self.assertEqual(dev.returncode, 0)
        self.assertIn("delivered_not_received", dev.stderr)
        self.assertFalse(json.loads(dev.stdout)["ok"])
        self.assertEqual(run("dev", "--strict").returncode, 1)
        self.assertEqual(run("product").returncode, 1)

    def test_reconcile_detects_unlogged_delivery_and_unlogged_ack(self):
        self.queue(1)
        r = self.rounds({})
        recs = [e for e in bn.export(self.log, 1) if not (e.get("type") == "entry" and e.get("decision") == "delivered")]
        rep = bn.reconcile(recs, "remote1", r + [{"sent": [], "ack": 1, "received": []}])
        types = sorted(d["type"] for d in rep["discrepancies"])
        self.assertEqual([t for t in types if t != "verify_error"],
                         ["ack_sent_not_logged", "received_not_logged"])
        # 2026-09-16: ez a fixtúra a SAJÁT exportjából KITÖRÖL egy bejegyzést — attól a hash-lánc valóban
        # törik, és a jelentés eddig csak a TÜNETET nevezte meg („a kézbesítés nincs naplózva"), a LYUKAT
        # magát nem. Egy naplóból kivágott sor viszont sokkal súlyosabb vád, mint egy hiányzó nyugta, és a
        # `verify()` tudta is — a `reconcile` dobta el. Innentől kimondjuk.
        errs = sorted(d["error"] for d in rep["discrepancies"] if d["type"] == "verify_error")
        self.assertEqual(len(errs), 2, "a kivágott sor nyoma nincs megnevezve: %r" % errs)
        self.assertTrue(any("gap" in e for e in errs), errs)
        self.assertTrue(any("chain broken" in e for e in errs), errs)


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class ClientReceiptsEndToEnd(_Base):
    """A valódi kliens (bus_ssh_client) nyugta-fájlja + a `bus_notary reconcile` CLI, hamis ssh-val."""

    def _fake_ssh(self):
        path = os.path.join(self.tmp.name, "fake_ssh.py")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""
                import sys
                sys.path.insert(0, %r)
                import bus_ssh_exchange
                sys.exit(bus_ssh_exchange.main(["remote1"]))
            """ % HERE))
        return [sys.executable, path]

    def test_receipts_reconcile_clean_then_flag_a_withheld_cursor_jump(self):
        import bus_ssh_client as cli
        key = os.path.join(self.tmp.name, "notary.key")
        with open(key, "w") as f:
            f.write(self.seed.hex())
        state, local_db = os.path.join(self.tmp.name, "state"), os.path.join(self.tmp.name, "local.db")
        with mock.patch.dict(os.environ, {"AGENT_BUS_NOTARY": "on", "AGENT_BUS_NOTARY_KEY": key}):
            ab.send("hub", "remote1", "első", db=self.db, mirror=False)
            cli.exchange("bus", "me", [{"to": "hub", "body": "szia"}], ssh_cmd=self._fake_ssh(), state_dir=state, db=local_db)
            cli.exchange("bus", "me", [], ssh_cmd=self._fake_ssh(), state_dir=state, db=local_db)   # ack 1
            receipts = cli.receipts_path(state, "bus", "me")
            exp = os.path.join(self.tmp.name, "export.jsonl")

            def run():
                with open(exp, "w") as fh:
                    for r in bn.export(self.log, 1):
                        fh.write(json.dumps(r, sort_keys=True) + "\n")
                return subprocess.run([sys.executable, os.path.join(HERE, "bus_notary.py"), "reconcile", exp,
                                       "--identity", "remote1", "--receipts", receipts, "--pub", self.pub],
                                      capture_output=True, text=True)
            p = run()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            ab.send("hub", "remote1", "elnyelendő", db=self.db, mirror=False)
            ab.ack("remote1", 10 ** 6, db=self.db)                  # a busz-gép előreugratja a kurzort
            cli.exchange("bus", "me", [], ssh_cmd=self._fake_ssh(), state_dir=state, db=local_db)
            p = run()
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertEqual([d["type"] for d in json.loads(p.stdout)["discrepancies"]], ["cursor_moved_without_logged_ack"])


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(bn.HAVE_CRYPTO, "cryptography missing")
class CursorTargetAndOutcomes(_Base):
    """37Z: a kurzor-cél kötése a naplóból (verify is), a kör-kimenetel a nyugtában, a --pub alak."""

    def _dump(self, name, rows):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in rows))
        return p

    def test_verify_reports_a_cursor_target_beyond_max_from_ack(self):
        self.queue(1)
        self.x({"ack": 1})                                      # becsületes: cursor 0->1 (ack 1)
        self.assertEqual(bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)["ack_target_violations"], [])
        self.notary.record(envelope={"ack": 1}, sender_identity="remote1", sender_auth="ssh-key", recipient="remote1",
                           kind="ack", decision="accepted", reason="cursor 1->9 (ack 1)")
        self.notary.checkpoint()
        rep = bn.verify(bn.export(self.log, 1), trusted_pub=self.pub)
        self.assertTrue(rep["ok"] and rep["trusted"])            # a lánc aláírtan ép ...
        self.assertEqual([v["reason"] for v in rep["ack_target_violations"]], ["cursor 1->9 (ack 1)"])   # ... és hazug
        exp = self._dump("e.jsonl", bn.export(self.log, 1))
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(bn.main(["verify", exp, "--pub", self.pub]), 1)

    def test_unknown_outcome_is_unresolved_not_an_accusation(self):
        rows = [{"phase": "request", "round": "r1", "sent": [{"to": "hub", "body": "talán"}], "ack": 3, "received": []},
                {"phase": "outcome", "round": "r1", "outcome": "unknown"}]
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", rows, strict=False)
        self.assertEqual((rep["ok"], rep["discrepancies"]), (True, []))
        self.assertEqual(sorted(u["type"] for u in rep["unresolved"]), ["ack_outcome_unknown", "sent_outcome_unknown"])
        self.assertFalse(bn.reconcile(bn.export(self.log, 1), "remote1", rows, strict=True)["ok"])
        exp, rp = self._dump("e.jsonl", bn.export(self.log, 1)), self._dump("r.jsonl", rows)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(bn.main(["reconcile", exp, "--identity", "remote1", "--receipts", rp]), 0)
            self.assertEqual(bn.main(["reconcile", exp, "--identity", "remote1", "--receipts", rp, "--strict"]), 1)
            with mock.patch.dict(os.environ, {"AGENT_BUS_MODE": "product"}):
                self.assertEqual(bn.main(["reconcile", exp, "--identity", "remote1", "--receipts", rp,
                                          "--pub", self.pub]), 1)

    def test_client_ssh_that_cannot_start_records_not_sent(self):
        import bus_ssh_client as cli
        state = os.path.join(self.tmp.name, "state")
        res = cli.exchange("bus", "me", [{"to": "hub", "body": "x"}], ssh_cmd=[os.path.join(self.tmp.name, "nincs-ilyen")],
                           state_dir=state, db=os.path.join(self.tmp.name, "l.db"))
        self.assertIn("error", res)
        rows = [json.loads(l) for l in open(cli.receipts_path(state, "bus", "me"))]
        self.assertEqual([(r["phase"], r.get("outcome")) for r in rows], [("request", None), ("outcome", "not-sent")])
        rep = bn.reconcile(bn.export(self.log, 1), "remote1", rows, strict=True)
        self.assertEqual((rep["ok"], rep["discrepancies"], rep["unresolved"]), (True, [], []))

    def test_pub_given_as_a_path_is_named_not_silently_failed(self):
        exp = self._dump("e.jsonl", bn.export(self.log, 1))
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()) as err, mock.patch("sys.stdout"):
            self.assertEqual(bn.main(["verify", exp, "--pub", "/etc/notary.pub"]), 2)
        self.assertIn("nem fájl-út", err.getvalue())
