"""The silent-failure detector: a delivery the transport ACCEPTED and the receiving side never PROCESSED.

The bus already proves a great deal about delivery. What it could not say anything about was the step after it.
`recv --mark` (and `mark_delivered` on the SSH tier) records that the message was handed over; nothing recorded
whether anyone acted on it. So a handler that returns early, filters the message away, or swallows its own
exception left a bus that looks perfectly healthy: the row is read, the cursor moved, `reconcile` is empty — and
the message is gone. `reconcile` answers "what did the cursor step over without delivering"; this answers the
question next to it, "what was delivered into a void", and the two together leave no silent hole.

The comparison is between two facts that both live in the hash-chained `cursor_audit`: the ids the chain records as
delivered, and the ids carrying a `processed` row. No new table, no new dependency.

Measured here: the detector must go RED on a silent drop and stay QUIET on a processed message; it must name the
dropped ids exactly, not the whole page; a receiver must not be able to claim processing for mail it was never
given; and the new rows must stay inside the tamper-evident chain.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


class ProcessingGap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.env = {"AGENT_BUS_DB": os.path.join(t, "b.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_MODE": "dev",
                    "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"), "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"),
                    "AGENT_WAKE_DIR": os.path.join(t, "wake"), "AGENT_BUS_AUTO_SIGN": "0"}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        global ab
        import agent_bus as ab  # noqa: E402 — after the environment, like every other bus test here
        self.db = self.env["AGENT_BUS_DB"]

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    # ── the two sides of the bus, as small as they can be ───────────────────────────────────────────────
    def deliver(self, n, to="worker"):
        for i in range(1, n + 1):
            ab.send("hub", to, "task-%d" % i, topic="work", db=self.db, mirror=False)

    def consume(self, agent, handler):
        """A minimal receiving side: take the delivered page, acknowledge ONLY what the handler really processed.

        That is the whole contract. The transport accepts the page either way — the ack has to be EARNED. A handler
        that swallows its exception has nothing to acknowledge, and the gap is what says so out loud."""
        done = []
        for m in ab.recv(agent, mark=True, db=self.db):
            try:
                handler(m)
            except Exception:
                continue                       # the swallowing handler: exactly the bug this detector exists for
            done.append(m["id"])
        ab.mark_processed(agent, done, db=self.db)
        return done

    def ops(self, agent="worker"):
        return [(r["op"], r["from_id"]) for r in ab.audit_export(agent, db=self.db)]

    # ── the detector ───────────────────────────────────────────────────────────────────────────────────
    def test_a_swallowed_message_is_reported_as_a_silent_drop(self):
        self.deliver(1)
        self.consume("worker", lambda m: (_ for _ in ()).throw(RuntimeError("the handler falls over, quietly")))
        gap = ab.processing_gap("worker", db=self.db)
        self.assertEqual([g["id"] for g in gap], [1], "an accepted delivery nobody processed stayed invisible")
        self.assertEqual(gap[0]["sender"], "hub")
        self.assertIn("no proof-of-processing ack", gap[0]["why"])

    def test_a_processed_message_is_not_reported(self):
        self.deliver(1)
        handled = []
        self.assertEqual(self.consume("worker", handled.append), [1])
        self.assertEqual(handled[0]["body"], "task-1")
        self.assertEqual(ab.processing_gap("worker", db=self.db), [], "a processed message must not be accused")

    def test_the_dropped_ids_are_named_exactly_not_the_whole_page(self):
        """A page is not all-or-nothing: the detector has to point at the ids that were really dropped."""
        self.deliver(4)

        def flaky(m):
            if m["id"] % 2 == 0:
                raise ValueError("this one is swallowed")
        self.assertEqual(self.consume("worker", flaky), [1, 3])
        self.assertEqual([g["id"] for g in ab.processing_gap("worker", db=self.db)], [2, 4])

    def test_the_transport_sees_nothing_wrong_which_is_the_whole_point(self):
        """Everything the bus measured BEFORE this detector stays green on a silent drop — that was the hole.

        The message is read, the cursor is at the top, the delivered high-water covers it and `reconcile` — which
        answers a DIFFERENT question, what the cursor skipped WITHOUT delivery — is empty. Only the processing
        comparison has anything to say."""
        self.deliver(2)
        self.consume("worker", lambda m: (_ for _ in ()).throw(RuntimeError("swallowed")))
        self.assertEqual(ab.cursor_of("worker", db=self.db), 2)
        self.assertEqual(ab.reconcile("worker", db=self.db), [], "reconcile is the wrong detector for this failure")
        self.assertEqual(ab.delivered_ids("worker", db=self.db), [1, 2])
        self.assertEqual([g["id"] for g in ab.processing_gap("worker", db=self.db)], [1, 2])

    def test_the_grace_window_does_not_accuse_a_message_still_in_flight(self):
        self.deliver(1)
        self.consume("worker", lambda m: (_ for _ in ()).throw(RuntimeError("swallowed")))
        self.assertEqual(ab.processing_gap("worker", grace_s=3600, db=self.db), [],
                         "a delivery from a second ago is in flight, not a drop")
        self.assertEqual([g["id"] for g in ab.processing_gap("worker", grace_s=0, db=self.db)], [1],
                         "the DEFAULT must report everything outstanding — a detector that hides by default is none")

    def test_a_remote_ssh_tier_delivery_is_covered_too(self):
        """`mark_delivered` is the other way a message reaches a receiving side; the detector must not be blind to it."""
        self.deliver(2)
        self.assertEqual(ab.mark_delivered("worker", [1, 2], db=self.db), 2)
        self.assertEqual(ab.delivered_ids("worker", db=self.db), [1, 2])
        self.assertEqual([g["id"] for g in ab.processing_gap("worker", db=self.db)], [1, 2])
        ab.mark_processed("worker", [1, 2], db=self.db)
        self.assertEqual(ab.processing_gap("worker", db=self.db), [])

    def test_mail_the_cursor_skipped_without_delivering_is_not_accused_here(self):
        """A cursor jump over UNDELIVERED mail is `reconcile`'s finding. Reporting it here too would turn one
        failure into two accusations, and a detector that cries about everything is read as noise."""
        self.deliver(3)
        ab.ack("worker", 3, db=self.db)                       # the cursor moves, nothing was ever delivered
        self.assertEqual(ab.delivered_ids("worker", db=self.db), [])
        self.assertEqual(ab.processing_gap("worker", db=self.db), [])
        self.assertEqual([m["id"] for m in ab.reconcile("worker", db=self.db)], [1, 2, 3])

    # ── the ack cannot be used to buy silence ──────────────────────────────────────────────────────────
    def test_processing_cannot_be_claimed_for_a_message_that_was_never_delivered(self):
        """A receiver that may claim anything can silence the audit by claiming everything."""
        self.deliver(2)                                       # delivered to nobody yet
        res = ab.mark_processed("worker", [1, 2, 99], db=self.db)
        self.assertEqual((res["processed"], res["refused"]), ([], [1, 2, 99]))
        ops = self.ops()
        self.assertEqual([o for o in ops if o[0] == ab.AUDIT_OP_PROCESSED], [],
                         "an unearned claim manufactured a processing row")
        self.assertEqual(sorted(o[1] for o in ops if o[0] == ab.AUDIT_OP_PROCESSED_REFUSED), [1, 2, 99],
                         "the refusal itself has to enter the hash chain, not merely be returned")

    def test_the_ack_is_idempotent(self):
        self.deliver(1)
        self.consume("worker", lambda m: None)
        again = ab.mark_processed("worker", [1], db=self.db)
        self.assertEqual((again["processed"], again["already"]), ([], [1]))
        self.assertEqual(len([o for o in self.ops() if o[0] == ab.AUDIT_OP_PROCESSED]), 1)

    def test_the_processing_rows_stay_inside_the_tamper_evident_chain(self):
        self.deliver(2)
        self.consume("worker", lambda m: None)
        ab.mark_processed("worker", [99], db=self.db)          # a refusal row as well
        self.assertTrue(ab.audit_verify("worker", db=self.db)["ok"])
        rows = ab.audit_export("worker", db=self.db)
        rep = ab.audit_chain_verify(rows)
        self.assertTrue(rep["ok"] and rep["anchored"], rep)
        self.assertIn(ab.AUDIT_OP_PROCESSED, {r["op"] for r in rows})

    def test_a_deleted_processing_row_breaks_the_chain(self):
        """The ack is only worth something if removing it is detectable — otherwise a drop can be tidied away."""
        self.deliver(1)
        self.consume("worker", lambda m: None)
        ab.mark_processed("worker", [99], db=self.db)          # a later row, so the ack is not the chain's tail
        rows = ab.audit_export("worker", db=self.db)
        kept = [r for r in rows if r["op"] != ab.AUDIT_OP_PROCESSED]
        self.assertNotEqual(len(kept), len(rows), "there was no processing row to remove")
        self.assertFalse(ab.audit_chain_verify(kept)["chain_ok"], "a removed processing row left no trace")

    # ── the operator's view ────────────────────────────────────────────────────────────────────────────
    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(HERE, "agent_bus.py")] + list(args),
                              capture_output=True, text=True, env=dict(os.environ, **self.env))

    def test_the_cli_exits_non_zero_on_a_silent_drop_and_zero_once_processed(self):
        """A cron job or a CI step has to be able to SEE the silence without anyone going to look for it."""
        self.deliver(1)
        self.consume("worker", lambda m: (_ for _ in ()).throw(RuntimeError("swallowed")))
        p = self.cli("silent-drops", "--agent", "worker")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("never processed", p.stdout)

        j = self.cli("silent-drops", "--agent", "worker", "--json")
        self.assertEqual([r["id"] for r in json.loads(j.stdout)], [1])

        ack = self.cli("processed", "--agent", "worker", "--ids", "1")
        self.assertEqual(ack.returncode, 0, ack.stdout + ack.stderr)
        self.assertEqual(self.cli("silent-drops", "--agent", "worker").returncode, 0)

    def test_the_cli_refuses_an_unearned_claim_with_a_non_zero_exit(self):
        self.deliver(1)
        p = self.cli("processed", "--agent", "worker", "--ids", "1,7")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("REFUSED", p.stdout)


if __name__ == "__main__":
    unittest.main()
