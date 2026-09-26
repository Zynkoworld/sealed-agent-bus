"""The anti-spoof boundary REVERSED on the client side — (2026-09-17, HIGH).

The server (bus_ssh_exchange) takes the identity from the force-command argument, the payload's `from`/`sender` does not
count. The client (bus_ssh_client.exchange), however, made the REMOTE reply's `sender` field raw into the LOCAL bus's
sender: the remote machine chose under what name a message enters the local bus (measured: one arm, the operator, empty,
`../`-shaped — all got in). The remaining protection (verify_sender → "unsigned") did not even look at the registry, so a
bare row arriving in the name of a sender that signs 100 percent of the time was also just an anonymous `unsigned`.

Two layers close it: (1) NAMESPACE — the local sender is `ssh:<host>~<named>`, and `/` and every non-[A-Za-z0-9_.-] character are removed
from the named part, so the remote party NEVER writes under a local name, and the registry's `basename`-based resolution cannot
fall back to a local key either; (2) A FOURTH CLASS — `verify_sender` "unsigned-pinned": a bare row under a pinned (signing-capable)
name, which product mode rejects with its own reason. Mutant probe: without the namespace `test_remote_cannot_write_as_local_agent`
and `test_traversal_shaped_claim_cannot_reach_local_key` fail; without the fourth class `test_bare_row_under_pinned_name_is_its_own_class`.

stdlib unittest; a fake ssh (a local python script gives the endpoint's reply), an isolated DB and state.
"""
import json
import os
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_bus as ab  # noqa: E402
import bus_ssh_client as cli  # noqa: E402


class _Iso(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "local.db")
        self.state = os.path.join(self.tmp.name, "state")
        self._env = dict(os.environ)
        os.environ["AGENT_BUS_AUTO_SIGN"] = "0"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def fake_endpoint(self, replies):
        """A fake ssh: the endpoint's reply may be MALICIOUS — the remote party chooses the `sender` field."""
        path = os.path.join(self.tmp.name, "fake_ssh_%d.py" % len(os.listdir(self.tmp.name)))
        with open(path, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent("""
                import json, sys
                sys.stdin.read()
                print(json.dumps({"accepted": 0, "replies": %s}))
            """ % json.dumps(replies)))
        return [sys.executable, path]

    def local_rows(self):
        return ab.recv("me", db=self.db)


class RemoteSenderIsNamespaced(_Iso):
    def test_remote_cannot_write_as_local_agent(self):
        # one arm, the operator, an empty string — none of them may be a local sender
        replies = [{"id": 1, "sender": "hub", "body": "a"}, {"id": 2, "sender": "ops", "body": "b"},
                   {"id": 3, "sender": "", "body": "c"}, {"id": 4, "sender": "remotehub", "body": "d"}]
        res = cli.exchange("bus@example.invalid", "me", [], ssh_cmd=self.fake_endpoint(replies),
                           state_dir=self.state, db=self.db)
        self.assertEqual(res["stored_locally"], 4)
        senders = [r["sender"] for r in self.local_rows()]
        self.assertEqual(senders, ["ssh:example.invalid~hub", "ssh:example.invalid~ops",
                                   "ssh:example.invalid~?", "ssh:example.invalid~remotehub"])
        for s in senders:
            self.assertNotIn(s, ("hub", "ops", "", "remotehub"))
        self.assertEqual([r["body"] for r in self.local_rows()], ["a", "b", "c", "d"])   # the content is unchanged

    def test_traversal_shaped_claim_cannot_reach_local_key(self):
        # the registry is `basename`-based: `../hub` would become `hub`; the namespace knocks out `/` too
        res = cli.exchange("bus@example.invalid", "me", [],
                           ssh_cmd=self.fake_endpoint([{"id": 1, "sender": "../hub", "body": "x"}]),
                           state_dir=self.state, db=self.db)
        self.assertEqual(res["stored_locally"], 1)
        s = self.local_rows()[0]["sender"]
        self.assertEqual(s, "ssh:example.invalid~.._hub")
        self.assertEqual(os.path.basename(s), s)                    # there is no '/' in it, the basename is itself
        self.assertNotEqual(os.path.basename(s), "hub")

    def test_name_function_bounds_and_states_the_unknown(self):
        self.assertEqual(cli.remote_sender_name("bus@host", "hub"), "ssh:host~hub")
        self.assertEqual(cli.remote_sender_name("host-only", "hub"), "ssh:host-only~hub")
        self.assertEqual(cli.remote_sender_name("bus@host", None), "ssh:host~?")
        self.assertEqual(cli.remote_sender_name("bus@host", 42), "ssh:host~?")
        self.assertEqual(cli.remote_sender_name("bus@host", "..."), "ssh:host~?")
        self.assertEqual(cli.remote_sender_name("bus@host", "a b\tc\n/d"), "ssh:host~a_b_c__d")
        self.assertEqual(len(cli.remote_sender_name("bus@host", "x" * 500)), len("ssh:host~") + 48)
        self.assertEqual(cli.remote_sender_name("bus@h/o s t", "hub"), "ssh:h_o_s_t~hub")

    def test_control_honest_round_trip_still_stores_and_dedupes(self):
        ep = self.fake_endpoint([{"id": 7, "sender": "hub", "body": "valasz"}])
        self.assertEqual(cli.exchange("bus@example.invalid", "me", [], ssh_cmd=ep, state_dir=self.state,
                                      db=self.db)["stored_locally"], 1)
        self.assertEqual(cli.exchange("bus@example.invalid", "me", [], ssh_cmd=ep, state_dir=self.state,
                                      db=self.db)["stored_locally"], 0)            # the same id → dedupe
        self.assertEqual(len(self.local_rows()), 1)


class BareRowUnderPinnedName(unittest.TestCase):
    def test_bare_row_under_pinned_name_is_its_own_class(self):
        if not ab._A2_HAVE:
            self.skipTest("no cryptography")
        with tempfile.TemporaryDirectory() as keys:
            with open(os.path.join(keys, "hub.pub"), "w") as fh:
                fh.write("00" * 32)
            row = {"v": 2, "sender": "hub", "recipient": "me", "topic": "", "kind": "msg",
                   "in_reply_to": None, "body": "hi", "ts": 1}
            self.assertEqual(ab.verify_sender(row, keys_dir=keys), "unsigned-pinned")
            self.assertEqual(ab.verify_sender({**row, "sender": "nobody"}, keys_dir=keys), "unsigned")
            # a namespaced remote sender is NOT pinned → an anonymous unsigned, not a suspected forgery
            self.assertEqual(ab.verify_sender({**row, "sender": "ssh:host~hub"}, keys_dir=keys), "unsigned")
            # product mode rejects it with its own reason
            import bus_enforce as enf
            self.assertEqual(enf.check(row, keys_dir=keys), (False, "unsigned-pinned"))


if __name__ == "__main__":
    unittest.main()
