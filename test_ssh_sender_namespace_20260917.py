"""A kliensoldalon MEGFORDULT anti-spoof határ — (2026-09-17, MAGAS).

A szerver (bus_ssh_exchange) az identitást a force-command argumentumából veszi, a payload `from`/`sender`-e nem
számít. A kliens (bus_ssh_client.exchange) viszont a TÁVOLI válasz `sender` mezőjét nyersen tette a HELYI busz
feladójává: a távoli gép megválasztotta, milyen néven kerül be üzenet a helyi buszba (mért: az egyik kar, az üzemeltető, üres,
`../`-alakú — mind bekerült). A maradék védelem (verify_sender → "unsigned") a registryt meg sem nézte, tehát egy
100%-ban aláíró feladó nevében jött csupasz sor is csak névtelen `unsigned` volt.

Két réteg zárja: (1) NÉVTÉR — a helyi feladó `ssh:<host>~<mondott>`, a mondott részből a `/` és minden nem
[A-Za-z0-9_.-] kiesik, tehát a távoli fél SOHA nem ír helyi néven, és a registry `basename`-alapú feloldása sem
eshet vissza helyi kulcsra; (2) NEGYEDIK OSZTÁLY — `verify_sender` „unsigned-pinned": csupasz sor egy pinelt (aláírásra
képes) név alatt, a product-mód saját okkal utasítja el. Mutáns-próba: a névtér nélkül `test_remote_cannot_write_as_local_agent`
és `test_traversal_shaped_claim_cannot_reach_local_key` bukik; a negyedik osztály nélkül `test_bare_row_under_pinned_name_is_its_own_class`.

stdlib unittest; hamis ssh (egy helyi python script adja a végpont válaszát), izolált DB és state.
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
        """Hamis ssh: a végpont válasza ROSSZINDULATÚ lehet — a `sender` mezőt a távoli fél választja."""
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
        # az egyik kar, az üzemeltető, üres string — egyik sem lehet helyi feladó
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
        self.assertEqual([r["body"] for r in self.local_rows()], ["a", "b", "c", "d"])   # a tartalom változatlan

    def test_traversal_shaped_claim_cannot_reach_local_key(self):
        # a registry `basename`-alapú: `../hub` → `hub` lenne; a névtér a `/`-t is kiüti
        res = cli.exchange("bus@example.invalid", "me", [],
                           ssh_cmd=self.fake_endpoint([{"id": 1, "sender": "../hub", "body": "x"}]),
                           state_dir=self.state, db=self.db)
        self.assertEqual(res["stored_locally"], 1)
        s = self.local_rows()[0]["sender"]
        self.assertEqual(s, "ssh:example.invalid~.._hub")
        self.assertEqual(os.path.basename(s), s)                    # nincs benne '/', a basename önmaga
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
                                      db=self.db)["stored_locally"], 0)            # ugyanaz az id → dedupe
        self.assertEqual(len(self.local_rows()), 1)


class BareRowUnderPinnedName(unittest.TestCase):
    def test_bare_row_under_pinned_name_is_its_own_class(self):
        if not ab._A2_HAVE:
            self.skipTest("nincs cryptography")
        with tempfile.TemporaryDirectory() as keys:
            with open(os.path.join(keys, "hub.pub"), "w") as fh:
                fh.write("00" * 32)
            row = {"v": 2, "sender": "hub", "recipient": "me", "topic": "", "kind": "msg",
                   "in_reply_to": None, "body": "hi", "ts": 1}
            self.assertEqual(ab.verify_sender(row, keys_dir=keys), "unsigned-pinned")
            self.assertEqual(ab.verify_sender({**row, "sender": "nobody"}, keys_dir=keys), "unsigned")
            # a névterezett távoli feladó NEM pinelt → névtelen unsigned, nem hamisítás-gyanú
            self.assertEqual(ab.verify_sender({**row, "sender": "ssh:host~hub"}, keys_dir=keys), "unsigned")
            # a product-mód saját okkal utasít el
            import bus_enforce as enf
            self.assertEqual(enf.check(row, keys_dir=keys), (False, "unsigned-pinned"))


if __name__ == "__main__":
    unittest.main()
