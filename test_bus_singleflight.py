"""bus_singleflight — „egy agent — egy instancia" regresszió. stdlib unittest.

A tesztek VALÓDI OS-folyamatokat indítanak a dokumentált CLI-vel (`python3 bus_singleflight.py acquire …`),
mert a B1 hiba pont a rövid életű CLI-hívásnál jött ki: a lock tulajdonosa a hívás végén meghalt."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_singleflight as sf  # noqa: E402


def _cli(bridge, *args):
    env = dict(os.environ, AGENT_BRIDGE_DIR=bridge)
    return subprocess.Popen([sys.executable, os.path.join(HERE, "bus_singleflight.py"), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)


class SessionLockCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _statuses(self, procs):
        out = []
        for p in procs:
            so, _ = p.communicate(timeout=30)
            out.append((p.returncode, so.strip()))
        return out

    def test_B1_concurrent_distinct_instances_only_one_acquires(self):
        """két egyidejű `acquire --instance PROC_A/PROC_B` → pontosan egy nyer."""
        for _ in range(5):
            agent = "race%d" % _
            res = self._statuses([_cli(self.bridge, "acquire", "--agent", agent, "--instance", "PROC_A"),
                                  _cli(self.bridge, "acquire", "--agent", agent, "--instance", "PROC_B")])
            acquired = [r for r in res if "status=acquired" in r[1]]
            self.assertEqual(len(acquired), 1, res)
            self.assertEqual(sorted(r[0] for r in res), [0, 3], res)

    def test_B1_sequential_bare_acquire_does_not_steal(self):
        """szekvenciális, flag nélküli `acquire --agent X` 1 mp-cel eltolva.
        Ugyanabból a hívó-folyamatból (ugyanaz a tulajdonos) → a második UGYANAZT az identitást kapja
        vissza (already-own), NEM egy új példány veszi át; egy MÁSIK, élő tulajdonos → duplikátum."""
        r1 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2")])[0]
        self.assertEqual(r1[0], 0, r1)
        inst1 = r1[1].split()[0]
        time.sleep(1)
        r2 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2")])[0]
        self.assertEqual(r2[0], 0, r2)
        self.assertIn("status=already-own", r2[1])
        self.assertEqual(r2[1].split()[0], inst1)
        other = subprocess.Popen(["sleep", "30"])
        try:
            r3 = self._statuses([_cli(self.bridge, "acquire", "--agent", "race2", "--owner-pid", str(other.pid))])[0]
            self.assertEqual(r3[0], 3, r3)
            self.assertIn("status=duplicate", r3[1])
        finally:
            other.kill(); other.wait()

    def test_B1var_owner_pid_vs_nonexistent_target_never_double_acquired(self):
        """újramérés (B1-var): `--owner-pid` vs `--target nemletezo-session` ugyanarra az
        agentre, 15 kör → soha nem lehet két `acquired`. Korábban 9/15 kettős: a sosem-élő targettel írt
        zárat a másik azonnal stale-nek látta és visszaigényelte, miközben az első már `acquired`-et kapott."""
        other = subprocess.Popen(["sleep", "60"])
        try:
            for i in range(15):
                agent = "b1var%d" % i
                res = self._statuses([
                    _cli(self.bridge, "acquire", "--agent", agent, "--owner-pid", str(other.pid)),
                    _cli(self.bridge, "acquire", "--agent", agent, "--instance", "FAKE_T",
                         "--target", "nemletezo-session-b1var-%d" % i)])
                acquired = [r for r in res if "status=acquired" in r[1]]
                self.assertLessEqual(len(acquired), 1, res)
        finally:
            other.kill(); other.wait()


def _api_acquire(bridge, agent, instance, target=None, owner_pid=None):
    code = ("import sys; sys.path.insert(0, %r); import bus_singleflight as sf; "
            "st, _ = sf.SessionLock(%r, bridge=%r).acquire(%r, target=%r, owner_pid=%r); print('status=' + st)"
            % (HERE, agent, bridge, instance, target, owner_pid))
    return subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class OwnerNotLiveB1var2(unittest.TestCase):
    """CHANGES_REQUESTED, a B1-var javítás (317702e) csak a target-ágat zárta.
    Egy SOSEM ÉLT owner-pid-del (vagy halott derivált pid-del) írt zárat a másik hívó azonnal stale-nek látja és
    visszaigényli, miközben az első már `acquired`-et kapott → két worker. Mért: 7/15 kettős acquired.
    4 eset × 15 kör, valódi párhuzamos folyamatok, valódi pid-liveness és valódi tmux-panel."""
    ROUNDS = 15
    NEVER = 999999999                                           # sosem élt pid

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bridge = self.tmp.name
        self.live = subprocess.Popen(["sleep", "120"])
        self.sess = "sfb1v2%d" % os.getpid()
        self.have_tmux = subprocess.run(["tmux", "new-session", "-d", "-s", self.sess, "sleep 120"],
                                        capture_output=True).returncode == 0

    def tearDown(self):
        self.live.kill(); self.live.wait()
        if self.have_tmux:
            subprocess.run(["tmux", "kill-session", "-t", self.sess], capture_output=True)
        self.tmp.cleanup()

    def _race(self, tag, left, right):
        doubles = 0
        for i in range(self.ROUNDS):
            agent = "%s%d" % (tag, i)
            procs = [_api_acquire(self.bridge, agent, **left), _api_acquire(self.bridge, agent, **right)]
            outs = [p.communicate(timeout=30)[0].strip() for p in procs]
            if sum("status=acquired" in o for o in outs) > 1:
                doubles += 1
        return doubles

    def test_dead_owner_vs_live_owner_never_double(self):
        self.assertEqual(self._race("o", dict(instance="A", owner_pid=self.NEVER),
                                    dict(instance="B", owner_pid=self.live.pid)), 0)

    def test_live_panel_dead_owner_vs_live_panel_live_owner_never_double(self):
        if not self.have_tmux:
            self.skipTest("tmux nincs")
        self.assertEqual(self._race("p", dict(instance="A", target=self.sess, owner_pid=self.NEVER),
                                    dict(instance="B", target=self.sess, owner_pid=self.live.pid)), 0)

    def test_ttl_branch_dead_instance_vs_live_instance_never_double(self):
        self.assertEqual(self._race("t", dict(instance="host:%d" % self.NEVER),
                                    dict(instance="host:%d" % self.live.pid)), 0)

    def test_control_two_live_owners_never_double(self):
        other = subprocess.Popen(["sleep", "120"])
        try:
            self.assertEqual(self._race("c", dict(instance="A", owner_pid=self.live.pid),
                                        dict(instance="B", owner_pid=other.pid)), 0)
        finally:
            other.kill(); other.wait()

    def test_dead_owner_is_refused_and_writes_nothing(self):
        lock = sf.SessionLock("onl", bridge=self.bridge)
        st, _ = lock.acquire("A", owner_pid=self.NEVER)
        self.assertEqual(st, "owner-not-live")
        self.assertIsNone(lock.holder())
        r = subprocess.run([sys.executable, os.path.join(HERE, "bus_singleflight.py"), "acquire", "--agent", "onl2",
                            "--owner-pid", str(self.NEVER)], capture_output=True, text=True,
                           env=dict(os.environ, AGENT_BRIDGE_DIR=self.bridge), timeout=30)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("owner-not-live", r.stdout)


class SessionLockLiveness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_H1_target_alive_but_owner_pid_dead_is_stale(self):
        """tmux-panel él, de az explicit owner-pid MEGHAL → a zár NEM ragadhat be.
        B1var-2  átfogalmazás: a korábbi változat egy SOSEM ÉLT owner-pid-del kapott `acquired`-et, és ezzel
        épp a kettős acquired-et rögzítette elvárásként. A H1 célja megmarad, valódi életciklussal: az owner él az
        acquire-kor → acquired; `kill -9` → a guard szerint a zár már nem él → egy új hívó (élő owner-rel) igényel."""
        owner = subprocess.Popen(["sleep", "120"])
        lock = sf.SessionLock("tmuxtest", bridge=self.tmp.name, target_alive=lambda t: True)
        st, _ = lock.acquire("workerX", target="sftest:0.0", owner_pid=owner.pid)
        self.assertEqual(st, "acquired")
        self.assertTrue(lock._holder_alive(lock.holder(), time.time_ns()))
        owner.kill(); owner.wait()                                               # kill -9
        self.assertFalse(lock._holder_alive(lock.holder(), time.time_ns()))      # guard: tiszta
        heir = subprocess.Popen(["sleep", "120"])
        try:
            st2, h = sf.SessionLock("tmuxtest", bridge=self.tmp.name, target_alive=lambda t: True).acquire(
                "workerY", target="sftest:0.0", owner_pid=heir.pid)
            self.assertEqual((st2, h["instance"]), ("acquired", "workerY"))
        finally:
            heir.kill(); heir.wait()

    def test_H1_target_without_owner_pid_still_uses_pane(self):
        lock = sf.SessionLock("t2", bridge=self.tmp.name, is_alive=lambda pid: False, target_alive=lambda t: True)
        lock.acquire("w1", target="s:0.0")
        self.assertTrue(lock._holder_alive(lock.holder(), time.time_ns()))

    def test_B1var_acquire_with_dead_target_is_refused_and_writes_nothing(self):
        """Nem élő target az acquire pillanatában → `target-not-live`, és a lock-fájl NEM jön létre
        (egy sosem-élő targettel írt zár mindenki másnak azonnal stale lenne → kizárólagosság-sértés)."""
        lock = sf.SessionLock("t4", bridge=self.tmp.name, is_alive=lambda pid: True, target_alive=lambda t: False)
        st, _ = lock.acquire("w1", target="nincs:0.0")
        self.assertEqual(st, "target-not-live")
        self.assertIsNone(lock.holder())

    def test_ttl_without_pid_is_alive_until_ttl(self):
        """Nem-pid alakú instance (pl. „PROC_A") + nincs owner-pid: a friss zár ÉL a TTL-ig (korábban azonnal halott volt)."""
        lock = sf.SessionLock("t3", bridge=self.tmp.name, is_alive=lambda pid: False, ttl_ns=10 * 10**9)
        now = time.time_ns()
        lock.acquire("PROC_A", now_ns=now)
        self.assertTrue(lock._holder_alive(lock.holder(), now + 5 * 10**9))
        self.assertFalse(lock._holder_alive(lock.holder(), now + 11 * 10**9))


class MessageClaimBasics(unittest.TestCase):
    def test_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            inbox = os.path.join(d, "inbox", "a")
            os.makedirs(inbox)
            for i in range(5):
                with open(os.path.join(inbox, "m%d.json" % i), "w") as f:
                    json.dump({"i": i}, f)
            a = sf.MessageClaim("a", "ia", bridge=d)
            b = sf.MessageClaim("a", "ib", bridge=d)
            won_a = a.claim_pending()
            won_b = b.claim_pending()
            self.assertEqual(len(won_a), 5)
            self.assertEqual(won_b, [])


if __name__ == "__main__":
    unittest.main()
