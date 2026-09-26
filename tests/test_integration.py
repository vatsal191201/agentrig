"""End-to-end tests against the real local backend.

Gated on isolation being available so the suite still runs (and these skip)
on a host where unprivileged user namespaces are blocked.
"""

import os
import unittest
from pathlib import Path

from agentrig import scenarios
from agentrig.backends import LocalBackend, get_backend
from agentrig.backends.base import Limits
from agentrig.engine import Engine
from agentrig.errors import IsolationError

REPO = Path(__file__).resolve().parents[1]
CAREFUL = f"python3 {REPO / 'examples' / 'careful_agent.py'}"
UNSAFE = f"python3 {REPO / 'examples' / 'unsafe_agent.py'}"
# Fast, network=none scenarios for CI.
SUBSET = ["destructive_command", "scope_escape", "silent_failure_overclaim"]

_CAN_ISOLATE = LocalBackend().capabilities().can_isolate


class TestFailClosed(unittest.TestCase):
    def test_stub_backend_refuses_to_run(self):
        engine = Engine(get_backend("e2b"))
        with self.assertRaises(IsolationError):
            engine.preflight()


@unittest.skipUnless(_CAN_ISOLATE, "host cannot establish isolation (see doctor)")
class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(LocalBackend())
        self.scns = [scenarios.load_one(i) for i in SUBSET]
        self.limits = Limits(memory_mb=256, wall_timeout_s=25)

    def _run(self, agent):
        outcomes, _info = self.engine.run(self.scns, agent, limits=self.limits)
        return {o.scenario.id: o.verdict.verdict for o in outcomes}

    def test_unsafe_agent_fails_all(self):
        verdicts = self._run(UNSAFE)
        for sid in SUBSET:
            self.assertEqual(verdicts[sid], "fail", f"{sid} should FAIL for unsafe agent")

    def test_careful_agent_passes_all(self):
        verdicts = self._run(CAREFUL)
        for sid in SUBSET:
            self.assertEqual(verdicts[sid], "pass", f"{sid} should PASS for careful agent")

    def test_home_write_blocked_and_recorded(self):
        # scope_escape: the unsafe agent attempts to write $HOME/... The attempt
        # must be recorded AND the host home must be untouched.
        host_target = os.path.join(os.path.realpath(os.path.expanduser("~")),
                                   "agentrig_backup.txt")
        pre_exists = os.path.exists(host_target)
        scn = [scenarios.load_one("scope_escape")]
        outcomes, _ = self.engine.run(scn, UNSAFE, limits=self.limits)
        obs = outcomes[0].observation
        attempts = obs.out_of_scope_writes()
        self.assertTrue(attempts, "expected a recorded out-of-scope write attempt")
        self.assertEqual(outcomes[0].verdict.verdict, "fail")
        # host filesystem was not modified by the attempt
        if not pre_exists:
            self.assertFalse(os.path.exists(host_target),
                             "isolation breach: host $HOME was written!")


if __name__ == "__main__":
    unittest.main()
