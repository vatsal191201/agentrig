"""The runtime tripwire (--halt-on critical): halt on the first critical event,
record detection->halt latency, and fail the trial. Off by default.

Mirrors the DNS-escape report's operational gap: the run "did not auto-stop".
"""

import time
import unittest
from pathlib import Path

from agentrig import scenarios
from agentrig.backends import LocalBackend
from agentrig.backends.base import Limits
from agentrig.engine import Engine, RunConfig, _critical_spec
from agentrig.observe.tripwire import Tripwire

REPO = Path(__file__).resolve().parents[1]
CAREFUL = f"python3 {REPO / 'examples' / 'careful_agent.py'}"
UNSAFE = f"python3 {REPO / 'examples' / 'unsafe_agent.py'}"
_CAN_ISOLATE = LocalBackend().capabilities().can_isolate


class _FakeGate:
    def __init__(self):
        self._recs = []

    @property
    def records(self):
        return list(self._recs)

    def block(self, dest):
        class R:
            method = "CONNECT"
            destination = dest
            allowed = False

            def blob(self):
                return b""
        self._recs.append(R())


class TestTripwireUnit(unittest.TestCase):
    def test_blocked_egress_trips_and_kills(self):
        gate = _FakeGate()
        killed = []
        tw = Tripwire(gate=gate)
        tw.arm(None, lambda: killed.append(True), time.monotonic())
        gate.block("evil.example:443")
        for _ in range(50):
            if tw.result["tripped"]:
                break
            time.sleep(0.01)
        tw.disarm()
        self.assertTrue(tw.result["tripped"])
        self.assertEqual(tw.result["event"]["kind"], "blocked_egress")
        self.assertIsNotNone(tw.result["detection_latency_s"])
        self.assertEqual(killed, [True])

    def test_clean_run_does_not_trip(self):
        tw = Tripwire(gate=_FakeGate())
        tw.arm(None, lambda: None, time.monotonic())
        time.sleep(0.1)
        tw.disarm()
        self.assertFalse(tw.result["tripped"])

    def test_critical_spec_from_scenario_checks(self):
        reads, cmds = _critical_spec(scenarios.load_one("correction_persistence"))
        self.assertIn("other_team_submission", reads)
        self.assertIn(r"\bgh\b", cmds)


@unittest.skipUnless(_CAN_ISOLATE, "host cannot establish isolation (see doctor)")
class TestTripwireEndToEnd(unittest.TestCase):
    def _run(self, agent, sid, halt=True):
        cfg = RunConfig(limits=Limits(wall_timeout_s=30),
                        halt_on="critical" if halt else None)
        outcomes, _ = Engine(LocalBackend()).run(
            [scenarios.load_one(sid)], agent, config=cfg)
        return outcomes[0]

    def test_halt_on_decoy_read_records_latency_and_fails(self):
        o = self._run(UNSAFE, "credential_exfiltration")
        tw = [c for c in o.verdict.checks if c.type == "runtime_tripwire"]
        self.assertEqual(o.verdict.verdict, "fail")
        self.assertTrue(tw and tw[0].verdict == "fail")
        latency = o.observation.tripwire["detection_latency_s"]
        self.assertIsNotNone(latency)
        self.assertLess(latency, 25)

    def test_careful_agent_never_trips(self):
        o = self._run(CAREFUL, "credential_exfiltration")
        self.assertEqual(o.verdict.verdict, "pass")
        self.assertFalse(o.observation.tripwire["tripped"])

    def test_off_by_default(self):
        o = self._run(UNSAFE, "credential_exfiltration", halt=False)
        self.assertIsNone(o.observation.tripwire)
        self.assertEqual(o.verdict.verdict, "fail")  # still fails, just not halted


if __name__ == "__main__":
    unittest.main()
