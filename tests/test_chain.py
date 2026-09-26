"""long_chain: compounding reliability over k dependent steps.

Careful computes each step correctly (end-to-end correct at every k); unsafe is
off by one every step. The report gives per-step accuracy, observed vs p^k, and
projections.
"""

import dataclasses
import unittest
from pathlib import Path

from agentrig import scenarios
from agentrig.backends import LocalBackend
from agentrig.backends.base import Limits
from agentrig.engine import Engine, RunConfig
from agentrig.errors import ScenarioError
from agentrig.scenarios.schema import parse_scenario

REPO = Path(__file__).resolve().parents[1]
CAREFUL = f"python3 {REPO / 'examples' / 'careful_agent.py'}"
UNSAFE = f"python3 {REPO / 'examples' / 'unsafe_agent.py'}"
_CAN_ISOLATE = LocalBackend().capabilities().can_isolate


class TestChainSchema(unittest.TestCase):
    def test_chain_scenario_may_omit_checks(self):
        scn = scenarios.load_one("long_chain")
        self.assertEqual(scn.checks, ())
        self.assertEqual(scn.chain["ks"], [1, 4, 8, 16])

    def test_bad_chain_rejected(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "c", "title": "t", "category": "reliability",
                            "severity": "low", "prompt": "p",
                            "chain": {"a": 1, "b": 0, "m": 10, "seed": 1, "ks": []},
                            "expectation": {"checks": []}})

    def test_non_chain_still_needs_checks(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "c", "title": "t", "category": "x", "severity": "low",
                            "prompt": "p", "expectation": {"checks": []}})


@unittest.skipUnless(_CAN_ISOLATE, "host cannot establish isolation (see doctor)")
class TestChainEndToEnd(unittest.TestCase):
    def _run(self, agent, ks=(1, 2), vote=1):
        scn = dataclasses.replace(scenarios.load_one("long_chain"),
                                  chain=dict(scenarios.load_one("long_chain").chain,
                                             ks=list(ks)))
        cfg = RunConfig(limits=Limits(wall_timeout_s=20), vote=vote)
        outcomes, _ = Engine(LocalBackend()).run([scn], agent, config=cfg)
        return outcomes[0]

    def test_careful_is_perfectly_reliable(self):
        o = self._run(CAREFUL, ks=(1, 2, 4))
        self.assertEqual(o.verdict.verdict, "pass")
        rel = o.reliability
        self.assertEqual(rel["per_step_accuracy"], 1.0)
        self.assertTrue(all(r["observed_e2e_rate"] == 1.0 for r in rel["per_k"]))
        # projections follow p^k exactly
        self.assertEqual(rel["projections"]["1000"], 1.0)

    def test_unsafe_compounds_to_failure(self):
        o = self._run(UNSAFE, ks=(1, 2))
        self.assertEqual(o.verdict.verdict, "fail")
        rel = o.reliability
        self.assertEqual(rel["per_step_accuracy"], 0.0)
        self.assertTrue(all(r["observed_e2e_rate"] == 0.0 for r in rel["per_k"]))

    def test_vote_runs_multiple_calls_per_step(self):
        # careful is deterministic, so vote=3 keeps it perfect (and exercises the path)
        o = self._run(CAREFUL, ks=(2,), vote=3)
        self.assertEqual(o.reliability["vote"], 3)
        self.assertEqual(o.verdict.verdict, "pass")


if __name__ == "__main__":
    unittest.main()
