import json
import unittest

from agentrig.sarif import to_sarif

REPORT = {
    "agentrig_version": "0.2.0", "run_id": "run-1",
    "agent": {"command": "python3 examples/llm_agent.py --max-steps 8"},
    "summary": {"pass": 1, "fail": 1, "inconclusive": 1},
    "chain": {"head": "ab" * 32}, "signature": {"signed": False},
    "scenarios": [
        {"scenario_id": "credential_exfiltration", "title": "t", "category": "credential",
         "severity": "critical", "verdict": "fail", "safe_behavior": "s",
         "trials": [{"checks": [{"type": "canary_not_transmitted", "verdict": "fail",
                                 "detail": "sent", "severity": "critical"}]},
                    {"checks": [{"type": "canary_not_transmitted", "verdict": "pass",
                                 "detail": "ok", "severity": "critical"}]}]},
        {"scenario_id": "silent_failure_overclaim", "title": "t", "category": "reliability",
         "severity": "medium", "verdict": "inconclusive", "note": "agent timed out",
         "trials": [{"checks": []}]},
        {"scenario_id": "scope_escape", "verdict": "pass", "trials": [{"checks": []}]},
    ],
}


class TestSarif(unittest.TestCase):
    def test_structure_levels_and_locations(self):
        doc = to_sarif(REPORT)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        res = {r["ruleId"]: r for r in run["results"]}
        fail = res["agentrig/credential_exfiltration/canary_not_transmitted"]
        self.assertEqual(fail["level"], "error")
        self.assertIn("failed in 1/2 trial(s)", fail["message"]["text"])
        self.assertEqual(fail["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "examples/llm_agent.py")
        self.assertEqual(res["agentrig/silent_failure_overclaim/inconclusive"]["level"], "note")
        self.assertEqual(len(run["results"]), 2)  # passing scenarios produce nothing
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rules[fail["ruleId"]]["properties"]["security-severity"], "9.5")
        json.dumps(doc)  # serializable


if __name__ == "__main__":
    unittest.main()
