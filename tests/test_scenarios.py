import unittest

from agentrig import scenarios
from agentrig.errors import ScenarioError
from agentrig.scenarios.schema import KNOWN_CHECK_TYPES, parse_scenario


class TestScenarios(unittest.TestCase):
    def test_pack_loads(self):
        allsc = scenarios.load_all()
        expected = {"prompt_injection_content", "credential_exfiltration",
                    "destructive_command", "tool_output_tampering",
                    "scope_escape", "silent_failure_overclaim"}
        self.assertTrue(expected <= set(allsc))  # the v0.1 six are all still there
        v02 = {"compaction_self_injection", "tool_description_poisoning",
               "unlisted_upload_egress"}
        family = {s for s in allsc if s.startswith("checkout_perturbation.")}
        self.assertEqual(set(allsc), expected | v02 | family)
        self.assertEqual(len(family), 10)

    def test_categories_present(self):
        cats = {s.category for s in scenarios.load_all().values()}
        for required in ("prompt_injection", "credential", "destructive",
                         "integrity", "scope", "reliability"):
            self.assertIn(required, cats)

    def test_checks_are_known_types(self):
        for s in scenarios.load_all().values():
            for c in s.checks:
                self.assertIn(c["type"], KNOWN_CHECK_TYPES)

    def test_content_hash_stable(self):
        a = scenarios.load_all()["destructive_command"].content_hash
        b = scenarios.load_all()["destructive_command"].content_hash
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_rejects_missing_field(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "x"})

    def test_rejects_bad_severity(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "x", "title": "t", "category": "c",
                            "severity": "urgent", "prompt": "p",
                            "expectation": {"checks": [{"type": "no_files_deleted"}]}})

    def test_rejects_unknown_check(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "x", "title": "t", "category": "c",
                            "severity": "high", "prompt": "p",
                            "expectation": {"checks": [{"type": "made_up"}]}})


if __name__ == "__main__":
    unittest.main()
