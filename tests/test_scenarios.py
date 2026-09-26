import re
import unittest
from pathlib import Path

from agentrig import scenarios
from agentrig.errors import ScenarioError
from agentrig.scenarios.schema import KNOWN_CHECK_TYPES, parse_scenario

_DATA_DIR = Path(scenarios.__file__).parent / "data"
# The exact shape GitGuardian flagged: a canary token with a committed hex tail.
_SECRET_LITERAL = re.compile(r"CANARY_[A-Z]+_[0-9a-f]{6,}|sk-[A-Za-z0-9]{12,}")


class TestScenarios(unittest.TestCase):
    def test_pack_loads(self):
        allsc = scenarios.load_all()
        expected = {"prompt_injection_content", "credential_exfiltration",
                    "destructive_command", "tool_output_tampering",
                    "scope_escape", "silent_failure_overclaim"}
        self.assertTrue(expected <= set(allsc))  # the v0.1 six are all still there
        v02 = {"compaction_self_injection", "tool_description_poisoning",
               "unlisted_upload_egress"}
        incident = {"dns_egress_escape"}
        family = {s for s in allsc if s.startswith("checkout_perturbation.")}
        self.assertEqual(set(allsc), expected | v02 | incident | family)
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

    def test_no_secret_shaped_literal_in_scenario_data(self):
        # Decoy-secret hygiene: no committed high-entropy secret literal in the
        # scenario JSON (canaries are generated at run time from a spec).
        for path in sorted(_DATA_DIR.glob("*.json")):
            hits = _SECRET_LITERAL.findall(path.read_text(encoding="utf-8"))
            self.assertEqual(hits, [], f"secret-shaped literal in {path.name}: {hits}")

    def test_canaries_are_specs_and_generate_fresh_values(self):
        cred = scenarios.load_one("credential_exfiltration")
        self.assertIsInstance(cred.canaries["aws_key"], dict)  # spec, not a literal
        a = cred.generate_canaries()
        b = cred.generate_canaries()
        self.assertTrue(a["aws_key"].startswith("CANARY_EXFIL_"))
        self.assertEqual(len(a["aws_key"]), len("CANARY_EXFIL_") + 10)
        self.assertNotEqual(a["aws_key"], b["aws_key"])  # fresh each call
        # content hash is over the spec, so it is stable across runs
        self.assertEqual(scenarios.load_one("credential_exfiltration").content_hash,
                         cred.content_hash)

    def test_rejects_bad_canary_spec(self):
        with self.assertRaises(ScenarioError):
            parse_scenario({"id": "x", "title": "t", "category": "c", "severity": "high",
                            "prompt": "p", "canaries": {"k": {"random_hex": "lots"}},
                            "expectation": {"checks": [{"type": "no_files_deleted"}]}})

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
