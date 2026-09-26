import copy
import os
import tempfile
import unittest
from pathlib import Path

from agentrig import scenarios
from agentrig.backends.base import Capabilities
from agentrig.engine import ScenarioOutcome
from agentrig.observe import Observation
from agentrig.observe.manifest import ManifestDiff
from agentrig.report import _chain_records, _compute_chain, build_report, verify_report
from agentrig.signing import Signer
from agentrig.verdict import FAIL, PASS, CheckResult, ScenarioVerdict


def _caps():
    return Capabilities(backend="local", filesystem_isolation=True,
                        network_isolation=True, memory_limit=True, cpu_limit=True,
                        pids_limit=True, syscall_observation=True)


def _outcome(scn, verdict):
    ver = ScenarioVerdict(
        scenario_id=scn.id, category=scn.category, severity=scn.severity,
        verdict=verdict, safe_behavior=scn.safe_behavior,
        checks=[CheckResult("no_files_deleted", verdict, "detail", {"k": "v"})])
    o = Observation(events=[{"type": "process_spawn", "argv": ["rm", "-rf", "/work/x"]}],
                    manifest_diff=ManifestDiff(deleted=["x"]), stdout="", stderr="",
                    trace_available=True, exit_code=0)
    return ScenarioOutcome(scenario=scn, verdict=ver, observation=o)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arig-rep-")
        self.signer = Signer(key_path=Path(self.tmp) / "k.key")
        scn = scenarios.load_one("destructive_command")
        self.outcomes = [_outcome(scn, FAIL)]
        self.agent_info = {"command": "python3 a.py", "argv": ["python3", "/agent0/a.py"],
                           "files_sha256": {"a.py": "abc"}}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self):
        return build_report(self.outcomes, self.agent_info, _caps(), signer=self.signer)

    def test_build_and_verify_ok(self):
        report = self.build()
        self.assertEqual(report["summary"]["fail"], 1)
        v = verify_report(report)
        self.assertTrue(v.ok)
        self.assertTrue(v.chain_ok)
        self.assertEqual(v.head_stored, v.head_recomputed)

    def test_chain_is_deterministic(self):
        report = self.build()
        recs = _chain_records(report)
        _e1, h1 = _compute_chain(recs)
        _e2, h2 = _compute_chain(recs)
        self.assertEqual(h1, h2)
        self.assertEqual(h1, report["chain"]["head"])

    def test_tamper_verdict_detected(self):
        report = self.build()
        tampered = copy.deepcopy(report)
        tampered["scenarios"][0]["verdict"] = PASS  # a lie
        v = verify_report(tampered)
        self.assertFalse(v.ok)
        self.assertFalse(v.chain_ok)

    def test_tamper_event_detected(self):
        report = self.build()
        tampered = copy.deepcopy(report)
        tampered["scenarios"][0]["events"][0]["argv"] = ["true"]  # hide rm -rf
        v = verify_report(tampered)
        self.assertFalse(v.ok)

    def test_tamper_single_byte_in_head_detected(self):
        report = self.build()
        tampered = copy.deepcopy(report)
        head = list(tampered["chain"]["head"])
        head[0] = "0" if head[0] != "0" else "1"
        tampered["chain"]["head"] = "".join(head)
        v = verify_report(tampered)
        self.assertFalse(v.ok)

    def test_resolved_canaries_are_recorded_and_chained(self):
        import dataclasses
        scn = dataclasses.replace(scenarios.load_one("credential_exfiltration"),
                                  canaries={"aws_key": "CANARY_EXFIL_deadbeef01"})
        report = build_report([_outcome(scn, PASS)], self.agent_info, _caps(),
                              signer=self.signer)
        self.assertEqual(report["scenarios"][0]["canaries"],
                         {"aws_key": "CANARY_EXFIL_deadbeef01"})
        # the recorded canary is inside the tamper-evident chain
        tampered = copy.deepcopy(report)
        tampered["scenarios"][0]["canaries"]["aws_key"] = "CANARY_EXFIL_00000000"
        self.assertFalse(verify_report(tampered).ok)

    def test_signature_present_when_crypto_available(self):
        report = self.build()
        if self.signer.available:
            self.assertTrue(report["signature"]["signed"])
            self.assertEqual(verify_report(report).signature_status, "valid")
        else:
            self.assertFalse(report["signature"]["signed"])


if __name__ == "__main__":
    unittest.main()
