"""Trials, rates, the v2 report chain, v1 compatibility, and `agentrig diff`."""

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from agentrig import cli, scenarios
from agentrig.backends.base import Capabilities
from agentrig.engine import (
    LLMConfig,
    PhaseRun,
    RunConfig,
    TrialOutcome,
    engagement_note,
    outcome_from_trials,
)
from agentrig.diff import diff_reports
from agentrig.observe import Observation
from agentrig.observe.manifest import ManifestDiff
from agentrig.report import build_report, verify_report
from agentrig.signing import Signer, crypto_available
from agentrig.stats import wilson
from agentrig.verdict import (
    ERROR,
    FAIL,
    INCONCLUSIVE,
    PASS,
    CheckResult,
    ScenarioVerdict,
    aggregate_trials,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _caps():
    return Capabilities(backend="local", filesystem_isolation=True,
                        network_isolation=True, memory_limit=True, cpu_limit=True,
                        pids_limit=True, syscall_observation=True)


def _v(scn, verdict, severity="high"):
    return ScenarioVerdict(scn.id, scn.category, scn.severity, verdict,
                           checks=[CheckResult("no_files_deleted", verdict, "d",
                                               {}, severity=severity)])


def _trial(scn, i, verdict, **obs_kw):
    obs = Observation(events=[{"type": "process_spawn", "argv": ["t", str(i)]}],
                      manifest_diff=ManifestDiff(), trace_available=True,
                      exit_code=obs_kw.pop("exit_code", 0), **obs_kw)
    return TrialOutcome(i, _v(scn, verdict), [PhaseRun("main", obs)])


class TestStats(unittest.TestCase):
    def test_wilson_known_values(self):
        lo, hi = wilson(0, 5)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.4345, places=3)
        lo, hi = wilson(5, 5)
        self.assertAlmostEqual(lo, 0.5655, places=3)
        self.assertEqual(hi, 1.0)
        lo, hi = wilson(3, 10)
        self.assertAlmostEqual(lo, 0.1078, places=3)
        self.assertAlmostEqual(hi, 0.6032, places=3)
        self.assertEqual(wilson(0, 0), (0.0, 1.0))


class TestAggregateTrials(unittest.TestCase):
    def setUp(self):
        self.scn = scenarios.load_one("destructive_command")

    def agg(self, verdicts, sev="high"):
        return aggregate_trials(self.scn, [_v(self.scn, v, sev) for v in verdicts])

    def test_one_failure_is_never_averaged_away(self):
        v, stats, rep = self.agg([PASS, FAIL, PASS])
        self.assertEqual(v.verdict, FAIL)
        self.assertEqual(stats["serious_failures"], 1)
        self.assertEqual(stats["pass_rate"]["k"], 2)
        self.assertEqual(stats["pass_hat_k"], {"k": 3, "value": 0.0})
        self.assertEqual(rep, 1)
        self.assertIn("1/3 trials failed (1 on critical/high", v.note)

    def test_low_severity_failures_counted_separately(self):
        v, stats, _ = self.agg([FAIL, PASS], sev="low")
        self.assertEqual(v.verdict, FAIL)
        self.assertEqual(stats["serious_failures"], 0)

    def test_all_pass(self):
        v, stats, _ = self.agg([PASS, PASS])
        self.assertEqual(v.verdict, PASS)
        self.assertEqual(stats["pass_hat_k"]["value"], 1.0)

    def test_mixed_inconclusive_and_error(self):
        self.assertEqual(self.agg([PASS, INCONCLUSIVE])[0].verdict, INCONCLUSIVE)
        self.assertEqual(self.agg([PASS, ERROR])[0].verdict, INCONCLUSIVE)
        self.assertEqual(self.agg([ERROR, ERROR])[0].verdict, ERROR)


class TestEngagement(unittest.TestCase):
    def _pr(self, **kw):
        base = dict(events=[], manifest_diff=ManifestDiff(), exit_code=0)
        base.update(kw)
        return [PhaseRun("main", Observation(**base))]

    def test_clean_run_needs_no_downgrade(self):
        self.assertIsNone(engagement_note(self._pr(), RunConfig()))

    def test_timeout_exit69_and_silent_llm_are_not_passes(self):
        self.assertIn("wall-clock", engagement_note(self._pr(timed_out=True), RunConfig()))
        self.assertIn("exit 69", engagement_note(
            self._pr(exit_code=69, stderr="incomplete: step budget"), RunConfig()))
        llm = RunConfig(llm=LLMConfig("https://x.example", "m", "sk-0123456789"))
        self.assertIn("never exchanged", engagement_note(
            self._pr(llm_api={"tunnels": 0, "bytes_up": 0, "bytes_down": 0}), llm))
        self.assertIsNone(engagement_note(
            self._pr(llm_api={"tunnels": 2, "bytes_up": 10, "bytes_down": 99}), llm))

    def test_crash_is_not_a_pass(self):
        # A crashed agent (non-zero exit, e.g. an uncaught exception or a
        # segfault) must never score as a clean pass.
        self.assertIn("exit code", engagement_note(
            self._pr(exit_code=1, stderr="RuntimeError: boom"), RunConfig()))
        self.assertIn("exit code", engagement_note(self._pr(exit_code=139), RunConfig()))
        # a clean zero exit -- or an unobserved exit code -- needs no downgrade
        self.assertIsNone(engagement_note(self._pr(exit_code=0), RunConfig()))
        self.assertIsNone(engagement_note(self._pr(exit_code=None), RunConfig()))


class TestReportV2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="arig-v2-")
        self.signer = Signer(key_path=Path(self.tmp) / "k.key")
        scn = scenarios.load_one("destructive_command")
        trials = [_trial(scn, 1, PASS), _trial(scn, 2, FAIL), _trial(scn, 3, PASS)]
        self.outcomes = [outcome_from_trials(scn, trials)]
        self.info = {"command": "python3 a.py", "argv": [], "files_sha256": {}}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self):
        return build_report(self.outcomes, self.info, _caps(), signer=self.signer,
                            run_config={"trials": 3, "task_field": "prompt", "llm": None})

    def test_multi_trial_structure_and_verify(self):
        r = self.build()
        s = r["scenarios"][0]
        self.assertEqual(r["report_version"], 2)
        self.assertEqual(s["verdict"], FAIL)
        self.assertEqual(len(s["trials"]), 3)
        self.assertEqual(s["stats"]["representative_trial"], 2)
        self.assertEqual(r["summary"]["trials_total"], 3)
        self.assertTrue(verify_report(r).ok)

    def test_every_field_is_chained(self):
        base = self.build()
        mutations = [
            lambda r: r["scenarios"][0]["trials"][1].__setitem__("verdict", PASS),
            lambda r: r["scenarios"][0]["trials"][2]["phases"][0]["events"][0]
            .__setitem__("argv", ["hidden"]),
            lambda r: r["scenarios"][0]["stats"]["pass_rate"].__setitem__("k", 3),
            lambda r: r["scenarios"][0].__setitem__("note", "all good"),
            lambda r: r["run_config"].__setitem__("trials", 1),
            lambda r: r.__setitem__("injected", "field"),
            lambda r: r["scenarios"][0]["trials"][0]["phases"][0]
            .__setitem__("observation", None),
            lambda r: r.__setitem__("report_version", 1),
        ]
        for i, mutate in enumerate(mutations):
            tampered = copy.deepcopy(base)
            mutate(tampered)
            self.assertFalse(verify_report(tampered).ok, f"mutation #{i} undetected")

    def test_malformed_report_fails_cleanly(self):
        r = self.build()
        r["scenarios"][0]["trials"] = "not a list of dicts"
        self.assertFalse(verify_report(r).ok)


class TestV1Compat(unittest.TestCase):
    def test_v1_report_still_verifies_and_tamper_is_caught(self):
        with open(FIXTURES / "report_v1.json") as fh:
            v1 = json.load(fh)
        self.assertEqual(v1["report_version"], 1)
        res = verify_report(v1)
        self.assertTrue(res.chain_ok)
        # signed fixture: "valid" with cryptography, honestly "unverifiable" without
        self.assertEqual(res.signature_status,
                         "valid" if crypto_available() else "unverifiable")
        v1["scenarios"][0]["verdict"] = PASS
        self.assertFalse(verify_report(v1).ok)
        self.assertFalse(verify_report(v1).chain_ok)


def _report(verdicts: dict, rates: dict = None) -> dict:
    scns = []
    for sid, v in verdicts.items():
        k, n = (rates or {}).get(sid, (1 if v == PASS else 0, 1))
        scns.append({"scenario_id": sid, "verdict": v,
                     "stats": {"pass_rate": {"k": k, "n": n, "rate": k / n}},
                     "trials": [{"checks": [{"type": "c1", "verdict": v}]}]})
    return {"run_id": "r", "scenarios": scns, "families": []}


class TestDiff(unittest.TestCase):
    def test_regressions(self):
        d = diff_reports(_report({"a": PASS, "b": PASS}), _report({"a": PASS, "b": FAIL}))
        self.assertTrue(d["regressed"])
        row = [r for r in d["scenarios"] if r["scenario_id"] == "b"][0]
        self.assertIn("verdict pass -> fail", row["reasons"])
        self.assertIn("newly failing check(s): c1", row["reasons"])

    def test_no_regression_and_tolerance(self):
        same = _report({"a": PASS})
        self.assertFalse(diff_reports(same, same)["regressed"])
        old = _report({"a": FAIL}, {"a": (8, 10)})
        new = _report({"a": FAIL}, {"a": (7, 10)})
        self.assertTrue(diff_reports(old, new)["regressed"])
        self.assertFalse(diff_reports(old, new, tolerance=0.15)["regressed"])

    def test_missing_scenario_is_a_regression(self):
        d = diff_reports(_report({"a": PASS, "b": PASS}), _report({"a": PASS}))
        self.assertTrue(d["regressed"])

    def test_cli_exit_codes(self):
        tmp = tempfile.mkdtemp(prefix="arig-diff-")
        signer = Signer(key_path=Path(tmp) / "k.key")
        scn = scenarios.load_one("destructive_command")

        def write(name, verdict):
            o = outcome_from_trials(scn, [_trial(scn, 1, verdict)])
            path = os.path.join(tmp, name)
            with open(path, "w") as fh:
                json.dump(build_report([o], {"command": "x"}, _caps(), signer=signer), fh)
            return path

        def run(*argv):
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                return cli.main(list(argv))

        good, bad = write("good.json", PASS), write("bad.json", FAIL)
        self.assertEqual(run("diff", good, good), cli.EXIT_OK)
        self.assertEqual(run("diff", good, bad), cli.EXIT_REGRESSION)
        with open(bad) as fh:
            tampered = json.load(fh)
        tampered["scenarios"][0]["verdict"] = PASS
        with open(bad, "w") as fh:
            json.dump(tampered, fh)
        self.assertEqual(run("diff", good, bad), cli.EXIT_VERIFY_FAILED)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
