"""SARIF 2.1.0 output so agentrig findings show up in GitHub code scanning.

One result per (scenario, failed check), counted across trials; inconclusive
scenarios become ``note`` results (we could not confirm safety -- say so).
Built only from the finished report, which is already secret-scrubbed, so the
SARIF cannot carry the LLM API key either.

Code scanning needs a file location. We point at the agent's own script as it
appeared in the ``--agent`` command (the thing under test), line 1.
"""

from __future__ import annotations

import shlex

from agentrig.report_text import failing_checks

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
_SCRIPT_EXT = (".py", ".js", ".mjs", ".ts", ".sh", ".rb", ".go")


def _agent_location(report: dict) -> str:
    try:
        tokens = shlex.split(report.get("agent", {}).get("command", ""))
    except ValueError:
        tokens = []
    for tok in tokens:
        if tok.endswith(_SCRIPT_EXT) and not tok.startswith("/"):
            return tok
    for tok in tokens:
        if tok.endswith(_SCRIPT_EXT):
            return tok.lstrip("/")
    return "agentrig-agent"


def _severity_of(scn: dict, check_type: str) -> str:
    for t in scn.get("trials") or [{"checks": scn.get("checks", [])}]:
        for c in t.get("checks", []):
            if c.get("type") == check_type and c.get("severity"):
                return c["severity"]
    return scn.get("severity", "high")


def to_sarif(report: dict) -> dict:
    location = _agent_location(report)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    def rule(rule_id: str, scn: dict, sev: str) -> None:
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("/", "_"),
            "shortDescription": {"text": scn.get("title") or scn.get("scenario_id")},
            "fullDescription": {"text": "Safe behavior: " + (scn.get("safe_behavior") or "")},
            "helpUri": "https://github.com/vatsal191201/agentrig/blob/master/docs/scenarios.md",
            "defaultConfiguration": {"level": _LEVEL.get(sev, "error")},
            "properties": {"tags": ["security", "ai-agent", scn.get("category", "")],
                           "security-severity": _SECURITY_SEVERITY.get(sev, "8.0")},
        })

    for scn in report.get("scenarios", []):
        sid = scn.get("scenario_id")
        verdict = scn.get("verdict")
        if verdict == "fail":
            for ctype, nfail, ntrials, detail in failing_checks(scn):
                if not nfail:
                    continue
                sev = _severity_of(scn, ctype)
                rid = f"agentrig/{sid}/{ctype}"
                rule(rid, scn, sev)
                results.append(_result(rid, _LEVEL.get(sev, "error"),
                                       f"{sid}: {ctype} failed in {nfail}/{ntrials} "
                                       f"trial(s): {detail}", location, sid, ctype,
                                       report))
        elif verdict in ("inconclusive", "error"):
            rid = f"agentrig/{sid}/{verdict}"
            rule(rid, scn, "low")
            results.append(_result(rid, "note", f"{sid}: {verdict} — "
                                   f"{scn.get('note') or scn.get('error') or ''}",
                                   location, sid, verdict, report))

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentrig",
                "version": report.get("agentrig_version"),
                "informationUri": "https://github.com/vatsal191201/agentrig",
                "rules": list(rules.values())}},
            "automationDetails": {"id": f"agentrig/{report.get('run_id')}"},
            "results": results,
            "properties": {"summary": report.get("summary"),
                           "chain_head": (report.get("chain") or {}).get("head"),
                           "signed": (report.get("signature") or {}).get("signed")},
        }],
    }


def _result(rule_id, level, text, location, sid, key, report) -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": text},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": location},
            "region": {"startLine": 1}}}],
        "partialFingerprints": {"agentrigScenarioCheck/v1": f"{sid}/{key}"},
        "properties": {"scenario_id": sid, "run_id": report.get("run_id")},
    }
