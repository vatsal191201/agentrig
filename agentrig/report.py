"""Build, sign, and verify the report card.

The report is a JSON document. Its tamper-evidence is a SHA-256 hash chain over
an ordered list of records (header, then each scenario and each of its observed
events, then the summary). Each chain entry folds in the previous digest, so the
final ``head`` commits to the entire document. If ``cryptography`` is available
the head is signed with ed25519; otherwise the report is emitted unsigned and
says so.

``verify_report`` recomputes the chain from the document's own content and
compares it to the stored chain and head, then checks the signature. Flipping a
single byte anywhere in the chained content changes the recomputed head and the
verification fails.

Report version 2 (v0.2) adds trials and phases. Its chain covers *every* field
by construction -- each record is a whole dict minus only its child list --
so a field added later can never silently fall outside the chain. Version 1
reports keep their original record layout and still verify.

Before chaining, the whole report is passed through the run's secret scrubber:
the LLM API key cannot be signed into a report, whatever path it took.
"""

from __future__ import annotations

import hashlib
import platform
from dataclasses import dataclass, field
from typing import Optional

from agentrig import __version__
from agentrig.backends.base import Capabilities
from agentrig.engine import ScenarioOutcome, TrialOutcome
from agentrig.signing import Signer, crypto_available, verify_signature
from agentrig.stats import rate
from agentrig.util import canonical_json, canonical_sha256, new_run_id, utc_now_iso
from agentrig.verdict import ERROR, FAIL, INCONCLUSIVE, PASS, trial_aborted

REPORT_VERSION = 2
GENESIS = "0" * 64
# Keys that are structure (child lists) or chain output, not chained content.
_V2_STRUCTURAL = ("scenarios", "families", "summary", "chain", "signature")


# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------


def _chain_records(report: dict) -> list[dict]:
    """Deterministic ordered records the chain covers. Used by build AND verify
    so both sides agree byte-for-byte."""
    if isinstance(report.get("report_version"), int) and report["report_version"] >= 2:
        return _chain_records_v2(report)
    return _chain_records_v1(report)


def _without(d: dict, *keys: str) -> dict:
    return {k: v for k, v in d.items() if k not in keys}


def _chain_records_v2(report: dict) -> list[dict]:
    records: list[dict] = [{"kind": "header",
                            "header": _without(report, *_V2_STRUCTURAL)}]
    for s in report.get("scenarios", []):
        sid = s.get("scenario_id")
        records.append({"kind": "scenario", "scenario": _without(s, "trials")})
        for t in s.get("trials", []):
            records.append({"kind": "trial", "scenario_id": sid,
                            "trial": _without(t, "phases")})
            for ph in t.get("phases", []):
                records.append({"kind": "phase", "scenario_id": sid,
                                "trial_index": t.get("trial"),
                                "phase": _without(ph, "events")})
                for ev in ph.get("events", []):
                    records.append({"kind": "event", "scenario_id": sid,
                                    "trial_index": t.get("trial"),
                                    "phase_id": ph.get("phase"), "event": ev})
    records.append({"kind": "families", "families": report.get("families")})
    records.append({"kind": "summary", "summary": report.get("summary")})
    return records


def _chain_records_v1(report: dict) -> list[dict]:
    records: list[dict] = [{
        "kind": "header",
        "agentrig_version": report.get("agentrig_version"),
        "report_version": report.get("report_version"),
        "run_id": report.get("run_id"),
        "timestamp_utc": report.get("timestamp_utc"),
        "agent": report.get("agent"),
        "host": report.get("host"),
        "backend": report.get("backend"),
    }]
    for s in report.get("scenarios", []):
        records.append({
            "kind": "scenario",
            "scenario_id": s.get("scenario_id"),
            "title": s.get("title"),
            "category": s.get("category"),
            "severity": s.get("severity"),
            "network": s.get("network"),
            "content_hash": s.get("content_hash"),
            "verdict": s.get("verdict"),
            "safe_behavior": s.get("safe_behavior"),
            "checks": s.get("checks"),
            "observation": s.get("observation"),
        })
        for ev in s.get("events", []):
            records.append({"kind": "event", "scenario_id": s.get("scenario_id"),
                            "event": ev})
    records.append({"kind": "summary", "summary": report.get("summary")})
    return records


def _compute_chain(records: list[dict]) -> tuple[list[dict], str]:
    """Return (entries, head). entry = {seq, digest}; digest folds in prev."""
    prev = GENESIS
    entries: list[dict] = []
    for i, rec in enumerate(records):
        h = hashlib.sha256(bytes.fromhex(prev) + canonical_json(rec)).hexdigest()
        entries.append({"seq": i, "digest": h})
        prev = h
    return entries, prev


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _host_fingerprint() -> dict:
    # Deliberately excludes hostname / user / paths -- no host secrets.
    return {
        "os": platform.system(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
    }


def _trials_of(outcome: ScenarioOutcome) -> list[TrialOutcome]:
    """Trials of an outcome; a hand-built single-run outcome counts as one."""
    if outcome.trials:
        return outcome.trials
    from agentrig.engine import PhaseRun
    return [TrialOutcome(1, outcome.verdict,
                         [PhaseRun("main", outcome.observation, outcome.spec_summary)],
                         error=outcome.error)]


def _trial_dict(t: TrialOutcome) -> dict:
    d = {"trial": t.index, "verdict": t.verdict.verdict, "note": t.verdict.note,
         "checks": [c.to_dict() for c in t.verdict.checks],
         "phases": [{"phase": ph.phase_id,
                     "observation": ph.observation.summary() if ph.observation else None,
                     "events": ph.observation.events if ph.observation else []}
                    for ph in t.phases]}
    if t.error:
        d["error"] = t.error
    return d


def _scenario_dict(outcome: ScenarioOutcome) -> dict:
    scn = outcome.scenario
    trials = _trials_of(outcome)
    stats = outcome.stats or {
        "trials": 1, "pass_rate": rate(int(outcome.verdict.verdict == PASS), 1),
        "representative_trial": 1}
    d = {
        "scenario_id": scn.id,
        "title": scn.title,
        "category": scn.category,
        "severity": scn.severity,
        "network": scn.network,
        "content_hash": scn.content_hash,
        "verdict": outcome.verdict.verdict,
        "safe_behavior": outcome.verdict.safe_behavior,
        "note": outcome.verdict.note,
        "stats": stats,
        # Representative trial (see stats.representative_trial), first phase:
        # the v1-shaped view. trials[] below is the complete record.
        "checks": [c.to_dict() for c in outcome.verdict.checks],
        "observation": outcome.observation.summary() if outcome.observation else None,
        "events": outcome.observation.events if outcome.observation else [],
        "trials": [_trial_dict(t) for t in trials],
    }
    if scn.family:
        d.update(family=scn.family, variant=scn.variant, perturbed=scn.perturbed)
    if outcome.error:
        d["error"] = outcome.error
    return d


def _summary(outcomes: list[ScenarioOutcome]) -> dict:
    counts = {PASS: 0, FAIL: 0, INCONCLUSIVE: 0, ERROR: 0}
    for o in outcomes:
        counts[o.verdict.verdict] = counts.get(o.verdict.verdict, 0) + 1
    counts["total"] = len(outcomes)
    counts["trials_total"] = sum(len(_trials_of(o)) for o in outcomes)
    return counts


def _families(outcomes: list[ScenarioOutcome]) -> list[dict]:
    """Catch rate (perturbed -> aborted) and false-stop rate (control ->
    aborted) for each scenario family, over every trial of every variant."""
    fams: dict[str, dict] = {}
    for o in outcomes:
        scn = o.scenario
        if not scn.family:
            continue
        f = fams.setdefault(scn.family, {"perturbed": [0, 0], "control": [0, 0],
                                         "undetermined": 0, "variants": []})
        f["variants"].append(scn.variant)
        bucket = f["perturbed" if scn.perturbed else "control"]
        for t in _trials_of(o):
            aborted = trial_aborted(t, scn.abort_signal)
            if aborted is None:
                f["undetermined"] += 1
                continue
            bucket[0] += int(aborted)
            bucket[1] += 1
    out = []
    for name, f in sorted(fams.items()):
        out.append({
            "family": name,
            "variants": f["variants"],
            "catch_rate": rate(*f["perturbed"]),
            "false_stop_rate": rate(*f["control"]),
            "undetermined_trials": f["undetermined"],
            "definition": "catch = a perturbed variant's trial aborted (never "
                          "triggered the abort signal's request); false stop = a "
                          "control variant's trial aborted",
        })
    return out


def build_report(outcomes: list[ScenarioOutcome], agent_info: dict,
                 capabilities: Capabilities, *,
                 signer: Optional[Signer] = None,
                 run_config: Optional[dict] = None,
                 scrubber=None) -> dict:
    """Assemble the full report dict, scrub it, compute the chain, sign it."""
    report: dict = {
        "agentrig_version": __version__,
        "report_version": REPORT_VERSION,
        "run_id": new_run_id(),
        "timestamp_utc": utc_now_iso(),
        "agent": agent_info,
        "host": _host_fingerprint(),
        "backend": {"name": capabilities.backend,
                    "capabilities": capabilities.to_dict()},
        "run_config": run_config or {"trials": 1, "task_field": "prompt", "llm": None},
        "scenarios": [_scenario_dict(o) for o in outcomes],
        "families": _families(outcomes),
        "summary": _summary(outcomes),
    }
    if scrubber:
        report = scrubber.deep(report)

    entries, head = _compute_chain(_chain_records(report))
    report["chain"] = {"algorithm": "sha256-chain", "genesis": GENESIS,
                       "length": len(entries), "entries": entries, "head": head}

    signer = signer or Signer()
    if signer.available:
        report["signature"] = {
            "signed": True,
            "algorithm": "ed25519",
            "public_key": signer.public_key_hex(),
            "fingerprint": signer.fingerprint(),
            "signature": signer.sign_hex(bytes.fromhex(head)),
        }
    else:
        report["signature"] = {
            "signed": False,
            "reason": "cryptography not installed; report is unsigned "
                      "(hash chain still provides tamper-evidence)",
        }
    return report


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool
    chain_ok: bool
    signature_status: str  # valid | invalid | unsigned | unverifiable
    head_stored: Optional[str] = None
    head_recomputed: Optional[str] = None
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "chain_ok": self.chain_ok,
            "signature_status": self.signature_status,
            "head_stored": self.head_stored,
            "head_recomputed": self.head_recomputed,
            "problems": self.problems,
        }


def verify_report(report: dict) -> VerifyResult:
    """Independently re-derive the chain and check the signature."""
    problems: list[str] = []
    stored_chain = report.get("chain") or {}
    stored_head = stored_chain.get("head")

    try:
        entries, head = _compute_chain(_chain_records(report))
    except (AttributeError, TypeError, ValueError) as exc:
        return VerifyResult(ok=False, chain_ok=False, signature_status="unverifiable",
                            head_stored=stored_head, head_recomputed=None,
                            problems=[f"malformed report structure: {exc}"])
    chain_ok = head == stored_head
    if not chain_ok:
        problems.append(
            f"chain head mismatch: recomputed {head[:16]}... != "
            f"stored {str(stored_head)[:16]}... (content was altered)")

    stored_entries = stored_chain.get("entries")
    if stored_entries is not None and stored_entries != entries:
        chain_ok = False
        problems.append("per-entry digests do not match recomputed chain")

    sig = report.get("signature") or {}
    if not sig.get("signed"):
        signature_status = "unsigned"
    elif not crypto_available():
        signature_status = "unverifiable"
        problems.append("report is signed but cryptography is not installed; "
                        "cannot check the ed25519 signature")
    else:
        try:
            valid = verify_signature(sig["public_key"], bytes.fromhex(str(stored_head)),
                                     sig["signature"])
        except Exception as exc:  # malformed signature material
            valid = False
            problems.append(f"signature material invalid: {exc}")
        signature_status = "valid" if valid else "invalid"
        if not valid:
            problems.append("ed25519 signature does not verify against the "
                            "embedded public key")

    ok = chain_ok and signature_status in ("valid", "unsigned")
    return VerifyResult(ok=ok, chain_ok=chain_ok,
                        signature_status=signature_status,
                        head_stored=stored_head, head_recomputed=head,
                        problems=problems)
