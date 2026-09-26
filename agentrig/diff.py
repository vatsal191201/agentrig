"""Regression view between two report cards (``agentrig diff old new``).

Typical uses: model A vs model B, or before/after a prompt change. Per
scenario it shows the pass-rate change and any check that fails now but did
not before. It is built to gate CI, so it is strict by default:

  regression =  the verdict got worse (pass -> inconclusive/error -> fail)
             or a check type fails now that never failed before
             or the pass rate dropped by more than --tolerance (default 0)
             or a scenario present before is missing now
             or a new scenario fails
             or a family's catch rate dropped / false-stop rate rose
                beyond --tolerance
"""

from __future__ import annotations

_RANK = {"fail": 0, "error": 1, "inconclusive": 1, "pass": 2}


def _pass_rate(scn: dict) -> float:
    r = ((scn.get("stats") or {}).get("pass_rate") or {}).get("rate")
    if r is None:  # v1 report: one run
        return 1.0 if scn.get("verdict") == "pass" else 0.0
    return float(r)


def _failed_checks(scn: dict) -> set[str]:
    trials = scn.get("trials") or [{"checks": scn.get("checks", [])}]
    return {c.get("type") for t in trials for c in t.get("checks", [])
            if c.get("verdict") == "fail"}


def diff_reports(old: dict, new: dict, *, tolerance: float = 0.0) -> dict:
    rows: list[dict] = []
    old_s = {s["scenario_id"]: s for s in old.get("scenarios", [])}
    new_s = {s["scenario_id"]: s for s in new.get("scenarios", [])}
    for sid in sorted(set(old_s) | set(new_s)):
        o, n = old_s.get(sid), new_s.get(sid)
        row: dict = {"scenario_id": sid, "reasons": []}
        if o is None:
            row.update(status="added", new_verdict=n["verdict"],
                       new_rate=_pass_rate(n))
            if n["verdict"] == "fail":
                row["reasons"].append("new scenario fails")
        elif n is None:
            row.update(status="removed", old_verdict=o["verdict"],
                       old_rate=_pass_rate(o))
            row["reasons"].append("scenario missing from the new report")
        else:
            orate, nrate = _pass_rate(o), _pass_rate(n)
            new_fail = sorted(_failed_checks(n) - _failed_checks(o))
            row.update(status="compared", old_verdict=o["verdict"],
                       new_verdict=n["verdict"], old_rate=orate, new_rate=nrate,
                       rate_delta=round(nrate - orate, 4), new_failing_checks=new_fail)
            if _RANK.get(n["verdict"], 1) < _RANK.get(o["verdict"], 1):
                row["reasons"].append(f"verdict {o['verdict']} -> {n['verdict']}")
            if new_fail:
                row["reasons"].append("newly failing check(s): " + ", ".join(new_fail))
            if nrate < orate - tolerance - 1e-9:
                row["reasons"].append(f"pass rate {orate:.0%} -> {nrate:.0%}")
        row["regressed"] = bool(row["reasons"])
        rows.append(row)

    fam_rows: list[dict] = []
    old_f = {f["family"]: f for f in old.get("families") or []}
    for f in new.get("families") or []:
        of = old_f.get(f["family"])
        if not of:
            continue
        reasons = []
        oc, nc = of["catch_rate"].get("rate"), f["catch_rate"].get("rate")
        ofs, nfs = of["false_stop_rate"].get("rate"), f["false_stop_rate"].get("rate")
        if oc is not None and nc is not None and nc < oc - tolerance - 1e-9:
            reasons.append(f"catch rate {oc:.0%} -> {nc:.0%}")
        if ofs is not None and nfs is not None and nfs > ofs + tolerance + 1e-9:
            reasons.append(f"false-stop rate {ofs:.0%} -> {nfs:.0%}")
        fam_rows.append({"family": f["family"], "reasons": reasons,
                         "regressed": bool(reasons)})

    regressed = any(r["regressed"] for r in rows) or any(r["regressed"] for r in fam_rows)
    return {"old_run": old.get("run_id"), "new_run": new.get("run_id"),
            "tolerance": tolerance, "scenarios": rows, "families": fam_rows,
            "regressed": regressed}


def render_diff(d: dict) -> str:
    lines = [f"agentrig diff  {d['old_run']}  ->  {d['new_run']}"
             f"  (tolerance {d['tolerance']:.0%})", "-" * 72]
    for r in d["scenarios"]:
        mark = "REGRESSED" if r["regressed"] else "ok"
        if r["status"] == "compared":
            lines.append(f"  {mark:10} {r['scenario_id']:34} {r['old_verdict']:>12} -> "
                         f"{r['new_verdict']:<12} pass {r['old_rate']:.0%} -> "
                         f"{r['new_rate']:.0%} ({r['rate_delta']:+.0%})")
        elif r["status"] == "added":
            lines.append(f"  {mark:10} {r['scenario_id']:34} (new) -> {r['new_verdict']}")
        else:
            lines.append(f"  {mark:10} {r['scenario_id']:34} {r['old_verdict']} -> (missing)")
        for reason in r["reasons"]:
            lines.append(f"      - {reason}")
    for f in d["families"]:
        lines.append(f"  {'REGRESSED' if f['regressed'] else 'ok':10} family {f['family']}")
        for reason in f["reasons"]:
            lines.append(f"      - {reason}")
    lines.append("-" * 72)
    n = sum(r["regressed"] for r in d["scenarios"]) + sum(f["regressed"] for f in d["families"])
    lines.append(f"result: {'REGRESSION (' + str(n) + ')' if d['regressed'] else 'no regression'}")
    return "\n".join(lines)
