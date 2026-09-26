"""Terminal rendering of a report card (v1 and v2 reports)."""

from __future__ import annotations


def _pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def rate_str(r: dict) -> str:
    """'3/5 (60%, 95% CI 23-88%)' from a stats.rate() dict."""
    if not r or not r.get("n"):
        return "n/a"
    lo, hi = r.get("wilson95", [None, None])
    return (f"{r['k']}/{r['n']} ({_pct(r['rate'])}, 95% CI "
            f"{_pct(lo)}-{_pct(hi)})")


def failing_checks(scn: dict) -> list[tuple[str, int, int, str]]:
    """(check type, trials failed, trials, first failing detail) per check."""
    trials = scn.get("trials") or [{"checks": scn.get("checks", [])}]
    order: list[str] = []
    fails: dict[str, int] = {}
    detail: dict[str, str] = {}
    other: dict[str, str] = {}
    for t in trials:
        for c in t.get("checks", []):
            ct = c.get("type")
            if ct not in order:
                order.append(ct)
            if c.get("verdict") == "fail":
                fails[ct] = fails.get(ct, 0) + 1
                detail.setdefault(ct, c.get("detail", ""))
            elif c.get("verdict") != "pass":
                other.setdefault(ct, f"{c.get('verdict')} — {c.get('detail', '')}")
    out = []
    for ct in order:
        if ct in fails:
            out.append((ct, fails[ct], len(trials), detail[ct]))
        elif ct in other:
            out.append((ct, 0, len(trials), other[ct]))
    return out


def render_run_summary(report: dict, *, json_path=None, md_path=None,
                       sarif_path=None) -> str:
    lines: list[str] = []
    w = lines.append
    w(f"agentrig {report['agentrig_version']}  run {report['run_id']}")
    w(f"agent: {report['agent']['command']}")
    cfg = report.get("run_config") or {}
    if cfg:
        llm = cfg.get("llm")
        extra = f"; llm: {llm['model']} via {llm['allowed_endpoint']}" if llm else ""
        w(f"trials: {cfg.get('trials', 1)}; task field: {cfg.get('task_field', 'prompt')}"
          f"{extra}")
    caps = report["backend"]["capabilities"]
    enforcing = [k for k in ("filesystem_isolation", "network_isolation",
                             "memory_limit", "cpu_limit", "pids_limit",
                             "syscall_observation") if caps.get(k)]
    w(f"backend: {report['backend']['name']} (enforcing: "
      f"{', '.join(enforcing) or 'nothing'})")
    w("-" * 64)
    multi = int(cfg.get("trials", 1) or 1) > 1
    for scn in report["scenarios"]:
        head = (f"  {scn['verdict'].upper():13} {scn['scenario_id']:34} "
                f"{scn['category']}/{scn['severity']}")
        st = scn.get("stats") or {}
        if multi and st:
            k = (st.get("pass_hat_k") or {})
            head += (f"\n      pass {rate_str(st.get('pass_rate'))}; "
                     f"pass^{k.get('k')}={int(k.get('value', 0))}")
        w(head)
        for ct, nfail, ntr, det in failing_checks(scn):
            if nfail:
                where = f" in {nfail}/{ntr} trials" if multi else ""
                w(f"      - {ct}: fail{where} — {det}")
            else:
                w(f"      - {ct}: {det}")
        if scn.get("note") and (multi or scn["verdict"] in ("inconclusive", "error")):
            w(f"      note: {scn['note']}")
        for tr in _trip_events(scn):
            w(f"      HALTED ({tr['event']['kind']}: {tr['event']['detail']}) "
              f"after {tr['detection_latency_s']}s")
        prop = scn.get("propagation")
        if prop:
            w(f"      propagation: {prop['infected_hops']}/{prop['hops_run']} hops "
              f"infected (replication rate {_pct(prop['replication_rate'])}); "
              f"chain length {prop['chain_length']}")
            for h in prop.get("per_hop", []):
                w(f"        hop {h['hop']}: "
                  + ("replied" if h["replied"] else "no reply")
                  + (", INFECTED" if h["infected"] else ", clean")
                  + (", scheduled" if h.get("scheduled") else "")
                  + (", language switch" if h.get("switched_language") else ""))
        if scn.get("error"):
            w(f"      ! harness error: {scn['error']}")
    w("-" * 64)
    for fam in report.get("families") or []:
        w(f"family {fam['family']}: catch rate {rate_str(fam['catch_rate'])}; "
          f"false-stop rate {rate_str(fam['false_stop_rate'])}")
    s = report["summary"]
    w(f"summary: {s.get('pass', 0)} pass, {s.get('fail', 0)} fail, "
      f"{s.get('inconclusive', 0)} inconclusive, {s.get('error', 0)} error "
      f"(of {s.get('total', 0)}"
      + (f"; {s.get('trials_total')} trials)" if multi else ")"))
    llm = _llm_totals(report)
    if llm:
        w(f"llm_api egress: {llm['tunnels']} tunnel(s), {llm['bytes_up']} B up, "
          f"{llm['bytes_down']} B down (the only traffic allowed out)")
    sig = report["signature"]
    if sig.get("signed"):
        w(f"signed: ed25519 fingerprint {sig['fingerprint']}; "
          f"chain head {report['chain']['head'][:16]}…")
    else:
        w(f"unsigned (hash chain head {report['chain']['head'][:16]}…)")
    for label, path in (("report", json_path), ("markdown", md_path),
                        ("sarif", sarif_path)):
        if path:
            w(f"{label} written: {path}")
    return "\n".join(lines)


def _trip_events(scn: dict) -> list[dict]:
    """Tripwire halts recorded across a scenario's trials/phases."""
    out = []
    for t in scn.get("trials") or []:
        for ph in t.get("phases") or []:
            tw = (ph.get("observation") or {}).get("tripwire")
            if tw and tw.get("tripped"):
                out.append(tw)
    return out


def _llm_totals(report: dict):
    tot = None
    for scn in report.get("scenarios", []):
        for t in scn.get("trials", []):
            for ph in t.get("phases", []):
                llm = (ph.get("observation") or {}).get("llm_api")
                if llm:
                    tot = tot or {"tunnels": 0, "bytes_up": 0, "bytes_down": 0}
                    for k in tot:
                        tot[k] += int(llm.get(k, 0))
    return tot
