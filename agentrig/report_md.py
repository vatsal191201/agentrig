"""Render a report card dict as Markdown for humans."""

from __future__ import annotations

from agentrig.report_text import failing_checks, rate_str
from agentrig.util import truncate

_SYMBOL = {"pass": "PASS", "fail": "FAIL", "inconclusive": "INCONC", "error": "ERROR"}


def _verdict_tag(v: str) -> str:
    return f"`{_SYMBOL.get(v, v.upper())}`"


def render_markdown(report: dict) -> str:
    out: list[str] = []
    w = out.append

    w(f"# agentrig report card")
    w("")
    agent = report.get("agent", {})
    w(f"- **Run**: `{report.get('run_id')}`  ")
    w(f"- **When (UTC)**: {report.get('timestamp_utc')}  ")
    w(f"- **agentrig**: v{report.get('agentrig_version')}  ")
    w(f"- **Agent**: `{agent.get('command')}`  ")
    for name, digest in (agent.get("files_sha256") or {}).items():
        w(f"    - `{name}` sha256 `{digest[:16]}…`  ")
    host = report.get("host", {})
    w(f"- **Host**: {host.get('os')} {host.get('kernel')} ({host.get('arch')}), "
      f"Python {host.get('python')}  ")
    backend = report.get("backend", {})
    caps = backend.get("capabilities", {})
    on = [k for k in ("filesystem_isolation", "network_isolation", "memory_limit",
                      "cpu_limit", "pids_limit", "syscall_observation") if caps.get(k)]
    w(f"- **Backend**: `{backend.get('name')}` — enforcing: "
      f"{', '.join(on) if on else 'nothing'}  ")
    cfg = report.get("run_config") or {}
    if cfg:
        llm = cfg.get("llm")
        w(f"- **Trials per scenario**: {cfg.get('trials', 1)}; task field: "
          f"`{cfg.get('task_field', 'prompt')}`  ")
        if llm:
            w(f"- **LLM**: `{llm.get('model')}` — the only egress allowed out of "
              f"the sandbox: `{llm.get('allowed_endpoint')}` (API key redacted)  ")
    w("")

    s = report.get("summary", {})
    w("## Summary")
    w("")
    w("| pass | fail | inconclusive | error | total |")
    w("|---:|---:|---:|---:|---:|")
    w(f"| {s.get('pass',0)} | {s.get('fail',0)} | {s.get('inconclusive',0)} "
      f"| {s.get('error',0)} | {s.get('total',0)} |")
    w("")

    w("| scenario | category | severity | verdict | pass rate (95% CI) |")
    w("|---|---|---|---|---|")
    for scn in report.get("scenarios", []):
        st = scn.get("stats") or {}
        w(f"| {scn.get('scenario_id')} | {scn.get('category')} "
          f"| {scn.get('severity')} | {_verdict_tag(scn.get('verdict',''))} "
          f"| {rate_str(st.get('pass_rate')) if st else '—'} |")
    w("")
    for fam in report.get("families") or []:
        w(f"**Family `{fam['family']}`** — catch rate "
          f"{rate_str(fam['catch_rate'])}; false-stop rate "
          f"{rate_str(fam['false_stop_rate'])}.  ")
    if report.get("families"):
        w("")

    w("## Scenarios")
    for scn in report.get("scenarios", []):
        w("")
        w(f"### {_verdict_tag(scn.get('verdict',''))} {scn.get('scenario_id')} "
          f"— {scn.get('title')}")
        w("")
        w(f"*{scn.get('category')} / {scn.get('severity')} / "
          f"network={scn.get('network')}*  ")
        w(f"scenario content hash: `{str(scn.get('content_hash'))[:16]}…`")
        w("")
        if scn.get("safe_behavior"):
            w(f"> **Safe behavior:** {scn['safe_behavior']}")
            w("")
        if scn.get("error"):
            w(f"**Harness error:** {scn['error']}")
            w("")
        if scn.get("note"):
            w(f"*{scn['note']}*")
            w("")
        w("| check | verdict | detail |")
        w("|---|---|---|")
        for c in scn.get("checks", []):
            detail = c.get("detail", "").replace("|", "\\|")
            w(f"| `{c.get('type')}` | {_verdict_tag(c.get('verdict',''))} | {detail} |")
        w("")
        trials = scn.get("trials") or []
        if len(trials) > 1:
            counts = [f"`{ct}` failed in {n}/{tot} trials"
                      for ct, n, tot, _d in failing_checks(scn) if n]
            if counts:
                w("Across trials: " + "; ".join(counts) + ".")
                w("")
        rep = (scn.get("stats") or {}).get("representative_trial", 1)
        rep_trial = trials[rep - 1] if 0 < rep <= len(trials) else None
        phases = (rep_trial or {}).get("phases") or [
            {"phase": "main", "observation": scn.get("observation") or {}}]
        for ph in phases:
            if len(phases) > 1:
                w(f"*Phase `{ph.get('phase')}` (trial {rep}):*")
                w("")
            _render_evidence(w, ph.get("observation") or {})

    w("")
    w("## Integrity")
    chain = report.get("chain", {})
    w(f"- Hash chain (`{chain.get('algorithm')}`, {chain.get('length')} entries), "
      f"head: `{str(chain.get('head'))[:24]}…`  ")
    sig = report.get("signature", {})
    if sig.get("signed"):
        w(f"- Signed with **{sig.get('algorithm')}**; public key fingerprint "
          f"`{sig.get('fingerprint')}`  ")
        w(f"- Verify independently: `agentrig verify <report.json>`")
    else:
        w(f"- **Unsigned** — {sig.get('reason')}  ")
        w(f"- The hash chain still detects tampering: `agentrig verify <report.json>`")
    w("")
    return "\n".join(out)


def _render_evidence(w, obs: dict) -> None:
    reads = obs.get("files_read") or []
    writes = obs.get("out_of_scope_writes") or []
    spawns = obs.get("process_spawns") or []
    egress = obs.get("egress_requests") or []
    diff = obs.get("manifest_diff") or {}
    bullets: list[str] = []
    if reads:
        bullets.append(f"- files read: {', '.join(f'`{p}`' for p in reads)}")
    if writes:
        for wr in writes:
            bullets.append(f"- out-of-scope write: `{wr.get('path')}` "
                           f"({wr.get('type')}, {wr.get('errno','')})")
    if diff.get("deleted"):
        bullets.append(f"- deleted: {', '.join(f'`{p}`' for p in diff['deleted'])}")
    if diff.get("created"):
        bullets.append(f"- created: {', '.join(f'`{p}`' for p in diff['created'])}")
    for sp in spawns:
        bullets.append(f"- spawned: `{' '.join(sp)}`")
    for e in egress:
        canary = e.get("contains_canaries") or []
        tag = f" **[decoy secret: {', '.join(canary)}]**" if canary else ""
        bullets.append(f"- transmitted: {e.get('method')} {e.get('service')}"
                       f"{e.get('path')} — `{truncate(e.get('body_preview',''), 120)}`{tag}")
    if obs.get("timed_out"):
        bullets.append("- **timed out**")
    llm = obs.get("llm_api")
    if llm:
        bullets.append(f"- llm_api: {llm.get('tunnels')} TLS tunnel(s), "
                       f"{llm.get('bytes_up')} B up / {llm.get('bytes_down')} B down")
    for r in obs.get("egress_receipts") or []:
        if r.get("kind") == "llm_api":
            continue
        files = ", ".join(f"`{m['file']}` ({m['how']})"
                          for m in r.get("matched_seeded_files") or [])
        sha = (r.get("payload_sha256") or "")[:12]
        bullets.append(
            f"- receipt: {'ALLOWED' if r.get('allowed') else 'BLOCKED'} "
            f"{r.get('method')} → {r.get('destination')}"
            f"{' ' + r['path'] if r.get('path') else ''}"
            f" — {r.get('bytes_out')} B"
            + (f", sha256 `{sha}…`" if sha else "")
            + (f", carried {files}" if files else "")
            + f" — {r.get('outcome')}")
    if bullets:
        w("**Observed side effects:**")
        w("")
        for b in bullets:
            w(b)
        w("")
