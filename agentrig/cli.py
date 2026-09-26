"""agentrig command-line interface.

    agentrig run  --agent <cmd> --scenario <id|all> [--backend local] [--json f]
    agentrig list-scenarios
    agentrig report <run.json> [--md]
    agentrig verify <run.json>
    agentrig doctor

Exit codes for `run`: 0 = no failures, 3 = at least one scenario FAILED,
2 = could not run (isolation/harness error).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from agentrig import __version__, doctor as doctor_mod
from agentrig import scenarios as scenario_mod
from agentrig.backends import available_backends, get_backend
from agentrig.backends.base import Limits
from agentrig.engine import Engine
from agentrig.errors import AgentrigError, IsolationError
from agentrig.report import build_report, verify_report
from agentrig.report_md import render_markdown

EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_CANNOT_RUN = 2
EXIT_FINDINGS = 3


def _select_scenarios(spec: str, extra_dir: Optional[str]) -> list:
    allsc = scenario_mod.load_all(extra_dir)
    if spec in ("all", "*"):
        return [allsc[i] for i in sorted(allsc)]
    chosen = []
    for sid in [s.strip() for s in spec.split(",") if s.strip()]:
        if sid not in allsc:
            raise AgentrigError(
                f"unknown scenario {sid!r}; available: {', '.join(sorted(allsc))}")
        chosen.append(allsc[sid])
    return chosen


def cmd_run(args: argparse.Namespace) -> int:
    try:
        backend = get_backend(args.backend)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    try:
        scns = _select_scenarios(args.scenario, args.scenarios_dir)
    except AgentrigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    engine = Engine(backend)
    limits = Limits(memory_mb=args.memory_mb, cpu_quota_percent=args.cpu_quota,
                    pids_max=args.pids_max, wall_timeout_s=args.timeout)
    try:
        outcomes, agent_info = engine.run(scns, args.agent, limits=limits)
    except IsolationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Run `agentrig doctor` for remedies. Refusing to run unsandboxed.",
              file=sys.stderr)
        return EXIT_CANNOT_RUN

    report = build_report(outcomes, agent_info, backend.capabilities())

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))

    _print_run_summary(report, args)

    s = report["summary"]
    if s.get("fail", 0):
        return EXIT_FINDINGS
    return EXIT_OK


def _print_run_summary(report: dict, args: argparse.Namespace) -> None:
    print(f"agentrig {report['agentrig_version']}  run {report['run_id']}")
    print(f"agent: {report['agent']['command']}")
    caps = report["backend"]["capabilities"]
    enforcing = [k for k in ("filesystem_isolation", "network_isolation",
                             "memory_limit", "cpu_limit", "pids_limit",
                             "syscall_observation") if caps.get(k)]
    print(f"backend: {report['backend']['name']} (enforcing: "
          f"{', '.join(enforcing) or 'nothing'})")
    print("-" * 64)
    for scn in report["scenarios"]:
        print(f"  {scn['verdict'].upper():13} {scn['scenario_id']:26} "
              f"{scn['category']}/{scn['severity']}")
        for c in scn["checks"]:
            if c["verdict"] != "pass":
                print(f"      - {c['type']}: {c['verdict']} — {c['detail']}")
        if scn.get("error"):
            print(f"      ! harness error: {scn['error']}")
    print("-" * 64)
    s = report["summary"]
    print(f"summary: {s.get('pass',0)} pass, {s.get('fail',0)} fail, "
          f"{s.get('inconclusive',0)} inconclusive, {s.get('error',0)} error "
          f"(of {s.get('total',0)})")
    sig = report["signature"]
    if sig.get("signed"):
        print(f"signed: ed25519 fingerprint {sig['fingerprint']}; "
              f"chain head {report['chain']['head'][:16]}…")
    else:
        print(f"unsigned (hash chain head {report['chain']['head'][:16]}…)")
    if args.json:
        print(f"report written: {args.json}")
    if args.md:
        print(f"markdown written: {args.md}")


def cmd_list(args: argparse.Namespace) -> int:
    allsc = scenario_mod.load_all(args.scenarios_dir)
    if args.json:
        print(json.dumps([allsc[i].to_summary() for i in sorted(allsc)], indent=2))
        return EXIT_OK
    print(f"{len(allsc)} scenarios:")
    for sid in sorted(allsc):
        s = allsc[sid]
        print(f"  {s.id:26} [{s.severity:8}] {s.category:15} {s.title}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    if args.md:
        print(render_markdown(report))
    else:
        _print_run_summary(report, argparse.Namespace(json=None, md=None))
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return EXIT_VERIFY_FAILED
    result = verify_report(report)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"chain:     {'OK' if result.chain_ok else 'TAMPERED'}")
        print(f"signature: {result.signature_status}")
        print(f"head:      {str(result.head_stored)[:32]}…")
        for p in result.problems:
            print(f"  ! {p}")
        print(f"result:    {'VERIFIED' if result.ok else 'FAILED'}")
    return EXIT_OK if result.ok else EXIT_VERIFY_FAILED


def cmd_doctor(args: argparse.Namespace) -> int:
    result = doctor_mod.run_doctor()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(doctor_mod.render_text(result))
    return EXIT_OK if result.can_run_scenarios else EXIT_VERIFY_FAILED


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentrig",
        description="Adversarial test harness for AI agents: run a real agent "
                    "under attack in a disposable sandbox and emit a signed, "
                    "reproducible report card.")
    p.add_argument("--version", action="version", version=f"agentrig {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run scenarios against an agent")
    r.add_argument("--agent", required=True,
                   help="agent command, e.g. 'python3 examples/careful_agent.py'")
    r.add_argument("--scenario", default="all",
                   help="scenario id, comma-separated ids, or 'all' (default)")
    r.add_argument("--backend", default="local", choices=available_backends())
    r.add_argument("--json", metavar="FILE", help="write the JSON report card")
    r.add_argument("--md", metavar="FILE", help="write a Markdown report card")
    r.add_argument("--timeout", type=float, default=30.0,
                   help="per-scenario wall-clock timeout (s)")
    r.add_argument("--memory-mb", type=int, default=256, dest="memory_mb")
    r.add_argument("--cpu-quota", type=int, default=100, dest="cpu_quota",
                   help="CPU quota percent (100 = one core)")
    r.add_argument("--pids-max", type=int, default=256, dest="pids_max")
    r.add_argument("--scenarios-dir", dest="scenarios_dir",
                   help="extra directory of scenario JSON files")
    r.set_defaults(func=cmd_run)

    ls = sub.add_parser("list-scenarios", help="list available scenarios")
    ls.add_argument("--json", action="store_true")
    ls.add_argument("--scenarios-dir", dest="scenarios_dir")
    ls.set_defaults(func=cmd_list)

    rp = sub.add_parser("report", help="render a saved report card")
    rp.add_argument("report", help="path to a run.json report")
    rp.add_argument("--md", action="store_true", help="render as Markdown")
    rp.set_defaults(func=cmd_report)

    v = sub.add_parser("verify", help="re-check a report's hash chain/signature")
    v.add_argument("report", help="path to a run.json report")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("doctor", help="probe host isolation capabilities")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_doctor)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AgentrigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
