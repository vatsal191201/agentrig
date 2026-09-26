"""agentrig command-line interface.

    agentrig run  --agent <cmd> --scenario <id|all> [--trials N] [--json f]
                  [--task-field prompt|task] [--llm-base-url URL --llm-model M]
    agentrig list-scenarios
    agentrig report <run.json> [--md]
    agentrig verify <run.json>
    agentrig diff <old.json> <new.json> [--tolerance 0.1]
    agentrig doctor

Exit codes for `run`: 0 = no failures, 3 = at least one scenario FAILED,
2 = could not run (isolation/harness error). `verify`: 1 = verification failed.
`diff`: 4 = regression, 1 = a report failed verification.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from agentrig import __version__, doctor as doctor_mod
from agentrig import scenarios as scenario_mod
from agentrig.backends import available_backends, get_backend
from agentrig.backends.base import Limits
from agentrig.diff import diff_reports, render_diff
from agentrig.engine import Engine, LLMConfig, RunConfig
from agentrig.errors import AgentrigError, IsolationError
from agentrig.report import build_report, verify_report
from agentrig.report_md import render_markdown
from agentrig.report_text import render_run_summary

EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_CANNOT_RUN = 2
EXIT_FINDINGS = 3
EXIT_REGRESSION = 4


def _read_env_file(path: str, name: str) -> Optional[str]:
    """Read one NAME=value from a dotenv file (value never printed)."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:].lstrip()
                key, sep, value = line.partition("=")
                if sep and key.strip() == name:
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    return value
    except OSError as exc:
        raise AgentrigError(f"cannot read --env-file: {exc}") from None
    return None


def _llm_config(args: argparse.Namespace) -> Optional[LLMConfig]:
    if not args.llm_base_url:
        return None
    if not args.llm_model:
        raise AgentrigError("--llm-model is required with --llm-base-url")
    key = os.environ.get(args.llm_api_key_env)
    if not key and args.env_file:
        key = _read_env_file(args.env_file, args.llm_api_key_env)
    if not key:
        raise AgentrigError(
            f"no API key: set ${args.llm_api_key_env} (or pass --env-file); "
            "the key is handed to the agent via an fd and never written out")
    return LLMConfig(base_url=args.llm_base_url, model=args.llm_model, api_key=key)


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

    if args.trials < 1:
        print("error: --trials must be >= 1", file=sys.stderr)
        return EXIT_CANNOT_RUN
    engine = Engine(backend)
    limits = Limits(memory_mb=args.memory_mb, cpu_quota_percent=args.cpu_quota,
                    pids_max=args.pids_max, wall_timeout_s=args.timeout)
    config = RunConfig(trials=args.trials, task_field=args.task_field,
                       llm=_llm_config(args), trace=not args.no_trace, limits=limits)
    try:
        outcomes, agent_info = engine.run(scns, args.agent, config=config)
    except IsolationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Run `agentrig doctor` for remedies. Refusing to run unsandboxed.",
              file=sys.stderr)
        return EXIT_CANNOT_RUN

    report = build_report(outcomes, agent_info, backend.capabilities(),
                          run_config=config.to_dict(), scrubber=config.scrubber())

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
    if getattr(args, "sarif", None):
        from agentrig.sarif import to_sarif
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(report), fh, indent=2)

    print(render_run_summary(report, json_path=args.json, md_path=args.md,
                             sarif_path=getattr(args, "sarif", None)))

    s = report["summary"]
    if s.get("fail", 0):
        return EXIT_FINDINGS
    return EXIT_OK


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
        print(render_run_summary(report))
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    reports = []
    for path in (args.old, args.new):
        try:
            with open(path, encoding="utf-8") as fh:
                reports.append(json.load(fh))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read report {path}: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
    if not args.no_verify:
        for path, rep in zip((args.old, args.new), reports):
            v = verify_report(rep)
            if not v.ok:
                print(f"error: {path} failed verification "
                      f"({'; '.join(v.problems)}); refusing to diff "
                      f"(--no-verify to override)", file=sys.stderr)
                return EXIT_VERIFY_FAILED
    d = diff_reports(reports[0], reports[1], tolerance=args.tolerance)
    print(json.dumps(d, indent=2) if args.json else render_diff(d))
    return EXIT_REGRESSION if d["regressed"] else EXIT_OK


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
    r.add_argument("--no-trace", action="store_true", dest="no_trace",
                   help="disable syscall observation (checks that need it become "
                        "INCONCLUSIVE -- simulates a backend without tracing)")
    r.add_argument("--scenarios-dir", dest="scenarios_dir",
                   help="extra directory of scenario JSON files")
    r.add_argument("--trials", type=int, default=1,
                   help="run each scenario N times, each in a fresh sandbox; "
                        "reports pass rate, pass^N and a Wilson 95%% interval")
    r.add_argument("--task-field", choices=("prompt", "task"), default="prompt",
                   dest="task_field",
                   help="what the agent is handed: 'prompt' = directive "
                        "vocabulary (demo agents), 'task' = natural language "
                        "(real LLM agents)")
    r.add_argument("--llm-base-url", dest="llm_base_url",
                   help="OpenAI-compatible https endpoint: the ONLY external "
                        "destination the sandbox may reach (recorded as llm_api)")
    r.add_argument("--llm-model", dest="llm_model", help="model name for the agent")
    r.add_argument("--llm-api-key-env", dest="llm_api_key_env",
                   default="AGENTRIG_LLM_API_KEY",
                   help="name of the env var holding the API key (default "
                        "AGENTRIG_LLM_API_KEY); passed to the agent via an fd "
                        "and scrubbed from every output")
    r.add_argument("--env-file", dest="env_file",
                   help="dotenv file to read the API key variable from if it "
                        "is not in the environment")
    r.add_argument("--sarif", metavar="FILE",
                   help="write SARIF 2.1.0 (GitHub code scanning)")
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

    df = sub.add_parser("diff", help="regression view between two reports")
    df.add_argument("old", help="baseline report JSON")
    df.add_argument("new", help="candidate report JSON")
    df.add_argument("--tolerance", type=float, default=0.0,
                    help="allowed pass-rate drop before it counts as a "
                         "regression (0.1 = 10 points; default 0)")
    df.add_argument("--no-verify", action="store_true", dest="no_verify",
                    help="diff even if a report fails verification")
    df.add_argument("--json", action="store_true")
    df.set_defaults(func=cmd_diff)

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
