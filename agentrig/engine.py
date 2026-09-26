"""The run engine: setup -> execute-in-sandbox -> observe -> verdict.

One scenario, start to finish:

  1. start the fake services so their ports are known
  2. resolve {{...}} placeholders (service URLs, canary values, workdir)
  3. create a disposable sandbox and lay down the scenario files + TASK.md
  4. snapshot the workdir, run the agent under observation, snapshot again
  5. assemble the observation and evaluate the verdict
  6. tear the sandbox down -- guaranteed, even on error or timeout

Fail-closed: :meth:`Engine.preflight` refuses to run anything unless the
backend can establish isolation.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Optional

from agentrig.backends.base import Limits, SandboxBackend, SandboxSpec
from agentrig.errors import BackendError, IsolationError
from agentrig.observe import Observation, assemble
from agentrig.observe.fakes import FakeServiceSet
from agentrig.observe.manifest import Manifest, diff_manifests
from agentrig.scenarios.schema import Scenario
from agentrig.util import sha256_file, substitute_deep
from agentrig.verdict import ERROR, ScenarioVerdict, evaluate_scenario


@dataclass
class ScenarioOutcome:
    scenario: Scenario
    verdict: ScenarioVerdict
    spec_summary: dict = field(default_factory=dict)
    observation: Optional[Observation] = None
    error: Optional[str] = None


def prepare_agent(agent_cmd: str) -> tuple[list[str], list[tuple[str, str]], dict]:
    """Split the agent command and make any local script files available.

    Local files (not under /usr or /bin) are exposed to the sandbox via a
    read-only mount and the argument is rewritten to the in-sandbox path. Their
    SHA-256 becomes the agent's "resolved version" -- honest and reproducible.
    """
    argv = shlex.split(agent_cmd)
    if not argv:
        raise BackendError("empty --agent command")
    ro_mounts: list[tuple[str, str]] = []
    dir_to_mount: dict[str, str] = {}
    files_sha: dict[str, str] = {}
    new_argv: list[str] = []
    for tok in argv:
        p = os.path.abspath(tok)
        if os.path.isfile(p) and not p.startswith(("/usr/", "/bin/", "/sbin/")):
            d = os.path.dirname(p)
            if d not in dir_to_mount:
                dir_to_mount[d] = f"/agent{len(dir_to_mount)}"
                ro_mounts.append((d, dir_to_mount[d]))
            new_argv.append(f"{dir_to_mount[d]}/{os.path.basename(p)}")
            files_sha[os.path.basename(p)] = sha256_file(p)
        else:
            new_argv.append(tok)
    info = {"command": agent_cmd, "argv": new_argv, "files_sha256": files_sha}
    return new_argv, ro_mounts, info


class Engine:
    def __init__(self, backend: SandboxBackend) -> None:
        self.backend = backend

    def preflight(self) -> None:
        """Raise IsolationError unless the backend can isolate. Fail closed."""
        caps = self.backend.capabilities()
        if not caps.can_isolate:
            raise IsolationError(
                "refusing to run: backend cannot establish isolation "
                f"({caps.notes.get('bwrap', 'unknown')}). Run `agentrig doctor`.")

    def _subst_map(self, scenario: Scenario, services: FakeServiceSet) -> dict[str, str]:
        m = {"{{WORKDIR}}": "/work"}
        for name, svc in services.services.items():
            m[f"{{{{SVC_{name.upper()}}}}}"] = svc.base_url
        for name, value in scenario.canaries.items():
            m[f"{{{{CANARY_{name.upper()}}}}}"] = value
        return m

    def run_scenario(self, scenario: Scenario, agent_argv: list[str],
                     ro_mounts: list[tuple[str, str]], *,
                     limits: Optional[Limits] = None) -> ScenarioOutcome:
        limits = limits or Limits()
        services = FakeServiceSet()
        handle = None
        try:
            for sdef in scenario.services:
                services.add(sdef.name, routes=dict(sdef.routes),
                             default=dict(sdef.default) if sdef.default else None)
            services.start_all()
            subst = self._subst_map(scenario, services)

            # resolve scripted service responses now that ports are known
            for svc in services.services.values():
                svc.routes = substitute_deep(svc.routes, subst)
                svc.default = substitute_deep(svc.default, subst)

            prompt = substitute_deep(scenario.prompt, subst)
            env = dict(substitute_deep(scenario.setup_env, subst))
            env.update(services.env())
            env["AGENTRIG_TASK"] = prompt

            spec = SandboxSpec(network=scenario.network, env=env, limits=limits,
                               ro_mounts=ro_mounts)
            handle = self.backend.create(spec)

            for rel, content in scenario.setup_files.items():
                self.backend.put_file(
                    handle, rel, substitute_deep(content, subst).encode("utf-8"))
            self.backend.put_file(handle, "TASK.md", prompt.encode("utf-8"))

            before = Manifest.snapshot(handle.work_dir)
            result = self.backend.exec(handle, agent_argv, stdin=prompt,
                                       timeout=limits.wall_timeout_s)
            after = Manifest.snapshot(handle.work_dir)
            diff = diff_manifests(before, after)

            services.stop_all()
            reqs = {n: s.requests for n, s in services.services.items()}
            obs = assemble(result, diff, reqs, scenario.canaries)

            resolved_checks = [substitute_deep(dict(c), subst) for c in scenario.checks]
            service_addrs = {n: ("127.0.0.1", s.port or 0)
                             for n, s in services.services.items()}

            def file_reader(rel: str) -> Optional[bytes]:
                try:
                    return self.backend.get_file(handle, rel)
                except (BackendError, OSError):
                    return None

            verdict = evaluate_scenario(
                scenario, obs, resolved_checks,
                trace_available=obs.trace_available,
                service_addrs=service_addrs, file_reader=file_reader)
            return ScenarioOutcome(scenario=scenario, verdict=verdict,
                                   spec_summary=spec.to_dict(), observation=obs)
        except IsolationError:
            raise  # never degrade; abort the whole run
        except (BackendError, OSError) as exc:
            return ScenarioOutcome(
                scenario=scenario,
                verdict=ScenarioVerdict(scenario.id, scenario.category,
                                        scenario.severity, ERROR, note=str(exc)),
                error=str(exc))
        finally:
            services.stop_all()
            if handle is not None:
                self.backend.destroy(handle)

    def run(self, scenarios: list[Scenario], agent_cmd: str, *,
            limits: Optional[Limits] = None) -> tuple[list[ScenarioOutcome], dict]:
        """Run every scenario. Returns (outcomes, agent_info)."""
        self.preflight()
        agent_argv, ro_mounts, agent_info = prepare_agent(agent_cmd)
        outcomes = [self.run_scenario(s, agent_argv, ro_mounts, limits=limits)
                    for s in scenarios]
        return outcomes, agent_info
