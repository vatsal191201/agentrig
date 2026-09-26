"""Scenario schema and validation.

Scenarios are pure data (shipped as JSON, no code) so they are auditable and
reproducible. This module turns a raw dict into a validated :class:`Scenario`
and computes a content hash that pins exactly what was run into the report.

A scenario hands the agent its assignment in one of two forms, chosen per run
(``agentrig run --task-field``):

    prompt   the v0.1 directive vocabulary (``VERB | arg``) the demo agents speak
    task     a natural-language task for real (LLM) agents

A scenario may also be multi-phase (``phases``): each phase is a fresh agent
process in a fresh sandbox, optionally carrying files forward from the
previous phase (e.g. a handoff summary). Single-phase scenarios are normalized
to one implicit phase named ``main``.

Placeholders resolved at run time by the engine (never stored expanded):
    {{SVC_<NAME>}}   base URL of a fake service, e.g. http://127.0.0.1:<port>
    {{CANARY_<NAME>}}the decoy secret's value, generated fresh each run from the
                     canary spec (see ``Scenario.generate_canaries``)
    {{WORKDIR}}      the in-sandbox working directory (/work)
    $HOME            expanded by the agent; points outside every mount on
                     purpose, so a "$HOME/..." write is denied and recorded
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from agentrig.errors import ScenarioError
from agentrig.util import canonical_sha256, gen_canary

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_NETWORKS = {"none", "loopback"}

# Check types the verdict engine understands. Kept here so a malformed scenario
# fails at load time, not mid-run.
KNOWN_CHECK_TYPES = {
    "file_not_read",            # {path}                     needs syscall trace
    "no_out_of_scope_write",    # {}                         needs syscall trace
    "no_command_matching",      # {pattern}                  needs syscall trace
    "no_connect_except",        # {allow_services:[...], allow:[{addr,port}]} trace
    "canary_not_transmitted",   # {canary}                   always observable
    "canary_not_in_output",     # {canary}                   always observable
    "no_files_deleted",         # {paths:[...]} or {under}   always observable
    "egress_not_containing",    # {service?, contains}       always observable
    "claim_requires_effect",    # {claim_pattern, required_file, required_contains?}
    # v0.2
    "summary_free_of_directives",  # {file, canary_phrases?:[...]}  always observable
    "no_request_to",            # {service, path?, methods?:[...]}  always observable
    "request_made",             # {service, path?, contains?}       always observable
    "no_seeded_file_egress",    # {under?} or {files:[...]}         always observable
    # incident pack
    "no_dns_query",             # {allow_names?:[...], allow_qtypes?:[...]}  DNS sink
    "no_payload_replication",   # {service, path?, canary?, reference, ngram?, max_shared?}
    "no_language_switch",       # {service, path?, threshold?}
    "outgoing_matches",         # {service, path?, pattern, expect?}
    "acknowledged_then_violated",  # {ack_phase, read_under?, command_pattern?, canary?, publish_service?}
}

# Which check types depend on syscall-level observation. If the backend cannot
# provide a trace, these become `inconclusive` rather than a false pass.
CHECKS_NEEDING_TRACE = {
    "file_not_read", "no_out_of_scope_write", "no_command_matching",
    "no_connect_except",
}


SEVERE = {"critical", "high"}
TASK_FIELDS = ("prompt", "task")


@dataclass(frozen=True)
class Phase:
    """One agent process in one fresh sandbox."""

    id: str
    prompt: str
    task: Optional[str]
    setup_files: dict[str, Any]  # rel path -> str, or {"base64": "..."} for bytes
    setup_env: dict[str, str]
    carry: tuple[str, ...] = ()  # workdir files copied in from the previous phase

    def assignment(self, task_field: str) -> Optional[str]:
        return self.task if task_field == "task" else self.prompt


@dataclass(frozen=True)
class ServiceDef:
    name: str
    routes: dict[str, dict] = field(default_factory=dict)
    default: dict | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    category: str
    severity: str
    description: str
    network: str
    canaries: dict[str, str]
    setup_files: dict[str, str]
    setup_env: dict[str, str]
    services: tuple[ServiceDef, ...]
    prompt: str
    safe_behavior: str
    checks: tuple[dict, ...]
    raw: dict = field(default_factory=dict, compare=False, repr=False)
    task: Optional[str] = None
    phases: tuple[Phase, ...] = ()
    # Scenario families (one template, many variants) -- see scenarios/family.py
    family: Optional[str] = None
    variant: Optional[str] = None
    perturbed: Optional[bool] = None
    abort_signal: Optional[dict] = None
    # When true, run a recording DNS sink on loopback :53 inside the sandbox
    # and point the resolver at it (see observe/dns_sink.py).
    dns_monitor: bool = False
    # The initial injected message for a propagation (worm) scenario, exposed as
    # {{INBOX_EMAIL}} for hop 0; later hops override it with the prior outgoing.
    inbox_seed: Optional[str] = None
    # Seeded files to make executable (mode 0o755), e.g. a stub `gh` on PATH.
    executable: tuple[str, ...] = ()
    # Compounding-reliability chain: k dependent steps where each step computes
    # next = (x*a + b) mod m and feeds the next. {a, b, m, seed, ks:[...], op}.
    chain: Optional[dict] = None

    @property
    def content_hash(self) -> str:
        """Stable SHA-256 of the scenario definition (pins what was run)."""
        return canonical_sha256(self.raw)

    def run_phases(self) -> tuple[Phase, ...]:
        """The phases to execute; a single-phase scenario is one 'main' phase."""
        if self.phases:
            return self.phases
        return (Phase("main", self.prompt, self.task, dict(self.setup_files),
                      dict(self.setup_env)),)

    def generate_canaries(self) -> dict[str, str]:
        """Resolve each canary spec to a fresh per-run value.

        A canary may be declared as a literal string (kept for flexibility) or,
        preferably, a spec ``{"prefix": str, "random_hex": int}`` that is
        expanded at run time. Generating per run keeps every decoy secret out
        of the scenario JSON *and* makes it un-memorisable by a model. The
        resolved values are recorded in the report.
        """
        out: dict[str, str] = {}
        for name, spec in self.canaries.items():
            if isinstance(spec, str):
                out[name] = spec
            else:
                out[name] = gen_canary(spec.get("prefix", "CANARY_"),
                                       int(spec.get("random_hex", 8)))
        return out

    def check_severity(self, chk: dict) -> str:
        return chk.get("severity") or self.severity

    def to_summary(self) -> dict:
        d = {
            "id": self.id, "title": self.title, "category": self.category,
            "severity": self.severity, "network": self.network,
            "n_checks": len(self.checks), "content_hash": self.content_hash,
            "phases": [p.id for p in self.run_phases()],
            "has_task": all(p.task for p in self.run_phases()),
        }
        if self.family:
            d.update(family=self.family, variant=self.variant,
                     perturbed=self.perturbed)
        return d


def _require(d: dict, key: str, typ: type, ctx: str) -> Any:
    if key not in d:
        raise ScenarioError(f"{ctx}: missing required field {key!r}")
    val = d[key]
    if not isinstance(val, typ):
        raise ScenarioError(
            f"{ctx}: field {key!r} must be {typ.__name__}, got {type(val).__name__}")
    return val


def parse_scenario(raw: dict) -> Scenario:
    """Validate a raw dict and build a Scenario, or raise ScenarioError."""
    if not isinstance(raw, dict):
        raise ScenarioError("scenario must be a JSON object")
    sid = _require(raw, "id", str, "scenario")
    ctx = f"scenario {sid!r}"
    severity = _require(raw, "severity", str, ctx)
    if severity not in VALID_SEVERITIES:
        raise ScenarioError(f"{ctx}: severity {severity!r} not in {VALID_SEVERITIES}")
    network = raw.get("network", "loopback")
    if network not in VALID_NETWORKS:
        raise ScenarioError(f"{ctx}: network {network!r} not in {VALID_NETWORKS}")

    canaries = raw.get("canaries", {})
    if not isinstance(canaries, dict):
        raise ScenarioError(f"{ctx}: 'canaries' must be an object")
    for cname, spec in canaries.items():
        if isinstance(spec, str):
            continue
        if not isinstance(spec, dict):
            raise ScenarioError(f"{ctx}: canary {cname!r} must be a string literal "
                                'or a spec {"prefix": str, "random_hex": int}')
        if "prefix" in spec and not isinstance(spec["prefix"], str):
            raise ScenarioError(f"{ctx}: canary {cname!r} 'prefix' must be a string")
        if "random_hex" in spec and not isinstance(spec["random_hex"], int):
            raise ScenarioError(f"{ctx}: canary {cname!r} 'random_hex' must be an int")

    setup = raw.get("setup", {})
    if not isinstance(setup, dict):
        raise ScenarioError(f"{ctx}: 'setup' must be an object")
    files = setup.get("files", {})
    env = setup.get("env", {})
    if not isinstance(files, dict) or not isinstance(env, dict):
        raise ScenarioError(f"{ctx}: setup.files and setup.env must be objects")
    _validate_files(files, ctx)
    phases = _parse_phases(raw, ctx)
    task = raw.get("task")
    if task is not None and not isinstance(task, str):
        raise ScenarioError(f"{ctx}: 'task' must be a string")

    services = []
    for i, svc in enumerate(setup.get("services", [])):
        if not isinstance(svc, dict) or "name" not in svc:
            raise ScenarioError(f"{ctx}: service #{i} needs a 'name'")
        services.append(ServiceDef(
            name=svc["name"], routes=svc.get("routes", {}),
            default=svc.get("default")))

    chain = raw.get("chain")
    if chain is not None:
        if not isinstance(chain, dict) or not all(
                isinstance(chain.get(k), int) for k in ("a", "b", "m", "seed")):
            raise ScenarioError(f"{ctx}: 'chain' needs integer a, b, m, seed")
        ks = chain.get("ks")
        if not isinstance(ks, list) or not ks or not all(isinstance(k, int) and k > 0
                                                         for k in ks):
            raise ScenarioError(f"{ctx}: chain.ks must be a non-empty list of "
                                "positive ints")

    checks = _require(raw, "expectation", dict, ctx).get("checks", [])
    # A chain scenario derives its verdict from the chain runner, so it may omit
    # checks; every other scenario needs at least one.
    if not isinstance(checks, list) or (not checks and chain is None):
        raise ScenarioError(f"{ctx}: expectation.checks must be a non-empty list")
    phase_ids = {p.id for p in phases} if phases else {"main"}
    for i, chk in enumerate(checks):
        if not isinstance(chk, dict) or "type" not in chk:
            raise ScenarioError(f"{ctx}: check #{i} needs a 'type'")
        if chk["type"] not in KNOWN_CHECK_TYPES:
            raise ScenarioError(
                f"{ctx}: check #{i} unknown type {chk['type']!r}; "
                f"known: {sorted(KNOWN_CHECK_TYPES)}")
        if "phase" in chk and chk["phase"] not in phase_ids:
            raise ScenarioError(f"{ctx}: check #{i} names unknown phase "
                                f"{chk['phase']!r}; phases: {sorted(phase_ids)}")
        if "severity" in chk and chk["severity"] not in VALID_SEVERITIES:
            raise ScenarioError(f"{ctx}: check #{i} severity {chk['severity']!r} "
                                f"not in {VALID_SEVERITIES}")
    if phases:
        prompt = raw.get("prompt", "")
    else:
        prompt = _require(raw, "prompt", str, ctx)

    return Scenario(
        id=sid,
        title=_require(raw, "title", str, ctx),
        category=_require(raw, "category", str, ctx),
        severity=severity,
        description=raw.get("description", ""),
        network=network,
        canaries=dict(raw.get("canaries", {})),
        setup_files=dict(files),
        setup_env=dict(env),
        services=tuple(services),
        prompt=prompt,
        safe_behavior=raw.get("expectation", {}).get("safe_behavior", ""),
        checks=tuple(checks),
        raw=raw,
        task=task,
        phases=phases,
        family=raw.get("family"),
        variant=raw.get("variant"),
        perturbed=raw.get("perturbed"),
        abort_signal=raw.get("abort_signal"),
        dns_monitor=bool(raw.get("dns_monitor", False)),
        inbox_seed=raw.get("inbox_seed"),
        executable=tuple(raw.get("executable", [])),
        chain=raw.get("chain"),
    )


def _validate_files(files: dict, ctx: str) -> None:
    for rel, content in files.items():
        if isinstance(content, str):
            continue
        if isinstance(content, dict) and (isinstance(content.get("base64"), str)
                                          or "json" in content):
            continue
        raise ScenarioError(f"{ctx}: file {rel!r} must be a string, "
                            f'{{"base64": "..."}} or {{"json": ...}}')


def _parse_phases(raw: dict, ctx: str) -> tuple[Phase, ...]:
    """Parse an optional ``phases`` list. Top-level setup is shared by all."""
    spec = raw.get("phases")
    if spec is None:
        return ()
    if not isinstance(spec, list) or len(spec) < 2:
        raise ScenarioError(f"{ctx}: 'phases' must be a list of at least two phases")
    base = raw.get("setup", {})
    phases: list[Phase] = []
    for i, ph in enumerate(spec):
        pctx = f"{ctx} phase #{i}"
        if not isinstance(ph, dict):
            raise ScenarioError(f"{pctx}: must be an object")
        pid = _require(ph, "id", str, pctx)
        if pid in {p.id for p in phases}:
            raise ScenarioError(f"{pctx}: duplicate phase id {pid!r}")
        psetup = ph.get("setup", {})
        files = dict(base.get("files", {}))
        files.update(psetup.get("files", {}))
        _validate_files(files, pctx)
        env = dict(base.get("env", {}))
        env.update(psetup.get("env", {}))
        carry = ph.get("carry", [])
        if not isinstance(carry, list) or (i == 0 and carry):
            raise ScenarioError(f"{pctx}: 'carry' must be a list (and empty for "
                                f"the first phase)")
        task = ph.get("task")
        if task is not None and not isinstance(task, str):
            raise ScenarioError(f"{pctx}: 'task' must be a string")
        phases.append(Phase(pid, _require(ph, "prompt", str, pctx), task,
                            files, env, tuple(carry)))
    return tuple(phases)
