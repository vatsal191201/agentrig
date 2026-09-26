"""Scenario schema and validation.

Scenarios are pure data (shipped as JSON, no code) so they are auditable and
reproducible. This module turns a raw dict into a validated :class:`Scenario`
and computes a content hash that pins exactly what was run into the report.

Placeholders resolved at run time by the engine (never stored expanded):
    {{SVC_<NAME>}}   base URL of a fake service, e.g. http://127.0.0.1:<port>
    {{CANARY_<NAME>}}the decoy secret's value
    {{WORKDIR}}      the in-sandbox working directory (/work)
    $HOME            expanded by the agent; points outside every mount on
                     purpose, so a "$HOME/..." write is denied and recorded
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentrig.errors import ScenarioError
from agentrig.util import canonical_sha256

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
}

# Which check types depend on syscall-level observation. If the backend cannot
# provide a trace, these become `inconclusive` rather than a false pass.
CHECKS_NEEDING_TRACE = {
    "file_not_read", "no_out_of_scope_write", "no_command_matching",
    "no_connect_except",
}


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

    @property
    def content_hash(self) -> str:
        """Stable SHA-256 of the scenario definition (pins what was run)."""
        return canonical_sha256(self.raw)

    def to_summary(self) -> dict:
        return {
            "id": self.id, "title": self.title, "category": self.category,
            "severity": self.severity, "network": self.network,
            "n_checks": len(self.checks), "content_hash": self.content_hash,
        }


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

    setup = raw.get("setup", {})
    if not isinstance(setup, dict):
        raise ScenarioError(f"{ctx}: 'setup' must be an object")
    files = setup.get("files", {})
    env = setup.get("env", {})
    if not isinstance(files, dict) or not isinstance(env, dict):
        raise ScenarioError(f"{ctx}: setup.files and setup.env must be objects")

    services = []
    for i, svc in enumerate(setup.get("services", [])):
        if not isinstance(svc, dict) or "name" not in svc:
            raise ScenarioError(f"{ctx}: service #{i} needs a 'name'")
        services.append(ServiceDef(
            name=svc["name"], routes=svc.get("routes", {}),
            default=svc.get("default")))

    checks = _require(raw, "expectation", dict, ctx).get("checks", [])
    if not isinstance(checks, list) or not checks:
        raise ScenarioError(f"{ctx}: expectation.checks must be a non-empty list")
    for i, chk in enumerate(checks):
        if not isinstance(chk, dict) or "type" not in chk:
            raise ScenarioError(f"{ctx}: check #{i} needs a 'type'")
        if chk["type"] not in KNOWN_CHECK_TYPES:
            raise ScenarioError(
                f"{ctx}: check #{i} unknown type {chk['type']!r}; "
                f"known: {sorted(KNOWN_CHECK_TYPES)}")

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
        prompt=_require(raw, "prompt", str, ctx),
        safe_behavior=raw.get("expectation", {}).get("safe_behavior", ""),
        checks=tuple(checks),
        raw=raw,
    )
