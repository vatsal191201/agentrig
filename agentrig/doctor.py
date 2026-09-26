"""Host capability probe with actionable remedies.

``agentrig doctor`` answers one question: can this host run attack scenarios
under real isolation, and if not, exactly what to do about it. It never guesses
from a version string -- it uses the backend's live probes.
"""

from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field
from typing import Optional

from agentrig.backends.local import LocalBackend
from agentrig.signing import Signer, crypto_available

OK = "ok"
WARN = "warn"
FAIL = "fail"

_APPARMOR_SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
_PTRACE_SYSCTL = "/proc/sys/kernel/yama/ptrace_scope"

_USERNS_REMEDY = (
    "Unprivileged user namespaces are blocked (Ubuntu 23.10+ ships AppArmor "
    "restrictions on by default). Enable them with:\n"
    "    echo 'kernel.apparmor_restrict_unprivileged_userns=0' | "
    "sudo tee /etc/sysctl.d/60-agentrig-userns.conf\n"
    "    sudo sysctl --system\n"
    "  (Alternatively add an AppArmor profile for bwrap. A root-run or "
    "privileged-container setup avoids this entirely.)")


@dataclass
class Check:
    name: str
    status: str
    detail: str
    remedy: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"name": self.name, "status": self.status, "detail": self.detail}
        if self.remedy:
            d["remedy"] = self.remedy
        return d


@dataclass
class DoctorResult:
    checks: list[Check] = field(default_factory=list)
    can_run_scenarios: bool = False

    def to_dict(self) -> dict:
        return {"can_run_scenarios": self.can_run_scenarios,
                "checks": [c.to_dict() for c in self.checks]}


def _read_int(path: str) -> Optional[int]:
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def run_doctor() -> DoctorResult:
    checks: list[Check] = []
    backend = LocalBackend()
    caps = backend.capabilities()

    # 1) bubblewrap + user namespaces (the make-or-break capability).
    bwrap = shutil.which("bwrap")
    if not bwrap:
        checks.append(Check("bubblewrap", FAIL, "bwrap not found on PATH",
                            "Install it: sudo apt install bubblewrap"))
    elif caps.filesystem_isolation:
        checks.append(Check("bubblewrap + user namespaces", OK,
                            f"{bwrap}: {caps.notes.get('bwrap')}"))
    else:
        checks.append(Check("bubblewrap + user namespaces", FAIL,
                            caps.notes.get("bwrap", "userns unavailable"),
                            _USERNS_REMEDY))

    # 2) AppArmor userns restriction sysctl (the usual culprit).
    apparmor = _read_int(_APPARMOR_SYSCTL)
    if apparmor is None:
        checks.append(Check("apparmor_restrict_unprivileged_userns", OK,
                            "not present on this kernel (no restriction)"))
    elif apparmor == 0:
        checks.append(Check("apparmor_restrict_unprivileged_userns", OK,
                            "0 (unprivileged user namespaces allowed)"))
    else:
        status = FAIL if not caps.filesystem_isolation else WARN
        checks.append(Check("apparmor_restrict_unprivileged_userns", status,
                            f"{apparmor} (restricts unprivileged user namespaces)",
                            _USERNS_REMEDY))

    # 3) cgroup v2 resource limits.
    if caps.memory_limit:
        checks.append(Check("cgroup v2 resource limits", OK,
                            caps.notes.get("cgroup")))
    else:
        checks.append(Check("cgroup v2 resource limits", WARN,
                            caps.notes.get("cgroup", "unavailable") +
                            " (scenarios still run, without resource caps)"))

    # 4) strace syscall observation.
    if caps.syscall_observation:
        checks.append(Check("strace syscall observation", OK,
                            caps.notes.get("strace")))
    else:
        checks.append(Check("strace syscall observation", WARN,
                            "strace not found; read/write/connect checks will be "
                            "INCONCLUSIVE (install: sudo apt install strace)"))

    # 5) ptrace scope (informational; strace-as-parent works even at 1).
    ptrace = _read_int(_PTRACE_SYSCTL)
    if ptrace is not None:
        checks.append(Check("yama.ptrace_scope", OK,
                            f"{ptrace} (agentrig traces its own descendants, so "
                            f"this value does not block observation)"))

    # 6) signing (optional).
    if crypto_available():
        signer = Signer()
        checks.append(Check("report signing (ed25519)", OK,
                            f"cryptography present; key fingerprint "
                            f"{signer.fingerprint()}"))
    else:
        checks.append(Check("report signing (ed25519)", WARN,
                            "cryptography not installed; reports will be unsigned "
                            "(the chain is a recomputable digest, not tamper-evidence). "
                            "Install: pip install 'agentrig[signing]'"))

    # 7) outbound internet (informational -- explains the exfil model).
    checks.append(_internet_check())

    can_run = caps.filesystem_isolation
    return DoctorResult(checks=checks, can_run_scenarios=can_run)


def _internet_check() -> Check:
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=2)
        s.close()
        return Check("outbound internet", OK,
                     "reachable from the host, not from sandboxes: each sandbox has "
                     "its own network namespace; the only way out is the egress "
                     "gate, which forwards nothing unless --llm-base-url "
                     "allowlists exactly one endpoint.")
    except OSError:
        return Check("outbound internet", OK,
                     "not reachable from here; sandboxes are additionally confined "
                     "to their own network namespace.")


def render_text(result: DoctorResult) -> str:
    mark = {OK: "[ ok ]", WARN: "[warn]", FAIL: "[FAIL]"}
    lines = ["agentrig doctor", "=" * 60]
    for c in result.checks:
        lines.append(f"{mark.get(c.status, '[????]')} {c.name}")
        lines.append(f"        {c.detail}")
        if c.remedy:
            for rl in c.remedy.splitlines():
                lines.append(f"        {rl}")
    lines.append("-" * 60)
    if result.can_run_scenarios:
        lines.append("READY: this host can run attack scenarios under isolation.")
    else:
        lines.append("NOT READY: isolation cannot be established; agentrig will "
                     "refuse to run scenarios (fail closed). See remedies above.")
    return "\n".join(lines)
