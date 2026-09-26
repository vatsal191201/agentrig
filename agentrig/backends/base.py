"""Backend abstraction.

A :class:`SandboxBackend` is a *driver* for some sandbox runtime. agentrig
never implements a sandbox runtime itself -- the local driver merely composes
tools that already exist on the host (bubblewrap, cgroup v2, strace). Other
backends (E2B, OpenSandbox, CubeSandbox) are declared as seams and left as
honest stubs until wired to their real APIs.

The data classes here are the contract every backend speaks in. They are plain
stdlib dataclasses so they serialize cleanly into the report card.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Capabilities:
    """What a backend can actually enforce and observe, on this host, now.

    Every field is a claim the backend is willing to stand behind. ``doctor``
    and the report card surface these verbatim so a reader never has to guess
    which guarantees were in force for a given run.
    """

    backend: str
    filesystem_isolation: bool
    network_isolation: bool
    memory_limit: bool
    cpu_limit: bool
    pids_limit: bool
    syscall_observation: bool
    notes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "filesystem_isolation": self.filesystem_isolation,
            "network_isolation": self.network_isolation,
            "memory_limit": self.memory_limit,
            "cpu_limit": self.cpu_limit,
            "pids_limit": self.pids_limit,
            "syscall_observation": self.syscall_observation,
            "notes": dict(self.notes),
        }

    @property
    def can_isolate(self) -> bool:
        """The minimum bar to run an attack scenario at all.

        We *fail closed*: without filesystem isolation there is no safe way to
        execute a hostile scenario, so the engine refuses.
        """
        return self.filesystem_isolation


@dataclass(frozen=True)
class Limits:
    """Resource caps requested for a run. ``None`` means "do not cap"."""

    memory_mb: Optional[int] = 256
    cpu_quota_percent: Optional[int] = 100
    pids_max: Optional[int] = 256
    wall_timeout_s: float = 30.0

    def to_dict(self) -> dict:
        return {
            "memory_mb": self.memory_mb,
            "cpu_quota_percent": self.cpu_quota_percent,
            "pids_max": self.pids_max,
            "wall_timeout_s": self.wall_timeout_s,
        }


# Network policy values.
NET_NONE = "none"  # fully isolated network namespace; not even loopback egress
NET_LOOPBACK = "loopback"  # shares host net ns so loopback fake services work


@dataclass
class SandboxSpec:
    """Everything a backend needs to stand up one disposable sandbox.

    ``network`` is deliberately coarse. See the README for why real-internet
    egress is never used: scenarios talk only to deterministic fake services on
    loopback, and the *blocked-attempt* is itself the signal.
    """

    network: str = NET_LOOPBACK
    env: dict[str, str] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    trace_syscalls: bool = True

    def to_dict(self) -> dict:
        return {
            "network": self.network,
            "env_keys": sorted(self.env.keys()),  # values may be secret/host-specific
            "limits": self.limits.to_dict(),
            "trace_syscalls": self.trace_syscalls,
        }


@dataclass
class ExecResult:
    """The raw result of running one command in a sandbox.

    This is intentionally *raw*: normalized side-effect events are assembled by
    the observation layer (which also owns the pre/post file manifest), so that
    every backend only has to hand back the primitives it can cheaply capture.
    ``trace_path`` is a host-side file the agent cannot see or tamper with.
    """

    argv: list[str]
    exit_code: Optional[int]
    timed_out: bool
    duration_s: float
    stdout: str
    stderr: str
    peak_rss_kb: Optional[int]
    trace_path: Optional[str]
    backend: str


@dataclass
class SandboxHandle:
    """Opaque per-sandbox state returned by :meth:`SandboxBackend.create`."""

    sandbox_id: str
    spec: SandboxSpec
    root: str  # host path; owns work/ and .control/
    work_dir: str  # host path bound to /work inside the sandbox
    control_dir: str  # host-only; strace + service logs; never mounted in
    extra: dict = field(default_factory=dict)


# The path the work directory is mounted at inside every sandbox.
SANDBOX_WORKDIR = "/work"


class SandboxBackend(abc.ABC):
    """Driver interface. Implementations must guarantee teardown."""

    name: str = "abstract"

    @abc.abstractmethod
    def capabilities(self) -> Capabilities:
        """Probe and report what this backend can enforce/observe right now."""

    @abc.abstractmethod
    def create(self, spec: SandboxSpec) -> SandboxHandle:
        """Stand up a disposable sandbox. Raise IsolationError if it cannot."""

    @abc.abstractmethod
    def exec(
        self,
        handle: SandboxHandle,
        argv: list[str],
        *,
        stdin: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> ExecResult:
        """Run ``argv`` inside the sandbox and collect raw observations."""

    @abc.abstractmethod
    def put_file(
        self,
        handle: SandboxHandle,
        rel_path: str,
        data: bytes,
        *,
        mode: int = 0o644,
    ) -> None:
        """Place a file into the sandbox working dir (path relative to /work)."""

    @abc.abstractmethod
    def get_file(self, handle: SandboxHandle, rel_path: str) -> bytes:
        """Read a file from the sandbox working dir (path relative to /work)."""

    @abc.abstractmethod
    def destroy(self, handle: SandboxHandle) -> None:
        """Tear the sandbox down. Must be safe to call more than once."""
