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


# Network policy values. Both run in an isolated network namespace (nothing
# routable); they differ in what is bridged in from the host side:
NET_NONE = "none"  # no scenario services; only the egress gate (see below)
NET_LOOPBACK = "loopback"  # scenario fake services bridged to 127.0.0.1:<port>

# In-sandbox locations of the launcher and its host-side Unix sockets.
LAUNCHER_PATH = "/.agentrig/inside.py"
NET_MOUNT = "/.agentrig/net"


@dataclass
class SandboxSpec:
    """Everything a backend needs to stand up one disposable sandbox.

    ``network`` is deliberately coarse. Every sandbox gets its own network
    namespace; see the README "network model" for what is bridged in and why
    the *blocked attempt* is itself the signal.
    """

    network: str = NET_LOOPBACK
    env: dict[str, str] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    trace_syscalls: bool = True
    # Extra read-only mounts (host_path -> sandbox_path). Used to make the
    # agent-under-test's own code available inside the sandbox without putting
    # it in /work (which is scenario territory that we hash and diff).
    ro_mounts: list[tuple[str, str]] = field(default_factory=list)
    # Loopback forwards: (in-sandbox 127.0.0.1 port, socket file name in
    # ``net_dir``). The host-side ends are fake services and the egress gate.
    forwards: list[tuple[int, str]] = field(default_factory=list)
    net_dir: Optional[str] = None  # host dir of Unix sockets, mounted read-only
    # Secret env vars for the agent. Delivered through an inherited pipe fd --
    # never argv, never disk -- and deliberately absent from to_dict().
    secret_env: dict[str, str] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "network": self.network,
            "env_keys": sorted(self.env.keys()),  # values may be secret/host-specific
            "secret_env_keys": sorted(self.secret_env.keys()),  # names only
            "limits": self.limits.to_dict(),
            "trace_syscalls": self.trace_syscalls,
            # Only the sandbox-side path; host paths are not reported.
            "ro_mounts": sorted(dst for _src, dst in self.ro_mounts),
            "forward_ports": sorted(port for port, _sock in self.forwards),
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
