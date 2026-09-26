"""Honest stub backends for hosted sandbox runtimes.

These declare the *seam* for pluggable backends without faking an integration.
Each raises ``NotImplementedError`` with a clear message. We would rather ship
one real driver and name the others than pretend an untested backend works --
per the project's cardinal rule: never claim an unrun path passes.

Wiring any of these means implementing the SandboxBackend contract against the
provider's API and, crucially, re-verifying which capabilities actually hold
there (syscall-level observation, in particular, is not a given on a hosted
MicroVM and may force more scenario checks to `inconclusive`).
"""

from __future__ import annotations

from agentrig.backends.base import (
    Capabilities,
    ExecResult,
    SandboxBackend,
    SandboxHandle,
    SandboxSpec,
)

_MESSAGE = (
    "The {name!r} backend is a declared seam, not an implementation. agentrig "
    "ships one real driver (local: bubblewrap + cgroup v2 + strace). To use "
    "{name!r}, implement the SandboxBackend contract against its API and "
    "re-probe its true capabilities. See docs and README 'Backends'."
)


class _UnimplementedBackend(SandboxBackend):
    name = "unimplemented"

    def capabilities(self) -> Capabilities:
        # Report an all-false capability set so callers can discover the seam
        # without triggering an exception just to list backends.
        return Capabilities(
            backend=self.name,
            filesystem_isolation=False,
            network_isolation=False,
            memory_limit=False,
            cpu_limit=False,
            pids_limit=False,
            syscall_observation=False,
            notes={"status": "stub: not implemented"},
        )

    def create(self, spec: SandboxSpec) -> SandboxHandle:
        raise NotImplementedError(_MESSAGE.format(name=self.name))

    def exec(self, handle, argv, *, stdin=None, timeout=None) -> ExecResult:
        raise NotImplementedError(_MESSAGE.format(name=self.name))

    def put_file(self, handle, rel_path, data, *, mode=0o644) -> None:
        raise NotImplementedError(_MESSAGE.format(name=self.name))

    def get_file(self, handle, rel_path) -> bytes:
        raise NotImplementedError(_MESSAGE.format(name=self.name))

    def destroy(self, handle) -> None:  # pragma: no cover - nothing to tear down
        raise NotImplementedError(_MESSAGE.format(name=self.name))


class E2BBackend(_UnimplementedBackend):
    """Seam for E2B (https://e2b.dev) Firecracker MicroVMs."""

    name = "e2b"


class OpenSandboxBackend(_UnimplementedBackend):
    """Seam for alibaba/OpenSandbox."""

    name = "opensandbox"


class CubeSandboxBackend(_UnimplementedBackend):
    """Seam for TencentCloud/CubeSandbox (E2B-compatible MicroVMs)."""

    name = "cubesandbox"
