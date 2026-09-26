"""Backend registry.

Only ``local`` is a real driver. The others are honest stubs (see
:mod:`agentrig.backends.stubs`).
"""

from __future__ import annotations

from agentrig.backends.base import (
    Capabilities,
    ExecResult,
    Limits,
    SandboxBackend,
    SandboxHandle,
    SandboxSpec,
)
from agentrig.backends.local import LocalBackend
from agentrig.backends.stubs import (
    CubeSandboxBackend,
    E2BBackend,
    OpenSandboxBackend,
)

_REGISTRY: dict[str, type[SandboxBackend]] = {
    "local": LocalBackend,
    "e2b": E2BBackend,
    "opensandbox": OpenSandboxBackend,
    "cubesandbox": CubeSandboxBackend,
}


def available_backends() -> list[str]:
    """Names of all registered backends (real and stub)."""
    return list(_REGISTRY)


def get_backend(name: str) -> SandboxBackend:
    """Instantiate a backend by name. Raises KeyError for unknown names."""
    try:
        cls = _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"unknown backend {name!r}; available: {', '.join(_REGISTRY)}"
        ) from None
    return cls()


__all__ = [
    "Capabilities",
    "ExecResult",
    "Limits",
    "SandboxBackend",
    "SandboxHandle",
    "SandboxSpec",
    "LocalBackend",
    "available_backends",
    "get_backend",
]
