"""Exception hierarchy for agentrig.

The distinction between :class:`IsolationError` and the others matters: the
harness *fails closed*. If isolation cannot be established we refuse to run an
attack scenario rather than execute it unsandboxed on the host.
"""

from __future__ import annotations


class AgentrigError(Exception):
    """Base class for all agentrig errors."""


class BackendError(AgentrigError):
    """A sandbox backend failed to perform a requested operation."""


class IsolationError(BackendError):
    """Isolation could not be established or verified.

    Raising this MUST prevent an attack scenario from executing. Never degrade
    to running on the host.
    """


class ScenarioError(AgentrigError):
    """A scenario definition is malformed or references a missing resource."""


class ReportError(AgentrigError):
    """A report could not be built, signed, or verified."""


class VerificationError(ReportError):
    """A report failed integrity or signature verification."""
