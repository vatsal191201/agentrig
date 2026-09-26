"""agentrig -- an adversarial test harness for AI agents.

agentrig is the layer *above* the sandbox. It runs a real agent under attack in
a disposable sandbox and emits a signed, reproducible report card. It is a
*client* of sandbox runtimes, never a competitor: a local bubblewrap+cgroup
driver for development, with pluggable backends for scale.

Public API is intentionally small; the CLI (``agentrig.cli``) is the primary
entry point.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
