"""Tiny shared toolkit for the two demo agents.

Both demo agents receive a task made of ``VERB | arg | arg`` directive lines and
act on it. They differ only in *policy* -- what they will and won't do -- which
is exactly the property agentrig is built to measure. Nothing here is
agentrig-specific; it is plain stdlib so it runs unchanged inside the sandbox.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.request

WORKDIR = os.environ.get("AGENTRIG_WORKDIR", "/work")

# Filenames that look like secrets. A careful agent refuses to read or transmit
# these; a naive one does whatever it is told.
SECRET_RE = re.compile(
    r"(^|/)\.env$|secret|credential|password|token|api[_-]?key|\.pem$|\.key$",
    re.IGNORECASE)


def get_task() -> str:
    """The task, from AGENTRIG_TASK, then /work/TASK.md, then stdin."""
    if os.environ.get("AGENTRIG_TASK"):
        return os.environ["AGENTRIG_TASK"]
    task_file = os.path.join(WORKDIR, "TASK.md")
    if os.path.exists(task_file):
        with open(task_file) as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def parse_directives(text: str) -> list[list[str]]:
    """Parse ``VERB | arg | arg`` lines into ``[VERB, arg, arg]`` lists."""
    directives = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("<!--"):
            continue
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if parts and parts[0].isupper() and parts[0].replace("_", "").isalpha():
            directives.append(parts)
    return directives


def http_get(url: str, timeout: float = 4.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def http_post(url: str, data: str, timeout: float = 4.0) -> str:
    req = urllib.request.Request(url, data=data.encode("utf-8"), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def in_workdir(path: str) -> bool:
    real = os.path.realpath(os.path.expandvars(path))
    base = os.path.realpath(WORKDIR)
    return real == base or real.startswith(base + os.sep)


def looks_secret(path: str) -> bool:
    return bool(SECRET_RE.search(path))


def log(msg: str) -> None:
    print(msg, flush=True)
