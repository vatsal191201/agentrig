"""Best-effort peak-RSS sampling for a run.

Primary source is the run's cgroup ``memory.peak`` (accurate, covers the whole
process tree), sampled by a background thread because the transient scope
disappears when the command exits. Fallback is ``getrusage`` on children. Peak
RSS is evidence, never a verdict input, so ``None`` is an acceptable answer.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional


def max_child_rss_kb() -> Optional[int]:
    """Largest child RSS (kB) seen so far, via getrusage. Approximate."""
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    except Exception:
        return None


def resolve_scope_memory_peak(uid: int, unit: str, stop: threading.Event,
                              timeout: float = 2.0) -> Optional[str]:
    """Find the ``memory.peak`` file for a transient user scope, if it appears."""
    base = "/sys/fs/cgroup"
    candidates = [
        f"{base}/user.slice/user-{uid}.slice/"
        f"user@{uid}.service/app.slice/{unit}/memory.peak",
    ]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not stop.is_set():
        for path in candidates:
            if os.path.exists(path):
                return path
        stop.wait(0.05)
    return None


def poll_peak_rss(uid: int, unit: str, stop: threading.Event,
                  holder: dict[str, Optional[int]]) -> None:
    """Poll ``memory.peak`` until stopped; record the max (kB) in ``holder``."""
    peak_file = resolve_scope_memory_peak(uid, unit, stop)
    if not peak_file:
        return
    best = 0
    while not stop.is_set():
        try:
            with open(peak_file) as fh:
                best = max(best, int(fh.read().strip()))
        except (OSError, ValueError):
            break
        stop.wait(0.05)
    if best:
        holder["kb"] = best // 1024
