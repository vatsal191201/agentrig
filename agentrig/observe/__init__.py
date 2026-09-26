"""Observation layer: assemble raw run artifacts into normalized evidence.

The verdict engine and the report card both consume :class:`Observation`. It
unifies three independent sources of truth:

  * strace  -> reads, out-of-scope writes (allowed or denied), spawns, connects
  * the file manifest -> authoritative created/modified/deleted inside /work
  * fake-service logs -> exactly what the agent transmitted, and where

Keeping these three separate and then merging them is deliberate: no single
source can see everything, and a security verdict should never rest on one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from agentrig.backends.base import SANDBOX_WORKDIR, ExecResult
from agentrig.observe.fakes import LoggedRequest
from agentrig.observe.manifest import ManifestDiff
from agentrig.observe.strace_parse import parse_trace
from agentrig.util import sha256_text, truncate

__all__ = ["Observation", "assemble", "ManifestDiff", "LoggedRequest",
           "parse_trace"]


@dataclass
class Observation:
    """Everything we managed to observe about one scenario run."""

    events: list[dict] = field(default_factory=list)
    manifest_diff: Optional[ManifestDiff] = None
    exit_code: Optional[int] = None
    timed_out: bool = False
    duration_s: float = 0.0
    peak_rss_kb: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    trace_available: bool = False

    # -- convenience predicates used by verdict checks ---------------------

    def _of(self, kind: str) -> list[dict]:
        return [e for e in self.events if e.get("type") == kind]

    def files_read(self) -> list[str]:
        # Unique, and excluding the workdir root's own directory open (noise).
        seen: list[str] = []
        for e in self._of("file_read"):
            p = e["path"]
            if p == SANDBOX_WORKDIR or p in seen:
                continue
            seen.append(p)
        return seen

    def out_of_scope_writes(self) -> list[dict]:
        return self._of("file_write") + self._of("file_write_attempt_denied")

    def spawns(self) -> list[list[str]]:
        return [e.get("argv", []) for e in self._of("process_spawn")]

    def connects(self) -> list[dict]:
        return self._of("connect")

    def egress_requests(self) -> list[dict]:
        return self._of("egress_request")

    def created(self) -> list[str]:
        return list(self.manifest_diff.created) if self.manifest_diff else []

    def modified(self) -> list[str]:
        return list(self.manifest_diff.modified) if self.manifest_diff else []

    def deleted(self) -> list[str]:
        return list(self.manifest_diff.deleted) if self.manifest_diff else []

    def summary(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_s": self.duration_s,
            "peak_rss_kb": self.peak_rss_kb,
            "trace_available": self.trace_available,
            "n_events": len(self.events),
            "files_read": self.files_read(),
            "out_of_scope_writes": self.out_of_scope_writes(),
            "process_spawns": self.spawns(),
            "connects": self.connects(),
            "egress_requests": self.egress_requests(),
            "manifest_diff": self.manifest_diff.to_dict() if self.manifest_diff else None,
            "stdout": truncate(self.stdout),
            "stderr": truncate(self.stderr),
        }


def assemble(
    exec_result: ExecResult,
    manifest_diff: ManifestDiff,
    service_requests: dict[str, list[LoggedRequest]],
    canaries: dict[str, str],
    *,
    workdir: str = SANDBOX_WORKDIR,
) -> Observation:
    """Merge raw artifacts into a single ordered, normalized Observation."""
    events: list[dict] = []

    # 1) syscall-level events (in trace order) -- reads, out-of-scope writes,
    #    spawns, connects.
    trace_available = bool(exec_result.trace_path)
    if trace_available:
        events.extend(parse_trace(exec_result.trace_path, workdir=workdir))

    # 2) authoritative workdir lifecycle from the manifest.
    for path in sorted(manifest_diff.created):
        events.append({"type": "workfile_created", "path": f"{workdir}/{path}"})
    for path in sorted(manifest_diff.modified):
        events.append({"type": "workfile_modified", "path": f"{workdir}/{path}"})
    for path in sorted(manifest_diff.deleted):
        events.append({"type": "workfile_deleted", "path": f"{workdir}/{path}"})

    # 3) exactly what was transmitted, scanned for the decoy secret(s).
    for svc_name, reqs in sorted(service_requests.items()):
        for req in reqs:
            matched = [name for name, value in canaries.items()
                       if value and value in req.body]
            events.append({
                "type": "egress_request",
                "service": svc_name,
                "method": req.method,
                "path": req.path,
                "body_sha256": sha256_text(req.body),
                "body_preview": truncate(req.body, 500),
                "contains_canaries": matched,
            })

    return Observation(
        events=events,
        manifest_diff=manifest_diff,
        exit_code=exec_result.exit_code,
        timed_out=exec_result.timed_out,
        duration_s=exec_result.duration_s,
        peak_rss_kb=exec_result.peak_rss_kb,
        stdout=exec_result.stdout,
        stderr=exec_result.stderr,
        trace_available=trace_available,
    )
