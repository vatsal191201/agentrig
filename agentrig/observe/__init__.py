"""Observation layer: assemble raw run artifacts into normalized evidence.

The verdict engine and the report card both consume :class:`Observation`. It
unifies four independent sources of truth:

  * strace  -> reads, out-of-scope writes (allowed or denied), spawns, connects
  * the file manifest -> authoritative created/modified/deleted inside /work
  * fake-service logs -> exactly what the agent transmitted, and where
  * the egress gate -> every attempt to leave the sandbox, allowed or blocked

Keeping these separate and then merging them is deliberate: no single source
can see everything, and a security verdict should never rest on one.

Every outbound attempt also becomes an **egress receipt**: destination, bytes,
payload SHA-256, which seeded file(s) the payload carried (by content), and
whether it was allowed or blocked.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from agentrig.backends.base import SANDBOX_WORKDIR, ExecResult
from agentrig.observe.dns_sink import DnsQuery, qtype_name
from agentrig.observe.fakes import LoggedRequest
from agentrig.observe.gate import GateRecord
from agentrig.observe.manifest import ManifestDiff
from agentrig.observe.matching import encoded_forms, reveals
from agentrig.observe.strace_parse import parse_trace
from agentrig.util import sha256_text, truncate, truncate_middle

__all__ = ["Observation", "assemble", "ManifestDiff", "LoggedRequest",
           "parse_trace", "match_seeded_files"]

_LOOPBACK = ("127.", "::1")


@dataclass
class Observation:
    """Everything we managed to observe about one agent run (one phase)."""

    events: list[dict] = field(default_factory=list)
    manifest_diff: Optional[ManifestDiff] = None
    exit_code: Optional[int] = None
    timed_out: bool = False
    duration_s: float = 0.0
    peak_rss_kb: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    trace_available: bool = False
    egress: list[dict] = field(default_factory=list)  # receipts
    llm_api: Optional[dict] = None  # None when no LLM endpoint was configured
    gate_port: Optional[int] = None
    dns_port: Optional[int] = None  # set when a DNS sink was in use
    # (egress event, full request blob) -- in memory only, never serialized, so
    # checks see whole payloads rather than the report's truncated previews.
    raw_egress: list[tuple[dict, bytes]] = field(default_factory=list, repr=False)

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

    def gate_blocked(self) -> list[dict]:
        """Attempts the egress gate refused (always observable, no trace needed)."""
        return [r for r in self.egress if r.get("channel") == "gate"
                and not r.get("allowed")]

    def dns_queries(self) -> list[dict]:
        """Every DNS query the sandbox made (recorded by the sink, no trace needed)."""
        return self._of("dns_query")

    def outgoing_bodies(self, service: str, path: Optional[str] = None) -> list[str]:
        """Full request bodies the agent sent to a fake service (for propagation).

        Uses the in-memory raw payloads, so the body is complete, not the
        report's truncated preview.
        """
        out: list[str] = []
        for ev, blob in self.raw_egress:
            if ev.get("service") != service:
                continue
            if path is not None and ev.get("path", "").split("?", 1)[0] != path:
                continue
            parts = blob.split(b"\n\n", 1)
            body = parts[1] if len(parts) > 1 else b""
            out.append(body.decode("utf-8", "replace"))
        return out

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
            "egress_receipts": self.egress,
            "dns_queries": self.dns_queries(),
            "llm_api": self.llm_api,
            "manifest_diff": self.manifest_diff.to_dict() if self.manifest_diff else None,
            "stdout": truncate_middle(self.stdout),
            "stderr": truncate_middle(self.stderr),
        }


def match_seeded_files(payload: bytes, blob: bytes,
                       seeded: dict[str, bytes]) -> list[dict]:
    """Which seeded files does this outbound payload carry, and how?"""
    out: list[dict] = []
    digest = hashlib.sha256(payload).hexdigest() if payload else None
    for rel, content in sorted(seeded.items()):
        if not content:
            continue
        if digest and hashlib.sha256(content).hexdigest() == digest:
            out.append({"file": rel, "how": "exact"})
        elif len(content) >= 8 and content in blob:
            out.append({"file": rel, "how": "verbatim"})
        elif len(content) >= 8 and any(
                f in blob for f in encoded_forms(content, full=False)[1:]):
            out.append({"file": rel, "how": "base64"})
    return out


def _canaries_in(blob: bytes, canaries: dict[str, str]) -> list[str]:
    return [name for name, value in canaries.items()
            if value and reveals(blob, value.encode("utf-8"))]


def assemble(
    exec_result: ExecResult,
    manifest_diff: ManifestDiff,
    service_requests: dict[str, list[LoggedRequest]],
    canaries: dict[str, str],
    *,
    workdir: str = SANDBOX_WORKDIR,
    agent_mounts: tuple[str, ...] = (),
    service_ports: Optional[dict[str, int]] = None,
    gate_records: Optional[list[GateRecord]] = None,
    gate_port: Optional[int] = None,
    seeded_files: Optional[dict[str, bytes]] = None,
    llm_configured: bool = False,
    dns_records: Optional[list[DnsQuery]] = None,
    dns_port: Optional[int] = None,
    scrubber=None,
) -> Observation:
    """Merge raw artifacts into a single ordered, normalized Observation.

    ``agent_mounts`` are the sandbox paths the agent-under-test's own code is
    mounted at (read-only). Writes there -- e.g. an interpreter's denied
    bytecode-cache write -- are infrastructure, not scenario scope, so they are
    filtered out of the out-of-scope-write signal.
    """
    service_ports = service_ports or {}
    seeded = seeded_files or {}
    events: list[dict] = []
    receipts: list[dict] = []
    raw_egress: list[tuple[dict, bytes]] = []

    def payload_digest(payload: bytes) -> tuple[Optional[str], bool]:
        if scrubber and scrubber.contains_secret(payload):
            return None, True  # never publish a digest of a run secret
        return hashlib.sha256(payload).hexdigest(), False

    # 1) syscall-level events (in trace order) -- reads, out-of-scope writes,
    #    spawns, connects.
    trace_available = bool(exec_result.trace_path)
    if trace_available:
        events.extend(parse_trace(exec_result.trace_path, workdir=workdir,
                                  extra_noise_write_roots=tuple(agent_mounts)))
    # A connect to the in-sandbox DNS sink (127.0.0.1:<dns_port>) is sanctioned
    # transport, like the gate: the *query content* is judged from the sink's
    # own records below, not from this loopback connect.
    if dns_port:
        events = [e for e in events if not (
            e.get("type") == "connect" and e.get("port") == dns_port
            and str(e.get("addr", "")).startswith("127."))]

    # 2) authoritative workdir lifecycle from the manifest.
    for path in sorted(manifest_diff.created):
        events.append({"type": "workfile_created", "path": f"{workdir}/{path}"})
    for path in sorted(manifest_diff.modified):
        events.append({"type": "workfile_modified", "path": f"{workdir}/{path}"})
    for path in sorted(manifest_diff.deleted):
        events.append({"type": "workfile_deleted", "path": f"{workdir}/{path}"})

    # 3) exactly what was transmitted to fake services, scanned for the decoy
    #    secret(s) in path, headers and body (verbatim or encoded).
    for svc_name, reqs in sorted(service_requests.items()):
        for req in reqs:
            blob = req.blob()
            ev = {
                "type": "egress_request",
                "channel": "service",
                "service": svc_name,
                "method": req.method,
                "path": req.path,
                "headers": req.shown_headers(),
                "body_sha256": sha256_text(req.body),
                "body_preview": truncate(req.body, 500),
                "contains_canaries": _canaries_in(blob, canaries),
                "allowed": True,
            }
            events.append(ev)
            raw_egress.append((ev, blob))
            digest, redacted = payload_digest(req.raw)
            port = service_ports.get(svc_name)
            receipts.append({
                "channel": "service",
                "destination": f"{svc_name} (127.0.0.1:{port})" if port else svc_name,
                "method": req.method,
                "path": req.path,
                "bytes_out": len(req.raw),
                "payload_sha256": digest,
                "payload_redacted": redacted,
                "matched_seeded_files": match_seeded_files(req.raw, blob, seeded),
                "contains_canaries": ev["contains_canaries"],
                "allowed": True,
                "outcome": "delivered to a scenario fake service (never the internet)",
            })

    # 4) the egress gate: the only way out of the sandbox network namespace.
    llm = {"tunnels": 0, "bytes_up": 0, "bytes_down": 0} if llm_configured else None
    for rec in gate_records or []:
        if rec.kind == "llm_api" and rec.allowed:
            if llm is not None:
                llm["tunnels"] += 1
                llm["bytes_up"] += rec.bytes_up
                llm["bytes_down"] += rec.bytes_down
            events.append({"type": "llm_api", "destination": rec.destination,
                           "bytes_up": rec.bytes_up, "bytes_down": rec.bytes_down})
            receipts.append({
                "channel": "gate", "kind": "llm_api",
                "destination": rec.destination, "method": "CONNECT",
                "bytes_out": rec.bytes_up, "bytes_in": rec.bytes_down,
                "payload_sha256": None, "payload_redacted": False,
                "matched_seeded_files": [], "contains_canaries": [],
                "allowed": True,
                "outcome": "tunneled to the configured LLM API (TLS; payload "
                           "not inspected)" + (f"; {rec.note}" if "failed" in rec.note else ""),
            })
            continue
        blob = rec.blob()
        canary_hits = _canaries_in(blob, canaries)
        if rec.method == "CONNECT":
            events.append({"type": "egress_blocked", "channel": "gate",
                           "method": "CONNECT", "destination": rec.destination,
                           "contains_canaries": canary_hits})
        else:
            ev = {
                "type": "egress_request", "channel": "gate",
                "service": f"gate:{rec.destination}", "method": rec.method,
                "path": rec.url or "", "headers": {},
                "body_sha256": sha256_text(rec.payload.decode("utf-8", "replace")),
                "body_preview": truncate(rec.payload.decode("utf-8", "replace"), 500),
                "contains_canaries": canary_hits, "allowed": False,
            }
            events.append(ev)
            raw_egress.append((ev, blob))
        digest, redacted = payload_digest(rec.payload) if rec.payload else (None, False)
        receipts.append({
            "channel": "gate", "kind": "agent",
            "destination": rec.destination, "method": rec.method,
            "url": rec.url, "bytes_out": rec.bytes_up,
            "payload_sha256": digest, "payload_redacted": redacted,
            "matched_seeded_files": match_seeded_files(rec.payload, blob, seeded)
            if rec.payload else [],
            "contains_canaries": canary_hits,
            "allowed": False,
            "outcome": "blocked by the egress gate (" + rec.note + ")",
        })

    # 4b) DNS queries recorded by the in-sandbox sink (name, type, transport,
    #     labels). A query is a finding even though nothing could leave: the
    #     sink answered locally (NXDOMAIN / sinkhole) and the netns has no route.
    for q in dns_records or []:
        scan = (q.name + " " + " ".join(q.labels)).encode("utf-8", "replace")
        canary_hits = _canaries_in(scan, canaries)
        events.append({
            "type": "dns_query", "name": q.name, "qtype": q.qtype,
            "qtype_name": qtype_name(q.qtype), "transport": q.transport,
            "labels": list(q.labels), "answered": q.answered,
            "contains_canaries": canary_hits})
        receipts.append({
            "channel": "dns",
            "destination": f"dns:{q.name or '(malformed)'}/{qtype_name(q.qtype)}",
            "method": q.transport.upper(), "bytes_out": None,
            "payload_sha256": None, "payload_redacted": False,
            "matched_seeded_files": [], "contains_canaries": canary_hits,
            "allowed": False,
            "outcome": f"DNS query recorded, answered {q.answered}; the sandbox "
                       f"netns has no route to a real resolver"})

    # 5) direct connects that bypassed the bridges: nothing is routable from the
    #    sandbox's own network namespace, so none of these left the sandbox.
    bridge_ports = set(service_ports.values()) | ({gate_port} if gate_port else set())
    for c in (e for e in events if e.get("type") == "connect"):
        addr = c.get("addr") or ""
        if addr.startswith(_LOOPBACK) and c.get("port") in bridge_ports:
            continue  # transport to a fake service or the gate; receipted above
        receipts.append({
            "channel": "direct", "destination": f"{addr}:{c.get('port')}",
            "method": "connect", "bytes_out": None, "payload_sha256": None,
            "payload_redacted": False, "matched_seeded_files": [],
            "contains_canaries": [], "allowed": False,
            "outcome": f"did not leave the sandbox: its network namespace has no "
                       f"route out (connect result: {c.get('result')}"
                       + (f" {c.get('errno')}" if c.get("errno") else "") + ")",
        })

    stdout, stderr = exec_result.stdout, exec_result.stderr
    if scrubber:
        stdout, stderr = scrubber.text(stdout), scrubber.text(stderr)
        events = scrubber.deep(events)
        receipts = scrubber.deep(receipts)
        # Re-point raw payloads at the scrubbed event copies. Every
        # egress_request event was appended exactly once, in the same order
        # as raw_egress, so the two sequences line up.
        scrubbed_reqs = [e for e in events if e.get("type") == "egress_request"]
        raw_egress = [(ev, blob) for ev, (_old, blob) in zip(scrubbed_reqs, raw_egress)]

    return Observation(
        events=events,
        manifest_diff=manifest_diff,
        exit_code=exec_result.exit_code,
        timed_out=exec_result.timed_out,
        duration_s=exec_result.duration_s,
        peak_rss_kb=exec_result.peak_rss_kb,
        stdout=stdout,
        stderr=stderr,
        trace_available=trace_available,
        egress=receipts,
        llm_api=llm,
        gate_port=gate_port,
        dns_port=dns_port,
        raw_egress=raw_egress,
    )
