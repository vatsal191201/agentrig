"""The egress gate: the sandbox's only way out.

Every sandbox runs in its own network namespace with nothing routable. The
single exit is this gate -- an HTTP proxy on a host-side Unix socket, reached
from inside at ``127.0.0.1:<gate port>`` (agents are pointed at it through
``http_proxy``/``https_proxy``). It enforces an explicit allowlist and records
every attempt:

  * ``CONNECT host:port`` to an allowlisted endpoint (the configured LLM API,
    nothing else) is tunneled and recorded as ``llm_api`` with byte counts.
    The tunnel is TLS end to end; its payload is *not* inspected.
  * Any other ``CONNECT`` is refused (403) and recorded as a blocked attempt.
  * Plain-HTTP proxy requests are never forwarded. The body the agent tried to
    send is read and recorded, so a blocked upload still produces a receipt
    saying exactly what it tried to send, and where.

With no LLM endpoint configured the allowlist is empty: the gate forwards
nothing and only records.
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from agentrig.observe.fakes import read_body

_MAX_HEAD = 64 * 1024


@dataclass
class GateRecord:
    method: str
    destination: str          # host:port
    allowed: bool
    kind: str = "agent"       # "llm_api" for the allowlisted model endpoint
    url: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    payload: bytes = b""      # plain-HTTP body (never for CONNECT tunnels)
    bytes_up: int = 0
    bytes_down: int = 0
    note: str = ""

    def blob(self) -> bytes:
        head = f"{self.method} {self.url or self.destination}\n" + "".join(
            f"{k}: {v}\n" for k, v in self.headers.items())
        return head.encode("utf-8", "replace") + b"\n" + self.payload


class _SockReader:
    """Minimal buffered reader over a socket (readline/read) that starts with
    bytes already consumed while parsing the request head."""

    def __init__(self, sock, initial: bytes = b"") -> None:
        self.sock = sock
        self.buf = bytearray(initial)

    def _fill(self) -> bool:
        data = self.sock.recv(65536)
        if data:
            self.buf += data
        return bool(data)

    def readline(self, limit: int = 65537) -> bytes:
        while b"\n" not in self.buf and len(self.buf) < limit:
            if not self._fill():
                break
        idx = self.buf.find(b"\n")
        end = idx + 1 if idx >= 0 else len(self.buf)
        end = min(end, limit)
        out = bytes(self.buf[:end])
        del self.buf[:end]
        return out

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                break
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def _read_head(sock) -> tuple[bytes, bytes]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
        if len(buf) > _MAX_HEAD:
            break
        data = sock.recv(65536)
        if not data:
            break
        buf += data
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = buf.find(sep)
        if idx >= 0:
            return bytes(buf[:idx]), bytes(buf[idx + len(sep):])
    return bytes(buf), b""


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    lines = head.decode("latin-1").splitlines()
    parts = (lines[0] if lines else "").split()
    method = parts[0].upper() if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, target, headers


def _split_hostport(target: str, default_port: int) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or "]" in port:
        host, port = target, ""
    try:
        p = int(port) if port else default_port
    except ValueError:
        p = default_port
    return host.strip("[]").lower(), p


class EgressGate:
    """Allowlisting, recording HTTP proxy on a host Unix socket."""

    def __init__(self, allow: Optional[set[tuple[str, int]]] = None) -> None:
        self.allow = {(h.lower(), int(p)) for h, p in (allow or set())}
        self._records: list[GateRecord] = []
        self._lock = threading.Lock()
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None
        self.unix_path: Optional[str] = None

    @property
    def records(self) -> list[GateRecord]:
        with self._lock:
            return list(self._records)

    def _add(self, rec: GateRecord) -> GateRecord:
        with self._lock:
            self._records.append(rec)
        return rec

    def start(self, unix_path: str, sandbox_port: int) -> None:
        gate = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                gate._handle(self.request)

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        if os.path.exists(unix_path):
            os.unlink(unix_path)
        self._server = Server(unix_path, Handler)
        self.unix_path = unix_path
        self.port = sandbox_port
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    # -- request handling ---------------------------------------------------

    def _handle(self, sock) -> None:
        try:
            head, rest = _read_head(sock)
            if not head:
                return
            method, target, headers = _parse_head(head)
            if method == "CONNECT":
                self._connect(sock, target, headers, rest)
            else:
                self._plain(sock, method, target, headers, rest)
        except OSError:
            return

    def _connect(self, sock, target, headers, rest) -> None:
        host, port = _split_hostport(target, 443)
        dest = f"{host}:{port}"
        if (host, port) not in self.allow:
            self._add(GateRecord("CONNECT", dest, allowed=False, headers=headers,
                                 note="destination not on the egress allowlist"))
            sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            return
        rec = self._add(GateRecord("CONNECT", dest, allowed=True, kind="llm_api",
                                   note="TLS tunnel; payload not inspected"))
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            rec.note = f"upstream connect failed: {exc}"
            sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            return
        upstream.settimeout(None)
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if rest:
            upstream.sendall(rest)
            rec.bytes_up += len(rest)
        self._splice(sock, upstream, rec)

    def _splice(self, client, upstream, rec: GateRecord) -> None:
        def pump(src, dst, up: bool) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
                    if up:
                        rec.bytes_up += len(data)
                    else:
                        rec.bytes_down += len(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        back = threading.Thread(target=pump, args=(upstream, client, False), daemon=True)
        back.start()
        pump(client, upstream, True)
        back.join()
        upstream.close()

    def _plain(self, sock, method, target, headers, rest) -> None:
        parts = urlsplit(target)
        host = (parts.hostname or headers.get("Host", "")).lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        body = read_body(_SockReader(sock, rest), headers)
        self._add(GateRecord(method or "?", f"{host}:{port}", allowed=False,
                             url=target, headers=headers, payload=body,
                             bytes_up=len(body),
                             note="plain-HTTP egress is never forwarded"))
        sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                     b"Connection: close\r\n\r\n")
