"""Deterministic fake services.

Scenarios never touch the live internet. Instead the engine stands up small
HTTP servers with *scripted, fixed* responses and a full request log. They
listen on host-side Unix sockets; the sandbox (its own network namespace)
reaches them at ``127.0.0.1:<port>`` through the in-sandbox launcher's
forwards. Recording happens here, on the host, out of the agent's reach.

Two shapes cover every scenario need:
  * a collector    -- accepts anything, logs method/path/headers/body. If the
                      decoy secret shows up anywhere in a request, that is
                      exfiltration, and we can say exactly what was sent where.
  * a data service -- returns scripted content (a web page carrying an
                      injection, or a lookup that returns a *tampered* value).

Every HTTP method is logged (an unlogged PATCH would be a blind spot), and
chunked request bodies are decoded, so an agent cannot slip a payload past
the recorder by choosing an unusual verb or transfer encoding.
"""

from __future__ import annotations

import os
import socketserver
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

MAX_BODY = 16 * 1024 * 1024  # bytes kept per request; the rest is drained
_SHOWN_HEADERS = ("host", "content-type", "user-agent")


@dataclass
class LoggedRequest:
    method: str
    path: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes = b""  # exact body bytes; never serialized into the report

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path,
                "headers": self.shown_headers(), "body": self.body}

    def shown_headers(self) -> dict[str, str]:
        return {k: v for k, v in self.headers.items() if k.lower() in _SHOWN_HEADERS}

    def blob(self) -> bytes:
        """Everything the agent controlled in this request, for scanning."""
        head = f"{self.method} {self.path}\n" + "".join(
            f"{k}: {v}\n" for k, v in self.headers.items())
        return head.encode("utf-8", "replace") + b"\n" + self.raw


def read_body(reader, headers, cap: int = MAX_BODY) -> bytes:
    """Read a request body (Content-Length or chunked) from a file-like reader."""
    te = (headers.get("Transfer-Encoding") or "").lower()
    out = bytearray()
    if "chunked" in te:
        while True:
            line = reader.readline(65537)
            if not line:
                break
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                while True:  # trailers
                    t = reader.readline(65537)
                    if not t or t in (b"\r\n", b"\n"):
                        break
                break
            chunk = reader.read(size)
            reader.readline(65537)  # CRLF after each chunk
            if len(out) < cap:
                out += chunk[: cap - len(out)]
            if not chunk:
                break
        return bytes(out)
    try:
        length = int(headers.get("Content-Length") or 0)
    except ValueError:
        length = 0
    remaining = max(length, 0)
    while remaining > 0:
        data = reader.read(min(remaining, 65536))
        if not data:
            break
        remaining -= len(data)
        if len(out) < cap:
            out += data[: cap - len(out)]
    return bytes(out)


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeHttpService:
    """A single scripted HTTP service on a Unix socket (or loopback TCP)."""

    def __init__(self, name: str, routes: Optional[dict[str, dict]] = None,
                 default: Optional[dict] = None) -> None:
        self.name = name
        self.routes = routes or {}
        # A missing default means "collector": accept everything with 200 ok.
        self.default = default if default is not None else {"status": 200, "body": "ok"}
        self._requests: list[LoggedRequest] = []
        self._lock = threading.Lock()
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None          # port the *agent* uses
        self.unix_path: Optional[str] = None     # host-side socket, if any

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def requests(self) -> list[LoggedRequest]:
        with self._lock:
            return list(self._requests)

    def _record(self, req: LoggedRequest) -> None:
        with self._lock:
            self._requests.append(req)

    def _handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def __getattr__(self, name):
                # Route every verb (GET, POST, PATCH, DELETE, anything) to _reply.
                if name.startswith("do_"):
                    return lambda: self._reply(name[3:])
                raise AttributeError(name)

            def _reply(self, method: str) -> None:
                raw = read_body(self.rfile, self.headers)
                path_only = self.path.split("?", 1)[0]
                service._record(LoggedRequest(
                    method=method, path=self.path,
                    body=raw.decode("utf-8", "replace"),
                    headers={k: v for k, v in self.headers.items()}, raw=raw))
                spec = service.routes.get(path_only, service.default)
                payload = spec.get("body", "").encode("utf-8")
                self.send_response(int(spec.get("status", 200)))
                for hk, hv in spec.get("headers", {}).items():
                    self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", spec.get("content_type", "text/plain"))
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(payload)

            def log_message(self, *_args):  # silence stderr spam
                return

        return Handler

    def start(self, unix_path: Optional[str] = None,
              sandbox_port: Optional[int] = None) -> None:
        """Listen on ``unix_path`` (bridged into the sandbox at ``sandbox_port``)
        or, if no path is given, on an ephemeral 127.0.0.1 TCP port."""
        if unix_path:
            if os.path.exists(unix_path):
                os.unlink(unix_path)
            self._server = _UnixHTTPServer(unix_path, self._handler())
            self.unix_path = unix_path
            self.port = sandbox_port
        else:
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
            self.port = self._server.server_address[1]
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


class FakeServiceSet:
    """Manages the group of fake services for one scenario run."""

    def __init__(self) -> None:
        self.services: dict[str, FakeHttpService] = {}

    def add(self, name: str, routes: Optional[dict] = None,
            default: Optional[dict] = None) -> FakeHttpService:
        svc = FakeHttpService(name, routes=routes, default=default)
        self.services[name] = svc
        return svc

    def start_all(self, unix_dir: Optional[str] = None,
                  first_port: int = 0) -> None:
        """Start every service. With ``unix_dir`` each listens on a Unix socket
        there and is assigned a fixed in-sandbox port from ``first_port``."""
        for i, svc in enumerate(self.services.values()):
            if unix_dir:
                svc.start(os.path.join(unix_dir, f"svc{i}.sock"), first_port + i)
            else:
                svc.start()

    def stop_all(self) -> None:
        for svc in self.services.values():
            svc.stop()

    def env(self, prefix: str = "AGENTRIG_SVC_") -> dict[str, str]:
        """Expose each service's base URL as ``AGENTRIG_SVC_<NAME>``."""
        return {f"{prefix}{name.upper()}": svc.base_url
                for name, svc in self.services.items()}
