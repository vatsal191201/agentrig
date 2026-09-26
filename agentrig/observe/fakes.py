"""Deterministic fake services.

Scenarios never touch the live internet. Instead the engine stands up small
HTTP servers on the host loopback with *scripted, fixed* responses and a full
request log. The sandbox (network=loopback) reaches them at 127.0.0.1:<port>;
network=none sandboxes cannot, and the refused connection is itself the signal.

Two shapes cover every scenario need:
  * a collector    -- accepts anything, logs method/path/body. If the decoy
                      secret shows up in a body, that is exfiltration, and we
                      can say exactly what was sent and where.
  * a data service -- returns scripted content (a web page carrying an
                      injection, or a lookup that returns a *tampered* value).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional


@dataclass
class LoggedRequest:
    method: str
    path: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path,
                "headers": self.headers, "body": self.body}


class FakeHttpService:
    """A single scripted HTTP service bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, name: str, routes: Optional[dict[str, dict]] = None,
                 default: Optional[dict] = None) -> None:
        self.name = name
        self.routes = routes or {}
        # A missing default means "collector": accept everything with 200 ok.
        self.default = default if default is not None else {"status": 200, "body": "ok"}
        self._requests: list[LoggedRequest] = []
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None

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

    def start(self) -> None:
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _reply(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                path_only = self.path.split("?", 1)[0]
                service._record(LoggedRequest(
                    method=method, path=self.path, body=body,
                    headers={k: v for k, v in self.headers.items()
                             if k.lower() in ("host", "content-type", "user-agent")},
                ))
                spec = service.routes.get(path_only, service.default)
                payload = spec.get("body", "").encode("utf-8")
                self.send_response(int(spec.get("status", 200)))
                for hk, hv in spec.get("headers", {}).items():
                    self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type",
                                 spec.get("content_type", "text/plain"))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):  # noqa: N802
                self._reply("GET")

            def do_POST(self):  # noqa: N802
                self._reply("POST")

            def do_PUT(self):  # noqa: N802
                self._reply("PUT")

            def log_message(self, *_args):  # silence stderr spam
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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

    def start_all(self) -> None:
        for svc in self.services.values():
            svc.start()

    def stop_all(self) -> None:
        for svc in self.services.values():
            svc.stop()

    def env(self, prefix: str = "AGENTRIG_SVC_") -> dict[str, str]:
        """Expose each service's base URL as ``AGENTRIG_SVC_<NAME>``."""
        return {f"{prefix}{name.upper()}": svc.base_url
                for name, svc in self.services.items()}
