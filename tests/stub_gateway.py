"""A canned-decision HTTP stub of the Onyx gateway, for the test suite ONLY.

It speaks the ``POST /gate/tool-call`` wire shape so the client/guard/adapter
can be exercised without the engine, but it makes no real decisions — a test
scripts each response. It is not a policy engine and must never be deployed as
one.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional


class StubGateway:
    """Runs a scripted gateway on an ephemeral loopback port.

    ``responder`` receives the parsed request payload and returns
    ``(status_code, response_dict)``. Every received payload (and the request
    path + auth header) is recorded for assertions.
    """

    def __init__(
        self,
        responder: Optional[Callable[[dict], tuple[int, dict]]] = None,
        require_bearer: Optional[str] = None,
        ready_body: Optional[dict] = None,
    ) -> None:
        self.responder = responder or (lambda payload: (200, {"decision": "allow"}))
        self.require_bearer = require_bearer
        # What GET /ready answers; the default is a pre-0.2.0 shape (no `server`).
        self.ready_body = ready_body if ready_body is not None else {"policies": 1, "entities": 0}
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                stub.requests.append(
                    {
                        "path": self.path,
                        "payload": payload,
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                if stub.require_bearer is not None and self.headers.get(
                    "Authorization"
                ) != f"Bearer {stub.require_bearer}":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"unauthorized")
                    return
                status, body = stub.responder(payload)
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                elif self.path == "/ready":
                    data = json.dumps(stub.ready_body).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args: object) -> None:  # silence test output
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "StubGateway":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
