"""The webhook receiver — a standard-library HTTP server, no dependencies.

Run it next to your Onyx gateway and point an Obot HTTP filter at it::

    onyx-gate-obot --gateway-url http://127.0.0.1:8080 \\
                   --secret-file webhook.secret --port 8891

Obot filter configuration (Gateway → Filters → add HTTP filter):

* **URL**: ``http://<host>:8891/webhook`` (from inside an Obot container,
  ``http://host.docker.internal:8891/webhook``)
* **Secret**: the same value as ``--secret-file`` — the receiver verifies the
  ``X-Obot-Signature-256`` HMAC on every payload and rejects unsigned or
  mis-signed requests with 401.
* **Selectors**: scope to ``tools/call`` (the receiver accepts everything else
  untouched anyway).

Endpoints: ``POST /webhook`` (the filter), ``GET /health``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .client import OnyxGate
from .filter import SIGNATURE_HEADER, FilterResponse, decide_message, verify_signature
from .guard import ToolGuard

MAX_BODY_BYTES = 1_000_000  # a JSON-RPC tool call is small; refuse absurd bodies


def make_server(
    guard: ToolGuard,
    secret: Optional[str],
    addr: str = "127.0.0.1",
    port: int = 8891,
    path: str = "/webhook",
    log=lambda line: print(line, file=sys.stderr, flush=True),
) -> ThreadingHTTPServer:
    """Build the HTTP server (not yet serving) — separated for tests."""

    class Handler(BaseHTTPRequestHandler):
        def _respond(self, response: FilterResponse) -> None:
            data = json.dumps(response.body).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.path == "/health":
                self._respond(FilterResponse(200, {"status": "healthy", "filter": "ready"}))
            else:
                self._respond(FilterResponse(404, {"detail": "not found"}))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != path:
                self._respond(FilterResponse(404, {"detail": "not found"}))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                self._respond(FilterResponse(400, {"detail": "invalid content length"}))
                return
            body = self.rfile.read(length)

            if secret is not None and not verify_signature(
                body, self.headers.get(SIGNATURE_HEADER), secret
            ):
                log("[onyx-gate-obot] 401 invalid or missing payload signature")
                self._respond(FilterResponse(401, {"detail": "invalid signature"}))
                return

            try:
                message = json.loads(body)
                if not isinstance(message, dict):
                    raise ValueError("payload is not a JSON object")
            except ValueError as e:
                # Fail-closed: an unparseable payload is rejected, not waved on.
                self._respond(FilterResponse(400, {"detail": f"invalid payload: {e}"}))
                return

            response = decide_message(message, guard)
            verdict = "accept" if response.accepted else f"reject {response.status}"
            log(
                f"[onyx-gate-obot] {verdict} method={message.get('method')!r} "
                f"tool={(message.get('params') or {}).get('name')!r}"
            )
            self._respond(response)

        def log_message(self, *args: object) -> None:  # our own log lines instead
            pass

    return ThreadingHTTPServer((addr, port), Handler)


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="onyx-gate-obot",
        description="Onyx gate filter receiver for the Obot MCP Gateway",
    )
    parser.add_argument("--addr", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8891)
    parser.add_argument("--path", default="/webhook", help="webhook path (default /webhook)")
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("ONYX_GATE_URL", "http://127.0.0.1:8080"),
        help="the Onyx gateway deciding the calls (env ONYX_GATE_URL)",
    )
    parser.add_argument(
        "--agent",
        default="obot",
        help='agent identity presented to policy as Agent::"<name>" (default obot)',
    )
    parser.add_argument(
        "--secret-file",
        help="file holding the shared filter secret; falls back to env "
        "OBOT_WEBHOOK_SECRET. Without a secret, payload signatures are NOT "
        "verified (loud warning) — fine only on a trusted loopback.",
    )
    parser.add_argument(
        "--observe",
        action="store_true",
        help="never reject: accept every call but log/annotate would-denies "
        "(the pilot mode; the Onyx trail still records the real decisions)",
    )
    parser.add_argument(
        "--certify",
        action="store_true",
        help="request a kernel-re-checkable certificate with each decision",
    )
    args = parser.parse_args(argv)

    secret: Optional[str] = None
    if args.secret_file:
        try:
            secret = open(args.secret_file, encoding="utf-8").read().strip()
        except OSError as e:
            print(f"cannot read --secret-file: {e}", file=sys.stderr)
            return 2
    elif os.environ.get("OBOT_WEBHOOK_SECRET"):
        secret = os.environ["OBOT_WEBHOOK_SECRET"]
    if secret == "":
        print("the shared secret must be non-empty", file=sys.stderr)
        return 2

    gate = OnyxGate(args.gateway_url)
    guard = ToolGuard(
        gate,
        agent=args.agent,
        mode="observe" if args.observe else "enforce",
        certify=args.certify,
    )
    server = make_server(guard, secret, addr=args.addr, port=args.port, path=args.path)

    print(
        f"onyx-gate-obot listening on http://{args.addr}:{args.port}{args.path}  "
        f"gateway={args.gateway_url}  agent={args.agent}  mode={guard.mode}  "
        f"signature={'verified' if secret else 'NOT VERIFIED (no secret configured)'}",
        file=sys.stderr,
        flush=True,
    )
    if not gate.health():
        print(
            f"warning: no Onyx gateway answering at {args.gateway_url} — "
            "tool calls will be rejected fail-closed until it is up",
            file=sys.stderr,
            flush=True,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
