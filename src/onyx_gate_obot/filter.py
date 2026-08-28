"""Map Obot MCP-gateway filter payloads onto Onyx gate decisions.

Obot's HTTP filter contract (docs: Functionality → Filters): the gateway POSTs
the intercepted JSON-RPC message (`{"jsonrpc", "id", "method", "params", ...}`)
to the configured webhook URL; **HTTP 200 accepts** the message, **any non-200
rejects** it (the response detail may be surfaced to the user). When a shared
secret is configured, the payload is HMAC-SHA256-signed in the
``X-Obot-Signature-256`` header.

This module is transport-free: :func:`decide_message` takes the parsed JSON-RPC
message and returns the HTTP status + JSON body the receiver should answer
with. The actual authorization decision is the same framework-agnostic
:class:`~onyx_gate_obot.guard.ToolGuard` used by the CrewAI integration — one
mapping, one message discipline, every gateway decision in the Onyx trail.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Optional

from .guard import ToolGuard

SIGNATURE_HEADER = "X-Obot-Signature-256"


def verify_signature(body: bytes, header_value: Optional[str], secret: str) -> bool:
    """Check the ``X-Obot-Signature-256`` HMAC (``sha256=`` prefix optional)."""
    if not header_value:
        return False
    presented = header_value.strip()
    if presented.startswith("sha256="):
        presented = presented[len("sha256=") :]
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(presented, expected)


@dataclass(frozen=True)
class FilterResponse:
    """What the webhook receiver should answer: an HTTP status + JSON body."""

    status: int
    body: dict[str, Any]

    @property
    def accepted(self) -> bool:
        return self.status == 200


def decide_message(message: dict[str, Any], guard: ToolGuard) -> FilterResponse:
    """Decide one intercepted JSON-RPC message.

    Only ``tools/call`` requests are gated — that is the execution boundary.
    Everything else (initialize, tools/list, notifications, and response
    messages carrying ``result``/``error``) is accepted untouched; scope the
    filter to ``tools/call`` with Obot's selectors and this is belt-and-braces.
    """
    method = message.get("method")
    if method != "tools/call":
        return FilterResponse(200, {"status": "accepted", "reason": f"not a tool call ({method or 'response message'})"})

    params = message.get("params") or {}
    tool_name = params.get("name")
    if not isinstance(tool_name, str) or not tool_name:
        # A tools/call with no tool name is malformed — reject, fail-closed.
        return FilterResponse(
            400, {"detail": "[Onyx Gate] rejected: tools/call carries no tool name"}
        )
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}

    result = guard.check(tool_name, arguments)

    if result.allowed:
        body: dict[str, Any] = {"status": "accepted"}
        if result.advisory_note:
            body["advisory"] = result.advisory_note
        return FilterResponse(200, body)

    # Blocked: an infrastructure failure (gateway unreachable) is 503, a real
    # policy deny is 403 — both non-200, so Obot rejects either way, but the
    # distinction keeps operator dashboards honest.
    status = 503 if result.error else 403
    return FilterResponse(status, {"detail": result.blocked_message})
