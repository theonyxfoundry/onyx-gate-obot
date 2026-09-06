"""Onyx Gate for Obot — a verifiable authorization filter for the Obot MCP Gateway.

* :mod:`onyx_gate_obot.filter` — the Obot filter contract mapped onto Onyx gate
  decisions (payload signature check, JSON-RPC ``tools/call`` → allow/deny).
* :mod:`onyx_gate_obot.server` — the dependency-free webhook receiver
  (``onyx-gate-obot`` console entry point).
* :mod:`onyx_gate_obot.client` / :mod:`onyx_gate_obot.guard` /
  :mod:`onyx_gate_obot.receipt` — the shared framework-agnostic core (the gate
  client, the guard, and signed per-decision receipts), vendored from
  ``onyx-gate-crewai``.
"""

from .client import GateDecision, OnyxGate, OnyxGateError
from .filter import SIGNATURE_HEADER, FilterResponse, decide_message, verify_signature
from .guard import GateResult, ToolGuard
from .receipt import (
    ReceiptError,
    ReceiptInvalid,
    ReceiptMismatch,
    ReceiptMissing,
    read_public_key,
    request_sha256,
    require_receipt,
    verify_receipt,
)

__all__ = [
    "GateDecision",
    "GateResult",
    "OnyxGate",
    "OnyxGateError",
    "ToolGuard",
    "ReceiptError",
    "ReceiptInvalid",
    "ReceiptMismatch",
    "ReceiptMissing",
    "read_public_key",
    "request_sha256",
    "require_receipt",
    "verify_receipt",
    "FilterResponse",
    "SIGNATURE_HEADER",
    "decide_message",
    "verify_signature",
]

__version__ = "0.3.0"
