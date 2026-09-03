"""Onyx Gate for Obot — a verifiable authorization filter for the Obot MCP Gateway.

* :mod:`onyx_gate_obot.filter` — the Obot filter contract mapped onto Onyx gate
  decisions (payload signature check, JSON-RPC ``tools/call`` → allow/deny).
* :mod:`onyx_gate_obot.server` — the dependency-free webhook receiver
  (``onyx-gate-obot`` console entry point).
* :mod:`onyx_gate_obot.client` / :mod:`onyx_gate_obot.guard` — the shared
  framework-agnostic core, vendored from ``onyx-gate-crewai``.
"""

from .client import GateDecision, OnyxGate, OnyxGateError
from .filter import SIGNATURE_HEADER, FilterResponse, decide_message, verify_signature
from .guard import GateResult, ToolGuard

__all__ = [
    "GateDecision",
    "GateResult",
    "OnyxGate",
    "OnyxGateError",
    "ToolGuard",
    "FilterResponse",
    "SIGNATURE_HEADER",
    "decide_message",
    "verify_signature",
]

__version__ = "0.2.0"
