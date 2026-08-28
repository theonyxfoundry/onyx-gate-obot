"""Fire signed Obot-style filter payloads at a REAL receiver + REAL Onyx gateway.

This script plays the part of the Obot MCP Gateway, byte-for-byte per the
documented HTTP filter contract: it POSTs JSON-RPC ``tools/call`` messages,
HMAC-SHA256-signed in ``X-Obot-Signature-256``, and treats 200 as accept /
non-200 as reject — so you can watch the whole filter path work without an
Obot deployment.

Run the Onyx gateway and the receiver first::

    eg_gateway --policies examples/obot/policy.cedar --log trail.jsonl
    echo -n somethingsecret > webhook.secret
    onyx-gate-obot --secret-file webhook.secret --port 8891

then::

    python examples/obot/dry_run.py

and re-check the decision trail afterwards::

    eg_verify --audit-log trail.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request


def fire(url: str, secret: str, message: dict) -> tuple[int, dict, float]:
    """Send one signed filter payload, exactly as the Obot gateway does."""
    body = json.dumps(message).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Obot-Signature-256", "sha256=" + digest)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read()), (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}"), (time.perf_counter() - started) * 1000


def tools_call(name: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ONYX_OBOT_URL", "http://127.0.0.1:8891/webhook"))
    parser.add_argument("--secret", default=os.environ.get("OBOT_WEBHOOK_SECRET", "somethingsecret"))
    args = parser.parse_args()

    calls = [
        ("an agent searches", tools_call("search", {"query": "quarterly report template"})),
        ("reads a public file", tools_call("read_file", {"path": "/data/public/handbook.md"})),
        ("reads a restricted file", tools_call("read_file", {"path": "/data/finance/q3-figures.txt"})),
        ("tries an un-permitted tool", tools_call("delete_file", {"path": "/data/public/handbook.md"})),
        ("a tampered payload arrives", None),  # wrong signature, see below
    ]

    print(f"receiver: {args.url}\n")
    for label, message in calls:
        if message is None:
            body = json.dumps(tools_call("read_file", {"path": "/data/public/x"})).encode()
            req = urllib.request.Request(args.url, data=body, method="POST")
            req.add_header("X-Obot-Signature-256", "sha256=" + "0" * 64)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status, payload, ms = resp.status, json.loads(resp.read()), 0.0
            except urllib.error.HTTPError as e:
                status, payload, ms = e.code, json.loads(e.read() or b"{}"), 0.0
            print(f"[{status}] {label}")
            print(f"      {payload.get('detail')}\n")
            continue
        status, payload, ms = fire(args.url, args.secret, message)
        verdict = "accepted" if status == 200 else f"REJECTED ({status})"
        name = message["params"]["name"]
        print(f"[{status}] {label} — {name}{json.dumps(message['params']['arguments'])} → {verdict}  ({ms:.1f} ms)")
        if status != 200:
            print("      what Obot surfaces to the caller:")
            for line in payload.get("detail", "").splitlines():
                print(f"      {line}")
        print()

    print("Every gated decision above is in the Onyx gateway's hash-chained trail")
    print("(if started with --log). Re-check it offline:  eg_verify --audit-log trail.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
