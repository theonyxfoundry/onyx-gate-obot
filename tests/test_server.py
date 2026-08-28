"""End-to-end through the HTTP receiver, driving it exactly as Obot's gateway
does per the documented filter contract (signed JSON-RPC POST; 200 accepts,
non-200 rejects)."""

import hashlib
import hmac
import json
import urllib.error
import urllib.request

import pytest

from onyx_gate_obot import OnyxGate, ToolGuard
from onyx_gate_obot.server import make_server, serve_in_thread
from tests.stub_gateway import StubGateway

SECRET = "somethingsecret"
DENY = (200, {"decision": "deny", "explanation": "path outside the permitted tree"})
ALLOW = (200, {"decision": "allow"})


class Receiver:
    """A running receiver on an ephemeral port, wired to a stub Onyx gateway."""

    def __init__(self, stub, secret=SECRET, **guard_kwargs):
        guard = ToolGuard(gate=OnyxGate(stub.url), agent="obot", **guard_kwargs)
        self.server = make_server(guard, secret, port=0, log=lambda line: None)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def __enter__(self):
        serve_in_thread(self.server)
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def post(self, message, sign_with=SECRET, header=None, path="/webhook"):
        body = json.dumps(message).encode() if isinstance(message, dict) else message
        req = urllib.request.Request(self.url + path, data=body, method="POST")
        if sign_with is not None:
            digest = hmac.new(sign_with.encode(), body, hashlib.sha256).hexdigest()
            req.add_header("X-Obot-Signature-256", "sha256=" + digest)
        if header:
            req.add_header(*header)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def tools_call(name, arguments):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


def test_signed_allow_roundtrip():
    with StubGateway(lambda p: ALLOW) as stub, Receiver(stub) as rx:
        status, body = rx.post(tools_call("read_file", {"path": "/data/public/a.txt"}))
        assert (status, body["status"]) == (200, "accepted")


def test_signed_deny_is_rejected_with_reason():
    with StubGateway(lambda p: DENY) as stub, Receiver(stub) as rx:
        status, body = rx.post(tools_call("read_file", {"path": "/data/finance/q3.txt"}))
        assert status == 403
        assert "path outside the permitted tree" in body["detail"]


def test_unsigned_and_missigned_payloads_are_401():
    with StubGateway(lambda p: ALLOW) as stub, Receiver(stub) as rx:
        assert rx.post(tools_call("t", {}), sign_with=None)[0] == 401
        assert rx.post(tools_call("t", {}), sign_with="wrong-secret")[0] == 401
        assert stub.requests == []  # never reached the Onyx gateway


def test_no_secret_configured_accepts_unsigned():
    with StubGateway(lambda p: ALLOW) as stub, Receiver(stub, secret=None) as rx:
        assert rx.post(tools_call("t", {}), sign_with=None)[0] == 200


def test_malformed_json_is_rejected_400():
    with StubGateway() as stub, Receiver(stub) as rx:
        status, _ = rx.post(b"not json at all")
        assert status == 400
        status, _ = rx.post(b'["a","list"]')
        assert status == 400


def test_onyx_gateway_down_is_503_through_the_receiver():
    guard = ToolGuard(gate=OnyxGate("http://127.0.0.1:1", timeout=0.5), agent="obot")
    server = make_server(guard, SECRET, port=0, log=lambda line: None)
    url = "http://127.0.0.1:%d" % server.server_address[1]
    serve_in_thread(server)
    try:
        body = json.dumps(tools_call("t", {})).encode()
        digest = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(url + "/webhook", data=body, method="POST")
        req.add_header("X-Obot-Signature-256", digest)
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == 503
    finally:
        server.shutdown()
        server.server_close()


def test_health_and_unknown_paths():
    with StubGateway() as stub, Receiver(stub) as rx:
        req = urllib.request.Request(rx.url + "/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        assert rx.post(tools_call("t", {}), path="/elsewhere")[0] == 404
