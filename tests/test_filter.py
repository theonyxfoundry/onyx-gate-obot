import hashlib
import hmac

from onyx_gate_obot import OnyxGate, ToolGuard, decide_message, verify_signature
from tests.stub_gateway import StubGateway

DENY = (200, {"decision": "deny", "explanation": "path outside the permitted tree"})
ALLOW = (200, {"decision": "allow"})


def make_guard(stub, **kwargs):
    return ToolGuard(gate=OnyxGate(stub.url), agent="obot", **kwargs)


# -- signature -----------------------------------------------------------


def test_signature_matches_the_documented_obot_scheme():
    body = b'{"jsonrpc":"2.0","method":"tools/call"}'
    secret = "somethingsecret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_signature(body, digest, secret)
    assert verify_signature(body, "sha256=" + digest, secret)  # prefix optional


def test_signature_rejects_wrong_missing_or_tampered():
    body = b'{"a":1}'
    secret = "s"
    good = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert not verify_signature(body, None, secret)
    assert not verify_signature(body, "", secret)
    assert not verify_signature(body, good[:-1] + "0", secret)
    assert not verify_signature(b'{"a":2}', good, secret)


# -- decide_message ------------------------------------------------------


def tools_call(name="read_file", arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_allowed_tool_call_is_accepted():
    with StubGateway(lambda p: ALLOW) as stub:
        r = decide_message(tools_call("read_file", {"path": "/data/public/a.txt"}), make_guard(stub))
        assert r.status == 200 and r.accepted
        sent = stub.requests[0]["payload"]
        assert sent["tool"] == "read_file"
        assert sent["resource_attrs"] == {"path": "/data/public/a.txt"}
        assert sent["agent"] == "obot"


def test_denied_tool_call_is_rejected_403_with_the_reason():
    with StubGateway(lambda p: DENY) as stub:
        r = decide_message(tools_call("read_file", {"path": "/data/finance/q3.txt"}), make_guard(stub))
        assert r.status == 403 and not r.accepted
        assert "did NOT execute" in r.body["detail"]
        assert "path outside the permitted tree" in r.body["detail"]
        assert "read_file(path='/data/finance/q3.txt')" in r.body["detail"]


def test_onyx_gateway_down_rejects_503_fail_closed():
    guard = ToolGuard(gate=OnyxGate("http://127.0.0.1:1", timeout=0.5), agent="obot")
    r = decide_message(tools_call(), guard)
    assert r.status == 503
    assert "fail-closed" in r.body["detail"]


def test_non_tool_call_messages_pass_untouched():
    with StubGateway() as stub:
        guard = make_guard(stub)
        for msg in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 7, "result": {"content": []}},  # a response
            {"jsonrpc": "2.0", "method": "notifications/progress"},
        ):
            assert decide_message(msg, guard).status == 200
        assert stub.requests == []  # never consulted the gateway


def test_nameless_tools_call_is_rejected_400():
    with StubGateway() as stub:
        r = decide_message({"jsonrpc": "2.0", "method": "tools/call", "params": {}}, make_guard(stub))
        assert r.status == 400
        assert stub.requests == []


def test_non_dict_arguments_are_tolerated():
    with StubGateway(lambda p: ALLOW) as stub:
        r = decide_message(
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": None}},
            make_guard(stub),
        )
        assert r.status == 200


def test_observe_mode_accepts_but_annotates_the_flagged_call():
    with StubGateway(lambda p: DENY) as stub:
        r = decide_message(tools_call("read_file", {"path": "/x"}), make_guard(stub, mode="observe"))
        assert r.status == 200
        assert "would have been DENIED" in r.body["advisory"]
