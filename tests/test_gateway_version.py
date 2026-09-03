"""The soft gateway-version check: a warning at guard construction outside the
supported range, never a refusal; silent for in-range, pre-0.2.0 (no `server`
block), or unreachable gateways."""

import warnings

import pytest

from onyx_gate_obot import OnyxGate, ToolGuard
from onyx_gate_obot.client import SUPPORTED_GATEWAY_BELOW, SUPPORTED_GATEWAY_MIN, _parse_version
from tests.stub_gateway import StubGateway


def ready(version: str) -> dict:
    return {"policies": 1, "entities": 0, "server": {"name": "eg_gateway", "version": version, "commit": "abc"}}


def no_runtime_warning(fn):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = fn()
    assert not [w for w in caught if issubclass(w.category, RuntimeWarning)]
    return result


def test_in_range_gateway_is_silent():
    lo = ".".join(map(str, SUPPORTED_GATEWAY_MIN))
    with StubGateway(ready_body=ready(lo)) as stub:
        gate = OnyxGate(stub.url)
        assert gate.server_info()["version"] == lo
        assert gate.gateway_version_warning() is None
        guard = no_runtime_warning(lambda: ToolGuard(gate))
        assert guard.gate is gate


def test_out_of_range_gateway_warns_and_still_decides():
    hi = ".".join(map(str, SUPPORTED_GATEWAY_BELOW))
    with StubGateway(ready_body=ready(hi)) as stub:
        gate = OnyxGate(stub.url)
        message = gate.gateway_version_warning()
        assert message and hi in message and stub.url in message
        with pytest.warns(RuntimeWarning, match="written against"):
            ToolGuard(gate)
        # Never a refusal: the decision path is untouched.
        assert gate.gate_tool_call(agent="a", tool="t").allowed


def test_pre_0_2_gateway_without_a_server_block_is_silent():
    with StubGateway() as stub:  # default /ready: no `server` block
        gate = OnyxGate(stub.url)
        assert gate.server_info() is None
        assert gate.gateway_version_warning() is None
        no_runtime_warning(lambda: ToolGuard(gate))


def test_unreachable_gateway_is_silent_at_startup():
    gate = OnyxGate("http://127.0.0.1:1", timeout=0.5)
    assert gate.server_info() is None
    assert gate.gateway_version_warning() is None
    no_runtime_warning(lambda: ToolGuard(gate))


def test_the_check_can_be_disabled():
    with StubGateway(ready_body=ready("9.9.9")) as stub:
        no_runtime_warning(lambda: ToolGuard(OnyxGate(stub.url), check_version=False))


def test_version_parsing_tolerates_suffixes_and_rejects_junk():
    assert _parse_version("0.3.0") == (0, 3, 0)
    assert _parse_version("0.3.0+abc.dirty") == (0, 3, 0)
    assert _parse_version("1.0.0-rc1") == (1, 0, 0)
    assert _parse_version("three") is None
    assert _parse_version("1.2") is None
