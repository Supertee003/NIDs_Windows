"""CONTROL-REPLAY-001: active v2 control envelopes are fresh and single-use.

The authoritative enforcement is the Zig daemon (`src/control/handler_registry.zig`
plus `src/control/replay_guard.zig`). These Python checks pin the client-side
builder against that contract and prove that two successive requests never
reuse a nonce or request id. No named pipe is opened and no host effect is
performed, so this is an E2 contract proof, not an E3/E5 claim.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from tools.aegisctl.envelope import (
    CONTROL_PROTOCOL_VERSION,
    build_v2_envelope,
    build_v2_request,
    serialize_envelope,
)

REPO = Path(__file__).resolve().parents[2]
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


def test_v2_envelope_carries_freshness_single_use_fields_and_no_role() -> None:
    before = int(time.time() * 1000)
    env = build_v2_envelope("system.health", {"probe": True})
    after = int(time.time() * 1000)

    assert env["command"] == "system.health"
    assert env["payload"] == {"probe": True}
    assert env["protocol_version"] == CONTROL_PROTOCOL_VERSION == 2
    assert HEX32.match(env["request_id"])
    assert HEX32.match(env["nonce"])
    assert before <= env["issued_at_ms"] <= after
    # The daemon derives the role from the impersonated Windows token; a
    # caller-supplied role field must never reappear on the wire.
    assert "role" not in env
    assert "caller_role" not in env


def test_two_envelopes_have_distinct_nonce_and_request_id() -> None:
    first = build_v2_envelope("system.status")
    second = build_v2_envelope("system.status")
    assert first["nonce"] != second["nonce"]
    assert first["request_id"] != second["request_id"]


def test_serialized_request_is_one_json_document() -> None:
    wire = build_v2_request("system.health")
    assert wire == serialize_envelope(json.loads(wire))
    assert wire.count(b"\n") == 0
    parsed = json.loads(wire)
    assert parsed["protocol_version"] == 2


def test_active_zig_dispatch_enforces_version_nonce_and_freshness() -> None:
    source = (REPO / "src" / "control" / "handler_registry.zig").read_text(encoding="utf-8")
    guard = (REPO / "src" / "control" / "replay_guard.zig").read_text(encoding="utf-8")
    assert 'root.object.get("protocol_version")' in source
    assert 'root.object.get("nonce")' in source
    assert 'root.object.get("issued_at_ms")' in source
    assert "replay_guard.g_guard.checkAndRecord(" in source
    assert "MAX_SKEW_MS" in guard
    assert ".replay" in guard
    assert "CAPACITY" in guard


def test_every_active_python_probe_uses_the_shared_builder() -> None:
    client = (REPO / "tools" / "aegisctl" / "client.py").read_text(encoding="utf-8")
    api = (REPO / "tools" / "aegisctl" / "api" / "control_api.py").read_text(encoding="utf-8")
    probe = (REPO / "tools" / "probe_control_pipe.py").read_text(encoding="utf-8")
    conftest = (REPO / "tests" / "runtime" / "conftest.py").read_text(encoding="utf-8")
    for source in (client, api, probe, conftest):
        assert "build_v2_request" in source
    utils = (REPO / "tools" / "aegisctl" / "utils.py").read_text(encoding="utf-8")
    assert "build_v2_envelope" in utils
    assert '"role": role' not in utils
