"""FE-SSE-090: the web SSE stream survives disconnects and bad ticks.

Failure modes pinned here (previously silent):

  1. A disconnected client kept rendering full snapshots every tick
     until garbage collection (no explicit GeneratorExit handling).
  2. One failed snapshot killed the whole stream (the exception
     propagated instead of becoming an error event).

Both are read-only-path faults: no enforcement, no mutation, no tree
writes. All control-plane access is mocked; the generator is driven
directly with interval 0 so no test ever sleeps or binds a socket.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]

from tools.aegisctl.web_dashboard import app as dashboard


def _mocked_control():
    health = {
        "state": "RUNNING",
        "degraded": False,
        "counters": {},
        "rules_loaded": 2,
        "policies_loaded": 1,
    }
    queries = {
        "enforcement.status": {"prevention_gate": "closed", "host_effect_capable": False},
        "metrics.snapshot": {"events_processed": 1},
        "incidents.list": {"incidents": []},
        "forensics.verify": {"verified": True, "integrity": "ok", "records": 0},
    }
    return (
        patch.object(dashboard, "get_health_payload", return_value=health),
        patch.object(
            dashboard, "query_control", side_effect=lambda command, payload=None: queries.get(command, {})
        ),
        patch.object(dashboard, "load_rules", return_value={"nids_rules": []}),
    )


def _drive(gen, count):
    return [next(gen) for _ in range(count)]


def test_stream_endpoint_is_event_stream_with_retry_hint():
    mocks = _mocked_control()
    for m in mocks:
        m.start()
    try:
        client = dashboard.app.test_client()
        response = client.get("/stream", buffered=False)
        assert response.status_code == 200
        assert response.mimetype == "text/event-stream"
        first = next(response.response)
        text = first.decode() if isinstance(first, bytes) else first
        assert text.startswith(": connected")
        assert f"retry: {dashboard.SSE_RETRY_MS}" in text
        response.close()
    finally:
        for m in mocks:
            m.stop()


def test_disconnect_ends_the_generator_immediately():
    mocks = _mocked_control()
    for m in mocks:
        m.start()
    try:
        gen = dashboard._sse_events(interval_s=0)
        chunks = _drive(gen, 2)  # hello + one snapshot
        assert chunks[0].startswith(": connected")
        assert chunks[1].startswith("data: ")
        gen.close()  # client disconnect -> GeneratorExit inside
        try:
            next(gen)
        except StopIteration:
            pass
        else:
            raise AssertionError("generator kept yielding after disconnect")
    finally:
        for m in mocks:
            m.stop()


def test_failed_snapshot_becomes_error_event_not_dead_stream():
    mocks = _mocked_control()
    for m in mocks:
        m.start()
    try:
        calls = {"n": 0}
        real_snapshot = dashboard.snapshot

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("control plane hiccup")
            return real_snapshot()

        with patch.object(dashboard, "snapshot", side_effect=flaky):
            gen = dashboard._sse_events(interval_s=0)
            assert next(gen).startswith(": connected")
            error_msg = next(gen)
            assert error_msg.startswith("data: ")
            body = json.loads(error_msg[len("data: "):])
            assert body["error"] == "snapshot_failed"
            recovered = next(gen)
            assert recovered.startswith("data: ")
            body = json.loads(recovered[len("data: "):])
            assert body.get("schema") == "aegis.operator.snapshot.v1"
            assert "error" not in body
            gen.close()
    finally:
        for m in mocks:
            m.stop()


def test_error_event_never_claims_enforcement():
    mocks = _mocked_control()
    for m in mocks:
        m.start()
    try:
        with patch.object(dashboard, "snapshot", side_effect=RuntimeError("down")):
            gen = dashboard._sse_events(interval_s=0)
            next(gen)
            body = json.loads(next(gen)[len("data: "):])
            assert body["error"] == "snapshot_failed"
            assert "ENFORCED" not in json.dumps(body)
            assert "BLOCKED_CONFIRMED" not in json.dumps(body)
            gen.close()
    finally:
        for m in mocks:
            m.stop()
