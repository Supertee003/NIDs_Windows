"""Control-pipe retry: contention backoff, dead-daemon bound.

The daemon serves one control client at a time, so concurrent queriers
(dashboard refresh, web snapshots, pytest live tests, operator scans)
collide routinely — plus a full-ring verify can hold the instance for
seconds under load. Pins:
  - transient None answers are retried with backoff and then succeed
    (5 attempts, ~0.75s worst; attempts counted exactly).
  - a dead daemon still resolves to None (bounded wait, no hang).
No daemon, no pipe, no sleeps beyond milliseconds (backoff is real
time: attempts are few and delays tiny by construction).
"""
from __future__ import annotations

from tools.aegisctl.api import control_api


def test_retry_succeeds_after_transient_failures(monkeypatch):
    calls = {"n": 0}

    def flaky(command, payload=None):
        calls["n"] += 1
        if calls["n"] < 3:
            return None
        return {"ok": True}

    monkeypatch.setattr(control_api, "_query_daemon", flaky)
    assert control_api._query_daemon_retry("system.health") == {"ok": True}
    assert calls["n"] == 3


def test_retry_gives_up_after_five_attempts(monkeypatch):
    calls = {"n": 0}

    def dead(command, payload=None):
        calls["n"] += 1
        return None

    monkeypatch.setattr(control_api, "_query_daemon", dead)
    assert control_api._query_daemon_retry("system.health") is None
    assert calls["n"] == 5


def test_latency_probe_counts_and_orders(monkeypatch):
    # Deterministic: mocked replies, real clock only for ordering math
    # (p50 <= p99 <= max must hold on any data).
    calls = {"n": 0}

    def ok3(command, payload=None):
        calls["n"] += 1
        return {"state": "RUNNING"} if calls["n"] <= 3 else None

    monkeypatch.setattr(control_api, "query_control", ok3)
    doc = control_api.pipe_latency_probe(5)
    assert doc["rounds"] == 5 and doc["ok"] == 3 and doc["failed"] == 2
    assert doc["p50_ms"] <= doc["p99_ms"] <= doc["max_ms"]
    assert doc["capped"] is False


def test_latency_probe_caps_rounds_and_survives_total_failure(monkeypatch):
    calls = {"n": 0}

    def count(command, payload=None):
        calls["n"] += 1
        return {"state": "RUNNING"}

    monkeypatch.setattr(control_api, "query_control", count)
    doc = control_api.pipe_latency_probe(10000)
    assert doc["rounds"] == 100 and calls["n"] == 100
    assert doc["capped"] is True

    def dead(command, payload=None):
        return None

    monkeypatch.setattr(control_api, "query_control", dead)
    doc = control_api.pipe_latency_probe(3)
    assert doc["ok"] == 0 and doc["failed"] == 3
    assert doc["p50_ms"] is None and doc["max_ms"] is None
