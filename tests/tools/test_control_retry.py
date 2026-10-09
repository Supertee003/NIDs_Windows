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
