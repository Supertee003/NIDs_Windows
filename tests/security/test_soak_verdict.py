"""E2 regression for the soak verdict (S1-05).

The previous soak tool reported PASS for a DEGRADED daemon with 265,675 dropped
queue rows, because it read `status` (which carries no degraded flag) and never
looked at the loss counters. These tests pin the fail-closed criteria.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "host_soak_check", ROOT / "tools" / "host_soak_check.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RUNNING = {name: "RUNNING" for name in ("AegisNids", "AegisAggregator", "AegisWfp", "AegisMinifilter")}


def base_kwargs(**over):
    kwargs = dict(
        elapsed_h=25.0,
        required_h=24.0,
        states=dict(RUNNING),
        expect=tuple(RUNNING),
        status={"state": "RUNNING", "uptime_ms": 25 * 3_600_000},
        health={"state": "RUNNING", "degraded": False, "data_integrity": {}},
        queue={"shed_overload": 0},
        restarts=[],
        loss_budget=0,
        shed_budget=0,
    )
    kwargs.update(over)
    return kwargs


def test_clean_window_passes() -> None:
    problems, complete = load_tool().evaluate(**base_kwargs())
    assert problems == []
    assert complete is True


def test_degraded_daemon_fails_even_with_zero_losses() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(health={"state": "DEGRADED", "degraded": True, "data_integrity": {}})
    )
    assert any("DEGRADED" in p for p in problems)


def test_any_loss_counter_above_budget_fails() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(
            health={
                "state": "RUNNING",
                "degraded": False,
                "data_integrity": {"queue_dropped_total": 265_675, "minifilter_pipeline_dropped": 1_016},
            }
        )
    )
    assert any("queue_dropped_total=265675" in p for p in problems)
    assert any("minifilter_pipeline_dropped=1016" in p for p in problems)


def test_owner_approved_budget_allows_bounded_loss() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(
            loss_budget=2_000,
            health={
                "state": "RUNNING",
                "degraded": False,
                "data_integrity": {"queue_dropped_total": 1_500},
            },
        )
    )
    assert problems == []


def test_restart_inside_window_fails() -> None:
    problems, _ = load_tool().evaluate(**base_kwargs(restarts=["2026-11-10T02:14:43"]))
    assert any("restarted inside the window" in p for p in problems)


def test_stopped_driver_fails() -> None:
    states = dict(RUNNING, AegisWfp="STOPPED")
    problems, _ = load_tool().evaluate(**base_kwargs(states=states))
    assert "AegisWfp is STOPPED" in problems


def test_short_uptime_fails() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(status={"state": "RUNNING", "uptime_ms": 1 * 3_600_000})
    )
    assert any("restarted mid-soak" in p for p in problems)


def test_incomplete_window_is_not_a_pass() -> None:
    problems, complete = load_tool().evaluate(**base_kwargs(elapsed_h=9.3))
    assert problems == []
    assert complete is False


def test_policy_shed_above_budget_fails() -> None:
    # QLOSS-ETW-PRIORITY-001: converting overflow into deliberate shed must not
    # make a zero-loss soak pass. The queue counter is part of the verdict.
    problems, _ = load_tool().evaluate(
        **base_kwargs(queue={"shed_overload": 145_915})
    )
    assert any("shed_overload=145915" in p for p in problems)


def test_owner_approved_shed_budget_allows_bounded_policy_loss() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(queue={"shed_overload": 150}, shed_budget=200)
    )
    assert problems == []


def test_queue_stats_unavailable_fails_closed() -> None:
    problems, _ = load_tool().evaluate(
        **base_kwargs(queue={"error": "control_daemon_query_failed"})
    )
    assert any("queue stats unavailable" in p for p in problems)
