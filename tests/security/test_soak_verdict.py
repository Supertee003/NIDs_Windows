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


def zero_integrity(**over) -> dict:
    """A complete data_integrity block, as the daemon actually emits it.

    SOAK-BASELINE-001 made a missing counter fail closed (an unread counter is
    not evidence of zero loss), so the fixtures carry all six keys.
    """
    block = {
        "queue_dropped_total": 0,
        "nose_frames_rejected": 0,
        "nose_frames_dropped": 0,
        "nose_pipe_errors": 0,
        "minifilter_ring_dropped": 0,
        "minifilter_pipeline_dropped": 0,
    }
    block.update(over)
    return block


def base_kwargs(**over):
    kwargs = dict(
        elapsed_h=25.0,
        required_h=24.0,
        states=dict(RUNNING),
        expect=tuple(RUNNING),
        status={"state": "RUNNING", "uptime_ms": 25 * 3_600_000},
        health={"state": "RUNNING", "degraded": False, "data_integrity": zero_integrity()},
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
                "data_integrity": zero_integrity(queue_dropped_total=1_500),
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


# ── SOAK-BASELINE-001 ───────────────────────────────────────────────────────
#
# The counters are cumulative for the process, so the absolute gate charges a
# window with everything that happened since process start. Observed on the
# host: a driver deploy plus its canaries shed 5,310 ETW rows in the first
# ~20 minutes, then the process shed nothing for the next two hours. Under the
# absolute rule that window can never pass, even if it is clean from then on;
# under a baseline rule it passes *and* the pre-window burst stays visible in
# the artifact. Both behaviours are pinned here.

def _baseline() -> dict:
    return {
        "recorded_at": "2026-11-14T18:55:00",
        "data_integrity": {
            "queue_dropped_total": 2_898,
            "nose_frames_rejected": 0,
            "nose_frames_dropped": 0,
            "nose_pipe_errors": 0,
            "minifilter_ring_dropped": 0,
            "minifilter_pipeline_dropped": 0,
        },
        "shed_overload": 5_310,
    }


def _live_after_baseline() -> dict:
    return {
        "state": "RUNNING",
        "degraded": False,
        "data_integrity": {
            "queue_dropped_total": 2_898,
            "nose_frames_rejected": 0,
            "nose_frames_dropped": 0,
            "nose_pipe_errors": 0,
            "minifilter_ring_dropped": 0,
            "minifilter_pipeline_dropped": 0,
        },
    }


def test_baseline_ignores_the_pre_window_burst_but_keeps_it_reported() -> None:
    problems, complete = load_tool().evaluate(
        **base_kwargs(
            health=_live_after_baseline(),
            queue={"shed_overload": 5_310},
            loss_budget=3_500,
            shed_budget=4_000,
            baseline=_baseline(),
        )
    )
    assert problems == []
    assert complete is True


def test_baseline_still_fails_on_growth_inside_the_window() -> None:
    live = _live_after_baseline()
    live["data_integrity"] = dict(live["data_integrity"], queue_dropped_total=2_898 + 3_501)
    problems, _ = load_tool().evaluate(
        **base_kwargs(
            health=live,
            queue={"shed_overload": 5_310 + 4_001},
            loss_budget=3_500,
            shed_budget=4_000,
            baseline=_baseline(),
        )
    )
    assert any("queue_dropped_total grew by 3501" in p for p in problems)
    assert any("shed_overload grew by 4001" in p for p in problems)


def test_baseline_counter_going_backwards_fails_closed() -> None:
    live = _live_after_baseline()
    live["data_integrity"] = dict(live["data_integrity"], queue_dropped_total=0)
    problems, _ = load_tool().evaluate(
        **base_kwargs(health=live, queue={"shed_overload": 5_310}, baseline=_baseline())
    )
    assert any("queue_dropped_total went backwards" in p for p in problems)


def test_baseline_missing_a_counter_fails_closed() -> None:
    base = _baseline()
    base["data_integrity"].pop("minifilter_ring_dropped")
    problems, _ = load_tool().evaluate(
        **base_kwargs(
            health=_live_after_baseline(),
            queue={"shed_overload": 5_310},
            baseline=base,
        )
    )
    assert any("baseline has no numeric minifilter_ring_dropped" in p for p in problems)

