"""CLI-STATE-001: a stale lifecycle must not degrade the runtime anonymously.

The daemon reports two states with different owners:

* `state` — the health contract, computed from live facts (workers, subsystems,
  data-loss counters);
* `runtime_state` — the lifecycle state machine, which `src/daemon.zig`
  sets once at startup and never re-promotes.

On the live host those two disagree: `state: RUNNING`, `degraded: false`,
seven of seven subsystems RUNNING, every worker ready — and `runtime_state:
DEGRADED`. The control API merged that into `DEGRADED` (fail-closed, correct)
but readiness then answered with `degraded_without_named_component`, which tells
an operator nothing.

These tests pin the naming, not the verdict: the gate still refuses, and it says
the state machine is the reason.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
AEGISCTL = TOOLS_DIR / "aegisctl.py"


def _load():
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location("aegisctl_state_machine_under_test", AEGISCTL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_state_machine_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def aegisctl():
    return _load()


def _disagreeing() -> dict:
    """The live shape: merged state DEGRADED, all facts healthy."""
    return {
        "state": "DEGRADED",
        "runtime_state": "DEGRADED",
        "state_machine_state": "DEGRADED",
        "state_machine_disagrees": True,
        "degraded": True,
        "rules_loaded": 23,
        "policies_loaded": 6,
        "subsystems": {
            name: {"state": "RUNNING", "error": None}
            for name in (
                "zig", "go", "cpp", "rust_pep", "tier3", "control", "forensic",
            )
        },
        "workers": {
            "pipeline_ready": True,
            "sensor_ready": True,
            "nose_ready": True,
            "etw_ready": True,
            "fim_ready": True,
            "registry_ready": True,
            "failed": False,
            "failure_mask": 0,
            "failure_reasons": [],
        },
    }


def test_a_stale_state_machine_is_named_instead_of_being_anonymous(aegisctl) -> None:
    result = aegisctl.build_readiness(_disagreeing())
    assert result["ready"] is False
    assert result["overall_gate"] is False
    assert "state_machine_degraded_but_health_facts_ready" in result["failure_reasons"]
    assert "degraded_without_named_component" not in result["failure_reasons"]
    assert result["degraded_components"] == []


def test_the_state_machine_state_is_reported(aegisctl) -> None:
    result = aegisctl.build_readiness(_disagreeing())
    assert result["state_machine_state"] == "DEGRADED"
    assert result["state_machine_disagrees"] is True


def test_a_healthy_payload_without_the_flag_is_unchanged(aegisctl) -> None:
    payload = _disagreeing()
    payload.update(
        {
            "state": "RUNNING",
            "runtime_state": "RUNNING",
            "state_machine_state": "RUNNING",
            "state_machine_disagrees": False,
            "degraded": False,
        }
    )
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is True
    assert result["failure_reasons"] == []


def test_real_degradation_still_names_its_component(aegisctl) -> None:
    """The new reason must not mask a genuine degraded subsystem."""
    payload = _disagreeing()
    payload["subsystems"]["fim"] = {"state": "DEGRADED", "error": "pipe_closed"}
    result = aegisctl.build_readiness(payload)
    assert "fim_pipe_closed" in result["failure_reasons"]
    assert result["ready"] is False
