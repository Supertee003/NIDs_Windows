"""READINESS-CAUSE-001: a gate that refuses must name a cause.

`aegisctl.py readiness` is the machine-facing release gate: automation branches
on its exit code, and the soak tool reads the same health payload. On the live
host it once answered `ready: false, overall_gate: false` with
`failure_reasons: []` and `degraded_components: []`, which is a refusal nobody
can act on and nobody can audit.

These tests pin the property rather than one shape of payload: whenever the gate
closes, `failure_reasons` is non-empty and every entry is a non-blank string.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / "tools"
AEGISCTL = TOOLS_DIR / "aegisctl.py"


def _load():
    # tools/ holds the `aegisctl` package the CLI imports; the CLI is loaded by
    # path so the test exercises the shipped file, not an installed copy.
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(
        "aegisctl_readiness_under_test", AEGISCTL
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegisctl_readiness_under_test"] = module  # dataclasses need it
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def aegisctl():
    return _load()


def _healthy() -> dict:
    return {
        "state": "RUNNING",
        "degraded": False,
        "rules_loaded": 12,
        "policies_loaded": 3,
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
        "subsystems": {},
    }


def test_healthy_payload_passes_with_no_reasons(aegisctl) -> None:
    result = aegisctl.build_readiness(_healthy())
    assert result["ready"] is True
    assert result["overall_gate"] is True
    assert result["failure_reasons"] == []
    assert result["missing"] == []


def test_unavailable_daemon_names_the_unknown_state(aegisctl) -> None:
    result = aegisctl.build_readiness({})
    assert result["ready"] is False
    assert "state_unknown" in result["failure_reasons"]
    assert result["failure_reasons"]


def test_stopped_state_names_itself(aegisctl) -> None:
    payload = _healthy()
    payload["state"] = "STOPPED"
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert "state_stopped" in result["failure_reasons"]


def test_a_missing_worker_flag_names_that_worker(aegisctl) -> None:
    payload = _healthy()
    payload["workers"]["fim_ready"] = False
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert "fim_ready" in result["missing"]
    assert "worker_fim_ready_not_ready" in result["failure_reasons"]


def test_failed_worker_is_named(aegisctl) -> None:
    payload = _healthy()
    payload["workers"]["failed"] = True
    payload["workers"]["failure_reasons"] = ["etw_pipe_error"]
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert "worker_failed" in result["failure_reasons"]
    assert "etw_pipe_error" in result["failure_reasons"]


def test_no_rules_loaded_is_named(aegisctl) -> None:
    payload = _healthy()
    payload["rules_loaded"] = 0
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert "rules_not_loaded" in result["failure_reasons"]


def test_degraded_subsystem_is_named_with_its_error(aegisctl) -> None:
    payload = _healthy()
    payload["degraded"] = True
    payload["subsystems"] = {"fim": {"state": "DEGRADED", "error": "pipe_closed"}}
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert "fim_pipe_closed" in result["failure_reasons"]


def test_degraded_with_no_attributable_component_is_still_named(aegisctl) -> None:
    """The exact shape the live host produced: degraded, nothing named."""
    payload = _healthy()
    payload["degraded"] = True
    payload["subsystems"] = {}
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False
    assert result["degraded_components"] == []
    assert result["failure_reasons"] == ["degraded_without_named_component"]


@pytest.mark.parametrize(
    "mutation",
    [
        {"state": "STARTING"},
        {"state": "DEGRADED"},
        {"state": "FAILED"},
        {"degraded": True},
        {"rules_loaded": 0},
        {"workers": {"pipeline_ready": False}},
        {"workers": {"failed": True}},
        {"workers": {"registry_ready": False}}, 
        {"state": None},
    ],
)
def test_no_closed_gate_is_silent(aegisctl, mutation) -> None:
    payload = _healthy()
    payload.update(mutation)
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is False, mutation
    assert result["failure_reasons"], f"silent refusal for {mutation}"
    assert all(
        isinstance(r, str) and r.strip() for r in result["failure_reasons"]
    ), mutation


def test_a_non_running_subsystem_is_reported_even_when_the_gate_opens(aegisctl) -> None:
    """The gate is worker-flag based; a subsystem state must still be visible.

    Whether a STOPPED subsystem should close the gate is a product decision
    (which subsystems are required for readiness), so this test pins only the
    reporting side: the component and its state are named in the output, never
    dropped because the aggregate boolean said healthy.
    """
    payload = _healthy()
    payload["subsystems"] = {"registry": {"state": "STOPPED"}}
    result = aegisctl.build_readiness(payload)
    assert result["ready"] is True  # unchanged semantics; see READINESS-CAUSE-001 §4
    assert result["degraded_components"] == [
        {"name": "registry", "state": "STOPPED", "error": None}
    ]
    assert "registry_stopped" in result["failure_reasons"]


def test_result_is_json_serialisable_like_the_cli_prints_it(aegisctl) -> None:
    json.dumps(aegisctl.build_readiness(_healthy()), sort_keys=True)
    json.dumps(aegisctl.build_readiness({}), sort_keys=True)
