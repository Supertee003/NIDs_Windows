"""FE-DEF-095a: the daemon is the DEFCON authority; UIs project it.

Failure mode pinned: four surfaces computed DEFCON independently from
files (two label vocabularies), and every file-tailed ladder showed
SAFE when the evidence log was absent while the daemon held open
incidents. Contract:

  AC1. control/defcon.zig is the single ladder (scope pin proves it
       executes; RUNTIME_CONTRACT §4.1 carries defcon_level/label).
  AC2. Python UIs prefer daemon health defcon; the local evidence
       ladder survives only as a labeled fallback.
  AC3. An empty evidence feed with live daemon DEFCON never renders
       SAFE (the exact live divergence found in verification).

No tree writes: control-plane access is mocked, the evidence log is
only read, Flask runs on an in-memory test client.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]

from tools.aegisctl.web_dashboard import app as dashboard


def _mocked_dashboard(health):
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


def _daemon_health(**overrides):
    base = {
        "state": "RUNNING",
        "degraded": False,
        "counters": {},
        "rules_loaded": 22,
        "policies_loaded": 6,
        "runtime_available": True,
    }
    base.update(overrides)
    return base


def test_zig_ladder_is_wired_into_the_unit_binary():
    closure_source = (REPO_ROOT / "src" / "all_tests.zig").read_text(encoding="utf-8")
    assert 'control/defcon.zig' in closure_source
    health_source = (REPO_ROOT / "src" / "control" / "state_machine.zig").read_text(encoding="utf-8")
    assert 'defcon_level' in health_source
    assert 'defcon_label' in health_source


def test_contract_declares_daemon_defcon_authority():
    contract = (REPO_ROOT / "docs" / "runtime" / "RUNTIME_CONTRACT.md").read_text(encoding="utf-8")
    assert "defcon_level" in contract
    assert "own ladder" in contract and "MUST" in contract


def test_empty_feed_with_live_daemon_defcon_does_not_render_safe():
    # THE fix proof: zero evidence records (missing log file) plus daemon
    # DEFCON 3 must project HIGH, never the ladder's SAFE.
    health = _daemon_health(defcon_level=3, defcon_label="HIGH")
    mocks = _mocked_dashboard(health)
    for m in mocks:
        m.start()
    try:
        with patch.object(
            dashboard, "_read_detection_feed",
            return_value={"available": False, "path": "mocked", "records": [], "total_scanned": 0},
        ):
            snap = dashboard.snapshot()
            assert snap["threat"]["records"] == 0
            assert snap["threat"]["defcon"] == 3
            assert snap["threat"]["label"] == "HIGH"
            assert "daemon authority" in snap["threat"]["basis"]
    finally:
        for m in mocks:
            m.stop()


def test_missing_daemon_defcon_falls_back_to_labeled_ladder():
    health = _daemon_health()  # pre-095a daemon: no defcon fields
    assert "defcon_level" not in health
    mocks = _mocked_dashboard(health)
    for m in mocks:
        m.start()
    try:
        with patch.object(
            dashboard, "_read_detection_feed",
            return_value={"available": False, "path": "mocked", "records": [], "total_scanned": 0},
        ):
            snap = dashboard.snapshot()
            assert snap["threat"]["defcon"] == 5
            assert snap["threat"]["label"] == "SAFE"
            assert "evidence log" in snap["threat"]["basis"]
    finally:
        for m in mocks:
            m.stop()


def test_get_defcon_prefers_daemon_over_file_fallback():
    from tools.aegisctl.api import control_api

    health = _daemon_health(defcon_level=2, defcon_label="SEVERE")
    with patch.object(control_api, "get_health_payload", return_value=health):
        assert control_api.get_defcon() == (2, "SEVERE")


def test_get_defcon_rejects_garbage_daemon_values():
    from tools.aegisctl.api import control_api

    for bad in (
        {"defcon_level": 9, "defcon_label": "MAXIMUM"},
        {"defcon_level": 1, "defcon_label": ""},
        {"defcon_level": "1", "defcon_label": "MAXIMUM"},
    ):
        health = _daemon_health(**bad)
        with patch.object(control_api, "get_health_payload", return_value=health):
            # Must not propagate garbage: falls through to the
            # diagnostic bridge/file path (None in this environment).
            assert control_api.get_defcon() is None
