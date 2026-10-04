"""B2-LOGTH-041: anomaly-log throttle pins (behavioral).

anomalous.json is append-only with no rotation; a detection storm would
fill the disk. anomaly_log_allowed() caps appends per 60s window and counts
shed load in DROPPED_COUNT (visible on the HEALTH probe); write_anomaly_log
returns WRITTEN/THROTTLED. Rotation/truncation is deliberately not used
(the mouth tail reader tracks absolute offsets and would go blind).

Uses a manual scratch dir (see test_hot_reload.py fixture note): this
host's Temp holds an admin-owned dead pytest-current symlink that breaks
pytest's own tmp_path teardown. E2 (real files, no daemon).
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import brain.windows_brain as brain  # noqa: E402


@pytest.fixture
def scratch() -> Path:
    name = tempfile.mkdtemp(prefix="aegis-logth-")
    yield Path(name)
    shutil.rmtree(name, ignore_errors=True)


@pytest.fixture(autouse=True)
def reset_throttle():
    brain._log_window_start = 0.0
    brain._log_window_count = 0
    brain.DROPPED_COUNT = 0
    yield
    brain._log_window_start = 0.0
    brain._log_window_count = 0


def entry(i: int = 0) -> dict:
    return {"source": "test", "src_ip": "10.0.0.1", "n": i}


def test_burst_cap_throttles_and_counts(scratch):
    target = scratch / "anomalous.json"
    outcomes = [
        brain.write_anomaly_log(entry(i), "T", "Alert", "R1", path=str(target))
        for i in range(brain.LOG_BURST_MAX + 5)
    ]
    assert outcomes.count("WRITTEN") == brain.LOG_BURST_MAX
    assert outcomes.count("THROTTLED") == 5
    assert brain.DROPPED_COUNT == 5
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == brain.LOG_BURST_MAX
    assert json.loads(lines[0])["attack_type"] == "T"


def test_window_rollover_rearms(scratch):
    target = scratch / "anomalous.json"
    for i in range(brain.LOG_BURST_MAX):
        assert brain.write_anomaly_log(entry(i), "T", "Alert", "R1", path=str(target)) == "WRITTEN"
    assert brain.write_anomaly_log(entry(), "T", "Alert", "R1", path=str(target)) == "THROTTLED"
    brain._log_window_start -= (brain.LOG_WINDOW_SEC + 1.0)
    assert brain.write_anomaly_log(entry(), "T", "Alert", "R1", path=str(target)) == "WRITTEN"
    assert brain.DROPPED_COUNT == 1


def test_gate_never_raises_and_is_deterministic():
    assert brain.anomaly_log_allowed() is True
    for _ in range(brain.LOG_BURST_MAX):
        brain.anomaly_log_allowed()
    assert brain.anomaly_log_allowed() is False
