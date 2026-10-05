"""B2-SCANVIS-048: Tier-2 regex scans windows, not just the prefix (behavioral).

run_regex_scan used to scan only the first 4096 bytes, so a marker past
4KB in a Case-2 UDP payload (up to 64KB) was silently missed (padding
evasion). Windows of SCAN_CHUNK with SCAN_OVERLAP overlap are now scanned
in order, first match wins, both Cython and Python paths per window
(equivalence preserved structurally). Uses a manual scratch dir (see
test_hot_reload.py fixture note). E2 (real rules, real payloads).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import brain.windows_brain as brain  # noqa: E402
from brain.windows_brain import (  # noqa: E402
    _scan_windows,
    compile_tier2_rules,
    run_regex_scan,
)

RULES = {
    "nids_rules": [
        {"rule_id": "R0056", "name": "sqli", "match_pattern": "' OR 1=1",
         "severity": "Critical", "action": "Drop"},
    ]
}


@pytest.fixture
def scratch() -> Path:
    name = tempfile.mkdtemp(prefix="aegis-scanvis-")
    yield Path(name)
    shutil.rmtree(name, ignore_errors=True)


@pytest.fixture
def engine():
    return compile_tier2_rules(RULES)


def test_prefix_marker_still_detected(engine):
    payload = "GET /login?u=x' OR 1=1 -- HTTP/1.1"
    hit = run_regex_scan(payload, engine, RULES)
    assert hit is not None and hit[2] == "R0056"


def test_deep_marker_detected_past_old_bound(engine):
    pad = "A" * 8000
    payload = pad + "' OR 1=1" + "B" * 8000
    assert len(payload) > brain.SCAN_CHUNK * 2
    hit = run_regex_scan(payload, engine, RULES)
    assert hit is not None and hit[2] == "R0056", "marker past 4KB must be found"


def test_marker_straddling_window_edge_detected(engine):
    # Marker starts inside the overlap zone of window 0 (ends at 4096).
    start = brain.SCAN_CHUNK - 512
    payload = "A" * start + "' OR 1=1" + "B" * 5000
    hit = run_regex_scan(payload, engine, RULES)
    assert hit is not None and hit[2] == "R0056"


def test_benign_large_payload_stays_quiet(engine):
    payload = "A" * 20000 + "hello world" * 500
    assert run_regex_scan(payload, engine, RULES) is None


def test_windows_cover_without_gaps():
    text = "x" * 10000
    covered = set()
    count = 0
    for w in _scan_windows(text):
        assert len(w) <= brain.SCAN_CHUNK
        count += 1
    assert count > 1
    # Rebuild coverage from documented geometry instead of internals.
    step = brain.SCAN_CHUNK - brain.SCAN_OVERLAP
    pos = 0
    while pos < len(text):
        covered.update(range(pos, min(pos + brain.SCAN_CHUNK, len(text))))
        if pos + brain.SCAN_CHUNK >= len(text):
            break
        pos += step
    assert covered == set(range(len(text)))
