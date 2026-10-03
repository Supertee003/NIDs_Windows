"""T2-BRAIN-023: Tier-2 sensor-pipe return contract pins.

The brain reports findings to the daemon sensor pipe with explicit
brain_tier2 provenance. Pinned here:
  B1. String rule IDs hash with FNV-1a identically to the Zig detector
      (golden: R0056 -> 2107512682, shared with the contract pin table).
  B2. Payload shape carries source/rule_id/severity/5-tuple the Zig
      applyJsonMetadata parser accepts.
  B3. Transport is opt-in only (AEGIS_SENSOR_PIPE=1); default off means
      DISABLED and no behavior change, no pipe handle is ever opened.
  B4. (T2-BRAIN-023b) The C edge is Cython, not ctypes: the compiled
      sender reports FAILED honestly on a missing pipe, and the ctypes
      fallback keeps the identical contract when no .pyd is built.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.windows_brain import (  # noqa: E402
    SENSOR_PIPE_ENABLED,
    _send_via_ctypes,
    build_sensor_payload,
    fnv1a32,
    send_to_sensor_pipe,
)

MISSING_PIPE = "\\\\.\\pipe\\aegis_probe_nonexistent_9z"


def test_fnv1a32_matches_zig_rule_id_space():
    assert fnv1a32("R0056") == 2107512682


def test_sensor_payload_shape_and_rule_hashing():
    doc = build_sensor_payload("SQL injection", "R0056", "High", "192.168.126.10")
    assert doc["source"] == "brain_tier2"
    assert doc["rule_id"] == 2107512682
    assert doc["severity"] == "High"
    assert doc["src_ip"] == "192.168.126.10"
    assert doc["protocol"] == "TCP"
    assert build_sensor_payload("x", 4242, "Low", "10.0.0.1")["rule_id"] == 4242


def test_sensor_pipe_disabled_by_default_reports_disabled():
    assert SENSOR_PIPE_ENABLED is False
    assert send_to_sensor_pipe({"source": "brain_tier2"}) == "DISABLED"


def test_ctypes_fallback_reports_failed_on_missing_pipe():
    assert _send_via_ctypes(MISSING_PIPE, b'{"a":1}') == "FAILED"


def test_cython_sender_reports_failed_on_missing_pipe():
    sensor_pipe = pytest.importorskip(
        "brain.cython.sensor_pipe",
        reason="sensor_pipe.pyd not built (fallback path active)",
    )
    assert sensor_pipe.send_bytes(MISSING_PIPE, b'{"a":1}') == "FAILED"
