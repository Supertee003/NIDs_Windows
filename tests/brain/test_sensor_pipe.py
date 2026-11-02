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

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from brain.windows_brain import (  # noqa: E402
    _send_via_ctypes,
    build_sensor_payload,
    fnv1a32,
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
    # The module reads AEGIS_SENSOR_PIPE at import time, so an operator shell
    # that exports it would otherwise flip this default-off pin. Probe the
    # contract in a clean child process instead of mutating this interpreter.
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_SENSOR_PIPE"}
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "from brain.windows_brain import SENSOR_PIPE_ENABLED, send_to_sensor_pipe;"
            "print('ENABLED=' + str(SENSOR_PIPE_ENABLED));"
            "print('SEND=' + send_to_sensor_pipe({'source': 'brain_tier2'}))",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert probe.returncode == 0, probe.stderr
    assert "ENABLED=False" in probe.stdout, probe.stdout
    assert "SEND=DISABLED" in probe.stdout, probe.stdout


def test_ctypes_fallback_reports_failed_on_missing_pipe():
    assert _send_via_ctypes(MISSING_PIPE, b'{"a":1}') == "FAILED"


def test_cython_sender_reports_failed_on_missing_pipe():
    sensor_pipe = pytest.importorskip(
        "brain.cython.sensor_pipe",
        reason="sensor_pipe.pyd not built (fallback path active)",
    )
    assert sensor_pipe.send_bytes(MISSING_PIPE, b'{"a":1}') == "FAILED"
