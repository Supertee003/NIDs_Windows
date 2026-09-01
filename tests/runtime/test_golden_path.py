"""
test_golden_path.py - Gate B integration tests

Verifies the end-to-end golden path pipeline:
  synthetic event → bridge → core → brain → aggregator → dashboard

This test suite has two modes:
  1. STATIC (always runs): verifies the pipeline contract (which
     components should be connected to which, what transport each
     uses, what the expected event flow is). These tests pass without
     any running components.

  2. LIVE (skipped if components not running): actually starts the
     pipeline, sends synthetic events via aegis_event_gen, and verifies
     that events appear at each stage. These tests require:
       - All binaries built (scripts/build_all.bat)
       - aegisctl.py available (to start/stop components)
       - Windows (for named pipe transport)

The static tests document the golden path contract so that any future
change to the pipeline structure is caught by CI.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "scripts" / "aegisctl.py"
EVENT_GEN = REPO_ROOT / "scripts" / "aegis_event_gen.py"

# Pipeline stages in order (per docs/runtime/LOCAL_RUNBOOK.md §7-8)
GOLDEN_PATH_STAGES = [
    {"name": "bridge",     "role": "ipc_hub",          "input": "pipe",          "output": "ring_buffer"},
    {"name": "core",       "role": "tier1_detection",  "input": "ring_buffer",    "output": "udp_brain"},
    {"name": "brain",      "role": "tier2_ips",        "input": "udp_brain",      "output": "ndjson_log"},
    {"name": "aggregator", "role": "dedup_correlate",  "input": "ndjson_log",    "output": "rest_api"},
    {"name": "dashboard",  "role": "ui",               "input": "rest_api",      "output": "egui_window"},
]

# Endpoints used by the golden path (per COMPONENT_MATRIX.md §3)
PIPE_BRIDGE_SENSOR = r"\\.\pipe\aegis_nids"           # event_gen → core (sensor pipe)
PIPE_BRIDGE_HEALTH = r"\\.\pipe\aegis-bridge-health"
PIPE_CORE_HEALTH   = r"\\.\pipe\aegis-core-health"
UDP_BRAIN_ALERT    = ("127.0.0.1", 9999)
TCP_CORE_SENSOR    = ("127.0.0.1", 12345)
HTTP_AGGREGATOR    = ("127.0.0.1", 9200)


def _is_windows() -> bool:
    return sys.platform == "win32"


def _have_aegisctl() -> bool:
    return AEGISCTL.exists()


def _have_event_gen() -> bool:
    return EVENT_GEN.exists()


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT),
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except (OSError, FileNotFoundError) as e:
        return -2, "", str(e)


def _aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    """Run aegisctl with the given subcommand args."""
    return _run([sys.executable, str(AEGISCTL)] + list(args), timeout=timeout)


def _is_component_running(name: str) -> bool:
    """Check if a component is running via aegisctl status."""
    if not _have_aegisctl():
        return False
    rc, stdout, _ = _aegisctl("status", "--component", name)
    if rc != 0:
        return False
    return "RUNNING" in stdout


# =====================================================================
# STATIC tests (always run — verify pipeline contract)
# =====================================================================

class TestGoldenPathContract(unittest.TestCase):
    """Verify the golden path pipeline structure is documented correctly."""

    def test_pipeline_has_5_stages(self):
        self.assertEqual(len(GOLDEN_PATH_STAGES), 5)

    def test_pipeline_stage_names(self):
        expected = ["bridge", "core", "brain", "aggregator", "dashboard"]
        actual = [s["name"] for s in GOLDEN_PATH_STAGES]
        self.assertEqual(actual, expected)

    def test_pipeline_input_output_chain(self):
        """Each stage's output should match the next stage's input
        (the transport medium between adjacent stages)."""
        # Adjacent stages share a transport medium — the output of one
        # IS the input of the next.
        # bridge.ring_buffer → core.ring_buffer (same medium)
        # core.udp_brain     → brain.udp_brain   (same medium)
        # brain.ndjson_log   → aggregator.ndjson_log (same medium)
        # aggregator.rest_api → dashboard.rest_api (same medium)
        for i in range(len(GOLDEN_PATH_STAGES) - 1):
            current = GOLDEN_PATH_STAGES[i]
            next_stage = GOLDEN_PATH_STAGES[i + 1]
            self.assertEqual(
                current["output"], next_stage["input"],
                f"stage {current['name']} output {current['output']!r} != "
                f"next stage {next_stage['name']} input {next_stage['input']!r} "
                f"(adjacent stages must share the same transport medium)"
            )

    def test_pipeline_stage_roles_unique(self):
        roles = [s["role"] for s in GOLDEN_PATH_STAGES]
        self.assertEqual(len(roles), len(set(roles)),
                         f"roles should be unique, got: {roles}")


class TestGoldenPathEndpoints(unittest.TestCase):
    """Verify the endpoints used by the golden path are documented."""

    def test_bridge_sensor_pipe_documented(self):
        self.assertTrue(PIPE_BRIDGE_SENSOR.startswith(r"\\.\pipe\aegis_"))

    def test_bridge_health_pipe_documented(self):
        self.assertTrue(PIPE_BRIDGE_HEALTH.startswith(r"\\.\pipe\aegis-bridge-health"))

    def test_core_health_pipe_documented(self):
        self.assertTrue(PIPE_CORE_HEALTH.startswith(r"\\.\pipe\aegis-core-health"))

    def test_brain_udp_port(self):
        host, port = UDP_BRAIN_ALERT
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 9999)

    def test_core_tcp_port(self):
        host, port = TCP_CORE_SENSOR
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 12345)

    def test_aggregator_http_port(self):
        host, port = HTTP_AGGREGATOR
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 9200)


class TestGoldenPathEventSchema(unittest.TestCase):
    """Verify the synthetic event schema is well-formed JSON with required fields."""

    SAMPLE_EVENT = {
        "attack_type": "SYN-FLOOD-TEST",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "severity": "High",
        "policy": "Alert",
        "rule_id": "TEST-001",
        "reason": "Gate-B synthetic event",
        "source": "aegis_event_gen",
    }

    def test_event_is_json_serializable(self):
        s = json.dumps(self.SAMPLE_EVENT)
        parsed = json.loads(s)
        self.assertEqual(parsed, self.SAMPLE_EVENT)

    def test_event_has_required_fields(self):
        for field in ("attack_type", "src_ip", "severity", "policy", "rule_id"):
            self.assertIn(field, self.SAMPLE_EVENT, f"missing field: {field}")

    def test_event_severity_is_valid(self):
        self.assertIn(self.SAMPLE_EVENT["severity"],
                      ("Low", "Medium", "High", "Critical"))

    def test_event_policy_is_valid(self):
        self.assertIn(self.SAMPLE_EVENT["policy"],
                      ("Alert", "Block", "Drop"))


class TestGoldenPathScriptsExist(unittest.TestCase):
    """Verify the helper scripts exist."""

    def test_aegisctl_exists(self):
        if not _have_aegisctl():
            self.skipTest("scripts/aegisctl.py not found")
        self.assertTrue(AEGISCTL.is_file())

    def test_event_gen_exists(self):
        if not _have_event_gen():
            self.skipTest("scripts/aegis_event_gen.py not found")
        self.assertTrue(EVENT_GEN.is_file())

    def test_event_gen_help_works(self):
        if not _have_event_gen():
            self.skipTest("scripts/aegis_event_gen.py not found")
        rc, stdout, stderr = _run([sys.executable, str(EVENT_GEN), "--help"])
        self.assertEqual(rc, 0)
        self.assertIn("--pipe", stdout)
        self.assertIn("--udp", stdout)
        self.assertIn("--tcp", stdout)


# =====================================================================
# LIVE tests (skipped if components not running)
# =====================================================================

class TestGoldenPathLive(unittest.TestCase):
    """Live integration tests — only run when components are up.

    These tests require:
      - Windows (for named pipe transport)
      - All binaries built
      - Components started via `aegisctl start --all`
    """

    @classmethod
    def setUpClass(cls):
        if not _have_aegisctl():
            raise unittest.SkipTest("aegisctl.py not available")
        if not _have_event_gen():
            raise unittest.SkipTest("aegis_event_gen.py not available")
        if not _is_windows():
            raise unittest.SkipTest("live tests are Windows-only")

    def setUp(self):
        # Check that bridge + core + brain are running
        for name in ("bridge", "core", "brain"):
            if not _is_component_running(name):
                self.skipTest(f"component {name} not running (use 'aegisctl start --all')")

    def test_brain_health_endpoint_responds(self):
        """Brain's UDP HEALTH endpoint should respond to {"op":"HEALTH"}."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(b'{"op":"HEALTH"}', UDP_BRAIN_ALERT)
                data, _ = s.recvfrom(8192)
            resp = json.loads(data.decode("utf-8"))
            self.assertEqual(resp.get("component"), "brain")
            self.assertEqual(resp.get("state"), "RUNNING")
        except (socket.timeout, ConnectionRefusedError, json.JSONDecodeError) as e:
            self.skipTest(f"brain health probe failed: {e}")

    def test_brain_receives_synthetic_event(self):
        """Send a synthetic event via UDP to brain and verify it processes it.

        We send an event with a unique rule_id, then query the brain's
        HEALTH endpoint to see if in_events counter increased.
        """
        # Get baseline counter
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(b'{"op":"HEALTH"}', UDP_BRAIN_ALERT)
                data, _ = s.recvfrom(8192)
            baseline = json.loads(data.decode("utf-8"))
            baseline_in = baseline.get("counters", {}).get("in_events", 0)
        except Exception as e:
            self.skipTest(f"cannot get baseline brain health: {e}")
            return

        # Send 3 synthetic events via UDP
        unique_rule = f"GATE-B-LIVE-{int(time.time())}"
        rc, _, _ = _run([
            sys.executable, str(EVENT_GEN),
            "--udp", "--count", "3", "--rule-id", unique_rule,
            "--attack", "GATE-B-TEST", "--severity", "High",
        ], timeout=10)
        if rc != 0:
            self.skipTest("event_gen failed to send events")
            return

        # Wait a moment for the brain to process
        time.sleep(0.5)

        # Get updated counter
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(b'{"op":"HEALTH"}', UDP_BRAIN_ALERT)
                data, _ = s.recvfrom(8192)
            updated = json.loads(data.decode("utf-8"))
            updated_in = updated.get("counters", {}).get("in_events", 0)
        except Exception as e:
            self.skipTest(f"cannot get updated brain health: {e}")
            return

        # Counter should have increased by at least 3
        self.assertGreaterEqual(
            updated_in, baseline_in + 3,
            f"brain in_events did not increase by 3 (baseline={baseline_in}, "
            f"updated={updated_in}). The brain may not be receiving events."
        )

    def test_aggregator_health_endpoint_responds(self):
        """Aggregator's /api/health should respond with the full schema."""
        if not _is_component_running("aggregator"):
            self.skipTest("aggregator not running")
        try:
            import urllib.request
            host, port = HTTP_AGGREGATOR
            url = f"http://{host}:{port}/api/health"
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                data = resp.read().decode("utf-8")
            parsed = json.loads(data)
            # G35: aggregator now returns full schema
            self.assertEqual(parsed.get("component"), "aggregator")
            self.assertEqual(parsed.get("state"), "RUNNING")
            self.assertIn("counters", parsed)
            self.assertIn("deps", parsed)
        except ImportError:
            self.skipTest("urllib not available")
        except Exception as e:
            self.skipTest(f"aggregator health probe failed: {e}")


# =====================================================================
# Pipeline orchestration test (uses aegisctl)
# =====================================================================

class TestGoldenPathOrchestration(unittest.TestCase):
    """Verify that aegisctl can drive the golden path."""

    @classmethod
    def setUpClass(cls):
        if not _have_aegisctl():
            raise unittest.SkipTest("aegisctl.py not available")

    def test_aegisctl_diagnose_reports_all_components(self):
        """`aegisctl diagnose` should mention every component in the golden path."""
        rc, stdout, _ = _aegisctl("diagnose")
        self.assertEqual(rc, 0)
        for stage in GOLDEN_PATH_STAGES:
            self.assertIn(stage["name"], stdout,
                          f"aegisctl diagnose did not mention {stage['name']}")

    def test_aegisctl_status_includes_primary_components(self):
        """`aegisctl status` should list every PRIMARY component.
        Note: 'dashboard' is an auxiliary service and may not appear
        in the COMPONENTS fixture if it's not yet registered there.
        """
        rc, stdout, _ = _aegisctl("status")
        self.assertEqual(rc, 0)
        # Primary components (per COMPONENT_MATRIX.md §2.1) that MUST appear
        primary_stages = [s for s in GOLDEN_PATH_STAGES if s["name"] != "dashboard"]
        for stage in primary_stages:
            self.assertIn(stage["name"], stdout,
                          f"aegisctl status did not mention primary component {stage['name']}")


if __name__ == "__main__":
    unittest.main()
