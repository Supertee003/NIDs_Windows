"""
test_harness_integration.py - Live integration tests for the runtime contract.

These tests actually start a real component process and observe its
lifecycle. They are gated on platform availability (Windows for named
pipes, the relevant binary being built, etc.) and skipped automatically
otherwise.

Run with:

    python -m pytest tests/runtime/test_harness_integration.py -v

The harness intentionally does NOT depend on the full supervisor; it
spawns one component at a time using the commands from
docs/runtime/LOCAL_RUNBOOK.md, observes its lifecycle, and stops it.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

from tests.runtime.conftest import (
    COMPONENTS,
    DEFAULT_TIMEOUTS_MS,
    REQUIRED_COMPONENTS,
    RuntimeProbe,
    assert_state_in,
    wait_for_state,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
IS_WINDOWS = sys.platform == "win32"


def _binary_path(component: dict) -> Path:
    return REPO_ROOT / component["binary"]


def _have_binary(component: dict) -> bool:
    return _binary_path(component).exists()


def _have_python() -> bool:
    return bool(shutil.which("python") or shutil.which("python3"))


def _skip_if_no(component: dict):
    if not IS_WINDOWS and component["health"]["transport"] == "pipe":
        raise unittest.SkipTest("named pipes are Windows-only")
    if not _have_binary(component):
        raise unittest.SkipTest(f"{component['name']} binary not built")
    if component["name"] == "brain" and not _have_python():
        raise unittest.SkipTest("no python interpreter on PATH")


def _start_command(component: dict) -> list[str]:
    """Mirror the start commands from LOCAL_RUNBOOK.md."""
    path = str(_binary_path(component))
    if component["name"] == "brain":
        python = shutil.which("python") or shutil.which("python3")
        return [python, path]
    return [path]


# --------------------------------------------------------------------------- #
# Integration tests (one per primary engine)                                  #
# --------------------------------------------------------------------------- #

class TestBridgeLifecycle(unittest.TestCase):
    """Start bridge, verify READY→RUNNING, then STOP."""

    def setUp(self):
        bridge = next(c for c in COMPONENTS if c["name"] == "bridge")
        _skip_if_no(bridge)
        self.component = bridge
        self.proc: subprocess.Popen | None = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=DEFAULT_TIMEOUTS_MS["shutdown"] / 1000)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def test_bridge_reaches_running_within_startup_timeout(self):
        cmd = _start_command(self.component)
        self.proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        probe = RuntimeProbe.for_component(self.component["name"])
        resp = wait_for_state(
            probe, "RUNNING",
            timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
        )
        assert_state_in(resp["state"])
        self.assertEqual(resp["component"], "bridge")


class TestCoreLifecycle(unittest.TestCase):
    """Start core (after bridge is up), verify it reaches RUNNING."""

    def setUp(self):
        core = next(c for c in COMPONENTS if c["name"] == "core")
        _skip_if_no(core)
        # Also need bridge running first.
        bridge = next(c for c in COMPONENTS if c["name"] == "bridge")
        if not _have_binary(bridge):
            self.skipTest("bridge binary required to start core")
        self.bridge_proc = subprocess.Popen(
            [_start_command(bridge)[0]],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Wait for bridge to be ready.
        bprobe = RuntimeProbe.for_component("bridge")
        try:
            wait_for_state(bprobe, "RUNNING",
                            timeout_ms=DEFAULT_TIMEOUTS_MS["startup"])
        except Exception:
            self.bridge_proc.terminate()
            self.skipTest("bridge failed to start; cannot test core")

        self.component = core
        self.proc: subprocess.Popen | None = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=DEFAULT_TIMEOUTS_MS["shutdown"] / 1000)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.bridge_proc and self.bridge_proc.poll() is None:
            self.bridge_proc.terminate()
            try:
                self.bridge_proc.wait(timeout=DEFAULT_TIMEOUTS_MS["shutdown"] / 1000)
            except subprocess.TimeoutExpired:
                self.bridge_proc.kill()

    def test_core_reaches_running_within_startup_timeout(self):
        cmd = _start_command(self.component)
        self.proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        probe = RuntimeProbe.for_component(self.component["name"])
        resp = wait_for_state(
            probe, "RUNNING",
            timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
        )
        self.assertEqual(resp["component"], "core")
        # Verify deps includes bridge.
        dep_names = [d["name"] for d in resp.get("deps", [])]
        self.assertIn("bridge", dep_names)


class TestBrainLifecycle(unittest.TestCase):
    """Start brain, verify it reaches RUNNING.

    G27: the brain now implements a HEALTH probe handler at the top of
    its UDP recv loop. When a packet {"op":"HEALTH"} arrives on UDP 9999,
    the brain responds with a JSON object matching the schema in
    RUNTIME_CONTRACT.md §4.1.
    """

    BRAIN_HAS_HEALTH_ENDPOINT = True  # G27: brain now implements HEALTH.

    def setUp(self):
        if not self.BRAIN_HAS_HEALTH_ENDPOINT:
            self.skipTest("brain does not yet implement HEALTH endpoint (Gate-A work)")
        brain = next(c for c in COMPONENTS if c["name"] == "brain")
        _skip_if_no(brain)
        self.component = brain
        self.proc: subprocess.Popen | None = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=DEFAULT_TIMEOUTS_MS["shutdown"] / 1000)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def test_brain_reaches_running_within_startup_timeout(self):
        cmd = _start_command(self.component)
        self.proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        probe = RuntimeProbe.for_component(self.component["name"])
        resp = wait_for_state(
            probe, "RUNNING",
            timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
        )
        self.assertEqual(resp["component"], "brain")


# --------------------------------------------------------------------------- #
# Idempotent start/stop tests                                                  #
# --------------------------------------------------------------------------- #

class TestIdempotentStop(unittest.TestCase):
    """Per LIFECYCLE.md §4.2, calling stop() on a STOPPED component MUST
    return success without logging an error. We simulate this by probing
    a component that we never started.

    Note: when no component is running, the health probe is expected to
    fail. We accept ANY exception here, because the probe transports
    raise different exception types on different platforms:

      - named pipe (Windows pywin32): pywintypes.error (winerror=2)
      - TCP: ConnectionRefusedError
      - UDP: timeout (socket.timeout)
      - stdout log: FileNotFoundError
      - delegate: any of the above from the delegate component

    The test only fails if a probe SUCCEEDS and claims state=RUNNING,
    which would be a false positive (a process answering that is not
    the one we expect)."""

    def test_probe_on_unstarted_component_returns_no_such_state(self):
        for name in REQUIRED_COMPONENTS:
            with self.subTest(component=name):
                probe = RuntimeProbe.for_component(name)
                try:
                    resp = probe.health()
                except Exception:
                    # Expected: nothing is running, any error is acceptable.
                    # This includes pywintypes.error on Windows, which is
                    # NOT a subclass of OSError on Python 3.14+.
                    continue
                # If we did get a response, it should not claim RUNNING
                # unless a process is actually there.
                self.assertNotEqual(resp.get("state"), "RUNNING")


if __name__ == "__main__":
    unittest.main()
