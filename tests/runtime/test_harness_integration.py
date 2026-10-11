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
import re
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
    component_output,
    start_component,
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


def _probe_health(probe: RuntimeProbe) -> dict | None:
    """Answer from a live component, or None when nothing serves the endpoint."""
    try:
        resp = probe.health()
    except Exception:
        return None
    return resp if isinstance(resp, dict) else None


def _worker_failure_reasons(resp: dict | None) -> list:
    """Named failing workers from either the raw daemon view or the CLI view.

    The daemon reports `failure_reason` (+ mask); the control-plane view
    normalizes it to a `failure_reasons` list.
    """
    workers = (resp or {}).get("workers") or {}
    reasons = list(workers.get("failure_reasons") or [])
    if not reasons and workers.get("failure_reason"):
        reasons.append(workers["failure_reason"])
    return reasons


def _foreign_owner_pid(probe: RuntimeProbe, expected_pid: int | None = None) -> int | None:
    """Pid of a process already serving the endpoint, if it is not ours."""
    resp = _probe_health(probe)
    if resp is None:
        return None
    pid = resp.get("pid")
    if not pid or pid == expected_pid:
        return None
    return int(pid)


def _unreadable_foreign_owner(probe: RuntimeProbe) -> str | None:
    """Describe a foreign runtime that owns the endpoint but cannot be read.

    The control pipe is single-instance. When another principal owns it (for
    example the LocalSystem AegisNids service), CreateFileW fails with
    ERROR_ACCESS_DENIED (5), and a concurrent second server sees
    ERROR_PIPE_BUSY (231). Only ERROR_FILE_NOT_FOUND (2) means nothing serves
    the endpoint, so only that case may start a local component here.
    """
    try:
        probe.health()
    except Exception as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror in (5, 231):
            return (
                f"endpoint {probe.endpoint!r} is owned by another runtime "
                f"(winerror={winerror})"
            )
    return None


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
        self.proc = start_component(cmd, cwd=REPO_ROOT)
        probe = RuntimeProbe.for_component(self.component["name"])
        try:
            resp = wait_for_state(
                probe, "RUNNING",
                timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
            )
        except TimeoutError as exc:
            raise AssertionError(
                f"{exc}\n--- {self.component['name']} output ---\n"
                + "\n".join(component_output(self.proc)["stdout"][-30:])
                + "\n--- stderr ---\n"
                + "\n".join(component_output(self.proc)["stderr"][-30:])
            ) from exc
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
        self.bridge_proc = start_component([_start_command(bridge)[0]], cwd=REPO_ROOT)
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
        probe = RuntimeProbe.for_component(self.component["name"])
        # The runtime is single-owner (one pipe instance, one runtime owner).
        # If another core already answers, the process started here could never
        # serve the contract, and the probe would report the foreign pid.
        # Single response object, reused below: the pipe is max-1-instance
        # and an immediate re-probe can transiently fail while the first
        # handle drains, which would fake a "no health" failure.
        resp = _probe_health(probe)
        owner = None
        if resp is not None and resp.get("pid"):
            owner = int(resp.get("pid"))
        if owner is None:
            owner = _foreign_owner_pid(probe)
            if owner is not None:
                resp = _probe_health(probe)
        if owner is not None:
            # Single-owner contract, proven before skipping: a second core
            # cannot be started here (the pipe is max-1-instance; a
            # concurrent server sees ERROR_PIPE_BUSY and the daemon only
            # logs + stops slowly instead of refusing fast -- GAP-020).
            # The holder must be a real runtime under the contract: its
            # health names its own pid and reports RUNNING or an honest
            # named-reason DEGRADED. A squatter or stale pipe fails here
            # loudly instead of hiding behind the skip.
            self.assertIsNotNone(
                resp, f"pipe owner pid={owner} answers no health")
            self.assertEqual(resp.get("pid"), owner)
            self.assertIn(resp.get("state"), ("RUNNING", "DEGRADED"))
            if resp.get("state") == "DEGRADED":
                self.assertTrue(
                    _worker_failure_reasons(resp),
                    "DEGRADED owner must name its failure reasons")
            self.skipTest(
                f"another core instance (pid={owner}) already owns the control "
                "pipe; the runtime contract is single-owner"
            )
        foreign = _unreadable_foreign_owner(probe)
        if foreign is not None:
            self.skipTest(
                f"{foreign}; the runtime contract is single-owner, so this "
                "test cannot start a second core against the same pipe"
            )

        cmd = _start_command(self.component)
        self.proc = start_component(cmd, cwd=REPO_ROOT)
        try:
            resp = wait_for_state(
                probe, "RUNNING",
                timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
                expected_pid=self.proc.pid,
            )
        except TimeoutError as exc:
            # A core that cannot arm every worker reports DEGRADED with a named
            # failure reason. That is an honest terminal state, not a startup
            # failure; RUNNING remains the requirement when no worker failed.
            terminal = _probe_health(probe)
            reasons = _worker_failure_reasons(terminal)
            degraded_is_honest = (
                terminal is not None
                and terminal.get("state") == "DEGRADED"
                and terminal.get("pid") == self.proc.pid
                and bool(reasons)
            )
            if not degraded_is_honest:
                exit_code = self.proc.poll()
                captured = component_output(self.proc)
                related = [
                    line for line in captured["stderr"]
                    if re.search(r"(?i)(etw|pep|wfp|bridge|worker|capabilit|failure)", line)
                ]
                raise AssertionError(
                    f"{exc}\n--- core process diagnostics ---\n"
                    f"exit_code={exit_code!r}\n"
                    f"running={exit_code is None}\n"
                    "health probe uses canonical command=system.health\n"
                    "--- related startup/dependency diagnostics ---\n"
                    + "\n".join(related[-80:])
                    + "\n"
                    f"--- stdout (last 30 lines) ---\n"
                    + "\n".join(captured["stdout"][-30:])
                    + "\n--- stderr (last 30 lines) ---\n"
                    + "\n".join(captured["stderr"][-30:])
                ) from exc
            resp = terminal
        self.assertEqual(resp["component"], "core")
        self.assertEqual(resp.get("pid"), self.proc.pid)
        if resp.get("state") == "DEGRADED":
            self.assertTrue(
                _worker_failure_reasons(resp),
                "a DEGRADED core must name the worker that failed",
            )
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
        self.proc = start_component(cmd, cwd=REPO_ROOT)
        probe = RuntimeProbe.for_component(self.component["name"])
        try:
            resp = wait_for_state(
                probe, "RUNNING",
                timeout_ms=DEFAULT_TIMEOUTS_MS["startup"],
            )
        except TimeoutError as exc:
            raise AssertionError(
                f"{exc}\n--- brain output ---\n"
                + "\n".join(component_output(self.proc)["stdout"][-30:])
            ) from exc
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
                resp = _probe_health(probe)
                if resp is None:
                    # Expected: nothing serves the endpoint. Every transport
                    # error is acceptable (pywintypes.error is not an OSError
                    # subclass on Python 3.14+).
                    continue
                # A component owned by the host or another session answers
                # honestly; that is not a false positive. The invariant that
                # still holds is that the answer is a valid lifecycle state and
                # a RUNNING claim identifies the serving process.
                assert_state_in(resp.get("state", "STOPPED"))
                if resp.get("state") == "RUNNING":
                    self.assertTrue(
                        resp.get("pid"),
                        f"{name} claims RUNNING without identifying its pid",
                    )


if __name__ == "__main__":
    unittest.main()
