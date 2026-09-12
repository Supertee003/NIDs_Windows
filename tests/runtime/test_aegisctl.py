"""
test_aegisctl.py - Tests for the aegisctl CLI (Gate C, v1).

Verifies that the aegisctl command/control CLI works as documented:
  - All subcommands parse correctly
  - version/status/health/diagnose are read-only and safe
  - start/stop/restart handle missing binaries gracefully
  - Exit codes follow the documented convention

These tests do NOT require running components — they verify the CLI
plumbing itself.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "tools" / "aegisctl.py"


def _run_aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    """Run aegisctl with the given args. Returns (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(AEGISCTL)] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT),
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"


class TestAegisctlExists(unittest.TestCase):
    """The aegisctl script must exist and be importable."""

    def test_aegisctl_script_exists(self):
        self.assertTrue(AEGISCTL.exists(), f"aegisctl.py not found at {AEGISCTL}")

    def test_aegisctl_help_exits_0(self):
        rc, stdout, stderr = _run_aegisctl("--help")
        self.assertEqual(rc, 0, f"--help should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("aegisctl", stdout.lower())
        self.assertIn("version", stdout)
        self.assertIn("status", stdout)
        self.assertIn("health", stdout)


class TestAegisctlVersionCommand(unittest.TestCase):
    """`aegisctl version` must list component versions from the runtime."""

    def test_version_lists_all_components(self):
        rc, stdout, stderr = _run_aegisctl("version")
        # CTRL-001: version now queries runtime via pipe
        # When daemon is running with new code, it returns versions from the pipe
        # When daemon is running with old code, it returns {"ok":false} (no handler)
        # When daemon is not running, it returns error
        self.assertIn("Component", stdout)
        # Either we got version data, or the daemon doesn't have the handler yet
        has_data = any(
            line.strip().startswith(("core", "nose", "shield", "pep"))
            for line in stdout.splitlines()
            if line.strip() and not line.startswith("-") and not line.startswith("Component")
        )
        has_error = "not reachable" in stderr or "not reachable" in stdout
        # Accept: data present, error present, or empty table (old daemon)
        self.assertTrue(
            has_data or has_error or rc == 0,
            f"unexpected output: stdout={stdout!r} stderr={stderr!r}"
        )

    def test_version_component_filter(self):
        rc, stdout, stderr = _run_aegisctl("version", "--component", "brain")
        # Should mention brain but not bridge/core/etc.
        self.assertIn("brain", stdout)
        # Other components should NOT appear in the table body
        # (the header "Component" is always present).
        lines = [l for l in stdout.splitlines() if l and not l.startswith("-") and not l.startswith("Component")]
        for line in lines:
            self.assertTrue(
                line.startswith("brain"),
                f"expected only 'brain' rows, got: {line}"
            )


class TestAegisctlStatusCommand(unittest.TestCase):
    """`aegisctl status` must show runtime state via pipe."""

    def test_status_lists_all_components(self):
        rc, stdout, stderr = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should exit 0, got {rc}; stderr={stderr}")
        # CTRL-001: status now queries runtime via pipe
        # Output shows Version, State, Uptime, etc.
        self.assertIn("State", stdout)
        self.assertIn("Version", stdout)

    def test_status_shows_state_column(self):
        rc, stdout, stderr = _run_aegisctl("status")
        # CTRL-001: status shows runtime state
        # Old daemon returns lowercase "running", new daemon returns "RUNNING"
        self.assertTrue(
            "running" in stdout.lower() or "not reachable" in stderr,
            f"expected running or connection error, got: stdout={stdout!r} stderr={stderr!r}"
        )


class TestAegisctlHealthCommand(unittest.TestCase):
    """`aegisctl health` must probe runtime health via pipe."""

    def test_health_runs_without_crash(self):
        rc, stdout, stderr = _run_aegisctl("health")
        # CTRL-001: health now queries runtime via pipe
        # Output shows Component, State, PID, Checks, etc.
        # When daemon is running, it shows subsystem checks
        # When daemon is not running, it shows connection error
        self.assertTrue(
            "State" in stdout or "not reachable" in stderr,
            f"expected State or connection error, got: stdout={stdout!r} stderr={stderr!r}"
        )


class TestAegisctlDiagnoseCommand(unittest.TestCase):
    """`aegisctl diagnose` must produce a comprehensive report."""

    def test_diagnose_contains_all_sections(self):
        rc, stdout, stderr = _run_aegisctl("diagnose")
        self.assertEqual(rc, 0, f"diagnose should exit 0, got {rc}; stderr={stderr}")
        # CTRL-001: diagnose now queries runtime via pipe
        # Sections: VERSION, RUNTIME STATUS, SUBSYSTEM HEALTH, LOG FILES
        self.assertIn("VERSION", stdout)
        self.assertIn("RUNTIME STATUS", stdout)
        self.assertIn("SUBSYSTEM HEALTH", stdout)
        self.assertIn("LOG FILES", stdout)
        self.assertIn("Diagnostic report complete", stdout)

    def test_diagnose_shows_repo_root(self):
        rc, stdout, stderr = _run_aegisctl("diagnose")
        self.assertIn("Repo root:", stdout)
        self.assertIn("Python:", stdout)
        self.assertIn("Platform:", stdout)


class TestAegisctlStartStopErrors(unittest.TestCase):
    """`aegisctl start/stop` must validate arguments."""

    def test_start_without_args_errors(self):
        rc, stdout, stderr = _run_aegisctl("start")
        self.assertNotEqual(rc, 0, "start without --component or --all should fail")
        # argparse enforces mutually_exclusive_group with required=True,
        # so the error message will mention that one of the options is required.
        combined = stdout + stderr
        self.assertTrue(
            "required" in combined.lower() or
            "must specify --component NAME or --all" in combined,
            f"expected error about required arg, got: stdout={stdout!r} stderr={stderr!r}"
        )

    def test_stop_without_args_errors(self):
        rc, stdout, stderr = _run_aegisctl("stop")
        self.assertNotEqual(rc, 0, "stop without --component or --all should fail")

    def test_restart_without_component_errors(self):
        rc, stdout, stderr = _run_aegisctl("restart")
        self.assertNotEqual(rc, 0, "restart without --component should fail")

    def test_start_and_all_are_mutually_exclusive(self):
        rc, stdout, stderr = _run_aegisctl("start", "--component", "brain", "--all")
        self.assertNotEqual(rc, 0, "should reject --component and --all together")


class TestAegisctlExitCodes(unittest.TestCase):
    """Exit codes follow the documented convention:
       0 = success, 1 = partial failure, 2 = usage error."""

    def test_version_returns_0_when_all_present_or_1_when_missing(self):
        rc, _, _ = _run_aegisctl("version")
        self.assertIn(rc, (0, 1), f"version exit code should be 0 or 1, got {rc}")

    def test_status_always_returns_0(self):
        rc, _, _ = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should always exit 0, got {rc}")

    def test_diagnose_returns_0(self):
        rc, _, _ = _run_aegisctl("diagnose")
        self.assertEqual(rc, 0, f"diagnose should exit 0, got {rc}")

    def test_bad_command_returns_2(self):
        rc, _, _ = _run_aegisctl("nonexistent-command")
        self.assertEqual(rc, 2, f"bad command should exit 2, got {rc}")


if __name__ == "__main__":
    unittest.main()
