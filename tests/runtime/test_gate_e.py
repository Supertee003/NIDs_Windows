"""
test_gate_e.py - Tests for Gate E commands (policy/simulate/canary).

Verifies that the aegisctl policy/simulate/canary commands work correctly.
These are mostly static tests that verify the CLI plumbing; the live
canary/simulate tests require running components.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "scripts" / "aegisctl.py"
CANARY_TESTS_FILE = REPO_ROOT / "config" / "canary_tests.json"
DISABLED_RULES_FILE = REPO_ROOT / "config" / "disabled_rules.json"
RULES_FILE = REPO_ROOT / "config" / "Rules.json"


def _run_aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    cmd = [sys.executable, str(AEGISCTL)] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT),
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"


class TestPolicyCommands(unittest.TestCase):
    """Tests for 'aegisctl policy list/show/reload/enable/disable'."""

    def setUp(self):
        if not RULES_FILE.exists():
            self.skipTest("config/Rules.json not found")
        # Clean up any disabled_rules.json from previous test runs
        if DISABLED_RULES_FILE.exists():
            DISABLED_RULES_FILE.unlink()

    def tearDown(self):
        # Clean up disabled_rules.json after each test
        if DISABLED_RULES_FILE.exists():
            DISABLED_RULES_FILE.unlink()

    def test_policy_list_shows_all_rules(self):
        rc, stdout, _ = _run_aegisctl("policy", "list")
        self.assertEqual(rc, 0)
        self.assertIn("Rule ID", stdout)
        self.assertIn("State", stdout)
        self.assertIn("ENABLED", stdout)
        self.assertIn("Total:", stdout)

    def test_policy_show_existing_rule(self):
        rc, stdout, _ = _run_aegisctl("policy", "show", "--id", "R0056")
        self.assertEqual(rc, 0)
        parsed = json.loads(stdout)
        self.assertEqual(parsed["rule_id"], "R0056")
        self.assertIn("state", parsed)
        self.assertEqual(parsed["state"], "ENABLED")

    def test_policy_show_nonexistent_rule(self):
        rc, stdout, _ = _run_aegisctl("policy", "show", "--id", "NONEXISTENT")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())

    def test_policy_disable_then_enable(self):
        # Disable R0056
        rc, stdout, _ = _run_aegisctl("policy", "disable", "--id", "R0056")
        self.assertEqual(rc, 0)
        self.assertIn("DISABLED", stdout)
        # Verify disabled_rules.json was created
        self.assertTrue(DISABLED_RULES_FILE.exists())
        data = json.loads(DISABLED_RULES_FILE.read_text())
        self.assertIn("R0056", data["disabled_rules"])

        # Verify policy list shows it as DISABLED
        rc, stdout, _ = _run_aegisctl("policy", "list")
        self.assertIn("DISABLED", stdout)

        # Re-enable R0056
        rc, stdout, _ = _run_aegisctl("policy", "enable", "--id", "R0056")
        self.assertEqual(rc, 0)
        self.assertIn("ENABLED", stdout)
        # Verify it's removed from disabled list
        data = json.loads(DISABLED_RULES_FILE.read_text())
        self.assertNotIn("R0056", data["disabled_rules"])

    def test_policy_disable_nonexistent_rule(self):
        rc, stdout, _ = _run_aegisctl("policy", "disable", "--id", "ZZZZZ")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())

    def test_policy_enable_already_enabled(self):
        rc, stdout, _ = _run_aegisctl("policy", "enable", "--id", "R0056")
        self.assertEqual(rc, 0)
        self.assertIn("already ENABLED", stdout)

    def test_policy_reload_without_core_running(self):
        rc, stdout, _ = _run_aegisctl("policy", "reload")
        # Should fail gracefully if core is not running
        self.assertNotEqual(rc, 0)
        self.assertTrue(
            "not running" in stdout or "ERROR" in stdout,
            f"expected error about core not running, got: {stdout}"
        )


class TestSimulateCommands(unittest.TestCase):
    """Tests for 'aegisctl simulate attack/packet/flood/replay'."""

    def test_simulate_attack_unknown_type(self):
        rc, stdout, _ = _run_aegisctl("simulate", "attack", "--type", "UNKNOWN")
        self.assertEqual(rc, 2)
        self.assertIn("unknown attack type", stdout.lower())
        self.assertIn("SQL_INJECTION", stdout)  # lists available types

    def test_simulate_attack_sends_event(self):
        # This will try to send via UDP to 127.0.0.1:9999
        # It will fail if brain is not running, but the command should
        # still produce output indicating the attempt.
        rc, stdout, _ = _run_aegisctl("simulate", "attack", "--type", "SQL_INJECTION")
        # rc is 0 if sent successfully, 1 if brain not running
        self.assertIn(rc, (0, 1))
        self.assertIn("SQL_INJECTION", stdout)
        self.assertIn("Event:", stdout)

    def test_simulate_packet_sends_event(self):
        rc, stdout, _ = _run_aegisctl(
            "simulate", "packet", "--src-ip", "10.0.0.5",
            "--dst-port", "3306", "--payload", "SELECT * FROM users"
        )
        self.assertIn(rc, (0, 1))
        self.assertIn("Sending custom packet", stdout)

    def test_simulate_flood_runs(self):
        # Use a small count + high rate so it completes quickly
        rc, stdout, _ = _run_aegisctl(
            "simulate", "flood", "--count", "5", "--rate", "100"
        )
        self.assertIn(rc, (0, 1))
        self.assertIn("Flood", stdout)
        self.assertIn("5", stdout)

    def test_simulate_replay_missing_file(self):
        rc, stdout, _ = _run_aegisctl("simulate", "replay", "--file", "/nonexistent/path.ndjson")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())


class TestCanaryCommands(unittest.TestCase):
    """Tests for 'aegisctl canary run/status/report'."""

    def setUp(self):
        if not CANARY_TESTS_FILE.exists():
            self.skipTest("config/canary_tests.json not found")

    def test_canary_run_all_tests(self):
        # Run all 10 canary tests. They will try to send via UDP.
        rc, stdout, _ = _run_aegisctl("canary", "run", timeout=30)
        # rc is 0 if all sent, 1 if some failed
        self.assertIn(rc, (0, 1))
        self.assertIn("Canary Test Runner", stdout)
        self.assertIn("Tests to run: 10", stdout)
        self.assertIn("sqli_bypass", stdout)

    def test_canary_run_specific_test(self):
        rc, stdout, _ = _run_aegisctl("canary", "run", "--test", "sqli_bypass", timeout=10)
        self.assertIn(rc, (0, 1))
        self.assertIn("sqli_bypass", stdout)
        self.assertIn("Tests to run: 1", stdout)

    def test_canary_run_nonexistent_test(self):
        rc, stdout, _ = _run_aegisctl("canary", "run", "--test", "nonexistent_test", timeout=10)
        self.assertEqual(rc, 2)
        self.assertIn("not found", stdout.lower())

    def test_canary_status_after_run(self):
        # First run the canary tests
        _run_aegisctl("canary", "run", timeout=30)
        # Then check status
        rc, stdout, _ = _run_aegisctl("canary", "status")
        self.assertEqual(rc, 0)
        self.assertIn("Canary Test Status", stdout)
        self.assertIn("Total:", stdout)
        self.assertIn("Sent:", stdout)

    def test_canary_report_after_run(self):
        # First run the canary tests
        _run_aegisctl("canary", "run", timeout=30)
        # Then generate report
        rc, stdout, _ = _run_aegisctl("canary", "report")
        self.assertEqual(rc, 0)
        self.assertIn("Canary Test Report", stdout)
        self.assertIn("Total tests:", stdout)
        self.assertIn("Test Name", stdout)

    def test_canary_status_without_prior_run(self):
        # Clean up any prior results
        results_file = REPO_ROOT / "logs" / "runtime" / "canary_results.json"
        if results_file.exists():
            results_file.unlink()
        rc, stdout, _ = _run_aegisctl("canary", "status")
        self.assertEqual(rc, 0)
        self.assertIn("No canary results", stdout)


class TestCanaryTestsFile(unittest.TestCase):
    """Verify the canary_tests.json structure is valid."""

    def test_canary_tests_file_exists(self):
        self.assertTrue(CANARY_TESTS_FILE.exists(),
                        f"canary_tests.json not found at {CANARY_TESTS_FILE}")

    def test_canary_tests_file_is_valid_json(self):
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.assertIn("tests", data)
        self.assertIsInstance(data["tests"], list)

    def test_canary_tests_count(self):
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(data["tests"]), 10,
                         f"expected 10 canary tests, got {len(data['tests'])}")

    def test_canary_tests_have_required_fields(self):
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        required = ("name", "description", "category", "expected_severity",
                    "expected_rule_id", "expected_tier", "event")
        for test in data["tests"]:
            for field in required:
                self.assertIn(field, test, f"test {test.get('name', '?')} missing {field}")

    def test_canary_test_names_unique(self):
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        names = [t["name"] for t in data["tests"]]
        self.assertEqual(len(names), len(set(names)),
                         f"canary test names should be unique: {names}")

    def test_canary_test_events_have_attack_type(self):
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        for test in data["tests"]:
            event = test.get("event", {})
            self.assertIn("attack_type", event,
                          f"test {test['name']} event missing attack_type")


class TestGateEHelpCommands(unittest.TestCase):
    """Verify the --help for all Gate E subcommands works."""

    def test_policy_help(self):
        rc, stdout, _ = _run_aegisctl("policy", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("list", "show", "reload", "enable", "disable"):
            self.assertIn(cmd, stdout)

    def test_simulate_help(self):
        rc, stdout, _ = _run_aegisctl("simulate", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("attack", "packet", "flood", "replay"):
            self.assertIn(cmd, stdout)

    def test_canary_help(self):
        rc, stdout, _ = _run_aegisctl("canary", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("run", "status", "report"):
            self.assertIn(cmd, stdout)


if __name__ == "__main__":
    unittest.main()
