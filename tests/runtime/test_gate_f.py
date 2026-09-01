"""
test_gate_f.py - Tests for Gate F enforcement commands (block/enforce/quarantine).

Verifies that the aegisctl enforcement commands work correctly:
  - block add/remove/list/clear
  - enforce status/enable/disable/push
  - quarantine add/remove/list

These tests verify the CLI plumbing and file-based state management.
They do NOT require running components.
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
BLOCK_LIST_FILE = REPO_ROOT / "logs" / "blocked_ips.json"
QUARANTINE_FILE = REPO_ROOT / "logs" / "quarantine.json"
PEP_STATE_FILE = REPO_ROOT / "logs" / "runtime" / "pep_state.json"
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


def _cleanup_state_files():
    """Remove state files between tests."""
    for f in (BLOCK_LIST_FILE, QUARANTINE_FILE, PEP_STATE_FILE):
        if f.exists():
            try:
                f.unlink()
            except OSError:
                pass


class TestBlockCommands(unittest.TestCase):
    """Tests for 'aegisctl block add/remove/list/clear'."""

    def setUp(self):
        _cleanup_state_files()

    def tearDown(self):
        _cleanup_state_files()

    def test_block_add_creates_entry(self):
        rc, stdout, _ = _run_aegisctl("block", "add", "--ip", "1.2.3.4",
                                       "--reason", "Test block")
        self.assertEqual(rc, 0)
        self.assertIn("BLOCKED", stdout)
        self.assertTrue(BLOCK_LIST_FILE.exists())
        data = json.loads(BLOCK_LIST_FILE.read_text())
        self.assertEqual(len(data["blocked_ips"]), 1)
        self.assertEqual(data["blocked_ips"][0]["ip"], "1.2.3.4")

    def test_block_add_with_duration(self):
        rc, stdout, _ = _run_aegisctl("block", "add", "--ip", "1.2.3.4",
                                       "--duration", "3600", "--reason", "1hr block")
        self.assertEqual(rc, 0)
        self.assertIn("3600s", stdout)

    def test_block_add_already_blocked(self):
        _run_aegisctl("block", "add", "--ip", "1.2.3.4", "--reason", "First block")
        rc, stdout, _ = _run_aegisctl("block", "add", "--ip", "1.2.3.4", "--reason", "Second")
        self.assertEqual(rc, 0)
        self.assertIn("already BLOCKED", stdout)

    def test_block_remove(self):
        _run_aegisctl("block", "add", "--ip", "1.2.3.4", "--reason", "Test")
        rc, stdout, _ = _run_aegisctl("block", "remove", "--ip", "1.2.3.4")
        self.assertEqual(rc, 0)
        self.assertIn("UNBLOCKED", stdout)
        data = json.loads(BLOCK_LIST_FILE.read_text())
        self.assertEqual(len(data["blocked_ips"]), 0)

    def test_block_remove_not_blocked(self):
        rc, stdout, _ = _run_aegisctl("block", "remove", "--ip", "9.9.9.9")
        self.assertEqual(rc, 0)
        self.assertIn("NOT in the block list", stdout)

    def test_block_list_empty(self):
        rc, stdout, _ = _run_aegisctl("block", "list")
        self.assertEqual(rc, 0)
        self.assertIn("No IPs", stdout)

    def test_block_list_with_entries(self):
        _run_aegisctl("block", "add", "--ip", "1.2.3.4", "--reason", "Test 1")
        _run_aegisctl("block", "add", "--ip", "5.6.7.8", "--reason", "Test 2")
        rc, stdout, _ = _run_aegisctl("block", "list")
        self.assertEqual(rc, 0)
        self.assertIn("1.2.3.4", stdout)
        self.assertIn("5.6.7.8", stdout)
        self.assertIn("Total: 2", stdout)

    def test_block_clear(self):
        _run_aegisctl("block", "add", "--ip", "1.2.3.4", "--reason", "Test")
        _run_aegisctl("block", "add", "--ip", "5.6.7.8", "--reason", "Test")
        rc, stdout, _ = _run_aegisctl("block", "clear")
        self.assertEqual(rc, 0)
        self.assertIn("Cleared 2", stdout)
        data = json.loads(BLOCK_LIST_FILE.read_text())
        self.assertEqual(len(data["blocked_ips"]), 0)

    def test_block_clear_empty(self):
        rc, stdout, _ = _run_aegisctl("block", "clear")
        self.assertEqual(rc, 0)
        self.assertIn("already empty", stdout)


class TestEnforceCommands(unittest.TestCase):
    """Tests for 'aegisctl enforce status/enable/disable/push'."""

    def setUp(self):
        _cleanup_state_files()

    def tearDown(self):
        _cleanup_state_files()

    def test_enforce_status_default(self):
        rc, stdout, _ = _run_aegisctl("enforce", "status")
        self.assertEqual(rc, 0)
        self.assertIn("PEP", stdout)
        self.assertIn("Enabled:", stdout)
        self.assertIn("Mode:", stdout)

    def test_enforce_disable_then_enable(self):
        # Default is enabled, so disable first
        rc, stdout, _ = _run_aegisctl("enforce", "disable")
        self.assertEqual(rc, 0)
        self.assertIn("DISABLED", stdout)

        # Verify state was saved
        state = json.loads(PEP_STATE_FILE.read_text())
        self.assertFalse(state["enabled"])

        # Now enable
        rc, stdout, _ = _run_aegisctl("enforce", "enable")
        self.assertEqual(rc, 0)
        self.assertIn("ENABLED", stdout)

        state = json.loads(PEP_STATE_FILE.read_text())
        self.assertTrue(state["enabled"])

    def test_enforce_enable_already_enabled(self):
        rc, stdout, _ = _run_aegisctl("enforce", "enable")
        self.assertEqual(rc, 0)
        self.assertIn("already ENABLED", stdout)

    def test_enforce_disable_already_disabled(self):
        _run_aegisctl("enforce", "disable")
        rc, stdout, _ = _run_aegisctl("enforce", "disable")
        self.assertEqual(rc, 0)
        self.assertIn("already DISABLED", stdout)

    def test_enforce_push_valid_policy(self):
        # Create a temporary policy file
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                          encoding="utf-8")
        json.dump({"nids_rules": [{"rule_id": "TEST1", "name": "Test Rule",
                                     "severity": "High", "action": "Alert"}]}, tmp)
        tmp.close()
        try:
            # Backup original Rules.json
            backup = RULES_FILE.read_bytes() if RULES_FILE.exists() else None
            try:
                rc, stdout, _ = _run_aegisctl("enforce", "push", "--policy", tmp.name)
                self.assertEqual(rc, 0)
                self.assertIn("Policy pushed", stdout)
                self.assertIn("Rules: 1", stdout)
                # Verify Rules.json was updated
                data = json.loads(RULES_FILE.read_text())
                self.assertEqual(len(data["nids_rules"]), 1)
            finally:
                # Restore original Rules.json
                if backup is not None:
                    RULES_FILE.write_bytes(backup)
        finally:
            os.unlink(tmp.name)

    def test_enforce_push_missing_file(self):
        rc, stdout, _ = _run_aegisctl("enforce", "push", "--policy", "/nonexistent/policy.json")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())

    def test_enforce_push_invalid_json(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                          encoding="utf-8")
        tmp.write("{invalid json")
        tmp.close()
        try:
            rc, stdout, _ = _run_aegisctl("enforce", "push", "--policy", tmp.name)
            self.assertEqual(rc, 1)
            self.assertIn("invalid json", stdout.lower())
        finally:
            os.unlink(tmp.name)


class TestQuarantineCommands(unittest.TestCase):
    """Tests for 'aegisctl quarantine add/remove/list'."""

    def setUp(self):
        _cleanup_state_files()

    def tearDown(self):
        _cleanup_state_files()

    def test_quarantine_add(self):
        rc, stdout, _ = _run_aegisctl("quarantine", "add", "--ip", "10.0.0.99",
                                       "--reason", "Test quarantine")
        self.assertEqual(rc, 0)
        self.assertIn("QUARANTINED", stdout)
        self.assertTrue(QUARANTINE_FILE.exists())
        self.assertTrue(BLOCK_LIST_FILE.exists())

        # Verify quarantine entry
        q_data = json.loads(QUARANTINE_FILE.read_text())
        self.assertEqual(len(q_data["quarantined_ips"]), 1)
        self.assertEqual(q_data["quarantined_ips"][0]["ip"], "10.0.0.99")

        # Verify block list also has the entry
        b_data = json.loads(BLOCK_LIST_FILE.read_text())
        self.assertEqual(len(b_data["blocked_ips"]), 1)
        self.assertIn("QUARANTINE", b_data["blocked_ips"][0]["reason"])

    def test_quarantine_add_already_quarantined(self):
        _run_aegisctl("quarantine", "add", "--ip", "10.0.0.99", "--reason", "First")
        rc, stdout, _ = _run_aegisctl("quarantine", "add", "--ip", "10.0.0.99", "--reason", "Second")
        self.assertEqual(rc, 0)
        self.assertIn("already QUARANTINED", stdout)

    def test_quarantine_remove(self):
        _run_aegisctl("quarantine", "add", "--ip", "10.0.0.99", "--reason", "Test")
        rc, stdout, _ = _run_aegisctl("quarantine", "remove", "--ip", "10.0.0.99")
        self.assertEqual(rc, 0)
        self.assertIn("removed from quarantine", stdout)

        # Verify both lists are empty
        q_data = json.loads(QUARANTINE_FILE.read_text())
        self.assertEqual(len(q_data["quarantined_ips"]), 0)
        b_data = json.loads(BLOCK_LIST_FILE.read_text())
        self.assertEqual(len(b_data["blocked_ips"]), 0)

    def test_quarantine_remove_not_quarantined(self):
        rc, stdout, _ = _run_aegisctl("quarantine", "remove", "--ip", "9.9.9.9")
        self.assertEqual(rc, 0)
        self.assertIn("NOT in the quarantine", stdout)

    def test_quarantine_list_empty(self):
        rc, stdout, _ = _run_aegisctl("quarantine", "list")
        self.assertEqual(rc, 0)
        self.assertIn("No IPs", stdout)

    def test_quarantine_list_with_entries(self):
        _run_aegisctl("quarantine", "add", "--ip", "10.0.0.99", "--reason", "Test 1")
        _run_aegisctl("quarantine", "add", "--ip", "10.0.0.100", "--reason", "Test 2")
        rc, stdout, _ = _run_aegisctl("quarantine", "list")
        self.assertEqual(rc, 0)
        self.assertIn("10.0.0.99", stdout)
        self.assertIn("10.0.0.100", stdout)
        self.assertIn("Total: 2", stdout)


class TestGateFHelpCommands(unittest.TestCase):
    """Verify the --help for all Gate F subcommands works."""

    def test_block_help(self):
        rc, stdout, _ = _run_aegisctl("block", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("add", "remove", "list", "clear"):
            self.assertIn(cmd, stdout)

    def test_enforce_help(self):
        rc, stdout, _ = _run_aegisctl("enforce", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("status", "enable", "disable", "push"):
            self.assertIn(cmd, stdout)

    def test_quarantine_help(self):
        rc, stdout, _ = _run_aegisctl("quarantine", "--help")
        self.assertEqual(rc, 0)
        for cmd in ("add", "remove", "list"):
            self.assertIn(cmd, stdout)


class TestGateFExitCodes(unittest.TestCase):
    """Verify exit codes follow the documented convention."""

    def setUp(self):
        _cleanup_state_files()

    def tearDown(self):
        _cleanup_state_files()

    def test_block_add_returns_0(self):
        rc, _, _ = _run_aegisctl("block", "add", "--ip", "1.2.3.4")
        self.assertEqual(rc, 0)

    def test_block_list_returns_0(self):
        rc, _, _ = _run_aegisctl("block", "list")
        self.assertEqual(rc, 0)

    def test_enforce_status_returns_0(self):
        rc, _, _ = _run_aegisctl("enforce", "status")
        self.assertEqual(rc, 0)

    def test_quarantine_list_returns_0(self):
        rc, _, _ = _run_aegisctl("quarantine", "list")
        self.assertEqual(rc, 0)

    def test_block_add_without_ip_returns_2(self):
        rc, _, _ = _run_aegisctl("block", "add")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
