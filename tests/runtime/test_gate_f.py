"""Gate F control-plane contract tests.

Read-only status/list commands remain usable. Privileged block, quarantine,
and enforcement mutations must return structured UNAVAILABLE until the
provider-owned receipt path is connected; they must not edit local JSON state.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "tools" / "aegisctl.py"
BLOCK_LIST_FILE = REPO_ROOT / "logs" / "blocked_ips.json"
QUARANTINE_FILE = REPO_ROOT / "logs" / "quarantine.json"
PEP_STATE_FILE = REPO_ROOT / "logs" / "runtime" / "pep_state.json"


def _run_aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    result = subprocess.run(
        [sys.executable, str(AEGISCTL), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


def _cleanup_state_files() -> None:
    for path in (BLOCK_LIST_FILE, QUARANTINE_FILE, PEP_STATE_FILE):
        path.unlink(missing_ok=True)


def _assert_unavailable(test: unittest.TestCase, *args: str) -> None:
    rc, _stdout, stderr = _run_aegisctl(*args)
    test.assertEqual(rc, 4)
    payload = json.loads(stderr)
    test.assertFalse(payload["available"])
    test.assertTrue(payload["reason"])


class TestReadOnlyCommands(unittest.TestCase):
    def setUp(self) -> None:
        _cleanup_state_files()

    def tearDown(self) -> None:
        _cleanup_state_files()

    def test_block_list_empty(self) -> None:
        rc, stdout, _ = _run_aegisctl("block", "list")
        self.assertEqual(rc, 0)
        self.assertIn("No IPs", stdout)

    def test_quarantine_list_empty(self) -> None:
        rc, stdout, _ = _run_aegisctl("quarantine", "list")
        self.assertEqual(rc, 0)
        self.assertIn("No IPs", stdout)

    def test_enforce_status_is_read_only(self) -> None:
        rc, stdout, _ = _run_aegisctl("enforce", "status")
        self.assertEqual(rc, 0)
        self.assertIn("PEP", stdout)
        self.assertIn("Mode:", stdout)


class TestPrivilegedMutationsFailClosed(unittest.TestCase):
    def setUp(self) -> None:
        _cleanup_state_files()

    def tearDown(self) -> None:
        _cleanup_state_files()

    def test_block_mutations_do_not_write_bookkeeping(self) -> None:
        commands = (
            ("block", "add", "--ip", "1.2.3.4"),
            ("block", "remove", "--ip", "1.2.3.4"),
            ("block", "clear"),
        )
        for command in commands:
            with self.subTest(command=command):
                _assert_unavailable(self, *command)
        self.assertFalse(BLOCK_LIST_FILE.exists())

    def test_quarantine_mutations_do_not_write_bookkeeping(self) -> None:
        for command in (
            ("quarantine", "add", "--ip", "1.2.3.4"),
            ("quarantine", "remove", "--ip", "1.2.3.4"),
        ):
            with self.subTest(command=command):
                _assert_unavailable(self, *command)
        self.assertFalse(QUARANTINE_FILE.exists())
        self.assertFalse(BLOCK_LIST_FILE.exists())

    def test_enforcement_mutations_do_not_write_pep_state(self) -> None:
        for command in (("enforce", "enable"), ("enforce", "disable")):
            with self.subTest(command=command):
                _assert_unavailable(self, *command)
        self.assertFalse(PEP_STATE_FILE.exists())

    def test_policy_push_is_not_a_local_file_mutation(self) -> None:
        _assert_unavailable(self, "enforce", "push", "--policy", "missing.json")


if __name__ == "__main__":
    unittest.main()
