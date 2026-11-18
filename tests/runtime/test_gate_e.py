"""Gate E control-plane contract tests.

Production policy, simulation, and enforcement mutations must not
write local state or claim host effect. They return a structured UNAVAILABLE
response until the daemon-owned provider/receipt path is connected.
Canary run/status/report are the exception: they are implemented
read-only commands (GATE-E-028, CANARY-QUAR-056) pinned here to stay
mutation-free and host-effect-free.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "tools" / "aegisctl.py"
CANARY_TESTS_FILE = REPO_ROOT / "configs" / "canary_tests.json"
DISABLED_RULES_FILE = REPO_ROOT / "configs" / "disabled_rules.json"
RULES_FILE = REPO_ROOT / "config" / "Rules.json"


def _run_aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    result = subprocess.run(
        [sys.executable, str(AEGISCTL), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


def _assert_unavailable(test: unittest.TestCase, args: tuple[str, ...]) -> None:
    rc, _stdout, stderr = _run_aegisctl(*args)
    test.assertEqual(rc, 4)
    payload = json.loads(stderr)
    test.assertFalse(payload["available"])
    test.assertTrue(payload["reason"])


class TestPolicyCommands(unittest.TestCase):
    def setUp(self) -> None:
        if not RULES_FILE.exists():
            self.skipTest("configs/Rules.json not found")
        DISABLED_RULES_FILE.unlink(missing_ok=True)

    def tearDown(self) -> None:
        DISABLED_RULES_FILE.unlink(missing_ok=True)

    def test_policy_list_is_read_only(self) -> None:
        rc, stdout, _ = _run_aegisctl("policy", "list")
        self.assertEqual(rc, 0)
        self.assertIn("Rule ID", stdout)
        self.assertIn("State", stdout)
        self.assertIn("Total:", stdout)

    def test_policy_show_existing_rule_is_read_only(self) -> None:
        rc, stdout, _ = _run_aegisctl("policy", "show", "--id", "R0056")
        self.assertEqual(rc, 0)
        parsed = json.loads(stdout)
        self.assertEqual(parsed["rule_id"], "R0056")
        self.assertIn("state", parsed)

    def test_policy_show_nonexistent_rule(self) -> None:
        rc, stdout, _ = _run_aegisctl("policy", "show", "--id", "NONEXISTENT")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())

    def test_policy_enable_disable_are_fail_closed(self) -> None:
        for action in ("enable", "disable"):
            with self.subTest(action=action):
                _assert_unavailable(self, ("policy", action, "--id", "R0056"))
        self.assertFalse(DISABLED_RULES_FILE.exists())

    def test_policy_reload_requires_daemon(self) -> None:
        rc, stdout, stderr = _run_aegisctl("policy", "reload")
        if rc == 0:
            self.assertIn("reloaded", stdout.lower())
        else:
            self.assertTrue(stdout or stderr)


class TestSimulationAndCanaryCommands(unittest.TestCase):
    def test_simulation_mutations_are_fail_closed(self) -> None:
        commands = (
            ("simulate", "attack", "--type", "SQL_INJECTION"),
            ("simulate", "packet", "--src-ip", "10.0.0.5", "--dst-port", "3306", "--payload", "fixture"),
            ("simulate", "flood", "--count", "1", "--rate", "1"),
            ("simulate", "replay", "--file", "fixture.ndjson"),
        )
        for command in commands:
            with self.subTest(command=command):
                _assert_unavailable(self, command)

    def test_canary_commands_are_read_only(self) -> None:
        if not CANARY_TESTS_FILE.exists():
            self.skipTest("configs/canary_tests.json not found")
        before = {
            p.name: (p.read_bytes() if p.exists() else None)
            for p in (REPO_ROOT / "logs" / "blocked_ips.json",
                      REPO_ROOT / "logs" / "quarantine.json")
        }
        # status: always available, read-only.
        rc, stdout, _ = _run_aegisctl("canary", "status")
        self.assertEqual(rc, 0)
        status = json.loads(stdout)
        self.assertTrue(status["available"])
        # run: 0 = all graded pass (quarantined reported, never graded),
        # 1 = a graded canary failed. Never a mutation, never a host effect.
        rc, stdout, _ = _run_aegisctl("canary", "run")
        self.assertIn(rc, (0, 1))
        result = json.loads(stdout)
        self.assertTrue(result["available"])
        self.assertNotIn("ENFORCED", stdout)
        # report: 0 = last receipt shown, 3 = no runs yet. Read-only either way.
        rc, _, _ = _run_aegisctl("canary", "report")
        self.assertIn(rc, (0, 3))
        after = {
            p.name: (p.read_bytes() if p.exists() else None)
            for p in (REPO_ROOT / "logs" / "blocked_ips.json",
                      REPO_ROOT / "logs" / "quarantine.json")
        }
        self.assertEqual(before, after, "canary must not touch enforcement bookkeeping")


class TestCanaryTestsFile(unittest.TestCase):
    def test_canary_tests_file_is_valid_and_complete(self) -> None:
        self.assertTrue(CANARY_TESTS_FILE.exists())
        data = json.loads(CANARY_TESTS_FILE.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.assertIsInstance(data.get("tests"), list)
        self.assertEqual(len(data["tests"]), 10)
        required = ("name", "description", "category", "expected_severity", "expected_rule_id", "expected_tier", "event")
        names = []
        for item in data["tests"]:
            names.append(item["name"])
            for field in required:
                self.assertIn(field, item)
            self.assertIn("attack_type", item.get("event", {}))
        self.assertEqual(len(names), len(set(names)))


class TestGateEHelpCommands(unittest.TestCase):
    def test_help_surfaces(self) -> None:
        for command in ("policy", "simulate", "canary"):
            with self.subTest(command=command):
                rc, stdout, _ = _run_aegisctl(command, "--help")
                self.assertEqual(rc, 0)
                self.assertTrue(stdout)


if __name__ == "__main__":
    unittest.main()
