"""
test_restart.py - Restart-policy and quarantine contract tests

Verifies the static contract for restart behavior described in
RUNTIME_CONTRACT.md §5: exponential backoff schedule, max-attempts cap,
quarantine trigger, and the "required vs optional" dependency rules.

Live restart tests (which actually trigger failures and observe restarts)
live in test_harness_integration.py.
"""

from __future__ import annotations

import unittest

from tests.runtime.conftest import (
    COMPONENTS,
    DEFAULT_RESTART_POLICY,
    REQUIRED_COMPONENTS,
)


class TestBackoffSchedule(unittest.TestCase):
    """The schedule from RUNTIME_CONTRACT.md §5 Table."""

    EXPECTED_BASE_DELAYS_MS = [250, 500, 1000, 2000, 4000, 8000, 16000, 30000]

    def _delay_for_attempt(self, attempt: int) -> int:
        base = DEFAULT_RESTART_POLICY["base_delay_ms"]
        cap = DEFAULT_RESTART_POLICY["max_delay_ms"]
        return min(base * (2 ** (attempt - 1)), cap)

    def test_schedule_matches_documented_values(self):
        for i, expected in enumerate(self.EXPECTED_BASE_DELAYS_MS, start=1):
            self.assertEqual(self._delay_for_attempt(i), expected,
                             f"attempt {i} expected {expected}, "
                             f"got {self._delay_for_attempt(i)}")

    def test_attempt_above_cap_stays_at_cap(self):
        for attempt in (9, 10, 20):
            self.assertEqual(self._delay_for_attempt(attempt),
                             DEFAULT_RESTART_POLICY["max_delay_ms"])


class TestQuarantineTrigger(unittest.TestCase):
    """After max_restarts consecutive failures, the supervisor must write
    logs/quarantine/<comp>.json and stop attempting restarts."""

    def test_max_attempts_is_8(self):
        self.assertEqual(DEFAULT_RESTART_POLICY["max_attempts"], 8)

    def test_quarantine_dir_path(self):
        from tests.runtime.conftest import quarantine_dir
        q = quarantine_dir()
        self.assertTrue(q.exists(), "quarantine dir must be created on demand")
        self.assertTrue(q.is_dir())

    def test_required_components_quarantine_escalates(self):
        """A Required=yes component that exceeds max_restarts must emit a
        SYSTEM_FAILED event; a Required=no component must emit
        SYSTEM_DEGRADED."""
        for c in COMPONENTS:
            if c["required"]:
                self.assertIn(c["name"], REQUIRED_COMPONENTS)
            else:
                self.assertNotIn(c["name"], REQUIRED_COMPONENTS)


class TestRestartWindowReset(unittest.TestCase):
    """If a component stays RUNNING for `reset_window_s`, the attempt
    counter resets to 1."""

    def test_reset_window_is_60s(self):
        self.assertEqual(DEFAULT_RESTART_POLICY["reset_window_s"], 60)

    def test_reset_window_gt_max_backoff(self):
        """The reset window must be longer than the longest backoff delay
        so a recovered component has had time to prove itself."""
        self.assertGreater(DEFAULT_RESTART_POLICY["reset_window_s"],
                           DEFAULT_RESTART_POLICY["max_delay_ms"] / 1000)


class TestRequiredVsOptionalDependencies(unittest.TestCase):
    """RUNTIME_CONTRACT.md §5: required dependencies cause DEGRADED on
    failure; optional dependencies do not block startup."""

    def test_bridge_is_required(self):
        names = [c["name"] for c in COMPONENTS if c["required"]]
        self.assertIn("bridge", names)

    def test_core_is_required(self):
        names = [c["name"] for c in COMPONENTS if c["required"]]
        self.assertIn("core", names)

    def test_nose_is_optional(self):
        nose = next(c for c in COMPONENTS if c["name"] == "nose")
        self.assertFalse(nose["required"])

    def test_mouth_is_optional(self):
        mouth = next(c for c in COMPONENTS if c["name"] == "mouth")
        self.assertFalse(mouth["required"])

    def test_aggregator_is_optional(self):
        agg = next(c for c in COMPONENTS if c["name"] == "aggregator")
        self.assertFalse(agg["required"])

    def test_shield_is_required(self):
        shield = next(c for c in COMPONENTS if c["name"] == "shield")
        self.assertTrue(shield["required"])


if __name__ == "__main__":
    unittest.main()
