"""
test_timeouts.py - Timeout budget tests

Verifies that the timeout budget table in RUNTIME_CONTRACT.md §3 is
internally consistent and that no component declares a timeout that
exceeds its hard ceiling.

These tests do NOT run live processes; they validate the static contract.
Live timing tests (which measure actual startup/shutdown latency) live
in test_harness_integration.py and are gated on platform availability.
"""

from __future__ import annotations

import unittest

from tests.runtime.conftest import DEFAULT_TIMEOUTS_MS, DEFAULT_RESTART_POLICY


class TestTimeoutBudgets(unittest.TestCase):
    """Mirror the timeout table from RUNTIME_CONTRACT.md §3 and verify
    the invariants."""

    def test_timeout_table_has_expected_keys(self):
        expected = {
            "startup", "ready", "health", "probe",
            "degrade", "shutdown", "grim_reap",
        }
        self.assertEqual(set(DEFAULT_TIMEOUTS_MS.keys()), expected)

    def test_startup_default_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["startup"], 30_000)

    def test_ready_default_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["ready"], 10_000)

    def test_health_interval_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["health"], 5_000)

    def test_probe_timeout_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["probe"], 2_000)

    def test_degrade_window_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["degrade"], 30_000)

    def test_shutdown_timeout_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["shutdown"], 15_000)

    def test_grim_reap_within_hard_ceiling(self):
        self.assertLessEqual(DEFAULT_TIMEOUTS_MS["grim_reap"], 10_000)


class TestTimeoutInvariants(unittest.TestCase):
    """Cross-field invariants that must hold for the table to be coherent."""

    def test_ready_lt_startup(self):
        """A component should not linger in READY longer than its whole
        startup budget. READY is transient (LIFECYCLE.md §2)."""
        self.assertLess(DEFAULT_TIMEOUTS_MS["ready"],
                        DEFAULT_TIMEOUTS_MS["startup"])

    def test_probe_lt_health_interval(self):
        """A probe must time out well before the next health cycle begins,
        otherwise probes pile up."""
        self.assertLess(DEFAULT_TIMEOUTS_MS["probe"],
                        DEFAULT_TIMEOUTS_MS["health"])

    def test_degrade_ge_recovery_k_times_health(self):
        """Per RUNTIME_CONTRACT.md §3 note: the degrade window MUST be at
        least k * health_interval so a component has a fair chance to
        recover."""
        recovery_k = DEFAULT_RESTART_POLICY["recovery_k"]
        self.assertGreaterEqual(
            DEFAULT_TIMEOUTS_MS["degrade"],
            recovery_k * DEFAULT_TIMEOUTS_MS["health"],
        )

    def test_shutdown_lt_grim_reap_x_5(self):
        """A shutdown that takes longer than 5x the grim-reap budget is a
        strong signal of a wedged component."""
        self.assertLess(DEFAULT_TIMEOUTS_MS["shutdown"],
                        5 * DEFAULT_TIMEOUTS_MS["grim_reap"])

    def test_startup_gt_2x_probe(self):
        """Startup must be long enough for at least two health probes to
        have run during the startup window."""
        self.assertGreater(DEFAULT_TIMEOUTS_MS["startup"],
                           2 * DEFAULT_TIMEOUTS_MS["probe"])


class TestRestartPolicyInvariants(unittest.TestCase):
    """Invariants on the restart policy table."""

    def test_max_attempts_is_positive(self):
        self.assertGreater(DEFAULT_RESTART_POLICY["max_attempts"], 0)

    def test_max_attempts_is_bounded(self):
        # 8 is the documented cap; a value > 16 would suggest a mis-tuned
        # policy that hides a real failure.
        self.assertLessEqual(DEFAULT_RESTART_POLICY["max_attempts"], 16)

    def test_base_delay_lt_max_delay(self):
        self.assertLess(DEFAULT_RESTART_POLICY["base_delay_ms"],
                        DEFAULT_RESTART_POLICY["max_delay_ms"])

    def test_recovery_k_is_positive(self):
        self.assertGreater(DEFAULT_RESTART_POLICY["recovery_k"], 0)

    def test_reset_window_is_long_enough(self):
        # 60 s documented; a value < 30 would cause flapping.
        self.assertGreaterEqual(DEFAULT_RESTART_POLICY["reset_window_s"], 30)


class TestExpectedBackoffSchedule(unittest.TestCase):
    """Verify the exponential-backoff schedule described in
    RUNTIME_CONTRACT.md §5 is correctly reproduced by the formula."""

    def _expected_delay(self, attempt: int) -> int:
        base = DEFAULT_RESTART_POLICY["base_delay_ms"]
        cap = DEFAULT_RESTART_POLICY["max_delay_ms"]
        # 250, 500, 1000, 2000, 4000, 8000, 16000, 30000(cap) ...
        delay = base * (2 ** (attempt - 1))
        return min(delay, cap)

    def test_attempt_1_is_base_delay(self):
        self.assertEqual(self._expected_delay(1), 250)

    def test_attempt_3_is_one_second(self):
        self.assertEqual(self._expected_delay(3), 1000)

    def test_attempt_5_is_four_seconds(self):
        self.assertEqual(self._expected_delay(5), 4000)

    def test_attempt_8_hits_cap(self):
        self.assertEqual(self._expected_delay(8),
                         DEFAULT_RESTART_POLICY["max_delay_ms"])

    def test_attempt_12_stays_at_cap(self):
        self.assertEqual(self._expected_delay(12),
                         DEFAULT_RESTART_POLICY["max_delay_ms"])


if __name__ == "__main__":
    unittest.main()
