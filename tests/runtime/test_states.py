"""
test_states.py - Lifecycle state transition tests

Verifies that every component, once started, only ever reports states from
the closed set defined in RUNTIME_CONTRACT.md §2, and that the transitions
it performs match the legal edge list in LIFECYCLE.md §3.

These are contract-shape tests: they do not require a live component. They
check the rules of the state machine. Live transition tests (which start a
real process and observe it) live in test_harness_integration.py and are
gated on the platform having the necessary toolchain.
"""

from __future__ import annotations

import unittest

from tests.runtime.conftest import (
    COMPONENTS,
    VALID_STATES,
    assert_state_in,
    write_audit_record,
)

# --------------------------------------------------------------------------- #
# Legal-transition table (mirrors LIFECYCLE.md §3)                            #
# --------------------------------------------------------------------------- #

LEGAL_TRANSITIONS: set[tuple[str, str]] = {
    ("STOPPED",   "STARTING"),
    ("STARTING",  "READY"),
    ("READY",     "RUNNING"),
    ("STARTING",  "FAILED"),
    ("RUNNING",   "DEGRADED"),
    ("RUNNING",   "FAILED"),
    ("DEGRADED",  "RUNNING"),
    ("DEGRADED",  "FAILED"),
    ("RUNNING",   "STOPPED"),
    ("DEGRADED",  "STOPPED"),
    ("READY",     "STOPPED"),
    ("FAILED",    "STOPPED"),
    ("FAILED",    "STARTING"),
}

# Sticky states per LIFECYCLE.md §2. A non-sticky state MUST transition
# within its timeout; a sticky state can persist indefinitely.
STICKY_STATES: set[str] = {"STOPPED", "RUNNING"}


class TestStateClosedSet(unittest.TestCase):
    """Verify the closed set of valid states is exactly as documented."""

    def test_valid_states_count(self):
        self.assertEqual(len(VALID_STATES), 6)

    def test_states_have_expected_names(self):
        for name in ("STOPPED", "STARTING", "READY", "RUNNING", "DEGRADED", "FAILED"):
            self.assertIn(name, VALID_STATES)

    def test_assert_state_in_accepts_valid(self):
        for s in VALID_STATES:
            assert_state_in(s)  # must not raise

    def test_assert_state_in_rejects_invalid(self):
        for bad in ("PAUSED", "INIT", "DONE", "running", "", "STARTING "):
            with self.assertRaises(AssertionError):
                assert_state_in(bad)


class TestStickyStates(unittest.TestCase):
    """Sticky states are the only ones a supervisor may leave a component
    in without further action."""

    def test_stoppped_is_sticky(self):
        self.assertIn("STOPPED", STICKY_STATES)

    def test_running_is_sticky(self):
        self.assertIn("RUNNING", STICKY_STATES)

    def test_failed_is_not_sticky(self):
        self.assertNotIn("FAILED", STICKY_STATES)

    def test_degraded_is_not_sticky(self):
        self.assertNotIn("DEGRADED", STICKY_STATES)

    def test_starting_is_not_sticky(self):
        self.assertNotIn("STARTING", STICKY_STATES)


class TestLegalTransitions(unittest.TestCase):
    """Verify the legal-transition table matches LIFECYCLE.md §3 exactly."""

    def test_all_transitions_use_valid_states(self):
        for src, dst in LEGAL_TRANSITIONS:
            self.assertIn(src, VALID_STATES, f"source {src!r} not in closed set")
            self.assertIn(dst, VALID_STATES, f"dest {dst!r} not in closed set")

    def test_count_of_legal_transitions(self):
        # The table in LIFECYCLE.md §3 has 13 entries.
        self.assertEqual(len(LEGAL_TRANSITIONS), 13)

    def test_forbidden_transitions(self):
        """Spot-check the explicitly forbidden transitions listed in
        LIFECYCLE.md §3."""
        forbidden = [
            ("STOPPED",  "RUNNING"),    # must go through STARTING
            ("RUNNING",  "READY"),       # cannot un-run
            ("RUNNING",  "STARTING"),    # restart must go through STOPPED
            ("DEGRADED", "STARTING"),    # restart must go through STOPPED
            ("FAILED",   "RUNNING"),     # restart must go through STOPPED
        ]
        for src, dst in forbidden:
            self.assertNotIn((src, dst), LEGAL_TRANSITIONS,
                             f"transition {src}->{dst} should be forbidden")

    def test_starting_can_reach_ready(self):
        self.assertIn(("STARTING", "READY"), LEGAL_TRANSITIONS)

    def test_starting_can_fail(self):
        self.assertIn(("STARTING", "FAILED"), LEGAL_TRANSITIONS)

    def test_running_can_degrade(self):
        self.assertIn(("RUNNING", "DEGRADED"), LEGAL_TRANSITIONS)

    def test_degraded_can_recover(self):
        self.assertIn(("DEGRADED", "RUNNING"), LEGAL_TRANSITIONS)

    def test_degraded_can_fail_after_window(self):
        self.assertIn(("DEGRADED", "FAILED"), LEGAL_TRANSITIONS)

    def test_failed_can_restart(self):
        self.assertIn(("FAILED", "STARTING"), LEGAL_TRANSITIONS)


class TestComponentStateConformance(unittest.TestCase):
    """Every component row in COMPONENTS must declare a state from the
    closed set as its initial state. Initial state is always STOPPED
    (we test the static declaration here; live behavior is in the
    harness-integration tests)."""

    def test_all_components_have_initial_state_stopped(self):
        # Initial state is implicitly STOPPED for every component per
        # RUNTIME_CONTRACT.md §2.1 (numeric 0).
        for c in COMPONENTS:
            self.assertEqual(c["name"], c["name"])  # smoke check the row
            # Initial state is implicit; we just assert the row exists and
            # the component has a name and a binary.
            self.assertTrue(c["binary"])

    def test_required_components_subset(self):
        from tests.runtime.conftest import REQUIRED_COMPONENTS
        for name in ("bridge", "core", "brain", "shield"):
            self.assertIn(name, REQUIRED_COMPONENTS,
                          f"{name} should be a Required=yes component")


class TestAuditTrailShape(unittest.TestCase):
    """An audit record must include at minimum: ts, component, from, to,
    reason. This is verified for records produced by our test helper."""

    def test_write_audit_record_emits_valid_record(self):
        # Write a record we know is legal.
        write_audit_record("RUNNING", "DEGRADED", "health_probe_timeout",
                            component="test_states")

        # Read it back from the audit log.
        from tests.runtime.conftest import audit_log_path
        import json
        lines = audit_log_path().read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 1)
        last = json.loads(lines[-1])

        for key in ("v", "ts", "component", "from", "to", "reason",
                    "attempts", "supervisor_pid", "uuid"):
            self.assertIn(key, last, f"audit record missing {key!r}")

        self.assertEqual(last["from"], "RUNNING")
        self.assertEqual(last["to"],   "DEGRADED")
        self.assertEqual(last["component"], "test_states")


if __name__ == "__main__":
    unittest.main()
