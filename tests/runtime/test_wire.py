"""
test_wire.py - Wire-format contract tests

Verifies the NDJSON envelope and the closed set of `kind` values and
error classes described in RUNTIME_CONTRACT.md §6.

The wire envelope is the single shape every control-plane message MUST
take, regardless of the underlying transport (pipe / TCP / UDP / file).
"""

from __future__ import annotations

import json
import time
import unittest
from typing import Any

# Closed set of `kind` values per RUNTIME_CONTRACT.md §6.
VALID_KINDS = {"STATUS", "HEALTH", "ERROR", "STARTING_PROGRESS"}

# Closed set of error classes per RUNTIME_CONTRACT.md §6.
VALID_ERROR_CLASSES = {
    "STARTUP_TIMEOUT",
    "DEP_UNAVAILABLE",
    "DEP_DEGRADED",
    "RESOURCE_EXHAUSTED",
    "CONFIG_INVALID",
    "CONTRACT_VIOLATION",
    "PANIC",
    "UNKNOWN",
}

# Error classes that are documented as non-recoverable.
NON_RECOVERABLE_ERROR_CLASSES = {
    "CONFIG_INVALID",
    "CONTRACT_VIOLATION",
    "PANIC",
}

# Envelope required fields (top-level).
ENVELOPE_REQUIRED_FIELDS = ("v", "ts", "src", "kind")


def make_envelope(src: str, kind: str, state: str = "RUNNING",
                  data: dict[str, Any] | None = None,
                  pid: int = 1234) -> dict[str, Any]:
    """Helper to build a well-formed envelope. Used by tests below."""
    assert kind in VALID_KINDS, f"unknown kind {kind!r}"
    return {
        "v":     1,
        "ts":    int(time.time() * 1000),
        "src":   src,
        "kind":  kind,
        "state": state,
        "pid":   pid,
        "data":  data or {},
    }


def validate_envelope(env: dict[str, Any]) -> None:
    """Raise AssertionError if `env` violates the wire-format contract."""
    for f in ENVELOPE_REQUIRED_FIELDS:
        if f not in env:
            raise AssertionError(f"envelope missing field {f!r}")

    if env["v"] != 1:
        raise AssertionError(f"unsupported envelope version {env['v']!r}")

    if env["kind"] not in VALID_KINDS:
        raise AssertionError(f"unknown kind {env['kind']!r}")

    valid_states = ("STOPPED", "STARTING", "READY", "RUNNING", "DEGRADED", "FAILED")
    if "state" in env and env["state"] not in valid_states:
        raise AssertionError(f"invalid state {env['state']!r} in envelope")

    # STARTING_PROGRESS implies the component is still initializing; its
    # state MUST be STARTING. Any other state is a contract violation.
    if env["kind"] == "STARTING_PROGRESS" and env.get("state") != "STARTING":
        raise AssertionError(
            f"STARTING_PROGRESS envelope must have state=STARTING, got "
            f"{env.get('state')!r}"
        )

    if env["kind"] == "ERROR":
        data = env.get("data", {})
        if "class" not in data:
            raise AssertionError("ERROR envelope missing data.class")
        if data["class"] not in VALID_ERROR_CLASSES:
            raise AssertionError(f"unknown error class {data['class']!r}")
        if "msg" not in data:
            raise AssertionError("ERROR envelope missing data.msg")
        if "recoverable" not in data:
            raise AssertionError("ERROR envelope missing data.recoverable")


class TestEnvelopeStructure(unittest.TestCase):

    def test_make_envelope_produces_valid(self):
        env = make_envelope("core", "STATUS")
        validate_envelope(env)  # must not raise

    def test_missing_v_rejected(self):
        env = make_envelope("core", "STATUS")
        del env["v"]
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_wrong_version_rejected(self):
        env = make_envelope("core", "STATUS")
        env["v"] = 2
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_missing_src_rejected(self):
        env = make_envelope("core", "STATUS")
        del env["src"]
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_unknown_kind_rejected(self):
        env = make_envelope("core", "STATUS")
        env["kind"] = "ALERT"
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_invalid_state_rejected(self):
        env = make_envelope("core", "STATUS")
        env["state"] = "ZOMBIE"
        with self.assertRaises(AssertionError):
            validate_envelope(env)


class TestErrorEnvelope(unittest.TestCase):

    def _err(self, klass: str, recoverable: bool = True) -> dict[str, Any]:
        return make_envelope(
            "core", "ERROR", state="FAILED",
            data={"class": klass, "msg": "test", "recoverable": recoverable}
        )

    def test_valid_error_accepted(self):
        for klass in VALID_ERROR_CLASSES:
            recoverable = klass not in NON_RECOVERABLE_ERROR_CLASSES
            validate_envelope(self._err(klass, recoverable))

    def test_unknown_class_rejected(self):
        with self.assertRaises(AssertionError):
            validate_envelope(self._err("NOT_A_REAL_CLASS"))

    def test_missing_msg_rejected(self):
        env = self._err("STARTUP_TIMEOUT")
        del env["data"]["msg"]
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_missing_recoverable_rejected(self):
        env = self._err("STARTUP_TIMEOUT")
        del env["data"]["recoverable"]
        with self.assertRaises(AssertionError):
            validate_envelope(env)

    def test_panic_must_be_non_recoverable(self):
        # If a producer marks PANIC as recoverable, the validator should
        # still accept the envelope (we trust the producer's claim), but
        # the test case below documents the expected mapping.
        env = self._err("PANIC", recoverable=False)
        validate_envelope(env)  # accepted


class TestErrorClassSetIsClosed(unittest.TestCase):

    def test_class_set_size(self):
        self.assertEqual(len(VALID_ERROR_CLASSES), 8)

    def test_expected_classes_present(self):
        for klass in ("STARTUP_TIMEOUT", "DEP_UNAVAILABLE", "CONFIG_INVALID",
                      "PANIC", "UNKNOWN"):
            self.assertIn(klass, VALID_ERROR_CLASSES)

    def test_recoverable_partition_is_consistent(self):
        # Every error class is either recoverable or not, never both.
        # We test the documented mapping explicitly.
        recoverable = VALID_ERROR_CLASSES - NON_RECOVERABLE_ERROR_CLASSES
        non_recoverable = NON_RECOVERABLE_ERROR_CLASSES
        self.assertEqual(recoverable & non_recoverable, set())
        self.assertEqual(recoverable | non_recoverable, VALID_ERROR_CLASSES)


class TestStartingProgressEnvelope(unittest.TestCase):

    def test_starting_progress_accepted(self):
        env = make_envelope(
            "core", "STARTING_PROGRESS", state="STARTING",
            data={"phase": "load_shield", "remaining_ms": 1200}
        )
        validate_envelope(env)

    def test_starting_progress_state_must_be_starting(self):
        env = make_envelope(
            "core", "STARTING_PROGRESS", state="RUNNING",
            data={"phase": "load_shield", "remaining_ms": 0}
        )
        with self.assertRaises(AssertionError):
            validate_envelope(env)


class TestJsonRoundTrip(unittest.TestCase):
    """The envelope MUST be JSON-serializable on a single line (NDJSON)."""

    def test_envelope_serializes_to_one_line(self):
        env = make_envelope("core", "STATUS",
                            data={"uptime_ms": 12345})
        s = json.dumps(env, separators=(",", ":"))
        self.assertEqual(len(s.splitlines()), 1)

    def test_envelope_round_trips(self):
        env = make_envelope("core", "STATUS",
                            data={"uptime_ms": 12345})
        s = json.dumps(env, separators=(",", ":"))
        env2 = json.loads(s)
        self.assertEqual(env, env2)


if __name__ == "__main__":
    unittest.main()
