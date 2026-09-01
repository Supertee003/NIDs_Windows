"""
test_health.py - Health-probe contract tests

Verifies that every component in COMPONENTS has a valid health-probe
declaration (transport + endpoint), and that the probe's JSON response
matches the schema in RUNTIME_CONTRACT.md §4.1.

Live probes (which actually start the component and hit its endpoint) are
in test_harness_integration.py. Here we validate the static contract and
the schema validator.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from tests.runtime.conftest import COMPONENTS, RuntimeProbe, VALID_STATES

VALID_TRANSPORTS = {"pipe", "tcp", "udp", "stdout", "delegate"}


class TestProbeDeclarations(unittest.TestCase):
    """Every component must declare a probe that the supervisor can hit."""

    def test_every_component_has_a_health_key(self):
        for c in COMPONENTS:
            self.assertIn("health", c, f"{c['name']} missing health declaration")

    def test_every_health_has_a_transport(self):
        for c in COMPONENTS:
            transport = c["health"].get("transport")
            self.assertIsNotNone(transport,
                                 f"{c['name']} missing transport in health")
            self.assertIn(transport, VALID_TRANSPORTS,
                          f"{c['name']} has unknown transport {transport!r}")

    def test_every_health_has_an_endpoint(self):
        for c in COMPONENTS:
            self.assertIn("endpoint", c["health"],
                          f"{c['name']} missing endpoint in health")

    def test_delegate_endpoints_reference_known_components(self):
        names = {c["name"] for c in COMPONENTS}
        for c in COMPONENTS:
            if c["health"]["transport"] == "delegate":
                delegate = c["health"]["endpoint"]
                self.assertIn(delegate, names,
                              f"{c['name']} delegates to unknown {delegate!r}")


class TestRuntimeProbeLookup(unittest.TestCase):
    """The RuntimeProbe.for_component lookup must succeed for every known
    component."""

    def test_lookup_succeeds_for_every_component(self):
        for c in COMPONENTS:
            probe = RuntimeProbe.for_component(c["name"])
            self.assertEqual(probe.component, c["name"])
            self.assertEqual(probe.transport, c["health"]["transport"])
            self.assertEqual(probe.endpoint, c["health"]["endpoint"])

    def test_lookup_raises_for_unknown(self):
        with self.assertRaises(KeyError):
            RuntimeProbe.for_component("does-not-exist")


# --------------------------------------------------------------------------- #
# Schema validator (mirrors RUNTIME_CONTRACT.md §4.1)                          #
# --------------------------------------------------------------------------- #

REQUIRED_FIELDS = ("component", "state", "pid", "uptime_ms", "last_event_ms",
                   "counters", "deps")
REQUIRED_COUNTERS = ("in_events", "out_events", "errors", "dropped")


def validate_health_response(resp: dict[str, Any]) -> None:
    """Raise AssertionError if `resp` does not match the schema."""
    for field in REQUIRED_FIELDS:
        if field not in resp:
            raise AssertionError(f"missing field {field!r} in health response")
    state = resp["state"]
    if state not in VALID_STATES:
        raise AssertionError(f"state {state!r} not in closed set {VALID_STATES}")
    if not isinstance(resp["pid"], int) or resp["pid"] <= 0:
        raise AssertionError(f"pid must be positive int, got {resp['pid']!r}")
    if not isinstance(resp["uptime_ms"], int) or resp["uptime_ms"] < 0:
        raise AssertionError(f"uptime_ms must be non-negative int, "
                             f"got {resp['uptime_ms']!r}")
    counters = resp["counters"]
    for c in REQUIRED_COUNTERS:
        if c not in counters:
            raise AssertionError(f"missing counter {c!r}")
        if not isinstance(counters[c], int) or counters[c] < 0:
            raise AssertionError(f"counter {c!r} must be non-negative int, "
                                 f"got {counters[c]!r}")
    deps = resp["deps"]
    if not isinstance(deps, list):
        raise AssertionError("deps must be a list")
    for dep in deps:
        if "name" not in dep or "state" not in dep:
            raise AssertionError(f"dep entry missing name/state: {dep!r}")
        if dep["state"] not in VALID_STATES:
            raise AssertionError(f"dep state {dep['state']!r} invalid")


class TestHealthSchemaValidator(unittest.TestCase):
    """The schema validator should accept a well-formed response and reject
    each kind of malformed one."""

    def _good(self) -> dict[str, Any]:
        return {
            "component":     "core",
            "state":         "RUNNING",
            "pid":           1234,
            "uptime_ms":     18217,
            "last_event_ms": 412,
            "counters": {
                "in_events":  1024,
                "out_events": 1023,
                "errors":     0,
                "dropped":    0,
            },
            "deps": [
                {"name": "bridge", "state": "RUNNING"},
                {"name": "fabric", "state": "RUNNING"},
            ],
        }

    def test_good_response_accepted(self):
        validate_health_response(self._good())

    def test_missing_component_rejected(self):
        r = self._good(); del r["component"]
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_invalid_state_rejected(self):
        r = self._good(); r["state"] = "PAUSED"
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_zero_pid_rejected(self):
        r = self._good(); r["pid"] = 0
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_negative_uptime_rejected(self):
        r = self._good(); r["uptime_ms"] = -1
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_missing_counter_rejected(self):
        r = self._good(); del r["counters"]["dropped"]
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_negative_counter_rejected(self):
        r = self._good(); r["counters"]["errors"] = -1
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_deps_not_list_rejected(self):
        r = self._good(); r["deps"] = {"name": "bridge"}
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_dep_missing_state_rejected(self):
        r = self._good(); r["deps"] = [{"name": "bridge"}]
        with self.assertRaises(AssertionError):
            validate_health_response(r)

    def test_dep_invalid_state_rejected(self):
        r = self._good(); r["deps"] = [{"name": "bridge", "state": "ZOMBIE"}]
        with self.assertRaises(AssertionError):
            validate_health_response(r)


class TestHealthSampleJsonFromContract(unittest.TestCase):
    """The exact JSON example in RUNTIME_CONTRACT.md §4.1 must pass the
    schema validator. This guards against drift between docs and tests."""

    def test_contract_example_passes(self):
        sample = json.loads(
            """
            {
              "component":   "core",
              "state":       "RUNNING",
              "pid":         12345,
              "uptime_ms":   98217,
              "last_event_ms": 412,
              "counters": {
                "in_events":     1024,
                "out_events":    1023,
                "errors":        0,
                "dropped":       0
              },
              "deps": [
                { "name": "bridge",  "state": "RUNNING" },
                { "name": "fabric",  "state": "RUNNING" }
              ]
            }
            """
        )
        validate_health_response(sample)


if __name__ == "__main__":
    unittest.main()
