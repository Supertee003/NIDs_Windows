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
from unittest.mock import patch

from tests.runtime.conftest import COMPONENTS, RuntimeProbe, VALID_STATES
from tools.aegisctl.api import control_api

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
# STEP-43 (CTRL-HEALTH-115): daemon also emits packets_captured (canonical
# nose submissions) and flows_active (live flow-table gauge). Optional here
# so older payloads still validate; when present they must be sane.
OPTIONAL_INT_FIELDS = ("packets_captured", "flows_active")


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
    for field in OPTIONAL_INT_FIELDS:
        if field in resp:
            if not isinstance(resp[field], int) or resp[field] < 0:
                raise AssertionError(f"{field} must be non-negative int, "
                                     f"got {resp[field]!r}")


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

    def test_daemon_metric_keys_accepted_when_present(self):
        # CTRL-HEALTH-115: live daemon payloads carry packets_captured /
        # flows_active alongside counters; all three must validate together.
        r = self._good()
        r["packets_captured"] = 900
        r["flows_active"] = 5
        validate_health_response(r)

    def test_negative_daemon_metric_rejected(self):
        r = self._good(); r["packets_captured"] = 10; r["flows_active"] = -1
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


class TestControlApiHealthPayload(unittest.TestCase):
    """The control backend must expose live, contract-complete health data."""

    def test_tier3_pep_ready_does_not_attest_wfp_host_effect(self):
        daemon_health = {
            "component": "core",
            "state": "DEGRADED",
            "runtime_state": "RUNNING",
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 0,
            "capabilities": {"wfp": False},
            "subsystems": [
                {"name": "rust_pep", "state": "RUNNING", "pid": 4321},
                {"name": "tier3", "state": "RUNNING", "pid": 4321},
            ],
            "workers": {"failure_mask": 0},
            "data_plane": {},
        }
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("DEGRADED", True)):
            payload = control_api.get_health_payload()

        self.assertTrue(payload["tier3"]["ready"])
        self.assertTrue(payload["tier3"]["dependency_ready"])
        self.assertFalse(payload["tier3"]["provider_ready"])
        self.assertFalse(payload["tier3"]["provider_capable"])
        self.assertFalse(payload["tier3"]["host_effect_capable"])
        self.assertTrue(payload["rust_shield"]["pep_ready"])
        self.assertFalse(payload["rust_shield"]["provider_ready"])
        self.assertFalse(payload["rust_shield"]["provider_capable"])
        self.assertFalse(payload["rust_shield"]["host_effect_capable"])
        self.assertEqual(payload["state"], "DEGRADED")
        self.assertTrue(payload["degraded"])

    def test_provider_ready_never_projects_production_host_effect(self):
        daemon_health = {
            "component": "core",
            "state": "RUNNING",
            "runtime_state": "RUNNING",
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 0,
            "capabilities": {"wfp": True},
            "subsystems": [
                {"name": "rust_pep", "state": "RUNNING", "pid": 4321},
                {"name": "tier3", "state": "RUNNING", "pid": 4321},
            ],
            "workers": {
                "pipeline_ready": True,
                "sensor_ready": True,
                "nose_ready": True,
                "etw_ready": True,
                "fim_ready": True,
                "registry_ready": True,
                "failure_mask": 0,
            },
            "data_plane": {},
        }
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("RUNNING", False)):
            payload = control_api.get_health_payload()

        self.assertTrue(payload["tier3"]["provider_ready"])
        self.assertTrue(payload["tier3"]["provider_capable"])
        self.assertFalse(payload["tier3"]["host_effect_capable"])
        self.assertTrue(payload["rust_pep"]["provider_ready"])
        self.assertTrue(payload["rust_pep"]["provider_capable"])
        self.assertFalse(payload["rust_pep"]["host_effect_capable"])

    def test_degraded_daemon_health_cannot_be_promoted_by_running_runtime_state(self):
        daemon_health = {
            "component": "core",
            "state": "DEGRADED",
            "runtime_state": "RUNNING",
            "degraded": True,
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 0,
            "capabilities": {"wfp": True},
            "subsystems": [
                {"name": "rust_pep", "state": "RUNNING", "pid": 4321},
                {"name": "tier3", "state": "RUNNING", "pid": 4321},
            ],
            "workers": {
                "pipeline_ready": True,
                "sensor_ready": True,
                "nose_ready": True,
                "etw_ready": True,
                "fim_ready": True,
                "registry_ready": True,
                "failure_mask": 0,
            },
            "data_plane": {},
            "data_integrity": {"queue_dropped_total": 1},
        }
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("RUNNING", False)):
            payload = control_api.get_health_payload()

        self.assertEqual(payload["state"], "DEGRADED")
        self.assertTrue(payload["degraded"])

    def test_payload_reports_subsystem_states_and_monotonic_uptime(self):
        statuses = [
            ("zig", True, 101),
            ("go_nose", False, None),
            ("rust_pep", True, 202),
        ]
        with patch.object(control_api, "get_all_status", return_value=statuses), \
             patch.object(control_api, "compute_health_state", return_value=("DEGRADED", True)):
            payload = control_api.get_health_payload()

        self.assertEqual(payload["state"], "DEGRADED")
        self.assertTrue(payload["degraded"])
        self.assertGreaterEqual(payload["uptime_ms"], 0)
        self.assertIn("subsystems", payload)
        self.assertEqual(payload["subsystems"]["zig"]["state"], "RUNNING")
        self.assertEqual(payload["subsystems"]["go_nose"]["state"], "STOPPED")
        self.assertEqual(payload["subsystems"]["zig"]["pid"], 101)

    def test_payload_exposes_tier3_and_counters(self):
        with patch.object(control_api, "_query_daemon_retry", return_value=None), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("FAILED", True)):
            payload = control_api.get_health_payload()

        self.assertIn("tier3", payload)
        self.assertFalse(payload["tier3"]["ready"])
        self.assertEqual(set(payload["counters"]),
                         {"in_events", "out_events", "errors", "dropped"})

    def test_unavailable_daemon_is_not_promoted_to_runtime_truth(self):
        with patch.object(control_api, "_query_daemon_retry", return_value=None), \
             patch.object(control_api, "get_all_status", return_value=[
                 ("zig", True, 101),
             ]):
            payload = control_api.get_health_payload()

        self.assertEqual(payload["state"], "DEGRADED")
        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["source"], "diagnostic")
        self.assertFalse(payload["runtime_available"])
        self.assertEqual(payload["tier3"]["state"], "UNAVAILABLE")
        self.assertIn("daemon unavailable", payload["availability_error"])

    def _daemon_with(self, **overrides):
        base = {
            "component": "core",
            "state": "RUNNING",
            "runtime_state": "RUNNING",
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 7,
            "capabilities": {"wfp": False},
            "subsystems": [],
            "workers": {"failure_mask": 0},
            "data_plane": {
                "nose_frames_read": 10,
                "nose_frames_submitted": 9,
                "nose_pipe_errors": 1,
                "nose_frames_dropped": 2,
            },
        }
        base.update(overrides)
        return base

    def _payload_for(self, daemon_health):
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("RUNNING", False)):
            return control_api.get_health_payload()

    def test_daemon_counters_used_verbatim_when_present(self):
        # CTRL-SHIM-150: fresh daemons own the 4.1 shape; prefer it.
        payload = self._payload_for(self._daemon_with(counters={
            "in_events": 100, "out_events": 90, "errors": 3, "dropped": 12,
        }))
        self.assertEqual(payload["counters"], {
            "in_events": 100, "out_events": 90, "errors": 3, "dropped": 12,
        })

    def test_data_integrity_counters_are_forwarded_from_daemon(self):
        integrity = {
            "queue_dropped_total": 7,
            "nose_frames_rejected": 2,
            "nose_frames_dropped": 3,
            "nose_pipe_errors": 4,
            "minifilter_ring_dropped": 5,
            "minifilter_pipeline_dropped": 6,
        }
        payload = self._payload_for(self._daemon_with(data_integrity=integrity))
        self.assertEqual(payload["data_integrity"], integrity)

    def test_data_integrity_absence_and_malformed_counters_are_honest(self):
        legacy = self._payload_for(self._daemon_with())
        self.assertEqual(legacy["data_integrity"], {})

        malformed = self._payload_for(self._daemon_with(data_integrity={
            "queue_dropped_total": True,
            "nose_frames_rejected": -1,
            "nose_frames_dropped": "3",
            "nose_pipe_errors": 0,
            "minifilter_ring_dropped": 2,
            "unknown": 99,
        }))
        self.assertEqual(malformed["data_integrity"], {
            "nose_pipe_errors": 0,
            "minifilter_ring_dropped": 2,
        })

    def test_counters_synthesized_when_daemon_lacks_them(self):
        # Pre-slice daemons carry no counters: fall back to data_plane.
        payload = self._payload_for(self._daemon_with())
        self.assertEqual(payload["counters"], {
            "in_events": 10, "out_events": 9, "errors": 1, "dropped": 2,
        })

    def test_malformed_daemon_counters_fall_back_whole(self):
        # Never merge per-field: a half-present object falls back entirely.
        for bad in ({"in_events": -1, "out_events": 9, "errors": 1, "dropped": 2},
                    {"in_events": "10", "out_events": 9, "errors": 1, "dropped": 2},
                    {"in_events": True, "out_events": 9, "errors": 1, "dropped": 2},
                    {"in_events": 10}):
            payload = self._payload_for(self._daemon_with(counters=bad))
            self.assertEqual(payload["counters"], {
                "in_events": 10, "out_events": 9, "errors": 1, "dropped": 2,
            }, bad)


class TestEndpointOwnershipInHealth(unittest.TestCase):
    """GAP-010 second half: orphan findings surface in health (cached)."""

    def setUp(self):
        control_api._reset_endpoint_ownership_cache()

    def tearDown(self):
        control_api._reset_endpoint_ownership_cache()

    def _payload_for(self, census):
        daemon_health = {
            "component": "core",
            "state": "RUNNING",
            "runtime_state": "RUNNING",
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 7,
            "capabilities": {"wfp": False},
            "subsystems": [],
            "workers": {"failure_mask": 0},
            "data_plane": {},
        }
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("RUNNING", False)), \
             patch.object(control_api, "diagnose_endpoint_ownership", return_value=census):
            return control_api.get_health_payload()

    def test_foreign_finding_surfaces_in_health(self):
        census = {"findings": [
            {"endpoint": "brain channel", "port": 9999, "pid": 4242,
             "status": "FOREIGN", "detail": "orphan"},
        ], "foreign_count": 1}
        payload = self._payload_for(census)
        self.assertEqual(payload["endpoint_ownership"]["status"], "FOREIGN")
        self.assertEqual(payload["endpoint_ownership"]["foreign_count"], 1)
        self.assertEqual(len(payload["endpoint_ownership"]["findings"]), 1)

    def test_clear_census_surfaces_as_clear(self):
        census = {"findings": [
            {"endpoint": "brain channel", "port": 9999, "pid": None,
             "status": "CLEAR", "detail": "no listener"},
        ], "foreign_count": 0}
        payload = self._payload_for(census)
        self.assertEqual(payload["endpoint_ownership"]["status"], "CLEAR")
        self.assertEqual(payload["endpoint_ownership"]["foreign_count"], 0)

    def test_unknown_does_not_outrank_clear_but_bows_to_foreign(self):
        self.assertEqual(control_api.summarize_endpoint_ownership(
            {"findings": [{"endpoint": "brain channel", "status": "UNKNOWN"}],
             "foreign_count": 0})["status"], "UNKNOWN")
        self.assertEqual(control_api.summarize_endpoint_ownership(
            {"findings": [{"endpoint": "brain channel", "status": "UNKNOWN"},
                           {"endpoint": "brain channel", "status": "FOREIGN"}],
             "foreign_count": 1})["status"], "FOREIGN")
        self.assertEqual(control_api.summarize_endpoint_ownership(
            {"findings": [], "foreign_count": 0})["status"], "CLEAR")

    def test_census_is_cached_within_ttl(self):
        calls = []
        fake = {"findings": [], "foreign_count": 0}

        def fake_census():
            calls.append(1)
            return fake

        with patch.object(control_api, "diagnose_endpoint_ownership",
                          side_effect=fake_census):
            control_api.get_endpoint_ownership_cached()
            control_api.get_endpoint_ownership_cached()
            self.assertEqual(len(calls), 1)
            control_api._reset_endpoint_ownership_cache()
            control_api.get_endpoint_ownership_cached()
            self.assertEqual(len(calls), 2)


class TestTrafficGaugesInHealth(unittest.TestCase):
    """CLI-SHOW-158: daemon traffic gauges ride the health payload."""

    def setUp(self):
        control_api._reset_endpoint_ownership_cache()

    def tearDown(self):
        control_api._reset_endpoint_ownership_cache()

    def _payload_for(self, daemon_health):
        with patch.object(control_api, "_query_daemon_retry", return_value=daemon_health), \
             patch.object(control_api, "get_all_status", return_value=[]), \
             patch.object(control_api, "compute_health_state", return_value=("RUNNING", False)), \
             patch.object(control_api, "diagnose_endpoint_ownership",
                          return_value={"findings": [], "foreign_count": 0}):
            return control_api.get_health_payload()

    def _daemon_with(self, **overrides):
        base = {
            "component": "core",
            "state": "RUNNING",
            "runtime_state": "RUNNING",
            "pid": 4321,
            "uptime_ms": 100,
            "last_event_ms": 7,
            "capabilities": {"wfp": False},
            "subsystems": [],
            "workers": {"failure_mask": 0},
            "data_plane": {},
        }
        base.update(overrides)
        return base

    def test_daemon_gauges_forwarded_verbatim(self):
        payload = self._payload_for(self._daemon_with(
            packets_captured=424242, flows_active=7))
        self.assertEqual(payload["packets_captured"], 424242)
        self.assertEqual(payload["flows_active"], 7)

    def test_missing_gauges_read_as_zero(self):
        # Pre-slice daemons carry no such keys; downstream .get(key, 0)
        # convention is preserved here.
        payload = self._payload_for(self._daemon_with())
        self.assertEqual(payload["packets_captured"], 0)
        self.assertEqual(payload["flows_active"], 0)


if __name__ == "__main__":
    unittest.main()
