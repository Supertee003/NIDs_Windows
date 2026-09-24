import unittest
from unittest.mock import patch

from tools.aegisctl.api import control_api


class RustShieldLifecycleTests(unittest.TestCase):
    def _daemon_health(self):
        return {
            "component": "core",
            "pid": 21552,
            "version": "6.0.0",
            "runtime_state": "RUNNING",
            "uptime_ms": 1000,
            "last_event_ms": 10,
            "capabilities": {
                "cpp_bridge": True,
                "udp_brain": True,
                "wfp": False,
            },
            "subsystems": [
                {"name": "rust_pep", "state": "RUNNING", "pid": 21552, "version": "1.0.0"},
                {"name": "tier3", "state": "STOPPED", "pid": None, "version": "1.0.0", "error": "tier3_dependencies_not_ready"},
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
            "data_plane": {
                "nose_frames_read": 10,
                "nose_frames_submitted": 10,
                "nose_frames_dropped": 0,
                "nose_pipe_errors": 0,
                "nose_last_event_id": 5,
                "nose_duplicate_event_ids": 0,
                "nose_non_monotonic_event_ids": 0,
            },
        }

    def test_rust_shield_is_ready_but_host_effect_is_not_capable(self):
        statuses = [
            ("rust_pep", True, 21552),
            ("tier3", False, None),
        ]
        with patch.object(control_api, "_query_daemon_retry", return_value=self._daemon_health()), \
             patch.object(control_api, "get_all_status", return_value=statuses), \
             patch.object(control_api, "_tier3_artifact_diagnostics", return_value={
                 "artifact_present": False,
                 "artifact_path": None,
                 "dependency_ready": False,
                 "provider_ready": False,
                 "host_effect_capable": False,
             }):
            payload = control_api.get_health_payload()

        self.assertEqual(payload["rust_shield"]["state"], "READY")
        self.assertTrue(payload["rust_shield"]["pep_ready"])
        self.assertTrue(payload["rust_shield"]["policy_authority"])
        self.assertFalse(payload["rust_shield"]["provider_ready"])
        self.assertFalse(payload["rust_shield"]["host_effect_capable"])
        self.assertFalse(payload["tier3"]["ready"])
        self.assertEqual(payload["state"], "DEGRADED")
        self.assertTrue(payload["degraded"])

    def test_wfp_unavailable_never_promotes_overall_gate(self):
        statuses = [("rust_pep", True, 21552)]
        with patch.object(control_api, "_query_daemon_retry", return_value=self._daemon_health()), \
             patch.object(control_api, "get_all_status", return_value=statuses), \
             patch.object(control_api, "_tier3_artifact_diagnostics", return_value={
                 "artifact_present": True,
                 "artifact_path": "fixture/sec_monitor.dll",
                 "dependency_ready": True,
                 "provider_ready": False,
                 "host_effect_capable": False,
             }):
            payload = control_api.get_health_payload()

        self.assertFalse(payload["rust_shield"]["provider_ready"])
        self.assertFalse(payload["rust_shield"]["host_effect_capable"])
        self.assertFalse(payload["tier3"]["ready"])
        self.assertEqual(payload["state"], "DEGRADED")


if __name__ == "__main__":
    unittest.main()
