import unittest
from unittest.mock import patch

from tools.aegisctl.contracts import (
    PEP_DECISION_ORDINALS,
    POLICY_ACTION_ORDINALS,
    incident_from_record,
    project_operator_state,
    validate_enforcement_receipt,
)


class TestActionNamespaces(unittest.TestCase):
    def test_policy_block_is_two(self):
        self.assertEqual(POLICY_ACTION_ORDINALS["BLOCK"], 2)

    def test_pep_response_block_is_distinct(self):
        self.assertEqual(PEP_DECISION_ORDINALS["BLOCK"], 1)
        self.assertNotEqual(POLICY_ACTION_ORDINALS["BLOCK"], PEP_DECISION_ORDINALS["BLOCK"])


class TestReceiptValidation(unittest.TestCase):
    def valid(self):
        return {
            "receipt_version": 1,
            "request_id": 10,
            "event_id": 20,
            "policy_id": 30,
            "decision": "block",
            "status": "enforced",
            "provider": "wfp",
            "filter_id": 40,
            "host_effect_confirmed": True,
            "trace_id": 50,
            "audit_id": 60,
        }

    def test_confirmed_receipt_requires_all_forensic_identity(self):
        ok, errors = validate_enforcement_receipt(self.valid())
        self.assertTrue(ok, errors)

    def test_decision_alone_is_not_confirmed_block(self):
        r = self.valid()
        r["status"] = "pending"
        r["host_effect_confirmed"] = False
        r.pop("filter_id")
        ok, _ = validate_enforcement_receipt(r)
        self.assertTrue(ok)
        self.assertEqual(incident_from_record({"event_id": 20, "status": "observed", "enforcement_receipt": r})["status"], "OBSERVED")

    def test_host_effect_without_enforced_status_is_rejected(self):
        r = self.valid()
        r["status"] = "failed"
        ok, errors = validate_enforcement_receipt(r)
        self.assertFalse(ok)
        self.assertIn("host_effect_requires_enforced", errors)


class TestOperatorProjection(unittest.TestCase):
    def test_closed_gate_is_observe_only(self):
        result = project_operator_state({"state": "RUNNING", "degraded": False}, {"prevention_gate": "closed", "host_effect_capable": True})
        self.assertEqual(result["enforcement_label"], "OBSERVE_ONLY")
        self.assertTrue(result["confirmed_block_requires_receipt"])

    def test_closed_gate_rejects_active_enforcement_contract(self):
        result = project_operator_state(
            {"state": "RUNNING", "degraded": False},
            {
                "prevention_gate": "closed",
                "enforcement_mode": "active",
                "tier3_enforcing": True,
            },
        )
        self.assertEqual(result["enforcement_label"], "CONTRACT_VIOLATION")
        self.assertIn("tier3_enforcing_with_closed_gate", result["contract_errors"])
        self.assertIn("active_mode_with_closed_gate", result["contract_errors"])


class TestWebDashboardSurface(unittest.TestCase):
    def test_snapshot_uses_control_truth(self):
        from tools.aegisctl.web_dashboard import app as dashboard
        health = {"state": "DEGRADED", "degraded": True, "counters": {}, "rules_loaded": 22, "policies_loaded": 6}
        with patch.object(dashboard, "get_health_payload", return_value=health), \
             patch.object(dashboard, "query_control", side_effect=lambda command, payload=None: {
                 "enforcement.status": {"prevention_gate": "closed", "host_effect_capable": False},
                 "metrics.snapshot": {"events_processed": 3},
                 "incidents.list": {"incidents": []},
             }.get(command, {})), \
             patch.object(dashboard, "load_rules", return_value={"nids_rules": []}):
            client = dashboard.app.test_client()
            response = client.get("/api/snapshot")
            self.assertEqual(response.status_code, 200)
            body = response.get_json()
            self.assertEqual(body["operator"]["enforcement_label"], "OBSERVE_ONLY")
            self.assertEqual(body["metrics"]["events_processed"], 3)
            self.assertEqual(body["rules_runtime"]["active"], 22)
            self.assertEqual(body["rules_runtime"]["policies_active"], 6)
            self.assertEqual(client.get("/health").status_code, 503)

    def test_system_view_renders_traffic_screening_orphan_rows(self):
        # DASH-SHOW-172: operator-visible rows for the newer daemon keys.
        from tools.aegisctl.web_dashboard import app as dashboard
        html = dashboard.INDEX_HTML
        for label in ("'Traffic'", "'Screening'", "'Orphan watch'"):
            self.assertIn(label, html)

    def test_snapshot_carries_new_daemon_keys(self):
        # DASH-SHOW-172: packets, shield flags and orphan findings must
        # flow from control into the snapshot untouched.
        from tools.aegisctl.web_dashboard import app as dashboard
        health = {
            "state": "RUNNING", "degraded": False, "counters": {},
            "rules_loaded": 1, "policies_loaded": 1,
            "packets_captured": 424242, "flows_active": 7,
            "endpoint_ownership": {"status": "FOREIGN", "foreign_count": 1, "findings": []},
        }
        enforcement = {"shield_loaded": True, "payload_screening": True,
                       "prevention_gate": "closed", "host_effect_capable": False}
        with patch.object(dashboard, "get_health_payload", return_value=health), \
             patch.object(dashboard, "query_control", side_effect=lambda command, payload=None: {
                 "enforcement.status": enforcement,
                 "metrics.snapshot": {},
                 "incidents.list": {"incidents": []},
             }.get(command, {})), \
             patch.object(dashboard, "load_rules", return_value={"nids_rules": []}):
            client = dashboard.app.test_client()
            body = client.get("/api/snapshot").get_json()
            self.assertEqual(body["health"]["packets_captured"], 424242)
            self.assertEqual(body["health"]["flows_active"], 7)
            self.assertEqual(body["health"]["endpoint_ownership"]["status"], "FOREIGN")
            self.assertTrue(body["enforcement"]["shield_loaded"])
            self.assertTrue(body["enforcement"]["payload_screening"])


if __name__ == "__main__":
    unittest.main()
