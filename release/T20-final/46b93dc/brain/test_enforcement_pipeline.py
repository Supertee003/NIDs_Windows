import unittest

from brain.enforcement_pipeline import process_pep_response
from brain.pep_request import ACTION_BLOCK, PepRequest


class EnforcementPipelineTests(unittest.TestCase):
    def setUp(self):
        self.request = PepRequest(
            request_id=1,
            event_id=2,
            policy_id=3,
            trace_id=4,
            audit_id=5,
            requested_action=ACTION_BLOCK,
            severity=3,
            caller_capability_mask=1,
            reason="critical_match",
        )

    def test_wfp_unavailable_reaches_mouth_without_blocked_claim(self):
        receipt, evidence, mouth = process_pep_response(
            self.request,
            {"decision": 4, "reason": 4},
        )
        self.assertEqual(receipt.status, "UNAVAILABLE")
        self.assertEqual(evidence.receipt_status, "UNAVAILABLE")
        self.assertEqual(mouth.label, "PROVIDER_UNAVAILABLE")
        self.assertFalse(mouth.host_effect_confirmed)

    def test_failed_block_reaches_mouth_as_failed(self):
        receipt, evidence, mouth = process_pep_response(
            self.request,
            {"decision": 1, "reason": 4},
        )
        self.assertEqual(receipt.status, "FAILED")
        self.assertEqual(mouth.label, "ENFORCEMENT_FAILED")
        self.assertFalse(mouth.host_effect_confirmed)

    def test_confirmed_fixture_is_the_only_blocked_display(self):
        receipt, evidence, mouth = process_pep_response(
            self.request,
            {"decision": 1, "reason": 0},
            provider="fixture_provider",
            filter_id=77,
            host_effect_confirmed=True,
        )
        self.assertEqual(receipt.status, "ENFORCED")
        self.assertEqual(evidence.receipt_status, "ENFORCED")
        self.assertEqual(mouth.label, "BLOCKED")
        self.assertTrue(mouth.host_effect_confirmed)


if __name__ == "__main__":
    unittest.main()
