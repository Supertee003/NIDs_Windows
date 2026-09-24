"""End-to-end contract tests for the Rust Shield enforcement path.

These tests use PEP response fixtures only. They never invoke WFP, mutate the
host, install filters, or require a live daemon.
"""
import unittest

from brain.forensic_evidence import evidence_from_receipt
from brain.pep_receipt import (
    PEP_BLOCK,
    PEP_ESCALATE,
    receipt_from_pep_response,
)


class EnforcementPathIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "request_id": 7001,
            "event_id": 8001,
            "policy_id": 42,
            "trace_id": 9001,
            "audit_id": 10001,
        }

    def test_wfp_unavailable_path_is_fail_closed_end_to_end(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_ESCALATE, "reason": 4},
            **self.identity,
        )
        evidence = evidence_from_receipt(receipt)

        self.assertEqual(receipt.status, "UNAVAILABLE")
        self.assertEqual(receipt.mode, "alert_only")
        self.assertFalse(receipt.host_effect_confirmed)
        self.assertFalse(evidence.host_effect_confirmed)
        self.assertTrue(evidence.matches_receipt(receipt))

    def test_confirmed_provider_fixture_is_enforced_end_to_end(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_BLOCK, "reason": 0},
            filter_id=12345,
            host_effect_confirmed=True,
            provider="fixture_provider",
            **self.identity,
        )
        evidence = evidence_from_receipt(receipt)

        self.assertEqual(receipt.status, "ENFORCED")
        self.assertEqual(receipt.mode, "enforced")
        self.assertTrue(receipt.host_effect_confirmed)
        self.assertEqual(evidence.filter_id, 12345)
        self.assertEqual(evidence.provider, "fixture_provider")
        self.assertTrue(evidence.matches_receipt(receipt))

    def test_block_request_without_provider_proof_never_reaches_enforced(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_BLOCK, "reason": 0},
            **self.identity,
        )
        evidence = evidence_from_receipt(receipt)

        self.assertEqual(receipt.status, "FAILED")
        self.assertFalse(receipt.host_effect_confirmed)
        self.assertEqual(evidence.receipt_status, "FAILED")


if __name__ == "__main__":
    unittest.main()
