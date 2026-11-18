import unittest

from brain.enforcement_receipt import EnforcementReceipt
from brain.forensic_evidence import evidence_from_receipt


class ForensicEvidenceTests(unittest.TestCase):
    def _receipt(self, **overrides):
        values = {
            "request_id": 1,
            "event_id": 2,
            "policy_id": 3,
            "decision": 4,
            "status": "UNAVAILABLE",
            "provider": "rust_pep",
            "reason": "wfp_provider_unavailable",
            "trace_id": 5,
            "audit_id": 6,
        }
        values.update(overrides)
        return EnforcementReceipt(**values)

    def test_evidence_copies_receipt_identity(self):
        receipt = self._receipt()
        evidence = evidence_from_receipt(receipt)
        self.assertEqual(evidence.event_id, receipt.event_id)
        self.assertEqual(evidence.audit_id, receipt.audit_id)
        self.assertEqual(evidence.trace_id, receipt.trace_id)
        self.assertTrue(evidence.matches_receipt(receipt))

    def test_enforced_evidence_requires_host_proof(self):
        receipt = self._receipt(
            status="ENFORCED",
            provider="wfp",
            filter_id=77,
            host_effect_confirmed=True,
            mode="enforced",
        )
        evidence = evidence_from_receipt(receipt)
        self.assertEqual(evidence.receipt_status, "ENFORCED")
        self.assertTrue(evidence.host_effect_confirmed)
        self.assertEqual(evidence.filter_id, 77)

    def test_invalid_enforced_receipt_is_rejected(self):
        receipt = self._receipt(
            status="ENFORCED",
            provider="wfp",
            filter_id=77,
            host_effect_confirmed=False,
            mode="enforced",
        )
        with self.assertRaises(ValueError):
            evidence_from_receipt(receipt)

    def test_tampered_evidence_does_not_match_receipt(self):
        receipt = self._receipt()
        evidence = evidence_from_receipt(receipt)
        object.__setattr__(evidence, "audit_id", 999)
        self.assertFalse(evidence.matches_receipt(receipt))


if __name__ == "__main__":
    unittest.main()
