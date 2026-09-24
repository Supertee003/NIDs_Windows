import unittest

from brain.pep_receipt import (
    PEP_ALLOW,
    PEP_BLOCK,
    PEP_ESCALATE,
    receipt_from_pep_response,
)


BASE = {
    "request_id": 10,
    "event_id": 20,
    "policy_id": 30,
    "trace_id": 40,
    "audit_id": 50,
}


class PepReceiptTests(unittest.TestCase):
    def test_allow_is_simulated_not_enforced(self):
        receipt = receipt_from_pep_response({"decision": PEP_ALLOW}, **BASE)
        self.assertEqual(receipt.status, "SIMULATED")
        self.assertFalse(receipt.host_effect_confirmed)
        self.assertEqual(receipt.filter_id, 0)

    def test_wfp_unavailable_escalate_is_unavailable(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_ESCALATE, "reason": 4}, **BASE
        )
        self.assertEqual(receipt.status, "UNAVAILABLE")
        self.assertFalse(receipt.host_effect_confirmed)
        self.assertEqual(receipt.reason, "wfp_provider_unavailable")

    def test_block_without_proof_is_failed(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_BLOCK}, **BASE
        )
        self.assertEqual(receipt.status, "FAILED")
        self.assertFalse(receipt.host_effect_confirmed)

    def test_block_with_filter_and_host_proof_is_enforced(self):
        receipt = receipt_from_pep_response(
            {"decision": PEP_BLOCK},
            filter_id=900,
            host_effect_confirmed=True,
            **BASE,
        )
        self.assertEqual(receipt.status, "ENFORCED")
        self.assertTrue(receipt.host_effect_confirmed)
        self.assertEqual(receipt.filter_id, 900)
        self.assertTrue(receipt.is_forensically_linkable())


if __name__ == "__main__":
    unittest.main()
