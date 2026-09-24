import unittest

from brain.detection_result import DetectionResult
from brain.enforcement_receipt import (
    STATUS_ENFORCED,
    STATUS_SIMULATED,
    EnforcementReceipt,
    receipt_from_alert_decision,
)
from brain.policy_decision import decide_alert_only


class EnforcementReceiptTests(unittest.TestCase):
    def test_alert_only_receipt_never_confirms_host_effect(self):
        detection = DetectionResult.from_regex_match(41, ("SQLI", "BLOCK", "8", 3))
        decision = decide_alert_only(detection)
        receipt = receipt_from_alert_decision(decision, request_id=9001)
        self.assertEqual(receipt.status, STATUS_SIMULATED)
        self.assertFalse(receipt.host_effect_confirmed)
        self.assertEqual(receipt.provider, "none")
        self.assertEqual(receipt.to_dict()["event_id"], 41)
        self.assertTrue(receipt.is_forensically_linkable())

    def test_enforced_without_host_confirmation_is_rejected(self):
        receipt = EnforcementReceipt(
            request_id=1,
            event_id=2,
            policy_id=3,
            decision="BLOCK",
            status=STATUS_ENFORCED,
            provider="wfp",
            host_effect_confirmed=False,
        )
        with self.assertRaises(ValueError):
            receipt.validate()

    def test_alert_only_cannot_confirm_host_effect(self):
        receipt = EnforcementReceipt(
            request_id=1,
            event_id=2,
            policy_id=0,
            decision="ALERT",
            status=STATUS_SIMULATED,
            provider="none",
            host_effect_confirmed=True,
        )
        with self.assertRaises(ValueError):
            receipt.validate()


if __name__ == "__main__":
    unittest.main()
