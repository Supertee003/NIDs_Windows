import unittest

from brain.detection_result import DetectionResult
from brain.policy_decision import ACTION_ALERT, ACTION_ALLOW, decide_alert_only


class AlertOnlyPolicyTests(unittest.TestCase):
    def test_match_becomes_alert_without_enforcement_request(self):
        result = DetectionResult.from_regex_match(
            31, ("SQLI", "BLOCK", "42", 3)
        )
        decision = decide_alert_only(result)
        self.assertEqual(decision.action, ACTION_ALERT)
        self.assertEqual(decision.detection_rule_id, 42)
        self.assertFalse(decision.enforcement_requested)
        self.assertEqual(decision.mode, "alert_only")
        self.assertNotEqual(decision.action, "BLOCK")

    def test_no_match_becomes_allow(self):
        result = DetectionResult.from_regex_match(32, None)
        decision = decide_alert_only(result)
        self.assertEqual(decision.action, ACTION_ALLOW)
        self.assertFalse(decision.enforcement_requested)
        self.assertEqual(decision.reason, "no_match")

    def test_invalid_detection_is_rejected_before_policy(self):
        result = DetectionResult(event_id=0, matched=True, reason="bad")
        with self.assertRaises(ValueError):
            decide_alert_only(result)

    def test_privileged_action_cannot_validate(self):
        result = DetectionResult.from_regex_match(33, ("XSS", "BLOCK", "7", 2))
        decision = decide_alert_only(result)
        object.__setattr__(decision, "action", "BLOCK")
        with self.assertRaises(ValueError):
            decision.validate()


if __name__ == "__main__":
    unittest.main()
