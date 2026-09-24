import unittest

from brain.detection_result import DetectionResult


class DetectionResultTests(unittest.TestCase):
    def test_regex_match_maps_to_explainable_detection(self):
        result = DetectionResult.from_regex_match(
            17, ("SQLI", "BLOCK", "42", 3)
        )
        self.assertEqual(result.event_id, 17)
        self.assertTrue(result.matched)
        self.assertEqual(result.rule_id, 42)
        self.assertEqual(result.severity, 3)
        self.assertTrue(result.reason.startswith("signature_match:"))
        self.assertNotIn("policy", result.to_dict())

    def test_non_numeric_rule_id_is_not_authorized_as_numeric_policy(self):
        result = DetectionResult.from_regex_match(
            18, ("XSS", "ALERT", "RULE-XSS", 2)
        )
        self.assertEqual(result.rule_id, 0)
        self.assertTrue(result.matched)
        self.assertEqual(result.reason, "signature_match:XSS")

    def test_no_match_is_valid_and_explainable(self):
        result = DetectionResult.from_regex_match(19, None)
        self.assertFalse(result.matched)
        self.assertEqual(result.reason, "no_match")
        result.validate()

    def test_matched_without_reason_is_rejected(self):
        with self.assertRaises(ValueError):
            DetectionResult(event_id=20, matched=True).validate()


if __name__ == "__main__":
    unittest.main()
