import unittest

from brain.core_routing import route_core_detection
from brain.detection_result import SCAN_MATCH, SCAN_UNKNOWN, DetectionResult


class CoreRoutingTests(unittest.TestCase):
    def test_match_is_policy_route_without_tier3_request(self):
        detection = DetectionResult(event_id=1, matched=True, rule_id=10, reason="match", scan_status=SCAN_MATCH)
        decision = route_core_detection(detection, tier3_available=False)
        self.assertEqual(decision.route.route, "POLICY")
        self.assertIsNone(decision.tier3_request)

    def test_unknown_creates_identity_bound_tier3_request(self):
        detection = DetectionResult(event_id=2, reason="ambiguous", scan_status=SCAN_UNKNOWN)
        decision = route_core_detection(detection, tier3_available=True)
        self.assertEqual(decision.route.route, "TIER3")
        self.assertIsNotNone(decision.tier3_request)
        self.assertEqual(decision.tier3_request.event_id, 2)

    def test_unknown_without_tier3_is_fail_closed_without_request(self):
        detection = DetectionResult(event_id=3, reason="ambiguous", scan_status=SCAN_UNKNOWN)
        decision = route_core_detection(detection, tier3_available=False)
        self.assertEqual(decision.route.route, "FAIL_CLOSED")
        self.assertIsNone(decision.tier3_request)


if __name__ == "__main__":
    unittest.main()
