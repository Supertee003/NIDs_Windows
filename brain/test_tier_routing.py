import unittest

from brain.detection_result import (
    SCAN_ERROR,
    SCAN_MATCH,
    SCAN_UNKNOWN,
    DetectionResult,
)
from brain.tier_routing import (
    ROUTE_COMPLETE,
    ROUTE_FAIL_CLOSED,
    ROUTE_POLICY,
    ROUTE_TIER3,
    route_detection,
)


class TierRoutingTests(unittest.TestCase):
    def test_match_routes_to_policy_without_tier3(self):
        result = DetectionResult(event_id=1, matched=True, rule_id=42, reason="match", scan_status=SCAN_MATCH)
        route = route_detection(result, tier3_available=False)
        self.assertEqual(route.route, ROUTE_POLICY)
        self.assertFalse(route.tier3_required)

    def test_no_match_completes_without_tier3(self):
        result = DetectionResult(event_id=2, reason="no_match")
        route = route_detection(result, tier3_available=False)
        self.assertEqual(route.route, ROUTE_COMPLETE)

    def test_unknown_routes_to_tier3_when_available(self):
        result = DetectionResult(event_id=3, scan_status=SCAN_UNKNOWN, reason="ambiguous")
        route = route_detection(result, tier3_available=True)
        self.assertEqual(route.route, ROUTE_TIER3)
        self.assertTrue(route.tier3_required)

    def test_unknown_fails_closed_when_tier3_unavailable(self):
        result = DetectionResult(event_id=4, scan_status=SCAN_UNKNOWN, reason="ambiguous")
        route = route_detection(result, tier3_available=False)
        self.assertEqual(route.route, ROUTE_FAIL_CLOSED)
        self.assertFalse(route.tier3_available)

    def test_error_fails_closed_when_tier3_unavailable(self):
        result = DetectionResult(event_id=5, scan_status=SCAN_ERROR, reason="scanner_error")
        route = route_detection(result, tier3_available=False)
        self.assertEqual(route.route, ROUTE_FAIL_CLOSED)


if __name__ == "__main__":
    unittest.main()
