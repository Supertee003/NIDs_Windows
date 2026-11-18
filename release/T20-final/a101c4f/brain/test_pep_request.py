import unittest

from brain.core_routing import route_core_detection
from brain.detection_result import SCAN_MATCH, SCAN_UNKNOWN, DetectionResult
from brain.pep_request import (
    ACTION_ALERT,
    ACTION_BLOCK,
    pep_request_from_routing,
)


class PepRequestTests(unittest.TestCase):
    def test_policy_route_creates_identity_bound_request(self):
        detection = DetectionResult(
            event_id=11,
            matched=True,
            rule_id=44,
            severity=2,
            reason="signature_match:test",
            scan_status=SCAN_MATCH,
        )
        routing = route_core_detection(detection, tier3_available=False)
        request = pep_request_from_routing(
            routing,
            request_id=101,
            trace_id=202,
            audit_id=303,
            policy_id=44,
            requested_action=ACTION_ALERT,
        )
        self.assertIsNotNone(request)
        self.assertEqual(request.event_id, 11)
        self.assertEqual(request.policy_id, 44)
        self.assertEqual(request.severity, 2)

    def test_unknown_route_never_creates_pep_request(self):
        detection = DetectionResult(event_id=12, reason="ambiguous", scan_status=SCAN_UNKNOWN)
        routing = route_core_detection(detection, tier3_available=False)
        request = pep_request_from_routing(
            routing,
            request_id=102,
            trace_id=203,
            audit_id=304,
            policy_id=0,
        )
        self.assertIsNone(request)

    def test_block_request_is_still_only_a_request(self):
        detection = DetectionResult(
            event_id=13,
            matched=True,
            rule_id=45,
            severity=3,
            reason="critical_match",
            scan_status=SCAN_MATCH,
        )
        routing = route_core_detection(detection, tier3_available=False)
        request = pep_request_from_routing(
            routing,
            request_id=103,
            trace_id=204,
            audit_id=305,
            policy_id=45,
            caller_capability_mask=1,
            requested_action=ACTION_BLOCK,
        )
        self.assertEqual(request.requested_action, ACTION_BLOCK)
        self.assertFalse(hasattr(request, "host_effect_confirmed"))
        self.assertFalse(hasattr(request, "filter_id"))


if __name__ == "__main__":
    unittest.main()
