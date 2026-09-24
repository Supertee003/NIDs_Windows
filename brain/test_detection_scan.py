import unittest

from brain.detection_result import SCAN_ERROR, SCAN_MATCH, SCAN_NO_MATCH, SCAN_UNKNOWN
from brain.detection_scan import result_from_scan, scan_to_detection_result


class DetectionScanParityTests(unittest.TestCase):
    def test_python_and_cython_shape_maps_to_same_match_result(self):
        py_tuple = ("rule-a", "ALERT", "42", 2)
        cy_tuple = (b"rule-a", b"ALERT", b"42", 2, 0)
        py_result = result_from_scan(10, py_tuple)
        cy_result = result_from_scan(10, cy_tuple)
        self.assertEqual(py_result.scan_status, SCAN_MATCH)
        self.assertEqual(py_result.to_dict(), cy_result.to_dict())

    def test_no_match_maps_to_no_match(self):
        result = result_from_scan(11, None)
        self.assertEqual(result.scan_status, SCAN_NO_MATCH)
        self.assertFalse(result.matched)

    def test_unknown_is_preserved_for_tier_routing(self):
        result = result_from_scan(12, None, scan_status=SCAN_UNKNOWN)
        self.assertEqual(result.scan_status, SCAN_UNKNOWN)

    def test_scanner_exception_becomes_error_data(self):
        def broken(*_args):
            raise RuntimeError("bad extension")
        result = scan_to_detection_result(13, "payload", {}, {}, broken)
        self.assertEqual(result.scan_status, SCAN_ERROR)
        self.assertFalse(result.matched)

    def test_scanner_output_does_not_copy_policy_as_authority(self):
        result = result_from_scan(14, ("rule", "BLOCK", "99", 3))
        self.assertEqual(result.scan_status, SCAN_MATCH)
        self.assertEqual(result.rule_id, 99)
        self.assertFalse(hasattr(result, "action"))
        self.assertFalse(hasattr(result, "host_effect_confirmed"))


if __name__ == "__main__":
    unittest.main()
