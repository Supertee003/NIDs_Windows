#!/usr/bin/env python3
"""
test_fast_scan.py - Tests for Cython acceleration module (Phase 22)

Tests both the Cython module (if compiled) and Python fallbacks.
"""

import sys
import os
import unittest

# Add brain directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aegis_brain_cython.bridge import (
    scan_payload,
    get_severity,
    ip_in_list,
    extract_field,
    compute_defcon,
    check_payload_size,
    is_available,
)


class TestScanPayload(unittest.TestCase):
    def test_match_found(self):
        payload = b"GET /admin?id=1' OR '1'='1 HTTP/1.1"
        patterns = [b"SQL_INJECTION", b"OR '1'='1", b"XSS"]
        idx, matched = scan_payload(payload, patterns)
        self.assertEqual(idx, 1)
        self.assertEqual(matched, b"OR '1'='1")

    def test_no_match(self):
        payload = b"GET /index.html HTTP/1.1"
        patterns = [b"SQL_INJECTION", b"XSS_SCRIPT"]
        idx, matched = scan_payload(payload, patterns)
        self.assertEqual(idx, -1)
        self.assertIsNone(matched)

    def test_empty_payload(self):
        payload = b""
        patterns = [b"test"]
        idx, matched = scan_payload(payload, patterns)
        self.assertEqual(idx, -1)

    def test_empty_patterns(self):
        payload = b"test data"
        patterns = []
        idx, matched = scan_payload(payload, patterns)
        self.assertEqual(idx, -1)

    def test_first_pattern_matches(self):
        payload = b"malware.exe payload"
        patterns = [b"malware", b"virus", b"trojan"]
        idx, matched = scan_payload(payload, patterns)
        self.assertEqual(idx, 0)
        self.assertEqual(matched, b"malware")


class TestGetSeverity(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(get_severity("Critical"), 3)

    def test_high(self):
        self.assertEqual(get_severity("High"), 2)

    def test_medium(self):
        self.assertEqual(get_severity("Medium"), 1)

    def test_low(self):
        self.assertEqual(get_severity("Low"), 0)

    def test_unknown(self):
        self.assertEqual(get_severity("Unknown"), -1)

    def test_empty(self):
        self.assertEqual(get_severity(""), -1)


class TestIpInList(unittest.TestCase):
    def test_ip_in_list(self):
        ip_list = [0x0A000001, 0x0A000002, 0x0A000003]
        self.assertTrue(ip_in_list(0x0A000002, ip_list))

    def test_ip_not_in_list(self):
        ip_list = [0x0A000001, 0x0A000002]
        self.assertFalse(ip_in_list(0x0A000099, ip_list))

    def test_empty_list(self):
        self.assertFalse(ip_in_list(0x0A000001, []))


class TestComputeDefcon(unittest.TestCase):
    def test_defcon_1_critical(self):
        self.assertEqual(compute_defcon(1, 0, 0, 0), 1)

    def test_defcon_2_severe(self):
        self.assertEqual(compute_defcon(0, 3, 0, 0), 2)

    def test_defcon_3_elevated(self):
        self.assertEqual(compute_defcon(0, 0, 10, 0), 3)

    def test_defcon_4_guarded(self):
        self.assertEqual(compute_defcon(0, 0, 1, 0), 4)

    def test_defcon_5_normal(self):
        self.assertEqual(compute_defcon(0, 0, 0, 0), 5)

    def test_critical_overrides_all(self):
        self.assertEqual(compute_defcon(1, 10, 100, 100), 1)


class TestExtractField(unittest.TestCase):
    def test_extract_rule(self):
        json_bytes = b'{"rule":"SQL_INJECTION","level":"critical"}'
        result = extract_field(json_bytes, "rule")
        self.assertEqual(result, "SQL_INJECTION")

    def test_extract_level(self):
        json_bytes = b'{"rule":"R1","level":"warn"}'
        result = extract_field(json_bytes, "level")
        self.assertEqual(result, "warn")

    def test_field_not_found(self):
        json_bytes = b'{"rule":"R1"}'
        result = extract_field(json_bytes, "nonexistent")
        self.assertIsNone(result)


class TestCheckPayloadSize(unittest.TestCase):
    def test_payload_under_limit(self):
        self.assertFalse(check_payload_size(b"small", 100))

    def test_payload_over_limit(self):
        self.assertTrue(check_payload_size(b"x" * 200, 100))

    def test_payload_equal_limit(self):
        self.assertFalse(check_payload_size(b"x" * 100, 100))


if __name__ == "__main__":
    print(f"Cython available: {is_available()}")
    unittest.main(verbosity=2)
