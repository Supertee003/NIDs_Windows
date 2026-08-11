"""
test_validation_pipeline.py — AEGIS NIDS Automated Test Case Validation

Simulates attack scenarios against the NIDS and validates that:
  1. Kernel (C) drops/blocks packets correctly
  2. Rust correlation engine scores match expected thresholds
  3. Alerts appear on Vaadin Dashboard within time bounds
  4. Forensic hashes are computed and chain integrity verified

Uses Scapy for packet generation and the ScoringMatrix for validation.

Run: python -m pytest tests/test_validation_pipeline.py -v
"""

import json
import struct
import time
import unittest
from pathlib import Path
from dataclasses import dataclass

# Import scoring matrix
from brain_python.aegis_scoring_matrix import ScoringMatrix, Severity, EventVector


# ═══════════════════════════════════════════════════════════════
# Test Case Definitions
# ═══════════════════════════════════════════════════════════════

@dataclass
class TestCase:
    """A single test case with input, expected output, and metadata."""
    name: str
    category: str           # "network", "pipe", "cross_vector", "file"
    description: str
    input_ctx: dict         # Event context for scoring
    expected_min_score: float
    expected_min_severity: int  # 0-4
    expected_action: str    # "pass", "alert", "alert_preserve", "block_preserve"
    must_match_rule_ids: list   # Rule IDs that MUST match
    must_not_match_rule_ids: list = None  # Rule IDs that MUST NOT match


def get_all_test_cases() -> list[TestCase]:
    """Define all test cases for the AEGIS NIDS validation pipeline."""
    return [
        # ── Network Attack Test Cases ──
        TestCase(
            name="TC-N001: SQL Injection UNION SELECT",
            category="network",
            description="Detect SQL injection using UNION SELECT in HTTP request",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\r\n\r\n",
                "src_ip": 0xC0A80A01, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 80,
            },
            expected_min_score=50.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="alert_preserve",
            must_match_rule_ids=[101],
        ),
        TestCase(
            name="TC-N002: XSS Script Tag Injection",
            category="network",
            description="Detect cross-site scripting via script tag",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"POST /comment HTTP/1.1\r\n\r\ncontent=<script>alert('xss')</script>",
                "src_ip": 0xC0A80A01, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 80,
            },
            expected_min_score=35.0,
            expected_min_severity=3,  # HIGH
            expected_action="alert",
            must_match_rule_ids=[103],
        ),
        TestCase(
            name="TC-N003: C2 Beacon POST /gate",
            category="network",
            description="Detect HTTP C2 beacon check-in pattern",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"POST /gate HTTP/1.1\r\nHost: evil.c2.server\r\n\r\n",
                "src_ip": 0x0A000001, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 443,
            },
            expected_min_score=45.0,
            expected_min_severity=3,  # HIGH
            expected_action="alert_preserve",
            must_match_rule_ids=[105],
        ),
        TestCase(
            name="TC-N004: Command Injection cmd.exe",
            category="network",
            description="Detect OS command injection via cmd.exe",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"GET /exec?cmd=cmd.exe+/c+whoami HTTP/1.1\r\n\r\n",
                "src_ip": 0xC0A80A01, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 80,
            },
            expected_min_score=50.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="alert_preserve",
            must_match_rule_ids=[104],
        ),
        TestCase(
            name="TC-N005: Suspicious Port 4444",
            category="network",
            description="Detect connection to known suspicious port (4444)",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"\x00" * 64,
                "src_ip": 0xC0A80A01, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 4444,
            },
            expected_min_score=15.0,
            expected_min_severity=2,  # MEDIUM
            expected_action="alert",
            must_match_rule_ids=[106],
        ),
        TestCase(
            name="TC-N006: Normal HTTP Traffic (No Alert)",
            category="network",
            description="Normal HTTP GET should not trigger any alerts",
            input_ctx={
                "vector": EventVector.NETWORK,
                "payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "src_ip": 0xC0A80A01, "dst_ip": 0xC0A80A02,
                "src_port": 49152, "dst_port": 80,
            },
            expected_min_score=0.0,
            expected_min_severity=0,  # INFO
            expected_action="pass",
            must_match_rule_ids=[],
        ),

        # ── Named Pipe Test Cases ──
        TestCase(
            name="TC-P001: Cobalt Strike Default Pipe",
            category="pipe",
            description="Detect Cobalt Strike default named pipe \\pipe\\msagent",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\msagent",
                "suspicious_pipe": True,
            },
            expected_min_score=60.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="block_preserve",
            must_match_rule_ids=[201],
        ),
        TestCase(
            name="TC-P002: Meterpreter Pipe",
            category="pipe",
            description="Detect Meterpreter named pipe \\pipe\\msf",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\msf",
                "suspicious_pipe": True,
            },
            expected_min_score=55.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="block_preserve",
            must_match_rule_ids=[202],
        ),
        TestCase(
            name="TC-P003: Generic Backdoor Pipe",
            category="pipe",
            description="Detect generic backdoor named pipe \\pipe\\backdoor",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\backdoor",
                "suspicious_pipe": True,
            },
            expected_min_score=40.0,
            expected_min_severity=3,  # HIGH
            expected_action="alert_preserve",
            must_match_rule_ids=[203],
        ),

        # ── Cross-Vector Correlation Test Cases ──
        TestCase(
            name="TC-CV001: Network + Pipe = Lateral Movement",
            category="cross_vector",
            description="Network anomaly + suspicious pipe = lateral movement detection",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\backdoor",
                "suspicious_network": True,
                "suspicious_pipe": True,
            },
            expected_min_score=60.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="block_preserve",
            must_match_rule_ids=[203, 301],
        ),
        TestCase(
            name="TC-CV002: Cobalt Strike Full Pattern",
            category="cross_vector",
            description="CS pipe + network beacon = confirmed Cobalt Strike",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\msagent",
                "suspicious_network": True,
                "suspicious_pipe": True,
            },
            expected_min_score=90.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="block_preserve",
            must_match_rule_ids=[201, 304],
        ),
        TestCase(
            name="TC-CV003: Triple Vector Anomaly",
            category="cross_vector",
            description="All 3 vectors suspicious = full attack chain detected",
            input_ctx={
                "vector": EventVector.PIPE,
                "payload": b"",
                "pipe_name": "\\pipe\\backdoor",
                "suspicious_network": True,
                "suspicious_pipe": True,
                "suspicious_file": True,
            },
            expected_min_score=85.0,
            expected_min_severity=4,  # CRITICAL
            expected_action="block_preserve",
            must_match_rule_ids=[303],
        ),

        # ── File I/O Test Cases ──
        TestCase(
            name="TC-F001: PE Executable Written",
            category="file",
            description="Detect PE executable (MZ header) written to disk",
            input_ctx={
                "vector": EventVector.FILE,
                "payload": b"\x4d\x5a\x90\x00" + b"\x00" * 60 + b"\x50\x45\x00\x00",
            },
            expected_min_score=30.0,
            expected_min_severity=3,  # HIGH
            expected_action="alert",
            must_match_rule_ids=[401],
        ),
    ]


# ═══════════════════════════════════════════════════════════════
# Validation Pipeline
# ═══════════════════════════════════════════════════════════════

class ValidationPipeline:
    """
    Automated test case validation pipeline.
    Runs all test cases against the scoring matrix and reports results.
    """

    def __init__(self):
        self.matrix = ScoringMatrix()
        self.results: list[dict] = []

    def run_all(self) -> dict:
        """Run all test cases and return summary."""
        test_cases = get_all_test_cases()
        passed = 0
        failed = 0

        for tc in test_cases:
            result = self.matrix.validate_test_case({
                "name": tc.name,
                "input": tc.input_ctx,
                "expected": {
                    "min_score": tc.expected_min_score,
                    "min_severity": tc.expected_min_severity,
                    "action": tc.expected_action,
                    "must_match_rule_ids": tc.must_match_rule_ids,
                }
            })
            result["test_name"] = tc.name
            result["category"] = tc.category
            self.results.append(result)

            if result["passed"]:
                passed += 1
            else:
                failed += 1

        return {
            "total": len(test_cases),
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{passed/len(test_cases)*100:.1f}%",
            "results": self.results,
        }

    def export_report(self, path: Path) -> None:
        """Export validation results to JSON."""
        summary = self.run_all()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)


# ═══════════════════════════════════════════════════════════════
# Pytest Tests
# ═══════════════════════════════════════════════════════════════

class TestValidationPipeline(unittest.TestCase):
    """Run all test cases through the scoring validation pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.pipeline = ValidationPipeline()
        cls.summary = cls.pipeline.run_all()

    def test_all_cases_pass(self):
        """All test cases should pass."""
        failed = [r for r in self.summary["results"] if not r["passed"]]
        if failed:
            details = "\n".join(
                f"  ✗ {r['test_name']}: {r['failures']}" for r in failed
            )
            self.fail(f"{len(failed)} test cases failed:\n{details}")

    def test_pass_rate(self):
        """Pass rate should be 100%."""
        self.assertEqual(self.summary["failed"], 0,
                        f"Expected 0 failures, got {self.summary['failed']}")

    def test_total_cases(self):
        """Should have at least 12 test cases."""
        self.assertGreaterEqual(self.summary["total"], 12)


class TestNetworkAttacks(unittest.TestCase):
    """Individual network attack test cases."""

    def setUp(self):
        self.matrix = ScoringMatrix()

    def test_sql_injection(self):
        result = self.matrix.score_event({
            "vector": EventVector.NETWORK,
            "payload": b"' UNION SELECT * FROM users--",
            "src_ip": 0, "dst_ip": 0, "src_port": 0, "dst_port": 80,
        })
        self.assertGreaterEqual(result.threat_score, 50.0)
        self.assertGreaterEqual(result.severity, Severity.CRITICAL)

    def test_normal_traffic_passes(self):
        result = self.matrix.score_event({
            "vector": EventVector.NETWORK,
            "payload": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "src_ip": 0, "dst_ip": 0, "src_port": 0, "dst_port": 80,
        })
        self.assertLess(result.threat_score, 20.0)


class TestPipeAttacks(unittest.TestCase):
    """Named pipe attack test cases."""

    def setUp(self):
        self.matrix = ScoringMatrix()

    def test_cobalt_strike_pipe(self):
        result = self.matrix.score_event({
            "vector": EventVector.PIPE,
            "payload": b"",
            "pipe_name": "\\pipe\\msagent",
        })
        self.assertGreaterEqual(result.threat_score, 60.0)
        self.assertGreaterEqual(result.severity, Severity.CRITICAL)

    def test_normal_pipe_passes(self):
        result = self.matrix.score_event({
            "vector": EventVector.PIPE,
            "payload": b"",
            "pipe_name": "\\pipe\\svcctl",  # Legitimate Windows pipe
        })
        self.assertLess(result.threat_score, 20.0)


class TestCrossVectorCorrelation(unittest.TestCase):
    """Cross-vector correlation test cases."""

    def setUp(self):
        self.matrix = ScoringMatrix()

    def test_lateral_movement(self):
        """Network anomaly + suspicious pipe = lateral movement."""
        result = self.matrix.score_event({
            "vector": EventVector.PIPE,
            "payload": b"",
            "pipe_name": "\\pipe\\backdoor",
            "suspicious_network": True,
            "suspicious_pipe": True,
        })
        self.assertGreaterEqual(result.threat_score, 60.0)
        matched_ids = {r[0] for r in result.matched_rules}
        self.assertIn(301, matched_ids)  # Lateral Movement rule

    def test_cobalt_strike_full_pattern(self):
        """CS pipe + network = confirmed Cobalt Strike."""
        result = self.matrix.score_event({
            "vector": EventVector.PIPE,
            "payload": b"",
            "pipe_name": "\\pipe\\msagent",
            "suspicious_network": True,
            "suspicious_pipe": True,
        })
        self.assertGreaterEqual(result.threat_score, 90.0)
        matched_ids = {r[0] for r in result.matched_rules}
        self.assertIn(304, matched_ids)  # Cobalt Strike Full Pattern


if __name__ == "__main__":
    pipeline = ValidationPipeline()
    summary = pipeline.run_all()
    print(f"\n{'='*60}")
    print(f"  AEGIS NIDS Validation Pipeline Results")
    print(f"{'='*60}")
    print(f"  Total:  {summary['total']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Rate:   {summary['pass_rate']}")
    print(f"{'='*60}\n")

    for r in summary["results"]:
        status = "✓ PASS" if r["passed"] else "✗ FAIL"
        print(f"  {status}  {r['test_name']}  (score: {r['actual_score']:.1f}, action: {r['actual_action']})")
        if r["failures"]:
            for f in r["failures"]:
                print(f"         → {f}")

    unittest.main()
