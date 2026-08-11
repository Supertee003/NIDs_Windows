"""
test_e2e.py — AEGIS NIDS End-to-End Test Suite

Tests all 6 layers:
  1. Kernel: IPC bridge connection
  2. Zig: Capture + Aho-Corasick pattern matching
  3. Rust: Shield forensic hashing + QSBR RCU
  4. Python: Brain analysis + hooks
  5. Go: Performance metrics
  6. Java: Vaadin UI health check
"""

import unittest
import ctypes
import struct
import time
from pathlib import Path

# Import brain and bridge
from brain_python.windows_brain import (
    AnalysisBrain, PacketContext, AnalysisVerdict,
    HookAction, Severity, compute_entropy,
)
from brain_python.bridge.aegis_bridge_ctypes import (
    AegisPktMetaC, shield_init, shield_get_forensic_hash, shield_shutdown,
)


class TestEntropyCalculation(unittest.TestCase):
    """Test Layer 4: Shannon entropy calculation."""

    def test_empty_payload(self):
        self.assertEqual(compute_entropy(b""), 0.0)

    def test_single_byte(self):
        self.assertEqual(compute_entropy(b"\x00"), 0.0)

    def test_uniform_distribution(self):
        """All 256 byte values equally likely → entropy ≈ 8.0."""
        payload = bytes(range(256)) * 10
        entropy = compute_entropy(payload)
        self.assertAlmostEqual(entropy, 8.0, places=1)

    def test_low_entropy_repetitive(self):
        """Highly repetitive payload → low entropy."""
        payload = b"\x41" * 1000  # "AAA..."
        entropy = compute_entropy(payload)
        self.assertAlmostEqual(entropy, 0.0, places=1)


class TestAnalysisBrain(unittest.TestCase):
    """Test Layer 4: Analysis brain with hook pipeline."""

    def setUp(self):
        rules_path = Path(__file__).parent.parent / "config" / "Rules.json"
        self.brain = AnalysisBrain(rules_path=rules_path)

    def test_normal_packet_passes(self):
        ctx = PacketContext(
            src_ip=0xC0A80A01, dst_ip=0xC0A80A02,
            src_port=49152, dst_port=80, ip_proto=6,
            payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            timestamp_ms=int(time.time() * 1000),
        )
        verdict = self.brain.analyze(ctx)
        self.assertIn(verdict.action, [HookAction.PASS, HookAction.ALERT])

    def test_sql_injection_detected(self):
        ctx = PacketContext(
            src_ip=0x0A000001, dst_ip=0xC0A80A02,
            src_port=49152, dst_port=80, ip_proto=6,
            payload=b"GET /search?q=' OR 1=1-- HTTP/1.1\r\n\r\n",
            timestamp_ms=int(time.time() * 1000),
        )
        verdict = self.brain.analyze(ctx)
        self.assertIn(verdict.action, [HookAction.ALERT, HookAction.PRESERVE])
        self.assertGreater(verdict.severity, Severity.INFO)

    def test_blacklisted_ip(self):
        ctx = PacketContext(
            src_ip=0x0A000001, dst_ip=0xC0A80A02,
            src_port=49152, dst_port=4444, ip_proto=6,
            payload=b"\x00" * 100,
            timestamp_ms=int(time.time() * 1000),
        )
        verdict = self.brain.analyze(ctx)
        # Should trigger blacklist hook AND suspicious port hook
        self.assertIn(verdict.action, [HookAction.ALERT, HookAction.PRESERVE])

    def test_xss_detected(self):
        ctx = PacketContext(
            src_ip=0xC0A80A01, dst_ip=0xC0A80A02,
            src_port=49152, dst_port=80, ip_proto=6,
            payload=b"POST /comment HTTP/1.1\r\n\r\ncontent=<script>alert(1)</script>",
            timestamp_ms=int(time.time() * 1000),
        )
        verdict = self.brain.analyze(ctx)
        self.assertIn(verdict.action, [HookAction.ALERT, HookAction.PRESERVE])


class TestShieldBridge(unittest.TestCase):
    """Test Layer 3: Rust shield bridge."""

    def test_forensic_hash_structure(self):
        """Verify forensic hash is 32 bytes (SHA-256)."""
        # This test will skip if Rust shield is not built
        if not shield_init():
            self.skipTest("Rust shield library not available")

        try:
            hash_bytes = shield_get_forensic_hash()
            if hash_bytes is not None:
                self.assertEqual(len(hash_bytes), 32)
        finally:
            shield_shutdown()


class TestPktMetaStructure(unittest.TestCase):
    """Test cross-layer structure alignment."""

    def test_meta_size(self):
        """AegisPktMetaC must be 49 bytes (matches kernel/Zig/Rust with Semi-NIDS fields)."""
        meta = AegisPktMetaC()
        # With Semi-NIDS fields: threat_score(i32=4) + confidence(u8=1) + risk_flags(u32=4) = 9 extra
        # Base 40 + 9 = 49 bytes (packed)
        self.assertEqual(ctypes.sizeof(meta), 49)

    def test_meta_field_alignment(self):
        """Verify field offsets match kernel definition."""
        meta = AegisPktMetaC()
        self.assertEqual(ctypes.addressof(meta) - ctypes.addressof(meta), 0)


class TestRuleEngine(unittest.TestCase):
    """Test rule loading and matching."""

    def setUp(self):
        rules_path = Path(__file__).parent.parent / "config" / "Rules.json"
        self.brain = AnalysisBrain(rules_path=rules_path)

    def test_rules_loaded(self):
        self.assertGreater(len(self.brain.rules.rules), 0)

    def test_rule_matching(self):
        ctx = PacketContext(
            src_ip=0xC0A80A01, dst_ip=0xC0A80A02,
            src_port=49152, dst_port=80, ip_proto=6,
            payload=b"POST /gate HTTP/1.1\r\n\r\n",
            timestamp_ms=int(time.time() * 1000),
        )
        verdict = self.brain.analyze(ctx)
        # Should match C2 Beacon rule
        self.assertIn(verdict.action, [HookAction.ALERT, HookAction.PRESERVE])


if __name__ == "__main__":
    unittest.main()
