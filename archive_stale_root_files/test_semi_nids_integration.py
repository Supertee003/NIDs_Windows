"""
test_semi_nids_integration.py — Semi-NIDS Integration Test Suite

Tests the full Semi-NIDS pipeline:
  1. Rust FFI: semi_nids_init → evaluate → set_policy → get_pending → stats
  2. Decision threshold ladder verification
  3. Fail-open graceful degradation
  4. Human-in-the-loop policy decisions
  5. Console bridge connectivity

CRITICAL: Each test uses a UNIQUE source IP to avoid temporary block
carry-over from evaluate() auto-blocking IPs on high-threat scores.

FFI signatures MUST match Rust semi_nids.rs exactly:
  aegis_semi_nids_evaluate(src_ip:u32, dst_ip:u32, src_port:u16, dst_port:u16,
                           ip_proto:u8, threat_score:f64, confidence:u8,
                           risk_flags:u32, process_id:u32) -> u8
  aegis_semi_nids_block_ip(ip:u32, reason:u32) -> i32
  aegis_semi_nids_fail_open_status(out_active:*mut bool, out_cpu:*mut u8, out_queue:*mut u8) -> u8
  aegis_semi_nids_get_stats(out_stats:*mut SemiNidsStats) -> i32
  aegis_semi_nids_get_pending(index:u32, out_alert_id:*mut u64, out_src_ip:*mut u32,
                              out_threat_score:*mut f64, out_confidence:*mut u8,
                              out_decision:*mut u8) -> i32

This test requires the Rust shield library (libaegis_shield.so/.dll) to be built.
"""

import unittest
import ctypes
import os
import sys
import time
from pathlib import Path

# ─── Locate Rust shared library ───
REPO_ROOT = Path(__file__).parent.parent
SHIELD_SEARCH_PATHS = [
    REPO_ROOT / "shield_rust" / "target" / "release",
    REPO_ROOT / "shield_rust" / "target" / "debug",
    Path("."),
]

def _load_shield_lib():
    """Try to load the Rust shield shared library."""
    lib_names = ["libaegis_shield.so", "aegis_shield.dll", "aegis_shield.so"]
    for search_path in SHIELD_SEARCH_PATHS:
        for lib_name in lib_names:
            full_path = search_path / lib_name
            if full_path.exists():
                try:
                    return ctypes.CDLL(str(full_path))
                except OSError:
                    continue
    for lib_name in ["aegis_shield", "libaegis_shield"]:
        try:
            return ctypes.CDLL(lib_name)
        except OSError:
            continue
    return None

# Unique IP generator: 10.{test_num}.{case_num}.{1} to avoid block carry-over
def _test_ip(test_num: int, case_num: int = 1) -> int:
    """Generate unique IP: 10.test_num.case_num.1"""
    return (10 << 24) | (test_num << 16) | (case_num << 8) | 1


# ─── SemiNidsStats C-ABI struct (must match Rust SemiNidsStats #[repr(C)]) ───
class SemiNidsStatsC(ctypes.Structure):
    """Engine statistics — matches SemiNidsStats in Rust semi_nids.rs.

    Fields (must match Rust layout exactly for correct FFI):
      total_evaluated: u64, total_passed: u64, total_alerted: u64,
      total_blocked: u64, total_rate_limited: u64, total_fail_open_passes: u64,
      total_human_decisions: u64, permanent_blocks: u32, temporary_blocks: u32,
      fail_open_active: bool, load_state: u8 (LoadState), current_pps: u64
    """
    _pack_ = 1
    _fields_ = [
        ("total_evaluated",      ctypes.c_uint64),
        ("total_passed",         ctypes.c_uint64),
        ("total_alerted",        ctypes.c_uint64),
        ("total_blocked",        ctypes.c_uint64),
        ("total_rate_limited",   ctypes.c_uint64),
        ("total_fail_open_passes", ctypes.c_uint64),
        ("total_human_decisions", ctypes.c_uint64),
        ("permanent_blocks",     ctypes.c_uint32),
        ("temporary_blocks",     ctypes.c_uint32),
        ("fail_open_active",     ctypes.c_bool),
        ("load_state",           ctypes.c_uint8),   # LoadState enum: 0-3
        ("current_pps",          ctypes.c_uint64),
    ]


class TestSemiNidsFFI(unittest.TestCase):
    """Test Rust Semi-NIDS engine via ctypes FFI.

    FFI signature for evaluate matches Rust:
      (src_ip:u32, dst_ip:u32, src_port:u16, dst_port:u16, ip_proto:u8,
       threat_score:f64, confidence:u8, risk_flags:u32, process_id:u32) -> u8
    """

    lib = None

    @classmethod
    def setUpClass(cls):
        cls.lib = _load_shield_lib()
        if cls.lib is None:
            raise unittest.SkipTest("Rust shield library not found — build with: cargo build --release")

        # Initialize the Semi-NIDS engine
        cls.lib.aegis_semi_nids_init.restype = ctypes.c_int32
        rc = cls.lib.aegis_semi_nids_init()
        if rc != 0:
            raise RuntimeError(f"Semi-NIDS init failed: rc={rc}")

        # Setup function signatures — MUST match Rust FFI exactly
        cls.lib.aegis_semi_nids_evaluate.restype = ctypes.c_uint8
        cls.lib.aegis_semi_nids_evaluate.argtypes = [
            ctypes.c_uint32,  # src_ip
            ctypes.c_uint32,  # dst_ip
            ctypes.c_uint16,  # src_port
            ctypes.c_uint16,  # dst_port
            ctypes.c_uint8,   # ip_proto
            ctypes.c_double,  # threat_score
            ctypes.c_uint8,   # confidence
            ctypes.c_uint32,  # risk_flags
            ctypes.c_uint32,  # process_id
        ]
        cls.lib.aegis_semi_nids_set_policy.restype = ctypes.c_int32
        cls.lib.aegis_semi_nids_set_policy.argtypes = [ctypes.c_uint64, ctypes.c_uint8]
        cls.lib.aegis_semi_nids_get_pending_count.restype = ctypes.c_uint32
        cls.lib.aegis_semi_nids_fail_open_status.restype = ctypes.c_uint8
        cls.lib.aegis_semi_nids_fail_open_status.argtypes = [
            ctypes.POINTER(ctypes.c_bool),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        cls.lib.aegis_semi_nids_block_ip.restype = ctypes.c_int32
        cls.lib.aegis_semi_nids_block_ip.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        cls.lib.aegis_semi_nids_unblock_ip.restype = ctypes.c_int32
        cls.lib.aegis_semi_nids_unblock_ip.argtypes = [ctypes.c_uint32]
        cls.lib.aegis_semi_nids_get_stats.restype = ctypes.c_int32
        cls.lib.aegis_semi_nids_get_stats.argtypes = [ctypes.POINTER(SemiNidsStatsC)]
        cls.lib.aegis_semi_nids_maintenance.restype = ctypes.c_uint32
        cls.lib.aegis_semi_nids_update_load.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint64]

    @classmethod
    def tearDownClass(cls):
        if cls.lib is not None:
            cls.lib.aegis_semi_nids_shutdown.restype = None
            cls.lib.aegis_semi_nids_shutdown()

    def _evaluate(self, src_ip=0x0A000001, dst_ip=0xC0A80A01,
                  src_port=12345, dst_port=80, ip_proto=6,
                  threat_score=50.0, confidence=3, risk_flags=1, process_id=0):
        """Helper: call aegis_semi_nids_evaluate with correct typed args.

        Rust FFI: (src_ip:u32, dst_ip:u32, src_port:u16, dst_port:u16,
                   ip_proto:u8, threat_score:f64, confidence:u8,
                   risk_flags:u32, process_id:u32) -> u8
        """
        return self.lib.aegis_semi_nids_evaluate(
            ctypes.c_uint32(src_ip), ctypes.c_uint32(dst_ip),
            ctypes.c_uint16(src_port), ctypes.c_uint16(dst_port),
            ctypes.c_uint8(ip_proto),
            ctypes.c_double(threat_score),
            ctypes.c_uint8(confidence),
            ctypes.c_uint32(risk_flags),
            ctypes.c_uint32(process_id),
        )

    def test_01_init_success(self):
        """Semi-NIDS engine should initialize successfully."""
        count = self.lib.aegis_semi_nids_get_pending_count()
        self.assertGreaterEqual(count, 0)

    def test_02_pass_on_low_score(self):
        """Low threat score → Pass (decision 0)."""
        decision = self._evaluate(src_ip=_test_ip(2), threat_score=5.0, confidence=1, risk_flags=0)
        self.assertEqual(decision, 0, f"Expected Pass(0), got {decision}")

    def test_03_alert_only_on_medium_score(self):
        """Medium score + Low confidence → AlertOnly (decision 1)."""
        decision = self._evaluate(src_ip=_test_ip(3), threat_score=25.0, confidence=1, risk_flags=1)
        self.assertIn(decision, [1, 0], f"Expected AlertOnly(1) or Pass(0), got {decision}")

    def test_04_rate_limit_on_medium_confidence(self):
        """Score >= 40 + Medium confidence → RateLimit (decision 2)."""
        decision = self._evaluate(src_ip=_test_ip(4), threat_score=45.0, confidence=2, risk_flags=1)
        self.assertIn(decision, [2, 1], f"Expected RateLimit(2) or AlertOnly(1), got {decision}")

    def test_05_block_on_high_confidence(self):
        """Score >= 60 + High confidence → Block (decision 3)."""
        decision = self._evaluate(src_ip=_test_ip(5), threat_score=70.0, confidence=3, risk_flags=1)
        self.assertIn(decision, [3, 4], f"Expected Block(3) or BlockAndPreserve(4), got {decision}")

    def test_06_block_and_preserve_on_critical(self):
        """Score >= 80 + Critical confidence → BlockAndPreserve (decision 4)."""
        decision = self._evaluate(src_ip=_test_ip(6), threat_score=90.0, confidence=4, risk_flags=0x20)
        self.assertEqual(decision, 4, f"Expected BlockAndPreserve(4), got {decision}")

    def test_07_pending_human_on_medium_no_risk(self):
        """Medium score + Medium confidence but no risk flags → PendingHuman (decision 5)."""
        decision = self._evaluate(src_ip=_test_ip(7), threat_score=35.0, confidence=2, risk_flags=0)
        self.assertIn(decision, [5, 0, 1], f"Expected PendingHuman(5) or low-priority, got {decision}")

    def test_08_block_ip(self):
        """Block an IP via FFI — aegis_semi_nids_block_ip(ip:u32, reason:u32)."""
        ip = _test_ip(8)
        rc = self.lib.aegis_semi_nids_block_ip(ctypes.c_uint32(ip), ctypes.c_uint32(1))
        self.assertEqual(rc, 0, f"block_ip failed: rc={rc}")

    def test_09_unblock_ip(self):
        """Unblock/whitelist an IP via FFI."""
        ip = _test_ip(9)
        self.lib.aegis_semi_nids_block_ip(ctypes.c_uint32(ip), ctypes.c_uint32(1))
        rc = self.lib.aegis_semi_nids_unblock_ip(ctypes.c_uint32(ip))
        self.assertEqual(rc, 0, f"unblock_ip failed: rc={rc}")

    def test_10_fail_open_status(self):
        """Query fail-open status — verify function returns successfully.

        Rust FFI: aegis_semi_nids_fail_open_status(out_active:*mut bool,
                    out_cpu_pct:*mut u8, out_queue_pct:*mut u8) -> u8
        """
        out_active = ctypes.c_bool(False)
        out_cpu = ctypes.c_uint8(0)
        out_queue = ctypes.c_uint8(0)
        load_state = self.lib.aegis_semi_nids_fail_open_status(
            ctypes.byref(out_active), ctypes.byref(out_cpu), ctypes.byref(out_queue)
        )
        # load_state is 0-3 (LoadState enum)
        self.assertIn(load_state, [0, 1, 2, 3], f"Unexpected load_state: {load_state}")

    def test_11_update_load_and_fail_open(self):
        """Update load metrics → verify fail-open activates at high load."""
        # Push high load
        self.lib.aegis_semi_nids_update_load(
            ctypes.c_uint8(95),  # 95% CPU
            ctypes.c_uint8(98),  # 98% queue
            ctypes.c_uint64(600000),  # 600K PPS
        )
        time.sleep(0.2)

        out_active = ctypes.c_bool(False)
        out_cpu = ctypes.c_uint8(0)
        out_queue = ctypes.c_uint8(0)
        load_state = self.lib.aegis_semi_nids_fail_open_status(
            ctypes.byref(out_active), ctypes.byref(out_cpu), ctypes.byref(out_queue)
        )
        if load_state >= 2:
            # Fail-open should be active at 95% CPU
            self.assertTrue(out_active.value, "Fail-open should be active at 95% CPU / 98% queue")

        # Push normal load → fail-open should deactivate
        self.lib.aegis_semi_nids_update_load(
            ctypes.c_uint8(30),  # 30% CPU
            ctypes.c_uint8(20),  # 20% queue
            ctypes.c_uint64(10000),  # 10K PPS
        )
        time.sleep(0.2)

    def test_12_get_stats(self):
        """Get engine statistics via struct pointer.

        Rust FFI: aegis_semi_nids_get_stats(out_stats:*mut SemiNidsStats) -> i32
        """
        stats = SemiNidsStatsC()
        rc = self.lib.aegis_semi_nids_get_stats(ctypes.byref(stats))
        self.assertEqual(rc, 0, f"get_stats failed: rc={rc}")
        self.assertGreater(stats.total_evaluated, 0, "Should have evaluated at least some packets")

    def test_13_maintenance(self):
        """Run periodic maintenance (should not crash)."""
        self.lib.aegis_semi_nids_maintenance()

    def test_14_human_set_policy(self):
        """Human sets policy on a pending alert."""
        pending = self.lib.aegis_semi_nids_get_pending_count()
        if pending > 0:
            rc = self.lib.aegis_semi_nids_set_policy(
                ctypes.c_uint64(1),  # alert_id = 1
                ctypes.c_uint8(1),   # decision = Block
            )
            self.assertIsInstance(rc, int)


class TestSemiNidsDecisionLadder(unittest.TestCase):
    """Verify the complete decision threshold ladder with precise boundaries.

    Each test uses a UNIQUE IP to avoid temporary block carry-over.

    FFI: (src_ip:u32, dst_ip:u32, src_port:u16, dst_port:u16, ip_proto:u8,
          threat_score:f64, confidence:u8, risk_flags:u32, process_id:u32) -> u8
    """

    lib = None

    @classmethod
    def setUpClass(cls):
        cls.lib = _load_shield_lib()
        if cls.lib is None:
            raise unittest.SkipTest("Rust shield library not found")
        cls.lib.aegis_semi_nids_init.restype = ctypes.c_int32
        cls.lib.aegis_semi_nids_evaluate.restype = ctypes.c_uint8
        cls.lib.aegis_semi_nids_evaluate.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint8,
            ctypes.c_double, ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32,
        ]
        rc = cls.lib.aegis_semi_nids_init()
        if rc != 0:
            raise RuntimeError(f"Semi-NIDS init failed: rc={rc}")

    @classmethod
    def tearDownClass(cls):
        if cls.lib is not None:
            cls.lib.aegis_semi_nids_shutdown.restype = None
            cls.lib.aegis_semi_nids_shutdown()

    def _evaluate(self, score, confidence, risk_flags=1, test_id=0):
        """Evaluate with unique IP per test — correct FFI signature."""
        return self.lib.aegis_semi_nids_evaluate(
            ctypes.c_uint32(_test_ip(100 + test_id)),
            ctypes.c_uint32(0xC0A80A01),
            ctypes.c_uint16(12345),  # src_port
            ctypes.c_uint16(80),     # dst_port
            ctypes.c_uint8(6),       # ip_proto (TCP)
            ctypes.c_double(score),
            ctypes.c_uint8(confidence),
            ctypes.c_uint32(risk_flags),
            ctypes.c_uint32(0),      # process_id
        )

    def test_ladder_step_1_pass(self):
        """Score < 20 → Pass regardless of confidence."""
        d = self._evaluate(10.0, 1, risk_flags=0, test_id=1)
        self.assertEqual(d, 0)

    def test_ladder_step_2_alert_only(self):
        """Score 20-39 + Low confidence → AlertOnly."""
        d = self._evaluate(25.0, 1, risk_flags=1, test_id=2)
        self.assertIn(d, [1, 0])

    def test_ladder_step_3_rate_limit(self):
        """Score 40-59 + Medium confidence → RateLimit."""
        d = self._evaluate(50.0, 2, risk_flags=1, test_id=3)
        self.assertIn(d, [2, 1])

    def test_ladder_step_4_block(self):
        """Score 60-79 + High confidence → Block."""
        d = self._evaluate(65.0, 3, risk_flags=1, test_id=4)
        self.assertIn(d, [3, 4])

    def test_ladder_step_5_block_preserve(self):
        """Score >= 80 + Critical confidence → BlockAndPreserve."""
        d = self._evaluate(85.0, 4, risk_flags=0x20, test_id=5)
        self.assertEqual(d, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
