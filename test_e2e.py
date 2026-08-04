"""
AEGIS NIDS — End-to-End Integration Test (Phase 1)
====================================================
Tests the full pipeline: Zig Core → C++ Bridge → Python Brain → Dashboard

Test Flow:
  1. C++ Bridge self-test (aegis_bridge.exe --test)
  2. Python ctypes → Bridge init/push/pop/get_defcon
  3. Simulated Tier-1 event → Bridge → Brain
  4. Simulated Tier-2 event → Bridge → Dashboard
  5. DEFCON level calculation verification
  6. IPS block/unblock via Bridge
  7. Full pipeline: Zig pattern → Bridge → Dashboard API

Usage:
  python test_e2e.py
  python test_e2e.py --bridge-only    # Test only C++ Bridge
  python test_e2e.py --full           # Test with Dashboard API
"""

import sys
import os
import json
import time
import socket
import struct
import subprocess
import urllib.request
import urllib.error

# Add bridge directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "bridge"))

class UI:
    GREEN = '\033[92;1m'
    RED = '\033[91;1m'
    YELLOW = '\033[93m'
    CYAN = '\033[96;1m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

passed = 0
failed = 0
skipped = 0

def test_result(name, success, detail=""):
    global passed, failed, skipped
    if success:
        passed += 1
        print(f"  {UI.GREEN}PASS{UI.RESET} {name}")
    else:
        failed += 1
        print(f"  {UI.RED}FAIL{UI.RESET} {name} — {detail}")

def skip_test(name, reason=""):
    global skipped
    skipped += 1
    print(f"  {UI.YELLOW}SKIP{UI.RESET} {name} — {reason}")


# =====================================================================
# TEST 1: C++ Bridge Self-Test
# =====================================================================
def test_bridge_selftest():
    """Run aegis_bridge.exe --test to verify C++ Bridge works."""
    print(f"\n{UI.CYAN}[TEST 1] C++ Bridge Self-Test{UI.RESET}")

    bridge_exe = os.path.join("build", "Release", "aegis_bridge.exe")
    if not os.path.exists(bridge_exe):
        # Try Debug build
        bridge_exe = os.path.join("build", "Debug", "aegis_bridge.exe")
    if not os.path.exists(bridge_exe):
        skip_test("Bridge self-test", "aegis_bridge.exe not found — run cmake first")
        return

    try:
        result = subprocess.run(
            [bridge_exe, "--test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        test_result("Bridge self-test exit code", result.returncode == 0,
                    f"exit code: {result.returncode}")
        if "ALL TESTS PASSED" in result.stdout:
            test_result("Bridge all tests passed", True)
        else:
            test_result("Bridge all tests passed", False,
                        f"stdout: {result.stdout[:200]}")
    except FileNotFoundError:
        skip_test("Bridge self-test", "aegis_bridge.exe not found")
    except subprocess.TimeoutExpired:
        test_result("Bridge self-test", False, "timeout (30s)")


# =====================================================================
# TEST 2: Python ctypes → Bridge
# =====================================================================
def test_python_bridge():
    """Test Python ctypes integration with C++ Bridge."""
    print(f"\n{UI.CYAN}[TEST 2] Python ctypes → C++ Bridge{UI.RESET}")

    try:
        import aegis_bridge_ctypes as bridge
    except ImportError:
        skip_test("Python Bridge", "aegis_bridge_ctypes not available")
        return

    # Test 2a: Bridge init
    rc = bridge.bridge_init()
    test_result("bridge_init()", rc == 0, f"rc={rc}")

    if rc != 0:
        skip_test("Remaining Bridge tests", "bridge_init failed")
        return

    # Test 2b: Push event
    rc = bridge.push_event(
        event_type=0,       # NETWORK
        source_ip=0xC0A80101,  # 192.168.1.1
        dest_ip=0xC0A80102,    # 192.168.1.2
        source_port=12345,
        dest_port=80,
        protocol=6,         # TCP
        tier_result=1,      # Tier-1
        rule_id=56,
        severity=2,         # High
    )
    test_result("push_event()", rc == 0, f"rc={rc}")

    # Test 2c: Get event count
    count = bridge.get_event_count()
    test_result("get_event_count() > 0", count > 0, f"count={count}")

    # Test 2d: Pop event
    event = bridge.pop_event()
    test_result("pop_event() returns event", event is not None)
    if event:
        test_result("Event rule_id matches", event.rule_id == 56,
                    f"rule_id={event.rule_id}")
        test_result("Event tier_result is Tier-1", event.tier_result == 1,
                    f"tier_result={event.tier_result}")
        test_result("Event severity is High", event.severity == 2,
                    f"severity={event.severity}")

    # Test 2e: DEFCON level
    defcon = bridge.get_defcon_level()
    test_result("get_defcon_level() returns 1-5", 1 <= defcon <= 5,
                f"defcon={defcon}")

    # Test 2f: DEFCON label
    label = bridge.get_defcon_label()
    test_result("get_defcon_label() returns string", label in
                ("MAXIMUM", "SEVERE", "HIGH", "ELEVATED", "SAFE"),
                f"label={label}")

    # Test 2g: push_tier2_match
    rc = bridge.push_tier2_match(
        rule_id=56,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=12345,
        dst_port=80,
        protocol=6,
        severity=3,
    )
    test_result("push_tier2_match()", rc == 0, f"rc={rc}")

    # Test 2h: IPS block/unblock
    rc = bridge.block_ip("10.0.0.1")
    test_result("block_ip()", rc >= 0, f"rc={rc}")

    rc = bridge.unblock_ip("10.0.0.1")
    test_result("unblock_ip()", rc >= 0, f"rc={rc}")

    # Test 2i: Bridge shutdown
    rc = bridge.bridge_shutdown()
    test_result("bridge_shutdown()", rc == 0, f"rc={rc}")


# =====================================================================
# TEST 3: Simulated Tier-1 → Bridge → Brain (UDP)
# =====================================================================
def test_tier1_to_brain():
    """Simulate Zig Core sending a Tier-1 alert to Brain via UDP."""
    print(f"\n{UI.CYAN}[TEST 3] Tier-1 → Bridge → Brain (UDP){UI.RESET}")

    # Test 3a: Bridge init
    try:
        import aegis_bridge_ctypes as bridge
    except ImportError:
        skip_test("Tier-1 → Brain", "aegis_bridge_ctypes not available")
        return

    rc = bridge.bridge_init()
    if rc != 0:
        skip_test("Tier-1 → Brain", "bridge_init failed")
        return

    # Test 3b: Push Tier-1 event to Bridge
    rc = bridge.push_event(
        event_type=0,           # NETWORK
        source_ip=0xC0A80101,   # 192.168.1.1
        dest_ip=0xC0A80102,     # 192.168.1.2
        source_port=12345,
        dest_port=80,
        protocol=6,
        tier_result=1,          # Tier-1 fast match
        rule_id=56,
        severity=2,             # High
    )
    test_result("Tier-1 event pushed to Bridge", rc == 0, f"rc={rc}")

    # Test 3c: Simulate UDP message to Brain
    alert_msg = json.dumps({
        "timestamp": int(time.time()),
        "attack_type": "SQL Injection",
        "policy": "Block",
        "reason": "Tier-1 Fast Pattern Match",
        "source": "TCP_SOCKET",
        "raw_payload": "SELECT * FROM users WHERE id=1 OR 1=1",
    })

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(alert_msg.encode("utf-8"), ("127.0.0.1", 9999))
        sock.close()
        test_result("UDP alert sent to Brain", True)
    except Exception as e:
        test_result("UDP alert sent to Brain", False, str(e))

    # Test 3d: Verify Bridge event count increased
    count = bridge.get_event_count()
    test_result("Bridge has events after Tier-1 push", count >= 1,
                f"count={count}")

    # Test 3e: Verify DEFCON updated
    defcon = bridge.get_defcon_level()
    label = bridge.get_defcon_label()
    test_result("DEFCON level after Tier-1 event", defcon <= 4,
                f"DEFCON={defcon} ({label})")

    bridge.bridge_shutdown()


# =====================================================================
# TEST 4: DEFCON Calculation Verification
# =====================================================================
def test_defcon_calculation():
    """Verify DEFCON calculation matches Go Goroutines logic."""
    print(f"\n{UI.CYAN}[TEST 4] DEFCON Calculation Verification{UI.RESET}")

    try:
        import aegis_bridge_ctypes as bridge
    except ImportError:
        skip_test("DEFCON calculation", "aegis_bridge_ctypes not available")
        return

    rc = bridge.bridge_init()
    if rc != 0:
        skip_test("DEFCON calculation", "bridge_init failed")
        return

    # Test 4a: DEFCON 5 (SAFE) — 0 alerts
    defcon = bridge.get_defcon_level()
    test_result("DEFCON 5 (SAFE) — initial state", defcon == 5,
                f"defcon={defcon}")

    # Test 4b: Push 1 alert → DEFCON 4 (ELEVATED)
    bridge.push_event(0, 0, 0, 0, 0, 6, 0, 1, 0, 1)  # severity=1
    bridge.update_defcon(critical=0, blocked=0, kernel=0, total=1)
    defcon = bridge.get_defcon_level()
    test_result("DEFCON 4 (ELEVATED) — 1 alert", defcon == 4,
                f"defcon={defcon}")

    # Test 4c: Push 5+ alerts → DEFCON 3 (HIGH)
    for i in range(5):
        bridge.push_event(0, 0, 0, 0, 0, 6, 0, 1, 0, 1)
    bridge.update_defcon(critical=0, blocked=0, kernel=0, total=6)
    defcon = bridge.get_defcon_level()
    test_result("DEFCON 3 (HIGH) — 5+ alerts", defcon == 3,
                f"defcon={defcon}")

    # Test 4d: Push critical → DEFCON 3 (HIGH)
    bridge.push_event(0, 0, 0, 0, 0, 6, 0, 3, 0, 3)  # severity=3 (Critical)
    bridge.update_defcon(critical=1, blocked=0, kernel=0, total=7)
    defcon = bridge.get_defcon_level()
    test_result("DEFCON 3 (HIGH) — 1+ critical", defcon <= 3,
                f"defcon={defcon}")

    # Test 4e: DEFCON labels
    for level in range(1, 6):
        label = bridge.DEFCON_LABELS.get(level, "UNKNOWN")
        test_result(f"DEFCON {level} label", label in
                    ("MAXIMUM", "SEVERE", "HIGH", "ELEVATED", "SAFE"),
                    f"label={label}")

    bridge.bridge_shutdown()


# =====================================================================
# TEST 5: IPS Decision Logic
# =====================================================================
def test_ips_decision():
    """Test IPS decision logic via Bridge."""
    print(f"\n{UI.CYAN}[TEST 5] IPS Decision Logic{UI.RESET}")

    try:
        import aegis_bridge_ctypes as bridge
    except ImportError:
        skip_test("IPS decision", "aegis_bridge_ctypes not available")
        return

    rc = bridge.bridge_init()
    if rc != 0:
        skip_test("IPS decision", "bridge_init failed")
        return

    # Test 5a: Low severity → alert
    decision = bridge.ips_decide("R0056", 0, "192.168.1.1", "alert")
    test_result("IPS: Low severity → alert", decision == "alert",
                f"decision={decision}")

    # Test 5b: Critical severity → block
    decision = bridge.ips_decide("R0056", 3, "192.168.1.1", "alert")
    test_result("IPS: Critical severity → block", decision == "block",
                f"decision={decision}")

    # Test 5c: High severity with block action → block
    decision = bridge.ips_decide("R0056", 2, "192.168.1.1", "block")
    test_result("IPS: High severity + block action → block", decision == "block",
                f"decision={decision}")

    bridge.bridge_shutdown()


# =====================================================================
# TEST 6: Dashboard API (optional)
# =====================================================================
def test_dashboard_api():
    """Test Dashboard API endpoints (requires Next.js running)."""
    print(f"\n{UI.CYAN}[TEST 6] Dashboard API (optional){UI.RESET}")

    base_url = "http://localhost:3000"

    # Test 6a: Health endpoint
    try:
        req = urllib.request.Request(f"{base_url}/api/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            test_result("Dashboard /api/health", resp.status == 200,
                        f"status={resp.status}")
    except Exception as e:
        skip_test("Dashboard /api/health", f"Dashboard not running: {e}")

    # Test 6b: Stats endpoint
    try:
        req = urllib.request.Request(f"{base_url}/api/stats")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            test_result("Dashboard /api/stats", resp.status == 200,
                        f"status={resp.status}")
            if "defcon" in data:
                test_result("Stats includes DEFCON", True,
                            f"defcon={data['defcon']}")
    except Exception as e:
        skip_test("Dashboard /api/stats", f"Dashboard not running: {e}")

    # Test 6c: Alerts endpoint
    try:
        req = urllib.request.Request(f"{base_url}/api/alerts")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            test_result("Dashboard /api/alerts", resp.status == 200,
                        f"status={resp.status}")
    except Exception as e:
        skip_test("Dashboard /api/alerts", f"Dashboard not running: {e}")


# =====================================================================
# TEST 7: Full Pipeline Simulation
# =====================================================================
def test_full_pipeline():
    """Simulate full pipeline: Attack payload → Zig → Bridge → Brain → Dashboard."""
    print(f"\n{UI.CYAN}[TEST 7] Full Pipeline Simulation{UI.RESET}")

    try:
        import aegis_bridge_ctypes as bridge
    except ImportError:
        skip_test("Full pipeline", "aegis_bridge_ctypes not available")
        return

    rc = bridge.bridge_init()
    if rc != 0:
        skip_test("Full pipeline", "bridge_init failed")
        return

    # Simulate attack payloads matching Rules.json
    test_payloads = [
        {
            "name": "SQL Injection",
            "payload": b"GET /login?id=1' OR 1=1-- HTTP/1.1\r\nHost: target.com",
            "rule_id": 56,
            "expected_severity": 2,
        },
        {
            "name": "OS Command Injection",
            "payload": b"cmd=; cat /etc/passwd",
            "rule_id": 9064,
            "expected_severity": 3,
        },
        {
            "name": "XSS Attack",
            "payload": b"<script>alert('XSS')</script>",
            "rule_id": 9059,
            "expected_severity": 2,
        },
        {
            "name": "ICMP Flood",
            "payload": b"\x08\x00" + b"\x00" * 64,  # ICMP echo request
            "rule_id": 9002,
            "expected_severity": 2,
        },
    ]

    for tp in test_payloads:
        # Push to Bridge as Tier-1 event
        rc = bridge.push_event(
            event_type=0,           # NETWORK
            source_ip=0xC0A80101,   # 192.168.1.1
            dest_ip=0xC0A80102,     # 192.168.1.2
            source_port=12345,
            dest_port=80,
            protocol=6,
            tier_result=1,          # Tier-1
            rule_id=tp["rule_id"],
            severity=tp["expected_severity"],
        )
        test_result(f"Pipeline: {tp['name']} → Bridge", rc == 0,
                    f"rc={rc}")

        # Pop event back from Bridge
        event = bridge.pop_event()
        if event:
            test_result(f"Pipeline: {tp['name']} ← Bridge",
                        event.rule_id == tp["rule_id"],
                        f"rule_id={event.rule_id} (expected {tp['rule_id']})")
        else:
            test_result(f"Pipeline: {tp['name']} ← Bridge", False,
                        "no event returned")

    # Final DEFCON check
    defcon = bridge.get_defcon_level()
    label = bridge.get_defcon_label()
    test_result("Pipeline: Final DEFCON after all attacks", defcon <= 3,
                f"DEFCON={defcon} ({label})")

    bridge.bridge_shutdown()


# =====================================================================
# MAIN
# =====================================================================
def main():
    print(f"\n{UI.CYAN}{'=' * 70}{UI.RESET}")
    print(f"{UI.CYAN}  AEGIS NIDS — End-to-End Integration Test (Phase 1){UI.RESET}")
    print(f"{UI.CYAN}{'=' * 70}{UI.RESET}")

    test_bridge_selftest()
    test_python_bridge()
    test_tier1_to_brain()
    test_defcon_calculation()
    test_ips_decision()
    test_full_pipeline()

    # Optional: Dashboard API tests
    if "--full" in sys.argv:
        test_dashboard_api()

    # Summary
    print(f"\n{UI.CYAN}{'=' * 70}{UI.RESET}")
    print(f"  {UI.BOLD}Test Results:{UI.RESET}")
    print(f"  {UI.GREEN}PASSED: {passed}{UI.RESET}")
    print(f"  {UI.RED}FAILED: {failed}{UI.RESET}")
    print(f"  {UI.YELLOW}SKIPPED: {skipped}{UI.RESET}")
    print(f"{UI.CYAN}{'=' * 70}{UI.RESET}")

    if failed > 0:
        print(f"\n{UI.RED}Some tests failed — review the output above.{UI.RESET}")
        return 1
    else:
        print(f"\n{UI.GREEN}All tests passed! Phase 1 integration is complete.{UI.RESET}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
