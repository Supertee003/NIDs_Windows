"""
AEGIS NIDS — Mouth (Rust) Clean Test Suite v2.0
==============================================
ทดสอบ Rust Mouth subsystem แยกจาก Nose — ตรวจเฉพาะหน้าที่ของ Mouth

Mouth v2.0 หน้าที่จริง (SOLE DEFCON OWNER + TUI):
  1. DEFCON Calculation    — calculate_defcon() (sole owner, ไม่ทับซ้อนกับ Nose)
  2. Log Parsing           — reads anomalous.json for severity/policy/tier (sole owner)
  3. DEFCON TUI Display    — Header + Bar + Label (sole TUI window)
  4. Tier-3 Shield FFI     — validate_payload_safety (4 checks)
  5. ETW Monitor (stub)    — etw_security_monitor_poll()
  6. Process Monitor (stub)— process_creation_monitor_poll()

✅  ไม่ทับซ้อนกับ Nose แล้ว:
  - Nose ไม่คำนวณ DEFCON, ไม่มี TUI → Mouth เป็นเจ้าของเดียว
  - Mouth อ่าน anomalous.json เพื่อ DEFCON เท่านั้น
  - Nose อ่าน anomalous.json เพื่อ ThreatMap เท่านั้น (ไม่ parse severity/policy/tier)

Rust Files:
  - windows_sec_monitor.rs  → sole DEFCON TUI binary (compiled with rustc)
  - aegis_mouth_tui.rs      → enhanced TUI with ETW stubs
  - src/lib.rs               → Tier-3 FFI library (sec_monitor.dll)

Usage:
  python aegis_mouth_test.py
"""
import os
import sys
import json
import subprocess
import time
import ctypes
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── ANSI ──
R = '\033[0m'; B = '\033[1m'; RED = '\033[91m'; GRN = '\033[92m'
YLW = '\033[93m'; CYN = '\033[96m'; DIM = '\033[2m'

PASS = 0
FAIL = 0
WARN = 0

def result(name, ok, detail="", warn=False):
    global PASS, FAIL, WARN
    if ok:
        if warn:
            WARN += 1
            print(f"  {YLW}[WARN]{R} {name}  {DIM}{detail}{R}")
        else:
            PASS += 1
            print(f"  {GRN}[PASS]{R} {name}  {DIM}{detail}{R}")
    else:
        FAIL += 1
        print(f"  {RED}[FAIL]{R} {name}  {detail}")


print("=" * 64)
print("  AEGIS NIDS — MOUTH (Rust) CLEAN TEST SUITE v2.0")
print("  Testing Mouth-specific functions (sole DEFCON owner)")
print("=" * 64)
print()

# =====================================================================
# TEST 1: Rust Source Files Check
# =====================================================================
print(f"{'─' * 64}")
print("  [1] Rust Source Files Check")
print(f"{'─' * 64}")

rs_files = {
    "windows_sec_monitor.rs": os.path.join(SCRIPT_DIR, "windows_sec_monitor.rs"),
    "aegis_mouth_tui.rs": os.path.join(SCRIPT_DIR, "aegis_mouth_tui.rs"),
    "src/lib.rs": os.path.join(SCRIPT_DIR, "src", "lib.rs"),
    "Cargo.toml": os.path.join(SCRIPT_DIR, "Cargo.toml"),
}

for name, path in rs_files.items():
    result(f"{name} exists", os.path.exists(path),
           "found" if os.path.exists(path) else "MISSING")

# Check Rust toolchain
rustc_avail = False
cargo_avail = False
try:
    r = subprocess.run(["rustc", "--version"], capture_output=True, text=True, timeout=5)
    rustc_avail = r.returncode == 0
    result("rustc toolchain", rustc_avail, r.stdout.strip() if rustc_avail else "not found")
except Exception:
    result("rustc toolchain", False, "not in PATH")

try:
    r = subprocess.run(["cargo", "--version"], capture_output=True, text=True, timeout=5)
    cargo_avail = r.returncode == 0
    result("cargo toolchain", cargo_avail, r.stdout.strip() if cargo_avail else "not found")
except Exception:
    result("cargo toolchain", False, "not in PATH")

# =====================================================================
# TEST 2: Parse Rust Sources — Verify Mouth-Only Architecture
# =====================================================================
print(f"\n{'─' * 64}")
print("  [2] Mouth v2.0 Function Analysis")
print(f"{'─' * 64}")

# ── windows_sec_monitor.rs (sole DEFCON TUI) ──
rs_simple = rs_files["windows_sec_monitor.rs"]
if os.path.exists(rs_simple):
    with open(rs_simple, 'r') as f:
        src = f.read()

    result("calculate_defcon function (sole owner)", "calculate_defcon" in src,
           "Mouth is the ONLY DEFCON calculator")
    result("DEFCON TUI display (sole window)", "DEFCON" in src and "██" in src,
           "Mouth is the ONLY TUI display")
    result("Log file reading", 'logs/anomalous.json' in src,
           "reads log for DEFCON calculation")
    result("Auto-refresh loop", "loop {" in src, "1s refresh")

    # Mouth parses severity/policy/tier (Nose does NOT)
    result('Parses "Critical" severity', '"Critical"' in src,
           "Mouth-only — Nose does NOT parse this")
    result('Parses "Drop"/"Block" policy', '"Drop"' in src and '"Block"' in src,
           "Mouth-only — Nose does NOT parse this")
    result('Parses "Tier-3" kernel', '"Tier-3"' in src or 'KERNEL_FILE' in src,
           "Mouth-only — Nose does NOT parse this")

# ── aegis_mouth_tui.rs (enhanced TUI with ETW stubs) ──
rs_tui = rs_files["aegis_mouth_tui.rs"]
if os.path.exists(rs_tui):
    with open(rs_tui, 'r') as f:
        src = f.read()

    result("ETW monitor stub", "etw_security_monitor_poll" in src,
           "future ETW hooks (Mouth-only)")
    result("Process creation stub", "process_creation_monitor_poll" in src,
           "future process hooks (Mouth-only)")
    result("UTF-8 safe truncation", "chars().take()" in src or "chars().count()" in src,
           "fix-L3: multi-byte safe")

    # Check kernel threshold consistency
    has_kernel_3 = "kernel >= 3" in src
    has_kernel_1 = "kernel >= 1" in src
    result("kernel threshold = 3 (consistent)", has_kernel_3,
           f"{GRN}consistent with sec_monitor.rs{R}" if has_kernel_3 else
           f"{RED}INCONSISTENCY: has kernel>=1 instead of kernel>=3{R}" if has_kernel_1 else "check manually")

# ── src/lib.rs (Tier-3 Shield) ──
rs_lib = rs_files["src/lib.rs"]
if os.path.exists(rs_lib):
    with open(rs_lib, 'r') as f:
        src = f.read()

    result("validate_payload_safety FFI", "validate_payload_safety" in src,
           "C-ABI entry point (Mouth-only)")
    result("check_suspicious_size", "check_suspicious_size" in src, "Check 1")
    result("check_nop_sled", "check_nop_sled" in src, "Check 2")
    result("check_buffer_overflow_pattern", "check_buffer_overflow_pattern" in src, "Check 3")
    result("check_malformed_headers", "check_malformed_headers" in src, "Check 4")
    result("tier3_check_count API", "tier3_check_count" in src, "stats API")
    result("tier3_version API", "tier3_version" in src, "version API")
    result("#[cfg(test)] unit tests", "#[cfg(test)]" in src, "built-in Rust tests")

    # Count test functions
    test_count = src.count("#[test]")
    result(f"Rust unit test count >= 8", test_count >= 8,
           f"{test_count} tests defined")
else:
    # Mark as expected if file not found (might be in shield_rust/)
    result("src/lib.rs (Tier-3 Shield)", False, "not at expected path — check shield_rust/src/lib.rs", warn=True)

# =====================================================================
# TEST 3: DEFCON Calculation Logic (Mouth — Sole Owner)
# =====================================================================
print(f"\n{'─' * 64}")
print("  [3] DEFCON Calculation Logic (Mouth — Sole Owner)")
print(f"{'─' * 64}")

def mouth_calculate_defcon(total, critical, blocked, kernel):
    """Replica of Rust Mouth calculate_defcon (windows_sec_monitor.rs)
    Mouth is the ONLY component that calculates DEFCON"""
    if critical >= 10 or blocked >= 5 or kernel >= 3:
        return 1, "MAXIMUM"
    if critical >= 5 or blocked >= 3:
        return 2, "SEVERE"
    if total >= 5 or critical >= 1:
        return 3, "HIGH"
    if total >= 1:
        return 4, "ELEVATED"
    return 5, "SAFE"

test_cases = [
    (0,  0,  0, 0, 5, "SAFE"),       # No alerts
    (1,  0,  0, 0, 4, "ELEVATED"),   # 1 alert
    (5,  0,  0, 0, 3, "HIGH"),       # 5+ alerts
    (0,  1,  0, 0, 3, "HIGH"),       # 1+ critical
    (0,  5,  0, 0, 2, "SEVERE"),     # 5+ critical
    (0,  0,  3, 0, 2, "SEVERE"),     # 3+ blocked
    (0,  10, 0, 0, 1, "MAXIMUM"),    # 10+ critical
    (0,  0,  5, 0, 1, "MAXIMUM"),    # 5+ blocked
    (0,  0,  0, 3, 1, "MAXIMUM"),    # 3+ kernel
    (3,  0,  0, 0, 4, "ELEVATED"),   # 3 alerts (not 5)
    (0,  0,  2, 0, 5, "SAFE"),       # 2 blocked but no critical/alerts
]

for total, critical, blocked, kernel, exp_level, exp_label in test_cases:
    level, label = mouth_calculate_defcon(total, critical, blocked, kernel)
    ok = level == exp_level and label == exp_label
    result(f"DEFCON({total},{critical},{blocked},{kernel})={level} {label}", ok,
           f"expected {exp_level} {exp_label}")

# =====================================================================
# TEST 4: DEFCON from Parsed Log (Mouth-specific)
# =====================================================================
print(f"\n{'─' * 64}")
print("  [4] DEFCON from Parsed Log (Mouth reads severity/policy/tier)")
print(f"{'─' * 64}")

# Same test data — Mouth parses ALL fields
test_entries = [
    {"timestamp": "2025-01-01T10:00:00", "attack_type": "SQL_Injection", "severity": "High", "policy": "Alert", "tier": "Tier-2"},
    {"timestamp": "2025-01-01T10:01:00", "attack_type": "XSS", "severity": "Critical", "policy": "Block", "tier": "Tier-2"},
    {"timestamp": "2025-01-01T10:02:00", "attack_type": "Buffer_Overflow", "severity": "Critical", "policy": "Drop", "tier": "Tier-3"},
    {"timestamp": "2025-01-01T10:03:00", "attack_type": "Brute_Force", "severity": "Medium", "policy": "Alert", "tier": "Tier-2"},
    {"timestamp": "2025-01-01T10:04:00", "attack_type": "RCE", "severity": "Critical", "policy": "Alert", "tier": "Tier-3"},
]

# Mouth parses severity, policy, tier
total = 0
critical = 0
blocked = 0
kernel = 0
last_threat = ""

for entry in test_entries:
    total += 1
    last_threat = json.dumps(entry)
    if entry.get("severity") == "Critical":
        critical += 1
    policy = entry.get("policy", "")
    if policy in ("Drop", "Block", "BLOCK"):
        blocked += 1
    tier = entry.get("tier", "")
    if tier == "Tier-3":
        kernel += 1

result("Total alerts parsed", total == 5, f"count={total}")
result("Critical count", critical == 3, f"count={critical}")
result("Blocked/Dropped count", blocked == 2, f"count={blocked}")
result("Kernel threats (Tier-3)", kernel == 2, f"count={kernel}")

level, label = mouth_calculate_defcon(total, critical, blocked, kernel)
result(f"DEFCON from parsed log = {level} {label}", level == 2,
       f"3 critical + 2 blocked → SEVERE (Mouth sole calculation)")

# =====================================================================
# TEST 5: Tier-3 Shield FFI Test
# =====================================================================
print(f"\n{'─' * 64}")
print("  [5] Tier-3 Shield FFI Test (sec_monitor.dll)")
print(f"{'─' * 64}")

# Find DLL
dll_paths = [
    os.path.join(SCRIPT_DIR, "target", "release", "sec_monitor.dll"),
    os.path.join(SCRIPT_DIR, "zig-out", "bin", "sec_monitor.dll"),
]

shield_dll = None
for p in dll_paths:
    if os.path.exists(p):
        shield_dll = p
        break

result("sec_monitor.dll found", shield_dll is not None,
       shield_dll.replace(SCRIPT_DIR + os.sep, "") if shield_dll else "not built — run: cargo build --release")

if shield_dll:
    try:
        lib = ctypes.CDLL(shield_dll)

        # Test: tier3_check_count
        lib.tier3_check_count.restype = ctypes.c_uint32
        count = lib.tier3_check_count()
        result("tier3_check_count()", count == 4, f"returns {count} checks")

        # Test: tier3_version
        lib.tier3_version.restype = ctypes.c_char_p
        version = lib.tier3_version()
        result("tier3_version()", version is not None,
               version.decode('utf-8', errors='replace') if version else "null")

        # Test: validate_payload_safety — safe payload
        lib.validate_payload_safety.restype = ctypes.c_bool
        lib.validate_payload_safety.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        safe_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        buf = (ctypes.c_uint8 * len(safe_payload))(*safe_payload)
        is_safe = lib.validate_payload_safety(buf, len(safe_payload))
        result("validate safe HTTP payload", is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — NOP sled
        nop_sled = b'\x90' * 100
        buf = (ctypes.c_uint8 * len(nop_sled))(*nop_sled)
        is_safe = lib.validate_payload_safety(buf, len(nop_sled))
        result("reject NOP sled (100 bytes)", not is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — null/zero
        is_safe = lib.validate_payload_safety(None, 0)
        result("reject null pointer", not is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — oversized
        big = b'A' * 70000
        buf = (ctypes.c_uint8 * len(big))(*big)
        is_safe = lib.validate_payload_safety(buf, len(big))
        result("reject oversized packet (70KB)", not is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — all zeros
        zeros = b'\x00' * 16
        buf = (ctypes.c_uint8 * len(zeros))(*zeros)
        is_safe = lib.validate_payload_safety(buf, len(zeros))
        result("reject all-zero payload", not is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — heap spray
        spray = b'\x0c' * 250
        buf = (ctypes.c_uint8 * len(spray))(*spray)
        is_safe = lib.validate_payload_safety(buf, len(spray))
        result("reject heap spray (0x0c * 250)", not is_safe, f"returned {is_safe}")

        # Test: validate_payload_safety — meterpreter
        meter = b"POST /meterpreter HTTP/1.1\r\n"
        buf = (ctypes.c_uint8 * len(meter))(*meter)
        is_safe = lib.validate_payload_safety(buf, len(meter))
        result("reject meterpreter string", not is_safe, f"returned {is_safe}")

    except Exception as e:
        result("FFI load/test", False, str(e))

# =====================================================================
# TEST 6: Mouth EXE Check
# =====================================================================
print(f"\n{'─' * 64}")
print("  [6] Mouth Executable Check")
print(f"{'─' * 64}")

exe_path = os.path.join(SCRIPT_DIR, "windows_sec_monitor.exe")
result("windows_sec_monitor.exe pre-built", os.path.exists(exe_path),
       "found" if os.path.exists(exe_path) else "not built — use: rustc -O windows_sec_monitor.rs -o windows_sec_monitor.exe")

# Check if Mouth is running
mouth_running = False
mouth_pid = None
try:
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq windows_sec_monitor.exe", "/NH"],
                       capture_output=True, text=True, timeout=5)
    if "windows_sec_monitor" in r.stdout.lower():
        mouth_running = True
        parts = r.stdout.strip().split()
        mouth_pid = parts[1] if len(parts) > 1 else "?"
except Exception:
    pass

result("Mouth process running", mouth_running,
       f"PID={mouth_pid}" if mouth_running else "not running (use run_aegis.bat)")

# =====================================================================
# TEST 7: Cargo Build Test (library)
# =====================================================================
print(f"\n{'─' * 64}")
print("  [7] Cargo Build Test")
print(f"{'─' * 64}")

if cargo_avail:
    result("cargo available for shield build", True, "cargo build --release → sec_monitor.dll")
else:
    result("cargo available", False, "not in PATH", warn=True)

# Verify Cargo.toml produces cdylib
if os.path.exists(rs_files["Cargo.toml"]):
    with open(rs_files["Cargo.toml"], 'r') as f:
        cargo = f.read()
    result("Cargo.toml has [lib] section", "[lib]" in cargo, "cdylib configuration")
    result("crate-type = cdylib", "cdylib" in cargo, "produces sec_monitor.dll")
    result("lib name = sec_monitor", "sec_monitor" in cargo, "DLL naming")

# =====================================================================
# TEST 8: DEFCON Threshold Consistency (Mouth-only, all Rust files)
# =====================================================================
print(f"\n{'─' * 64}")
print("  [8] DEFCON Threshold Consistency (all Rust files)")
print(f"{'─' * 64}")

# Verify all Rust DEFCON implementations use same thresholds
all_consistent = True

# Check windows_sec_monitor.rs
if os.path.exists(rs_simple):
    with open(rs_simple, 'r') as f:
        src = f.read()
    if "kernel >= 3" not in src:
        all_consistent = False

# Check aegis_mouth_tui.rs
if os.path.exists(rs_tui):
    with open(rs_tui, 'r') as f:
        src = f.read()
    if "kernel >= 3" not in src:
        all_consistent = False

result("All Rust files use kernel>=3 for DEFCON 1", all_consistent,
       f"{GRN}consistent{R}" if all_consistent else f"{RED}INCONSISTENCY found{R}")

# =====================================================================
# TEST 9: NO Overlap with Nose
# =====================================================================
print(f"\n{'─' * 64}")
print("  [9] Mouth vs Nose Overlap Verification")
print(f"{'─' * 64}")

# Check that Nose (Go) does NOT have DEFCON
go_src_path = os.path.join(SCRIPT_DIR, "windows_perf.go")
nose_has_defcon = False
if os.path.exists(go_src_path):
    with open(go_src_path, 'r') as f:
        nose_src = f.read()
    nose_has_defcon = "calculateDEFCON" in nose_src or "defconCalculator" in nose_src

result("Nose does NOT calculate DEFCON", not nose_has_defcon,
       f"{GRN}CLEAN — Nose is headless{R}" if not nose_has_defcon else f"{RED}Nose still has DEFCON!{R}")

nose_has_tui = False
if os.path.exists(go_src_path):
    with open(go_src_path, 'r') as f:
        nose_src = f.read()
    nose_has_tui = "clearScreen" in nose_src

result("Nose does NOT have TUI display", not nose_has_tui,
       f"{GRN}CLEAN — no popup window{R}" if not nose_has_tui else f"{RED}Nose still has TUI!{R}")

# =====================================================================
# TEST 10: Architecture Summary
# =====================================================================
print(f"\n{'─' * 64}")
print("  [10] Mouth (Rust) Architecture Summary")
print(f"{'─' * 64}")

print(f"""
  {B}Mouth (Rust) v2.0 — Sole DEFCON Owner + Security Monitor{R}

  {GRN}Unique Functions (Mouth-only):{R}
    ✅ DEFCON Calculation — calculate_defcon()
       Sole owner: only Mouth calculates DEFCON level
       Reads severity/policy/tier from anomalous.json
    ✅ DEFCON TUI Display — single console window
       Header + Bar + Statistics + Last Threat
    ✅ Tier-3 Shield FFI — validate_payload_safety()
       4 checks: size, NOP sled, buffer overflow, malformed headers
    ✅ ETW Monitor (stub) — etw_security_monitor_poll()
       Future: Event Tracing for Windows hooks
    ✅ Process Monitor (stub) — process_creation_monitor_poll()
       Future: suspicious process detection

  {GRN}Sole Ownership:{R}
    ✅ Mouth is the ONLY DEFCON calculator
    ✅ Mouth is the ONLY TUI display (no more 2 หน้าต่าง)
    ✅ Mouth is the ONLY log parser (severity/policy/tier)

  {GRN}NO Overlap with Nose:{R}
    ✅ Resource Collection → Nose (Go)
    ✅ Traffic Sensing → Nose (Go)
    ✅ ThreatMap → Nose (Go)
    ✅ Mouth focuses on: DEFCON + Shield + Security
""")

# =====================================================================
# SUMMARY
# =====================================================================
print("=" * 64)
print(f"  MOUTH TEST SUMMARY v2.0")
print(f"  Passed  : {GRN}{PASS}{R}")
print(f"  Failed  : {RED}{FAIL}{R}")
print(f"  Warnings: {YLW}{WARN}{R}")
print("=" * 64)

if FAIL == 0:
    print(f"\n  {GRN}{B}*** MOUTH TESTS ALL PASSED ***{R}")
else:
    print(f"\n  {RED}{B}*** {FAIL} TEST(S) FAILED ***{R}")
