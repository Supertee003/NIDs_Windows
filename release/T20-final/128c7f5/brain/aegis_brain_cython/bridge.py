"""
aegis_brain_cython.bridge - Cython/Python transparent bridge (Phase 17)

Provides a unified API that uses Cython acceleration when available,
falling back to pure Python when Cython is not compiled.

Usage:
  from aegis_brain_cython.bridge import scan_payload, get_severity

  # These functions automatically use Cython if compiled, else Python
"""

import json
import re

# Try to import Cython module
try:
    from .fast_scan import (
        fast_payload_scan,
        fast_severity_lookup,
        fast_ip_in_list,
        fast_extract_field,
        calculate_defcon,
        payload_too_large,
    )
    CYTHON_AVAILABLE = True
    _CYTHON_VERSION = "1.0.0"
except ImportError:
    CYTHON_AVAILABLE = False
    _CYTHON_VERSION = None


# ============================================================
# Pure Python fallbacks
# ============================================================

def _python_payload_scan(payload: bytes, patterns: list):
    """Pure Python fallback for fast_payload_scan."""
    for i, p in enumerate(patterns):
        if p in payload:
            return (i, p)
    return (-1, None)


def _python_severity_lookup(severity_str: str) -> int:
    """Pure Python fallback for fast_severity_lookup."""
    return {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}.get(severity_str, -1)


def _python_ip_in_list(ip: int, ip_list: list) -> bool:
    """Pure Python fallback for fast_ip_in_list."""
    return ip in ip_list


def _python_extract_field(json_bytes: bytes, field_name: str):
    """Pure Python fallback for fast_extract_field."""
    try:
        data = json.loads(json_bytes.decode('utf-8'))
        return data.get(field_name)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _python_calculate_defcon(critical_count: int, block_count: int,
                             match_count: int, forward_count: int) -> int:
    """Pure Python fallback for calculate_defcon."""
    if critical_count >= 1:
        return 1
    elif block_count >= 3:
        return 2
    elif match_count >= 10:
        return 3
    elif match_count >= 1:
        return 4
    else:
        return 5


def _python_payload_too_large(payload: bytes, max_size: int) -> bool:
    """Pure Python fallback for payload_too_large."""
    return len(payload) > max_size


# BRAIN-FASTPATH-FIX: Case-2 pre-filter detectors. Semantics mirror the
# retired brain/cython/aegis_hotspot.pyx hotspots 2 and 5 exactly
# (longest-run NOP sled, marker list, longest repeated-byte run); the
# windows_brain.py import fallback carries identical mirrors for hosts
# where this package is not importable. A C accelerator for these three
# is a follow-up for fast_scan.pyx -- behavior must not change when it
# lands.

def _python_scan_nop_sled(payload: bytes, min_seq: int = 50):
    """Pure Python fallback: longest 0x90 run. Returns (found, run_len, offset)."""
    best = 0
    best_offset = 0
    run = 0
    start = 0
    for i, byte in enumerate(payload):
        if byte == 0x90:
            if run == 0:
                start = i
            run += 1
            if run > best:
                best = run
                best_offset = start
        else:
            run = 0
    return (best >= min_seq, best, best_offset)


def _python_scan_shellcode_markers(payload: bytes):
    """Pure Python fallback: [(marker_name, offset)] for known markers."""
    results = []
    if len(payload) < 4:
        return results
    i = payload.find(b"\x0c\x0c\x0c\x0c")
    if i != -1:
        results.append(("heap_spray_0c", i))
    if len(payload) >= 8:
        i = payload.find(b"meterpre")
        if i != -1:
            results.append(("meterpreter", i))
    i = payload.find(b"\xcc" * 8)
    if i != -1:
        results.append(("int3_padding", i))
    return results


def _python_detect_repeated_byte(payload: bytes, min_run: int = 200):
    """Pure Python fallback: longest identical-byte run >= min_run.

    Returns (found, byte_value, run_length, offset)."""
    if len(payload) < min_run:
        return (False, 0, 0, 0)
    run_byte = payload[0]
    run_len = 1
    start = 0
    best = 0
    best_byte = 0
    best_offset = 0
    for i in range(1, len(payload)):
        byte = payload[i]
        if byte == run_byte:
            run_len += 1
            if run_len > best:
                best = run_len
                best_byte = run_byte
                best_offset = start
        else:
            run_byte = byte
            run_len = 1
            start = i
    if best >= min_run:
        return (True, best_byte, best, best_offset)
    return (False, 0, 0, 0)


# ============================================================
# Public API (uses Cython if available, else Python)
# ============================================================

def scan_payload(payload: bytes, patterns: list):
    """Scan payload against patterns. Returns (index, pattern) or (-1, None)."""
    if CYTHON_AVAILABLE:
        return fast_payload_scan(payload, patterns)
    return _python_payload_scan(payload, patterns)


def get_severity(severity_str: str) -> int:
    """Convert severity string to int (0-3, or -1 for unknown)."""
    if CYTHON_AVAILABLE:
        return fast_severity_lookup(severity_str)
    return _python_severity_lookup(severity_str)


def ip_in_list(ip: int, ip_list: list) -> bool:
    """Check if IP is in list (32-bit integer comparison)."""
    if CYTHON_AVAILABLE:
        return fast_ip_in_list(ip, ip_list)
    return _python_ip_in_list(ip, ip_list)


def extract_field(json_bytes: bytes, field_name: str):
    """Extract a string field from JSON without full parse."""
    if CYTHON_AVAILABLE:
        return fast_extract_field(json_bytes, field_name)
    return _python_extract_field(json_bytes, field_name)


def compute_defcon(critical_count: int, block_count: int,
                   match_count: int, forward_count: int) -> int:
    """Calculate DEFCON level from event counts."""
    if CYTHON_AVAILABLE:
        return calculate_defcon(critical_count, block_count, match_count, forward_count)
    return _python_calculate_defcon(critical_count, block_count, match_count, forward_count)


def check_payload_size(payload: bytes, max_size: int) -> bool:
    """Check if payload exceeds max_size."""
    if CYTHON_AVAILABLE:
        return payload_too_large(payload, max_size)
    return _python_payload_too_large(payload, max_size)


# --- BRAIN-FASTPATH-FIX: Case-2 fast-path pre-filter detectors ---------
# Consumed by brain/windows_brain.py's Case-2 block. Return shapes are
# load-bearing: (found, run_len, offset) / [(name, offset)] /
# (found, byte, run_len, offset).

def scan_nop_sled(payload: bytes, min_seq: int = 50):
    """Longest 0x90 run: (found >= min_seq, run_length, run_offset)."""
    return _python_scan_nop_sled(payload, min_seq)


def scan_shellcode_markers(payload: bytes):
    """Known shellcode markers: [(marker_name, offset), ...], in detection order."""
    return _python_scan_shellcode_markers(payload)


def detect_repeated_byte(payload: bytes, min_run: int = 200):
    """Longest identical-byte run: (found >= min_run, byte, run_length, offset)."""
    return _python_detect_repeated_byte(payload, min_run)


def is_available() -> bool:
    """Check if Cython acceleration is available."""
    return CYTHON_AVAILABLE


def get_version():
    """Get Cython module version (or None if not compiled)."""
    return _CYTHON_VERSION


# ============================================================
# Self-test
# ============================================================

if __name__ == "__main__":
    print(f"Cython available: {CYTHON_AVAILABLE}")
    if CYTHON_AVAILABLE:
        print(f"Cython version: {_CYTHON_VERSION}")

        # Benchmark
        from .fast_scan import benchmark_scan
        print("\nBenchmarking payload scan (10000 iterations):")
        speedup = benchmark_scan(10000)
        print(f"\nCython is {speedup:.2f}x faster than pure Python")
    else:
        print("\nCython not compiled. To enable acceleration:")
        print("  cd brain/aegis_brain_cython")
        print("  python setup.py build_ext --inplace")
        print("\nUsing pure Python fallbacks.")
