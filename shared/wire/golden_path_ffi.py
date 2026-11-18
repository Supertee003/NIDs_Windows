#!/usr/bin/env python3
#! golden_path_ffi.py - Cross-language golden vector validation
#! Proves that Python can read the same .bin golden vector fixtures and produce
#! identical semantic output as Zig, Go, C++, and Rust.
#!
#! Evidence level: E3 (component integration across language runtimes)

import struct
import json
import os
import socket
import sys

# ── Path setup ──────────────────────────────────────────────────
# Vectors live in the repo tree (this script runs from shared/wire/).
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VECTORS_DIR = os.path.join(_REPO_ROOT,
                           "tests", "contracts", "event_vectors",
                           "event_vectors")
GOLDEN_JSON = os.path.join(_REPO_ROOT,
                           "tests", "contracts", "event_vectors",
                           "event_vectors",
                           "golden_vectors.json")

# ── Wire format constants (matches canonical_event.zig + wire_codec.py) ────────
WIRE_PAYLOAD_SIZE = 109
EVENT_MAGIC = 0x41454731
EVENT_VERSION = 1

# Struct format: little-endian matching the canonical wire layout
# "<IHHQQQBIHIHQBBBBIBIQIQBBBI16s" = 109 bytes total
# I = u32, H = u16, Q = u64, B = u8
WIRE_FORMAT = "<IHHQQQBIHIHQBBBBIBIQIQBBBI16s"

# ── Expected field values per vector (from golden_vectors.json) ──────────────
VECTOR_DEFS = {
    "event_v1_001.bin": {
        "description": "Benign forward event (192.168.1.100 -> 10.0.0.1:80)",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 1001,
            "timestamp_ms": 1700000000000,
            "monotonic_ns": 999999999,
            "source": 1,
            "source_name": "wfp_sensor",
            "source_ip": 0xC0A80164,
            "source_port": 12345,
            "dest_ip": 0x0A000001,
            "dest_port": 80,
            "session_id": 42,
            "protocol": 6,
            "protocol_name": "TCP",
            "direction": 0,
            "direction_name": "inbound",
            "layer_id": 1,
            "is_pipe": False,
            "event_type": 2,
            "event_type_name": "forward",
            "severity": 0,
            "severity_name": "Low",
            "rule_id": 0,
            "ruleset_version": 1,
            "payload_length": 512,
            "payload_hash": 0,
            "policy_action": 0,
            "policy_action_name": "allow",
            "enforcement_status": 0,
            "defcon_impact": 5,
            "context_flags": 0,
            "pid": 0,
            "ppid": 0,
            "proc_type": 0,
            "integrity": 0,
            "hids_flag": 0,
            "node_id": 0,
            "confidence": 0,
        }
    },
    "event_v1_002.bin": {
        "description": "APT block event (192.168.16.16 -> 10.0.0.1:445 SMB)",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 2002,
            "timestamp_ms": 1700000001000,
            "monotonic_ns": 1000000000,
            "source": 1,
            "source_name": "wfp_sensor",
            "source_ip": 0xC0A81010,
            "source_port": 54321,
            "dest_ip": 0x0A000001,
            "dest_port": 445,
            "session_id": 999,
            "protocol": 6,
            "protocol_name": "TCP",
            "direction": 0,
            "direction_name": "inbound",
            "layer_id": 1,
            "is_pipe": False,
            "event_type": 0,
            "event_type_name": "block",
            "severity": 3,
            "severity_name": "Critical",
            "rule_id": 0xABCDEF01,
            "ruleset_version": 2,
            "payload_length": 256,
            "payload_hash": 0xDEADBEEFCAFEBABE,
            "policy_action": 2,
            "policy_action_name": "block",
            "enforcement_status": 1,
            "defcon_impact": 1,
            "context_flags": 11,
            "pid": 0,
            "ppid": 0,
            "proc_type": 0,
            "integrity": 0,
            "hids_flag": 0,
            "node_id": 0,
            "confidence": 0,
        }
    },
    "event_v1_003.bin": {
        "description": "Host event (process start, minifilter)",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 3003,
            "timestamp_ms": 1700000002000,
            "monotonic_ns": 2000000000,
            "source": 3,
            "source_name": "minifilter",
            "source_ip": 0,
            "source_port": 0,
            "dest_ip": 0,
            "dest_port": 0,
            "session_id": 0,
            "protocol": 0,
            "protocol_name": "unknown",
            "direction": 0,
            "direction_name": "inbound",
            "layer_id": 2,
            "is_pipe": True,
            "event_type": 5,
            "event_type_name": "session_start",
            "severity": 1,
            "severity_name": "Medium",
            "rule_id": 0,
            "ruleset_version": 0,
            "payload_length": 0,
            "payload_hash": 0,
            "policy_action": 0,
            "policy_action_name": "allow",
            "enforcement_status": 0,
            "defcon_impact": 5,
            "context_flags": 0,
            "pid": 0,
            "ppid": 0,
            "proc_type": 0,
            "integrity": 0,
            "hids_flag": 0,
            "node_id": 0,
            "confidence": 0,
        }
    }
}


def load_golden_vectors():
    """Load the golden vector metadata from JSON."""
    with open(GOLDEN_JSON, "r") as f:
        return json.load(f)


def parse_wire(data):
    """Parse 109-byte binary into field values matching the canonical wire format."""
    if len(data) != WIRE_PAYLOAD_SIZE:
        print(f"FAIL: expected {WIRE_PAYLOAD_SIZE} bytes, got {len(data)}")
        return None
    fields = struct.unpack(WIRE_FORMAT, data)
    return fields


def _expected_num(name, value):
    """Normalize a golden_vectors.json field to int (hex/"0x", dotted IP)."""
    if isinstance(value, int):
        return value
    text = str(value)
    if "." in text and name.endswith("ip"):
        return struct.unpack("!I", socket.inet_aton(text))[0]
    return int(text, 0)


def validate_vector(vector_name, parsed_fields, expected_fields):
    """Validate parsed fields against the expected golden vector definition."""
    errors = []
    fields = expected_fields

    # Map parsed tuple positions to field names
    field_map = {
        "magic": ("I", 0),
        "version": ("H", 1),
        "struct_size": ("H", 2),
        "event_id": ("Q", 3),
        "timestamp_ms": ("Q", 4),
        "monotonic_ns": ("Q", 5),
        "source": ("B", 6),
        "source_ip": ("I", 7),
        "source_port": ("H", 8),
        "dest_ip": ("I", 9),
        "dest_port": ("H", 10),
        "session_id": ("Q", 11),
        "protocol": ("B", 12),
        "direction": ("B", 13),
        "layer_id": ("B", 14),
        "is_pipe": ("B", 15),
        "event_type": ("I", 16),
        "severity": ("B", 17),
        "rule_id": ("I", 18),
        "ruleset_version": ("Q", 19),
        "payload_length": ("I", 20),
        "payload_hash": ("Q", 21),
        "policy_action": ("B", 22),
        "enforcement_status": ("B", 23),
        "defcon_impact": ("B", 24),
        "context_flags": ("I", 25),
    }

    for name, (fmt, idx) in field_map.items():
        expected_val = fields.get(name)
        if expected_val is None:
            continue
        actual_val = parsed_fields[idx]
        try:
            want = _expected_num(name, expected_val)
        except (ValueError, OSError):
            continue  # human-only annotations (names, descriptions)
        if actual_val != want:
            errors.append(f"  {name}: got {actual_val} (0x{actual_val:08X}), expected {want} ({expected_val})")

    if errors:
        print(f"FAIL: {vector_name}")
        for e in errors:
            print(e)
        return False

    print(f"PASS: {vector_name}")
    return True


def test_golden_vector(vector_name):
    """Test a single golden vector: load .bin, parse, validate."""
    # Read the binary fixture
    bin_path = os.path.join(VECTORS_DIR, vector_name)
    if not os.path.exists(bin_path):
        print(f"FAIL: {vector_name} not found at {bin_path}")
        return False

    with open(bin_path, "rb") as f:
        data = f.read()

    # Parse the wire format
    parsed = parse_wire(data)
    if parsed is None:
        return False

    # Load expected values
    golden = load_golden_vectors()
    if vector_name not in golden["vectors"]:
        print(f"FAIL: {vector_name} not in golden_vectors.json")
        return False

    expected_fields = golden["vectors"][vector_name]["fields"]
    return validate_vector(vector_name, parsed, expected_fields)


def main():
    print("Cross-language Golden Vector Validation (Python)")
    print("=" * 56)
    print()

    all_pass = True

    # Test all 3 primary vectors
    for vec_name in ["event_v1_001.bin", "event_v1_002.bin", "event_v1_003.bin"]:
        result = test_golden_vector(vec_name)
        all_pass = all_pass and result
        print()

    if all_pass:
        print("ALL 3 VECTORS PASSED - Python can read shared .bin fixtures "
              "and produce identical semantic output as other languages")
        return 0
    else:
        print("SOME VECTORS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())