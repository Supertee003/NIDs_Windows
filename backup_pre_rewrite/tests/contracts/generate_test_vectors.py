#!/usr/bin/env python3
"""
STEP 1: Generate cross-language test vectors for Canonical Event.

Creates binary files that all languages (Zig/C++/Rust/Go/Python) must
read identically. Verifies ABI-safe encoding.

Output:
  tests/contracts/canonical_event.bin
  tests/contracts/wire_event.bin
"""

import struct
import json
import hashlib
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "contracts")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# Canonical Event v1 — field-by-field encoding (little-endian)
# ============================================================

# Test event: Block from 192.168.1.100:12345
MAGIC = 0x41454731  # "AEG1"
VERSION = 1
SOURCE_WFP = 1
EVENT_BLOCK = 0
POLICY_BLOCK = 2

fields = {
    "magic": MAGIC,
    "version": VERSION,
    "struct_size": 109,  # Calculated from layout
    "event_id": 12345,
    "timestamp_ms": 1700000000000,  # Fixed for reproducibility
    "monotonic_ns": 999999999,
    "source": SOURCE_WFP,
    "source_ip": 0xC0A80164,  # 192.168.1.100 (network byte order)
    "source_port": 12345,
    "dest_ip": 0x0A000001,  # 10.0.0.1
    "dest_port": 80,
    "session_id": 42,
    "protocol": 6,  # TCP
    "direction": 0,  # inbound
    "layer_id": 1,  # WFP
    "is_pipe": 0,
    "event_type": EVENT_BLOCK,
    "severity": 3,  # Critical
    "rule_id": 0xABCDEF,
    "ruleset_version": 1,
    "payload_length": 256,
    "payload_hash": 0xDEADBEEFCAFEBABE,
    "policy_action": POLICY_BLOCK,
    "enforcement_status": 1,  # enforced
    "defcon_impact": 2,
    "context_flags": 0x01,  # threat_intel_match
}

# Pack field-by-field (little-endian, explicit)
buf = bytearray()
buf += struct.pack("<I", fields["magic"])
buf += struct.pack("<H", fields["version"])
buf += struct.pack("<H", fields["struct_size"])
buf += struct.pack("<Q", fields["event_id"])
buf += struct.pack("<Q", fields["timestamp_ms"])
buf += struct.pack("<Q", fields["monotonic_ns"])
buf += struct.pack("<B", fields["source"])
buf += struct.pack("<I", fields["source_ip"])
buf += struct.pack("<H", fields["source_port"])
buf += struct.pack("<I", fields["dest_ip"])
buf += struct.pack("<H", fields["dest_port"])
buf += struct.pack("<Q", fields["session_id"])
buf += struct.pack("<B", fields["protocol"])
buf += struct.pack("<B", fields["direction"])
buf += struct.pack("<B", fields["layer_id"])
buf += struct.pack("<B", fields["is_pipe"])
buf += struct.pack("<I", fields["event_type"])
buf += struct.pack("<B", fields["severity"])
buf += struct.pack("<I", fields["rule_id"])
buf += struct.pack("<Q", fields["ruleset_version"])
buf += struct.pack("<I", fields["payload_length"])
buf += struct.pack("<Q", fields["payload_hash"])
buf += struct.pack("<B", fields["policy_action"])
buf += struct.pack("<B", fields["enforcement_status"])
buf += struct.pack("<B", fields["defcon_impact"])
buf += struct.pack("<I", fields["context_flags"])
buf += b'\x00' * 16  # reserved

print(f"Canonical Event payload size: {len(buf)} bytes")

# Write canonical_event.bin
with open(os.path.join(OUTPUT_DIR, "canonical_event.bin"), "wb") as f:
    f.write(buf)

# ============================================================
# Wire Event v1 — header + payload + CRC32
# ============================================================

WIRE_MAGIC = 0x57455631  # "WEV1"
WIRE_VERSION = 1
MSG_TYPE_EVENT = 0

import binascii
crc = binascii.crc32(buf) & 0xFFFFFFFF

wire_buf = bytearray()
wire_buf += struct.pack("<I", WIRE_MAGIC)
wire_buf += struct.pack("<H", WIRE_VERSION)
wire_buf += struct.pack("<H", MSG_TYPE_EVENT)
wire_buf += struct.pack("<I", len(buf))
wire_buf += struct.pack("<I", crc)
wire_buf += buf

print(f"Wire Event total size: {len(wire_buf)} bytes (header=16 + payload={len(buf)})")

# Write wire_event.bin
with open(os.path.join(OUTPUT_DIR, "wire_event.bin"), "wb") as f:
    f.write(wire_buf)

# ============================================================
# JSON metadata for verification
# ============================================================

metadata = {
    "canonical_event": {
        "file": "canonical_event.bin",
        "size": len(buf),
        "fields": fields,
    },
    "wire_event": {
        "file": "wire_event.bin",
        "size": len(wire_buf),
        "header_size": 16,
        "payload_size": len(buf),
        "crc32": f"0x{crc:08X}",
        "wire_magic": f"0x{WIRE_MAGIC:08X}",
    },
}

with open(os.path.join(OUTPUT_DIR, "test_vectors.json"), "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\nTest vectors written to: {OUTPUT_DIR}")
print(f"  canonical_event.bin  ({len(buf)} bytes)")
print(f"  wire_event.bin      ({len(wire_buf)} bytes)")
print(f"  test_vectors.json    (metadata)")
print(f"\nCRC32: 0x{crc:08X}")
