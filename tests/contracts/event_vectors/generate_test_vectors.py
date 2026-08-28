#!/usr/bin/env python3
"""Generate cross-language test vectors for Canonical Event.

REWRITE Phase 1.4: Create test vectors that all languages must read identically.

Output:
  tests/contracts/event_vectors/event_v1_001.bin  — benign forward event
  tests/contracts/event_vectors/event_v1_002.bin  — APT block event
  tests/contracts/event_vectors/event_v1_003.bin  — host event (process start)
  tests/contracts/event_vectors/event_v1_004.bin  — edge case (all zeros except magic)
  tests/contracts/event_vectors/event_v1_005.bin  — edge case (max values)
  tests/contracts/event_vectors/README.md         — field values for each vector
"""

import struct
import json
import os
import hashlib

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "event_vectors")
os.makedirs(OUTPUT_DIR, exist_ok=True)

EVENT_MAGIC = 0x41454731
EVENT_VERSION = 1
WIRE_PAYLOAD_SIZE = 109

# Format string: little-endian, field-by-field (matches wire_v1.md)
# I=u32, H=u16, Q=u64, B=u8, 16s=bytes[16]
FORMAT = "<IHHQQQBIHIHQBBBBIBIQIQBBBI16s"
assert struct.calcsize(FORMAT) == WIRE_PAYLOAD_SIZE

def encode_event(fields):
    """Encode event fields to 109-byte wire format."""
    return struct.pack(FORMAT, *fields)

# ============================================================
# Test Vectors
# ============================================================

vectors = []

# --- Vector 001: Benign forward event ---
v1_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION,
    "struct_size": WIRE_PAYLOAD_SIZE,
    "event_id": 1001,
    "timestamp_ms": 1700000000000,
    "monotonic_ns": 999999999,
    "source": 1,  # wfp_sensor
    "source_ip": 0xC0A80164,  # 192.168.1.100
    "source_port": 12345,
    "dest_ip": 0x0A000001,  # 10.0.0.1
    "dest_port": 80,
    "session_id": 42,
    "protocol": 6,  # TCP
    "direction": 0,  # inbound
    "layer_id": 1,  # WFP
    "is_pipe": 0,
    "event_type": 2,  # forward
    "severity": 0,  # Low
    "rule_id": 0,
    "ruleset_version": 1,
    "payload_length": 512,
    "payload_hash": 0,
    "policy_action": 0,  # allow
    "enforcement_status": 0,
    "defcon_impact": 5,  # normal
    "context_flags": 0,
    "reserved": b"\x00" * 16,
}
vectors.append(("event_v1_001.bin", v1_fields, "Benign forward event (192.168.1.100 -> 10.0.0.1:80)"))

# --- Vector 002: APT block event ---
v2_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION,
    "struct_size": WIRE_PAYLOAD_SIZE,
    "event_id": 2002,
    "timestamp_ms": 1700000001000,
    "monotonic_ns": 1000000000,
    "source": 1,  # wfp_sensor
    "source_ip": 0xC0A81010,  # 192.168.16.16 (APT)
    "source_port": 54321,
    "dest_ip": 0x0A000001,  # 10.0.0.1
    "dest_port": 445,  # SMB
    "session_id": 999,
    "protocol": 6,  # TCP
    "direction": 0,  # inbound
    "layer_id": 1,  # WFP
    "is_pipe": 0,
    "event_type": 0,  # block
    "severity": 3,  # Critical
    "rule_id": 0xABCDEF01,
    "ruleset_version": 2,
    "payload_length": 256,
    "payload_hash": 0xDEADBEEFCAFEBABE,
    "policy_action": 2,  # block
    "enforcement_status": 1,  # enforced
    "defcon_impact": 1,  # critical
    "context_flags": 0x0B,  # threat_intel + apt + high_confidence
    "reserved": b"\x00" * 16,
}
vectors.append(("event_v1_002.bin", v2_fields, "APT block event (192.168.16.16 -> 10.0.0.1:445 SMB)"))

# --- Vector 003: Host event (process start) ---
v3_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION,
    "struct_size": WIRE_PAYLOAD_SIZE,
    "event_id": 3003,
    "timestamp_ms": 1700000002000,
    "monotonic_ns": 2000000000,
    "source": 3,  # minifilter
    "source_ip": 0,
    "source_port": 0,
    "dest_ip": 0,
    "dest_port": 0,
    "session_id": 0,
    "protocol": 0,
    "direction": 0,
    "layer_id": 2,  # kernel
    "is_pipe": 1,  # host event
    "event_type": 5,  # session_start
    "severity": 1,  # Medium
    "rule_id": 0,
    "ruleset_version": 0,
    "payload_length": 0,
    "payload_hash": 0,
    "policy_action": 0,  # allow
    "enforcement_status": 0,
    "defcon_impact": 5,
    "context_flags": 0,
    "reserved": b"\x00" * 16,
}
vectors.append(("event_v1_003.bin", v3_fields, "Host event (process start, minifilter)"))

# --- Vector 004: Edge case (all zeros except magic/version/struct_size) ---
v4_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION,
    "struct_size": WIRE_PAYLOAD_SIZE,
    "event_id": 0,
    "timestamp_ms": 0,
    "monotonic_ns": 0,
    "source": 0,
    "source_ip": 0,
    "source_port": 0,
    "dest_ip": 0,
    "dest_port": 0,
    "session_id": 0,
    "protocol": 0,
    "direction": 0,
    "layer_id": 0,
    "is_pipe": 0,
    "event_type": 0xFFFFFFFF,  # custom
    "severity": 0,
    "rule_id": 0,
    "ruleset_version": 0,
    "payload_length": 0,
    "payload_hash": 0,
    "policy_action": 0,
    "enforcement_status": 0,
    "defcon_impact": 0,
    "context_flags": 0,
    "reserved": b"\x00" * 16,
}
vectors.append(("event_v1_004.bin", v4_fields, "Edge case: all zeros except magic/version (custom event type)"))

# --- Vector 005: Edge case (max values) ---
v5_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION,
    "struct_size": WIRE_PAYLOAD_SIZE,
    "event_id": 0xFFFFFFFFFFFFFFFF,
    "timestamp_ms": 0xFFFFFFFFFFFFFFFF,
    "monotonic_ns": 0xFFFFFFFFFFFFFFFF,
    "source": 255,  # external
    "source_ip": 0xFFFFFFFF,
    "source_port": 0xFFFF,
    "dest_ip": 0xFFFFFFFF,
    "dest_port": 0xFFFF,
    "session_id": 0xFFFFFFFFFFFFFFFF,
    "protocol": 255,
    "direction": 1,
    "layer_id": 255,
    "is_pipe": 1,
    "event_type": 0,  # block
    "severity": 3,  # Critical
    "rule_id": 0xFFFFFFFF,
    "ruleset_version": 0xFFFFFFFFFFFFFFFF,
    "payload_length": 0xFFFFFFFF,
    "payload_hash": 0xFFFFFFFFFFFFFFFF,
    "policy_action": 2,  # block
    "enforcement_status": 2,  # failed
    "defcon_impact": 1,  # critical
    "context_flags": 0xFFFFFFFF,
    "reserved": b"\xFF" * 16,
}
vectors.append(("event_v1_005.bin", v5_fields, "Edge case: all max values (0xFF everywhere)"))

# ============================================================
# Write vectors + README
# ============================================================

readme_lines = [
    "# Cross-Language Test Vectors for Canonical Event v1",
    "",
    "## Format",
    "",
    "Each .bin file is exactly 109 bytes (WIRE_PAYLOAD_SIZE).",
    "All fields are little-endian, explicit field-by-field encoding.",
    "No struct memcpy, no pointer cast.",
    "",
    "## Vectors",
    "",
]

metadata = {"format": FORMAT, "size": WIRE_PAYLOAD_SIZE, "vectors": []}

for filename, fields, description in vectors:
    # Encode
    field_values = (
        fields["magic"], fields["version"], fields["struct_size"],
        fields["event_id"], fields["timestamp_ms"], fields["monotonic_ns"],
        fields["source"], fields["source_ip"], fields["source_port"],
        fields["dest_ip"], fields["dest_port"], fields["session_id"],
        fields["protocol"], fields["direction"], fields["layer_id"], fields["is_pipe"],
        fields["event_type"], fields["severity"], fields["rule_id"], fields["ruleset_version"],
        fields["payload_length"], fields["payload_hash"],
        fields["policy_action"], fields["enforcement_status"], fields["defcon_impact"],
        fields["context_flags"], fields["reserved"],
    )
    data = encode_event(field_values)

    # Write binary
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    # Compute SHA256
    sha256 = hashlib.sha256(data).hexdigest()

    # Add to README
    readme_lines.append(f"### {filename}")
    readme_lines.append(f"- Description: {description}")
    readme_lines.append(f"- Size: {len(data)} bytes")
    readme_lines.append(f"- SHA256: `{sha256}`")
    readme_lines.append(f"- Magic at offset 0: 0x{data[0]:02X}{data[1]:02X}{data[2]:02X}{data[3]:02X}")
    readme_lines.append("")

    # Add to metadata
    metadata["vectors"].append({
        "file": filename,
        "description": description,
        "sha256": sha256,
        "size": len(data),
        "fields": {k: v if not isinstance(v, bytes) else v.hex() for k, v in fields.items()},
    })

    print(f"  {filename}: {len(data)} bytes, SHA256={sha256[:16]}...")

# Write README
readme_path = os.path.join(OUTPUT_DIR, "README.md")
with open(readme_path, "w") as f:
    f.write("\n".join(readme_lines))
    f.write("\n")

# Write metadata JSON
meta_path = os.path.join(OUTPUT_DIR, "vectors_metadata.json")
with open(meta_path, "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\nTest vectors written to: {OUTPUT_DIR}")
print(f"  5 binary vectors (109 bytes each)")
print(f"  README.md (human-readable)")
print(f"  vectors_metadata.json (machine-readable)")
