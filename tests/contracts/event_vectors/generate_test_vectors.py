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
# struct_size stamps the sender in-memory layout (128, like every live
# producer), never the wire length — strict decoders in all languages
# require 128 (see wire_v2.md).
IN_MEMORY_STRUCT_SIZE = 128

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
    "struct_size": IN_MEMORY_STRUCT_SIZE,
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
    "struct_size": IN_MEMORY_STRUCT_SIZE,
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
    "struct_size": IN_MEMORY_STRUCT_SIZE,
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
    "struct_size": IN_MEMORY_STRUCT_SIZE,
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
    "struct_size": IN_MEMORY_STRUCT_SIZE,
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
# Wire v2 vectors (T2-V6-022a): v1 109 bytes ++ 24-byte IPv6 tail.
# struct_size stamps the live in-memory size (128), per wire_v2.md.
# ============================================================

EVENT_VERSION_V2 = 2
FORMAT_V2 = FORMAT + "12s12s"
assert struct.calcsize(FORMAT_V2) == 133

SRC6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x01])  # 2001:0db8::1
DST6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x02])  # 2001:0db8::2

# --- Vector 006: IPv6 forward, full identity (2001:db8::1 -> ::2) ---
v6_fields = {
    "magic": EVENT_MAGIC,
    "version": EVENT_VERSION_V2,
    "struct_size": IN_MEMORY_STRUCT_SIZE,
    "event_id": 6006,
    "timestamp_ms": 1700000006000,
    "monotonic_ns": 6000000000,
    "source": 9,  # npcap_sensor
    "source_ip": 0x20010DB8,  # first 4 bytes of 2001:0db8::1
    "source_port": 49152,
    "dest_ip": 0x20010DB8,  # first 4 bytes of 2001:0db8::2
    "dest_port": 443,
    "session_id": 6060,
    "protocol": 6,  # TCP
    "direction": 0,  # inbound
    "layer_id": 0,
    "is_pipe": 0,
    "event_type": 2,  # forward
    "severity": 1,  # Medium
    "rule_id": 0,
    "ruleset_version": 3,
    "payload_length": 1500,
    "payload_hash": 0,
    "policy_action": 0,  # allow
    "enforcement_status": 0,
    "defcon_impact": 5,  # normal
    "context_flags": 0x04,  # ipv6 (bit2): 32-bit fields are NOT IPv4
    "reserved": b"\x00" * 16,
    "src_tail": SRC6[4:16],
    "dst_tail": DST6[4:16],
}
vectors_v2 = [("event_v2_006.bin", v6_fields, "IPv6 forward, full identity (2001:db8::1 -> 2001:db8::2:443)")]

# ============================================================
# Wire v3 vectors (PAYLOAD-ENVELOPE-V3-001)
# v3 = frozen v2 133-byte base (zero tail when bit2 clear) + 32-byte
# envelope + bounded payload. Envelope format: "<HBBHHIQIII" = 32 bytes.
# ============================================================

import zlib

EVENT_VERSION_V3 = 3
V3_BASE_SIZE = 133
V3_ENVELOPE_SIZE = 32
WIRE_V3_HEADER_SIZE = V3_BASE_SIZE + V3_ENVELOPE_SIZE  # 165
V3_FORMAT = "<HBBHHIQIII"
assert struct.calcsize(V3_FORMAT) == V3_ENVELOPE_SIZE


def v3_bytes(fields, envelope_fields, payload, tail):
    base = struct.pack(FORMAT_V2, *fields, *tail)
    assert len(base) == V3_BASE_SIZE
    # v3 always carries the full 133-byte base, including the zero tail.
    base = bytearray(base)
    base[4:6] = EVENT_VERSION_V3.to_bytes(2, "little")
    base[6:8] = IN_MEMORY_STRUCT_SIZE.to_bytes(2, "little")
    env = struct.pack(V3_FORMAT, *envelope_fields)
    assert len(env) == V3_ENVELOPE_SIZE
    return bytes(base) + env + payload

def v3_base_fields(**overrides):
    fields = {
        "magic": EVENT_MAGIC,
        "version": EVENT_VERSION_V3,
        "struct_size": IN_MEMORY_STRUCT_SIZE,
        "event_id": 0,
        "timestamp_ms": 0,
        "monotonic_ns": 0,
        "source": 9,  # npcap_sensor
        "source_ip": 0,
        "source_port": 0,
        "dest_ip": 0,
        "dest_port": 0,
        "session_id": 0,
        "protocol": 6,
        "direction": 0,
        "layer_id": 0,
        "is_pipe": 0,
        "event_type": 2,  # forward
        "severity": 0,
        "rule_id": 0,
        "ruleset_version": 4,
        "payload_length": 0,
        "payload_hash": 0,
        "policy_action": 0,
        "enforcement_status": 0,
        "defcon_impact": 5,
        "context_flags": 0,
        "reserved": b"\x00" * 16,
    }
    fields.update(overrides)
    return fields


def v3_field_values(fields):
    return (
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


# --- Vector 007: IPv6 complete payload (32 bytes) ---
payload7 = bytes(range(0x40, 0x60))
f7 = v3_base_fields(
    event_id=7007, timestamp_ms=1700000007000, monotonic_ns=7000000000,
    source_ip=0x20010DB8, source_port=49152, dest_ip=0x20010DB8, dest_port=443,
    session_id=7070, protocol=6, severity=1, ruleset_version=4,
    payload_length=len(payload7), context_flags=0x04,  # ipv6 bit2
)
env7 = (
    0x0003,  # payload present | provenance valid
    1,       # complete
    0,       # reserved
    len(payload7), len(payload7), zlib.crc32(payload7) & 0xFFFFFFFF,
    7007, 0x5F5E1000, 5, 0x0A0B0C0D,
)
vec7 = v3_bytes(v3_field_values(f7), env7, payload7, (SRC6[4:16], DST6[4:16]))
vectors_v3 = [
    ("event_v3_007.bin", vec7, "v3 IPv6 complete payload (32 bytes, provenance valid)",
     "v3: 133 base + 32 envelope + 32 payload"),
]

# --- Vector 008: IPv4 truncated payload (64 of 1514 bytes) ---
payload8 = bytes((i * 7 + 3) & 0xFF for i in range(64))
f8 = v3_base_fields(
    event_id=8008, timestamp_ms=1700000008000, monotonic_ns=8000000000,
    source_ip=0xC0A80164, source_port=40000, dest_ip=0x0A000001, dest_port=53,
    session_id=8080, protocol=17, direction=1, event_type=2, severity=0,
    ruleset_version=4, payload_length=len(payload8), policy_action=5,  # log_only
)
env8 = (
    0x0003, 2, 0, len(payload8), 1514, zlib.crc32(payload8) & 0xFFFFFFFF,
    8008, 0x5F5E1000, 2, 0x01020304,
)
vec8 = v3_bytes(v3_field_values(f8), env8, payload8, (b"\x00" * 12, b"\x00" * 12))
vectors_v3.append((
    "event_v3_008.bin", vec8, "v3 IPv4 truncated payload (64 of 1514 bytes)",
    "v3: 133 base + 32 envelope + 64 payload",
))

# --- Vector 009: IPv4 metadata-only (no payload bytes) ---
f9 = v3_base_fields(
    event_id=9009, timestamp_ms=1700000009000, monotonic_ns=9000000000,
    source_ip=0xC0A80164, source_port=40000, dest_ip=0x0A000001, dest_port=80,
    session_id=9090, protocol=6, direction=1, event_type=2, severity=0,
    payload_length=0,
)
env9 = (0x0000, 3, 0, 0, 0, 0, 0, 0, 0, 0)
vec9 = v3_bytes(v3_field_values(f9), env9, b"", (b"\x00" * 12, b"\x00" * 12))
vectors_v3.append((
    "event_v3_009.bin", vec9, "v3 IPv4 metadata-only (no payload bytes)",
    "v3: 133 base + 32 envelope (no payload)",
))

# ============================================================
# Write vectors + README
# ============================================================

readme_lines = [
    "# Cross-Language Test Vectors for Canonical Event",
    "",
    "## Format",
    "",
    "v1 vectors are exactly 109 bytes; v2 vectors are 133 bytes; v3 vectors",
    "are 165 + payload-length bytes (133-byte base + 32-byte envelope +",
    "bounded payload). All fields are little-endian, explicit field-by-field",
    "encoding. No struct memcpy, no pointer cast.",
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

for filename, fields, description in vectors_v2:
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
        fields["src_tail"], fields["dst_tail"],
    )
    data = struct.pack(FORMAT_V2, *field_values)
    assert len(data) == 133

    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    sha256 = hashlib.sha256(data).hexdigest()

    readme_lines.append(f"### {filename}")
    readme_lines.append(f"- Description: {description}")
    readme_lines.append(f"- Size: {len(data)} bytes (v2: 109 + 24 tail)")
    readme_lines.append(f"- SHA256: `{sha256}`")
    readme_lines.append(f"- Magic at offset 0: 0x{data[0]:02X}{data[1]:02X}{data[2]:02X}{data[3]:02X}")
    readme_lines.append("")

    metadata["vectors"].append({
        "file": filename,
        "description": description,
        "sha256": sha256,
        "size": len(data),
        "fields": {k: v if not isinstance(v, bytes) else v.hex() for k, v in fields.items()},
    })

    print(f"  {filename}: {len(data)} bytes, SHA256={sha256[:16]}...")

for filename, data, description, size_note in vectors_v3:
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    sha256 = hashlib.sha256(data).hexdigest()

    readme_lines.append(f"### {filename}")
    readme_lines.append(f"- Description: {description}")
    readme_lines.append(f"- Size: {len(data)} bytes ({size_note})")
    readme_lines.append(f"- SHA256: `{sha256}`")
    readme_lines.append(f"- Magic at offset 0: 0x{data[0]:02X}{data[1]:02X}{data[2]:02X}{data[3]:02X}")
    readme_lines.append("")

    metadata["vectors"].append({
        "file": filename,
        "description": description,
        "sha256": sha256,
        "size": len(data),
        "version": EVENT_VERSION_V3,
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
print(f"  5 binary vectors (109 bytes each, v1 frozen)")
print(f"  1 binary vector (133 bytes, v2 full IPv6)")
print(f"  3 binary vectors (v3 bounded payload + provenance)")
print(f"  README.md (human-readable)")
print(f"  vectors_metadata.json (machine-readable)")
