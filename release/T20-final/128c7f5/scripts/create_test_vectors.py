#!/usr/bin/env python3
"""
Canonical Event Test Vectors — Multi-Language Golden Vectors
"""

VECTORS = [
    {
        "id": "event-001",
        "description": "Benign forward event — WFP sensor, inbound, TCP",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 1001,
            "timestamp_ms": 1700000000000,
            "monotonic_ns": 999999999,
            "source": 1,
            "source_ip": 0xC0A80164,
            "source_port": 12345,
            "dest_ip": 0x0A000001,
            "dest_port": 80,
            "session_id": 42,
            "protocol": 6,
            "direction": 0,
            "layer_id": 1,
            "is_pipe": False,
            "event_type": 2,
            "severity": 0,
            "rule_id": 0,
            "ruleset_version": 1,
            "payload_length": 512,
            "payload_hash": 0,
            "policy_action": 0,
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
        },
        "expected_hex": None,
    },
    {
        "id": "event-002",
        "description": "High severity outbound TCP event — critical threat",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 2005,
            "timestamp_ms": 1700000001000,
            "monotonic_ns": 1234567890,
            "source": 0,
            "source_ip": 0x0A000002,
            "source_port": 54321,
            "dest_ip": 0xC0A801FF,
            "dest_port": 443,
            "session_id": 99,
            "protocol": 6,
            "direction": 1,
            "layer_id": 0,
            "is_pipe": True,
            "event_type": 1,
            "severity": 3,
            "rule_id": 999,
            "ruleset_version": 3,
            "payload_length": 8192,
            "payload_hash": 0xDEADBEEFCAFEBABE,
            "policy_action": 2,
            "enforcement_status": 1,
            "defcon_impact": 1,
            "context_flags": 0b1011,
            "pid": 5678,
            "ppid": 1234,
            "proc_type": 1,
            "integrity": 2,
            "hids_flag": 1,
            "node_id": 42,
            "confidence": 95,
        },
        "expected_hex": None,
    },
    {
        "id": "event-003",
        "description": "WFP layer event — outbound, IP blocked",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 3017,
            "timestamp_ms": 1700000002000,
            "monotonic_ns": 987654321,
            "source": 2,
            "source_ip": 0x0A000000,
            "source_port": 0,
            "dest_ip": 0xC0A80101,
            "dest_port": 80,
            "session_id": 7,
            "protocol": 17,
            "direction": 1,
            "layer_id": 2,
            "is_pipe": False,
            "event_type": 3,
            "severity": 2,
            "rule_id": 42,
            "ruleset_version": 2,
            "payload_length": 256,
            "payload_hash": 0xA1B2C3D4E5F60718,
            "policy_action": 2,
            "enforcement_status": 2,
            "defcon_impact": 3,
            "context_flags": 0b100,
            "pid": 0,
            "ppid": 0,
            "proc_type": 0,
            "integrity": 0,
            "hids_flag": 0,
            "node_id": 0,
            "confidence": 0,
        },
        "expected_hex": None,
    },
    {
        "id": "event-004",
        "description": "Pipe transport event — forwarded from another node",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 4029,
            "timestamp_ms": 1700000003000,
            "monotonic_ns": 555555555,
            "source": 3,
            "source_ip": 0x0A000003,
            "source_port": 8888,
            "dest_ip": 0xC0A80105,
            "dest_port": 22,
            "session_id": 128,
            "protocol": 6,
            "direction": 0,
            "layer_id": 3,
            "is_pipe": True,
            "event_type": 0,
            "severity": 1,
            "rule_id": 7,
            "ruleset_version": 1,
            "payload_length": 128,
            "payload_hash": 0x123456789ABCDEF0,
            "policy_action": 1,
            "enforcement_status": 0,
            "defcon_impact": 4,
            "context_flags": 0b1,
            "pid": 9999,
            "ppid": 8888,
            "proc_type": 2,
            "integrity": 1,
            "hids_flag": 1,
            "node_id": 7,
            "confidence": 80,
        },
        "expected_hex": None,
    },
    {
        "id": "event-005",
        "description": "Critical DEFCON event — maximum severity, all flags",
        "fields": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 109,
            "event_id": 5041,
            "timestamp_ms": 1700000004000,
            "monotonic_ns": 1111111111,
            "source": 1,
            "source_ip": 0xC0A80101,
            "source_port": 80,
            "dest_ip": 0xC0A80102,
            "dest_port": 8080,
            "session_id": 256,
            "protocol": 6,
            "direction": 1,
            "layer_id": 1,
            "is_pipe": False,
            "event_type": 0,
            "severity": 3,
            "rule_id": 255,
            "ruleset_version": 5,
            "payload_length": 4096,
            "payload_hash": 0xFFFFFFFFFFFFFFFF,
            "policy_action": 3,
            "enforcement_status": 3,
            "defcon_impact": 1,
            "context_flags": 0b1111,
            "pid": 65535,
            "ppid": 65535,
            "proc_type": 3,
            "integrity": 3,
            "hids_flag": 3,
            "node_id": 15,
            "confidence": 100,
        },
        "expected_hex": None,
    },
]

import struct

def vector_to_hex(fields):
    buf = bytearray(109)
    struct.pack_into('<I', buf, 0, fields["magic"])
    struct.pack_into('<H', buf, 4, fields["version"])
    struct.pack_into('<H', buf, 6, fields["struct_size"])
    struct.pack_into('<Q', buf, 8, fields["event_id"])
    struct.pack_into('<Q', buf, 16, fields["timestamp_ms"])
    struct.pack_into('<Q', buf, 24, fields["monotonic_ns"])
    buf[32] = fields["source"]
    struct.pack_into('<I', buf, 33, fields["source_ip"])
    struct.pack_into('<H', buf, 37, fields["source_port"])
    struct.pack_into('<I', buf, 39, fields["dest_ip"])
    struct.pack_into('<H', buf, 43, fields["dest_port"])
    struct.pack_into('<Q', buf, 45, fields["session_id"])
    buf[53] = fields["protocol"]
    buf[54] = fields["direction"]
    buf[55] = fields["layer_id"]
    buf[56] = fields["is_pipe"]
    struct.pack_into('<I', buf, 57, fields["event_type"])
    buf[61] = fields["severity"]
    struct.pack_into('<I', buf, 62, fields["rule_id"])
    struct.pack_into('<Q', buf, 66, fields["ruleset_version"])
    struct.pack_into('<I', buf, 74, fields["payload_length"])
    struct.pack_into('<Q', buf, 78, fields["payload_hash"])
    buf[86] = fields["policy_action"]
    buf[87] = fields["enforcement_status"]
    buf[88] = fields["defcon_impact"]
    struct.pack_into('<I', buf, 89, fields["context_flags"])
    buf[93:109] = b'\x00' * 16
    return buf.hex()

for v in VECTORS:
    v["expected_hex"] = vector_to_hex(v["fields"])

# Validate all vectors
for v in VECTORS:
    h = v["expected_hex"]
    assert len(h) == 218, f"{v['id']}: hex length {len(h)} != 218"
    assert all(c in '0123456789abcdef' for c in h), f"{v['id']}: non-hex chars"
    vs = int(h[12:16], 16)
    assert vs == 109, f"{v['id']}: struct_size={vs} != 109"

# Print summary
sev_names = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
pol_names = {0: "allow", 1: "alert", 2: "block", 3: "quarantine"}
dec_names = {1: "normal", 2: "warning", 3: "critical", 4: "moderate", 5: "critical"}
src_names = {0: "pipe_source", 1: "wfp_sensor", 2: "kernel_sensor", 3: "pipe_sensor"}
dir_names = {0: "inbound", 1: "outbound"}

print(f"Created {len(VECTORS)} canonical event test vectors")
print()
for v in VECTORS:
    s = sev_names.get(v["fields"]["severity"], "?")
    p = pol_names.get(v["fields"]["policy_action"], "?")
    d = dec_names.get(v["fields"]["defcon_impact"], "?")
    src = src_names.get(v["fields"]["source"], "?")
    d2 = dir_names.get(v["fields"]["direction"], "?")
    pname = "TCP" if v["fields"]["protocol"]==6 else "UDP" if v["fields"]["protocol"]==17 else "Other"
    print(f"  {v['id']:12s}  sev={s:6s}  pol={p:8s}  DEFCON={d:8s}  src={src:15s}  dir={d2:8s}  proto={pname}")

print()
print("Validation: all 109-byte hex strings = 218 chars, struct_size=109 confirmed")
print("Vectors ready for multi-language cross-verification (Go/Zig/C/Rust/Python)")