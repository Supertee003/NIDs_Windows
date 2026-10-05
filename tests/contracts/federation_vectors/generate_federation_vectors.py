#!/usr/bin/env python3
"""Generate cross-language golden vectors for the federation wire v1.

Mirrors tests/contracts/event_vectors/generate_test_vectors.py: a Python
reference encoder builds frames per src/federation/federation_codec.zig
(12-B header: magic u32 LE, version u8, msg_type u8, payload_len u16 LE,
crc32 u32 LE over the payload; payload fields little-endian, byte
slices as [u8 len][raw], f32 as bitcast LE, CRC32 IEEE).

Output (frozen — wire changes regenerate all three in the same patch):
  tests/contracts/federation_vectors/fed_v1_001.bin — heartbeat
  tests/contracts/federation_vectors/fed_v1_002.bin — incident w/ node
  tests/contracts/federation_vectors/fed_v1_003.bin — threat-intel share
  tests/contracts/federation_vectors/README.md
  tests/contracts/federation_vectors/vectors_metadata.json

Consumers: tests/contracts/test_federation_wire_v1.py (Python reference
codec must reproduce these bytes exactly) and the decode tests in
src/federation/federation_codec.zig (Zig must read them identically).
"""

import hashlib
import json
import os
import struct
import zlib

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

MAGIC = 0x41454749  # "AEGI"
VERSION = 1

# MessageType ordinals (cluster_coord.zig)
HEARTBEAT = 0
INCIDENT_REPORT = 3
THREAT_INTEL_SHARE = 4

# IncidentSeverity ordinals
SEV_INFO = 0
SEV_HIGH = 3


def _bytes_blob(raw: bytes) -> bytes:
    assert len(raw) <= 255
    return struct.pack("B", len(raw)) + raw


def encode_payload(msg: dict) -> bytes:
    p = b""
    p += struct.pack("<I", msg["from_node_id"])
    p += struct.pack("<I", msg["to_node_id"])
    p += struct.pack("<q", msg["timestamp_ns"])
    p += struct.pack("<I", msg["seq"])
    node = msg.get("node")
    if node is None:
        p += struct.pack("B", 0)
    else:
        p += struct.pack("B", 1)
        p += struct.pack("<I", node["node_id"])
        p += _bytes_blob(node["name"])
        p += _bytes_blob(node["endpoint"])
        p += struct.pack("B", node["role"])
        p += struct.pack("B", node["health"])
        p += struct.pack("<H", node["capacity"])
        p += struct.pack("<q", node["joined_ns"])
        p += struct.pack("<q", node["last_seen_ns"])
    inc = msg["incident"]
    p += bytes(inc["source_ip"])
    p += struct.pack("<H", inc["remote_port"])
    p += struct.pack("B", inc["proto"])
    p += struct.pack("B", inc["severity"])
    p += struct.pack("<f", inc["score"])
    p += _bytes_blob(inc["label"])
    ti = msg.get("threat_intel")
    if ti is None:
        p += struct.pack("B", 0)
    else:
        p += struct.pack("B", 1)
        p += struct.pack("B", ti["kind"])
        p += bytes(ti["ip"])
        assert len(ti["hash"]) == 16
        p += bytes(ti["hash"])
        p += _bytes_blob(ti["domain"])
        p += struct.pack("<I", ti["source_node_id"])
        p += struct.pack("<q", ti["first_seen_ns"])
        p += struct.pack("B", ti["confidence"])
    p += struct.pack("<I", msg["leader_node_id"])
    return p


def encode_frame(msg_type: int, payload: bytes) -> bytes:
    assert len(payload) <= 4096 - 12
    header = struct.pack("<I", MAGIC)
    header += struct.pack("B", VERSION)
    header += struct.pack("B", msg_type)
    header += struct.pack("<H", len(payload))
    header += struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    assert len(header) == 12
    return header + payload


def blank_incident() -> dict:
    return {"source_ip": [0, 0, 0, 0], "remote_port": 0, "proto": 6,
            "severity": SEV_INFO, "score": 0.0, "label": b""}


T0 = 1700000000000000000

vectors = [
    ("fed_v1_001.bin", HEARTBEAT, {
        "from_node_id": 7, "to_node_id": 0, "timestamp_ns": T0, "seq": 1,
        "node": None, "incident": blank_incident(), "threat_intel": None,
        "leader_node_id": 0,
    }, "Heartbeat node 7 -> broadcast, seq 1, no node/TI blocks"),
    ("fed_v1_002.bin", INCIDENT_REPORT, {
        "from_node_id": 7, "to_node_id": 9, "timestamp_ns": T0 + 1000, "seq": 42,
        "node": {"node_id": 7, "name": b"nids-07",
                 "endpoint": b"192.168.126.1:9001", "role": 0, "health": 0,
                 "capacity": 1000, "joined_ns": T0 - 3600000000000,
                 "last_seen_ns": T0 + 1000},
        "incident": {"source_ip": [10, 0, 0, 14], "remote_port": 53,
                     "proto": 17, "severity": SEV_HIGH, "score": 7.5,
                     "label": b"DNS-TUNNEL"},
        "threat_intel": None, "leader_node_id": 0,
    }, "Incident node 7 -> node 9 with announcement, DNS tunnel High 7.5"),
    ("fed_v1_003.bin", THREAT_INTEL_SHARE, {
        "from_node_id": 9, "to_node_id": 0, "timestamp_ns": T0 + 2000, "seq": 7,
        "node": None, "incident": blank_incident(),
        "threat_intel": {"kind": 0, "ip": [10, 0, 0, 14],
                         "hash": list(range(1, 17)), "domain": b"evil.com",
                         "source_node_id": 9, "first_seen_ns": T0 + 2000,
                         "confidence": 90},
        "leader_node_id": 2,
    }, "Threat-intel share node 9 -> broadcast, malicious IP 10.0.0.14"),
]

readme_lines = [
    "# Federation Wire v1 Golden Vectors",
    "",
    "12-byte header (magic u32 LE `AEGI`, version u8, msg_type u8,",
    "payload_len u16 LE, crc32 u32 LE) + payload. All payload fields",
    "little-endian; byte slices are `[u8 len][raw]`; f32 is bitcast LE;",
    "CRC32 is IEEE (zlib). Frozen: a wire change regenerates every",
    "vector in the same patch (one schema, N codecs).",
    "",
    "## Vectors",
    "",
]

metadata = {"magic": "AEGI", "version": 1, "header_len": 12, "vectors": []}

for filename, msg_type, msg, description in vectors:
    payload = encode_payload(msg)
    data = encode_frame(msg_type, payload)
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(data)
    sha256 = hashlib.sha256(data).hexdigest()
    readme_lines.append(f"### {filename}")
    readme_lines.append(f"- Description: {description}")
    readme_lines.append(f"- Size: {len(data)} bytes")
    readme_lines.append(f"- SHA256: `{sha256}`")
    readme_lines.append("")
    metadata["vectors"].append({
        "file": filename, "msg_type": msg_type, "description": description,
        "sha256": sha256, "size": len(data),
    })
    print(f"  {filename}: {len(data)} bytes, SHA256={sha256[:16]}...")

with open(os.path.join(OUTPUT_DIR, "README.md"), "w") as f:
    f.write("\n".join(readme_lines))
    f.write("\n")

with open(os.path.join(OUTPUT_DIR, "vectors_metadata.json"), "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\nFederation vectors written to: {OUTPUT_DIR}")
