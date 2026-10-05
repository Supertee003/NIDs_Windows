"""FED-P1B: federation wire v1 golden pins (Python side).

The committed fed_v1_*.bin (frozen by
tests/contracts/federation_vectors/generate_federation_vectors.py)
must:
  F1. Decode to the documented heartbeat / incident / threat-intel
      messages with exact fields (f32 score bit-identical, not close).
  F2. Round-trip through the independent Python reference codec
      (shared/federation/fed_codec.py) byte-identically — two
      implementations agreeing is the pin, not self-consistency.
  F3. Reject guards hold: bad magic, bad CRC, truncated frame,
      invalid msg_type.
The Zig side pins the same bytes in src/federation/federation_codec.zig
(decode of the committed files), so neither tier can drift the wire
alone. Frozen: a wire change regenerates every vector in the same patch.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from shared.federation.fed_codec import (  # noqa: E402
    FedWireError,
    decode_frame,
    encode_message,
)

VEC_DIR = REPO_ROOT / "tests" / "contracts" / "federation_vectors"
T0 = 1700000000000000000


def _heartbeat() -> dict:
    return {"msg_type": 0, "from_node_id": 7, "to_node_id": 0,
            "timestamp_ns": T0, "seq": 1, "node": None,
            "incident": {"source_ip": [0, 0, 0, 0], "remote_port": 0,
                         "proto": 6, "severity": 0, "score": 0.0,
                         "label": b""},
            "threat_intel": None, "leader_node_id": 0}


def _incident() -> dict:
    return {"msg_type": 3, "from_node_id": 7, "to_node_id": 9,
            "timestamp_ns": T0 + 1000, "seq": 42,
            "node": {"node_id": 7, "name": b"nids-07",
                     "endpoint": b"192.168.126.1:9001", "role": 0,
                     "health": 0, "capacity": 1000,
                     "joined_ns": T0 - 3600000000000,
                     "last_seen_ns": T0 + 1000},
            "incident": {"source_ip": [10, 0, 0, 14], "remote_port": 53,
                         "proto": 17, "severity": 3, "score": 7.5,
                         "label": b"DNS-TUNNEL"},
            "threat_intel": None, "leader_node_id": 0}


def _intel() -> dict:
    return {"msg_type": 4, "from_node_id": 9, "to_node_id": 0,
            "timestamp_ns": T0 + 2000, "seq": 7, "node": None,
            "incident": {"source_ip": [0, 0, 0, 0], "remote_port": 0,
                         "proto": 6, "severity": 0, "score": 0.0,
                         "label": b""},
            "threat_intel": {"kind": 0, "ip": [10, 0, 0, 14],
                             "hash": bytes(range(1, 17)),
                             "domain": b"evil.com", "source_node_id": 9,
                             "first_seen_ns": T0 + 2000, "confidence": 90},
            "leader_node_id": 2}


def test_committed_heartbeat_decodes_to_documented_fields():
    m = decode_frame((VEC_DIR / "fed_v1_001.bin").read_bytes())
    assert m["msg_type"] == 0
    assert m["from_node_id"] == 7
    assert m["to_node_id"] == 0
    assert m["timestamp_ns"] == T0
    assert m["seq"] == 1
    assert m["node"] is None
    assert m["threat_intel"] is None
    assert m["leader_node_id"] == 0


def test_committed_incident_decodes_with_node_and_score():
    m = decode_frame((VEC_DIR / "fed_v1_002.bin").read_bytes())
    assert m["msg_type"] == 3
    assert m["from_node_id"] == 7 and m["to_node_id"] == 9
    assert m["seq"] == 42
    assert m["node"]["name"] == b"nids-07"
    assert m["node"]["endpoint"] == b"192.168.126.1:9001"
    assert m["node"]["capacity"] == 1000
    assert m["incident"]["source_ip"] == [10, 0, 0, 14]
    assert m["incident"]["remote_port"] == 53
    assert m["incident"]["proto"] == 17
    assert m["incident"]["severity"] == 3
    assert m["incident"]["score"] == 7.5  # exact: bitcast LE, not float IO
    assert m["incident"]["label"] == b"DNS-TUNNEL"


def test_committed_intel_decodes_with_ti_block():
    m = decode_frame((VEC_DIR / "fed_v1_003.bin").read_bytes())
    assert m["msg_type"] == 4
    assert m["from_node_id"] == 9 and m["seq"] == 7
    ti = m["threat_intel"]
    assert ti["kind"] == 0
    assert ti["ip"] == [10, 0, 0, 14]
    assert ti["hash"] == bytes(range(1, 17))
    assert ti["domain"] == b"evil.com"
    assert ti["source_node_id"] == 9
    assert ti["confidence"] == 90
    assert m["leader_node_id"] == 2


def test_reference_encoder_reproduces_committed_bytes():
    for name, msg in (("fed_v1_001.bin", _heartbeat()),
                      ("fed_v1_002.bin", _incident()),
                      ("fed_v1_003.bin", _intel())):
        assert encode_message(msg) == (VEC_DIR / name).read_bytes(), name


def test_wire_guards():
    import pytest

    raw = bytearray((VEC_DIR / "fed_v1_001.bin").read_bytes())
    bad = bytes(raw)
    bad = b"\x00" + bad[1:]
    with pytest.raises(FedWireError):
        decode_frame(bad)  # magic
    bad = bytearray(raw)
    bad[8] ^= 0xFF
    with pytest.raises(FedWireError):
        decode_frame(bytes(bad))  # crc
    with pytest.raises(FedWireError):
        decode_frame(bytes(raw[:11]))  # truncated header
    with pytest.raises(FedWireError):
        decode_frame(bytes(raw[:20]))  # truncated payload
    bad = bytearray(raw)
    bad[5] = 99
    with pytest.raises(FedWireError):
        decode_frame(bytes(bad))  # invalid msg_type
