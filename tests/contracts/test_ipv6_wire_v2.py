"""T2-V6-022a: IPv6 full-identity wire v2 pins (Python side).

The committed event_v2_006.bin (frozen by generate_test_vectors.py) must:
  V1. Decode to 2001:0db8::1 -> 2001:0db8::2 with bit2 set (never IPv4).
  V2. Round-trip through the Python reference codec byte-identically.
  V3. Reject guards hold: missing bit2, first-4 mismatch, truncated v2.
  V4. v1 behavior frozen: 109-byte frames decode with zero v6 sidecars.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from shared.wire.wire_codec import (  # noqa: E402
    CONTEXT_V6_TRUNCATED,
    WIRE_PAYLOAD_SIZE,
    WIRE_V2_PAYLOAD_SIZE,
    CanonicalEvent,
    EventSource,
    EventType,
    PolicyAction,
    WireCodec,
)

VEC = REPO_ROOT / "tests" / "contracts" / "event_vectors" / "event_vectors" / "event_v2_006.bin"
SRC6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x01])
DST6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x02])


def _v6_event() -> CanonicalEvent:
    return CanonicalEvent(
        event_id=6006,
        timestamp_ms=1700000006000,
        monotonic_ns=6000000000,
        source=EventSource.npcap_sensor,
        source_ip=0x20010DB8,
        source_port=49152,
        dest_ip=0x20010DB8,
        dest_port=443,
        session_id=6060,
        protocol=6,
        event_type=EventType.forward,
        severity=1,
        ruleset_version=3,
        payload_length=1500,
        policy_action=PolicyAction.allow,
        defcon_impact=5,
        context_flags=CONTEXT_V6_TRUNCATED,
        src_ipv6=SRC6,
        dst_ipv6=DST6,
    )


def test_committed_v2_vector_decodes_to_full_identity():
    raw = VEC.read_bytes()
    assert len(raw) == WIRE_V2_PAYLOAD_SIZE
    e = WireCodec.decode_event(raw)
    assert e is not None
    assert e.version == 2
    assert e.context_flags & CONTEXT_V6_TRUNCATED != 0
    assert e.src_ipv6 == SRC6
    assert e.dst_ipv6 == DST6
    assert e.source_ip == 0x20010DB8


def test_python_encoder_reproduces_committed_v2_bytes():
    raw = VEC.read_bytes()
    assert WireCodec.encode_event_v2(_v6_event()) == raw


def test_v2_guards():
    import pytest

    e = _v6_event()
    e.context_flags = 0
    with pytest.raises(ValueError):
        WireCodec.encode_event_v2(e)
    e = _v6_event()
    e.source_ip = 0x0A000001
    with pytest.raises(ValueError):
        WireCodec.encode_event_v2(e)
    raw = VEC.read_bytes()
    assert WireCodec.decode_event(raw[:WIRE_PAYLOAD_SIZE]) is None
    assert WireCodec.decode_event(b"\x00" * 10) is None


def test_v1_still_decodes_with_zero_sidecars():
    e = _v6_event()
    v1 = WireCodec.encode_event(e)[:WIRE_PAYLOAD_SIZE]
    # encode_event stamps version 1 with the same v1 prefix bytes.
    back = WireCodec.decode_event(v1)
    assert back is not None
    assert back.version == 1
    assert back.src_ipv6 == b"\x00" * 16
    assert back.dst_ipv6 == b"\x00" * 16


def test_over_length_v1_frame_decodes_as_v1():
    # Hardening parity with Go/Zig/C++: version 1 with trailing bytes
    # decodes on the frozen path (first 109 bytes, tail ignored).
    e = _v6_event()
    v1 = WireCodec.encode_event(e) + b"\xAB" * 24
    back = WireCodec.decode_event(v1)
    assert back is not None
    assert back.version == 1
    assert back.src_ipv6 == b"\x00" * 16
    assert back.dst_ipv6 == b"\x00" * 16
