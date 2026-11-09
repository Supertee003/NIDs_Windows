"""PAYLOAD-ENVELOPE-V3-001: wire v3 bounded-payload + provenance pins (Python).

The committed v3 vectors (frozen by generate_test_vectors.py) must:

  V1. Decode to the same event identity as their v2 base and carry the
      exact payload bytes, envelope metadata, and provenance.
  V2. Round-trip through the Python reference codec byte-identically.
  V3. Strict envelope guards fail closed (crc, length, completeness,
      payload presence, zero v6 tail when bit2 is clear).
  V4. v1/v2 stay byte-identical metadata-only compatibility frames
      (no envelope, no payload bytes).
"""
from __future__ import annotations

import sys
import zlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from shared.wire.wire_codec import (  # noqa: E402
    CONTEXT_V6_TRUNCATED,
    PAYLOAD_COMPLETE,
    PAYLOAD_METADATA_ONLY,
    PAYLOAD_TRUNCATED,
    V3_BASE_SIZE,
    V3_ENVELOPE_SIZE,
    V3_FLAG_PAYLOAD_PRESENT,
    V3_FLAG_PROVENANCE_VALID,
    V3_MAX_PAYLOAD,
    WIRE_PAYLOAD_SIZE,
    WIRE_V2_PAYLOAD_SIZE,
    WIRE_V3_HEADER_SIZE,
    CanonicalEvent,
    EventSource,
    EventType,
    PayloadEnvelope,
    PolicyAction,
    WireCodec,
    validate_v3_envelope,
)

VECTOR_DIR = REPO_ROOT / "tests" / "contracts" / "event_vectors" / "event_vectors"
VEC_007 = VECTOR_DIR / "event_v3_007.bin"
VEC_008 = VECTOR_DIR / "event_v3_008.bin"
VEC_009 = VECTOR_DIR / "event_v3_009.bin"

SRC6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x01])
DST6 = bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x02])

PAYLOAD_007 = bytes(range(0x40, 0x60))
PAYLOAD_008 = bytes((i * 7 + 3) & 0xFF for i in range(64))


def _event_007() -> CanonicalEvent:
    return CanonicalEvent(
        version=3,
        struct_size=128,
        event_id=7007,
        timestamp_ms=1700000007000,
        monotonic_ns=7000000000,
        source=EventSource.npcap_sensor,
        source_ip=0x20010DB8,
        source_port=49152,
        dest_ip=0x20010DB8,
        dest_port=443,
        session_id=7070,
        protocol=6,
        direction=0,
        event_type=EventType.forward,
        severity=1,
        ruleset_version=4,
        payload_length=len(PAYLOAD_007),
        policy_action=PolicyAction.allow,
        defcon_impact=5,
        context_flags=CONTEXT_V6_TRUNCATED,
        src_ipv6=SRC6,
        dst_ipv6=DST6,
    )


def _env_007() -> PayloadEnvelope:
    return PayloadEnvelope(
        flags=V3_FLAG_PAYLOAD_PRESENT | V3_FLAG_PROVENANCE_VALID,
        completeness=PAYLOAD_COMPLETE,
        payload_len=len(PAYLOAD_007),
        original_len=len(PAYLOAD_007),
        payload_crc32=zlib.crc32(PAYLOAD_007) & 0xFFFFFFFF,
        capture_sequence=7007,
        producer_epoch=0x5F5E1000,
        producer_generation=5,
        interface_id=0x0A0B0C0D,
    )


def _event_008() -> CanonicalEvent:
    return CanonicalEvent(
        version=3,
        struct_size=128,
        event_id=8008,
        timestamp_ms=1700000008000,
        monotonic_ns=8000000000,
        source=EventSource.npcap_sensor,
        source_ip=0xC0A80164,
        source_port=40000,
        dest_ip=0x0A000001,
        dest_port=53,
        session_id=8080,
        protocol=17,
        direction=1,
        event_type=EventType.forward,
        severity=0,
        ruleset_version=4,
        payload_length=len(PAYLOAD_008),
        policy_action=PolicyAction.log_only,
        defcon_impact=5,
        context_flags=0,
    )


def _env_008() -> PayloadEnvelope:
    return PayloadEnvelope(
        flags=V3_FLAG_PAYLOAD_PRESENT | V3_FLAG_PROVENANCE_VALID,
        completeness=PAYLOAD_TRUNCATED,
        payload_len=len(PAYLOAD_008),
        original_len=1514,
        payload_crc32=zlib.crc32(PAYLOAD_008) & 0xFFFFFFFF,
        capture_sequence=8008,
        producer_epoch=0x5F5E1000,
        producer_generation=2,
        interface_id=0x01020304,
    )


def _event_009() -> CanonicalEvent:
    return CanonicalEvent(
        version=3,
        struct_size=128,
        event_id=9009,
        timestamp_ms=1700000009000,
        monotonic_ns=9000000000,
        source=EventSource.npcap_sensor,
        source_ip=0xC0A80164,
        source_port=40000,
        dest_ip=0x0A000001,
        dest_port=80,
        session_id=9090,
        protocol=6,
        direction=1,
        event_type=EventType.forward,
        severity=0,
        ruleset_version=4,
        payload_length=0,
        policy_action=PolicyAction.allow,
        defcon_impact=5,
        context_flags=0,
    )


def _env_009() -> PayloadEnvelope:
    return PayloadEnvelope(completeness=PAYLOAD_METADATA_ONLY)


# ---------------------------------------------------------------------------
# V1: committed vectors decode with the expected identity + envelope.
# ---------------------------------------------------------------------------

def test_committed_v3_complete_vector_decodes_payload_and_provenance():
    raw = VEC_007.read_bytes()
    assert len(raw) == WIRE_V3_HEADER_SIZE + len(PAYLOAD_007)
    e = WireCodec.decode_event(raw)
    assert e is not None
    assert e.version == 3
    assert e.struct_size == 128
    assert e.event_id == 7007
    assert e.context_flags & CONTEXT_V6_TRUNCATED != 0
    assert e.src_ipv6 == SRC6
    assert e.dst_ipv6 == DST6
    assert e.payload_bytes == PAYLOAD_007
    env = e.payload_envelope
    assert env is not None
    assert env.completeness == PAYLOAD_COMPLETE
    assert env.payload_present and env.provenance_valid
    assert env.payload_len == len(PAYLOAD_007)
    assert env.original_len == len(PAYLOAD_007)
    assert env.payload_crc32 == zlib.crc32(PAYLOAD_007) & 0xFFFFFFFF
    assert env.capture_sequence == 7007
    assert env.producer_epoch == 0x5F5E1000
    assert env.producer_generation == 5
    assert env.interface_id == 0x0A0B0C0D


def test_committed_v3_truncated_vector_decodes_captured_prefix():
    raw = VEC_008.read_bytes()
    assert len(raw) == WIRE_V3_HEADER_SIZE + len(PAYLOAD_008)
    e = WireCodec.decode_event(raw)
    assert e is not None
    assert e.version == 3
    assert e.event_id == 8008
    assert e.source_ip == 0xC0A80164
    assert e.dest_port == 53
    assert e.protocol == 17
    assert e.src_ipv6 == b"\x00" * 16
    assert e.dst_ipv6 == b"\x00" * 16
    assert e.payload_bytes == PAYLOAD_008
    env = e.payload_envelope
    assert env is not None
    assert env.completeness == PAYLOAD_TRUNCATED
    assert env.payload_len == len(PAYLOAD_008)
    assert env.original_len == 1514
    assert env.capture_sequence == 8008
    assert env.interface_id == 0x01020304


def test_committed_v3_metadata_only_vector_has_no_payload():
    raw = VEC_009.read_bytes()
    assert len(raw) == WIRE_V3_HEADER_SIZE
    e = WireCodec.decode_event(raw)
    assert e is not None
    assert e.version == 3
    assert e.event_id == 9009
    assert e.payload_bytes == b""
    env = e.payload_envelope
    assert env is not None
    assert env.completeness == PAYLOAD_METADATA_ONLY
    assert not env.payload_present
    assert env.payload_len == 0
    assert env.original_len == 0
    assert env.payload_crc32 == 0
    assert env.capture_sequence == 0
    assert env.producer_epoch == 0
    assert env.producer_generation == 0
    assert env.interface_id == 0


# ---------------------------------------------------------------------------
# V2: byte-identical round-trip on every committed vector.
# ---------------------------------------------------------------------------

def test_python_encoder_reproduces_committed_v3_complete_bytes():
    assert WireCodec.encode_event_v3(_event_007(), _env_007(), PAYLOAD_007) == VEC_007.read_bytes()


def test_python_encoder_reproduces_committed_v3_truncated_bytes():
    assert WireCodec.encode_event_v3(_event_008(), _env_008(), PAYLOAD_008) == VEC_008.read_bytes()


def test_python_encoder_reproduces_committed_v3_metadata_only_bytes():
    assert WireCodec.encode_event_v3(_event_009(), _env_009(), b"") == VEC_009.read_bytes()


def test_v3_frame_roundtrip():
    frame = WireCodec.encode_frame_v3(_event_007(), _env_007(), PAYLOAD_007)
    assert len(frame) == 16 + WIRE_V3_HEADER_SIZE + len(PAYLOAD_007)
    back = WireCodec.decode_frame(frame)
    assert back is not None
    assert back.version == 3
    assert back.payload_bytes == PAYLOAD_007
    assert back.payload_envelope.completeness == PAYLOAD_COMPLETE


# ---------------------------------------------------------------------------
# V3: strict guards fail closed.
# ---------------------------------------------------------------------------

def test_envelope_crc_mismatch_rejected():
    env = _env_007()
    env.payload_crc32 ^= 0xFFFFFFFF
    with pytest.raises(ValueError):
        validate_v3_envelope(env, PAYLOAD_007)


def test_envelope_length_mismatch_rejected():
    env = _env_007()
    env.payload_len += 1
    with pytest.raises(ValueError):
        validate_v3_envelope(env, PAYLOAD_007)


def test_envelope_complete_requires_payload_and_flag():
    env = _env_007()
    env.flags = V3_FLAG_PROVENANCE_VALID
    with pytest.raises(ValueError):
        validate_v3_envelope(env, PAYLOAD_007)
    env = _env_007()
    with pytest.raises(ValueError):
        validate_v3_envelope(env, b"")


def test_envelope_truncated_requires_growth():
    env = _env_008()
    env.original_len = env.payload_len
    with pytest.raises(ValueError):
        validate_v3_envelope(env, PAYLOAD_008)


def test_envelope_metadata_only_rejects_payload():
    env = _env_009()
    env.flags = V3_FLAG_PAYLOAD_PRESENT
    with pytest.raises(ValueError):
        validate_v3_envelope(env, b"")
    env = _env_009()
    env.payload_crc32 = 1
    with pytest.raises(ValueError):
        validate_v3_envelope(env, b"")


def test_envelope_unknown_completeness_rejected():
    env = _env_009()
    env.completeness = 4
    with pytest.raises(ValueError):
        validate_v3_envelope(env, b"")


def test_envelope_provenance_requires_valid_flag():
    env = _env_007()
    env.flags = V3_FLAG_PAYLOAD_PRESENT
    with pytest.raises(ValueError):
        validate_v3_envelope(env, PAYLOAD_007)


def test_envelope_oversized_payload_rejected():
    env = _env_007()
    env.payload_len = V3_MAX_PAYLOAD + 1
    env.original_len = env.payload_len
    with pytest.raises(ValueError):
        validate_v3_envelope(env, b"\x00" * (V3_MAX_PAYLOAD + 1))


def test_decoder_rejects_dirty_v6_tail_when_bit2_clear():
    raw = bytearray(VEC_008.read_bytes())
    # v6 tail lives at base[109:133]; flip a byte with bit2 clear.
    raw[WIRE_PAYLOAD_SIZE] = 0x01
    assert WireCodec.decode_event(bytes(raw)) is None


def test_decoder_rejects_trailing_bytes():
    raw = VEC_007.read_bytes()
    assert WireCodec.decode_event(raw + b"\x00") is None


def test_decoder_rejects_truncated_envelope():
    raw = VEC_009.read_bytes()
    assert WireCodec.decode_event(raw[: WIRE_V3_HEADER_SIZE - V3_ENVELOPE_SIZE]) is None


def test_decoder_rejects_bad_struct_size_tag():
    raw = bytearray(VEC_009.read_bytes())
    raw[6:8] = (109).to_bytes(2, "little")
    assert WireCodec.decode_event(bytes(raw)) is None


def test_decoder_rejects_non_zero_reserved_byte():
    # wire_v3.md pins the reserved envelope byte to 0. The encoder always
    # writes 0, so a set byte is a corrupt/foreign frame, not an extension.
    raw = bytearray(VEC_007.read_bytes())
    raw[V3_BASE_SIZE + 3] = 0x01
    assert WireCodec.decode_event(bytes(raw)) is None
    with pytest.raises(ValueError):
        PayloadEnvelope.decode(bytes(raw[V3_BASE_SIZE:V3_BASE_SIZE + V3_ENVELOPE_SIZE]))


# ---------------------------------------------------------------------------
# V4: v1/v2 remain metadata-only and byte-identical to their frozen bins.
# ---------------------------------------------------------------------------

def test_v1_vectors_stay_metadata_only():
    for name in ("event_v1_001.bin", "event_v1_002.bin", "event_v1_003.bin",
                 "event_v1_004.bin", "event_v1_005.bin"):
        raw = (VECTOR_DIR / name).read_bytes()
        assert len(raw) == WIRE_PAYLOAD_SIZE
        e = WireCodec.decode_event(raw)
        assert e is not None
        assert e.version == 1
        assert e.payload_envelope is None
        assert e.payload_bytes == b""


def test_v2_vector_stays_metadata_only():
    raw = (VECTOR_DIR / "event_v2_006.bin").read_bytes()
    assert len(raw) == WIRE_V2_PAYLOAD_SIZE
    e = WireCodec.decode_event(raw)
    assert e is not None
    assert e.version == 2
    assert e.payload_envelope is None
    assert e.payload_bytes == b""
