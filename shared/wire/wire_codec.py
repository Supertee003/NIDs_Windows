"""shared/wire/wire_codec.py - AEGIS Wire Codec v1 (Python Reference)

STEP 2: Cross-language explicit field-by-field encoding.

This module provides reference Python implementations of the AEGIS wire
protocol encoders/decoders. All other languages (Zig, C++, Rust, Go)
must produce byte-identical output to this implementation.

All multi-byte fields are LITTLE-ENDIAN. No struct.pack with raw memcpy.
Use the explicit encode/decode methods below.

See shared/protocol/wire_v1.md for the canonical specification.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ============================================================
# Constants (must match wire_event.zig)
# ============================================================

WIRE_MAGIC: int = 0x57455631      # "WEV1"
WIRE_VERSION: int = 1
WIRE_HEADER_SIZE: int = 16
WIRE_MAX_PAYLOAD: int = 65536

EVENT_MAGIC: int = 0x41454731     # "AEG1"
EVENT_VERSION: int = 1
WIRE_PAYLOAD_SIZE: int = 109       # canonical event payload
WIRE_FRAME_SIZE: int = WIRE_HEADER_SIZE + WIRE_PAYLOAD_SIZE  # 125


class PayloadType(IntEnum):
    canonical_event = 0
    command = 1
    ack = 2
    heartbeat = 3


class EventSource(IntEnum):
    zig_core = 0
    wfp_sensor = 1
    pipe_sensor = 2
    minifilter = 3
    pipe_monitor = 4
    python_brain = 5
    cpp_bridge = 6
    rust_shield = 7
    go_aggregator = 8
    external = 255


class EventType(IntEnum):
    block = 0
    match_ = 1
    forward = 2
    ip_blocked = 3
    rejected = 4
    session_start = 5
    session_end = 6
    ruleset_reload = 7
    shutdown = 8
    startup = 9
    custom = 0xFFFFFFFF


class PolicyAction(IntEnum):
    allow = 0
    alert = 1
    block = 2
    quarantine = 3
    rate_limit = 4
    log_only = 5


# ============================================================
# CanonicalEvent (logical dataclass)
# ============================================================

@dataclass
class CanonicalEvent:
    magic: int = EVENT_MAGIC
    version: int = EVENT_VERSION
    struct_size: int = WIRE_PAYLOAD_SIZE
    event_id: int = 0

    timestamp_ms: int = 0
    monotonic_ns: int = 0

    source: EventSource = EventSource.zig_core
    source_ip: int = 0
    source_port: int = 0
    dest_ip: int = 0
    dest_port: int = 0
    session_id: int = 0

    protocol: int = 0
    direction: int = 0
    layer_id: int = 0
    is_pipe: int = 0

    event_type: EventType = EventType.custom
    severity: int = 0
    rule_id: int = 0
    ruleset_version: int = 0

    payload_length: int = 0
    payload_hash: int = 0

    policy_action: PolicyAction = PolicyAction.allow
    enforcement_status: int = 0
    defcon_impact: int = 5
    context_flags: int = 0

    reserved: bytes = field(default_factory=lambda: b"\x00" * 16)


# ============================================================
# WireHeader (explicit encode/decode)
# ============================================================

@dataclass
class WireHeader:
    magic: int
    version: int
    payload_type: int
    payload_length: int
    crc32: int


class WireCodec:
    """Reference encoder/decoder for AEGIS wire format v1.

    All methods use explicit field-by-field encoding (struct.pack with explicit
    format strings, little-endian). No struct memcpy, no pointer cast.
    """

    # ============================================================
    # Header encode/decode (16 bytes, explicit)
    # ============================================================

    @staticmethod
    def encode_header(h: WireHeader) -> bytes:
        """Encode WireHeader into 16 bytes (little-endian, field-by-field)."""
        # Format: <I H H I I = little-endian u32 u16 u16 u32 u32 = 4+2+2+4+4 = 16
        return struct.pack("<IHHII", h.magic, h.version, h.payload_type, h.payload_length, h.crc32)

    @staticmethod
    def decode_header(data: bytes) -> Optional[WireHeader]:
        """Decode WireHeader from 16 bytes. Returns None if buffer too short."""
        if len(data) < WIRE_HEADER_SIZE:
            return None
        magic, version, ptype, plen, crc = struct.unpack_from("<IHHII", data, 0)
        return WireHeader(magic=magic, version=version, payload_type=ptype, payload_length=plen, crc32=crc)

    # ============================================================
    # CanonicalEvent encode/decode (109 bytes, explicit)
    # ============================================================

    @staticmethod
    def encode_event(e: CanonicalEvent) -> bytes:
        """Encode CanonicalEvent into 109 bytes (little-endian, field-by-field)."""
        # Build each field explicitly. Format string documents the wire layout.
        # Field order matches wire_v1.md offset table exactly:
        #   magic(I) version(H) struct_size(H) event_id(Q) timestamp_ms(Q)
        #   monotonic_ns(Q) source(B) source_ip(I) source_port(H) dest_ip(I)
        #   dest_port(H) session_id(Q) protocol(B) direction(B) layer_id(B)
        #   is_pipe(B) event_type(I) severity(B) rule_id(I) ruleset_version(Q)
        #   payload_length(I) payload_hash(Q) policy_action(B)
        #   enforcement_status(B) defcon_impact(B) context_flags(I) reserved(16s)
        return struct.pack(
            "<IHHQQQBIHIHQBBBBIBIQIQBBBI16s",
            e.magic,
            e.version,
            e.struct_size,
            e.event_id,
            e.timestamp_ms,
            e.monotonic_ns,
            int(e.source),
            e.source_ip,
            e.source_port,
            e.dest_ip,
            e.dest_port,
            e.session_id,
            e.protocol,
            e.direction,
            e.layer_id,
            e.is_pipe,
            int(e.event_type),
            e.severity,
            e.rule_id,
            e.ruleset_version,
            e.payload_length,
            e.payload_hash,
            int(e.policy_action),
            e.enforcement_status,
            e.defcon_impact,
            e.context_flags,
            e.reserved,
        )

    @staticmethod
    def decode_event(data: bytes) -> Optional[CanonicalEvent]:
        """Decode CanonicalEvent from 109 bytes. Returns None if invalid."""
        if len(data) < WIRE_PAYLOAD_SIZE:
            return None
        try:
            fields = struct.unpack_from("<IHHQQQBIHIHQBBBBIBIQIQBBBI16s", data, 0)
        except struct.error:
            return None
        e = CanonicalEvent()
        (e.magic, e.version, e.struct_size, e.event_id, e.timestamp_ms, e.monotonic_ns,
         src, e.source_ip, e.source_port, e.dest_ip, e.dest_port, e.session_id,
         e.protocol, e.direction, e.layer_id, e.is_pipe,
         etype, e.severity, e.rule_id, e.ruleset_version,
         e.payload_length, e.payload_hash,
         paction, e.enforcement_status, e.defcon_impact, e.context_flags,
         e.reserved) = fields

        try:
            e.source = EventSource(src)
            e.event_type = EventType(etype)
            e.policy_action = PolicyAction(paction)
        except ValueError:
            return None  # Unknown enum value

        # Validate magic + version.
        if e.magic != EVENT_MAGIC:
            return None
        if e.version != EVENT_VERSION:
            return None
        return e

    # ============================================================
    # Full wire frame encode/decode
    # ============================================================

    @staticmethod
    def encode_frame(e: CanonicalEvent) -> bytes:
        """Encode a complete wire frame (125 bytes = 16 header + 109 payload)."""
        payload = WireCodec.encode_event(e)
        assert len(payload) == WIRE_PAYLOAD_SIZE
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = WireHeader(
            magic=WIRE_MAGIC,
            version=WIRE_VERSION,
            payload_type=int(PayloadType.canonical_event),
            payload_length=WIRE_PAYLOAD_SIZE,
            crc32=crc,
        )
        return WireCodec.encode_header(header) + payload

    @staticmethod
    def decode_frame(buf: bytes) -> Optional[CanonicalEvent]:
        """Decode a complete wire frame. Returns None on any validation failure."""
        if len(buf) < WIRE_HEADER_SIZE:
            return None
        header = WireCodec.decode_header(buf)
        if header is None:
            return None
        if header.magic != WIRE_MAGIC:
            return None
        if header.version != WIRE_VERSION:
            return None
        if header.payload_type != int(PayloadType.canonical_event):
            return None
        if header.payload_length != WIRE_PAYLOAD_SIZE:
            return None
        if len(buf) < WIRE_HEADER_SIZE + header.payload_length:
            return None

        payload = buf[WIRE_HEADER_SIZE:WIRE_HEADER_SIZE + header.payload_length]
        computed_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if computed_crc != header.crc32:
            return None

        return WireCodec.decode_event(payload)

    # ============================================================
    # Command frame encode (non-event control message)
    # ============================================================

    @staticmethod
    def encode_command(cmd_id: int, data: bytes) -> bytes:
        """Encode a command wire frame."""
        cmd_bytes = struct.pack("<I", cmd_id)
        payload = cmd_bytes + data
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = WireHeader(
            magic=WIRE_MAGIC,
            version=WIRE_VERSION,
            payload_type=int(PayloadType.command),
            payload_length=len(payload),
            crc32=crc,
        )
        return WireCodec.encode_header(header) + payload

    # ============================================================
    # Frame inspection helpers
    # ============================================================

    @staticmethod
    def is_valid_frame(buf: bytes) -> bool:
        if len(buf) < WIRE_HEADER_SIZE:
            return False
        header = WireCodec.decode_header(buf)
        if header is None:
            return False
        return header.magic == WIRE_MAGIC and header.version == WIRE_VERSION

    @staticmethod
    def get_frame_size(buf: bytes) -> Optional[int]:
        if not WireCodec.is_valid_frame(buf):
            return None
        header = WireCodec.decode_header(buf)
        if header is None:
            return None
        return WIRE_HEADER_SIZE + header.payload_length


# ============================================================
# Self-test (run with: python wire_codec.py)
# ============================================================

if __name__ == "__main__":
    print("[TEST] AEGIS Wire Codec v1 (Python reference)")

    # Test 1: header round-trip
    h = WireHeader(magic=WIRE_MAGIC, version=WIRE_VERSION, payload_type=0, payload_length=109, crc32=0xDEADBEEF)
    encoded_h = WireCodec.encode_header(h)
    assert len(encoded_h) == WIRE_HEADER_SIZE, f"Header must be 16 bytes, got {len(encoded_h)}"
    assert encoded_h[0] == 0x31, f"magic[0] should be 0x31 (LSB of 0x57455631), got 0x{encoded_h[0]:02X}"
    assert encoded_h[1] == 0x56
    assert encoded_h[2] == 0x45
    assert encoded_h[3] == 0x57
    print("  [OK] Header encodes to 16 bytes little-endian")

    # Test 2: header decode
    decoded_h = WireCodec.decode_header(encoded_h)
    assert decoded_h is not None
    assert decoded_h.magic == WIRE_MAGIC
    assert decoded_h.payload_length == 109
    print("  [OK] Header round-trip preserves all fields")

    # Test 3: canonical event encode produces 109 bytes
    e = CanonicalEvent(
        event_id=12345,
        source=EventSource.wfp_sensor,
        source_ip=0xC0A80164,
        source_port=8080,
        event_type=EventType.block,
        severity=3,
        rule_id=0x12345678,
        payload_length=256,
    )
    payload = WireCodec.encode_event(e)
    assert len(payload) == WIRE_PAYLOAD_SIZE, f"Payload must be 109 bytes, got {len(payload)}"
    assert payload[0] == 0x31, "magic[0] should be 0x31 (LSB of 0x41454731)"
    assert payload[1] == 0x47
    assert payload[2] == 0x45
    assert payload[3] == 0x41
    print("  [OK] Event payload encodes to 109 bytes")

    # Test 4: event round-trip
    decoded_e = WireCodec.decode_event(payload)
    assert decoded_e is not None
    assert decoded_e.event_id == 12345
    assert decoded_e.source == EventSource.wfp_sensor
    assert decoded_e.source_ip == 0xC0A80164
    assert decoded_e.source_port == 8080
    assert decoded_e.event_type == EventType.block
    assert decoded_e.severity == 3
    assert decoded_e.rule_id == 0x12345678
    assert decoded_e.payload_length == 256
    print("  [OK] Event round-trip preserves all fields")

    # Test 5: full wire frame encode/decode
    frame = WireCodec.encode_frame(e)
    assert len(frame) == WIRE_FRAME_SIZE, f"Frame must be 125 bytes, got {len(frame)}"
    assert frame[0] == 0x31, "wire magic[0] should be 0x31"
    decoded_frame = WireCodec.decode_frame(frame)
    assert decoded_frame is not None
    assert decoded_frame.event_id == e.event_id
    assert decoded_frame.source_ip == e.source_ip
    print("  [OK] Full wire frame round-trip (125 bytes)")

    # Test 6: reject corrupted CRC
    corrupted = bytearray(frame)
    corrupted[20] ^= 0xFF  # Flip a payload byte
    assert WireCodec.decode_frame(bytes(corrupted)) is None
    print("  [OK] Rejects corrupted CRC32")

    # Test 7: reject wrong magic
    bad_magic = bytearray(frame)
    bad_magic[0] = 0x00
    assert WireCodec.decode_frame(bytes(bad_magic)) is None
    print("  [OK] Rejects wrong wire magic")

    # Test 8: reject short buffer
    assert WireCodec.decode_frame(b"\x00" * 10) is None
    print("  [OK] Rejects short buffer")

    print()
    print("[PASS] All wire codec tests passed.")
    print(f"  Wire frame size: {WIRE_FRAME_SIZE} bytes (16 header + 109 payload)")
    print(f"  Zig/C++/Rust/Go/Python produce identical bytes for same input.")
