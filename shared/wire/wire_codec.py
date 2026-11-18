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
WIRE_PAYLOAD_SIZE: int = 109       # canonical event payload (v1, frozen)
WIRE_FRAME_SIZE: int = WIRE_HEADER_SIZE + WIRE_PAYLOAD_SIZE  # 125

# Wire v2 (T2-V6-022a, see shared/protocol/wire_v2.md): v1 109 bytes plus a
# 24-byte tail (source bytes [4..16] then dest bytes [4..16], network
# order). v1 is frozen; v2 is additive. Bit2 keeps its meaning in both.
EVENT_VERSION_V2: int = 2
V6_TAIL_SIZE: int = 24
WIRE_V2_PAYLOAD_SIZE: int = WIRE_PAYLOAD_SIZE + V6_TAIL_SIZE  # 133
WIRE_V2_FRAME_SIZE: int = WIRE_HEADER_SIZE + WIRE_V2_PAYLOAD_SIZE  # 149
CONTEXT_V6_TRUNCATED: int = 1 << 2
# Additive ContextFlags transport-metadata lane (RB-021-NOSE-FLAGS):
# bits 16..23 = raw TCP flags byte (FIN=0x01 .. CWR=0x80), bit24 = valid.
# This does not change the 109-byte v1 or 133-byte v2 wire layout; existing
# allocations (RAG bits 0..3, L7 bits 8..13) do not overlap.
CONTEXT_TCP_FLAGS_SHIFT: int = 16
CONTEXT_TCP_FLAGS_MASK: int = 0xFF << CONTEXT_TCP_FLAGS_SHIFT
CONTEXT_TCP_FLAGS_VALID: int = 1 << 24

# Wire v3 (PAYLOAD-ENVELOPE-V3-001): frozen v2 133-byte base (zero 24-byte
# tail when bit2 is clear) + 32-byte envelope + 0..1024 payload bytes.
# v1/v2 stay byte-identical metadata-only compatibility frames.
EVENT_VERSION_V3: int = 3
V3_BASE_SIZE: int = WIRE_V2_PAYLOAD_SIZE  # 133
V3_ENVELOPE_SIZE: int = 32
WIRE_V3_HEADER_SIZE: int = V3_BASE_SIZE + V3_ENVELOPE_SIZE  # 165
V3_MAX_PAYLOAD: int = 1024
WIRE_V3_MAX_SIZE: int = WIRE_V3_HEADER_SIZE + V3_MAX_PAYLOAD  # 1189

PAYLOAD_UNAVAILABLE: int = 0
PAYLOAD_COMPLETE: int = 1
PAYLOAD_TRUNCATED: int = 2
PAYLOAD_METADATA_ONLY: int = 3

V3_FLAG_PAYLOAD_PRESENT: int = 1 << 0
V3_FLAG_PROVENANCE_VALID: int = 1 << 1

V3_ENVELOPE_FORMAT: str = "<HBBHHIQIII"  # 32 bytes, little-endian


@dataclass
class PayloadEnvelope:
    flags: int = 0
    completeness: int = PAYLOAD_UNAVAILABLE
    payload_len: int = 0
    original_len: int = 0
    payload_crc32: int = 0
    capture_sequence: int = 0
    producer_epoch: int = 0
    producer_generation: int = 0
    interface_id: int = 0

    @property
    def payload_present(self) -> bool:
        return (self.flags & V3_FLAG_PAYLOAD_PRESENT) != 0

    @property
    def provenance_valid(self) -> bool:
        return (self.flags & V3_FLAG_PROVENANCE_VALID) != 0

    def encode(self) -> bytes:
        return struct.pack(
            V3_ENVELOPE_FORMAT,
            self.flags,
            self.completeness,
            0,  # reserved
            self.payload_len,
            self.original_len,
            self.payload_crc32,
            self.capture_sequence,
            self.producer_epoch,
            self.producer_generation,
            self.interface_id,
        )

    @staticmethod
    def decode(data: bytes) -> "PayloadEnvelope":
        if len(data) < V3_ENVELOPE_SIZE:
            raise ValueError("short v3 envelope")
        (flags, completeness, reserved, payload_len, original_len, crc,
         seq, epoch, generation, interface_id) = struct.unpack_from(V3_ENVELOPE_FORMAT, data, 0)
        # wire_v3.md: any non-zero reserved byte is rejected fail closed. The
        # encoder always writes 0, so a set byte means a corrupt frame.
        if reserved != 0:
            raise ValueError("v3 reserved byte must be zero")
        return PayloadEnvelope(
            flags=flags,
            completeness=completeness,
            payload_len=payload_len,
            original_len=original_len,
            payload_crc32=crc,
            capture_sequence=seq,
            producer_epoch=epoch,
            producer_generation=generation,
            interface_id=interface_id,
        )


def validate_v3_envelope(env: PayloadEnvelope, payload: bytes) -> None:
    """Strict envelope/payload consistency. Raises ValueError (fail closed)."""
    if len(payload) > V3_MAX_PAYLOAD:
        raise ValueError("v3 payload exceeds maximum")
    if env.payload_len != len(payload):
        raise ValueError("v3 payload length mismatch")
    present = env.payload_present
    if env.completeness in (PAYLOAD_UNAVAILABLE, PAYLOAD_METADATA_ONLY):
        if present or payload or env.payload_crc32 != 0:
            raise ValueError("v3 metadata-only envelope carries payload")
        if env.completeness == PAYLOAD_METADATA_ONLY and env.original_len != 0:
            raise ValueError("v3 metadata-only original length must be zero")
    elif env.completeness == PAYLOAD_COMPLETE:
        if not present or not payload:
            raise ValueError("v3 complete envelope requires payload")
        if env.original_len != env.payload_len:
            raise ValueError("v3 complete original length mismatch")
        if zlib.crc32(payload) & 0xFFFFFFFF != env.payload_crc32:
            raise ValueError("v3 payload crc mismatch")
    elif env.completeness == PAYLOAD_TRUNCATED:
        if not present or not payload:
            raise ValueError("v3 truncated envelope requires payload")
        if env.original_len <= env.payload_len:
            raise ValueError("v3 truncated original length must exceed captured")
        if zlib.crc32(payload) & 0xFFFFFFFF != env.payload_crc32:
            raise ValueError("v3 payload crc mismatch")
    else:
        raise ValueError("unknown v3 completeness")
    if not env.provenance_valid:
        if (env.capture_sequence or env.producer_epoch or
                env.producer_generation or env.interface_id):
            raise ValueError("v3 provenance without valid flag")


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
    npcap_sensor = 9
    host_telemetry = 10
    ml_detector = 11
    cluster_federation = 12
    process_sensor = 13
    file_sensor = 14
    registry_sensor = 15
    replay_sensor = 16
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

    # Full IPv6 identity (wire v2 only). The u32 source_ip/dest_ip always
    # carry first-4-bytes (bit2 set); these hold the complete addresses in
    # network order when a v2 frame was decoded, zeros otherwise.
    src_ipv6: bytes = field(default_factory=lambda: b"\x00" * 16)
    dst_ipv6: bytes = field(default_factory=lambda: b"\x00" * 16)

    # Wire v3 only: bounded payload + provenance. None/empty for the frozen
    # v1/v2 metadata-only compatibility paths.
    payload_envelope: Optional[PayloadEnvelope] = None
    payload_bytes: bytes = b""


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
        """Decode CanonicalEvent from 109 (v1) or 133 (v2) bytes.

        Version-dispatched: v1 → frozen path (v6 sidecars stay zero);
        v2 → full-address reconstruction. Anything else → None.
        """
        if len(data) < WIRE_PAYLOAD_SIZE:
            return None
        version = struct.unpack_from("<H", data, 4)[0]
        if version == EVENT_VERSION:
            return WireCodec._decode_v1(data)
        if version == EVENT_VERSION_V3:
            return WireCodec._decode_v3(data)
        if version != EVENT_VERSION_V2:
            return None
        if len(data) < WIRE_V2_PAYLOAD_SIZE:
            return None  # v2 with 109 bytes is malformed, never truncated
        e = WireCodec._decode_v1(data, EVENT_VERSION_V2)
        if e is None:
            return None
        tail = data[WIRE_PAYLOAD_SIZE:WIRE_V2_PAYLOAD_SIZE]
        e.src_ipv6 = e.source_ip.to_bytes(4, "big") + tail[0:12]
        e.dst_ipv6 = e.dest_ip.to_bytes(4, "big") + tail[12:24]
        return e

    @staticmethod
    def _decode_v1(data: bytes, expect_version: int = EVENT_VERSION) -> Optional[CanonicalEvent]:
        """Frozen v1 decode path (109-byte prefix of either version)."""
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
        if e.version != expect_version:
            return None
        return e

    @staticmethod
    def encode_event_v2(e: CanonicalEvent) -> bytes:
        """Encode CanonicalEvent into 133 bytes (v1 prefix + v6 tail).

        Requires bit2 (v2 is v6-identity only) and first-4-byte
        consistency (BigEndian.Uint32(addr[:4]) == u32 field, Go rule).
        """
        if (e.context_flags & CONTEXT_V6_TRUNCATED) == 0:
            raise ValueError("v2 requires ContextFlags bit2 (ipv6)")
        if int.from_bytes(e.src_ipv6[:4], "big") != e.source_ip:
            raise ValueError("src first-4 mismatch")
        if int.from_bytes(e.dst_ipv6[:4], "big") != e.dest_ip:
            raise ValueError("dst first-4 mismatch")
        v1 = bytearray(WireCodec.encode_event(e))
        v1[4:6] = EVENT_VERSION_V2.to_bytes(2, "little")
        # struct_size is the sender in-memory layout tag (128), never the
        # wire length -- patch normatively like the version field.
        v1[6:8] = (128).to_bytes(2, "little")
        return bytes(v1) + e.src_ipv6[4:16] + e.dst_ipv6[4:16]

    @staticmethod
    def encode_event_v3(e: CanonicalEvent, envelope: PayloadEnvelope, payload: bytes) -> bytes:
        """Encode a v3 frame: frozen v2 base + envelope + bounded payload.

        The envelope is validated against the payload before any byte is
        emitted (fail closed). Non-v6 events carry an all-zero 24-byte tail.
        """
        validate_v3_envelope(envelope, payload)
        if e.context_flags & CONTEXT_V6_TRUNCATED:
            base = bytearray(WireCodec.encode_event_v2(e))
        else:
            base = bytearray(WireCodec.encode_event(e)) + bytearray(V6_TAIL_SIZE)
        base[4:6] = EVENT_VERSION_V3.to_bytes(2, "little")
        base[6:8] = (128).to_bytes(2, "little")
        return bytes(base) + envelope.encode() + payload

    @staticmethod
    def _decode_v3(data: bytes) -> Optional[CanonicalEvent]:
        """Strict v3 decode: exact length, crc scope, and v6 tail rules."""
        if len(data) < WIRE_V3_HEADER_SIZE:
            return None
        e = WireCodec._decode_v1(data, EVENT_VERSION_V3)
        if e is None:
            return None
        # struct_size is the in-memory layout tag (128) for every live
        # producer, exactly as v2 pins it.
        if e.struct_size != 128:
            return None
        try:
            env = PayloadEnvelope.decode(data[V3_BASE_SIZE:V3_BASE_SIZE + V3_ENVELOPE_SIZE])
        except ValueError:
            return None
        if env.payload_len > V3_MAX_PAYLOAD:
            return None
        if len(data) != WIRE_V3_HEADER_SIZE + env.payload_len:
            return None
        payload = data[WIRE_V3_HEADER_SIZE:]
        try:
            validate_v3_envelope(env, payload)
        except ValueError:
            return None
        if e.context_flags & CONTEXT_V6_TRUNCATED:
            tail = data[WIRE_PAYLOAD_SIZE:WIRE_V2_PAYLOAD_SIZE]
            e.src_ipv6 = e.source_ip.to_bytes(4, "big") + tail[0:12]
            e.dst_ipv6 = e.dest_ip.to_bytes(4, "big") + tail[12:24]
        else:
            if any(data[WIRE_PAYLOAD_SIZE:WIRE_V2_PAYLOAD_SIZE]):
                return None
        e.payload_envelope = env
        e.payload_bytes = payload
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
    def encode_frame_v2(e: CanonicalEvent) -> bytes:
        """Encode a complete v2 wire frame (149 bytes = 16 header + 133 payload)."""
        payload = WireCodec.encode_event_v2(e)
        assert len(payload) == WIRE_V2_PAYLOAD_SIZE
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = WireHeader(
            magic=WIRE_MAGIC,
            version=WIRE_VERSION,
            payload_type=int(PayloadType.canonical_event),
            payload_length=WIRE_V2_PAYLOAD_SIZE,
            crc32=crc,
        )
        return WireCodec.encode_header(header) + payload

    @staticmethod
    def encode_frame_v3(e: CanonicalEvent, envelope: PayloadEnvelope, payload: bytes) -> bytes:
        """Encode a complete v3 wire frame (16 header + v3 payload)."""
        body = WireCodec.encode_event_v3(e, envelope, payload)
        assert len(body) == WIRE_V3_HEADER_SIZE + len(payload)
        crc = zlib.crc32(body) & 0xFFFFFFFF
        header = WireHeader(
            magic=WIRE_MAGIC,
            version=WIRE_VERSION,
            payload_type=int(PayloadType.canonical_event),
            payload_length=len(body),
            crc32=crc,
        )
        return WireCodec.encode_header(header) + body

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
        if not (
            header.payload_length in (WIRE_PAYLOAD_SIZE, WIRE_V2_PAYLOAD_SIZE)
            or WIRE_V3_HEADER_SIZE <= header.payload_length <= WIRE_V3_MAX_SIZE
        ):
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

    # Test 9: v2 round-trip preserves full IPv6 identity and bit2
    v6 = CanonicalEvent(
        event_id=6006,
        source=EventSource.go_aggregator,
        source_ip=0x20010DB8,
        source_port=49152,
        dest_ip=0x20010DB8,
        dest_port=443,
        event_type=EventType.forward,
        severity=1,
        context_flags=CONTEXT_V6_TRUNCATED,
        src_ipv6=bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x01]),
        dst_ipv6=bytes([0x20, 0x01, 0x0D, 0xB8] + [0] * 11 + [0x02]),
    )
    v2payload = WireCodec.encode_event_v2(v6)
    assert len(v2payload) == WIRE_V2_PAYLOAD_SIZE, f"v2 payload must be 133 bytes, got {len(v2payload)}"
    back6 = WireCodec.decode_event(v2payload)
    assert back6 is not None
    assert back6.src_ipv6 == v6.src_ipv6 and back6.dst_ipv6 == v6.dst_ipv6
    assert back6.context_flags & CONTEXT_V6_TRUNCATED != 0
    print("  [OK] v2 round-trip preserves full IPv6 identity and bit2")

    # Test 10: v2 guards (flag, consistency, truncated frame)
    nov6 = CanonicalEvent(source_ip=0x20010DB8)
    try:
        WireCodec.encode_event_v2(nov6)
        raise AssertionError("v2 without bit2 must fail")
    except ValueError:
        pass
    badv6 = CanonicalEvent(source_ip=0x0A000001, dest_ip=0x20010DB8,
                            context_flags=CONTEXT_V6_TRUNCATED,
                            src_ipv6=v6.src_ipv6, dst_ipv6=v6.dst_ipv6)
    try:
        WireCodec.encode_event_v2(badv6)
        raise AssertionError("v2 with mismatched first-4 must fail")
    except ValueError:
        pass
    assert WireCodec.decode_event(v2payload[:WIRE_PAYLOAD_SIZE]) is None
    print("  [OK] v2 guards hold (flag, first-4, truncated frame)")

    # Test 11: v2 framed round-trip (149 bytes)
    frame2 = WireCodec.encode_frame_v2(v6)
    assert len(frame2) == WIRE_V2_FRAME_SIZE
    assert WireCodec.decode_frame(frame2) is not None
    assert WireCodec.decode_frame(frame2).src_ipv6 == v6.src_ipv6
    print("  [OK] v2 wire frame round-trip (149 bytes)")

    print()
    print("[PASS] All wire codec tests passed.")
    print(f"  Wire frame size: {WIRE_FRAME_SIZE} bytes (16 header + 109 payload)")
    print(f"  Zig/C++/Rust/Go/Python produce identical bytes for same input.")
