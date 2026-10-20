"""CONTRACT-01: Canonical Event 109-byte wire codec (Python analytics side).

Plane-C (Intelligence) read-only binding. Decodes/encodes the frozen
109-byte wire frame for Brain analytics. NEVER enforces, NEVER touches
WFP, NEVER makes privileged OS calls. Final enforcement authority is
solely the Rust PEP (rust-src/lib.rs).

Wire layout (little-endian, offsets from shared/event/canonical_event.md):
  magic(4) ver(2) struct_size(2) event_id(8) ts_ms(8) mono_ns(8)
  source(1) src_ip(4) src_port(2) dst_ip(4) dst_port(2) session(8)
  proto(1) dir(1) layer(1) is_pipe(1) evtype(4) sev(1) rule(4) rsv_ver(8)
  pay_len(4) pay_hash(8) pol_act(1) enf(1) defcon(1) ctx_flags(4) reserved(16)
Total = 109 bytes.
"""
# SEAM-STATUS: not wired to the production entrypoint (brain/windows_brain.py); exercised by brain tests.
from __future__ import annotations

import struct
from dataclasses import dataclass, replace

EVENT_MAGIC = 0x41454731
EVENT_VERSION = 1
WIRE_SIZE = 109
# Wire v2 (T2-V6-022a): v1 109 bytes ++ 24-byte IPv6 tail (src[4..16],
# dst[4..16] network order). Bit2 keeps its meaning in both versions.
EVENT_VERSION_V2 = 2
V6_TAIL_SIZE = 24
WIRE_V2_SIZE = WIRE_SIZE + V6_TAIL_SIZE  # 133
CONTEXT_V6_TRUNCATED = 1 << 2
# Additive ContextFlags transport-metadata lane (RB-021-NOSE-FLAGS):
# bits 16..23 = raw TCP flags byte, bit24 = valid. Wire size is unchanged;
# this mirrors nose/canonical.go and shared/wire/wire_codec.py.
CONTEXT_TCP_FLAGS_SHIFT = 16
CONTEXT_TCP_FLAGS_MASK = 0xFF << CONTEXT_TCP_FLAGS_SHIFT
CONTEXT_TCP_FLAGS_VALID = 1 << 24
EVENT_CUSTOM = 0xFFFFFFFF

# Frozen ordinals — MUST match src/contract/canonical_event.zig.
SOURCE = {
    "zig_core": 0, "wfp_sensor": 1, "pipe_sensor": 2, "minifilter": 3,
    "pipe_monitor": 4, "python_brain": 5, "cpp_bridge": 6,
    "rust_shield": 7, "go_aggregator": 8, "npcap_sensor": 9,
    "host_telemetry": 10, "ml_detector": 11, "cluster_federation": 12,
    "process_sensor": 13, "file_sensor": 14, "registry_sensor": 15,
    "replay_sensor": 16, "external": 255,
}
EVENT_TYPE = {
    "block": 0, "match": 1, "forward": 2, "ip_blocked": 3,
    "rejected": 4, "session_start": 5, "session_end": 6,
    "ruleset_reload": 7, "shutdown": 8, "startup": 9,
    "custom": EVENT_CUSTOM,
}
POLICY_ACTION = {
    "allow": 0, "alert": 1, "block": 2, "quarantine": 3,
    "rate_limit": 4, "log_only": 5,
}

_STRUCT = struct.Struct(
    "<I H H Q Q Q B I H I H Q B B B B I B I Q I Q B B B I 16s"
)
_ASSERT_SIZE = _STRUCT.size
assert _ASSERT_SIZE == WIRE_SIZE, f"codec size {_ASSERT_SIZE} != {WIRE_SIZE}"

_VALID_SOURCES = frozenset(SOURCE.values())
_VALID_EVENT_TYPES = frozenset(EVENT_TYPE.values())
_VALID_POLICY_ACTIONS = frozenset(POLICY_ACTION.values())


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: int
    timestamp_ms: int
    monotonic_ns: int
    source: int
    source_ip: int
    source_port: int
    dest_ip: int
    dest_port: int
    session_id: int
    protocol: int
    direction: int
    layer_id: int
    is_pipe: int
    event_type: int
    severity: int
    rule_id: int
    ruleset_version: int
    payload_length: int
    payload_hash: int
    policy_action: int
    enforcement_status: int
    defcon_impact: int
    context_flags: int
    reserved: bytes
    struct_size: int = WIRE_SIZE  # producer in-memory layout tag, preserved
    # Full IPv6 identity (wire v2 only): complete addresses in network
    # order; zeros when decoded from v1 (truncated identity + bit2).
    src_ipv6: bytes = b"\x00" * 16
    dst_ipv6: bytes = b"\x00" * 16


def decode(buf: bytes) -> CanonicalEvent:
    """Decode 109+ (v1) or 133+ (v2) wire bytes; validate magic/version/enums."""
    if len(buf) < WIRE_SIZE:
        raise ValueError(f"wire frame must be at least {WIRE_SIZE} bytes, got {len(buf)}")
    version = struct.unpack_from("<H", buf, 4)[0]
    if version == EVENT_VERSION:
        # v1 prefix of either length (parity with Go/Zig decoders, which
        # read the first 109 bytes and ignore any tail).
        return _decode_v1(buf)
    if version != EVENT_VERSION_V2 or len(buf) < WIRE_V2_SIZE:
        raise ValueError(f"unsupported version {version} (v2 needs 133+ bytes)")
    ev = _decode_v1(buf)
    tail = buf[WIRE_SIZE:WIRE_V2_SIZE]
    return replace(
        ev,
        src_ipv6=ev.source_ip.to_bytes(4, "big") + tail[0:12],
        dst_ipv6=ev.dest_ip.to_bytes(4, "big") + tail[12:24],
    )


def _decode_v1(buf: bytes) -> CanonicalEvent:
    """Frozen v1 decode path (109-byte prefix of either version)."""
    f = _STRUCT.unpack_from(buf, 0)
    if f[0] != EVENT_MAGIC:
        raise ValueError(f"bad magic 0x{f[0]:08X}")
    if f[1] not in (EVENT_VERSION, EVENT_VERSION_V2):
        raise ValueError(f"unsupported version {f[1]}")
    if f[6] not in _VALID_SOURCES:
        raise ValueError(f"unknown source {f[6]}")
    if f[16] not in _VALID_EVENT_TYPES:
        raise ValueError(f"unknown event_type {f[16]}")
    if f[22] not in _VALID_POLICY_ACTIONS:
        raise ValueError(f"unknown policy_action {f[22]}")
    if f[26][15] > 100:
        raise ValueError("confidence must be 0-100")
    return CanonicalEvent(
        event_id=f[3],
        timestamp_ms=f[4],
        monotonic_ns=f[5],
        source=f[6],
        source_ip=f[7],
        source_port=f[8],
        dest_ip=f[9],
        dest_port=f[10],
        session_id=f[11],
        protocol=f[12],
        direction=f[13],
        layer_id=f[14],
        is_pipe=f[15],
        event_type=f[16],
        severity=f[17],
        rule_id=f[18],
        ruleset_version=f[19],
        payload_length=f[20],
        payload_hash=f[21],
        policy_action=f[22],
        enforcement_status=f[23],
        defcon_impact=f[24],
        context_flags=f[25],
        reserved=f[26],
        struct_size=f[2],
    )


def encode(ev: CanonicalEvent) -> bytes:
    """Encode to 109 wire bytes, preserving the producer struct_size tag."""
    return _STRUCT.pack(
        EVENT_MAGIC,
        EVENT_VERSION,
        ev.struct_size,
        ev.event_id,
        ev.timestamp_ms,
        ev.monotonic_ns,
        ev.source,
        ev.source_ip,
        ev.source_port,
        ev.dest_ip,
        ev.dest_port,
        ev.session_id,
        ev.protocol,
        ev.direction,
        ev.layer_id,
        ev.is_pipe,
        ev.event_type,
        ev.severity,
        ev.rule_id,
        ev.ruleset_version,
        ev.payload_length,
        ev.payload_hash,
        ev.policy_action,
        ev.enforcement_status,
        ev.defcon_impact,
        ev.context_flags,
        ev.reserved,
    )


def encode_v2(ev: CanonicalEvent) -> bytes:
    """Encode to 133 wire bytes (v1 prefix + v6 tail). Requires bit2 and
    first-4-byte consistency (BigEndian.Uint32(addr[:4]), Go rule)."""
    if (ev.context_flags & CONTEXT_V6_TRUNCATED) == 0:
        raise ValueError("v2 requires ContextFlags bit2 (ipv6)")
    if int.from_bytes(ev.src_ipv6[:4], "big") != ev.source_ip:
        raise ValueError("src first-4 mismatch")
    if int.from_bytes(ev.dst_ipv6[:4], "big") != ev.dest_ip:
        raise ValueError("dst first-4 mismatch")
    v1 = bytearray(encode(ev))
    v1[4:6] = EVENT_VERSION_V2.to_bytes(2, "little")
    return bytes(v1) + ev.src_ipv6[4:16] + ev.dst_ipv6[4:16]
