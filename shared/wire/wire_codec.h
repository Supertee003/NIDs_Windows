// ============================================================
// shared/wire/wire_codec.h - AEGIS Wire Codec v1 (C++ Reference)
// ============================================================
// STEP 2: Cross-language explicit field-by-field encoding.
//
// This header provides reference C++ implementations of the AEGIS wire
// protocol encoders/decoders. All other languages (Zig, Rust, Go, Python)
// must produce byte-identical output to these implementations.
//
// All multi-byte fields are LITTLE-ENDIAN. No struct memcpy. No #pragma pack
// with raw pointer cast. Use the encode/decode functions below.
//
// See shared/protocol/wire_v1.md for the canonical specification.
// ============================================================

#ifndef AEGIS_WIRE_CODEC_H
#define AEGIS_WIRE_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h> // memcpy for byte arrays only

namespace aegis {

// ============================================================
// Constants (must match wire_event.zig)
// ============================================================

static constexpr uint32_t WIRE_MAGIC         = 0x57455631u; // "WEV1"
static constexpr uint16_t WIRE_VERSION        = 1;
static constexpr size_t   WIRE_HEADER_SIZE    = 16;
static constexpr size_t   WIRE_MAX_PAYLOAD    = 65536;

static constexpr uint32_t EVENT_MAGIC         = 0x41454731u; // "AEG1"
static constexpr uint16_t EVENT_VERSION       = 1;
static constexpr size_t   WIRE_PAYLOAD_SIZE   = 109; // canonical event payload (v1, frozen)
static constexpr size_t   WIRE_FRAME_SIZE     = WIRE_HEADER_SIZE + WIRE_PAYLOAD_SIZE; // 125

// Wire v2 (T2-V6-022a, see shared/protocol/wire_v2.md): v1 109 bytes plus
// a 24-byte tail (source bytes [4..16] then dest bytes [4..16], network
// order). Bit2 keeps its meaning in both versions.
static constexpr uint16_t EVENT_VERSION_V2    = 2;
static constexpr size_t   V6_TAIL_SIZE        = 24;
static constexpr size_t   WIRE_V2_PAYLOAD_SIZE = WIRE_PAYLOAD_SIZE + V6_TAIL_SIZE; // 133
static constexpr size_t   WIRE_V2_FRAME_SIZE  = WIRE_HEADER_SIZE + WIRE_V2_PAYLOAD_SIZE; // 149
static constexpr uint32_t CONTEXT_V6_TRUNCATED = (1u << 2);

// Additive ContextFlags transport-metadata lane (RB-021-NOSE-FLAGS):
// bits 16..23 = raw TCP flags byte (FIN=0x01 .. CWR=0x80), bit24 = valid.
// The 109-byte v1 / 133-byte v2 wire layout is unchanged; existing
// allocations (RAG bits 0..3, L7 bits 8..13) do not overlap.
static constexpr uint32_t CONTEXT_TCP_FLAGS_SHIFT = 16;
static constexpr uint32_t CONTEXT_TCP_FLAGS_MASK = (0xFFu << CONTEXT_TCP_FLAGS_SHIFT);
static constexpr uint32_t CONTEXT_TCP_FLAGS_VALID = (1u << 24);

enum class PayloadType : uint16_t {
    canonical_event = 0,
    command         = 1,
    ack             = 2,
    heartbeat       = 3,
};

enum class EventSource : uint8_t {
    zig_core        = 0,
    wfp_sensor      = 1,
    pipe_sensor     = 2,
    minifilter      = 3,
    pipe_monitor    = 4,
    python_brain    = 5,
    cpp_bridge      = 6,
    rust_shield     = 7,
    go_aggregator   = 8,
    npcap_sensor    = 9,
    host_telemetry  = 10,
    ml_detector     = 11,
    cluster_federation = 12,
    process_sensor  = 13,
    file_sensor     = 14,
    registry_sensor = 15,
    replay_sensor   = 16,
    external        = 255,
};

enum class EventType : uint32_t {
    block           = 0,
    match_          = 1,
    forward         = 2,
    ip_blocked      = 3,
    rejected        = 4,
    session_start   = 5,
    session_end     = 6,
    ruleset_reload  = 7,
    shutdown        = 8,
    startup         = 9,
    custom          = 0xFFFFFFFFu,
};

enum class PolicyAction : uint8_t {
    allow           = 0,
    alert           = 1,
    block           = 2,
    quarantine      = 3,
    rate_limit      = 4,
    log_only        = 5,
};

// ============================================================
// CanonicalEvent (logical struct — NOT serialized via memcpy)
// ============================================================

struct CanonicalEvent {
    uint32_t magic;
    uint16_t version;
    uint16_t struct_size;
    uint64_t event_id;

    uint64_t timestamp_ms;
    uint64_t monotonic_ns;

    EventSource source;
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint64_t session_id;

    uint8_t protocol;
    uint8_t direction;
    uint8_t layer_id;
    uint8_t is_pipe;

    EventType event_type;
    uint8_t severity;
    uint32_t rule_id;
    uint64_t ruleset_version;

    uint32_t payload_length;
    uint64_t payload_hash;

    PolicyAction policy_action;
    uint8_t enforcement_status;
    uint8_t defcon_impact;
    uint32_t context_flags;

    uint8_t reserved[16];

    // Full IPv6 identity (wire v2 only). The u32 source_ip/dest_ip always
    // carry first-4-bytes (bit2 set); these hold complete addresses in
    // network order when a v2 frame was decoded, zeros otherwise.
    uint8_t src_ipv6[16];
    uint8_t dst_ipv6[16];
};

static_assert(sizeof(CanonicalEvent) >= 93, "CanonicalEvent must hold all fields");
// Note: sizeof(CanonicalEvent) may exceed 109 due to C++ struct padding.
// The WIRE encoding is fixed at 109 bytes regardless of in-memory layout.

// ============================================================
// Little-endian write helpers (no struct memcpy)
// ============================================================

inline void write_u16_le(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

inline void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

inline void write_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
    p[4] = (uint8_t)((v >> 32) & 0xFF);
    p[5] = (uint8_t)((v >> 40) & 0xFF);
    p[6] = (uint8_t)((v >> 48) & 0xFF);
    p[7] = (uint8_t)((v >> 56) & 0xFF);
}

inline uint16_t read_u16_le(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    return (uint64_t)p[0]
        | ((uint64_t)p[1] << 8)
        | ((uint64_t)p[2] << 16)
        | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32)
        | ((uint64_t)p[5] << 40)
        | ((uint64_t)p[6] << 48)
        | ((uint64_t)p[7] << 56);
}

// ============================================================
// WireHeader encode/decode (explicit field-by-field, no struct memcpy)
// ============================================================

struct WireHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t payload_type;
    uint32_t payload_length;
    uint32_t crc32;
};

// Encode WireHeader into buf[0..16]. Returns 16 on success, 0 on failure.
inline size_t aegis_wire_encode_header(uint8_t* buf, size_t buf_len, const WireHeader& h) {
    if (buf_len < WIRE_HEADER_SIZE) return 0;
    write_u32_le(buf + 0,  h.magic);
    write_u16_le(buf + 4,  h.version);
    write_u16_le(buf + 6,  h.payload_type);
    write_u32_le(buf + 8,  h.payload_length);
    write_u32_le(buf + 12, h.crc32);
    return WIRE_HEADER_SIZE;
}

// Decode WireHeader from bytes[0..16]. Returns true on success.
inline bool aegis_wire_decode_header(const uint8_t* bytes, size_t bytes_len, WireHeader& out) {
    if (bytes_len < WIRE_HEADER_SIZE) return false;
    out.magic          = read_u32_le(bytes + 0);
    out.version        = read_u16_le(bytes + 4);
    out.payload_type   = read_u16_le(bytes + 6);
    out.payload_length = read_u32_le(bytes + 8);
    out.crc32          = read_u32_le(bytes + 12);
    return true;
}

// ============================================================
// CRC32 (IEEE 802.3, same as std.hash.Crc32 in Zig)
// ============================================================

// Standard CRC32 lookup table — initialized lazily on first call.
inline uint32_t aegis_crc32(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool initialized = false;
    if (!initialized) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        initialized = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// ============================================================
// CanonicalEvent encode/decode (explicit field-by-field, 109 bytes)
// ============================================================

// Encode CanonicalEvent into buf[0..109]. Returns 109 on success, 0 on failure.
inline size_t aegis_wire_encode_event(uint8_t* buf, size_t buf_len, const CanonicalEvent& e) {
    if (buf_len < WIRE_PAYLOAD_SIZE) return 0;
    size_t off = 0;

    write_u32_le(buf + off, e.magic);              off += 4;
    write_u16_le(buf + off, e.version);            off += 2;
    write_u16_le(buf + off, e.struct_size);        off += 2;
    write_u64_le(buf + off, e.event_id);           off += 8;

    write_u64_le(buf + off, e.timestamp_ms);      off += 8;
    write_u64_le(buf + off, e.monotonic_ns);      off += 8;

    buf[off] = static_cast<uint8_t>(e.source);    off += 1;
    write_u32_le(buf + off, e.source_ip);         off += 4;
    write_u16_le(buf + off, e.source_port);       off += 2;
    write_u32_le(buf + off, e.dest_ip);           off += 4;
    write_u16_le(buf + off, e.dest_port);         off += 2;
    write_u64_le(buf + off, e.session_id);        off += 8;

    buf[off] = e.protocol;                        off += 1;
    buf[off] = e.direction;                       off += 1;
    buf[off] = e.layer_id;                        off += 1;
    buf[off] = e.is_pipe;                         off += 1;

    write_u32_le(buf + off, static_cast<uint32_t>(e.event_type)); off += 4;
    buf[off] = e.severity;                        off += 1;
    write_u32_le(buf + off, e.rule_id);           off += 4;
    write_u64_le(buf + off, e.ruleset_version);   off += 8;

    write_u32_le(buf + off, e.payload_length);    off += 4;
    write_u64_le(buf + off, e.payload_hash);      off += 8;

    buf[off] = static_cast<uint8_t>(e.policy_action); off += 1;
    buf[off] = e.enforcement_status;             off += 1;
    buf[off] = e.defcon_impact;                   off += 1;
    write_u32_le(buf + off, e.context_flags);    off += 4;

    ::memcpy(buf + off, e.reserved, 16);           off += 16;

    return off; // 109
}

// Decode CanonicalEvent from bytes[0..109]. Returns true on success, false on validation failure.
inline bool aegis_wire_decode_event(const uint8_t* bytes, size_t bytes_len, CanonicalEvent& out) {
    if (bytes_len < WIRE_PAYLOAD_SIZE) return false;
    size_t off = 0;

    out.magic          = read_u32_le(bytes + off); off += 4;
    out.version        = read_u16_le(bytes + off); off += 2;
    out.struct_size    = read_u16_le(bytes + off); off += 2;
    out.event_id       = read_u64_le(bytes + off); off += 8;

    out.timestamp_ms   = read_u64_le(bytes + off); off += 8;
    out.monotonic_ns   = read_u64_le(bytes + off); off += 8;

    out.source         = static_cast<EventSource>(bytes[off]); off += 1;
    out.source_ip      = read_u32_le(bytes + off); off += 4;
    out.source_port    = read_u16_le(bytes + off); off += 2;
    out.dest_ip        = read_u32_le(bytes + off); off += 4;
    out.dest_port      = read_u16_le(bytes + off); off += 2;
    out.session_id     = read_u64_le(bytes + off); off += 8;

    out.protocol       = bytes[off]; off += 1;
    out.direction      = bytes[off]; off += 1;
    out.layer_id       = bytes[off]; off += 1;
    out.is_pipe        = bytes[off]; off += 1;

    out.event_type     = static_cast<EventType>(read_u32_le(bytes + off)); off += 4;
    out.severity       = bytes[off]; off += 1;
    out.rule_id        = read_u32_le(bytes + off); off += 4;
    out.ruleset_version = read_u64_le(bytes + off); off += 8;

    out.payload_length = read_u32_le(bytes + off); off += 4;
    out.payload_hash   = read_u64_le(bytes + off); off += 8;

    out.policy_action        = static_cast<PolicyAction>(bytes[off]); off += 1;
    out.enforcement_status   = bytes[off]; off += 1;
    out.defcon_impact        = bytes[off]; off += 1;
    out.context_flags        = read_u32_le(bytes + off); off += 4;

    ::memcpy(out.reserved, bytes + off, 16); off += 16;

    // Validate magic + version after decode.
    if (out.magic != EVENT_MAGIC) return false;
    if (out.version != EVENT_VERSION) return false;
    return true;
}

// --- v2 helpers (full IPv6 identity) ---

// Big-endian u32 of the first 4 network-order bytes (Go derivation rule:
// SourceIP == BigEndian.Uint32(addr[:4])).
inline uint32_t v6_first4_be(const uint8_t addr[16]) {
    return (static_cast<uint32_t>(addr[0]) << 24) |
           (static_cast<uint32_t>(addr[1]) << 16) |
           (static_cast<uint32_t>(addr[2]) << 8) |
           static_cast<uint32_t>(addr[3]);
}

inline void v6_first4_write_be(uint32_t v, uint8_t out[16]) {
    out[0] = (uint8_t)((v >> 24) & 0xFF);
    out[1] = (uint8_t)((v >> 16) & 0xFF);
    out[2] = (uint8_t)((v >> 8) & 0xFF);
    out[3] = (uint8_t)(v & 0xFF);
}

// Encode CanonicalEvent into buf[0..133] (v1 prefix + v6 tail).
// Returns 133 on success, 0 on failure. Requires bit2 + first-4 consistency.
inline size_t aegis_wire_encode_event_v2(uint8_t* buf, size_t buf_len, const CanonicalEvent& e) {
    if (buf_len < WIRE_V2_PAYLOAD_SIZE) return 0;
    if ((e.context_flags & CONTEXT_V6_TRUNCATED) == 0) return 0;
    if (v6_first4_be(e.src_ipv6) != e.source_ip) return 0;
    if (v6_first4_be(e.dst_ipv6) != e.dest_ip) return 0;
    size_t n = aegis_wire_encode_event(buf, buf_len, e);
    if (n != WIRE_PAYLOAD_SIZE) return 0;
    // Patch the version field (logical event stays v1-layout, version 1).
    write_u16_le(buf + 4, EVENT_VERSION_V2);
    ::memcpy(buf + WIRE_PAYLOAD_SIZE, e.src_ipv6 + 4, 12);
    ::memcpy(buf + WIRE_PAYLOAD_SIZE + 12, e.dst_ipv6 + 4, 12);
    return WIRE_V2_PAYLOAD_SIZE;
}

// Decode a v2 frame (133 bytes) with full-address reconstruction.
// Returns true on success, false on any validation failure.
inline bool aegis_wire_decode_event_v2(const uint8_t* bytes, size_t bytes_len, CanonicalEvent& out) {
    if (bytes_len < WIRE_V2_PAYLOAD_SIZE) return false;
    // Decode the v1 prefix with the frozen validator, then lift the
    // version gate: decode_event demands schema 1.
    uint8_t prefix[WIRE_PAYLOAD_SIZE];
    ::memcpy(prefix, bytes, WIRE_PAYLOAD_SIZE);
    write_u16_le(prefix + 4, EVENT_VERSION);
    if (!aegis_wire_decode_event(prefix, WIRE_PAYLOAD_SIZE, out)) return false;
    // Restore the as-read version, then reconstruct network-order addresses.
    out.version = EVENT_VERSION_V2;
    v6_first4_write_be(out.source_ip, out.src_ipv6);
    ::memcpy(out.src_ipv6 + 4, bytes + WIRE_PAYLOAD_SIZE, 12);
    v6_first4_write_be(out.dest_ip, out.dst_ipv6);
    ::memcpy(out.dst_ipv6 + 4, bytes + WIRE_PAYLOAD_SIZE + 12, 12);
    return true;
}

// --- v3 helpers (bounded payload + capture provenance) ---
// v3 = v2 133-byte base (zero tail when bit2 is clear) + 32-byte envelope
// + 0..1024 payload bytes. v1/v2 stay byte-identical metadata-only frames.
static constexpr uint16_t EVENT_VERSION_V3 = 3;
static constexpr size_t V3_BASE_SIZE = WIRE_V2_PAYLOAD_SIZE;
static constexpr size_t V3_ENVELOPE_SIZE = 32;
static constexpr size_t WIRE_V3_HEADER_SIZE = V3_BASE_SIZE + V3_ENVELOPE_SIZE; // 165
static constexpr size_t V3_MAX_PAYLOAD = 1024;
static constexpr size_t WIRE_V3_MAX_SIZE = WIRE_V3_HEADER_SIZE + V3_MAX_PAYLOAD; // 1189

static constexpr uint8_t PAYLOAD_UNAVAILABLE = 0;
static constexpr uint8_t PAYLOAD_COMPLETE = 1;
static constexpr uint8_t PAYLOAD_TRUNCATED = 2;
static constexpr uint8_t PAYLOAD_METADATA_ONLY = 3;
static constexpr uint16_t V3_FLAG_PAYLOAD_PRESENT = (1u << 0);
static constexpr uint16_t V3_FLAG_PROVENANCE_VALID = (1u << 1);

struct V3Envelope {
    uint16_t flags;
    uint8_t completeness;
    uint16_t payload_len;
    uint16_t original_len;
    uint32_t payload_crc32;
    uint64_t capture_sequence;
    uint32_t producer_epoch;
    uint32_t producer_generation;
    uint32_t interface_id;
};

inline bool aegis_v3_envelope_valid(const V3Envelope& env, const uint8_t* payload, size_t payload_len) {
    if (payload_len > V3_MAX_PAYLOAD) return false;
    if ((size_t)env.payload_len != payload_len) return false;
    const bool present = (env.flags & V3_FLAG_PAYLOAD_PRESENT) != 0;
    if (env.completeness == PAYLOAD_UNAVAILABLE || env.completeness == PAYLOAD_METADATA_ONLY) {
        if (present || payload_len != 0 || env.payload_crc32 != 0) return false;
        if (env.completeness == PAYLOAD_METADATA_ONLY && env.original_len != 0) return false;
    } else if (env.completeness == PAYLOAD_COMPLETE) {
        if (!present || payload_len == 0) return false;
        if (env.original_len != env.payload_len) return false;
        if (aegis_crc32(payload, payload_len) != env.payload_crc32) return false;
    } else if (env.completeness == PAYLOAD_TRUNCATED) {
        if (!present || payload_len == 0) return false;
        if (env.original_len <= env.payload_len) return false;
        if (aegis_crc32(payload, payload_len) != env.payload_crc32) return false;
    } else {
        return false;
    }
    if ((env.flags & V3_FLAG_PROVENANCE_VALID) == 0) {
        if (env.capture_sequence != 0 || env.producer_epoch != 0 ||
            env.producer_generation != 0 || env.interface_id != 0) return false;
    }
    return true;
}

// Encode a v3 frame into buf. Requires src/dst IPv6 iff bit2 is set.
// Returns the frame length, or 0 on any validation failure.
inline size_t aegis_wire_encode_event_v3(uint8_t* buf, size_t buf_len,
                                         const CanonicalEvent& e,
                                         const V3Envelope& env,
                                         const uint8_t* payload, size_t payload_len) {
    if (!aegis_v3_envelope_valid(env, payload, payload_len)) return 0;
    const size_t total = WIRE_V3_HEADER_SIZE + payload_len;
    if (buf_len < total) return 0;

    if ((e.context_flags & CONTEXT_V6_TRUNCATED) != 0) {
        if (aegis_wire_encode_event_v2(buf, buf_len, e) != WIRE_V2_PAYLOAD_SIZE) return 0;
    } else {
        if (aegis_wire_encode_event(buf, buf_len, e) != WIRE_PAYLOAD_SIZE) return 0;
        ::memset(buf + WIRE_PAYLOAD_SIZE, 0, V6_TAIL_SIZE);
    }
    write_u16_le(buf + 4, EVENT_VERSION_V3);

    const size_t off = V3_BASE_SIZE;
    write_u16_le(buf + off + 0, env.flags);
    buf[off + 2] = env.completeness;
    buf[off + 3] = 0;
    write_u16_le(buf + off + 4, env.payload_len);
    write_u16_le(buf + off + 6, env.original_len);
    write_u32_le(buf + off + 8, env.payload_crc32);
    write_u64_le(buf + off + 12, env.capture_sequence);
    write_u32_le(buf + off + 20, env.producer_epoch);
    write_u32_le(buf + off + 24, env.producer_generation);
    write_u32_le(buf + off + 28, env.interface_id);
    if (payload_len > 0) ::memcpy(buf + WIRE_V3_HEADER_SIZE, payload, payload_len);
    return total;
}

// Decode a strict v3 frame. `payload` aliases the input buffer.
inline bool aegis_wire_decode_event_v3(const uint8_t* bytes, size_t bytes_len,
                                       CanonicalEvent& out, V3Envelope& env,
                                       const uint8_t** payload, size_t* payload_len) {
    if (bytes_len < WIRE_V3_HEADER_SIZE) return false;
    uint8_t prefix[WIRE_PAYLOAD_SIZE];
    ::memcpy(prefix, bytes, WIRE_PAYLOAD_SIZE);
    write_u16_le(prefix + 4, EVENT_VERSION);
    if (!aegis_wire_decode_event(prefix, WIRE_PAYLOAD_SIZE, out)) return false;

    const bool is_v6 = (out.context_flags & CONTEXT_V6_TRUNCATED) != 0;
    if (is_v6) {
        v6_first4_write_be(out.source_ip, out.src_ipv6);
        ::memcpy(out.src_ipv6 + 4, bytes + WIRE_PAYLOAD_SIZE, 12);
        v6_first4_write_be(out.dest_ip, out.dst_ipv6);
        ::memcpy(out.dst_ipv6 + 4, bytes + WIRE_PAYLOAD_SIZE + 12, 12);
    } else {
        for (size_t i = WIRE_PAYLOAD_SIZE; i < V3_BASE_SIZE; ++i) {
            if (bytes[i] != 0) return false;
        }
        ::memset(out.src_ipv6, 0, 16);
        ::memset(out.dst_ipv6, 0, 16);
    }

    const size_t off = V3_BASE_SIZE;
    // wire_v3.md: any non-zero reserved byte is rejected fail closed.
    if (bytes[off + 3] != 0) return false;
    env.flags = read_u16_le(bytes + off + 0);
    env.completeness = bytes[off + 2];
    env.payload_len = read_u16_le(bytes + off + 4);
    env.original_len = read_u16_le(bytes + off + 6);
    env.payload_crc32 = read_u32_le(bytes + off + 8);
    env.capture_sequence = read_u64_le(bytes + off + 12);
    env.producer_epoch = read_u32_le(bytes + off + 20);
    env.producer_generation = read_u32_le(bytes + off + 24);
    env.interface_id = read_u32_le(bytes + off + 28);
    if ((size_t)env.payload_len > V3_MAX_PAYLOAD) return false;
    if (bytes_len != WIRE_V3_HEADER_SIZE + (size_t)env.payload_len) return false;
    *payload = bytes + WIRE_V3_HEADER_SIZE;
    *payload_len = env.payload_len;
    if (!aegis_v3_envelope_valid(env, *payload, *payload_len)) return false;
    out.version = EVENT_VERSION_V3;
    return true;
}

// Version-dispatched decode: 109-byte v1 (sidecars zeroed), 133-byte v2, or
// a bounded v3 frame. For v3 the caller supplies envelope/payload outputs.
inline bool aegis_wire_decode_event_dispatch(const uint8_t* bytes, size_t bytes_len, CanonicalEvent& out) {
    if (bytes_len < WIRE_PAYLOAD_SIZE) return false;
    uint16_t ver = (uint16_t)bytes[4] | ((uint16_t)bytes[5] << 8);
    if (ver == EVENT_VERSION) {
        bool ok = aegis_wire_decode_event(bytes, bytes_len, out);
        if (!ok) return false;
        ::memset(out.src_ipv6, 0, 16);
        ::memset(out.dst_ipv6, 0, 16);
        return true;
    }
    if (ver == EVENT_VERSION_V3) {
        V3Envelope env;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        return aegis_wire_decode_event_v3(bytes, bytes_len, out, env, &payload, &payload_len);
    }
    if (ver != EVENT_VERSION_V2) return false;
    return aegis_wire_decode_event_v2(bytes, bytes_len, out);
}

// ============================================================
// Full wire frame encode (header + canonical event payload)
// ============================================================

// Encode a complete wire frame into buf[0..125]. Returns 125 on success.
inline size_t aegis_wire_encode_frame(uint8_t* buf, size_t buf_len, const CanonicalEvent& e) {
    if (buf_len < WIRE_FRAME_SIZE) return 0;

    // Encode payload at offset 16.
    size_t payload_written = aegis_wire_encode_event(buf + WIRE_HEADER_SIZE, buf_len - WIRE_HEADER_SIZE, e);
    if (payload_written != WIRE_PAYLOAD_SIZE) return 0;

    // Compute CRC32 over payload.
    uint32_t crc = aegis_crc32(buf + WIRE_HEADER_SIZE, WIRE_PAYLOAD_SIZE);

    // Encode header field-by-field.
    WireHeader h;
    h.magic          = WIRE_MAGIC;
    h.version        = WIRE_VERSION;
    h.payload_type   = static_cast<uint16_t>(PayloadType::canonical_event);
    h.payload_length = static_cast<uint32_t>(WIRE_PAYLOAD_SIZE);
    h.crc32          = crc;

    if (aegis_wire_encode_header(buf, buf_len, h) != WIRE_HEADER_SIZE) return 0;
    return WIRE_FRAME_SIZE;
}

// Decode a complete wire frame. Returns true on success, false on validation failure.
inline bool aegis_wire_decode_frame(const uint8_t* buf, size_t buf_len, CanonicalEvent& out) {
    if (buf_len < WIRE_HEADER_SIZE) return false;

    WireHeader h;
    if (!aegis_wire_decode_header(buf, buf_len, h)) return false;

    if (h.magic != WIRE_MAGIC) return false;
    if (h.version != WIRE_VERSION) return false;
    if (h.payload_type != static_cast<uint16_t>(PayloadType::canonical_event)) return false;
    if (h.payload_length != WIRE_PAYLOAD_SIZE && h.payload_length != WIRE_V2_PAYLOAD_SIZE) return false;
    if (buf_len < WIRE_HEADER_SIZE + h.payload_length) return false;

    // Verify CRC32.
    uint32_t computed_crc = aegis_crc32(buf + WIRE_HEADER_SIZE, h.payload_length);
    if (computed_crc != h.crc32) return false;

    // Decode canonical event (version-dispatched).
    if (h.payload_length == WIRE_PAYLOAD_SIZE)
        return aegis_wire_decode_event(buf + WIRE_HEADER_SIZE, h.payload_length, out);
    return aegis_wire_decode_event_v2(buf + WIRE_HEADER_SIZE, h.payload_length, out);
}

} // namespace aegis

#endif // AEGIS_WIRE_CODEC_H
