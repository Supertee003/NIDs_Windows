// ============================================================
// shared/protocol/wire_v1.h - AEGIS Wire Protocol v1 (Rewrite Phase 2)
// ============================================================
// C header defining the cross-language wire protocol.
// ALL languages (Zig, C++, Rust, Go, Python) MUST produce byte-identical
// output to these reference implementations.
//
// Rules:
//   - Fixed-width fields only (u8, u16, u32, u64)
//   - Little-endian byte order (explicit)
//   - Explicit field-by-field encoding (NOT struct memcpy)
//   - No @ptrCast, no pointer cast, no compiler padding
//   - No i128 (not portable)
//
// Wire frame layout (125 bytes total):
//   [0..4]    magic           u32  0x57455631 ("WEV1")
//   [4..6]    version          u16  1
//   [6..8]    payload_type     u16  0=event, 1=cmd, 2=ack, 3=heartbeat
//   [8..12]   payload_length   u32  109 (canonical event)
//   [12..16]  crc32            u32  CRC32 of payload
//   [16..125] payload          109 bytes (canonical event)
// ============================================================

#ifndef AEGIS_WIRE_V1_H
#define AEGIS_WIRE_V1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Constants
// ============================================================

#define AEGIS_WIRE_MAGIC        0x57455631u  // "WEV1"
#define AEGIS_WIRE_VERSION      1
#define AEGIS_WIRE_HEADER_SIZE  16
#define AEGIS_WIRE_PAYLOAD_SIZE 109
#define AEGIS_WIRE_FRAME_SIZE   (AEGIS_WIRE_HEADER_SIZE + AEGIS_WIRE_PAYLOAD_SIZE) // 125

#define AEGIS_EVENT_MAGIC       0x41454731u  // "AEG1"
#define AEGIS_EVENT_VERSION     1

// ============================================================
// Payload types
// ============================================================

#define AEGIS_PAYLOAD_EVENT     0
#define AEGIS_PAYLOAD_COMMAND   1
#define AEGIS_PAYLOAD_ACK       2
#define AEGIS_PAYLOAD_HEARTBEAT 3

// ============================================================
// Wire header (16 bytes, explicit encoding)
// ============================================================

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t payload_type;
    uint32_t payload_length;
    uint32_t crc32;
} aegis_wire_header_t;

// ============================================================
// Little-endian write helpers (no struct memcpy)
// ============================================================

static inline void aegis_write_u16_le(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void aegis_write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline void aegis_write_u64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
    p[4] = (uint8_t)((v >> 32) & 0xFF);
    p[5] = (uint8_t)((v >> 40) & 0xFF);
    p[6] = (uint8_t)((v >> 48) & 0xFF);
    p[7] = (uint8_t)((v >> 56) & 0xFF);
}

static inline uint16_t aegis_read_u16_le(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t aegis_read_u32_le(const uint8_t* p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static inline uint64_t aegis_read_u64_le(const uint8_t* p) {
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
// Wire header encode/decode (explicit, no memcpy)
// ============================================================

// Encode wire header into buf[0..16]. Returns 16 on success, 0 on failure.
static inline size_t aegis_wire_encode_header(uint8_t* buf, size_t buf_len,
                                                uint16_t payload_type,
                                                uint32_t payload_length,
                                                uint32_t crc32) {
    if (buf_len < AEGIS_WIRE_HEADER_SIZE) return 0;
    aegis_write_u32_le(buf + 0, AEGIS_WIRE_MAGIC);
    aegis_write_u16_le(buf + 4, AEGIS_WIRE_VERSION);
    aegis_write_u16_le(buf + 6, payload_type);
    aegis_write_u32_le(buf + 8, payload_length);
    aegis_write_u32_le(buf + 12, crc32);
    return AEGIS_WIRE_HEADER_SIZE;
}

// Decode wire header from bytes[0..16]. Returns 1 on success, 0 on failure.
static inline int aegis_wire_decode_header(const uint8_t* bytes, size_t bytes_len,
                                             aegis_wire_header_t* out) {
    if (bytes_len < AEGIS_WIRE_HEADER_SIZE) return 0;
    out->magic          = aegis_read_u32_le(bytes + 0);
    out->version        = aegis_read_u16_le(bytes + 4);
    out->payload_type   = aegis_read_u16_le(bytes + 6);
    out->payload_length = aegis_read_u32_le(bytes + 8);
    out->crc32          = aegis_read_u32_le(bytes + 12);
    return 1;
}

// ============================================================
// CRC32 (IEEE 802.3, same as zlib.crc32 / std.hash.Crc32)
// ============================================================

static inline uint32_t aegis_crc32(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static int initialized = 0;
    if (!initialized) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        initialized = 1;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// ============================================================
// Canonical event encode/decode (109 bytes, explicit)
// ============================================================

// Encode canonical event into buf[0..109]. Returns 109 on success, 0 on failure.
static inline size_t aegis_wire_encode_event(uint8_t* buf, size_t buf_len,
    uint32_t magic, uint16_t version, uint16_t struct_size,
    uint64_t event_id, uint64_t timestamp_ms, uint64_t monotonic_ns,
    uint8_t source, uint32_t source_ip, uint16_t source_port,
    uint32_t dest_ip, uint16_t dest_port, uint64_t session_id,
    uint8_t protocol, uint8_t direction, uint8_t layer_id, uint8_t is_pipe,
    uint32_t event_type, uint8_t severity, uint32_t rule_id, uint64_t ruleset_version,
    uint32_t payload_length, uint64_t payload_hash,
    uint8_t policy_action, uint8_t enforcement_status, uint8_t defcon_impact,
    uint32_t context_flags, const uint8_t reserved[16])
{
    if (buf_len < AEGIS_WIRE_PAYLOAD_SIZE) return 0;
    size_t off = 0;
    aegis_write_u32_le(buf + off, magic); off += 4;
    aegis_write_u16_le(buf + off, version); off += 2;
    aegis_write_u16_le(buf + off, struct_size); off += 2;
    aegis_write_u64_le(buf + off, event_id); off += 8;
    aegis_write_u64_le(buf + off, timestamp_ms); off += 8;
    aegis_write_u64_le(buf + off, monotonic_ns); off += 8;
    buf[off] = source; off += 1;
    aegis_write_u32_le(buf + off, source_ip); off += 4;
    aegis_write_u16_le(buf + off, source_port); off += 2;
    aegis_write_u32_le(buf + off, dest_ip); off += 4;
    aegis_write_u16_le(buf + off, dest_port); off += 2;
    aegis_write_u64_le(buf + off, session_id); off += 8;
    buf[off] = protocol; off += 1;
    buf[off] = direction; off += 1;
    buf[off] = layer_id; off += 1;
    buf[off] = is_pipe; off += 1;
    aegis_write_u32_le(buf + off, event_type); off += 4;
    buf[off] = severity; off += 1;
    aegis_write_u32_le(buf + off, rule_id); off += 4;
    aegis_write_u64_le(buf + off, ruleset_version); off += 8;
    aegis_write_u32_le(buf + off, payload_length); off += 4;
    aegis_write_u64_le(buf + off, payload_hash); off += 8;
    buf[off] = policy_action; off += 1;
    buf[off] = enforcement_status; off += 1;
    buf[off] = defcon_impact; off += 1;
    aegis_write_u32_le(buf + off, context_flags); off += 4;
    if (reserved) {
        for (int i = 0; i < 16; ++i) buf[off + i] = reserved[i];
    } else {
        for (int i = 0; i < 16; ++i) buf[off + i] = 0;
    }
    off += 16;
    return off; // 109
}

// ============================================================
// Full wire frame encode (header + payload)
// ============================================================

// Encode a complete wire frame (125 bytes). Returns 125 on success.
static inline size_t aegis_wire_encode_frame(uint8_t* buf, size_t buf_len,
    uint16_t payload_type,
    uint32_t magic, uint16_t version, uint16_t struct_size,
    uint64_t event_id, uint64_t timestamp_ms, uint64_t monotonic_ns,
    uint8_t source, uint32_t source_ip, uint16_t source_port,
    uint32_t dest_ip, uint16_t dest_port, uint64_t session_id,
    uint8_t protocol, uint8_t direction, uint8_t layer_id, uint8_t is_pipe,
    uint32_t event_type, uint8_t severity, uint32_t rule_id, uint64_t ruleset_version,
    uint32_t payload_length, uint64_t payload_hash,
    uint8_t policy_action, uint8_t enforcement_status, uint8_t defcon_impact,
    uint32_t context_flags, const uint8_t reserved[16])
{
    if (buf_len < AEGIS_WIRE_FRAME_SIZE) return 0;

    // Encode payload first
    size_t payload_written = aegis_wire_encode_event(
        buf + AEGIS_WIRE_HEADER_SIZE, buf_len - AEGIS_WIRE_HEADER_SIZE,
        magic, version, struct_size, event_id, timestamp_ms, monotonic_ns,
        source, source_ip, source_port, dest_ip, dest_port, session_id,
        protocol, direction, layer_id, is_pipe,
        event_type, severity, rule_id, ruleset_version,
        payload_length, payload_hash,
        policy_action, enforcement_status, defcon_impact,
        context_flags, reserved);
    if (payload_written != AEGIS_WIRE_PAYLOAD_SIZE) return 0;

    // Compute CRC32
    uint32_t crc = aegis_crc32(buf + AEGIS_WIRE_HEADER_SIZE, AEGIS_WIRE_PAYLOAD_SIZE);

    // Encode header
    if (aegis_wire_encode_header(buf, buf_len, payload_type,
                                  AEGIS_WIRE_PAYLOAD_SIZE, crc) != AEGIS_WIRE_HEADER_SIZE)
        return 0;

    return AEGIS_WIRE_FRAME_SIZE;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // AEGIS_WIRE_V1_H
