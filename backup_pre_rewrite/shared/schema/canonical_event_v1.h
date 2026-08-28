// ============================================================
// AEGIS Canonical Event Schema v1 (STEP 1 — ABI-safe)
// ============================================================
// This is the single source of truth for the Canonical Event schema.
// All languages MUST implement the same layout:
//   - Zig:   extern struct (natural alignment)
//   - C++:   struct with same field order
//   - Rust:  #[repr(C)]
//   - Go:    struct with same field order
//   - Python: dataclass with same field names
//
// STEP 1 Changes:
//   - timestamp_ms: i64 → u64 (no negative timestamps)
//   - monotonic_ns: i128 → u64 (i128 not portable across languages)
//   - All fields are fixed-width primitive types (no pointers, no padding dependency)
// ============================================================

#pragma once
#include <stdint.h>

#define AEGIS_EVENT_MAGIC   0x41454731u  // "AEG1"
#define AEGIS_EVENT_VERSION 1u
#define AEGIS_EVENT_SIZE    sizeof(AegisCanonicalEvent)

typedef enum {
    AEGIS_SOURCE_ZIG_CORE      = 0,
    AEGIS_SOURCE_WFP_SENSOR    = 1,
    AEGIS_SOURCE_PIPE_SENSOR   = 2,
    AEGIS_SOURCE_MINIFILTER    = 3,
    AEGIS_SOURCE_PIPE_MONITOR  = 4,
    AEGIS_SOURCE_PYTHON_BRAIN  = 5,
    AEGIS_SOURCE_CPP_BRIDGE    = 6,
    AEGIS_SOURCE_RUST_SHIELD   = 7,
    AEGIS_SOURCE_GO_AGGREGATOR = 8,
    AEGIS_SOURCE_EXTERNAL      = 255,
} AegisEventSource;

typedef enum {
    AEGIS_EVENT_BLOCK          = 0,
    AEGIS_EVENT_MATCH          = 1,
    AEGIS_EVENT_FORWARD        = 2,
    AEGIS_EVENT_IP_BLOCKED     = 3,
    AEGIS_EVENT_REJECTED       = 4,
    AEGIS_EVENT_SESSION_START  = 5,
    AEGIS_EVENT_SESSION_END    = 6,
    AEGIS_EVENT_RULESET_RELOAD = 7,
    AEGIS_EVENT_SHUTDOWN       = 8,
    AEGIS_EVENT_STARTUP        = 9,
    AEGIS_EVENT_CUSTOM         = 0xFFFFFFFFu,
} AegisEventType;

typedef enum {
    AEGIS_POLICY_ALLOW       = 0,
    AEGIS_POLICY_ALERT       = 1,
    AEGIS_POLICY_BLOCK       = 2,
    AEGIS_POLICY_QUARANTINE  = 3,
    AEGIS_POLICY_RATE_LIMIT  = 4,
    AEGIS_POLICY_LOG_ONLY    = 5,
} AegisPolicyAction;

// ABI-safe Canonical Event (no i128, no compiler-specific padding)
#pragma pack(push, 1)
typedef struct {
    // --- Header (16 bytes) ---
    uint32_t magic;            // 0x41454731 ("AEG1")
    uint16_t version;          // 1
    uint16_t struct_size;      // sizeof this struct
    uint64_t event_id;         // Unique ID

    // --- Timestamps (16 bytes, STEP 1: u64 not i128) ---
    uint64_t timestamp_ms;     // Wall-clock epoch ms
    uint64_t monotonic_ns;     // Monotonic ns (in-process ordering)

    // --- Source Identification (24 bytes) ---
    uint8_t  source;           // AegisEventSource
    uint32_t source_ip;        // Network byte order
    uint16_t source_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint64_t session_id;       // Cross-tier correlation ID

    // --- Protocol (4 bytes) ---
    uint8_t  protocol;         // IPPROTO_TCP=6, etc.
    uint8_t  direction;        // 0=inbound, 1=outbound
    uint8_t  layer_id;          // 0=TCP, 1=WFP, 2=kernel, 3=pipe
    uint8_t  is_pipe;           // 1 if from named pipe

    // --- Detection Results (24 bytes) ---
    uint32_t event_type;       // AegisEventType
    uint8_t  severity;          // 0-3
    uint32_t rule_id;           // SipHash64
    uint64_t ruleset_version;

    // --- Payload Reference (12 bytes) ---
    uint32_t payload_length;
    uint64_t payload_hash;      // SHA-256 prefix

    // --- Policy/Enforcement (8 bytes) ---
    uint8_t  policy_action;     // AegisPolicyAction
    uint8_t  enforcement_status; // 0=pending, 1=enforced, 2=failed
    uint8_t  defcon_impact;     // 1-5
    uint32_t context_flags;     // Bitfield

    // --- Reserved (16 bytes) ---
    uint8_t  reserved[16];

} AegisCanonicalEvent;
#pragma pack(pop)

// Verify size is consistent
_Static_assert(sizeof(AegisCanonicalEvent) > 0, "CanonicalEvent must not be zero-sized");
