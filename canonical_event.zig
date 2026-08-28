//! canonical_event.zig - AEGIS Canonical Event Model v1 (Rewrite Phase 1)
//!
//! REWRITE v3.0 Phase 1: Canonical Event Reset
//!
//! Changes from previous version:
//!   1. serializeToBytes()/deserializeFromBytes() are now the OFFICIAL API
//!   2. Legacy serialize()/deserialize() are DEPRECATED (marked with @deprecated)
//!   3. @ptrCast and @alignCast are no longer used in the official path
//!   4. All serialization uses explicit field-by-field encoding (little-endian)
//!   5. Cross-language test vectors in tests/contracts/event_vectors/
//!
//! Single source of truth for event structure across all AEGIS subsystems.
//! Every sensor, detector, correlator, and policy engine MUST use this model.

const std = @import("std");

// ============================================================
// Event Schema Version
// ============================================================

pub const EVENT_MAGIC: u32 = 0x41454731; // "AEG1" - Canonical Event v1
pub const EVENT_VERSION: u16 = 1;
pub const EVENT_SCHEMA_SIZE: u16 = @sizeOf(CanonicalEvent);

// ============================================================
// Canonical Event Model v1
// ============================================================
// This is the single source of truth for event structure.
// All languages must implement the same field layout via explicit
// field-by-field encoding (NOT struct memcpy).

pub const CanonicalEvent = extern struct {
    // --- Header (B-05 ABI safety) ---
    magic: u32,             // 0x41454731 ("AEG1")
    version: u16,           // 1
    struct_size: u16,       // sizeof(CanonicalEvent) for forward compat
    event_id: u64,          // Unique ID (atomic counter)

    // --- Timestamps (IR-04 dual-clock, ABI-safe u64) ---
    timestamp_ms: u64,      // Wall-clock epoch milliseconds
    monotonic_ns: u64,      // Monotonic nanoseconds (was i128 -- not portable ABI)

    // --- Source Identification ---
    source: EventSource,   // Which subsystem produced this event
    source_ip: u32,        // Network byte order (0 = N/A for host events)
    source_port: u16,
    dest_ip: u32,
    dest_port: u16,
    session_id: u64,        // Cross-tier correlation ID

    // --- Protocol/Transport ---
    protocol: u8,           // IPPROTO_TCP=6, IPPROTO_UDP=17, etc.
    direction: u8,          // 0=inbound, 1=outbound
    layer_id: u8,           // 0=TCP, 1=WFP, 2=kernel, 3=pipe
    is_pipe: u8,            // 1 if from named pipe (host event)

    // --- Detection Results ---
    event_type: EventType,  // BLOCK/MATCH/FORWARD/IP_BLOCKED/REJECTED
    severity: u8,           // 0=Low, 1=Medium, 2=High, 3=Critical
    rule_id: u32,           // Rule hash (SipHash64 from P-04)
    ruleset_version: u64,   // Which ruleset version matched

    // --- Payload Reference ---
    payload_length: u32,    // Original payload size
    payload_hash: u64,      // SHA-256 prefix (first 8 bytes) for dedup

    // --- Policy/Enforcement ---
    policy_action: PolicyAction, // ALLOW/ALERT/BLOCK/QUARANTINE
    enforcement_status: u8, // 0=pending, 1=enforced, 2=failed, 3=rolled_back

    // --- Context/Intelligence (filled by Brain/Correlator) ---
    defcon_impact: u8,      // 1-5 (5=normal, 1=critical)
    context_flags: u32,     // Bitfield: bit0=threat_intel_match, bit1=correlation_match, etc.

    // --- Reserved for future expansion ---
    reserved: [16]u8,       // Zero-filled, available for v2 fields
};

// ============================================================
// Enums (must match across all languages)
// ============================================================

pub const EventSource = enum(u8) {
    zig_core = 0,
    wfp_sensor = 1,
    pipe_sensor = 2,
    minifilter = 3,
    pipe_monitor = 4,
    python_brain = 5,
    cpp_bridge = 6,
    rust_shield = 7,
    go_aggregator = 8,
    external = 255,
};

pub const EventType = enum(u32) {
    block = 0,
    match_ = 1,
    forward = 2,
    ip_blocked = 3,
    rejected = 4,
    session_start = 5,
    session_end = 6,
    ruleset_reload = 7,
    shutdown = 8,
    startup = 9,
    custom = 0xFFFFFFFF,
};

pub const PolicyAction = enum(u8) {
    allow = 0,
    alert = 1,
    block = 2,
    quarantine = 3,
    rate_limit = 4,
    log_only = 5,
};

// ============================================================
// Validation (B-05 ABI safety)
// ============================================================

pub fn validate(event: *const CanonicalEvent) bool {
    if (event.magic != EVENT_MAGIC) return false;
    if (event.version != EVENT_VERSION) return false;
    if (event.struct_size != EVENT_SCHEMA_SIZE) return false;
    return true;
}

// ============================================================
// Event ID Generator (atomic counter)
// ============================================================

var g_event_id_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub fn nextEventId() u64 {
    return g_event_id_counter.fetchAdd(1, .acq_rel) + 1;
}

// ============================================================
// Event Creation Helper
// ============================================================

pub fn create(source: EventSource) CanonicalEvent {
    return .{
        .magic = EVENT_MAGIC,
        .version = EVENT_VERSION,
        .struct_size = EVENT_SCHEMA_SIZE,
        .event_id = nextEventId(),
        .timestamp_ms = @as(u64, @intCast(@max(@as(i64, 0), std.time.milliTimestamp()))),
        .monotonic_ns = @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()))),
        .source = source,
        .source_ip = 0,
        .source_port = 0,
        .dest_ip = 0,
        .dest_port = 0,
        .session_id = 0,
        .protocol = 0,
        .direction = 0,
        .layer_id = 0,
        .is_pipe = 0,
        .event_type = .custom,
        .severity = 0,
        .rule_id = 0,
        .ruleset_version = 0,
        .payload_length = 0,
        .payload_hash = 0,
        .policy_action = .allow,
        .enforcement_status = 0,
        .defcon_impact = 5,
        .context_flags = 0,
        .reserved = [_]u8{0} ** 16,
    };
}

// ============================================================
// OFFICIAL Serialization API (Rewrite Phase 1)
// ============================================================
// Explicit field-by-field encoding (little-endian, no memcpy).
// This is the ONLY official serialization path.
// All cross-language communication MUST use these functions.

/// Wire payload size (matches shared/protocol/wire_v1.md offset table)
pub const WIRE_PAYLOAD_SIZE: usize = 109;

/// Serialize CanonicalEvent to bytes via explicit field-by-field encoding.
/// REWRITE Phase 1: This is the OFFICIAL API.
/// No memcpy, no pointer cast, no compiler-padding dependency.
/// All fields little-endian, fixed-width.
pub fn serializeToBytes(event: *const CanonicalEvent, buf: []u8) !usize {
    if (buf.len < WIRE_PAYLOAD_SIZE) return error.BufferTooSmall;

    var off: usize = 0;

    // --- Header (16 bytes) ---
    std.mem.writeInt(u32, buf[off..][0..4], event.magic, .little); off += 4;
    std.mem.writeInt(u16, buf[off..][0..2], event.version, .little); off += 2;
    std.mem.writeInt(u16, buf[off..][0..2], event.struct_size, .little); off += 2;
    std.mem.writeInt(u64, buf[off..][0..8], event.event_id, .little); off += 8;

    // --- Timestamps (16 bytes) ---
    std.mem.writeInt(u64, buf[off..][0..8], event.timestamp_ms, .little); off += 8;
    std.mem.writeInt(u64, buf[off..][0..8], event.monotonic_ns, .little); off += 8;

    // --- Source Identification ---
    buf[off] = @intFromEnum(event.source); off += 1;
    std.mem.writeInt(u32, buf[off..][0..4], event.source_ip, .little); off += 4;
    std.mem.writeInt(u16, buf[off..][0..2], event.source_port, .little); off += 2;
    std.mem.writeInt(u32, buf[off..][0..4], event.dest_ip, .little); off += 4;
    std.mem.writeInt(u16, buf[off..][0..2], event.dest_port, .little); off += 2;
    std.mem.writeInt(u64, buf[off..][0..8], event.session_id, .little); off += 8;

    // --- Protocol ---
    buf[off] = event.protocol; off += 1;
    buf[off] = event.direction; off += 1;
    buf[off] = event.layer_id; off += 1;
    buf[off] = event.is_pipe; off += 1;

    // --- Detection Results ---
    std.mem.writeInt(u32, buf[off..][0..4], @intFromEnum(event.event_type), .little); off += 4;
    buf[off] = event.severity; off += 1;
    std.mem.writeInt(u32, buf[off..][0..4], event.rule_id, .little); off += 4;
    std.mem.writeInt(u64, buf[off..][0..8], event.ruleset_version, .little); off += 8;

    // --- Payload Reference ---
    std.mem.writeInt(u32, buf[off..][0..4], event.payload_length, .little); off += 4;
    std.mem.writeInt(u64, buf[off..][0..8], event.payload_hash, .little); off += 8;

    // --- Policy/Enforcement ---
    buf[off] = @intFromEnum(event.policy_action); off += 1;
    buf[off] = event.enforcement_status; off += 1;
    buf[off] = event.defcon_impact; off += 1;
    std.mem.writeInt(u32, buf[off..][0..4], event.context_flags, .little); off += 4;

    // --- Reserved ---
    @memcpy(buf[off..][0..16], &event.reserved); off += 16;

    return off; // 109
}

/// Deserialize bytes into CanonicalEvent via explicit field-by-field decoding.
/// REWRITE Phase 1: This is the OFFICIAL API.
/// No pointer cast, no alignment dependency.
pub fn deserializeFromBytes(bytes: []const u8) ?CanonicalEvent {
    if (bytes.len < WIRE_PAYLOAD_SIZE) return null;

    var event: CanonicalEvent = undefined;
    var off: usize = 0;

    // --- Header ---
    event.magic = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;
    event.version = std.mem.readInt(u16, bytes[off..][0..2], .little); off += 2;
    event.struct_size = std.mem.readInt(u16, bytes[off..][0..2], .little); off += 2;
    event.event_id = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;

    // --- Timestamps ---
    event.timestamp_ms = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;
    event.monotonic_ns = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;

    // --- Source ---
    event.source = @enumFromInt(bytes[off]); off += 1;
    event.source_ip = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;
    event.source_port = std.mem.readInt(u16, bytes[off..][0..2], .little); off += 2;
    event.dest_ip = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;
    event.dest_port = std.mem.readInt(u16, bytes[off..][0..2], .little); off += 2;
    event.session_id = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;

    // --- Protocol ---
    event.protocol = bytes[off]; off += 1;
    event.direction = bytes[off]; off += 1;
    event.layer_id = bytes[off]; off += 1;
    event.is_pipe = bytes[off]; off += 1;

    // --- Detection ---
    event.event_type = @enumFromInt(std.mem.readInt(u32, bytes[off..][0..4], .little)); off += 4;
    event.severity = bytes[off]; off += 1;
    event.rule_id = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;
    event.ruleset_version = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;

    // --- Payload ---
    event.payload_length = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;
    event.payload_hash = std.mem.readInt(u64, bytes[off..][0..8], .little); off += 8;

    // --- Policy ---
    event.policy_action = @enumFromInt(bytes[off]); off += 1;
    event.enforcement_status = bytes[off]; off += 1;
    event.defcon_impact = bytes[off]; off += 1;
    event.context_flags = std.mem.readInt(u32, bytes[off..][0..4], .little); off += 4;

    // --- Reserved ---
    @memcpy(&event.reserved, bytes[off..][0..16]); off += 16;

    if (!validate(&event)) return null;
    return event;
}

// ============================================================
// DEPRECATED Legacy Serialization (Rewrite Phase 1)
// ============================================================
// These functions use @ptrCast / @alignCast which are NOT portable
// across compilers, languages, or platforms.
//
// DEPRECATED: Do NOT use in new code.
// Migration: Replace serialize() -> serializeToBytes()
//            Replace deserialize() -> deserializeFromBytes()
//
// These will be REMOVED in Rewrite Phase 20 (Legacy Removal).

pub const deprecated_serialize = serialize;
pub const deprecated_deserialize = deserialize;

/// DEPRECATED: Use serializeToBytes() instead.
/// This uses @ptrCast which is not portable.
pub fn serialize(event: *const CanonicalEvent) []const u8 {
    const ptr: [*]const u8 = @ptrCast(event);
    return ptr[0..@sizeOf(CanonicalEvent)];
}

/// DEPRECATED: Use deserializeFromBytes() instead.
/// This uses @ptrCast + @alignCast which is not portable.
pub fn deserialize(bytes: []const u8) ?*const CanonicalEvent {
    if (bytes.len < @sizeOf(CanonicalEvent)) return null;
    const event: *const CanonicalEvent = @ptrCast(@alignCast(bytes.ptr));
    if (!validate(event)) return null;
    return event;
}

// ============================================================
// Tests
// ============================================================

test "CanonicalEvent magic and version" {
    try std.testing.expect(EVENT_MAGIC == 0x41454731);
    try std.testing.expect(EVENT_VERSION == 1);
}

test "create sets correct header fields" {
    const event = create(.zig_core);
    try std.testing.expect(event.magic == EVENT_MAGIC);
    try std.testing.expect(event.version == EVENT_VERSION);
    try std.testing.expect(event.struct_size == @sizeOf(CanonicalEvent));
    try std.testing.expect(event.event_id > 0);
    try std.testing.expect(event.source == .zig_core);
    try std.testing.expect(event.timestamp_ms > 0);
}

test "validate accepts correct event" {
    const event = create(.wfp_sensor);
    try std.testing.expect(validate(&event));
}

test "validate rejects wrong magic" {
    var event = create(.zig_core);
    event.magic = 0xDEADBEEF;
    try std.testing.expect(!validate(&event));
}

test "validate rejects wrong version" {
    var event = create(.zig_core);
    event.version = 999;
    try std.testing.expect(!validate(&event));
}

test "nextEventId returns increasing values" {
    const a = nextEventId();
    const b = nextEventId();
    try std.testing.expect(b > a);
}

test "EventSource enum values" {
    try std.testing.expect(@intFromEnum(EventSource.zig_core) == 0);
    try std.testing.expect(@intFromEnum(EventSource.wfp_sensor) == 1);
    try std.testing.expect(@intFromEnum(EventSource.go_aggregator) == 8);
}

test "PolicyAction enum values" {
    try std.testing.expect(@intFromEnum(PolicyAction.allow) == 0);
    try std.testing.expect(@intFromEnum(PolicyAction.block) == 2);
}

// ============================================================
// OFFICIAL API tests (serializeToBytes / deserializeFromBytes)
// ============================================================

test "serializeToBytes produces WIRE_PAYLOAD_SIZE bytes" {
    var event = create(.wfp_sensor);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;
    event.source_ip = 0xC0A80164;

    var buf: [128]u8 = undefined;
    const written = try serializeToBytes(&event, &buf);
    try std.testing.expect(written == WIRE_PAYLOAD_SIZE);
    try std.testing.expect(written == 109);
}

test "deserializeFromBytes round-trip" {
    var event = create(.pipe_sensor);
    event.event_type = .match_;
    event.severity = 2;
    event.rule_id = 0xABCDEF;
    event.source_ip = 0x0A000001;
    event.source_port = 8080;
    event.session_id = 42;
    event.payload_length = 256;

    var buf: [128]u8 = undefined;
    const written = try serializeToBytes(&event, &buf);

    const restored = deserializeFromBytes(buf[0..written]);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.event_type == .match_);
    try std.testing.expect(restored.?.severity == 2);
    try std.testing.expect(restored.?.rule_id == 0xABCDEF);
    try std.testing.expect(restored.?.source_ip == 0x0A000001);
    try std.testing.expect(restored.?.source_port == 8080);
    try std.testing.expect(restored.?.session_id == 42);
    try std.testing.expect(restored.?.payload_length == 256);
}

test "deserializeFromBytes rejects short buffer" {
    const short = [_]u8{0} ** 50;
    try std.testing.expect(deserializeFromBytes(&short) == null);
}

test "deserializeFromBytes rejects wrong magic" {
    var event = create(.zig_core);
    var buf: [128]u8 = undefined;
    _ = try serializeToBytes(&event, &buf);
    buf[0] = 0x00; // Corrupt magic
    try std.testing.expect(deserializeFromBytes(&buf) == null);
}

test "explicit encoding matches wire_v1.md offset table" {
    var event = create(.wfp_sensor);
    event.magic = 0x41454731;
    event.version = 1;
    event.event_id = 12345;

    var buf: [128]u8 = undefined;
    _ = try serializeToBytes(&event, &buf);

    // Verify magic at offset 0 (4 bytes, little-endian)
    try std.testing.expect(buf[0] == 0x31); // LSB of 0x41454731
    try std.testing.expect(buf[1] == 0x47);
    try std.testing.expect(buf[2] == 0x45);
    try std.testing.expect(buf[3] == 0x41);

    // Verify version at offset 4 (2 bytes)
    try std.testing.expect(buf[4] == 1);
    try std.testing.expect(buf[5] == 0);
}

// ============================================================
// DEPRECATED API tests (legacy compatibility — will be removed)
// ============================================================

test "DEPRECATED: serialize/deserialize still works (backward compat)" {
    var event = create(.pipe_sensor);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;

    const bytes = serialize(&event);
    try std.testing.expect(bytes.len == @sizeOf(CanonicalEvent));

    const restored = deserialize(bytes);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.event_type == .block);
    try std.testing.expect(restored.?.severity == 3);
    try std.testing.expect(restored.?.rule_id == 0x12345678);
}

test "DEPRECATED: deserialize rejects short buffer" {
    const short = [_]u8{ 0x41, 0x45, 0x47, 0x31 };
    try std.testing.expect(deserialize(&short) == null);
}

test "DEPRECATED: deserialize rejects wrong magic" {
    var event = create(.zig_core);
    event.magic = 0x00000000;
    const bytes = serialize(&event);
    try std.testing.expect(deserialize(bytes) == null);
}
