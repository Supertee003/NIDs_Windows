//! canonical_event.zig - AEGIS Canonical Event Model v1 (Phase 23, AEGIS-002)
//!
//! Unified event schema for all AEGIS subsystems (Zig/Python/Go/Rust/C++).
//! Every sensor, detector, correlator, and policy engine must use this model.
//!
//! Versioning: bump EVENT_VERSION when schema changes. All receivers must
//! validate version before reading fields.

const std = @import("std");

// ============================================================
// Event Schema Version (AEGIS-002)
// ============================================================

pub const EVENT_MAGIC: u32 = 0x41454731; // "AEG1" - Canonical Event v1
pub const EVENT_VERSION: u16 = 1;
pub const EVENT_SCHEMA_SIZE: u16 = @sizeOf(CanonicalEvent);

// ============================================================
// Canonical Event Model v1
// ============================================================
// This is the single source of truth for event structure.
// All languages must implement the same layout:
//   - Zig:   extern struct (natural alignment)
//   - C++:   #pragma pack(push, 1) struct
//   - Rust:  #[repr(C, packed)]
//   - Go:    struct with same field order
//   - Python: dataclass with same field names

pub const CanonicalEvent = extern struct {
    // --- Header (B-05 ABI safety) ---
    magic: u32,             // 0x41454731 ("AEG1")
    version: u16,           // 1
    struct_size: u16,       // sizeof(CanonicalEvent) for forward compat
    event_id: u64,          // Unique ID (atomic counter)

    // --- Timestamps (IR-04 dual-clock) ---
    timestamp_ms: i64,      // Wall-clock epoch milliseconds
    monotonic_ns: i128,     // Monotonic nanoseconds (in-process ordering)

    // --- Source Identification ---
    source: EventSource,   // Which subsystem produced this event
    source_ip: u32,        // Network byte order (0 = N/A for host events)
    source_port: u16,
    dest_ip: u32,
    dest_port: u16,
    session_id: u64,        // IR-03: Cross-tier correlation ID

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

/// Validate that a CanonicalEvent has correct magic + version + size.
/// Returns false if ABI mismatch detected.
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

/// Generate next unique event ID.
pub fn nextEventId() u64 {
    return g_event_id_counter.fetchAdd(1, .acq_rel) + 1;
}

// ============================================================
// Event Creation Helper
// ============================================================

/// Create a new CanonicalEvent with current timestamps and unique ID.
/// Caller fills in detection-specific fields after creation.
pub fn create(source: EventSource) CanonicalEvent {
    return .{
        .magic = EVENT_MAGIC,
        .version = EVENT_VERSION,
        .struct_size = EVENT_SCHEMA_SIZE,
        .event_id = nextEventId(),
        .timestamp_ms = std.time.milliTimestamp(),
        .monotonic_ns = std.time.nanoTimestamp(),
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
// Serialization (for IPC/Wire transport, AEGIS-003)
// ============================================================

/// Serialize CanonicalEvent to bytes (for named pipe / UDP / shared memory).
/// Returns the byte slice pointing into the event struct.
pub fn serialize(event: *const CanonicalEvent) []const u8 {
    const ptr: [*]const u8 = @ptrCast(event);
    return ptr[0..@sizeOf(CanonicalEvent)];
}

/// Deserialize bytes into CanonicalEvent.
/// Returns null if validation fails (wrong magic/version).
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

test "serialize/deserialize round-trip" {
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

test "deserialize rejects short buffer" {
    const short = [_]u8{ 0x41, 0x45, 0x47, 0x31 };
    try std.testing.expect(deserialize(&short) == null);
}

test "deserialize rejects wrong magic" {
    var event = create(.zig_core);
    event.magic = 0x00000000;
    const bytes = serialize(&event);
    try std.testing.expect(deserialize(bytes) == null);
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
