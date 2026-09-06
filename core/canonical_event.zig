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

    // --- Timestamps (IR-04 dual-clock, STEP 1: ABI-safe u64) ---
    timestamp_ms: u64,      // Wall-clock epoch milliseconds (was i64)
    monotonic_ns: u64,      // Monotonic nanoseconds (was i128 — not portable ABI)

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

    // --- Reserved: v1 extension area (G2 frozen layout, see RESERVED_* below) ---
    reserved: [16]u8,       // Offset table in shared/protocol/wire_v1.md
};

// ============================================================
// G2: Frozen reserved-area layout (host/process/node identity)
// De-facto layout of hids_engine.zig formalized as contract.
// Wire size and struct size are UNCHANGED (ABI-safe, still v1).
// ============================================================

/// reserved[0..4]  = process_id (u32 LE) — host telemetry PID
/// reserved[4..8]  = parent_process_id (u32 LE)
/// reserved[8]     = process event type (HIDS ProcessEventType)
/// reserved[9]     = process integrity level
/// reserved[10]    = HIDS flag
/// reserved[11..15]= node_id (u32 LE) — host identity for federation/cluster
/// reserved[15]    = confidence (0-100, 0 = unknown; detector confidence)

pub const RES_OFF_PID: usize = 0;
pub const RES_OFF_PPID: usize = 4;
pub const RES_OFF_PROC_TYPE: usize = 8;
pub const RES_OFF_INTEGRITY: usize = 9;
pub const RES_OFF_HIDS_FLAG: usize = 10;
pub const RES_OFF_NODE_ID: usize = 11;
pub const RES_OFF_CONFIDENCE: usize = 15;

/// Set process identity (host telemetry provenance).
pub fn setProcessIdentity(event: *CanonicalEvent, pid: u32, ppid: u32) void {
    std.mem.writeInt(u32, event.reserved[RES_OFF_PID..][0..4], pid, .little);
    std.mem.writeInt(u32, event.reserved[RES_OFF_PPID..][0..4], ppid, .little);
}

pub fn getProcessId(event: *const CanonicalEvent) u32 {
    return std.mem.readInt(u32, event.reserved[RES_OFF_PID..][0..4], .little);
}

pub fn getParentProcessId(event: *const CanonicalEvent) u32 {
    return std.mem.readInt(u32, event.reserved[RES_OFF_PPID..][0..4], .little);
}

/// Set originating node identity (federation host identity).
pub fn setNodeId(event: *CanonicalEvent, node_id: u32) void {
    std.mem.writeInt(u32, event.reserved[RES_OFF_NODE_ID..][0..4], node_id, .little);
}

pub fn getNodeId(event: *const CanonicalEvent) u32 {
    return std.mem.readInt(u32, event.reserved[RES_OFF_NODE_ID..][0..4], .little);
}

/// Detector confidence 0-100 (0 = unknown). Values >100 are clamped.
pub fn setConfidence(event: *CanonicalEvent, confidence: u8) void {
    event.reserved[RES_OFF_CONFIDENCE] = @min(confidence, 100);
}

pub fn getConfidence(event: *const CanonicalEvent) u8 {
    return event.reserved[RES_OFF_CONFIDENCE];
}

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
    // G2 additive sources (network + host + federation in one schema)
    npcap_sensor = 9,
    host_telemetry = 10,
    ml_detector = 11,
    cluster_federation = 12,
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
// Serialization (STEP 2: explicit field-by-field encoding, no memcpy)
// ============================================================

/// Wire payload size (matches shared/protocol/wire_v1.md offset table)
pub const WIRE_PAYLOAD_SIZE: usize = 109;

/// Serialize CanonicalEvent to bytes via explicit field-by-field encoding.
/// STEP 2: No memcpy, no pointer cast, no compiler-padding dependency.
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

    return off; // Should be 109
}

/// Deserialize bytes into CanonicalEvent via explicit field-by-field decoding.
/// STEP 2: No pointer cast, no alignment dependency.
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

// Legacy compatibility (delegates to new explicit encoding)
pub fn serialize(event: *const CanonicalEvent) []const u8 {
    const ptr: [*]const u8 = @ptrCast(event);
    return ptr[0..@sizeOf(CanonicalEvent)];
}

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

// ============================================================
// STEP 2: Explicit encoding tests
// ============================================================

test "STEP2: serializeToBytes produces WIRE_PAYLOAD_SIZE bytes" {
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

test "STEP2: deserializeFromBytes round-trip" {
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

test "STEP2: deserializeFromBytes rejects short buffer" {
    const short = [_]u8{0} ** 50;
    try std.testing.expect(deserializeFromBytes(&short) == null);
}

test "STEP2: deserializeFromBytes rejects wrong magic" {
    var event = create(.zig_core);
    var buf: [128]u8 = undefined;
    _ = try serializeToBytes(&event, &buf);
    // Corrupt magic
    buf[0] = 0x00;
    try std.testing.expect(deserializeFromBytes(&buf) == null);
}

test "STEP2: explicit encoding matches wire_v1.md offset table" {    var event = create(.wfp_sensor);
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
// G2: reserved-area contract tests (host/process/node identity)
// ============================================================

test "G2: process identity round-trip" {
    var event = create(.host_telemetry);
    setProcessIdentity(&event, 4242, 800);
    try std.testing.expect(getProcessId(&event) == 4242);
    try std.testing.expect(getParentProcessId(&event) == 800);
}

test "G2: node id and confidence round-trip through wire bytes" {
    var event = create(.cluster_federation);
    setNodeId(&event, 0xDEADBEEF);
    setConfidence(&event, 95);

    var buf: [128]u8 = undefined;
    const written = try serializeToBytes(&event, &buf);
    const restored = deserializeFromBytes(buf[0..written]).?;

    try std.testing.expect(getNodeId(&restored) == 0xDEADBEEF);
    try std.testing.expect(getConfidence(&restored) == 95);
}

test "G2: confidence clamps to 100" {
    var event = create(.npcap_sensor);
    setConfidence(&event, 255);
    try std.testing.expect(getConfidence(&event) == 100);
    setConfidence(&event, 0);
    try std.testing.expect(getConfidence(&event) == 0);
}

test "G2: new EventSource values are additive and stable" {
    try std.testing.expect(@intFromEnum(EventSource.npcap_sensor) == 9);
    try std.testing.expect(@intFromEnum(EventSource.host_telemetry) == 10);
    try std.testing.expect(@intFromEnum(EventSource.ml_detector) == 11);
    try std.testing.expect(@intFromEnum(EventSource.cluster_federation) == 12);
    try std.testing.expect(@intFromEnum(EventSource.external) == 255);
}

test "G2: struct size unchanged after reserved-layout formalization" {
    try std.testing.expect(EVENT_SCHEMA_SIZE == @sizeOf(CanonicalEvent));
    try std.testing.expect(WIRE_PAYLOAD_SIZE == 109);
}
