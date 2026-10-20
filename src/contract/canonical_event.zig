//! canonical_event.zig - AEGIS Canonical Event Model v1 (Phase 23, AEGIS-002)
//!
//! Unified event schema for all AEGIS subsystems (Zig/Python/Go/Rust/C++).
//! Every sensor, detector, correlator, and policy engine must use this model.
//!
//! Versioning: bump EVENT_VERSION when schema changes. All receivers must
//! validate version before reading fields.
//!
//! VER-NS-039 namespace note: EVENT_MAGIC/VERSION here belong to the WIRE
//! canonical event only (magic "AEG1", v1, v2 adds the IPv6 tail). They are
//! a different namespace from the INTERNAL queue event in
//! contract/event.zig (magic 0xAE615011, currently v5). The magics differ
//! on purpose so the two framings can never be confused, and the versions
//! evolve independently — 5-vs-1 is not drift. Never compare a version or
//! magic across the two modules.

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
    monotonic_ns: u64,      // Monotonic nanoseconds (was i128 ΓÇö not portable ABI)

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
    context_flags: u32,     // Bitfield: bit0=threat_intel_match,
                            // bit1=correlation_match, bit2=ipv6_truncated
                            // (v1 wire has no IPv6 fields; bit2 means the
                            // 32-bit IP identity is first-4-bytes only and
                            // must never be treated as IPv4 identity).

    // --- Reserved: v1 extension area (G2 frozen layout, see RESERVED_* below) ---
    reserved: [16]u8,       // Offset table in shared/protocol/wire_v1.md
};

// ============================================================
// G2: Frozen reserved-area layout (host/process/node identity)
// De-facto layout of hids_engine.zig formalized as contract.
// Wire size and struct size are UNCHANGED (ABI-safe, still v1).
// ============================================================

/// ContextFlags bit2 (CONTEXT_V6_TRUNCATED): set when the 32-bit IP
/// identity is first-4-bytes of IPv6 (v1 wire limitation). Consumers must
/// not treat such identity as IPv4.
pub const CONTEXT_V6_TRUNCATED: u32 = 1 << 2;

// ── ContextFlags transport-metadata lane (RB-021-NOSE-FLAGS) ──────────
// Bits 16..23 carry the raw TCP flags byte observed by the acquisition
// path; bit24 marks the lane valid. This is an additive semantic use of
// previously unused ContextFlags bits, not a wire-layout change: v1 stays
// 109 bytes and v2 stays 133. Existing allocations (RAG bits 0..3, L7
// bits 8..13) are disjoint. Absence (bit24 clear) means "no flag
// evidence", never "the observed flags byte was zero".
pub const CONTEXT_TCP_FLAGS_SHIFT: u5 = 16;
pub const CONTEXT_TCP_FLAGS_MASK: u32 = 0xFF << CONTEXT_TCP_FLAGS_SHIFT;
pub const CONTEXT_TCP_FLAGS_VALID: u32 = 1 << 24;

/// Record the raw TCP flags byte in the ContextFlags transport lane.
pub fn setTcpFlags(event: *CanonicalEvent, flags: u8) void {
    event.context_flags = (event.context_flags & ~(CONTEXT_TCP_FLAGS_MASK | CONTEXT_TCP_FLAGS_VALID)) |
        CONTEXT_TCP_FLAGS_VALID |
        (@as(u32, flags) << CONTEXT_TCP_FLAGS_SHIFT);
}

/// Return the observed TCP flags, or null when the producer supplied no
/// flag evidence. A valid zero byte is distinct from absence.
pub fn getTcpFlags(event: *const CanonicalEvent) ?u8 {
    if ((event.context_flags & CONTEXT_TCP_FLAGS_VALID) == 0) return null;
    return @truncate((event.context_flags & CONTEXT_TCP_FLAGS_MASK) >> CONTEXT_TCP_FLAGS_SHIFT);
}

/// reserved[0..4]  = process_id (u32 LE) ΓÇö host telemetry PID
/// reserved[4..8]  = parent_process_id (u32 LE)
/// reserved[8]     = process event type (HIDS ProcessEventType)
/// reserved[9]     = process integrity level
/// reserved[10]    = HIDS flag
/// reserved[11..15]= node_id (u32 LE) ΓÇö host identity for federation/cluster
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
// T2: Canonical identity accessors (Step 9 contract)
// The T2 contract requires unique/known identity fields:
//   event_id, source_id, source_type, timestamp, schema_version,
//   provenance, host identity, process identity, network identity.
// All map onto the frozen 109-byte wire ΓÇö this is the single
// source-of-truth mapping shared by Go/C++/Rust/Python bindings.
// ============================================================

/// schema_version  Γëí version field (wire offset 4, u16 LE).
pub fn getSchemaVersion(event: *const CanonicalEvent) u16 {
    return event.version;
}

/// source_type Γëí source (u8 enum). See SourceKind.classify() for the
/// canonical many-to-one mapping required by T2 (network/host/.../replay).
pub fn getSourceType(event: *const CanonicalEvent) EventSource {
    return event.source;
}

/// source_id Γëí session_id (u64). AEGIS IR-03 cross-tier correlation ID;
/// T2 requires a stable per-source ID and session_id is the frozen field
/// reserved for that role. node_id covers host identity separately.
pub fn getSourceId(event: *const CanonicalEvent) u64 {
    return event.session_id;
}

pub fn setSourceId(event: *CanonicalEvent, source_id: u64) void {
    event.session_id = source_id;
}

/// provenance Γëí (source, layer_id, is_pipe): which subsystem at which
/// pipeline layer produced the event. layer_id is the provenance layer.
pub fn getProvenance(event: *const CanonicalEvent) struct { source: EventSource, layer_id: u8, is_pipe: u8 } {
    return .{ .source = event.source, .layer_id = event.layer_id, .is_pipe = event.is_pipe };
}

/// host identity Γëí node_id (reserved[11..15], u32 LE).
pub fn getHostIdentity(event: *const CanonicalEvent) u32 {
    return getNodeId(event);
}

pub fn setHostIdentity(event: *CanonicalEvent, node_id: u32) void {
    setNodeId(event, node_id);
}

/// process identity Γëí (pid, ppid) in reserved[0..8].
pub fn getProcessIdentity(event: *const CanonicalEvent) struct { pid: u32, ppid: u32 } {
    return .{ .pid = getProcessId(event), .ppid = getParentProcessId(event) };
}

/// network identity Γëí 5-tuple (source_ip/port, dest_ip/port, protocol).
pub fn getNetworkIdentity(event: *const CanonicalEvent) struct { source_ip: u32, source_port: u16, dest_ip: u32, dest_port: u16, protocol: u8 } {
    return .{ .source_ip = event.source_ip, .source_port = event.source_port, .dest_ip = event.dest_ip, .dest_port = event.dest_port, .protocol = event.protocol };
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
    // T2 additive sources (Go Nose capture + C++ adapter framework)
    process_sensor = 13,
    file_sensor = 14,
    registry_sensor = 15,
    replay_sensor = 16,
    external = 255,
};

/// Stable lowercase name for every canonical source ordinal. Operator surfaces
/// render this instead of a bare ordinal so every tier names the same sensor
/// (the names are frozen with the ordinals in `SOURCE` in
/// brain/canonical_event.py and pinned by tests/forensics/test_forensic_source_space.py).
pub fn sourceName(source: EventSource) []const u8 {
    return switch (source) {
        .zig_core => "zig_core",
        .wfp_sensor => "wfp_sensor",
        .pipe_sensor => "pipe_sensor",
        .minifilter => "minifilter",
        .pipe_monitor => "pipe_monitor",
        .python_brain => "python_brain",
        .cpp_bridge => "cpp_bridge",
        .rust_shield => "rust_shield",
        .go_aggregator => "go_aggregator",
        .npcap_sensor => "npcap_sensor",
        .host_telemetry => "host_telemetry",
        .ml_detector => "ml_detector",
        .cluster_federation => "cluster_federation",
        .process_sensor => "process_sensor",
        .file_sensor => "file_sensor",
        .registry_sensor => "registry_sensor",
        .replay_sensor => "replay_sensor",
        .external => "external",
    };
}

test "sourceName names every canonical source" {
    try std.testing.expectEqualStrings("zig_core", sourceName(.zig_core));
    try std.testing.expectEqualStrings("npcap_sensor", sourceName(.npcap_sensor));
    try std.testing.expectEqualStrings("external", sourceName(.external));
}

/// T2: canonical source-kind classification. Maps every EventSource to one
/// of the required T2 source kinds (network/host/process/file/registry/
/// ML/federation/replay). Cross-language consumers (Go/C++/Rust/Python)
/// MUST agree on this classification.
pub const SourceKind = enum(u8) {
    network = 0,
    host = 1,
    process = 2,
    file = 3,
    registry = 4,
    ml = 5,
    federation = 6,
    replay = 7,
    core = 8,
    external = 255,

    pub fn classify(source: EventSource) SourceKind {
        return switch (source) {
            .wfp_sensor, .npcap_sensor => .network,
            .host_telemetry, .minifilter, .pipe_monitor, .pipe_sensor => .host,
            .process_sensor => .process,
            .file_sensor => .file,
            .registry_sensor => .registry,
            .ml_detector => .ml,
            .cluster_federation => .federation,
            .replay_sensor => .replay,
            .zig_core, .cpp_bridge, .go_aggregator, .python_brain, .rust_shield => .core,
            .external => .external,
        };
    }
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

// ============================================================
// Wire v2 — full IPv6 identity (T2-V6-022a, see shared/protocol/wire_v2.md)
// v1 (109B) is frozen: this section is purely additive. The in-memory
// CanonicalEvent layout stays 128 bytes; full addresses travel on the
// wire only and decode into DecodedFrame sidecars.
// ============================================================

/// Canonical event wire schema version 2 (full IPv6 tail present).
pub const EVENT_VERSION_V2: u16 = 2;
/// v6 tail: source bytes [4..16] ++ dest bytes [4..16] (raw network order).
pub const V6_TAIL_SIZE: usize = 24;
/// v2 payload = v1 109 bytes ++ 24-byte tail.
pub const WIRE_V2_PAYLOAD_SIZE: usize = WIRE_PAYLOAD_SIZE + V6_TAIL_SIZE;

/// Version-agnostic decode product. Full addresses are present if and only
/// if the frame was v2; v1 frames decode with null sidecars (truncated
/// identity + CONTEXT_V6_TRUNCATED, exactly as before).
pub const DecodedFrame = struct {
    event: CanonicalEvent,
    src_ipv6: ?[16]u8,
    dst_ipv6: ?[16]u8,
};

/// Serialize a v2 frame: frozen v1 bytes with version=2 plus the v6 tail.
/// Requires CONTEXT_V6_TRUNCATED (v2 is only for v6 identity) and
/// first-4-byte consistency between the event fields and the full
/// addresses (Go derives the u32 as BigEndian.Uint32(addr[:4])).
pub fn serializeV2(event: *const CanonicalEvent, src6: [16]u8, dst6: [16]u8, buf: []u8) !usize {
    if ((event.context_flags & CONTEXT_V6_TRUNCATED) == 0) return error.V6FlagRequired;
    if (std.mem.readInt(u32, src6[0..4], .big) != event.source_ip) return error.IpMismatch;
    if (std.mem.readInt(u32, dst6[0..4], .big) != event.dest_ip) return error.IpMismatch;
    if (buf.len < WIRE_V2_PAYLOAD_SIZE) return error.BufferTooSmall;
    const n = try serializeToBytes(event, buf);
    std.debug.assert(n == WIRE_PAYLOAD_SIZE);
    // Patch the version field (event itself stays v1-layout, version 1).
    std.mem.writeInt(u16, buf[4..][0..2], EVENT_VERSION_V2, .little);
    @memcpy(buf[WIRE_PAYLOAD_SIZE..][0..12], src6[4..16]);
    @memcpy(buf[WIRE_PAYLOAD_SIZE + 12 ..][0..12], dst6[4..16]);
    return WIRE_V2_PAYLOAD_SIZE;
}

/// Dispatch on the version field: v1 → frozen path (sidecars null),
/// v2 → full-address reconstruction, anything else → null.
/// v2 frames must carry the full tail; version==2 with 109 bytes is
/// malformed (fail closed, never silently truncate).
pub fn deserializeDispatch(bytes: []const u8) ?DecodedFrame {
    if (bytes.len < WIRE_PAYLOAD_SIZE) return null;
    const ver = std.mem.readInt(u16, bytes[4..][0..2], .little);
    if (ver == EVENT_VERSION) {
        const event = deserializeFromBytes(bytes) orelse return null;
        return .{ .event = event, .src_ipv6 = null, .dst_ipv6 = null };
    }
    if (ver != EVENT_VERSION_V2) return null;
    if (bytes.len < WIRE_V2_PAYLOAD_SIZE) return null;
    const event = decodeFields(bytes) orelse return null;
    if (event.magic != EVENT_MAGIC) return null;
    if (event.struct_size != EVENT_SCHEMA_SIZE) return null;
    var src6: [16]u8 = undefined;
    var dst6: [16]u8 = undefined;
    // First-4 in network order: the u32 fields hold BigEndian.Uint32(addr[:4])
    // (Go derivation), while the wire stores them little-endian. Write back
    // big-endian so the sidecar is canonical network byte order, matching
    // the tail bytes that follow on the wire verbatim.
    std.mem.writeInt(u32, src6[0..4], event.source_ip, .big);
    @memcpy(src6[4..16], bytes[WIRE_PAYLOAD_SIZE..][0..12]);
    std.mem.writeInt(u32, dst6[0..4], event.dest_ip, .big);
    @memcpy(dst6[4..16], bytes[WIRE_PAYLOAD_SIZE + 12 ..][0..12]);
    return .{ .event = event, .src_ipv6 = src6, .dst_ipv6 = dst6 };
}

/// Validate a decoded frame (the wire-dispatch product) for the queue gate.
///
/// Shape contract, enforced fail-closed (both directions are codec
/// invariants, not conventions):
///   - v1 frames decode to version==EVENT_VERSION with null sidecars;
///   - v2 frames decode to version==EVENT_VERSION_V2 with BOTH sidecars
///     (the 24-byte tail always carries both truncated addresses).
/// A mixed shape cannot be produced by the frozen codecs; rejecting it
/// keeps a future codec bug loud instead of silently widening the ABI.
///
/// V6-QUEUE-DROP (found by NIC-001): the queue gate used the strict event
/// validator, which pins version==EVENT_VERSION and therefore rejected
/// every wire-decoded v2 frame - all IPv6 acquisition - as an untracked
/// frames_dropped increment (live: 87.7% of frames read, silent).
pub fn validateDecodedFrame(frame: *const DecodedFrame) bool {
    if (frame.event.magic != EVENT_MAGIC) return false;
    if (frame.event.struct_size != EVENT_SCHEMA_SIZE) return false;
    const has_src = frame.src_ipv6 != null;
    const has_dst = frame.dst_ipv6 != null;
    if (has_src != has_dst) return false; // sidecars are all-or-nothing
    if (has_src) return frame.event.version == EVENT_VERSION_V2;
    return frame.event.version == EVENT_VERSION;
}

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
/// Frozen v1 path: 109-byte frames with version 1 (plus in-memory size).
pub fn deserializeFromBytes(bytes: []const u8) ?CanonicalEvent {
    if (bytes.len < WIRE_PAYLOAD_SIZE) return null;
    const event = decodeFields(bytes) orelse return null;
    if (!validate(&event)) return null;
    return event;
}

/// Shared field decoder (v1 prefix of both wire versions): enum gates +
/// field reads, no version/size validation (callers validate per version).
fn decodeFields(bytes: []const u8) ?CanonicalEvent {
    // Validate integer enum representations before @enumFromInt.  A wire
    // frame is untrusted input; converting an unknown ordinal directly can
    // trap in safety builds or create an invalid semantic event.
    const source_raw = bytes[32];
    const event_type_raw = std.mem.readInt(u32, bytes[57..][0..4], .little);
    const policy_action_raw = bytes[86];
    const confidence_raw = bytes[93 + RES_OFF_CONFIDENCE];
    const source_valid = (source_raw <= 16) or source_raw == 255;
    const event_type_valid = event_type_raw <= 9 or event_type_raw == 0xFFFFFFFF;
    const policy_action_valid = policy_action_raw <= 5;
    if (!source_valid or !event_type_valid or !policy_action_valid or confidence_raw > 100) return null;

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

    return event;
}

// CODEC-CLEAN-067: the memcpy codec is gone. Wire transport uses only
// serializeToBytes/deserializeFromBytes (109 bytes, explicit encoding);
// in-memory layout never crosses a boundary, so no compatibility shim
// remains to drift from the frozen wire format.

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

test "serializeToBytes/deserializeFromBytes round-trip" {
    // CODEC-CLEAN-067: migrated from the memcpy codec (removed). The wire
    // codec is the only framing; in-memory layout never crosses a boundary.
    var event = create(.pipe_sensor);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0x12345678;

    var buf: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    const n = try serializeToBytes(&event, &buf);
    try std.testing.expect(n == WIRE_PAYLOAD_SIZE);

    const restored = deserializeFromBytes(buf[0..n]);
    try std.testing.expect(restored != null);
    try std.testing.expect(restored.?.event_type == .block);
    try std.testing.expect(restored.?.severity == 3);
    try std.testing.expect(restored.?.rule_id == 0x12345678);
}

test "deserializeFromBytes rejects short buffer" {
    const short = [_]u8{ 0x41, 0x45, 0x47, 0x31 };
    try std.testing.expect(deserializeFromBytes(&short) == null);
}

test "deserializeFromBytes rejects unknown enum ordinals" {
    var event = create(.npcap_sensor);
    var bytes: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeToBytes(&event, &bytes);

    bytes[32] = 17; // no EventSource value between registry and external
    try std.testing.expect(deserializeFromBytes(&bytes) == null);

    _ = try serializeToBytes(&event, &bytes);
    std.mem.writeInt(u32, bytes[57..][0..4], 10, .little); // no EventType 10
    try std.testing.expect(deserializeFromBytes(&bytes) == null);

    _ = try serializeToBytes(&event, &bytes);
    bytes[86] = 6; // no PolicyAction value above log_only
    try std.testing.expect(deserializeFromBytes(&bytes) == null);
}

test "deserializeFromBytes rejects confidence above 100" {
    var event = create(.npcap_sensor);
    var bytes: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeToBytes(&event, &bytes);
    bytes[93 + RES_OFF_CONFIDENCE] = 101;
    try std.testing.expect(deserializeFromBytes(&bytes) == null);
}

test "deserializeFromBytes rejects wrong magic" {
    var event = create(.zig_core);
    event.magic = 0x00000000;
    var buf: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeToBytes(&event, &buf);
    try std.testing.expect(deserializeFromBytes(&buf) == null);
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

// ============================================================
// T2 (Step 9): Canonical identity contract tests
// ============================================================

test "T2: new EventSource values are additive and stable" {
    try std.testing.expect(@intFromEnum(EventSource.process_sensor) == 13);
    try std.testing.expect(@intFromEnum(EventSource.file_sensor) == 14);
    try std.testing.expect(@intFromEnum(EventSource.registry_sensor) == 15);
    try std.testing.expect(@intFromEnum(EventSource.replay_sensor) == 16);
    try std.testing.expect(@intFromEnum(EventSource.external) == 255);
}

test "T2: SourceKind.classify covers all required T2 kinds" {
    try std.testing.expect(SourceKind.classify(.npcap_sensor) == .network);
    try std.testing.expect(SourceKind.classify(.wfp_sensor) == .network);
    try std.testing.expect(SourceKind.classify(.host_telemetry) == .host);
    try std.testing.expect(SourceKind.classify(.process_sensor) == .process);
    try std.testing.expect(SourceKind.classify(.file_sensor) == .file);
    try std.testing.expect(SourceKind.classify(.registry_sensor) == .registry);
    try std.testing.expect(SourceKind.classify(.ml_detector) == .ml);
    try std.testing.expect(SourceKind.classify(.cluster_federation) == .federation);
    try std.testing.expect(SourceKind.classify(.replay_sensor) == .replay);
    try std.testing.expect(SourceKind.classify(.zig_core) == .core);
    try std.testing.expect(SourceKind.classify(.external) == .external);
}

test "T2: source classification round-trips through wire bytes" {
    var event = create(.process_sensor);
    setProcessIdentity(&event, 4242, 800);
    setHostIdentity(&event, 777);
    setSourceId(&event, 99);

    var buf: [128]u8 = undefined;
    const written = try serializeToBytes(&event, &buf);
    const restored = deserializeFromBytes(buf[0..written]).?;

    try std.testing.expect(getSourceType(&restored) == .process_sensor);
    try std.testing.expect(SourceKind.classify(getSourceType(&restored)) == .process);
    try std.testing.expect(getProcessIdentity(&restored).pid == 4242);
    try std.testing.expect(getProcessIdentity(&restored).ppid == 800);
    try std.testing.expect(getHostIdentity(&restored) == 777);
    try std.testing.expect(getSourceId(&restored) == 99);
}

test "T2: network identity is the frozen 5-tuple" {
    var event = create(.npcap_sensor);
    event.source_ip = 0xC0A80164;
    event.source_port = 49152;
    event.dest_ip = 0xAC1F0A0A;
    event.dest_port = 443;
    event.protocol = 6;

    const nid = getNetworkIdentity(&event);
    try std.testing.expect(nid.source_ip == 0xC0A80164);
    try std.testing.expect(nid.source_port == 49152);
    try std.testing.expect(nid.dest_ip == 0xAC1F0A0A);
    try std.testing.expect(nid.dest_port == 443);
    try std.testing.expect(nid.protocol == 6);
}

test "T2: provenance and schema version accessors" {
    var event = create(.cpp_bridge);
    event.layer_id = 1;
    event.is_pipe = 0;
    try std.testing.expect(getSchemaVersion(&event) == EVENT_VERSION);
    const p = getProvenance(&event);
    try std.testing.expect(p.source == .cpp_bridge);
    try std.testing.expect(p.layer_id == 1);
    try std.testing.expect(p.is_pipe == 0);
}

// T2: golden-vector compatibility test. This byte sequence is the frozen
// wire encoding of the event built below. Go/C++/Rust/Python bindings that
// emit CanonicalEvents MUST reproduce these bytes byte-for-byte. If a
// cross-language binding disagrees, this test is the arbiter (see
// docs/contracts/canonical-event-v1.md).
test "T2: golden-vector wire output matches cross-language contract" {
    var event = create(.npcap_sensor);
    event.event_id = 0x1122334455667788;
    event.timestamp_ms = 0xAABBCCDDEEFF0011;
    event.monotonic_ns = 0x9988776655443322;
    event.source_ip = 0xC0A80164;
    event.source_port = 49152;
    event.dest_ip = 0xAC1F0A0A;
    event.dest_port = 443;
    event.session_id = 0xDEADBEEFCAFEBABE;
    event.protocol = 6;
    event.direction = 0;
    event.layer_id = 0;
    event.is_pipe = 0;
    event.event_type = .match_;
    event.severity = 2;
    event.rule_id = 0x01020304;
    event.ruleset_version = 7;
    event.payload_length = 1500;
    event.payload_hash = 0x0BADF00DBEEFDEAD;
    event.policy_action = .alert;
    event.enforcement_status = 1;
    event.defcon_impact = 4;
    event.context_flags = 0x00000003;
    setProcessIdentity(&event, 4242, 800);
    setNodeId(&event, 0x00007B00);
    setConfidence(&event, 95);

    const golden = [_]u8{
        0x31, 0x47, 0x45, 0x41, 0x01, 0x00, 0x80, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x09, 0x64, 0x01, 0xA8, 0xC0, 0x00, 0xC0, 0x0A,
        0x0A, 0x1F, 0xAC, 0xBB, 0x01, 0xBE, 0xBA, 0xFE,
        0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x06, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x03,
        0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xDC, 0x05, 0x00, 0x00, 0xAD, 0xDE,
        0xEF, 0xBE, 0x0D, 0xF0, 0xAD, 0x0B, 0x01, 0x01,
        0x04, 0x03, 0x00, 0x00, 0x00, 0x92, 0x10, 0x00,
        0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x7B, 0x00, 0x00, 0x5F,
    };
    try std.testing.expectEqual(golden.len, WIRE_PAYLOAD_SIZE); // 109

    var buf: [128]u8 = undefined;
    const written = try serializeToBytes(&event, &buf);
    try std.testing.expect(written == golden.len);
    try std.testing.expectEqualSlices(u8, &golden, buf[0..written]);
}

test "T2: golden vector deserializes to canonical identity fields" {
    const golden = [_]u8{
        0x31, 0x47, 0x45, 0x41, 0x01, 0x00, 0x80, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x09, 0x64, 0x01, 0xA8, 0xC0, 0x00, 0xC0, 0x0A,
        0x0A, 0x1F, 0xAC, 0xBB, 0x01, 0xBE, 0xBA, 0xFE,
        0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x06, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x03,
        0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xDC, 0x05, 0x00, 0x00, 0xAD, 0xDE,
        0xEF, 0xBE, 0x0D, 0xF0, 0xAD, 0x0B, 0x01, 0x01,
        0x04, 0x03, 0x00, 0x00, 0x00, 0x92, 0x10, 0x00,
        0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x7B, 0x00, 0x00, 0x5F,
    };

    const restored = deserializeFromBytes(&golden).?;
    try std.testing.expect(SourceKind.classify(getSourceType(&restored)) == .network);
    try std.testing.expect(getNetworkIdentity(&restored).source_ip == 0xC0A80164);
    try std.testing.expect(getProcessIdentity(&restored).pid == 4242);
    try std.testing.expect(getProcessIdentity(&restored).ppid == 800);
    try std.testing.expect(getHostIdentity(&restored) == 0x00007B00);
    try std.testing.expect(getConfidence(&restored) == 95);
    try std.testing.expect(restored.payload_length == 1500);
    try std.testing.expect(restored.rule_id == 0x01020304);
    try std.testing.expect(restored.event_type == .match_);
}

// ============================================================
// Wire v2 tests (T2-V6-022a)
// ============================================================

fn v6ProbeEvent() CanonicalEvent {
    var ev = create(.zig_core);
    // 2001:0db8::1 / 2001:0db8::2 — first-4-bytes identity + truncated flag.
    ev.source_ip = 0x20010DB8;
    ev.dest_ip = 0x20010DB8;
    ev.context_flags = CONTEXT_V6_TRUNCATED;
    return ev;
}

fn v6ProbeAddrs() struct { src: [16]u8, dst: [16]u8 } {
    return .{
        .src = .{ 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .dst = .{ 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    };
}

test "v2 round-trip preserves full IPv6 identity and bit2" {
    var ev = v6ProbeEvent();
    const addrs = v6ProbeAddrs();
    var buf: [WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    const n = try serializeV2(&ev, addrs.src, addrs.dst, &buf);
    try std.testing.expectEqual(WIRE_V2_PAYLOAD_SIZE, n);
    // Version field bumped; v1 prefix intact.
    try std.testing.expectEqual(EVENT_VERSION_V2, std.mem.readInt(u16, buf[4..][0..2], .little));
    try std.testing.expectEqual(ev.source_ip, std.mem.readInt(u32, buf[33..][0..4], .little));

    const frame = deserializeDispatch(&buf).?;
    try std.testing.expectEqual(EVENT_VERSION_V2, frame.event.version);
    try std.testing.expect((frame.event.context_flags & CONTEXT_V6_TRUNCATED) != 0);
    try std.testing.expectEqualSlices(u8, &addrs.src, &frame.src_ipv6.?);
    try std.testing.expectEqualSlices(u8, &addrs.dst, &frame.dst_ipv6.?);
}

test "dispatch on v1 frames yields null sidecars (frozen behavior)" {
    var ev = v6ProbeEvent();
    var buf: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeToBytes(&ev, &buf);
    const frame = deserializeDispatch(&buf).?;
    try std.testing.expectEqual(EVENT_VERSION, frame.event.version);
    try std.testing.expect(frame.src_ipv6 == null);
    try std.testing.expect(frame.dst_ipv6 == null);
}

test "dispatch rejects unknown versions and truncated v2" {
    var ev = v6ProbeEvent();
    const addrs = v6ProbeAddrs();
    var buf: [WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeV2(&ev, addrs.src, addrs.dst, &buf);
    // Unknown version.
    buf[4] = 9;
    buf[5] = 0;
    try std.testing.expect(deserializeDispatch(&buf) == null);
    // Version 2 with only 109 bytes is malformed, never truncated silently.
    var short: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(&short, buf[0..WIRE_PAYLOAD_SIZE]);
    try std.testing.expect(deserializeDispatch(&short) == null);
    // Short buffer.
    try std.testing.expect(deserializeDispatch(buf[0..10]) == null);
}

test "serializeV2 enforces flag and first-4 consistency" {
    var ev = create(.zig_core);
    const addrs = v6ProbeAddrs();
    var buf: [WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    // No truncated flag → refused (v2 is v6-only).
    try std.testing.expectError(error.V6FlagRequired, serializeV2(&ev, addrs.src, addrs.dst, &buf));
    ev.context_flags = CONTEXT_V6_TRUNCATED;
    // Flag set but fields hold other values → refused.
    try std.testing.expectError(error.IpMismatch, serializeV2(&ev, addrs.src, addrs.dst, &buf));
    // Buffer too small.
    ev.source_ip = 0x20010DB8;
    ev.dest_ip = 0x20010DB8;
    var tiny: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, serializeV2(&ev, addrs.src, addrs.dst, &tiny));
}

test "v2 shared vector 006 encodes byte-identical across languages" {
    // Field values frozen by tests/contracts/event_vectors/
    // generate_test_vectors.py (event_v2_006.bin, 133 bytes). Go
    // SerializeV2 and Python encode_event_v2 pin the same bytes.
    var ev = CanonicalEvent{
        .magic = EVENT_MAGIC,
        .version = EVENT_VERSION,
        .struct_size = EVENT_SCHEMA_SIZE,
        .event_id = 6006,
        .timestamp_ms = 1700000006000,
        .monotonic_ns = 6000000000,
        .source = .npcap_sensor,
        .source_ip = 0x20010DB8,
        .source_port = 49152,
        .dest_ip = 0x20010DB8,
        .dest_port = 443,
        .session_id = 6060,
        .protocol = 6,
        .direction = 0,
        .layer_id = 0,
        .is_pipe = 0,
        .event_type = .forward,
        .severity = 1,
        .rule_id = 0,
        .ruleset_version = 3,
        .payload_length = 1500,
        .payload_hash = 0,
        .policy_action = .allow,
        .enforcement_status = 0,
        .defcon_impact = 5,
        .context_flags = CONTEXT_V6_TRUNCATED,
        .reserved = [_]u8{0} ** 16,
    };
    const addrs = v6ProbeAddrs();
    var buf: [WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    const n = try serializeV2(&ev, addrs.src, addrs.dst, &buf);
    try std.testing.expectEqual(WIRE_V2_PAYLOAD_SIZE, n);
    const golden: [WIRE_V2_PAYLOAD_SIZE]u8 = .{
        0x31, 0x47, 0x45, 0x41, 0x02, 0x00, 0x80, 0x00,
        0x76, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x70, 0x7F, 0xE5, 0xCF, 0x8B, 0x01, 0x00, 0x00,
        0x00, 0xBC, 0xA0, 0x65, 0x01, 0x00, 0x00, 0x00,
        0x09, 0xB8, 0x0D, 0x01, 0x20, 0x00, 0xC0, 0xB8,
        0x0D, 0x01, 0x20, 0xBB, 0x01, 0xAC, 0x17, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xDC, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02,
    };
    try std.testing.expectEqualSlices(u8, &golden, &buf);
    // And it decodes back to full identity.
    const frame = deserializeDispatch(&buf).?;
    try std.testing.expectEqualSlices(u8, &addrs.src, &frame.src_ipv6.?);
    try std.testing.expectEqualSlices(u8, &addrs.dst, &frame.dst_ipv6.?);
}

test "over-length v1 frame decodes as v1 (version authoritative)" {
    // Hardening parity with Go/Python/C++: version 1 with trailing bytes
    // decodes on the frozen v1 path (first 109 bytes, tail ignored).
    var ev = v6ProbeEvent();
    var buf: [WIRE_PAYLOAD_SIZE]u8 = undefined;
    _ = try serializeToBytes(&ev, &buf);
    var long: [WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(long[0..WIRE_PAYLOAD_SIZE], &buf);
    for (long[WIRE_PAYLOAD_SIZE..], 0..) |*b, i| b.* = @intCast(i);
    const frame = deserializeDispatch(&long).?;
    try std.testing.expectEqual(EVENT_VERSION, frame.event.version);
    try std.testing.expect(frame.src_ipv6 == null);
    try std.testing.expect(frame.dst_ipv6 == null);
    try std.testing.expectEqual(ev.source_ip, frame.event.source_ip);
}

test "TCP flags transport lane is valid, exact, and absence-distinct" {
    // RB-021-NOSE-FLAGS: the lane is additive ContextFlags metadata, not a
    // wire field. Absence must stay distinguishable from an observed 0.
    var ev = create(.npcap_sensor);
    try std.testing.expect(getTcpFlags(&ev) == null);

    setTcpFlags(&ev, 0x02); // SYN
    try std.testing.expectEqual(@as(?u8, 0x02), getTcpFlags(&ev));
    try std.testing.expect((ev.context_flags & CONTEXT_TCP_FLAGS_VALID) != 0);

    setTcpFlags(&ev, 0x00); // observed zero flags, still valid evidence
    try std.testing.expectEqual(@as(?u8, 0x00), getTcpFlags(&ev));

    setTcpFlags(&ev, 0x29); // FIN|PSH|URG (R9007)
    try std.testing.expectEqual(@as(?u8, 0x29), getTcpFlags(&ev));

    // Replacing the lane must not disturb neighboring allocations.
    ev.context_flags |= CONTEXT_V6_TRUNCATED;
    setTcpFlags(&ev, 0x12); // SYN|ACK
    try std.testing.expectEqual(@as(?u8, 0x12), getTcpFlags(&ev));
    try std.testing.expect((ev.context_flags & CONTEXT_V6_TRUNCATED) != 0);
}
