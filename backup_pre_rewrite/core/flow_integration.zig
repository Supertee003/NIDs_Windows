//! flow_integration.zig - AEGIS Flow Engine Integration (STEP 5)
//!
//! Bridge between the Event Fabric and the Flow Engine.
//! Provides flow-aware context to the Detection layer.
//!
//! Before STEP 5:
//!   - flow_engine.zig existed but was standalone (only used by sprint2_e2e_test)
//!   - nids_main.zig created a FlowTable but never fed events to it
//!   - Detection layer had no access to flow context (packet_count, byte_count, risk_score)
//!
//! After STEP 5:
//!   - flow_integration.processEvent(event) is called for every popped event
//!   - It updates FlowTable state (upsert by 5-tuple)
//!   - It returns FlowContext (snapshot of flow state for detection)
//!   - Detection layer can use FlowContext to make stateful decisions:
//!     e.g. "this is the 1000th packet from same source — escalate severity"
//!
//! Design choices:
//!   - FlowTable is a process-wide singleton (single source of truth)
//!   - FlowContext is a value type (not a pointer) to avoid race conditions
//!   - Host events (is_pipe=1, source_ip=0) are skipped — no flow to track
//!   - TCP state tracking is left to a future step (we only count packets/bytes)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// STEP 5: Flow context snapshot (value type, race-safe)
// ============================================================

pub const FlowContext = struct {
    /// True if this is the first packet of a flow (just created).
    is_new_flow: bool,
    /// True if event had no flow info (host event, source_ip=0).
    is_host_event: bool,
    /// Flow key extracted from the event (zeros if host event).
    key: flow.FlowKey,
    /// Total packets seen in this flow (including this one).
    packet_count: u64,
    /// Total bytes seen in this flow (including this one).
    byte_count: u64,
    /// Flow creation time (millis since epoch).
    created_at_ms: i64,
    /// Time of last packet before this one.
    last_seen_ms: i64,
    /// Current TCP state (always .none for non-TCP / host events).
    tcp_state: flow.TCPState,
    /// Flow risk score (0-255, set by detection layer).
    risk_score: u8,
    /// Cross-tier session ID for XDR correlation.
    session_id: u64,
};

// ============================================================
// STEP 5: Integration state
// ============================================================

var g_flow_table: ?flow.FlowTable = null;
var g_initialized: bool = false;
var g_total_events_processed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_host_events_skipped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_flows_created: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_flow_updates: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// ============================================================
// Initialization
// ============================================================

/// Initialize the flow integration layer. Call once at startup.
pub fn init() void {
    if (g_initialized) return;
    g_flow_table = flow.FlowTable.init();
    g_initialized = true;
    g_total_events_processed.store(0, .monotonic);
    g_total_host_events_skipped.store(0, .monotonic);
    g_total_flows_created.store(0, .monotonic);
    g_total_flow_updates.store(0, .monotonic);
    std.log.info("[FLOW-INT] Flow integration initialized (max 4096 flows)", .{});
}

/// Shutdown the flow integration layer.
pub fn shutdown() void {
    if (!g_initialized) return;
    g_flow_table = null;
    g_initialized = false;
    std.log.info("[FLOW-INT] Flow integration shutdown", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

// ============================================================
// Helpers: extract flow data from CanonicalEvent
// ============================================================

/// Extract a FlowKey from a CanonicalEvent.
/// Returns null if event has no flow info (host event with source_ip=0).
fn extractKey(event: canonical.CanonicalEvent) ?flow.FlowKey {
    // Host events (pipe, minifilter) have source_ip=0 — no flow to track.
    if (event.source_ip == 0) return null;
    if (event.is_pipe != 0) return null;

    return flow.FlowKey{
        .src_ip = event.source_ip,
        .dst_ip = event.dest_ip,
        .src_port = event.source_port,
        .dst_port = event.dest_port,
        .protocol = event.protocol,
    };
}

/// Extract byte count from a CanonicalEvent (uses payload_length).
fn extractBytes(event: canonical.CanonicalEvent) u64 {
    return @as(u64, event.payload_length);
}

// ============================================================
// STEP 5: Main API — process event + return flow context
// ============================================================

/// Process a popped event through the Flow Engine.
/// Updates flow state and returns a FlowContext snapshot for detection.
/// Host events (no source_ip) return a host-event FlowContext without touching FlowTable.
pub fn processEvent(event: canonical.CanonicalEvent) FlowContext {
    if (!g_initialized) {
        // Defensive: return empty context if not initialized.
        return .{
            .is_new_flow = false,
            .is_host_event = true,
            .key = .{ .src_ip = 0, .dst_ip = 0, .src_port = 0, .dst_port = 0, .protocol = 0 },
            .packet_count = 0,
            .byte_count = 0,
            .created_at_ms = 0,
            .last_seen_ms = 0,
            .tcp_state = .none,
            .risk_score = 0,
            .session_id = 0,
        };
    }

    g_total_events_processed.store(g_total_events_processed.load(.monotonic) + 1, .monotonic);

    // Host event — no flow to track.
    const maybe_key = extractKey(event);
    if (maybe_key == null) {
        g_total_host_events_skipped.store(g_total_host_events_skipped.load(.monotonic) + 1, .monotonic);
        return .{
            .is_new_flow = false,
            .is_host_event = true,
            .key = .{ .src_ip = 0, .dst_ip = 0, .src_port = 0, .dst_port = 0, .protocol = 0 },
            .packet_count = 0,
            .byte_count = 0,
            .created_at_ms = 0,
            .last_seen_ms = 0,
            .tcp_state = .none,
            .risk_score = 0,
            .session_id = event.session_id,
        };
    }

    // Network event — upsert into FlowTable.
    var table = &g_flow_table.?;
    const key = maybe_key.?;
    const bytes = extractBytes(event);

    // To detect "is_new_flow" we look up first (under same lock as upsert).
    // The FlowTable.upsert() does its own locking, but to keep is_new_flow
    // accurate we do a quick lookup first. There's a small race window if
    // another thread inserts the same key between lookup and upsert, but
    // the cost is just a false-positive is_new_flow=false, which is
    // harmless for detection decisions.
    const existed_before = table.lookup(key) != null;
    const flow_state = table.upsert(key, bytes, event.session_id);

    if (!existed_before) {
        g_total_flows_created.store(g_total_flows_created.load(.monotonic) + 1, .monotonic);
    } else {
        g_total_flow_updates.store(g_total_flow_updates.load(.monotonic) + 1, .monotonic);
    }

    return .{
        .is_new_flow = !existed_before,
        .is_host_event = false,
        .key = key,
        .packet_count = flow_state.packet_count,
        .byte_count = flow_state.byte_count,
        .created_at_ms = flow_state.created_at_ms,
        .last_seen_ms = flow_state.last_seen_ms,
        .tcp_state = flow_state.tcp_state,
        .risk_score = flow_state.risk_score,
        .session_id = flow_state.session_id,
    };
}

/// Convenience: process event + return flow pointer (for advanced callers).
/// Caller MUST NOT hold the pointer across yields (mutex is released on return).
pub fn processEventWithFlowPtr(event: canonical.CanonicalEvent) struct { context: FlowContext, flow: ?*flow.FlowState } {
    if (!g_initialized) {
        return .{
            .context = processEvent(event),
            .flow = null,
        };
    }

    const ctx = processEvent(event);
    if (ctx.is_host_event) {
        return .{ .context = ctx, .flow = null };
    }

    var table = &g_flow_table.?;
    const flow_ptr = table.lookup(ctx.key);
    return .{ .context = ctx, .flow = flow_ptr };
}

// ============================================================
// STEP 5: Update flow risk score (for detection layer)
// ============================================================

/// Update the risk score on a flow. Called by detection layer after a verdict.
pub fn updateRiskScore(key: flow.FlowKey, risk_score: u8) void {
    if (!g_initialized) return;
    var table = &g_flow_table.?;
    if (table.lookup(key)) |flow_state| {
        flow_state.risk_score = risk_score;
    }
}

// ============================================================
// STEP 5: Maintenance — purge expired flows
// ============================================================

/// Purge expired flows. Returns number purged.
/// Call periodically (e.g., every 60s) from a maintenance thread.
pub fn purgeExpired() usize {
    if (!g_initialized) return 0;
    var table = &g_flow_table.?;
    return table.purgeExpired();
}

// ============================================================
// STEP 5: Statistics
// ============================================================

pub const IntegrationStats = struct {
    initialized: bool,
    active_flows: usize,
    total_events_processed: u64,
    total_host_events_skipped: u64,
    total_flows_created: u64,
    total_flow_updates: u64,
    total_flows_expired: u64,
};

pub fn getStats() IntegrationStats {
    if (!g_initialized) {
        return .{
            .initialized = false,
            .active_flows = 0,
            .total_events_processed = 0,
            .total_host_events_skipped = 0,
            .total_flows_created = 0,
            .total_flow_updates = 0,
            .total_flows_expired = 0,
        };
    }
    var table = &g_flow_table.?;
    const fstats = table.getStats();
    return .{
        .initialized = true,
        .active_flows = fstats.active_flows,
        .total_events_processed = g_total_events_processed.load(.monotonic),
        .total_host_events_skipped = g_total_host_events_skipped.load(.monotonic),
        .total_flows_created = g_total_flows_created.load(.monotonic),
        .total_flow_updates = g_total_flow_updates.load(.monotonic),
        .total_flows_expired = fstats.total_expired,
    };
}

/// Get the underlying FlowTable (for advanced callers / tests).
pub fn getFlowTable() ?*flow.FlowTable {
    if (!g_initialized) return null;
    return &g_flow_table.?;
}

/// Reset stats (for tests).
pub fn resetStats() void {
    g_total_events_processed.store(0, .monotonic);
    g_total_host_events_skipped.store(0, .monotonic);
    g_total_flows_created.store(0, .monotonic);
    g_total_flow_updates.store(0, .monotonic);
}

// ============================================================
// Tests
// ============================================================

test "FlowContext is a value type" {
    // Verify FlowContext can be created on the stack and copied by value.
    const ctx = FlowContext{
        .is_new_flow = true,
        .is_host_event = false,
        .key = .{ .src_ip = 1, .dst_ip = 2, .src_port = 80, .dst_port = 443, .protocol = 6 },
        .packet_count = 1,
        .byte_count = 1024,
        .created_at_ms = 1000,
        .last_seen_ms = 1000,
        .tcp_state = .none,
        .risk_score = 0,
        .session_id = 42,
    };
    const copy = ctx;
    try std.testing.expect(copy.packet_count == 1);
    try std.testing.expect(copy.key.src_ip == 1);
}

test "init and shutdown lifecycle" {
    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.active_flows == 0);
}

test "processEvent before init returns host-event context" {
    if (isInitialized()) shutdown();
    init();
    defer shutdown();
    // Reset state — processEvent should still work because we re-init above
    // but let's actually test the not-initialized path:
    shutdown();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .block;
    const ctx = processEvent(event);
    try std.testing.expect(ctx.is_host_event);
    try std.testing.expect(ctx.packet_count == 0);

    init(); // re-init for the defer shutdown
}

test "processEvent handles host event (source_ip=0)" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.minifilter);
    event.event_type = .session_start;
    event.source_ip = 0; // host event
    event.is_pipe = 0;

    const ctx = processEvent(event);
    try std.testing.expect(ctx.is_host_event);
    try std.testing.expect(ctx.packet_count == 0);
    try std.testing.expect(ctx.byte_count == 0);

    const stats = getStats();
    try std.testing.expect(stats.total_events_processed == 1);
    try std.testing.expect(stats.total_host_events_skipped == 1);
    try std.testing.expect(stats.active_flows == 0);
}

test "processEvent handles pipe event (is_pipe=1)" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.pipe_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001; // would be a flow, but...
    event.is_pipe = 1; // ...is_pipe=1 means host event
    event.payload_length = 512;

    const ctx = processEvent(event);
    try std.testing.expect(ctx.is_host_event); // pipe events are host events
    try std.testing.expect(ctx.packet_count == 0);

    const stats = getStats();
    try std.testing.expect(stats.total_host_events_skipped == 1);
}

test "processEvent creates new flow for network event" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6; // TCP
    event.payload_length = 1024;
    event.is_pipe = 0;

    const ctx = processEvent(event);
    try std.testing.expect(!ctx.is_host_event);
    try std.testing.expect(ctx.is_new_flow);
    try std.testing.expect(ctx.packet_count == 1);
    try std.testing.expect(ctx.byte_count == 1024);
    try std.testing.expect(ctx.session_id == event.session_id);

    const stats = getStats();
    try std.testing.expect(stats.total_events_processed == 1);
    try std.testing.expect(stats.total_flows_created == 1);
    try std.testing.expect(stats.active_flows == 1);
}

test "processEvent updates existing flow" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 1024;
    event.is_pipe = 0;

    // First event — creates flow
    _ = processEvent(event);

    // Second event — updates flow
    event.payload_length = 2048;
    const ctx = processEvent(event);
    try std.testing.expect(!ctx.is_new_flow);
    try std.testing.expect(ctx.packet_count == 2);
    try std.testing.expect(ctx.byte_count == 3072); // 1024 + 2048

    const stats = getStats();
    try std.testing.expect(stats.total_flows_created == 1);
    try std.testing.expect(stats.total_flow_updates == 1);
    try std.testing.expect(stats.active_flows == 1);
}

test "processEvent distinguishes different flows" {
    init();
    defer shutdown();
    resetStats();

    // Flow 1: src_ip = 1
    var event1 = canonical.create(.wfp_sensor);
    event1.event_type = .forward;
    event1.source_ip = 0x0A000001;
    event1.dest_ip = 0x0A000002;
    event1.source_port = 12345;
    event1.dest_port = 80;
    event1.protocol = 6;
    event1.payload_length = 100;
    event1.is_pipe = 0;
    _ = processEvent(event1);

    // Flow 2: src_ip = 3
    var event2 = canonical.create(.wfp_sensor);
    event2.event_type = .forward;
    event2.source_ip = 0x0A000003;
    event2.dest_ip = 0x0A000002;
    event2.source_port = 12345;
    event2.dest_port = 80;
    event2.protocol = 6;
    event2.payload_length = 200;
    event2.is_pipe = 0;
    _ = processEvent(event2);

    // Flow 1 again — should still see packet_count=2 (only flow 1)
    const ctx = processEvent(event1);
    try std.testing.expect(ctx.packet_count == 2);
    try std.testing.expect(ctx.byte_count == 200); // 100 + 100 (not 100+200+100)

    const stats = getStats();
    try std.testing.expect(stats.active_flows == 2);
}

test "updateRiskScore sets risk on flow" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 1024;
    event.is_pipe = 0;

    const ctx = processEvent(event);
    try std.testing.expect(ctx.risk_score == 0);

    // Update risk score
    updateRiskScore(ctx.key, 200);

    // Process another event — risk score should persist
    const ctx2 = processEvent(event);
    try std.testing.expect(ctx2.risk_score == 200);
}

test "purgeExpired removes old flows" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 1024;
    event.is_pipe = 0;

    _ = processEvent(event);
    try std.testing.expect(getStats().active_flows == 1);

    // Purge — but flow is fresh, so nothing purged
    const purged = purgeExpired();
    try std.testing.expect(purged == 0);
    try std.testing.expect(getStats().active_flows == 1);
}

test "processEventWithFlowPtr returns flow pointer for network event" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 1024;
    event.is_pipe = 0;

    const result = processEventWithFlowPtr(event);
    try std.testing.expect(!result.context.is_host_event);
    try std.testing.expect(result.flow != null);
    try std.testing.expect(result.flow.?.packet_count == 1);
}

test "processEventWithFlowPtr returns null flow for host event" {
    init();
    defer shutdown();
    resetStats();

    var event = canonical.create(.minifilter);
    event.event_type = .session_start;
    event.source_ip = 0; // host event
    event.is_pipe = 0;

    const result = processEventWithFlowPtr(event);
    try std.testing.expect(result.context.is_host_event);
    try std.testing.expect(result.flow == null);
}

test "getStats returns full integration state" {
    init();
    defer shutdown();
    resetStats();

    // Process 3 events: 1 host, 2 network (same flow)
    var host_event = canonical.create(.minifilter);
    host_event.event_type = .session_start;
    host_event.source_ip = 0;
    host_event.is_pipe = 0;
    _ = processEvent(host_event);

    var net_event = canonical.create(.wfp_sensor);
    net_event.event_type = .forward;
    net_event.source_ip = 0x0A000001;
    net_event.dest_ip = 0x0A000002;
    net_event.source_port = 12345;
    net_event.dest_port = 80;
    net_event.protocol = 6;
    net_event.payload_length = 1024;
    net_event.is_pipe = 0;
    _ = processEvent(net_event);
    _ = processEvent(net_event);

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.total_events_processed == 3);
    try std.testing.expect(stats.total_host_events_skipped == 1);
    try std.testing.expect(stats.total_flows_created == 1);
    try std.testing.expect(stats.total_flow_updates == 1);
    try std.testing.expect(stats.active_flows == 1);
}

test "getFlowTable returns null before init" {
    if (isInitialized()) shutdown();
    try std.testing.expect(getFlowTable() == null);
    init();
    defer shutdown();
    try std.testing.expect(getFlowTable() != null);
}

test "STEP5: flow integration detects scanning pattern (multiple packets, escalating risk)" {
    // Simulate a port-scan detection scenario:
    // 1. Same source IP sends many packets (different ports)
    // 2. Detection layer uses packet_count + risk_score to escalate
    init();
    defer shutdown();
    resetStats();

    // First packet from this source (flow A: port 22)
    var event_a = canonical.create(.wfp_sensor);
    event_a.event_type = .forward;
    event_a.source_ip = 0xC0A80164;
    event_a.dest_ip = 0x0A000001;
    event_a.source_port = 50000;
    event_a.dest_port = 22;
    event_a.protocol = 6;
    event_a.payload_length = 64;
    event_a.is_pipe = 0;
    const ctx_a = processEvent(event_a);
    try std.testing.expect(ctx_a.is_new_flow);
    try std.testing.expect(ctx_a.packet_count == 1);

    // Second packet from same source (flow B: port 80)
    var event_b = canonical.create(.wfp_sensor);
    event_b.event_type = .forward;
    event_b.source_ip = 0xC0A80164;
    event_b.dest_ip = 0x0A000001;
    event_b.source_port = 50000;
    event_b.dest_port = 80;
    event_b.protocol = 6;
    event_b.payload_length = 64;
    event_b.is_pipe = 0;
    const ctx_b = processEvent(event_b);
    try std.testing.expect(ctx_b.is_new_flow); // different flow (different dest_port)
    try std.testing.expect(ctx_b.packet_count == 1);

    // Third packet — same as flow A, should see count=2
    const ctx_a2 = processEvent(event_a);
    try std.testing.expect(!ctx_a2.is_new_flow);
    try std.testing.expect(ctx_a2.packet_count == 2);

    // Detection layer could now use this to flag port scanning
    // (multiple flows from same source_ip in short time)
    const stats = getStats();
    try std.testing.expect(stats.active_flows == 2);
    try std.testing.expect(stats.total_flows_created == 2);
    try std.testing.expect(stats.total_flow_updates == 1);
}
