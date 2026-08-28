//! correlation_integration.zig - AEGIS Correlation Layer (STEP 7)
//!
//! Wires the XDR Correlator with the Detection Integration layer.
//! Before STEP 7, the XDR correlator existed but was never fed events —
//! it was created in nids_main.zig as dead code (`_ = &xdr_corr`).
//!
//! After STEP 7, every DetectionContext produced by detection_int is also
//! submitted to the XDR correlator, which links events by session_id into
//! cross-tier incidents (network attack + host process + file write = one
//! incident with full timeline).
//!
//! Pipeline (full Golden Path):
//!   Sensor -> nose_int.submit (STEP 4)
//!     -> fabric.popEvent (STEP 3)
//!       -> flow_int.processEvent (STEP 5)
//!         -> detection_int.processEvent (STEP 6)
//!           -> correlation_int.submitDetectionContext (STEP 7)
//!             -> XDR Incident (links network + host events)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const xdr = @import("xdr_correlator.zig");
const detection_int = @import("detection_integration.zig");
const detection = @import("detection_interface.zig");
const flow_int = @import("flow_integration.zig");

// ============================================================
// STEP 7: Correlation result (returned to caller)
// ============================================================

pub const CorrelationResult = struct {
    /// True if event was linked to an existing incident (not new).
    linked_to_existing: bool,
    /// Index of incident in XDR table (null if submission failed — table full).
    incident_index: ?usize,
    /// Number of events in the linked incident after this submission.
    incident_event_count: u32,
    /// Current severity of the incident (may have escalated).
    incident_severity: u8,
    /// Number of distinct session_ids in the incident.
    incident_session_count: usize,
    /// Number of distinct source IPs in the incident.
    incident_ip_count: usize,
};

// ============================================================
// STEP 7: Integration state
// ============================================================

var g_correlator: ?xdr.XDRCorrelator = null;
var g_initialized: bool = false;
var g_total_submissions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_new_incidents: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_correlations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_escalations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_correlator = xdr.XDRCorrelator.init();
    g_initialized = true;
    g_total_submissions.store(0, .monotonic);
    g_total_new_incidents.store(0, .monotonic);
    g_total_correlations.store(0, .monotonic);
    g_total_escalations.store(0, .monotonic);
    std.log.info("[CORR-INT] Correlation integration initialized (max 256 incidents)", .{});
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_correlator = null;
    g_initialized = false;
    std.log.info("[CORR-INT] Correlation integration shutdown", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Get the underlying XDR correlator (for advanced callers / tests).
pub fn getCorrelator() ?*xdr.XDRCorrelator {
    if (!g_initialized) return null;
    return &g_correlator.?;
}

// ============================================================
// STEP 7: Main API — submit detection context to XDR
// ============================================================

/// Submit a DetectionContext to the XDR correlator.
/// The event inside det_ctx is used to:
///   - Link to existing incident by session_id (if event.session_id != 0)
///   - Or create new incident
///   - Escalate incident severity if event.severity > current
/// Returns CorrelationResult with incident info.
pub fn submitDetectionContext(det_ctx: detection_int.DetectionContext) CorrelationResult {
    g_total_submissions.store(g_total_submissions.load(.monotonic) + 1, .monotonic);

    if (!g_initialized) {
        return .{
            .linked_to_existing = false,
            .incident_index = null,
            .incident_event_count = 0,
            .incident_severity = 0,
            .incident_session_count = 0,
            .incident_ip_count = 0,
        };
    }

    var corr = &g_correlator.?;

    // Snapshot incident_count BEFORE submission to detect "new" vs "linked"
    const before_count = corr.activeIncidents();

    // Submit the (possibly mutated by detection) event
    const maybe_idx = corr.submitEvent(det_ctx.event);

    if (maybe_idx == null) {
        return .{
            .linked_to_existing = false,
            .incident_index = null,
            .incident_event_count = 0,
            .incident_severity = 0,
            .incident_session_count = 0,
            .incident_ip_count = 0,
        };
    }

    const idx = maybe_idx.?;
    const after_count = corr.activeIncidents();
    const linked_to_existing = (after_count == before_count);

    if (linked_to_existing) {
        g_total_correlations.store(g_total_correlations.load(.monotonic) + 1, .monotonic);
    } else {
        g_total_new_incidents.store(g_total_new_incidents.load(.monotonic) + 1, .monotonic);
    }

    // Read back incident snapshot (under XDR lock)
    var event_count: u32 = 0;
    var severity: u8 = 0;
    var session_count: usize = 0;
    var ip_count: usize = 0;
    if (corr.getIncident(idx)) |inc| {
        event_count = inc.event_count;
        severity = inc.severity;
        session_count = inc.session_count;
        ip_count = inc.ip_count;
    }

    // Track escalations
    if (severity > det_ctx.event.severity) {
        // Incident severity is higher than this event's — was escalated
        g_total_escalations.store(g_total_escalations.load(.monotonic) + 1, .monotonic);
    }

    return .{
        .linked_to_existing = linked_to_existing,
        .incident_index = idx,
        .incident_event_count = event_count,
        .incident_severity = severity,
        .incident_session_count = session_count,
        .incident_ip_count = ip_count,
    };
}

// ============================================================
// STEP 7: Combined pipeline — process event + correlate
// ============================================================

/// Process an event through the full pipeline:
///   1. detection_int.processEvent() (flow + escalation + detectors)
///   2. correlation_int.submitDetectionContext() (XDR linking)
///
/// Returns both DetectionContext and CorrelationResult.
pub fn processEventWithCorrelation(
    event: canonical.CanonicalEvent,
    det_mgr: ?*detection.DetectionManager,
    payload: []const u8,
) struct {
    det_ctx: detection_int.DetectionContext,
    corr_result: CorrelationResult,
} {
    const det_ctx = detection_int.processEvent(event, det_mgr, payload);
    const corr_result = submitDetectionContext(det_ctx);
    return .{ .det_ctx = det_ctx, .corr_result = corr_result };
}

// ============================================================
// STEP 7: Maintenance — purge old incidents
// ============================================================

/// Purge incidents older than max_age_ms. Returns number purged.
/// Call periodically from a maintenance thread.
pub fn purgeOlder(max_age_ms: i64) usize {
    if (!g_initialized) return 0;
    var corr = &g_correlator.?;
    return corr.purgeOlder(max_age_ms);
}

// ============================================================
// STEP 7: Stats
// ============================================================

pub const IntegrationStats = struct {
    initialized: bool,
    active_incidents: usize,
    total_submissions: u64,
    total_new_incidents: u64,
    total_correlations: u64,
    total_escalations: u64,
};

pub fn getStats() IntegrationStats {
    if (!g_initialized) {
        return .{
            .initialized = false,
            .active_incidents = 0,
            .total_submissions = 0,
            .total_new_incidents = 0,
            .total_correlations = 0,
            .total_escalations = 0,
        };
    }
    var corr = &g_correlator.?;
    const xstats = corr.getStats();
    return .{
        .initialized = true,
        .active_incidents = xstats.active_incidents,
        .total_submissions = g_total_submissions.load(.monotonic),
        .total_new_incidents = g_total_new_incidents.load(.monotonic),
        .total_correlations = g_total_correlations.load(.monotonic),
        .total_escalations = g_total_escalations.load(.monotonic),
    };
}

pub fn resetStats() void {
    g_total_submissions.store(0, .monotonic);
    g_total_new_incidents.store(0, .monotonic);
    g_total_correlations.store(0, .monotonic);
    g_total_escalations.store(0, .monotonic);
}

// ============================================================
// Tests
// ============================================================

// Helper: init all three layers (flow + detection + correlation) for tests
fn initAllLayers() void {
    flow_int.init();
    detection_int.init(detection_int.EscalationThresholds.default());
    init();
}

fn shutdownAllLayers() void {
    shutdown();
    flow_int.shutdown();
    detection_int.resetStats();
    resetStats();
}

test "CorrelationResult is a value type" {
    const r = CorrelationResult{
        .linked_to_existing = true,
        .incident_index = 5,
        .incident_event_count = 3,
        .incident_severity = 2,
        .incident_session_count = 1,
        .incident_ip_count = 2,
    };
    const copy = r;
    try std.testing.expect(copy.linked_to_existing);
    try std.testing.expect(copy.incident_index.? == 5);
}

test "init and shutdown lifecycle" {
    initAllLayers();
    defer shutdownAllLayers();
    try std.testing.expect(isInitialized());
    try std.testing.expect(getCorrelator() != null);
}

test "submitDetectionContext creates new incident for first event" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .block;
    event.session_id = 42;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    event.severity = 2;

    const det_ctx = detection_int.processEvent(event, null, &.{});
    const result = submitDetectionContext(det_ctx);

    try std.testing.expect(!result.linked_to_existing);
    try std.testing.expect(result.incident_index != null);
    try std.testing.expect(result.incident_event_count == 1);

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 1);
    try std.testing.expect(stats.total_new_incidents == 1);
    try std.testing.expect(stats.active_incidents == 1);
}

test "submitDetectionContext links events by session_id" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    // Event 1: network event with session_id=100
    var e1 = canonical.create(.wfp_sensor);
    e1.event_type = .forward;
    e1.session_id = 100;
    e1.source_ip = 0x0A000001;
    e1.dest_ip = 0x0A000002;
    e1.source_port = 12345;
    e1.dest_port = 80;
    e1.protocol = 6;
    e1.payload_length = 100;
    e1.is_pipe = 0;
    e1.severity = 1;

    const det_ctx1 = detection_int.processEvent(e1, null, &.{});
    const result1 = submitDetectionContext(det_ctx1);
    try std.testing.expect(!result1.linked_to_existing);

    // Event 2: host event with same session_id=100
    var e2 = canonical.create(.minifilter);
    e2.event_type = .block;
    e2.session_id = 100; // SAME session_id
    e2.source_ip = 0; // host event (different IP space)
    e2.payload_length = 50;
    e2.is_pipe = 1;
    e2.severity = 3;

    const det_ctx2 = detection_int.processEvent(e2, null, &.{});
    const result2 = submitDetectionContext(det_ctx2);
    try std.testing.expect(result2.linked_to_existing);
    try std.testing.expect(result2.incident_index.? == result1.incident_index.?);
    try std.testing.expect(result2.incident_event_count == 2);

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 2);
    try std.testing.expect(stats.total_new_incidents == 1);
    try std.testing.expect(stats.total_correlations == 1);
    try std.testing.expect(stats.active_incidents == 1);
}

test "submitDetectionContext creates separate incidents for different sessions" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    var e1 = canonical.create(.wfp_sensor);
    e1.event_type = .forward;
    e1.session_id = 1;
    e1.source_ip = 0x0A000001;
    e1.dest_ip = 0x0A000002;
    e1.source_port = 1000;
    e1.dest_port = 80;
    e1.protocol = 6;
    e1.payload_length = 100;
    e1.is_pipe = 0;
    const r1 = submitDetectionContext(detection_int.processEvent(e1, null, &.{}));

    var e2 = canonical.create(.wfp_sensor);
    e2.event_type = .forward;
    e2.session_id = 2; // DIFFERENT session_id
    e2.source_ip = 0x0A000003;
    e2.dest_ip = 0x0A000004;
    e2.source_port = 2000;
    e2.dest_port = 80;
    e2.protocol = 6;
    e2.payload_length = 100;
    e2.is_pipe = 0;
    const r2 = submitDetectionContext(detection_int.processEvent(e2, null, &.{}));

    try std.testing.expect(r1.incident_index.? != r2.incident_index.?);

    const stats = getStats();
    try std.testing.expect(stats.active_incidents == 2);
    try std.testing.expect(stats.total_new_incidents == 2);
}

test "processEventWithCorrelation runs full pipeline" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.session_id = 999;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;

    const result = processEventWithCorrelation(event, null, &.{});

    try std.testing.expect(result.det_ctx.flow_context.packet_count == 1);
    try std.testing.expect(!result.corr_result.linked_to_existing);
    try std.testing.expect(result.corr_result.incident_index != null);
}

test "escalation tracking across multiple events" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    // First event: low severity
    var e1 = canonical.create(.wfp_sensor);
    e1.event_type = .forward;
    e1.session_id = 500;
    e1.source_ip = 0x0A000001;
    e1.dest_ip = 0x0A000002;
    e1.source_port = 12345;
    e1.dest_port = 80;
    e1.protocol = 6;
    e1.payload_length = 100;
    e1.is_pipe = 0;
    e1.severity = 1;
    _ = processEventWithCorrelation(e1, null, &.{});

    // Second event: high severity, same session
    var e2 = canonical.create(.minifilter);
    e2.event_type = .block;
    e2.session_id = 500;
    e2.severity = 3;
    _ = processEventWithCorrelation(e2, null, &.{});

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 2);
    try std.testing.expect(stats.total_correlations == 1);
    try std.testing.expect(stats.active_incidents == 1);
}

test "getStats returns full integration state" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    const empty_stats = getStats();
    try std.testing.expect(empty_stats.initialized);
    try std.testing.expect(empty_stats.active_incidents == 0);

    // Submit one event
    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.session_id = 1;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    _ = processEventWithCorrelation(event, null, &.{});

    const stats = getStats();
    try std.testing.expect(stats.total_submissions == 1);
    try std.testing.expect(stats.total_new_incidents == 1);
    try std.testing.expect(stats.active_incidents == 1);
}

test "purgeOlder removes stale incidents" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.session_id = 1;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    _ = processEventWithCorrelation(event, null, &.{});

    try std.testing.expect(getStats().active_incidents == 1);

    // Purge incidents older than 1 hour — fresh incident won't be purged
    const purged = purgeOlder(60 * 60 * 1000);
    try std.testing.expect(purged == 0);
    try std.testing.expect(getStats().active_incidents == 1);
}

test "STEP7: cross-tier attack reconstruction (network + host in same incident)" {
    // Simulates an attack scenario:
    // 1. Network event: external IP scans internal host (session_id=ATTACK-1)
    // 2. Host event: suspicious process spawn (same session_id — correlates)
    // 3. Result: single incident with both events, escalated severity
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    // Phase 1: network scan
    var net_event = canonical.create(.wfp_sensor);
    net_event.event_type = .forward;
    net_event.session_id = 0xABC001AA;
    net_event.source_ip = 0xC0A80164; // external
    net_event.dest_ip = 0x0A000001; // internal
    net_event.source_port = 50000;
    net_event.dest_port = 445; // SMB
    net_event.protocol = 6;
    net_event.payload_length = 64;
    net_event.is_pipe = 0;
    net_event.severity = 1; // low — just a forward
    const net_result = processEventWithCorrelation(net_event, null, &.{});
    try std.testing.expect(!net_result.corr_result.linked_to_existing);
    try std.testing.expect(net_result.corr_result.incident_severity == 1);

    // Phase 2: host process spawn — same session (correlated)
    var host_event = canonical.create(.minifilter);
    host_event.event_type = .block;
    host_event.session_id = 0xABC001AA; // SAME — correlated
    host_event.source_ip = 0; // host event
    host_event.payload_length = 50;
    host_event.is_pipe = 1;
    host_event.severity = 3; // CRITICAL — escalation
    const host_result = processEventWithCorrelation(host_event, null, &.{});

    try std.testing.expect(host_result.corr_result.linked_to_existing);
    try std.testing.expect(host_result.corr_result.incident_index.? == net_result.corr_result.incident_index.?);
    try std.testing.expect(host_result.corr_result.incident_event_count == 2);
    try std.testing.expect(host_result.corr_result.incident_severity == 3); // escalated

    const stats = getStats();
    try std.testing.expect(stats.total_correlations == 1);
    try std.testing.expect(stats.active_incidents == 1);
}

test "STEP7: correlation survives multiple sessions, separates them" {
    // Multiple distinct attacks — each gets own incident
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    resetStats();

    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.event_type = .forward;
        event.session_id = i + 100; // distinct sessions
        event.source_ip = 0x0A000001 + @as(u32, @intCast(i));
        event.dest_ip = 0x0A000002;
        event.source_port = 12345 + @as(u16, @intCast(i));
        event.dest_port = 80;
        event.protocol = 6;
        event.payload_length = 100;
        event.is_pipe = 0;
        _ = processEventWithCorrelation(event, null, &.{});
    }

    const stats = getStats();
    try std.testing.expect(stats.active_incidents == 5);
    try std.testing.expect(stats.total_submissions == 5);
    try std.testing.expect(stats.total_new_incidents == 5);
    try std.testing.expect(stats.total_correlations == 0);
}
