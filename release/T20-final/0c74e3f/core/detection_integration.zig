//! detection_integration.zig - AEGIS Detection Integration (Rewrite Phase 7)
//!
//! Thin facade over detection_engine.zig that owns a singleton DetectionEngine.
//! Provides the per-event analyze() API consumed by the dispatcher.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()                 -> create DetectionEngine
//!   analyze(event, flow)   -> EvidenceList  (empty if not initialized)
//!   shutdown()             -> release engine

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const flow = @import("flow_engine.zig");

var g_engine: ?detection.DetectionEngine = null;
var g_initialized: bool = false;

var g_total_events: u64 = 0;
var g_total_threats: u64 = 0;
var g_total_evidence: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = detection.DetectionEngine.init();
    g_initialized = true;
    g_total_events = 0;
    g_total_threats = 0;
    g_total_evidence = 0;
    std.log.info("[DETECTION] Detection integration initialized (4 built-in detectors)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[DETECTION] Detection integration shutdown", .{});
}

/// Analyze an event with an optional flow_update. Returns an EvidenceList
/// (empty if not initialized).
pub fn analyze(event: canonical.CanonicalEvent, flow_update: ?flow.FlowUpdate) detection.EvidenceList {
    if (!g_initialized) return detection.EvidenceList.init();
    if (g_engine) |*engine| {
        const list = engine.analyze(event, flow_update);
        g_total_events += 1;
        g_total_evidence += list.count;
        if (list.hasThreat()) g_total_threats += 1;
        return list;
    }
    return detection.EvidenceList.init();
}

pub const DetectionStats = struct {
    total_events: u64,
    total_threats: u64,
    total_evidence: u64,
};

pub fn getStats() DetectionStats {
    if (g_initialized) {
        return .{
            .total_events = g_total_events,
            .total_threats = g_total_threats,
            .total_evidence = g_total_evidence,
        };
    }
    return .{ .total_events = 0, .total_threats = 0, .total_evidence = 0 };
}

pub fn resetStats() void {
    g_total_events = 0;
    g_total_threats = 0;
    g_total_evidence = 0;
    if (g_engine) |*engine| engine.resetStats();
}

// Tests (serial - singleton)
test "detection_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    try std.testing.expect(isInitialized());

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0xDEAD;

    const list = analyze(event, null);
    try std.testing.expect(list.count > 0);
    try std.testing.expect(list.hasThreat());

    const stats = getStats();
    try std.testing.expect(stats.total_events == 1);
    try std.testing.expect(stats.total_threats == 1);
    try std.testing.expect(stats.total_evidence > 0);

    shutdown();
    try std.testing.expect(!isInitialized());
}

test "detection_integration: returns empty list when not initialized" {
    if (isInitialized()) shutdown();
    const event = canonical.create(.zig_core);
    const list = analyze(event, null);
    try std.testing.expect(list.count == 0);
}
