//! detection_integration.zig - AEGIS Detection Integration (Rewrite Phase 7)
//!
//! Thin facade over detection_engine.zig that owns a singleton DetectionEngine.
//! Mirrors the pattern of flow_integration.zig and nose_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()              -> create DetectionEngine + register built-in detectors
//!   analyze(event, flow_update) -> returns EvidenceList
//!   shutdown()          -> reset engine state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow_types = @import("flow_types.zig");
const detection = @import("detection_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?detection.DetectionEngine = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_analyzed: u64 = 0;
var g_total_evidence: u64 = 0;
var g_total_threats: u64 = 0;
var g_total_errors: u64 = 0;

// ============================================================
// Initialization
// ============================================================

/// Initialize the Detection Engine and register built-in detectors.
pub fn init() void {
    if (g_initialized) return;
    g_engine = detection.DetectionEngine.init();
    if (g_engine) |*engine| {
        engine.registerBuiltins();
    }
    g_initialized = true;
    g_total_analyzed = 0;
    g_total_evidence = 0;
    g_total_threats = 0;
    g_total_errors = 0;
    std.log.info("[DETECTION] Detection integration initialized (3 built-in detectors)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_analyzed = 0;
    g_total_evidence = 0;
    g_total_threats = 0;
    g_total_errors = 0;
    if (g_engine) |*engine| {
        engine.total_analyzed = 0;
        engine.total_evidence = 0;
        engine.total_threats = 0;
        engine.total_errors = 0;
    }
}

// ============================================================
// Analysis
// ============================================================

/// Analyze an event + optional flow update. Returns EvidenceList (all detectors).
/// Returns empty list if not initialized.
pub fn analyze(
    event: canonical.CanonicalEvent,
    flow_update: ?flow_types.FlowUpdate,
) detection.EvidenceList {
    if (!g_initialized) return detection.EvidenceList.init();
    if (g_engine) |*engine| {
        const list = engine.analyze(event, flow_update);
        g_total_analyzed += 1;
        g_total_evidence += list.count;
        for (list.slice()) |e| {
            if (e.verdict == .error_) {
                g_total_errors += 1;
            } else if (e.verdict.isThreat()) {
                g_total_threats += 1;
            }
        }
        return list;
    }
    return detection.EvidenceList.init();
}

// ============================================================
// Stats
// ============================================================

pub const DetectionStats = struct {
    total_analyzed: u64,
    total_evidence: u64,
    total_threats: u64,
    total_errors: u64,
    detector_count: usize,
};

pub fn getStats() DetectionStats {
    if (g_engine) |*engine| {
        return .{
            .total_analyzed = g_total_analyzed,
            .total_evidence = g_total_evidence,
            .total_threats = g_total_threats,
            .total_errors = g_total_errors,
            .detector_count = engine.count,
        };
    }
    return .{
        .total_analyzed = 0,
        .total_evidence = 0,
        .total_threats = 0,
        .total_errors = 0,
        .detector_count = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[DETECTION] Detection integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "detection integration: full lifecycle (init, analyze, stats, shutdown, null-when-uninitialized)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: analyze returns empty list when not initialized ---
    var event = canonical.create(.wfp_sensor);
    const empty_list = analyze(event, null);
    try std.testing.expect(empty_list.count == 0);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.detector_count == 3); // 3 built-in detectors
    try std.testing.expect(stats_init.total_analyzed == 0);

    // --- Phase C: analyze with benign event ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0;
    event.severity = 0;

    const benign_list = analyze(event, null);
    try std.testing.expect(benign_list.count == 3);
    try std.testing.expect(benign_list.maxVerdict() == .benign);

    const stats_after_benign = getStats();
    try std.testing.expect(stats_after_benign.total_analyzed == 1);
    try std.testing.expect(stats_after_benign.total_evidence == 3);
    try std.testing.expect(stats_after_benign.total_threats == 0);

    // --- Phase D: analyze with rule-matched event (suspicious) ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xDEAD;
    event.severity = 2;

    const suspicious_list = analyze(event, null);
    try std.testing.expect(suspicious_list.count == 3);
    try std.testing.expect(suspicious_list.maxVerdict() == .suspicious);
    try std.testing.expect(suspicious_list.countByVerdict(.suspicious) >= 1);

    const stats_after_suspicious = getStats();
    try std.testing.expect(stats_after_suspicious.total_analyzed == 2);
    try std.testing.expect(stats_after_suspicious.total_threats == 1);

    // --- Phase E: analyze with critical rule match (malicious) ---
    event = canonical.create(.wfp_sensor);
    event.rule_id = 0xBEEF;
    event.severity = 3;

    const malicious_list = analyze(event, null);
    try std.testing.expect(malicious_list.maxVerdict() == .malicious);

    const stats_after_malicious = getStats();
    try std.testing.expect(stats_after_malicious.total_threats == 2);

    // --- Phase F: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_analyzed == 0);
    try std.testing.expect(stats_reset.total_threats == 0);

    // --- Phase G: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase H: after shutdown, analyze returns empty list ---
    const empty_list2 = analyze(event, null);
    try std.testing.expect(empty_list2.count == 0);
}
