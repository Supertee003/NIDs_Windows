//! forensics_integration.zig - AEGIS Forensics Integration (Rewrite Phase 14)
//!
//! Thin facade over forensics_engine.zig that owns a singleton ForensicLogger.
//! Final pipeline stage - records everything for replay and analysis.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create ForensicLogger
//!   logResult(event, av, alerts, ti, advice, decision, pep) -> sequence number
//!   shutdown() -> reset logger state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_logger: ?forensics.ForensicLogger = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_logged: u64 = 0;
var g_total_significant: u64 = 0;
var g_total_blocking: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_logger = forensics.ForensicLogger.init();
    g_initialized = true;
    g_total_logged = 0;
    g_total_significant = 0;
    g_total_blocking = 0;
    std.log.info("[FORENSICS] Forensics integration initialized (ring buffer 4096)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_logged = 0;
    g_total_significant = 0;
    g_total_blocking = 0;
    if (g_logger) |*logger| {
        logger.clear();
    }
}

// ============================================================
// Logging
// ============================================================

/// Log a pipeline result. Returns sequence number (0 if not initialized).
pub fn logResult(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [3]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
    decision: policy.EnforcementDecision,
    pep_result: rust_pep.EnforcementResult,
) u64 {
    if (!g_initialized) return 0;
    if (g_logger) |*logger| {
        const seq = logger.logResult(event, av, alerts, ti_match, advice, decision, pep_result);
        g_total_logged += 1;
        if (seq > 0) {
            // Check if significant by retrieving the record
            if (logger.getBySequence(seq)) |record| {
                if (record.result.isSignificant()) {
                    g_total_significant += 1;
                }
                if (record.result.isBlocking()) {
                    g_total_blocking += 1;
                }
            }
        }
        return seq;
    }
    return 0;
}

/// Get a forensic record by event_id.
pub fn getByEventId(event_id: u64) ?forensics.ForensicRecord {
    if (g_logger) |*logger| {
        return logger.getByEventId(event_id);
    }
    return null;
}

/// Get a forensic record by sequence number.
pub fn getBySequence(seq: u64) ?forensics.ForensicRecord {
    if (g_logger) |*logger| {
        return logger.getBySequence(seq);
    }
    return null;
}

/// Current record count in buffer.
pub fn recordCount() usize {
    if (g_logger) |*logger| {
        return logger.recordCount();
    }
    return 0;
}

// ============================================================
// Stats
// ============================================================

pub const ForensicsStats = struct {
    total_logged: u64,
    total_significant: u64,
    total_blocking: u64,
    buffer_count: usize,
    buffer_capacity: usize,
};

pub fn getStats() ForensicsStats {
    if (g_logger) |*logger| {
        return .{
            .total_logged = g_total_logged,
            .total_significant = g_total_significant,
            .total_blocking = g_total_blocking,
            .buffer_count = logger.recordCount(),
            .buffer_capacity = forensics.MAX_RECORDS,
        };
    }
    return .{
        .total_logged = 0,
        .total_significant = 0,
        .total_blocking = 0,
        .buffer_count = 0,
        .buffer_capacity = forensics.MAX_RECORDS,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_logger = null;
    g_initialized = false;
    std.log.info("[FORENSICS] Forensics integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "forensics integration: full lifecycle (init, log, query, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: logResult returns 0 when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = @import("detection_engine.zig").Indicator.RULE_MATCH,
        .event_id = event.event_id,
    };

    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti_match = threat_intel.ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
    const advice = brain.BrainAdvice{
        .kind = .keep,
        .threat_score = 50,
        .recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .explanation = "test",
        .signal_detection = 50,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = event.event_id,
    };
    const decision = policy.EnforcementDecision{
        .action = .alert,
        .rule = .verdict_suspicious,
        .confidence = 70,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .threat_score = 50,
    };
    const pep_result = rust_pep.EnforcementResult{
        .status = .no_op,
        .reason = .none,
        .requested_action = .alert,
        .actual_action = .alert,
        .event_id = event.event_id,
        .blocked_ip = 0,
        .message = "alert: logged only",
    };

    const empty_seq = logResult(event, av, alerts, ti_match, advice, decision, pep_result);
    try std.testing.expect(empty_seq == 0);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_logged == 0);
    try std.testing.expect(stats_init.buffer_count == 0);

    // --- Phase C: logResult creates record ---
    const seq = logResult(event, av, alerts, ti_match, advice, decision, pep_result);
    try std.testing.expect(seq > 0);

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_logged == 1);
    try std.testing.expect(stats_after.total_significant == 1); // alert is significant
    try std.testing.expect(stats_after.buffer_count == 1);

    // --- Phase D: query by event_id ---
    const found = getByEventId(event.event_id);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.result.aggregated_verdict == .suspicious);
    try std.testing.expect(found.?.result.policy_action == .alert);

    // --- Phase E: query by sequence ---
    const found_seq = getBySequence(seq);
    try std.testing.expect(found_seq != null);
    try std.testing.expect(found_seq.?.result.event_id == event.event_id);

    // --- Phase F: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_logged == 0);
    try std.testing.expect(stats_reset.buffer_count == 0);

    // --- Phase G: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase H: after shutdown, logResult returns 0 ---
    const empty_seq2 = logResult(event, av, alerts, ti_match, advice, decision, pep_result);
    try std.testing.expect(empty_seq2 == 0);
}
