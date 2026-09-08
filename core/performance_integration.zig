//! performance_integration.zig - AEGIS Performance Integration (Rewrite Phase 17)
//!
//! Thin facade over performance_harness.zig that owns a singleton PerformanceHarness.
//! Read-only measurement tool (does NOT modify the pipeline).
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create PerformanceHarness
//!   recordSample(sample) -> record latency for one event
//!   shutdown() -> reset harness state

const std = @import("std");
const perf = @import("performance_harness.zig");

// ============================================================
// Singleton state
// ============================================================

var g_harness: ?perf.PerformanceHarness = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_samples: u64 = 0;
var g_slow_events: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_harness = perf.PerformanceHarness.init();
    g_initialized = true;
    g_total_samples = 0;
    g_slow_events = 0;
    std.log.info("[PERF] Performance harness initialized (MAX_SAMPLES=4096)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_samples = 0;
    g_slow_events = 0;
    if (g_harness) |*harness| {
        harness.reset();
    }
}

// ============================================================
// Recording
// ============================================================

/// Record a latency sample for one event.
pub fn recordSample(sample: perf.LatencySample) void {
    if (!g_initialized) return;
    if (g_harness) |*harness| {
        harness.recordSample(sample);
        g_total_samples += 1;
        if (sample.total_ns > harness.slow_threshold_ns) {
            g_slow_events += 1;
        }
    }
}

/// Set the slow event threshold (ns).
pub fn setSlowThreshold(threshold_ns: u64) void {
    if (g_harness) |*harness| {
        harness.setSlowThreshold(threshold_ns);
    }
}

// ============================================================
// Stats
// ============================================================

/// Compute statistics for a specific stage.
pub fn computeStats(stage: perf.Stage) perf.LatencyStats {
    if (g_harness) |*harness| {
        return harness.computeStats(stage);
    }
    return .{
        .min_ns = 0,
        .max_ns = 0,
        .avg_ns = 0,
        .p50_ns = 0,
        .p95_ns = 0,
        .p99_ns = 0,
        .count = 0,
    };
}

/// Get throughput (events per second).
pub fn throughputEPS() f64 {
    if (g_harness) |*harness| {
        return harness.throughputEPS();
    }
    return 0;
}

/// Get slow event percentage.
pub fn slowEventPercent() u8 {
    if (g_harness) |*harness| {
        return harness.slowEventPercent();
    }
    return 0;
}

/// Get full performance summary.
pub fn getSummary() perf.PerformanceSummary {
    if (g_harness) |*harness| {
        return harness.getSummary();
    }
    // Return empty summary
    const empty_stats = perf.LatencyStats{
        .min_ns = 0,
        .max_ns = 0,
        .avg_ns = 0,
        .p50_ns = 0,
        .p95_ns = 0,
        .p99_ns = 0,
        .count = 0,
    };
    return .{
        .total_events = 0,
        .throughput_eps = 0,
        .total_stats = empty_stats,
        .flow_stats = empty_stats,
        .detection_stats = empty_stats,
        .aggregation_stats = empty_stats,
        .correlation_stats = empty_stats,
        .threat_intel_stats = empty_stats,
        .brain_stats = empty_stats,
        .policy_stats = empty_stats,
        .pep_stats = empty_stats,
        .forensics_stats = empty_stats,
        .slow_event_count = 0,
        .slow_event_percent = 0,
        .sample_count = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_harness = null;
    g_initialized = false;
    std.log.info("[PERF] Performance harness shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "performance integration: full lifecycle (init, record, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: recordSample is no-op when not initialized ---
    recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });

    const empty_stats = computeStats(.total);
    try std.testing.expect(!empty_stats.isValid());

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    // --- Phase C: record samples ---
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        recordSample(.{
            .total_ns = (i + 1) * 1000,
            .flow_ns = 100,
            .detection_ns = 200,
            .aggregation_ns = 150,
            .correlation_ns = 100,
            .threat_intel_ns = 50,
            .brain_ns = 100,
            .policy_ns = 100,
            .pep_ns = 100,
            .forensics_ns = 100,
            .event_id = i,
        });
    }

    // --- Phase D: verify stats ---
    const stats = computeStats(.total);
    try std.testing.expect(stats.isValid());
    try std.testing.expect(stats.count == 10);
    try std.testing.expect(stats.min_ns == 1000);
    try std.testing.expect(stats.max_ns == 10000);

    // --- Phase E: verify summary ---
    const summary = getSummary();
    try std.testing.expect(summary.total_events == 10);
    try std.testing.expect(summary.sample_count == 10);

    // --- Phase F: resetStats ---
    resetStats();
    const reset_stats = computeStats(.total);
    try std.testing.expect(!reset_stats.isValid());
    try std.testing.expect(reset_stats.count == 0);

    // --- Phase G: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase H: after shutdown, recordSample is no-op ---
    recordSample(.{
        .total_ns = 1000,
        .flow_ns = 100,
        .detection_ns = 200,
        .aggregation_ns = 150,
        .correlation_ns = 100,
        .threat_intel_ns = 50,
        .brain_ns = 100,
        .policy_ns = 100,
        .pep_ns = 100,
        .forensics_ns = 100,
        .event_id = 1,
    });
    const empty_after_shutdown = computeStats(.total);
    try std.testing.expect(!empty_after_shutdown.isValid());
}
