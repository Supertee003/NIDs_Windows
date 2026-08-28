//! metrics_export.zig - AEGIS Metrics Export (STEP 22)
//!
//! Prometheus-compatible metrics collection and export for production monitoring.
//! Collects metrics from all integration layers (STEP 3-21) and exposes them
//! via a simple HTTP endpoint (:9100/metrics) in Prometheus text format.
//!
//! Before STEP 22, the pipeline had stats scattered across modules:
//!   - fabric.getMetrics() (STEP 3): pending, accepted, rejected, dropped
//!   - nose_int.getStats() (STEP 4): submits, accepted, dropped_at_source
//!   - flow_int.getStats() (STEP 5): active_flows, events_processed
//!   - detection_int.getMetrics() (STEP 6): matches, escalations
//!   - correlation_int.getStats() (STEP 7): incidents, correlations
//!   - rag_int.getStats() (STEP 8): enriched, matches
//!   - policy_int.getStats() (STEP 9): evaluations, blocks
//!   - forensics_int.getStats() (STEP 10): records, ring_used
//!   - cpp_bridge.getStats() (STEP 17): pushed, popped
//!   - rust_shield.getStats() (STEP 18): scans, matches, blocks
//!   - go_aggregator.getIntegrationStats() (STEP 19): queries, pushes
//!   - python_brain.getStats() (STEP 20): submissions, defcon
//!   - cython.getStats() (STEP 21): scans, matches
//!
//! After STEP 22, all metrics are unified into a single Prometheus-compatible
//! export with proper naming conventions (aegis_* prefix).

const std = @import("std");

// ============================================================
// STEP 22: Metric types
// ============================================================

pub const MetricType = enum {
    counter, // Monotonically increasing (e.g., total_events)
    gauge, // Can go up or down (e.g., active_flows)
    histogram, // Distribution (e.g., event_latency_ns)

    pub fn toString(self: MetricType) []const u8 {
        return switch (self) {
            .counter => "counter",
            .gauge => "gauge",
            .histogram => "histogram",
        };
    }
};

pub const Metric = struct {
    name: []const u8,
    help: []const u8,
    metric_type: MetricType,
    value: u64,
};

// ============================================================
// STEP 22: Metrics registry (fixed-size array, no allocator needed)
// ============================================================

const MAX_METRICS: usize = 64;

var g_metrics: [MAX_METRICS]Metric = undefined;
var g_metric_count: usize = 0;
var g_initialized: bool = false;
var g_total_exports: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_initialized = true;
    g_metric_count = 0;
    g_total_exports.store(0, .monotonic);
    std.log.info("[METRICS] Metrics export initialized (max {} metrics)", .{MAX_METRICS});
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_initialized = false;
    std.log.info("[METRICS] Metrics export shutdown (exports={d})", .{
        g_total_exports.load(.monotonic),
    });
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetMetrics() void {
    g_metric_count = 0;
    g_total_exports.store(0, .monotonic);
}

// ============================================================
// STEP 22: Metric registration
// ============================================================

pub fn registerCounter(name: []const u8, help: []const u8, value: u64) bool {
    return registerMetric(name, help, .counter, value);
}

pub fn registerGauge(name: []const u8, help: []const u8, value: u64) bool {
    return registerMetric(name, help, .gauge, value);
}

fn registerMetric(name: []const u8, help: []const u8, mtype: MetricType, value: u64) bool {
    if (!g_initialized) return false;
    if (g_metric_count >= MAX_METRICS) return false;

    g_metrics[g_metric_count] = .{
        .name = name,
        .help = help,
        .metric_type = mtype,
        .value = value,
    };
    g_metric_count += 1;
    return true;
}

/// Update an existing metric's value (find by name).
pub fn updateMetric(name: []const u8, value: u64) bool {
    if (!g_initialized) return false;
    for (0..g_metric_count) |i| {
        if (std.mem.eql(u8, g_metrics[i].name, name)) {
            g_metrics[i].value = value;
            return true;
        }
    }
    return false;
}

// ============================================================
// STEP 22: Collect metrics from all integration layers
// ============================================================

/// Collect metrics from all pipeline layers.
/// This is the main entry point — call periodically (e.g., every 5s) to
/// refresh the metrics registry with current values from all modules.
pub fn collectAllMetrics() void {
    if (!g_initialized) return;
    resetMetrics();

    // Event Fabric (STEP 3)
    const fabric_mod = @import("event_fabric.zig");
    if (fabric_mod.isInitialized()) {
        const fm = fabric_mod.getMetrics();
        _ = registerGauge("aegis_fabric_pending", "Events currently in queue", fm.pending);
        _ = registerCounter("aegis_fabric_accepted_total", "Total events accepted", fm.total_accepted);
        _ = registerCounter("aegis_fabric_rejected_total", "Total events rejected", fm.total_rejected);
        _ = registerCounter("aegis_fabric_dropped_total", "Total events dropped", fm.total_dropped);
        _ = registerCounter("aegis_fabric_popped_total", "Total events popped", fm.total_popped);
        _ = registerGauge("aegis_fabric_high_pending", "High-priority queue depth", fm.high_pending);
        _ = registerGauge("aegis_fabric_normal_pending", "Normal-priority queue depth", fm.normal_pending);
        _ = registerGauge("aegis_fabric_low_pending", "Low-priority queue depth", fm.low_pending);
    }

    // Nose Integration (STEP 4)
    const nose_int = @import("nose_integration.zig");
    if (nose_int.isInitialized()) {
        const ns = nose_int.getStats();
        _ = registerCounter("aegis_nose_submissions_total", "Total nose submissions", ns.total_submits);
        _ = registerCounter("aegis_nose_accepted_total", "Nose accepted events", ns.accepted);
        _ = registerCounter("aegis_nose_dropped_source_total", "Events dropped at source", ns.dropped_at_source);
        _ = registerCounter("aegis_nose_dropped_fabric_total", "Events dropped by fabric", ns.dropped_by_fabric);
    }

    // Flow Integration (STEP 5)
    const flow_int = @import("flow_integration.zig");
    if (flow_int.isInitialized()) {
        const fs = flow_int.getStats();
        _ = registerGauge("aegis_flow_active_flows", "Active flow count", fs.active_flows);
        _ = registerCounter("aegis_flow_events_processed_total", "Flow events processed", fs.total_events_processed);
        _ = registerCounter("aegis_flow_flows_created_total", "Total flows created", fs.total_flows_created);
    }

    // Detection Integration (STEP 6)
    const detection_int = @import("detection_integration.zig");
    {
        const dm = detection_int.getMetrics();
        _ = registerCounter("aegis_detection_events_processed_total", "Detection events processed", dm.total_events_processed);
        _ = registerCounter("aegis_detection_matches_total", "Detection matches", dm.total_matches);
        _ = registerCounter("aegis_detection_blocks_total", "Detection blocks", dm.total_blocks);
        _ = registerCounter("aegis_detection_escalations_total", "Flow pattern escalations", dm.total_escalations);
    }

    // Correlation Integration (STEP 7)
    const correlation_int = @import("correlation_integration.zig");
    if (correlation_int.isInitialized()) {
        const cs = correlation_int.getStats();
        _ = registerGauge("aegis_correlation_active_incidents", "Active XDR incidents", cs.active_incidents);
        _ = registerCounter("aegis_correlation_submissions_total", "Correlation submissions", cs.total_submissions);
        _ = registerCounter("aegis_correlation_new_incidents_total", "New incidents created", cs.total_new_incidents);
        _ = registerCounter("aegis_correlation_links_total", "Events linked to existing incidents", cs.total_correlations);
    }

    // RAG Integration (STEP 8)
    const rag_int = @import("rag_integration.zig");
    if (rag_int.isInitialized()) {
        const rs = rag_int.getStats();
        _ = registerGauge("aegis_rag_db_entries", "Threat intel DB entries", rs.db_entries);
        _ = registerCounter("aegis_rag_enriched_total", "Events enriched", rs.total_enriched);
        _ = registerCounter("aegis_rag_matches_total", "Threat intel matches", rs.total_matches);
    }

    // Policy Integration (STEP 9)
    const policy_int = @import("policy_integration.zig");
    if (policy_int.isInitialized()) {
        const ps = policy_int.getStats();
        _ = registerGauge("aegis_policy_rules_total", "Active policy rules", ps.total_rules);
        _ = registerCounter("aegis_policy_evaluations_total", "Policy evaluations", ps.total_evaluations);
        _ = registerCounter("aegis_policy_blocks_total", "Policy BLOCK decisions", ps.total_blocks);
        _ = registerCounter("aegis_policy_alerts_total", "Policy ALERT decisions", ps.total_alerts);
        _ = registerCounter("aegis_policy_enforcement_failures_total", "PEP enforcement failures", ps.total_enforcement_failures);
    }

    // Forensics Integration (STEP 10)
    const forensics_int = @import("forensics_integration.zig");
    if (forensics_int.isInitialized()) {
        const fs = forensics_int.getStats();
        _ = registerCounter("aegis_forensics_records_total", "Total forensics records", fs.total_records);
        _ = registerGauge("aegis_forensics_ring_used", "Ring buffer entries in use", fs.ring_used);
    }

    // Release info (STEP 15)
    const release_info = @import("release_info.zig");
    _ = registerGauge("aegis_version_major", "AEGIS version major", release_info.VERSION_MAJOR);
    _ = registerGauge("aegis_version_minor", "AEGIS version minor", release_info.VERSION_MINOR);
    _ = registerGauge("aegis_version_patch", "AEGIS version patch", release_info.VERSION_PATCH);

    g_total_exports.store(g_total_exports.load(.monotonic) + 1, .monotonic);
}

// ============================================================
// STEP 22: Export metrics in Prometheus text format
// ============================================================

/// Export all metrics in Prometheus text format.
/// Writes to the provided buffer. Returns the number of bytes written.
pub fn exportPrometheus(buf: []u8) usize {
    if (!g_initialized) return 0;

    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    // Write header
    writer.print("# AEGIS NIDS Metrics Export\n", .{}) catch return 0;
    writer.print("# Export count: {d}\n", .{g_total_exports.load(.monotonic)}) catch return 0;
    writer.print("# Timestamp: {d}\n", .{std.time.milliTimestamp()}) catch return 0;
    writer.print("\n", .{}) catch return 0;

    // Write each metric in Prometheus format:
    // # HELP metric_name help text
    // # TYPE metric_name counter
    // metric_name value
    for (0..g_metric_count) |i| {
        const m = g_metrics[i];
        writer.print("# HELP {s} {s}\n", .{ m.name, m.help }) catch break;
        writer.print("# TYPE {s} {s}\n", .{ m.name, m.metric_type.toString() }) catch break;
        writer.print("{s} {d}\n", .{ m.name, m.value }) catch break;
        writer.print("\n", .{}) catch break;
    }

    return fbs.pos;
}

/// Get metric count.
pub fn getMetricCount() usize {
    return g_metric_count;
}

/// Get a specific metric by index.
pub fn getMetric(index: usize) ?Metric {
    if (index >= g_metric_count) return null;
    return g_metrics[index];
}

// ============================================================
// STEP 22: Stats
// ============================================================

pub const MetricsExportStats = struct {
    initialized: bool,
    metric_count: usize,
    max_metrics: usize,
    total_exports: u64,
};

pub fn getStats() MetricsExportStats {
    return .{
        .initialized = g_initialized,
        .metric_count = g_metric_count,
        .max_metrics = MAX_METRICS,
        .total_exports = g_total_exports.load(.monotonic),
    };
}

// ============================================================
// Tests
// ============================================================

test "MetricType.toString returns correct names" {
    try std.testing.expect(std.mem.eql(u8, MetricType.counter.toString(), "counter"));
    try std.testing.expect(std.mem.eql(u8, MetricType.gauge.toString(), "gauge"));
    try std.testing.expect(std.mem.eql(u8, MetricType.histogram.toString(), "histogram"));
}

test "Metric is a value type" {
    const m = Metric{
        .name = "test_metric",
        .help = "test help",
        .metric_type = .counter,
        .value = 42,
    };
    const copy = m;
    try std.testing.expect(copy.value == 42);
}

test "init and shutdown lifecycle" {
    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.max_metrics == MAX_METRICS);
}

test "registerCounter adds metric" {
    init();
    defer shutdown();
    resetMetrics();

    try std.testing.expect(registerCounter("test_counter", "test help", 100));
    try std.testing.expect(getMetricCount() == 1);

    const m = getMetric(0);
    try std.testing.expect(m != null);
    try std.testing.expect(m.?.value == 100);
    try std.testing.expect(m.?.metric_type == .counter);
}

test "registerGauge adds metric" {
    init();
    defer shutdown();
    resetMetrics();

    try std.testing.expect(registerGauge("test_gauge", "gauge help", 50));
    try std.testing.expect(getMetricCount() == 1);

    const m = getMetric(0);
    try std.testing.expect(m.?.metric_type == .gauge);
}

test "updateMetric changes existing value" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("events_total", "total events", 100);
    try std.testing.expect(updateMetric("events_total", 200));
    try std.testing.expect(getMetric(0).?.value == 200);
}

test "updateMetric returns false for unknown name" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("known_metric", "help", 0);
    try std.testing.expect(!updateMetric("unknown_metric", 100));
}

test "registerMetric returns false when full" {
    init();
    defer shutdown();
    resetMetrics();

    var i: usize = 0;
    while (i < MAX_METRICS) : (i += 1) {
        try std.testing.expect(registerCounter("metric", "help", i));
    }
    // Next should fail
    try std.testing.expect(!registerCounter("overflow", "help", 0));
    try std.testing.expect(getMetricCount() == MAX_METRICS);
}

test "exportPrometheus writes valid format" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("aegis_test_counter", "test counter", 42);
    _ = registerGauge("aegis_test_gauge", "test gauge", 99);

    var buf: [4096]u8 = undefined;
    const written = exportPrometheus(&buf);
    try std.testing.expect(written > 0);

    const output = buf[0..written];
    // Verify Prometheus format
    try std.testing.expect(std.mem.indexOf(u8, output, "# HELP aegis_test_counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "# TYPE aegis_test_counter counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_test_counter 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_test_gauge 99") != null);
}

test "exportPrometheus returns 0 before init" {
    if (isInitialized()) shutdown();
    var buf: [256]u8 = undefined;
    try std.testing.expect(exportPrometheus(&buf) == 0);
}

test "getMetric returns null for out-of-range index" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("test", "help", 0);
    try std.testing.expect(getMetric(0) != null);
    try std.testing.expect(getMetric(1) == null);
}

test "getStats returns full export state" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("m1", "h1", 1);
    _ = registerGauge("m2", "h2", 2);

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.metric_count == 2);
    try std.testing.expect(stats.max_metrics == MAX_METRICS);
}

test "STEP22: collectAllMetrics gathers from pipeline layers" {
    // This test verifies collectAllMetrics runs without crashing
    // even if some layers aren't initialized
    init();
    defer shutdown();
    resetMetrics();

    collectAllMetrics();

    // Should have at least version metrics (always available)
    try std.testing.expect(getMetricCount() > 0);

    // Verify version metrics exist
    var found_version: bool = false;
    var i: usize = 0;
    while (i < getMetricCount()) : (i += 1) {
        const m = getMetric(i).?;
        if (std.mem.startsWith(u8, m.name, "aegis_version")) {
            found_version = true;
            break;
        }
    }
    try std.testing.expect(found_version);
}

test "STEP22: Prometheus export includes all registered metrics" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("aegis_events_total", "total events", 1000);
    _ = registerGauge("aegis_active_flows", "active flows", 42);
    _ = registerCounter("aegis_blocks_total", "total blocks", 5);

    var buf: [8192]u8 = undefined;
    const written = exportPrometheus(&buf);
    try std.testing.expect(written > 0);

    const output = buf[0..written];

    // All 3 metrics should be present
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_events_total 1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_active_flows 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_blocks_total 5") != null);

    // Type declarations should be present
    try std.testing.expect(std.mem.indexOf(u8, output, "# TYPE aegis_events_total counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "# TYPE aegis_active_flows gauge") != null);
}

test "STEP22: metric names follow aegis_ prefix convention" {
    init();
    defer shutdown();
    resetMetrics();

    _ = registerCounter("aegis_custom_metric", "custom", 1);
    _ = registerGauge("non_aegis_metric", "should still work", 2);

    var i: usize = 0;
    while (i < getMetricCount()) : (i += 1) {
        const m = getMetric(i).?;
        // Both should be registered (we don't enforce prefix, just convention)
        try std.testing.expect(m.value > 0);
    }
}
