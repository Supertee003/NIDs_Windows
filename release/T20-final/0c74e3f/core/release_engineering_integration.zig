//! release_engineering_integration.zig - AEGIS Release Engineering Integration (Rewrite Phase 20)
//!
//! Thin facade over release_engineering.zig that owns a singleton ReleaseEngine.

const std = @import("std");
const rel = @import("release_engineering.zig");

var g_engine: ?rel.ReleaseEngine = null;
var g_initialized: bool = false;

pub fn init() void {
    if (g_initialized) return;
    g_engine = rel.ReleaseEngine.init();
    g_initialized = true;
    std.log.info("[RELEASE] Release engineering initialized (v{d}.{d}.{d}-{s})", .{
        rel.VERSION_MAJOR, rel.VERSION_MINOR, rel.VERSION_PATCH, rel.VERSION_SUFFIX,
    });
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    if (g_engine) |*engine| {
        engine.reset();
    }
}

pub fn collectStats(stats: rel.SystemStats) void {
    if (!g_initialized) return;
    if (g_engine) |*engine| {
        engine.collectStats(stats);
    }
}

pub fn exportMetrics(buf: []u8) usize {
    if (!g_initialized) return 0;
    if (g_engine) |*engine| {
        return engine.exportMetrics(buf);
    }
    return 0;
}

pub fn getBuildInfo() rel.BuildInfo {
    if (g_engine) |*engine| {
        return engine.getBuildInfo();
    }
    return rel.currentBuildInfo();
}

pub fn versionString(buf: []u8) []const u8 {
    if (g_engine) |*engine| {
        return engine.versionString(buf);
    }
    return "unknown";
}

pub fn metricCount() usize {
    if (g_engine) |*engine| {
        return engine.metricCount();
    }
    return 0;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[RELEASE] Release engineering shutdown", .{});
}

test "release integration: full lifecycle" {
    if (g_initialized) shutdown();

    // Not initialized
    var buf: [256]u8 = undefined;
    try std.testing.expect(exportMetrics(&buf) == 0);

    // Init
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    // Build info
    const info = getBuildInfo();
    try std.testing.expect(info.major == rel.VERSION_MAJOR);
    var vbuf: [64]u8 = undefined;
    const ver = versionString(&vbuf);
    try std.testing.expect(std.mem.startsWith(u8, ver, "3.0.0-"));

    // Collect stats
    const stats = rel.SystemStats{
        .flow_total_flows = 10,
        .flow_total_packets = 100,
        .flow_total_bytes = 1000,
        .detection_total_analyzed = 100,
        .detection_total_threats = 5,
        .correlation_total_alerts = 2,
        .threat_intel_total_matches = 1,
        .brain_total_escalations = 1,
        .policy_total_blocks = 3,
        .policy_total_alerts = 2,
        .policy_total_allows = 95,
        .pep_total_executed = 3,
        .pep_total_rejected = 1,
        .pep_blocklist_size = 2,
        .forensics_total_logged = 100,
        .forensics_buffer_count = 50,
        .e2e_pass_rate = 100,
        .perf_throughput_eps = 500.0,
        .perf_slow_event_percent = 0,
        .canary_health = rel.CANARY_HEALTH_HEALTHY,
        .canary_pass_rate = 100,
        .xdr_total_incidents = 3,
        .xdr_current_incidents = 1,
    };
    collectStats(stats);
    try std.testing.expect(metricCount() > 10);

    // Export
    var ebuf: [4096]u8 = undefined;
    const len = exportMetrics(&ebuf);
    try std.testing.expect(len > 0);

    // Reset
    resetStats();
    try std.testing.expect(metricCount() == 0);

    // Double-init/double-shutdown
    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());

    // After shutdown
    try std.testing.expect(exportMetrics(&buf) == 0);
}
