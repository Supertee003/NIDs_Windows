//! release_engineering.zig - AEGIS Release Engineering (Rewrite Phase 20)
//!
//! Build metadata, version management, and metrics export.
//! Provides system info, version string, and Prometheus-style metrics.
//!
//! Architecture:
//!   Release Engineering is a metadata/measurement module (not a pipeline stage).
//!   It collects stats from all subsystems and exports them for monitoring.
//!
//! Features:
//!   1. BuildInfo: version, build time, git hash, compiler version
//!   2. MetricsExporter: Prometheus-style text format (key-value pairs)
//!   3. SystemStats: aggregate stats from all subsystems

const std = @import("std");

// ============================================================
// Constants
// ============================================================

pub const VERSION_MAJOR: u8 = 3;
pub const VERSION_MINOR: u8 = 0;
pub const VERSION_PATCH: u8 = 0;
pub const VERSION_SUFFIX: []const u8 = "rewrite-phase20";

pub const BUILD_TARGET: []const u8 = "windows-x86_64";
pub const ZIG_VERSION: []const u8 = "0.13.0";

// ============================================================
// Build Info
// ============================================================

pub const BuildInfo = struct {
    major: u8,
    minor: u8,
    patch: u8,
    suffix: []const u8,
    target: []const u8,
    zig_version: []const u8,
    build_timestamp: i64,

    /// Returns version string like "3.0.0-rewrite-phase20"
    pub fn versionString(self: BuildInfo, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}-{s}", .{
            self.major, self.minor, self.patch, self.suffix,
        }) catch return "unknown";
    }

    /// Returns full version string with target
    pub fn fullVersionString(self: BuildInfo, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "AEGIS NIDS v{d}.{d}.{d}-{s} ({s}, Zig {s})", .{
            self.major, self.minor, self.patch, self.suffix,
            self.target, self.zig_version,
        }) catch return "unknown";
    }

    /// Returns true if this is a release build (no suffix)
    pub fn isRelease(self: BuildInfo) bool {
        return self.suffix.len == 0;
    }
};

pub fn currentBuildInfo() BuildInfo {
    return .{
        .major = VERSION_MAJOR,
        .minor = VERSION_MINOR,
        .patch = VERSION_PATCH,
        .suffix = VERSION_SUFFIX,
        .target = BUILD_TARGET,
        .zig_version = ZIG_VERSION,
        .build_timestamp = std.time.timestamp(),
    };
}

// ============================================================
// Metrics Exporter (Prometheus text format)
// ============================================================

pub const MetricEntry = struct {
    name: []const u8,
    value: u64,
    help: []const u8,
};

pub const MAX_METRICS: usize = 64;

pub const MetricsExporter = struct {
    entries: [MAX_METRICS]MetricEntry,
    count: usize,

    pub fn init() MetricsExporter {
        return .{
            .entries = undefined,
            .count = 0,
        };
    }

    /// Add a metric entry.
    pub fn addMetric(self: *MetricsExporter, name: []const u8, value: u64, help: []const u8) void {
        if (self.count < MAX_METRICS) {
            self.entries[self.count] = .{
                .name = name,
                .value = value,
                .help = help,
            };
            self.count += 1;
        }
    }

    /// Export metrics as Prometheus text format into buffer.
    /// Returns bytes written, or 0 if buffer too small.
    pub fn exportPrometheus(self: *const MetricsExporter, buf: []u8) usize {
        var written: usize = 0;
        for (0..self.count) |i| {
            const entry = self.entries[i];
            const remaining = buf[written..];
            const result = std.fmt.bufPrint(remaining, "# HELP {s} {s}\n# TYPE {s} counter\n{s} {d}\n", .{
                entry.name, entry.help,
                entry.name,
                entry.name, entry.value,
            }) catch break;
            written += result.len;
        }
        return written;
    }

    /// Current metric count.
    pub fn metricCount(self: *const MetricsExporter) usize {
        return self.count;
    }

    /// Clear all metrics.
    pub fn clear(self: *MetricsExporter) void {
        self.count = 0;
    }
};

// ============================================================
// System Stats (aggregate from all subsystems)
// ============================================================

pub const SystemStats = struct {
    // Flow Engine
    flow_total_flows: u64,
    flow_total_packets: u64,
    flow_total_bytes: u64,
    // Detection Engine
    detection_total_analyzed: u64,
    detection_total_threats: u64,
    // Correlation Engine
    correlation_total_alerts: u64,
    // Threat Intel
    threat_intel_total_matches: u64,
    // Brain
    brain_total_escalations: u64,
    // Policy
    policy_total_blocks: u64,
    policy_total_alerts: u64,
    policy_total_allows: u64,
    // PEP
    pep_total_executed: u64,
    pep_total_rejected: u64,
    pep_blocklist_size: usize,
    // Forensics
    forensics_total_logged: u64,
    forensics_buffer_count: usize,
    // E2E
    e2e_pass_rate: u8,
    // Performance
    perf_throughput_eps: f64,
    perf_slow_event_percent: u8,
    // Canary
    canary_health: u8, // 0=unknown, 1=healthy, 2=degraded, 3=failed
    canary_pass_rate: u8,
    // XDR
    xdr_total_incidents: u64,
    xdr_current_incidents: usize,
};

pub const CANARY_HEALTH_UNKNOWN: u8 = 0;
pub const CANARY_HEALTH_HEALTHY: u8 = 1;
pub const CANARY_HEALTH_DEGRADED: u8 = 2;
pub const CANARY_HEALTH_FAILED: u8 = 3;

// ============================================================
// Release Engine
// ============================================================

pub const ReleaseEngine = struct {
    build_info: BuildInfo,
    exporter: MetricsExporter,
    total_exports: u64,

    pub fn init() ReleaseEngine {
        return .{
            .build_info = currentBuildInfo(),
            .exporter = MetricsExporter.init(),
            .total_exports = 0,
        };
    }

    /// Collect system stats and add them as metrics.
    pub fn collectStats(self: *ReleaseEngine, stats: SystemStats) void {
        self.exporter.clear();

        self.exporter.addMetric("aegis_flow_total_flows", stats.flow_total_flows, "Total flows tracked");
        self.exporter.addMetric("aegis_flow_total_packets", stats.flow_total_packets, "Total packets processed");
        self.exporter.addMetric("aegis_flow_total_bytes", stats.flow_total_bytes, "Total bytes processed");
        self.exporter.addMetric("aegis_detection_total_analyzed", stats.detection_total_analyzed, "Total events analyzed");
        self.exporter.addMetric("aegis_detection_total_threats", stats.detection_total_threats, "Total threats detected");
        self.exporter.addMetric("aegis_correlation_total_alerts", stats.correlation_total_alerts, "Total correlation alerts");
        self.exporter.addMetric("aegis_threat_intel_total_matches", stats.threat_intel_total_matches, "Total threat intel matches");
        self.exporter.addMetric("aegis_brain_total_escalations", stats.brain_total_escalations, "Total brain escalations");
        self.exporter.addMetric("aegis_policy_total_blocks", stats.policy_total_blocks, "Total block decisions");
        self.exporter.addMetric("aegis_policy_total_alerts", stats.policy_total_alerts, "Total alert decisions");
        self.exporter.addMetric("aegis_policy_total_allows", stats.policy_total_allows, "Total allow decisions");
        self.exporter.addMetric("aegis_pep_total_executed", stats.pep_total_executed, "Total PEP executions");
        self.exporter.addMetric("aegis_pep_total_rejected", stats.pep_total_rejected, "Total PEP rejections");
        self.exporter.addMetric("aegis_pep_blocklist_size", @as(u64, stats.pep_blocklist_size), "Current blocklist size");
        self.exporter.addMetric("aegis_forensics_total_logged", stats.forensics_total_logged, "Total forensic records logged");
        self.exporter.addMetric("aegis_forensics_buffer_count", @as(u64, stats.forensics_buffer_count), "Current forensic buffer count");
        self.exporter.addMetric("aegis_e2e_pass_rate", @as(u64, stats.e2e_pass_rate), "E2E test pass rate (0-100)");
        self.exporter.addMetric("aegis_perf_slow_event_percent", @as(u64, stats.perf_slow_event_percent), "Slow event percentage");
        self.exporter.addMetric("aegis_canary_health", @as(u64, stats.canary_health), "Canary health (0=unknown,1=healthy,2=degraded,3=failed)");
        self.exporter.addMetric("aegis_canary_pass_rate", @as(u64, stats.canary_pass_rate), "Canary pass rate (0-100)");
        self.exporter.addMetric("aegis_xdr_total_incidents", stats.xdr_total_incidents, "Total XDR incidents");
        self.exporter.addMetric("aegis_xdr_current_incidents", @as(u64, stats.xdr_current_incidents), "Current XDR incidents");
    }

    /// Export metrics as Prometheus text.
    pub fn exportMetrics(self: *ReleaseEngine, buf: []u8) usize {
        const len = self.exporter.exportPrometheus(buf);
        if (len > 0) self.total_exports += 1;
        return len;
    }

    /// Get build info.
    pub fn getBuildInfo(self: *const ReleaseEngine) BuildInfo {
        return self.build_info;
    }

    /// Get version string.
    pub fn versionString(self: *const ReleaseEngine, buf: []u8) []const u8 {
        return self.build_info.versionString(buf);
    }

    /// Current metric count.
    pub fn metricCount(self: *const ReleaseEngine) usize {
        return self.exporter.metricCount();
    }

    /// Reset.
    pub fn reset(self: *ReleaseEngine) void {
        self.exporter.clear();
        self.total_exports = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "BuildInfo.versionString returns correct format" {
    const info = BuildInfo{
        .major = 3,
        .minor = 0,
        .patch = 0,
        .suffix = "rewrite-phase20",
        .target = "windows-x86_64",
        .zig_version = "0.13.0",
        .build_timestamp = 1700000000,
    };
    var buf: [64]u8 = undefined;
    const version = info.versionString(&buf);
    try std.testing.expect(std.mem.eql(u8, version, "3.0.0-rewrite-phase20"));
}

test "BuildInfo.fullVersionString includes all info" {
    const info = currentBuildInfo();
    var buf: [128]u8 = undefined;
    const full = info.fullVersionString(&buf);
    try std.testing.expect(std.mem.startsWith(u8, full, "AEGIS NIDS v3.0.0-"));
    try std.testing.expect(std.mem.indexOf(u8, full, "windows-x86_64") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "0.13.0") != null);
}

test "BuildInfo.isRelease" {
    const release = BuildInfo{
        .major = 3, .minor = 0, .patch = 0, .suffix = "",
        .target = "windows-x86_64", .zig_version = "0.13.0",
        .build_timestamp = 0,
    };
    try std.testing.expect(release.isRelease());

    const dev = currentBuildInfo();
    try std.testing.expect(!dev.isRelease());
}

test "currentBuildInfo returns correct version" {
    const info = currentBuildInfo();
    try std.testing.expect(info.major == VERSION_MAJOR);
    try std.testing.expect(info.minor == VERSION_MINOR);
    try std.testing.expect(info.patch == VERSION_PATCH);
    try std.testing.expect(std.mem.eql(u8, info.suffix, VERSION_SUFFIX));
}

test "MetricsExporter init has zero metrics" {
    const exporter = MetricsExporter.init();
    try std.testing.expect(exporter.metricCount() == 0);
}

test "MetricsExporter addMetric increases count" {
    var exporter = MetricsExporter.init();
    exporter.addMetric("test_metric", 42, "test help");
    try std.testing.expect(exporter.metricCount() == 1);
}

test "MetricsExporter addMetric respects MAX_METRICS" {
    var exporter = MetricsExporter.init();
    var i: usize = 0;
    while (i < MAX_METRICS + 10) : (i += 1) {
        exporter.addMetric("metric", i, "help");
    }
    try std.testing.expect(exporter.metricCount() == MAX_METRICS);
}

test "MetricsExporter exportPrometheus produces valid output" {
    var exporter = MetricsExporter.init();
    exporter.addMetric("aegis_test_count", 42, "test counter");

    var buf: [256]u8 = undefined;
    const len = exporter.exportPrometheus(&buf);

    try std.testing.expect(len > 0);
    const output = buf[0..len];
    // Should contain HELP, TYPE, and value
    try std.testing.expect(std.mem.indexOf(u8, output, "# HELP aegis_test_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "# TYPE aegis_test_count counter") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_test_count 42") != null);
}

test "MetricsExporter clear resets count" {
    var exporter = MetricsExporter.init();
    exporter.addMetric("test", 1, "help");
    try std.testing.expect(exporter.metricCount() == 1);

    exporter.clear();
    try std.testing.expect(exporter.metricCount() == 0);
}

test "ReleaseEngine init has correct build info" {
    const engine = ReleaseEngine.init();
    const info = engine.getBuildInfo();
    try std.testing.expect(info.major == VERSION_MAJOR);
    try std.testing.expect(info.minor == VERSION_MINOR);
    try std.testing.expect(info.patch == VERSION_PATCH);
    try std.testing.expect(engine.total_exports == 0);
    try std.testing.expect(engine.metricCount() == 0);
}

test "ReleaseEngine versionString works" {
    const engine = ReleaseEngine.init();
    var buf: [64]u8 = undefined;
    const version = engine.versionString(&buf);
    try std.testing.expect(std.mem.startsWith(u8, version, "3.0.0-"));
}

test "ReleaseEngine collectStats adds all metrics" {
    var engine = ReleaseEngine.init();

    const stats = SystemStats{
        .flow_total_flows = 100,
        .flow_total_packets = 5000,
        .flow_total_bytes = 500000,
        .detection_total_analyzed = 5000,
        .detection_total_threats = 50,
        .correlation_total_alerts = 10,
        .threat_intel_total_matches = 5,
        .brain_total_escalations = 8,
        .policy_total_blocks = 20,
        .policy_total_alerts = 30,
        .policy_total_allows = 4950,
        .pep_total_executed = 20,
        .pep_total_rejected = 5,
        .pep_blocklist_size = 15,
        .forensics_total_logged = 5000,
        .forensics_buffer_count = 4096,
        .e2e_pass_rate = 100,
        .perf_throughput_eps = 1250.5,
        .perf_slow_event_percent = 5,
        .canary_health = CANARY_HEALTH_HEALTHY,
        .canary_pass_rate = 100,
        .xdr_total_incidents = 10,
        .xdr_current_incidents = 3,
    };

    engine.collectStats(stats);
    try std.testing.expect(engine.metricCount() > 10); // should have many metrics

    var buf: [4096]u8 = undefined;
    const len = engine.exportMetrics(&buf);
    try std.testing.expect(len > 0);
    try std.testing.expect(engine.total_exports == 1);

    const output = buf[0..len];
    // Verify some metrics are present
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_flow_total_flows 100") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_policy_total_blocks 20") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "aegis_canary_health 1") != null);
}

test "ReleaseEngine reset clears metrics" {
    var engine = ReleaseEngine.init();
    engine.exporter.addMetric("test", 1, "help");
    try std.testing.expect(engine.metricCount() == 1);

    engine.reset();
    try std.testing.expect(engine.metricCount() == 0);
    try std.testing.expect(engine.total_exports == 0);
}

test "ReleaseEngine exportMetrics returns 0 when no metrics" {
    const engine = ReleaseEngine.init();
    var buf: [256]u8 = undefined;
    const len = engine.exportMetrics(&buf);
    try std.testing.expect(len == 0);
}

test "SystemStats has all expected fields" {
    const stats = SystemStats{
        .flow_total_flows = 0,
        .flow_total_packets = 0,
        .flow_total_bytes = 0,
        .detection_total_analyzed = 0,
        .detection_total_threats = 0,
        .correlation_total_alerts = 0,
        .threat_intel_total_matches = 0,
        .brain_total_escalations = 0,
        .policy_total_blocks = 0,
        .policy_total_alerts = 0,
        .policy_total_allows = 0,
        .pep_total_executed = 0,
        .pep_total_rejected = 0,
        .pep_blocklist_size = 0,
        .forensics_total_logged = 0,
        .forensics_buffer_count = 0,
        .e2e_pass_rate = 0,
        .perf_throughput_eps = 0,
        .perf_slow_event_percent = 0,
        .canary_health = CANARY_HEALTH_UNKNOWN,
        .canary_pass_rate = 0,
        .xdr_total_incidents = 0,
        .xdr_current_incidents = 0,
    };
    // Just verify it compiles and has all fields
    try std.testing.expect(stats.flow_total_flows == 0);
    try std.testing.expect(stats.canary_health == CANARY_HEALTH_UNKNOWN);
    try std.testing.expect(stats.xdr_current_incidents == 0);
}

test "canary health constants" {
    try std.testing.expect(CANARY_HEALTH_UNKNOWN == 0);
    try std.testing.expect(CANARY_HEALTH_HEALTHY == 1);
    try std.testing.expect(CANARY_HEALTH_DEGRADED == 2);
    try std.testing.expect(CANARY_HEALTH_FAILED == 3);
}
