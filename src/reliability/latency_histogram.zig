// II09 - Performance Telemetry (Latency Histogram)
// AEGIS NIDS v5.0+ â€” HDR-style fixed-bucket latency histogram
//
// Tracks per-stage latency (captureâ†’detect, detectâ†’policy, policyâ†’action).
// Bucket boundaries are powers of 2 (1, 2, 4, 8, ... Âµs).

const std = @import("std");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const NUM_BUCKETS: usize = manifest.Limits.LATENCY_HISTOGRAM_BUCKETS;

pub const LatencyHistogram = struct {
    buckets: [NUM_BUCKETS]u64 = [_]u64{0} ** NUM_BUCKETS,
    count: u64 = 0,
    sum_ns: u64 = 0,
    min_ns: u64 = std.math.maxInt(u64),
    max_ns: u64 = 0,

    pub fn observe(self: *LatencyHistogram, latency_ns: u64) void {
        self.count += 1;
        self.sum_ns += latency_ns;
        if (latency_ns < self.min_ns) self.min_ns = latency_ns;
        if (latency_ns > self.max_ns) self.max_ns = latency_ns;
        // Bucket: log2 of latency (1ns=0, 2ns=1, 4ns=2, ...)
        var bucket: usize = 0;
        var v = latency_ns;
        while (v > 1 and bucket < NUM_BUCKETS - 1) {
            v >>= 1;
            bucket += 1;
        }
        self.buckets[bucket] += 1;
    }

    pub fn p50(self: *const LatencyHistogram) u64 {
        return self.percentile(0.5);
    }

    pub fn p95(self: *const LatencyHistogram) u64 {
        return self.percentile(0.95);
    }

    pub fn p99(self: *const LatencyHistogram) u64 {
        return self.percentile(0.99);
    }

    pub fn percentile(self: *const LatencyHistogram, p: f64) u64 {
        if (self.count == 0) return 0;
        const target = @as(u64, @intFromFloat(@ceil(@as(f64, @floatFromInt(self.count)) * p)));
        var acc: u64 = 0;
        for (self.buckets, 0..) |b, i| {
            acc += b;
            if (acc >= target) {
                return @as(u64, 1) << @intCast(i);
            }
        }
        return self.max_ns;
    }

    pub fn mean(self: *const LatencyHistogram) f64 {
        if (self.count == 0) return 0;
        return @as(f64, @floatFromInt(self.sum_ns)) / @as(f64, @floatFromInt(self.count));
    }

    pub fn reset(self: *LatencyHistogram) void {
        @memset(&self.buckets, 0);
        self.count = 0;
        self.sum_ns = 0;
        self.min_ns = std.math.maxInt(u64);
        self.max_ns = 0;
    }
};

// ============================================================================
// Per-stage tracker
// ============================================================================
pub const Stage = enum(u8) {
    capture_to_decode = 1,
    decode_to_flow = 2,
    flow_to_detection = 3,
    detection_to_correlation = 4,
    correlation_to_policy = 5,
    policy_to_action = 6,
    action_to_forensic = 7,
};

pub const PerfTracker = struct {
    stages: [16]LatencyHistogram = [_]LatencyHistogram{.{}} ** 16,
    last_snapshot_ns: i128 = 0,

    pub fn observe(self: *PerfTracker, stage: Stage, latency_ns: u64) void {
        self.stages[@intFromEnum(stage)].observe(latency_ns);
    }

    pub fn snapshot(self: *PerfTracker) PerfSnapshot {
        var snap = PerfSnapshot{};
        inline for (@typeInfo(Stage).Enum.fields, 0..) |f, i| {
            const src = @intFromEnum(@as(Stage, @enumFromInt(f.value)));
            snap.stages[i] = .{
                .name = f.name,
                .count = self.stages[src].count,
                .p50_ns = self.stages[src].p50(),
                .p95_ns = self.stages[src].p95(),
                .p99_ns = self.stages[src].p99(),
                .mean_ns = self.stages[src].mean(),
                .max_ns = self.stages[src].max_ns,
            };
        }
        self.last_snapshot_ns = std.time.nanoTimestamp();
        return snap;
    }
};

pub const StageSnapshot = struct {
    name: []const u8,
    count: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    mean_ns: f64,
    max_ns: u64,
};

pub const PerfSnapshot = struct {
    stages: [@typeInfo(Stage).Enum.fields.len]StageSnapshot = undefined,

    pub fn print(self: *const PerfSnapshot, writer: anytype) !void {
        try writer.print("{s:<28} {s:>10} {s:>10} {s:>10} {s:>10} {s:>10}\n", .{
            "Stage", "count", "p50", "p95", "p99", "max",
        });
        for (self.stages) |s| {
            try writer.print("{s:<28} {d:>10} {d:>10} {d:>10} {d:>10} {d:>10}\n", .{
                s.name, s.count, s.p50_ns, s.p95_ns, s.p99_ns, s.max_ns,
            });
        }
    }
};

// ============================================================================
// Tests
// ============================================================================
test "LatencyHistogram basic stats" {
    var h = LatencyHistogram{};
    h.observe(1);
    h.observe(2);
    h.observe(4);
    h.observe(8);
    h.observe(16);
    try std.testing.expectEqual(@as(u64, 5), h.count);
    try std.testing.expectEqual(@as(u64, 1), h.min_ns);
    try std.testing.expectEqual(@as(u64, 16), h.max_ns);
    try std.testing.expectEqual(@as(u64, 4), h.p50()); // median of {1,2,4,8,16} = 4
}

test "LatencyHistogram p99" {
    var h = LatencyHistogram{};
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        h.observe(i + 1);
    }
    const p99 = h.p99();
    try std.testing.expect(p99 > 0);
}

test "PerfTracker snapshot" {
    var pt = PerfTracker{};
    pt.observe(.capture_to_decode, 100);
    pt.observe(.capture_to_decode, 200);
    pt.observe(.policy_to_action, 1000);
    const snap = pt.snapshot();
    try std.testing.expect(snap.stages[0].count >= 1);
}

test "LatencyHistogram reset" {
    var h = LatencyHistogram{};
    h.observe(100);
    h.observe(200);
    h.reset();
    try std.testing.expectEqual(@as(u64, 0), h.count);
    try std.testing.expectEqual(@as(u64, 0), h.sum_ns);
}
