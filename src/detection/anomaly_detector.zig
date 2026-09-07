// I12 - Statistical Anomaly Detector
// AEGIS NIDS v5.0+ â€” EWMA + z-score based baseline anomaly detection
//
// Tracks per-(src_ip, metric) baselines:
//   - packet rate
//   - byte rate
//   - flow count
//   - new-connection rate
//
// When the observed metric deviates more than 3Ïƒ from the EWMA mean,
// an `anomaly_detected` event is emitted.

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");

pub const ALPHA: f64 = 0.05; // EWMA decay (small = sticky)
pub const Z_THRESHOLD: f64 = 3.0;
pub const WARMUP_SAMPLES: u32 = 30;

pub const Metric = struct {
    ewma: f64 = 0.0,
    m2: f64 = 0.0, // running second moment for variance
    count: u32 = 0,
    last_value: f64 = 0.0,
    last_z: f64 = 0.0,

    pub fn observe(self: *Metric, value: f64) ?f64 {
        self.last_value = value;
        if (self.count == 0) {
            self.ewma = value;
            self.count = 1;
            return null;
        }
        const delta = value - self.ewma;
        self.ewma = self.ewma + ALPHA * delta;
        const delta2 = value - self.ewma;
        self.m2 = (1 - ALPHA) * self.m2 + ALPHA * delta2 * delta2;
        self.count += 1;
        if (self.count < WARMUP_SAMPLES) return null;
        const variance = self.m2;
        const sigma = @sqrt(variance);
        if (sigma < 1e-9) return null;
        const z = @abs(value - self.ewma) / sigma;
        self.last_z = z;
        if (z > Z_THRESHOLD) return z;
        return null;
    }
};

pub const EntityKey = struct {
    src_ip: [16]u8,
    metric_kind: u8, // 1=pps, 2=bytes, 3=flows, 4=new_conns
};

pub const AnomalyDetector = struct {
    metrics: std.AutoHashMap(EntityKey, Metric),
    allocator: std.mem.Allocator,
    anomalies_emitted: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) AnomalyDetector {
        return .{
            .metrics = std.AutoHashMap(EntityKey, Metric).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AnomalyDetector) void {
        self.metrics.deinit();
    }

    pub fn observe(self: *AnomalyDetector, key: EntityKey, value: f64) !?f64 {
        const gop = try self.metrics.getOrPut(key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        return gop.value_ptr.observe(value);
    }

    pub fn metricCount(self: *const AnomalyDetector) usize {
        return self.metrics.count();
    }
};

// ============================================================================
// Tests
// ============================================================================
test "Metric warmup does not emit" {
    var m = Metric{};
    var i: u32 = 0;
    while (i < WARMUP_SAMPLES) : (i += 1) {
        const z = m.observe(10.0);
        try std.testing.expect(z == null);
    }
}

test "Metric detects spike after warmup" {
    var m = Metric{};
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        _ = m.observe(10.0);
    }
    // Now inject a spike
    const z = m.observe(100.0);
    try std.testing.expect(z != null);
    try std.testing.expect(z.? > Z_THRESHOLD);
}

test "Metric stable value does not emit" {
    var m = Metric{};
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const z = m.observe(10.0 + 0.1 * @sin(@as(f64, @floatFromInt(i))));
        try std.testing.expect(z == null);
    }
}

test "AnomalyDetector tracks per-entity" {
    var ad = AnomalyDetector.init(std.testing.allocator);
    defer ad.deinit();
    const k1 = EntityKey{ .src_ip = [_]u8{ 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .metric_kind = 1 };
    const k2 = EntityKey{ .src_ip = [_]u8{ 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .metric_kind = 1 };
    // Warmup k1 with low values, k2 with high values
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        _ = try ad.observe(k1, 5.0);
        _ = try ad.observe(k2, 50.0);
    }
    // k1 spiking to 50 should be anomalous; k2 staying at 50 should not
    const z1 = try ad.observe(k1, 50.0);
    const z2 = try ad.observe(k2, 50.0);
    try std.testing.expect(z1 != null);
    try std.testing.expect(z2 == null);
    try std.testing.expectEqual(@as(usize, 2), ad.metricCount());
}
