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
        // GAP-016: saturating (CORR-SAT-069 idiom). A plain += traps at
        // 2^32 same-key observations (~71 min at 1M eps) and kills the
        // pipeline thread in -ODebug builds.
        self.count +|= 1;
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

/// Baseline identity for one source address (V6-DETECT-037). A v2 sidecar
/// keys the baseline on all 16 bytes so two v6 hosts sharing first-4 bytes
/// never share a baseline; otherwise the zero-padded u32 identity, exactly
/// the key the pipeline used before sidecars existed. Pure function so the
/// contract is unit-pinned here, not only at the pipeline call site.
pub fn entityKeyBytes(sidecar: ?[16]u8, truncated_ip: u32) [16]u8 {
    if (sidecar) |full| return full;
    var ip: [16]u8 = [_]u8{0} ** 16;
    const b: [4]u8 = @bitCast(truncated_ip);
    @memcpy(ip[0..4], &b);
    return ip;
}

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
        const z = gop.value_ptr.observe(value);
        // ANOM-COUNT-035: the detector owns its emission count. A z-score
        // hit is one emitted anomaly, counted here — never in the pipeline.
        if (z != null) self.anomalies_emitted += 1;
        return z;
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

test "Metric count saturates instead of trapping (GAP-016)" {
    var m = Metric{};
    m.count = std.math.maxInt(u32);
    _ = m.observe(10.0);
    try std.testing.expectEqual(std.math.maxInt(u32), m.count);
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

test "pipeline byte-signal: metric_kind=2 baselines are per-IP and spike-sensitive" {
    // Pins the contract src/pipeline/event_processor.zig relies on: kind=2
    // observes payload bytes per src_ip, so a sudden large payload from one
    // host fires while steady hosts stay quiet.
    var ad = AnomalyDetector.init(std.testing.allocator);
    defer ad.deinit();
    const steady = EntityKey{ .src_ip = [_]u8{ 192, 168, 126, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .metric_kind = 2 };
    const spiker = EntityKey{ .src_ip = [_]u8{ 192, 168, 126, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .metric_kind = 2 };
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const wobble = 10.0 * @sin(@as(f64, @floatFromInt(i)));
        _ = try ad.observe(steady, 300.0 + wobble);
        _ = try ad.observe(spiker, 300.0 + wobble);
    }
    try std.testing.expect(try ad.observe(steady, 305.0) == null);
    try std.testing.expect(try ad.observe(spiker, 9000.0) != null);
}

test "AnomalyDetector owns its emission count" {
    // ANOM-COUNT-035: anomalies_emitted counts exactly the z-score hits the
    // detector reports — warmup and steady observations never increment it.
    var ad = AnomalyDetector.init(std.testing.allocator);
    defer ad.deinit();
    const k = EntityKey{ .src_ip = [_]u8{ 10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .metric_kind = 2 };
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        _ = try ad.observe(k, 300.0);
    }
    try std.testing.expectEqual(@as(u64, 0), ad.anomalies_emitted);
    // One spike: exactly one emission. (Further spikes are asserted only
    // for non-decrement — EWMA adapts, so exact counts after the first
    // spike are distribution-dependent, not contract.)
    _ = try ad.observe(k, 9000.0);
    try std.testing.expectEqual(@as(u64, 1), ad.anomalies_emitted);
}

test "entityKeyBytes prefers sidecar, falls back to padded u32" {
    // V6-DETECT-037: the fallback must be byte-identical to the historical
    // inline key so v1 behavior does not shift under existing baselines.
    const full = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    try std.testing.expectEqualSlices(u8, &full, &entityKeyBytes(full, 0x12345678));
    const legacy = blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const b: [4]u8 = @bitCast(@as(u32, 0xC0A8010A));
        @memcpy(ip[0..4], &b);
        break :blk ip;
    };
    try std.testing.expectEqualSlices(u8, &legacy, &entityKeyBytes(null, 0xC0A8010A));
}
