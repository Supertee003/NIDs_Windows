//! nose_integration.zig - AEGIS Nose Integration (Rewrite Phase 4)
//!
//! REWRITE v3.0 Phase 4: Nose
//!
//! Sits between Sensors and Event Fabric.
//! Nose = intentional load shedding (sampling)
//! Fabric = congestion handling (queue overflow)
//!
//! Sensor lifecycle:
//!   Capture -> Timestamp -> Sequence -> Minimal normalization
//!   -> Provenance -> Validation -> Submit
//!
//! Principle: "แม่นก่อนเร็ว" (accurate before fast)
//! Event ที่ผิดตั้งแต่ต้นจะแก้ไม่ได้ในชั้นข้างบน
//!
//! Imports: canonical_event.zig + event_fabric.zig + priority_queue.zig (ALL EXIST)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const pq = @import("priority_queue.zig");

// ============================================================
// Submit result (richer than fabric's bool)
// ============================================================

pub const IntegratedSubmitResult = enum {
    accepted,
    dropped_at_source,
    dropped_by_fabric,
    rejected,
    not_initialized,
};

// ============================================================
// Sampling policy
// ============================================================

pub const SamplingPolicy = struct {
    medium_low_drop_fraction: f32 = 0.50,
    high_drop_low: bool = true,
    high_normal_drop_fraction: f32 = 0.0,
    saturated_drop_low_and_normal: bool = true,
    saturated_high_backoff_ns: u64 = 1_000_000,
    max_backoff_retries: u32 = 1,
    seed: u64 = 0xAE615A42,

    pub const default: SamplingPolicy = .{};
    pub const aggressive: SamplingPolicy = .{
        .medium_low_drop_fraction = 0.75,
        .high_normal_drop_fraction = 0.25,
        .saturated_high_backoff_ns = 5_000_000,
        .max_backoff_retries = 2,
    };
    pub const permissive: SamplingPolicy = .{
        .medium_low_drop_fraction = 0.0,
        .high_drop_low = false,
        .saturated_drop_low_and_normal = false,
    };
};

// ============================================================
// Sensor stats
// ============================================================

pub const SensorStats = struct {
    total_submits: u64,
    accepted: u64,
    dropped_at_source: u64,
    dropped_by_fabric: u64,
    rejected: u64,
    backoff_retries: u64,

    pub fn acceptRate(self: SensorStats) f32 {
        if (self.total_submits == 0) return 1.0;
        return @as(f32, @floatFromInt(self.accepted)) / @as(f32, @floatFromInt(self.total_submits));
    }
};

// ============================================================
// Integration state
// ============================================================

var g_initialized: bool = false;
var g_policy: SamplingPolicy = SamplingPolicy.default;
var g_stats: SensorStats = .{
    .total_submits = 0,
    .accepted = 0,
    .dropped_at_source = 0,
    .dropped_by_fabric = 0,
    .rejected = 0,
    .backoff_retries = 0,
};

// Per-sensor-type stats (9 sensor types)
const SENSOR_TYPE_COUNT: usize = 9;
var g_per_sensor_stats: [SENSOR_TYPE_COUNT]SensorStats = [_]SensorStats{
    .{ .total_submits = 0, .accepted = 0, .dropped_at_source = 0, .dropped_by_fabric = 0, .rejected = 0, .backoff_retries = 0 },
} ** SENSOR_TYPE_COUNT;

fn sensorStatsIndex(source: canonical.EventSource) usize {
    const idx = @intFromEnum(source);
    if (idx < SENSOR_TYPE_COUNT) return idx;
    return 0;
}

// ============================================================
// PRNG (deterministic xorshift for sampling)
// ============================================================

var g_prng_state: u64 = 0;

fn prngInit(seed: u64) void {
    g_prng_state = if (seed == 0) @as(u64, @intCast(std.time.milliTimestamp())) else seed;
    if (g_prng_state == 0) g_prng_state = 1;
}

fn prngNext() u64 {
    var x = g_prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_prng_state = x;
    return x;
}

fn shouldDrop(fraction: f32) bool {
    if (fraction <= 0.0) return false;
    if (fraction >= 1.0) return true;
    const r = @as(f32, @floatFromInt(prngNext() % 1000)) / 1000.0;
    return r < fraction;
}

// ============================================================
// Initialization
// ============================================================

pub fn init(policy: SamplingPolicy) void {
    g_policy = policy;
    g_initialized = true;
    g_stats = .{
        .total_submits = 0,
        .accepted = 0,
        .dropped_at_source = 0,
        .dropped_by_fabric = 0,
        .rejected = 0,
        .backoff_retries = 0,
    };
    for (&g_per_sensor_stats) |*s| {
        s.* = .{
            .total_submits = 0,
            .accepted = 0,
            .dropped_at_source = 0,
            .dropped_by_fabric = 0,
            .rejected = 0,
            .backoff_retries = 0,
        };
    }
    prngInit(policy.seed);
    std.log.info("[NOSE-INT] Nose integration initialized", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn currentPolicy() SamplingPolicy {
    return g_policy;
}

pub fn resetStats() void {
    g_stats = .{
        .total_submits = 0,
        .accepted = 0,
        .dropped_at_source = 0,
        .dropped_by_fabric = 0,
        .rejected = 0,
        .backoff_retries = 0,
    };
    for (&g_per_sensor_stats) |*s| {
        s.* = .{
            .total_submits = 0,
            .accepted = 0,
            .dropped_at_source = 0,
            .dropped_by_fabric = 0,
            .rejected = 0,
            .backoff_retries = 0,
        };
    }
}

// ============================================================
// Sampling decision (pure function)
// ============================================================

fn shouldDropAtSource(event: canonical.CanonicalEvent, pressure: fabric.Pressure, policy: SamplingPolicy) bool {
    if (pressure == .low) return false;

    const priority = pq.Priority.fromEvent(&event);

    switch (pressure) {
        .low => return false,
        .medium => {
            if (priority == .low) {
                return shouldDrop(policy.medium_low_drop_fraction);
            }
            return false;
        },
        .high => {
            if (priority == .low and policy.high_drop_low) {
                return true;
            }
            if (priority == .normal and policy.high_normal_drop_fraction > 0.0) {
                return shouldDrop(policy.high_normal_drop_fraction);
            }
            return false;
        },
        .saturated => {
            if (policy.saturated_drop_low_and_normal) {
                if (priority == .low or priority == .normal) return true;
            }
            return false;
        },
    }
}

// ============================================================
// Submit API
// ============================================================

pub fn submitWithSampling(event: canonical.CanonicalEvent, policy: SamplingPolicy) IntegratedSubmitResult {
    if (!fabric.isInitialized()) return .not_initialized;
    if (!g_initialized) {
        init(SamplingPolicy.default);
    }

    g_stats.total_submits += 1;
    const sensor_idx = sensorStatsIndex(event.source);
    g_per_sensor_stats[sensor_idx].total_submits += 1;

    const pressure = fabric.currentPressure();

    // Step 1: Sampling decision at source
    if (shouldDropAtSource(event, pressure, policy)) {
        g_stats.dropped_at_source += 1;
        g_per_sensor_stats[sensor_idx].dropped_at_source += 1;
        return .dropped_at_source;
    }

    // Step 2: Try to submit (with backoff for HIGH priority under saturation)
    var current_event = event;
    var retries: u32 = 0;
    while (true) {
        const result = fabric.submitWithBackpressure(current_event);
        if (result.accepted) {
            g_stats.accepted += 1;
            g_per_sensor_stats[sensor_idx].accepted += 1;
            return .accepted;
        }

        if (result.pressure != .saturated) {
            g_stats.rejected += 1;
            g_per_sensor_stats[sensor_idx].rejected += 1;
            return .rejected;
        }

        // Saturated — retry only if HIGH priority
        const priority = pq.Priority.fromEvent(&current_event);
        if (priority != .high or retries >= policy.max_backoff_retries) {
            g_stats.dropped_by_fabric += 1;
            g_per_sensor_stats[sensor_idx].dropped_by_fabric += 1;
            return .dropped_by_fabric;
        }

        std.time.sleep(policy.saturated_high_backoff_ns);
        g_stats.backoff_retries += 1;
        g_per_sensor_stats[sensor_idx].backoff_retries += 1;
        retries += 1;
    }
}

pub fn submit(event: canonical.CanonicalEvent) IntegratedSubmitResult {
    return submitWithSampling(event, g_policy);
}

// ============================================================
// Stats
// ============================================================

pub fn getStats() SensorStats {
    return g_stats;
}

pub fn getSensorStats(source: canonical.EventSource) SensorStats {
    return g_per_sensor_stats[sensorStatsIndex(source)];
}

// ============================================================
// Tests
// ============================================================

fn initAllLayers() void {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 64 }) catch {};
    init(SamplingPolicy.default);
}

fn shutdownAllLayers() void {
    const nose = @import("nose_contract.zig");
    nose.shutdownFabric(std.testing.allocator);
}

test "SamplingPolicy.default has sensible values" {
    const p = SamplingPolicy.default;
    try std.testing.expect(p.medium_low_drop_fraction == 0.50);
    try std.testing.expect(p.high_drop_low == true);
    try std.testing.expect(p.saturated_drop_low_and_normal == true);
    try std.testing.expect(p.max_backoff_retries == 1);
}

test "IntegratedSubmitResult enum has all variants" {
    try std.testing.expect(@intFromEnum(IntegratedSubmitResult.accepted) == 0);
    try std.testing.expect(@intFromEnum(IntegratedSubmitResult.dropped_at_source) != @intFromEnum(IntegratedSubmitResult.dropped_by_fabric));
}

test "submitWithSampling before fabric init returns not_initialized" {
    if (fabric.isInitialized()) {
        const nose = @import("nose_contract.zig");
        nose.shutdownFabric(std.testing.allocator);
    }
    init(SamplingPolicy.default);

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(submit(event) == .not_initialized);
}

test "submitWithSampling accepts valid event under low pressure" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    const result = submit(event);
    try std.testing.expect(result == .accepted);

    const stats = getStats();
    try std.testing.expect(stats.total_submits == 1);
    try std.testing.expect(stats.accepted == 1);
}

test "submitWithSampling rejects invalid event" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    var event = canonical.create(.zig_core);
    event.magic = 0xDEADBEEF;
    try std.testing.expect(submit(event) == .rejected);

    const stats = getStats();
    try std.testing.expect(stats.rejected == 1);
}

test "submitWithSampling drops low-priority at source under high pressure" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();
    init(.{ .seed = 42, .high_drop_low = true, .saturated_drop_low_and_normal = true });

    // Fill to 80% (HIGH queue full)
    var i: u32 = 0;
    while (i < 52) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    var low_event = canonical.create(.zig_core);
    low_event.event_type = .forward;
    try std.testing.expect(submit(low_event) == .dropped_at_source);
}

test "submitWithSampling accepts HIGH-priority even under high pressure" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();
    init(.{ .seed = 42, .high_drop_low = true });

    var i: u32 = 0;
    while (i < 52) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    var high_event = canonical.create(.zig_core);
    high_event.event_type = .block;
    try std.testing.expect(submit(high_event) == .accepted);
}

test "submitWithSampling drops low+normal at source under saturated" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();
    init(.{ .seed = 42, .saturated_drop_low_and_normal = true });

    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .saturated);

    var low_e = canonical.create(.zig_core);
    low_e.event_type = .forward;
    try std.testing.expect(submit(low_e) == .dropped_at_source);

    var normal_e = canonical.create(.zig_core);
    normal_e.event_type = .match_;
    try std.testing.expect(submit(normal_e) == .dropped_at_source);
}

test "SensorStats.acceptRate computes correctly" {
    const stats = SensorStats{
        .total_submits = 10,
        .accepted = 8,
        .dropped_at_source = 1,
        .dropped_by_fabric = 1,
        .rejected = 0,
        .backoff_retries = 0,
    };
    try std.testing.expect(stats.acceptRate() == 0.8);
}

test "SensorStats.acceptRate returns 1.0 for empty" {
    const stats = SensorStats{
        .total_submits = 0,
        .accepted = 0,
        .dropped_at_source = 0,
        .dropped_by_fabric = 0,
        .rejected = 0,
        .backoff_retries = 0,
    };
    try std.testing.expect(stats.acceptRate() == 1.0);
}

test "per-sensor stats track independently" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    var wfp_event = canonical.create(.wfp_sensor);
    wfp_event.event_type = .block;
    _ = submit(wfp_event);

    var pipe_event = canonical.create(.pipe_sensor);
    pipe_event.event_type = .block;
    _ = submit(pipe_event);

    const wfp_stats = getSensorStats(.wfp_sensor);
    const pipe_stats = getSensorStats(.pipe_sensor);
    try std.testing.expect(wfp_stats.total_submits == 1);
    try std.testing.expect(pipe_stats.total_submits == 1);
}

test "permissive policy never drops at source" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();
    init(SamplingPolicy.permissive);

    var i: u32 = 0;
    while (i < 52) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    var low_e = canonical.create(.zig_core);
    low_e.event_type = .forward;
    const result = submit(low_e);
    try std.testing.expect(result == .accepted);

    const stats = getStats();
    try std.testing.expect(stats.dropped_at_source == 0);
}
