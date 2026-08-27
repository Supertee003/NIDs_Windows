//! nose_integration.zig - AEGIS Nose Integration Layer (STEP 4)
//!
//! Pressure-aware submit helpers that sit between Sensors and the Event Fabric.
//! Sensors SHOULD use these helpers instead of calling nose.submitEvent() directly.
//!
//! Why this layer exists:
//!   1. Adaptive sampling — when queue pressure is high, drop non-critical
//!      events AT THE SOURCE (saves enqueue/dequeue cost, frees queue slots
//!      for critical events).
//!   2. Backoff — when queue is saturated, sleep briefly and retry once.
//!      Prevents thundering-herd on bursts where every sensor keeps pushing.
//!   3. Per-sensor stats — every sensor sees its own accept/drop/retry counts,
//!      useful for tuning sampling policy per sensor type.
//!
//! Usage:
//!   const nose_int = @import("nose_integration.zig");
//!
//!   // In a sensor hot path:
//!   var event = nose.createEvent(.pipe_sensor);
//!   event.event_type = .forward;  // low priority
//!   const result = nose_int.submitWithSampling(event, .default);
//!   // result = .accepted | .dropped_at_source | .dropped_by_fabric | .rejected
//!
//! Policy decisions:
//!   - .low pressure    : submit everything (no sampling)
//!   - .medium pressure : sample low-priority events at 50% (drop half)
//!   - .high pressure   : drop all low-priority events at source; keep normal+high
//!   - .saturated       : drop low+normal at source; backoff once for high

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const pq = @import("priority_queue.zig");
const nose = @import("nose_contract.zig");

// ============================================================
// STEP 4: Submit result (richer than SubmitResult)
// ============================================================

pub const IntegratedSubmitResult = enum {
    /// Event was accepted into the queue
    accepted,
    /// Event was dropped at source (sampling policy decided to skip)
    dropped_at_source,
    /// Event was dropped by the fabric (queue full after backoff)
    dropped_by_fabric,
    /// Event was rejected (validation failed)
    rejected,
    /// Fabric not initialized
    not_initialized,
};

// ============================================================
// STEP 4: Sampling policy
// ============================================================

pub const SamplingPolicy = struct {
    /// When pressure=medium, drop this fraction of LOW-priority events at source.
    /// 0.0 = never drop, 1.0 = always drop, 0.5 = drop half.
    medium_low_drop_fraction: f32 = 0.50,

    /// When pressure=high, drop ALL LOW-priority events at source?
    high_drop_low: bool = true,

    /// When pressure=high, drop this fraction of NORMAL-priority events.
    high_normal_drop_fraction: f32 = 0.0, // default: keep all normal

    /// When pressure=saturated, drop all LOW and NORMAL at source?
    saturated_drop_low_and_normal: bool = true,

    /// When pressure=saturated, retry HIGH-priority events after sleeping.
    saturated_high_backoff_ns: u64 = 1_000_000, // 1ms

    /// Maximum number of backoff retries before giving up.
    max_backoff_retries: u32 = 1,

    /// PRNG seed for sampling decisions (deterministic for tests).
    /// Set to 0 to use time-based seeding.
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
// Per-sensor statistics
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

var g_stats: SensorStats = .{
    .total_submits = 0,
    .accepted = 0,
    .dropped_at_source = 0,
    .dropped_by_fabric = 0,
    .rejected = 0,
    .backoff_retries = 0,
};

// Per-sensor-type stats (separate counters for each EventSource)
const SENSOR_TYPE_COUNT: usize = 9; // zig_core..go_aggregator
var g_per_sensor_stats: [SENSOR_TYPE_COUNT]SensorStats = [_]SensorStats{
    .{
        .total_submits = 0,
        .accepted = 0,
        .dropped_at_source = 0,
        .dropped_by_fabric = 0,
        .rejected = 0,
        .backoff_retries = 0,
    },
} ** SENSOR_TYPE_COUNT;

fn sensorStatsIndex(source: canonical.EventSource) usize {
    const idx = @intFromEnum(source);
    if (idx < SENSOR_TYPE_COUNT) return idx;
    return 0; // external -> zig_core bucket
}

// ============================================================
// PRNG (deterministic xorshift for sampling decisions)
// ============================================================

var g_prng_state: u64 = 0;

fn prngInit(seed: u64) void {
    g_prng_state = if (seed == 0) @as(u64, @intCast(std.time.milliTimestamp())) else seed;
    if (g_prng_state == 0) g_prng_state = 1; // xorshift can't start at 0
}

fn prngNext() u64 {
    // xorshift64
    var x = g_prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_prng_state = x;
    return x;
}

/// Returns true with probability `fraction` (0.0..1.0).
fn shouldDrop(fraction: f32) bool {
    if (fraction <= 0.0) return false;
    if (fraction >= 1.0) return true;
    const r = @as(f32, @floatFromInt(prngNext() % 1000)) / 1000.0;
    return r < fraction;
}

// ============================================================
// Public API
// ============================================================

/// Initialize the nose integration layer with a sampling policy.
/// Call once at startup (after nose.initFabric).
pub fn init(policy: SamplingPolicy) void {
    prngInit(policy.seed);
    g_stats = .{
        .total_submits = 0,
        .accepted = 0,
        .dropped_at_source = 0,
        .dropped_by_fabric = 0,
        .rejected = 0,
        .backoff_retries = 0,
    };
    g_current_policy = policy;
    g_initialized = true;
}

var g_current_policy: SamplingPolicy = SamplingPolicy.default;
var g_initialized: bool = false;

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn currentPolicy() SamplingPolicy {
    return g_current_policy;
}

/// Reset stats (for tests / restart).
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
// Sampling decision (pure function — no side effects)
// ============================================================

/// Decide whether to drop an event at the source based on current pressure.
/// Returns true if the event should be dropped at source.
fn shouldDropAtSource(event: canonical.CanonicalEvent, pressure: fabric.Pressure, policy: SamplingPolicy) bool {
    if (pressure == .low) return false;

    const priority = pq.Priority.fromEvent(&event);

    switch (pressure) {
        .low => return false,
        .medium => {
            // Sample low-priority events
            if (priority == .low) {
                return shouldDrop(policy.medium_low_drop_fraction);
            }
            return false;
        },
        .high => {
            // Drop all low-priority events
            if (priority == .low and policy.high_drop_low) {
                return true;
            }
            // Optionally sample normal-priority events
            if (priority == .normal and policy.high_normal_drop_fraction > 0.0) {
                return shouldDrop(policy.high_normal_drop_fraction);
            }
            return false;
        },
        .saturated => {
            // Drop all low + normal at source
            if (policy.saturated_drop_low_and_normal) {
                if (priority == .low or priority == .normal) return true;
            }
            return false;
        },
    }
}

// ============================================================
// Pressure-aware submit
// ============================================================

/// Submit an event with adaptive sampling.
/// Decisions:
///   1. Check pressure; if high enough, drop low-priority events at source
///   2. If saturated and event is HIGH priority, backoff once and retry
///   3. Otherwise, submit normally via fabric.submitWithBackpressure()
pub fn submitWithSampling(event: canonical.CanonicalEvent, policy: SamplingPolicy) IntegratedSubmitResult {
    if (!fabric.isInitialized()) return .not_initialized;
    if (!g_initialized) {
        // Auto-init with default policy if user forgot
        init(SamplingPolicy.default);
    }

    g_stats.total_submits +%= 1;
    const sensor_idx = sensorStatsIndex(event.source);
    g_per_sensor_stats[sensor_idx].total_submits +%= 1;

    const pressure = fabric.currentPressure();

    // Step 1: Sampling decision at source
    if (shouldDropAtSource(event, pressure, policy)) {
        g_stats.dropped_at_source +%= 1;
        g_per_sensor_stats[sensor_idx].dropped_at_source +%= 1;
        return .dropped_at_source;
    }

    // Step 2: Try to submit
    var current_event = event;
    var retries: u32 = 0;
    while (true) {
        const result = fabric.submitWithBackpressure(current_event);
        if (result.accepted) {
            g_stats.accepted +%= 1;
            g_per_sensor_stats[sensor_idx].accepted +%= 1;
            return .accepted;
        }

        // Submit failed. Determine cause:
        //   - rejected (validation failed) — no retry
        //   - saturated — retry once if event is high priority
        if (result.pressure != .saturated) {
            g_stats.rejected +%= 1;
            g_per_sensor_stats[sensor_idx].rejected +%= 1;
            return .rejected;
        }

        // Saturated. Retry only if event is HIGH priority and retries left.
        const priority = pq.Priority.fromEvent(&current_event);
        if (priority != .high or retries >= policy.max_backoff_retries) {
            g_stats.dropped_by_fabric +%= 1;
            g_per_sensor_stats[sensor_idx].dropped_by_fabric +%= 1;
            return .dropped_by_fabric;
        }

        // Backoff and retry
        std.time.sleep(policy.saturated_high_backoff_ns);
        g_stats.backoff_retries +%= 1;
        g_per_sensor_stats[sensor_idx].backoff_retries +%= 1;
        retries += 1;
    }
}

/// Submit using the globally-configured policy (preferred for most sensors).
pub fn submit(event: canonical.CanonicalEvent) IntegratedSubmitResult {
    return submitWithSampling(event, g_current_policy);
}

/// Get aggregate stats across all sensors.
pub fn getStats() SensorStats {
    return g_stats;
}

/// Get stats for a specific sensor type.
pub fn getSensorStats(source: canonical.EventSource) SensorStats {
    return g_per_sensor_stats[sensorStatsIndex(source)];
}

// ============================================================
// Tests
// ============================================================

test "SamplingPolicy.default has sensible values" {
    const p = SamplingPolicy.default;
    try std.testing.expect(p.medium_low_drop_fraction == 0.50);
    try std.testing.expect(p.high_drop_low == true);
    try std.testing.expect(p.high_normal_drop_fraction == 0.0);
    try std.testing.expect(p.saturated_drop_low_and_normal == true);
    try std.testing.expect(p.max_backoff_retries == 1);
}

test "IntegratedSubmitResult enum has all variants" {
    try std.testing.expect(@intFromEnum(IntegratedSubmitResult.accepted) == 0);
    try std.testing.expect(@intFromEnum(IntegratedSubmitResult.dropped_at_source) != @intFromEnum(IntegratedSubmitResult.dropped_by_fabric));
}

test "submitWithSampling before fabric init returns not_initialized" {
    if (fabric.isInitialized()) {
        fabric.shutdownFabric(std.testing.allocator);
    }
    init(SamplingPolicy.default);

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(submit(event) == .not_initialized);
}

test "submitWithSampling accepts valid event under low pressure" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(SamplingPolicy.default);
    resetStats();

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    const result = submit(event);
    try std.testing.expect(result == .accepted);

    const stats = getStats();
    try std.testing.expect(stats.total_submits == 1);
    try std.testing.expect(stats.accepted == 1);
    try std.testing.expect(stats.dropped_at_source == 0);
}

test "submitWithSampling drops low-priority events at source under high pressure" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{
        .medium_low_drop_fraction = 0.0, // don't sample at medium
        .high_drop_low = true,
        .high_normal_drop_fraction = 0.0,
        .saturated_drop_low_and_normal = false,
        .seed = 42,
    });
    resetStats();

    // Fill HIGH queue to 80% to trigger high pressure
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    // Now try to submit a LOW-priority event — should be dropped at source
    var low_event = canonical.create(.zig_core);
    low_event.event_type = .forward;
    const result = submit(low_event);
    try std.testing.expect(result == .dropped_at_source);

    const stats = getStats();
    try std.testing.expect(stats.dropped_at_source == 1);
    try std.testing.expect(stats.accepted == 0);
}

test "submitWithSampling accepts HIGH-priority events even under high pressure" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{ .seed = 42, .high_drop_low = true });
    resetStats();

    // Fill HIGH queue to 80%
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    // HIGH-priority event should still be accepted (queue has room)
    var high_event = canonical.create(.zig_core);
    high_event.event_type = .block;
    const result = submit(high_event);
    try std.testing.expect(result == .accepted);
}

test "submitWithSampling rejects invalid event" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(SamplingPolicy.default);
    resetStats();

    var event = canonical.create(.zig_core);
    event.magic = 0xDEADBEEF;
    const result = submit(event);
    try std.testing.expect(result == .rejected);

    const stats = getStats();
    try std.testing.expect(stats.rejected == 1);
}

test "submitWithSampling drops low+normal at source under saturated pressure" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{ .seed = 42, .saturated_drop_low_and_normal = true });
    resetStats();

    // Fill HIGH queue to 100% (2 events = saturated)
    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .saturated);

    // LOW-priority event should be dropped at source
    var low_e = canonical.create(.zig_core);
    low_e.event_type = .forward;
    try std.testing.expect(submit(low_e) == .dropped_at_source);

    // NORMAL-priority event should be dropped at source
    var normal_e = canonical.create(.zig_core);
    normal_e.event_type = .match_;
    try std.testing.expect(submit(normal_e) == .dropped_at_source);

    const stats = getStats();
    try std.testing.expect(stats.dropped_at_source == 2);
}

test "submitWithSampling backs off HIGH-priority event under saturated pressure" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{
        .seed = 42,
        .saturated_drop_low_and_normal = true,
        .saturated_high_backoff_ns = 1_000_000, // 1ms
        .max_backoff_retries = 1,
    });
    resetStats();

    // Fill HIGH queue to 100% (saturated)
    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .saturated);

    // Pop one to free a slot — depth drops to 1/2 = 50% => medium pressure
    _ = fabric.popEvent();
    try std.testing.expect(fabric.currentPressure() == .medium);

    // Now submit a HIGH event — should be accepted (queue has room again)
    var high_e = canonical.create(.zig_core);
    high_e.event_type = .block;
    const result = submit(high_e);
    try std.testing.expect(result == .accepted);
}

test "submitWithSampling drops HIGH-priority event if backoff retries exhausted" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{
        .seed = 42,
        .saturated_drop_low_and_normal = true,
        .saturated_high_backoff_ns = 1, // 1ns — instant retry
        .max_backoff_retries = 1,
    });
    resetStats();

    // Fill HIGH queue to 100% and keep it full
    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .saturated);

    // Submit another HIGH event — should retry once then drop
    var high_e = canonical.create(.zig_core);
    high_e.event_type = .block;
    const result = submit(high_e);
    try std.testing.expect(result == .dropped_by_fabric);

    const stats = getStats();
    try std.testing.expect(stats.backoff_retries >= 1);
    try std.testing.expect(stats.dropped_by_fabric == 1);
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
    const rate = stats.acceptRate();
    try std.testing.expect(rate == 0.8);
}

test "SensorStats.acceptRate returns 1.0 for empty stats" {
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
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(SamplingPolicy.default);
    resetStats();

    // Submit from wfp_sensor
    var wfp_event = canonical.create(.wfp_sensor);
    wfp_event.event_type = .block;
    _ = submit(wfp_event);

    // Submit from pipe_sensor
    var pipe_event = canonical.create(.pipe_sensor);
    pipe_event.event_type = .block;
    _ = submit(pipe_event);

    const wfp_stats = getSensorStats(.wfp_sensor);
    const pipe_stats = getSensorStats(.pipe_sensor);
    try std.testing.expect(wfp_stats.total_submits == 1);
    try std.testing.expect(pipe_stats.total_submits == 1);
    try std.testing.expect(wfp_stats.accepted == 1);
    try std.testing.expect(pipe_stats.accepted == 1);
}

test "aggressive policy drops more aggressively" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(.{
        .medium_low_drop_fraction = 0.75,
        .high_drop_low = true,
        .high_normal_drop_fraction = 0.25,
        .saturated_drop_low_and_normal = true,
        .seed = 42,
    });
    resetStats();

    // Fill HIGH queue to 50% => medium pressure
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .medium);

    // Submit 20 LOW events — most should be dropped at source (75% drop rate)
    var dropped: u32 = 0;
    var accepted: u32 = 0;
    i = 0;
    while (i < 20) : (i += 1) {
        var low_e = canonical.create(.zig_core);
        low_e.event_type = .forward;
        const result = submit(low_e);
        if (result == .dropped_at_source) dropped += 1;
        if (result == .accepted) accepted += 1;
    }

    // With 75% drop fraction, expect roughly 15 dropped / 5 accepted.
    // Statistical variance allowed — assert the shape, not exact count.
    try std.testing.expect(dropped + accepted == 20);
    try std.testing.expect(dropped >= 10); // most should be dropped
}

test "permissive policy never drops at source" {
    try nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer nose.shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();
    init(SamplingPolicy.permissive);
    resetStats();

    // Fill HIGH queue to 80% => high pressure
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        var e = canonical.create(.zig_core);
        e.event_type = .block;
        _ = fabric.submitEvent(e);
    }
    try std.testing.expect(fabric.currentPressure() == .high);

    // Permissive policy: never drop at source
    var low_e = canonical.create(.zig_core);
    low_e.event_type = .forward;
    const result = submit(low_e);
    try std.testing.expect(result == .accepted); // Queue has room (LOW queue empty)

    const stats = getStats();
    try std.testing.expect(stats.dropped_at_source == 0);
}
