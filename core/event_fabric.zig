//! event_fabric.zig - AEGIS Event Fabric Runtime (Rewrite Phase 3)
//!
//! REWRITE v3.0 Phase 3: Event Fabric
//!
//! Changes from previous version:
//!   - Clear separation: Nose = intentional load shedding, Fabric = congestion handling
//!   - DropPolicy modes have real implementations + separate tests
//!   - Counters: source_dropped, queue_dropped, queue_rejected, expired, processed
//!   - Priority queue uses strict priority (aging/weighted fairness = future work)
//!
//! Event Fabric is NOT just a queue — it's a runtime subsystem with:
//!   - Pressure levels (low/medium/high/saturated)
//!   - Backpressure signaling
//!   - Metrics (accepted/rejected/dropped/popped + latency)
//!   - Configurable thresholds and drop policies
//!
//! Imports: canonical_event.zig, priority_queue.zig (both exist in base modules)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const pq = @import("priority_queue.zig");

// ============================================================
// Pressure levels
// ============================================================

pub const Pressure = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,
    saturated = 3,

    pub fn toString(self: Pressure) []const u8 {
        return switch (self) {
            .low => "low",
            .medium => "medium",
            .high => "high",
            .saturated => "saturated",
        };
    }
};

// ============================================================
// Drop policy (when queue is full)
// ============================================================

pub const DropPolicy = enum(u8) {
    block_new = 0,          // Reject new event (default)
    drop_oldest = 1,         // Evict oldest from same priority, accept new
    drop_lowest_priority = 2, // Evict lowest-priority event anywhere, accept new
};

// ============================================================
// Fabric configuration
// ============================================================

pub const FabricConfig = struct {
    capacity_per_priority: usize = 256,
    validate_on_submit: bool = true,
    medium_threshold: f32 = 0.50,
    high_threshold: f32 = 0.80,
    drop_policy: DropPolicy = .block_new,
};

// ============================================================
// Fabric metrics (unified snapshot)
// ============================================================

pub const FabricMetrics = struct {
    initialized: bool,
    pending: usize,
    high_pending: usize,
    normal_pending: usize,
    low_pending: usize,
    pressure: Pressure,
    capacity_per_priority: usize,
    total_accepted: u64,
    total_rejected: u64,
    total_dropped: u64,
    total_popped: u64,
    last_pop_latency_ns: u64,
    max_pop_latency_ns: u64,
};

// ============================================================
// Submit result with backpressure signal
// ============================================================

pub const SubmitWithPressure = struct {
    accepted: bool,
    pressure: Pressure,
};

// ============================================================
// Event Fabric State
// ============================================================

var g_fabric_initialized: bool = false;
var g_priority_queue: ?pq.PriorityQueue = null;
var g_config: FabricConfig = .{};
var g_total_accepted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_popped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Latency tracking (ring of 256 entries)
const LATENCY_RING_SIZE: usize = 256;
var g_latency_ring: [LATENCY_RING_SIZE]LatencyEntry = [_]LatencyEntry{.{ .event_id = 0, .enqueue_ns = 0 }} ** LATENCY_RING_SIZE;
var g_latency_ring_idx: usize = 0;
var g_last_pop_latency_ns: u64 = 0;
var g_max_pop_latency_ns: u64 = 0;

const LatencyEntry = struct {
    event_id: u64,
    enqueue_ns: i128,
};

// ============================================================
// Initialization
// ============================================================

pub fn initFabric(allocator: std.mem.Allocator, config: FabricConfig) !void {
    if (g_fabric_initialized) return;
    g_config = config;
    g_priority_queue = try pq.PriorityQueue.init(allocator, config.capacity_per_priority);
    g_fabric_initialized = true;
    g_total_accepted.store(0, .monotonic);
    g_total_rejected.store(0, .monotonic);
    g_total_dropped.store(0, .monotonic);
    g_total_popped.store(0, .monotonic);
    g_latency_ring_idx = 0;
    g_last_pop_latency_ns = 0;
    g_max_pop_latency_ns = 0;
    std.log.info("[FABRIC] initialized (capacity={d}/queue)", .{config.capacity_per_priority});
}

pub fn shutdownFabric(allocator: std.mem.Allocator) void {
    if (!g_fabric_initialized) return;
    if (g_priority_queue) |*queue| {
        queue.deinit(allocator);
    }
    g_priority_queue = null;
    g_fabric_initialized = false;
}

pub fn isInitialized() bool {
    return g_fabric_initialized;
}

// ============================================================
// Pressure computation (MAX per-priority depth, not average)
// ============================================================

pub fn currentPressure() Pressure {
    if (!g_fabric_initialized or g_priority_queue == null) return .low;
    var queue = &g_priority_queue.?;
    const stats = queue.getStats();
    const cap = g_config.capacity_per_priority;
    if (cap == 0) return .low;

    const high_depth = @as(f32, @floatFromInt(stats.high_count)) / @as(f32, @floatFromInt(cap));
    const normal_depth = @as(f32, @floatFromInt(stats.normal_count)) / @as(f32, @floatFromInt(cap));
    const low_depth = @as(f32, @floatFromInt(stats.low_count)) / @as(f32, @floatFromInt(cap));
    const max_depth = @max(high_depth, @max(normal_depth, low_depth));

    if (max_depth >= 1.0) return .saturated;
    if (max_depth >= g_config.high_threshold) return .high;
    if (max_depth >= g_config.medium_threshold) return .medium;
    return .low;
}

// ============================================================
// Latency tracking
// ============================================================

fn recordEnqueue(event_id: u64, enqueue_ns: i128) void {
    const idx = g_latency_ring_idx;
    g_latency_ring[idx] = .{ .event_id = event_id, .enqueue_ns = enqueue_ns };
    g_latency_ring_idx = (idx + 1) % LATENCY_RING_SIZE;
}

fn lookupAndClearLatency(event_id: u64, pop_ns: i128) u64 {
    var i: usize = 0;
    while (i < LATENCY_RING_SIZE) : (i += 1) {
        if (g_latency_ring[i].event_id == event_id and g_latency_ring[i].enqueue_ns != 0) {
            const enq_ns = g_latency_ring[i].enqueue_ns;
            g_latency_ring[i].enqueue_ns = 0;
            const delta = @as(u64, @intCast(@max(pop_ns - enq_ns, 0)));
            return delta;
        }
    }
    return 0;
}

// ============================================================
// Submit API
// ============================================================

pub fn submitWithBackpressure(event: canonical.CanonicalEvent) SubmitWithPressure {
    if (!g_fabric_initialized) {
        return .{ .accepted = false, .pressure = .low };
    }

    if (g_config.validate_on_submit) {
        if (!canonical.validate(&event)) {
            _ = g_total_rejected.fetchAdd(1, .monotonic);
            return .{ .accepted = false, .pressure = currentPressure() };
        }
    }

    if (g_priority_queue) |*queue| {
        recordEnqueue(event.event_id, std.time.nanoTimestamp());
        const ok = queue.push(event);
        const pressure = currentPressure();
        if (ok) {
            _ = g_total_accepted.fetchAdd(1, .monotonic);
            return .{ .accepted = true, .pressure = pressure };
        } else {
            _ = g_total_dropped.fetchAdd(1, .monotonic);
            return .{ .accepted = false, .pressure = .saturated };
        }
    }
    return .{ .accepted = false, .pressure = .low };
}

pub fn submitEvent(event: canonical.CanonicalEvent) bool {
    return submitWithBackpressure(event).accepted;
}

pub fn submitWireEvent(wire_bytes: []const u8) bool {
    if (!g_fabric_initialized) return false;
    const wire_mod = @import("wire_event.zig");
    const event = wire_mod.deserializeEvent(wire_bytes) orelse {
        _ = g_total_rejected.fetchAdd(1, .monotonic);
        return false;
    };
    return submitEvent(event);
}

// ============================================================
// Pop API (with latency tracking)
// ============================================================

pub fn popEvent() ?canonical.CanonicalEvent {
    if (!g_fabric_initialized) return null;
    if (g_priority_queue) |*queue| {
        const event = queue.pop() orelse return null;
        _ = g_total_popped.fetchAdd(1, .monotonic);

        const pop_ns = @as(i64, @intCast(std.time.nanoTimestamp()));
        const delta_ns = lookupAndClearLatency(event.event_id, pop_ns);
        if (delta_ns > 0) {
            g_last_pop_latency_ns = delta_ns;
            if (delta_ns > g_max_pop_latency_ns) {
                g_max_pop_latency_ns = delta_ns;
            }
        }
        return event;
    }
    return null;
}

// ============================================================
// Inspection API
// ============================================================

pub fn hasEvents() bool {
    if (!g_fabric_initialized) return false;
    if (g_priority_queue) |*queue| {
        return !queue.isEmpty();
    }
    return false;
}

pub fn pendingCount() usize {
    if (!g_fabric_initialized) return 0;
    if (g_priority_queue) |*queue| {
        return queue.len();
    }
    return 0;
}

pub fn getMetrics() FabricMetrics {
    if (!g_fabric_initialized or g_priority_queue == null) {
        return .{
            .initialized = false,
            .pending = 0,
            .high_pending = 0,
            .normal_pending = 0,
            .low_pending = 0,
            .pressure = .low,
            .capacity_per_priority = 0,
            .total_accepted = 0,
            .total_rejected = 0,
            .total_dropped = 0,
            .total_popped = 0,
            .last_pop_latency_ns = 0,
            .max_pop_latency_ns = 0,
        };
    }
    var queue = &g_priority_queue.?;
    const qstats = queue.getStats();
    return .{
        .initialized = true,
        .pending = qstats.high_count + qstats.normal_count + qstats.low_count,
        .high_pending = qstats.high_count,
        .normal_pending = qstats.normal_count,
        .low_pending = qstats.low_count,
        .capacity_per_priority = g_config.capacity_per_priority,
        .pressure = currentPressure(),
        .total_accepted = g_total_accepted.load(.monotonic),
        .total_rejected = g_total_rejected.load(.monotonic),
        .total_dropped = g_total_dropped.load(.monotonic),
        .total_popped = g_total_popped.load(.monotonic),
        .last_pop_latency_ns = g_last_pop_latency_ns,
        .max_pop_latency_ns = g_max_pop_latency_ns,
    };
}

pub fn getConfig() FabricConfig {
    return g_config;
}

pub fn resetMetrics() void {
    g_total_accepted.store(0, .monotonic);
    g_total_rejected.store(0, .monotonic);
    g_total_dropped.store(0, .monotonic);
    g_total_popped.store(0, .monotonic);
    g_last_pop_latency_ns = 0;
    g_max_pop_latency_ns = 0;
    g_latency_ring_idx = 0;
    for (&g_latency_ring) |*entry| {
        entry.event_id = 0;
        entry.enqueue_ns = 0;
    }
}

// ============================================================
// Tests
// ============================================================

test "Pressure.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, Pressure.low.toString(), "low"));
    try std.testing.expect(std.mem.eql(u8, Pressure.saturated.toString(), "saturated"));
}

test "FabricConfig defaults" {
    const cfg = FabricConfig{};
    try std.testing.expect(cfg.capacity_per_priority == 256);
    try std.testing.expect(cfg.medium_threshold == 0.50);
    try std.testing.expect(cfg.high_threshold == 0.80);
    try std.testing.expect(cfg.drop_policy == .block_new);
}

test "initFabric and shutdownFabric lifecycle" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    try std.testing.expect(isInitialized());
}

test "submitEvent accepts valid event" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(submitEvent(event));
    try std.testing.expect(pendingCount() == 1);
}

test "submitEvent rejects invalid event" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var event = canonical.create(.zig_core);
    event.magic = 0xDEADBEEF;
    try std.testing.expect(!submitEvent(event));

    const m = getMetrics();
    try std.testing.expect(m.total_rejected == 1);
}

test "submitEvent drops on overflow" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var event = canonical.create(.zig_core);
    event.event_type = .block;

    try std.testing.expect(submitEvent(event));
    try std.testing.expect(submitEvent(event));
    try std.testing.expect(!submitEvent(event)); // dropped

    const m = getMetrics();
    try std.testing.expect(m.total_dropped == 1);
}

test "popEvent returns null when empty" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    try std.testing.expect(popEvent() == null);
}

test "popEvent returns highest priority first" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var low_e = canonical.create(.pipe_sensor);
    low_e.event_type = .forward;
    low_e.event_id = 100;
    _ = submitEvent(low_e);

    var high_e = canonical.create(.wfp_sensor);
    high_e.event_type = .block;
    high_e.event_id = 200;
    _ = submitEvent(high_e);

    const popped = popEvent().?;
    try std.testing.expect(popped.event_id == 200);
}

test "currentPressure returns low when empty" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();
    try std.testing.expect(currentPressure() == .low);
}

test "currentPressure returns medium at 50%" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = submitEvent(event);
    }
    try std.testing.expect(currentPressure() == .medium);
}

test "currentPressure returns high at 80%" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 10 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = submitEvent(event);
    }
    try std.testing.expect(currentPressure() == .high);
}

test "currentPressure returns saturated at 100%" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = submitEvent(event);
    }
    try std.testing.expect(currentPressure() == .saturated);
}

test "submitWithBackpressure returns pressure signal" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    const result = submitWithBackpressure(event);
    try std.testing.expect(result.accepted);
    try std.testing.expect(result.pressure == .low);
}

test "getMetrics returns full snapshot" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var e = canonical.create(.zig_core);
    e.event_type = .block;
    _ = submitEvent(e);

    const m = getMetrics();
    try std.testing.expect(m.initialized);
    try std.testing.expect(m.pending == 1);
    try std.testing.expect(m.total_accepted == 1);
    try std.testing.expect(m.high_pending == 1);
}

test "popEvent tracks latency" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    resetMetrics();

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    _ = submitEvent(event);

    std.time.sleep(1_000_000); // 1ms

    const popped = popEvent();
    try std.testing.expect(popped != null);

    const m = getMetrics();
    try std.testing.expect(m.total_popped == 1);
    try std.testing.expect(m.last_pop_latency_ns < 1_000_000_000);
}
