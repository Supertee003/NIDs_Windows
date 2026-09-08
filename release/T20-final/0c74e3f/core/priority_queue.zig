//! priority_queue.zig - AEGIS Priority Event Queue (Phase 25, AEGIS-005)
//!
//! 3-priority event queue for event routing between subsystems.
//! Critical events (BLOCK) are processed before normal events (MATCH),
//! which are processed before low-priority events (FORWARD).
//!
//! Priority levels:
//!   HIGH (0)   - Critical/Block events, must be processed immediately
//!   NORMAL (1) - Match/Alert events, processed in order
//!   LOW (2)    - Forward/Info events, can be delayed
//!
//! Each priority level has its own EventQueue (from event_queue.zig).
//! pop() always checks HIGH first, then NORMAL, then LOW.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const EventQueue = @import("event_queue.zig").EventQueue;

// ============================================================
// Priority Levels (AEGIS-005)
// ============================================================

pub const Priority = enum(u8) {
    high = 0,    // Critical/Block events
    normal = 1,  // Match/Alert events
    low = 2,     // Forward/Info events

    /// Determine priority from CanonicalEvent fields.
    pub fn fromEvent(event: *const canonical.CanonicalEvent) Priority {
        return switch (event.event_type) {
            .block, .ip_blocked, .rejected => .high,
            .match_, .session_start, .session_end => .normal,
            .forward, .ruleset_reload, .startup, .shutdown, .custom => .low,
        };
    }

    pub fn toString(self: Priority) []const u8 {
        return switch (self) {
            .high => "high",
            .normal => "normal",
            .low => "low",
        };
    }
};

pub const PRIORITY_COUNT: usize = 3;
pub const DEFAULT_PRIORITY_CAPACITY: usize = 256;

// ============================================================
// PriorityQueue (AEGIS-005)
// ============================================================

pub const PriorityQueue = struct {
    queues: [PRIORITY_COUNT]EventQueue,
    total_pushed: std.atomic.Value(u64),
    total_dropped: std.atomic.Value(u64),

    /// Initialize with per-queue capacity.
    pub fn init(allocator: std.mem.Allocator, capacity_per_queue: usize) !PriorityQueue {
        return .{
            .queues = .{
                try EventQueue.init(allocator, capacity_per_queue),
                try EventQueue.init(allocator, capacity_per_queue),
                try EventQueue.init(allocator, capacity_per_queue),
            },
            .total_pushed = std.atomic.Value(u64).init(0),
            .total_dropped = std.atomic.Value(u64).init(0),
        };
    }

    /// Destroy and free all queues.
    pub fn deinit(self: *PriorityQueue, allocator: std.mem.Allocator) void {
        for (&self.queues) |*q| {
            q.deinit(allocator);
        }
    }

    /// Push an event with auto-determined priority.
    /// Returns false if dropped (queue full).
    pub fn push(self: *PriorityQueue, event: canonical.CanonicalEvent) bool {
        const priority = Priority.fromEvent(&event);
        return self.pushWithPriority(event, priority);
    }

    /// Push an event with explicit priority.
    pub fn pushWithPriority(self: *PriorityQueue, event: canonical.CanonicalEvent, priority: Priority) bool {
        const idx = @intFromEnum(priority);
        const ok = self.queues[idx].push(event);
        if (ok) {
            _ = self.total_pushed.fetchAdd(1, .monotonic);
        } else {
            _ = self.total_dropped.fetchAdd(1, .monotonic);
        }
        return ok;
    }

    /// Pop the highest-priority event available.
    /// Checks HIGH → NORMAL → LOW. Returns null if all empty.
    pub fn pop(self: *PriorityQueue) ?canonical.CanonicalEvent {
        // Check high priority first
        if (self.queues[@intFromEnum(Priority.high)].pop()) |e| return e;
        // Then normal
        if (self.queues[@intFromEnum(Priority.normal)].pop()) |e| return e;
        // Then low
        if (self.queues[@intFromEnum(Priority.low)].pop()) |e| return e;
        return null;
    }

    /// Get total items across all priority levels.
    pub fn len(self: *PriorityQueue) usize {
        var total: usize = 0;
        for (&self.queues) |*q| {
            total += q.len();
        }
        return total;
    }

    /// Get items in a specific priority level.
    pub fn lenByPriority(self: *PriorityQueue, priority: Priority) usize {
        return self.queues[@intFromEnum(priority)].len();
    }

    /// Get total dropped count across all priorities.
    pub fn droppedCount(self: *PriorityQueue) u64 {
        var total: u64 = 0;
        for (&self.queues) |*q| {
            total += q.droppedCount();
        }
        return total;
    }

    /// Check if all queues are empty.
    pub fn isEmpty(self: *PriorityQueue) bool {
        for (&self.queues) |*q| {
            if (!q.isEmpty()) return false;
        }
        return true;
    }

    /// Clear all priority queues.
    pub fn clear(self: *PriorityQueue) void {
        for (&self.queues) |*q| {
            q.clear();
        }
    }

    /// Get statistics for monitoring.
    pub fn getStats(self: *PriorityQueue) PriorityStats {
        return .{
            .high_count = self.queues[0].len(),
            .normal_count = self.queues[1].len(),
            .low_count = self.queues[2].len(),
            .high_dropped = self.queues[0].droppedCount(),
            .normal_dropped = self.queues[1].droppedCount(),
            .low_dropped = self.queues[2].droppedCount(),
            .total_pushed = self.total_pushed.load(.monotonic),
            .total_dropped = self.total_dropped.load(.monotonic),
        };
    }
};

pub const PriorityStats = struct {
    high_count: usize,
    normal_count: usize,
    low_count: usize,
    high_dropped: u64,
    normal_dropped: u64,
    low_dropped: u64,
    total_pushed: u64,
    total_dropped: u64,
};

// ============================================================
// Tests (AEGIS-005)
// ============================================================

test "Priority.fromEvent maps block to high" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(Priority.fromEvent(&event) == .high);
}

test "Priority.fromEvent maps match to normal" {
    var event = canonical.create(.zig_core);
    event.event_type = .match_;
    try std.testing.expect(Priority.fromEvent(&event) == .normal);
}

test "Priority.fromEvent maps forward to low" {
    var event = canonical.create(.zig_core);
    event.event_type = .forward;
    try std.testing.expect(Priority.fromEvent(&event) == .low);
}

test "PriorityQueue init and deinit" {
    var pq = try PriorityQueue.init(std.testing.allocator, 16);
    defer pq.deinit(std.testing.allocator);
    try std.testing.expect(pq.isEmpty());
}

test "PriorityQueue pop returns high first" {
    var pq = try PriorityQueue.init(std.testing.allocator, 16);
    defer pq.deinit(std.testing.allocator);

    // Push in reverse priority order
    var low_event = canonical.create(.zig_core);
    low_event.event_type = .forward;
    low_event.event_id = 1;
    _ = pq.push(low_event);

    var normal_event = canonical.create(.zig_core);
    normal_event.event_type = .match_;
    normal_event.event_id = 2;
    _ = pq.push(normal_event);

    var high_event = canonical.create(.zig_core);
    high_event.event_type = .block;
    high_event.event_id = 3;
    _ = pq.push(high_event);

    // Pop should return high first
    const first = pq.pop().?;
    try std.testing.expect(first.event_id == 3);
    try std.testing.expect(first.event_type == .block);

    const second = pq.pop().?;
    try std.testing.expect(second.event_id == 2);

    const third = pq.pop().?;
    try std.testing.expect(third.event_id == 1);
}

test "PriorityQueue empty returns null" {
    var pq = try PriorityQueue.init(std.testing.allocator, 16);
    defer pq.deinit(std.testing.allocator);
    try std.testing.expect(pq.pop() == null);
}

test "PriorityQueue len tracks total" {
    var pq = try PriorityQueue.init(std.testing.allocator, 16);
    defer pq.deinit(std.testing.allocator);

    var e = canonical.create(.zig_core);
    e.event_type = .block;
    _ = pq.push(e);
    _ = pq.push(e);

    try std.testing.expect(pq.len() == 2);
    try std.testing.expect(pq.lenByPriority(.high) == 2);
    try std.testing.expect(pq.lenByPriority(.normal) == 0);
}

test "PriorityQueue overflow drops" {
    var pq = try PriorityQueue.init(std.testing.allocator, 2);
    defer pq.deinit(std.testing.allocator);

    var e = canonical.create(.zig_core);
    e.event_type = .block;

    _ = pq.push(e);
    _ = pq.push(e);
    try std.testing.expect(!pq.push(e)); // Drop

    try std.testing.expect(pq.droppedCount() == 1);
}

test "PriorityQueue getStats" {
    var pq = try PriorityQueue.init(std.testing.allocator, 16);
    defer pq.deinit(std.testing.allocator);

    var high_e = canonical.create(.zig_core);
    high_e.event_type = .block;
    _ = pq.push(high_e);

    var low_e = canonical.create(.zig_core);
    low_e.event_type = .forward;
    _ = pq.push(low_e);

    const stats = pq.getStats();
    try std.testing.expect(stats.high_count == 1);
    try std.testing.expect(stats.normal_count == 0);
    try std.testing.expect(stats.low_count == 1);
    try std.testing.expect(stats.total_pushed == 2);
}

test "Priority.toString" {
    try std.testing.expect(std.mem.eql(u8, Priority.high.toString(), "high"));
    try std.testing.expect(std.mem.eql(u8, Priority.normal.toString(), "normal"));
    try std.testing.expect(std.mem.eql(u8, Priority.low.toString(), "low"));
}
