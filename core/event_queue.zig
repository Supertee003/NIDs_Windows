//! event_queue.zig - AEGIS Thread-Safe Event Queue (Phase 24, AEGIS-004)
//!
//! Thread-safe bounded queue for CanonicalEvent passing between subsystems.
//! Uses mutex for thread-safety (B-06 equivalent on Zig side).
//!
//! Features:
//!   - Bounded capacity (prevents OOM)
//!   - Thread-safe Push/Pop via std.Thread.Mutex
//!   - Dropped counter for overflow monitoring
//!   - Non-blocking tryPop for polling
//!   - Capacity tracking for backpressure

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Configuration
// ============================================================

pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

// ============================================================
// Event Queue (AEGIS-004)
// ============================================================

pub const EventQueue = struct {
    buffer: []canonical.CanonicalEvent,
    head: usize,       // Read position
    tail: usize,       // Write position
    count: usize,      // Current items
    dropped: u64,      // Dropped due to overflow
    capacity: usize,
    mutex: std.Thread.Mutex,

    /// Initialize the queue with a given capacity.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !EventQueue {
        const buf = try allocator.alloc(canonical.CanonicalEvent, capacity);
        return EventQueue{
            .buffer = buf,
            .head = 0,
            .tail = 0,
            .count = 0,
            .dropped = 0,
            .capacity = capacity,
            .mutex = .{},
        };
    }

    /// Destroy the queue and free memory.
    pub fn deinit(self: *EventQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
    }

    /// Push an event onto the queue. Returns false if dropped (queue full).
    /// Thread-safe via mutex (AEGIS-004).
    pub fn push(self: *EventQueue, event: canonical.CanonicalEvent) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count >= self.capacity) {
            self.dropped += 1;
            return false;
        }

        self.buffer[self.tail] = event;
        self.tail = (self.tail + 1) % self.capacity;
        self.count += 1;
        return true;
    }

    /// Pop an event from the queue. Returns null if empty.
    /// Thread-safe via mutex (AEGIS-004).
    pub fn pop(self: *EventQueue) ?canonical.CanonicalEvent {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count == 0) return null;

        const event = self.buffer[self.head];
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;
        return event;
    }

    /// Non-blocking pop (same as pop, but explicit name for polling).
    pub fn tryPop(self: *EventQueue) ?canonical.CanonicalEvent {
        return self.pop();
    }

    /// Get current item count.
    pub fn len(self: *EventQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.count;
    }

    /// Get total dropped count.
    pub fn droppedCount(self: *EventQueue) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.dropped;
    }

    /// Check if queue is empty.
    pub fn isEmpty(self: *EventQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.count == 0;
    }

    /// Check if queue is full.
    pub fn isFull(self: *EventQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.count >= self.capacity;
    }

    /// Clear all events from the queue.
    pub fn clear(self: *EventQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
};

// ============================================================
// Tests (AEGIS-004: Ring Buffer stability)
// ============================================================

test "EventQueue init and deinit" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);
    try std.testing.expect(queue.capacity == 16);
    try std.testing.expect(queue.isEmpty());
}

test "EventQueue push and pop" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);

    var event = canonical.create(.zig_core);
    event.event_type = .block;
    try std.testing.expect(queue.push(event));
    try std.testing.expect(!queue.isEmpty());

    const popped = queue.pop();
    try std.testing.expect(popped != null);
    try std.testing.expect(popped.?.event_type == .block);
    try std.testing.expect(queue.isEmpty());
}

test "EventQueue FIFO order" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);

    var e1 = canonical.create(.wfp_sensor);
    e1.event_id = 100;
    var e2 = canonical.create(.pipe_sensor);
    e2.event_id = 200;
    var e3 = canonical.create(.minifilter);
    e3.event_id = 300;

    _ = queue.push(e1);
    _ = queue.push(e2);
    _ = queue.push(e3);

    try std.testing.expect(queue.pop().?.event_id == 100);
    try std.testing.expect(queue.pop().?.event_id == 200);
    try std.testing.expect(queue.pop().?.event_id == 300);
}

test "EventQueue overflow drops" {
    var queue = try EventQueue.init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    const e = canonical.create(.zig_core);
    try std.testing.expect(queue.push(e));
    try std.testing.expect(queue.push(e));
    try std.testing.expect(!queue.push(e)); // Should drop

    try std.testing.expect(queue.droppedCount() == 1);
    try std.testing.expect(queue.isFull());
}

test "EventQueue pop on empty returns null" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.pop() == null);
    try std.testing.expect(queue.tryPop() == null);
}

test "EventQueue clear" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);

    const e = canonical.create(.zig_core);
    _ = queue.push(e);
    _ = queue.push(e);
    _ = queue.push(e);

    queue.clear();
    try std.testing.expect(queue.isEmpty());
    try std.testing.expect(queue.len() == 0);
}

test "EventQueue wraparound" {
    var queue = try EventQueue.init(std.testing.allocator, 4);
    defer queue.deinit(std.testing.allocator);

    // Fill and drain multiple times to test wraparound
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const e = canonical.create(.zig_core);
        try std.testing.expect(queue.push(e));
        _ = queue.pop();
    }
    try std.testing.expect(queue.isEmpty());
}

test "EventQueue len tracks correctly" {
    var queue = try EventQueue.init(std.testing.allocator, 16);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.len() == 0);
    _ = queue.push(canonical.create(.zig_core));
    try std.testing.expect(queue.len() == 1);
    _ = queue.push(canonical.create(.wfp_sensor));
    try std.testing.expect(queue.len() == 2);
    _ = queue.pop();
    try std.testing.expect(queue.len() == 1);
}
