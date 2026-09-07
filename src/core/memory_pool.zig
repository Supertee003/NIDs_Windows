// I04 - Memory Pool & Lock-Free Ring Buffers
// AEGIS NIDS v5.0+ â€” Pre-allocated memory pools, no runtime allocation in
// hot paths. SPMC/MPSC ring buffers for cross-thread event passing.
//
// Hot-path rule: NEVER call `std.heap` allocators when capturing or detecting.
// All buffers are pre-allocated at startup from a single arena.

const std = @import("std");

// ============================================================================
// 1. Slab Allocator â€” fixed-size object pool
// ============================================================================
pub fn SlabPool(comptime T: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        items: [N]T = undefined,
        free_list: [N]u32 = undefined,
        free_head: u32 = 0,
        in_use: u32 = 0,
        mutex: std.Thread.Mutex = .{},

        pub fn init(self: *Self) void {
            self.free_head = 0;
            self.in_use = 0;
            var i: u32 = 0;
            while (i < N) : (i += 1) {
                self.free_list[i] = i + 1; // next free slot index
            }
            self.free_list[N - 1] = N; // last â†’ null
        }

        pub fn alloc(self: *Self) ?*T {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.free_head == @as(u32, @intCast(N))) return null;
            const idx = self.free_head;
            self.free_head = self.free_list[idx];
            self.in_use += 1;
            return &self.items[idx];
        }

        pub fn free(self: *Self, ptr: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            const base = @intFromPtr(&self.items[0]);
            const addr = @intFromPtr(ptr);
            const idx = (addr - base) / @sizeOf(T);
            std.debug.assert(idx < N);
            self.free_list[idx] = self.free_head;
            self.free_head = @intCast(idx);
            if (self.in_use > 0) self.in_use -= 1;
        }

        pub fn usage(self: *Self) f32 {
            return @as(f32, @floatFromInt(self.in_use)) / @as(f32, @floatFromInt(N));
        }
    };
}

// ============================================================================
// 2. SPMC Ring Buffer (single-producer, multi-consumer)
//    Used for capture â†’ detection pipeline
// ============================================================================
pub fn SPMCRing(comptime T: type, comptime N: comptime_int) type {
    return struct {
        const Self = @This();
        const MASK: usize = N - 1;
        comptime {
            if (N <= 0 or (N & MASK) != 0) {
                @compileError("SPMCRing size must be a power of two");
            }
        }
        buffer: [N]T = undefined,
        head: std.atomic.Value(u64) = std.atomic.Value(u64).init(0), // write
        tail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0), // read
        dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub fn tryPush(self: *Self, item: T) bool {
            const h = self.head.load(.acquire);
            const t = self.tail.load(.acquire);
            if (h - t >= N) {
                _ = self.dropped.fetchAdd(1, .monotonic);
                return false;
            }
            self.buffer[h & MASK] = item;
            self.head.store(h + 1, .release);
            return true;
        }

        pub fn tryPop(self: *Self) ?T {
            const t = self.tail.load(.acquire);
            const h = self.head.load(.acquire);
            if (t == h) return null;
            const item = self.buffer[t & MASK];
            self.tail.store(t + 1, .release);
            return item;
        }

        pub fn pending(self: *Self) u64 {
            const h = self.head.load(.acquire);
            const t = self.tail.load(.acquire);
            return h -% t;
        }

        pub fn drops(self: *Self) u64 {
            return self.dropped.load(.monotonic);
        }
    };
}

// ============================================================================
// 3. MPSC Ring Buffer (multi-producer, single-consumer)
//    Used for detection â†’ policy â†’ action pipeline
// ============================================================================
pub fn MPSCRing(comptime T: type, comptime N: comptime_int) type {
    return struct {
        const Self = @This();
        const MASK: usize = N - 1;
        comptime {
            if (N <= 0 or (N & MASK) != 0) {
                @compileError("MPSCRing size must be a power of two");
            }
        }
        buffer: [N]T = undefined,
        // head: writer claims a slot via CAS
        head: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        // committed: writers mark slots ready
        committed: [N]std.atomic.Value(u32) = [_]std.atomic.Value(u32){std.atomic.Value(u32).init(0)} ** N,
        tail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub fn tryPush(self: *Self, item: T) bool {
            const h = self.head.fetchAdd(1, .acq_rel);
            const t = self.tail.load(.acquire);
            if (h -% t >= N) {
                // queue full â†’ undo head claim and drop
                _ = self.dropped.fetchAdd(1, .monotonic);
                // Note: we cannot truly "undo" the head claim without ABA issues;
                // we leave a "stolen" slot that the consumer will skip via the
                // committed flag (set to 0 = stolen).
                return false;
            }
            self.buffer[h & MASK] = item;
            self.committed[h & MASK].store(1, .release);
            return true;
        }

        pub fn tryPop(self: *Self) ?T {
            const t = self.tail.load(.acquire);
            const h = self.head.load(.acquire);
            if (t == h) return null;
            const slot = t & MASK;
            const ready = self.committed[slot].load(.acquire);
            if (ready == 0) {
                // stolen slot â€” skip it
                self.tail.store(t + 1, .release);
                return null;
            }
            const item = self.buffer[slot];
            self.committed[slot].store(0, .release);
            self.tail.store(t + 1, .release);
            return item;
        }

        pub fn pending(self: *Self) u64 {
            const h = self.head.load(.acquire);
            const t = self.tail.load(.acquire);
            return h -% t;
        }
    };
}

// ============================================================================
// 4. Byte Arena â€” fixed-size byte buffer pool (for variable-length payloads)
// ============================================================================
pub const ByteArena = struct {
    storage: []u8,
    offset: usize = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, size: usize) !ByteArena {
        return .{ .storage = try allocator.alloc(u8, size) };
    }

    pub fn deinit(self: *ByteArena, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }

    pub fn alloc(self: *ByteArena, n: usize) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const aligned = std.mem.alignForward(usize, n, 8);
        if (self.offset + aligned > self.storage.len) return null;
        const slice = self.storage[self.offset .. self.offset + n];
        self.offset += aligned;
        return slice;
    }

    pub fn reset(self: *ByteArena) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.offset = 0;
    }

    pub fn used(self: *ByteArena) usize {
        return self.offset;
    }

    pub fn capacity(self: *ByteArena) usize {
        return self.storage.len;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "SlabPool alloc/free round-trip" {
    var pool: SlabPool(u64, 16) = .{};
    pool.init();
    const p1 = pool.alloc() orelse return error.OutOfMem;
    const p2 = pool.alloc() orelse return error.OutOfMem;
    try std.testing.expect(p1 != p2);
    p1.* = 0xDEADBEEF;
    p2.* = 0xCAFEBABE;
    pool.free(p1);
    pool.free(p2);
    try std.testing.expectEqual(@as(u32, 0), pool.in_use);
}

test "SlabPool exhaustion returns null" {
    var pool: SlabPool(u32, 2) = .{};
    pool.init();
    const a = pool.alloc().?;
    const b = pool.alloc().?;
    const c = pool.alloc();
    try std.testing.expect(c == null);
    pool.free(a);
    pool.free(b);
}

test "SPMCRing push/pop ordering" {
    var ring: SPMCRing(u32, 4) = .{};
    try std.testing.expect(ring.tryPush(1));
    try std.testing.expect(ring.tryPush(2));
    try std.testing.expect(ring.tryPush(3));
    try std.testing.expectEqual(@as(u32, 1), ring.tryPop().?);
    try std.testing.expectEqual(@as(u32, 2), ring.tryPop().?);
    try std.testing.expectEqual(@as(u32, 3), ring.tryPop().?);
    try std.testing.expect(ring.tryPop() == null);
}

test "SPMCRing drop on full" {
    var ring: SPMCRing(u32, 2) = .{};
    try std.testing.expect(ring.tryPush(1));
    try std.testing.expect(ring.tryPush(2));
    try std.testing.expect(!ring.tryPush(3));
    try std.testing.expectEqual(@as(u64, 1), ring.drops());
}

test "MPSCRing single-threaded" {
    var ring: MPSCRing(u32, 4) = .{};
    try std.testing.expect(ring.tryPush(10));
    try std.testing.expect(ring.tryPush(20));
    try std.testing.expectEqual(@as(u32, 10), ring.tryPop().?);
    try std.testing.expectEqual(@as(u32, 20), ring.tryPop().?);
}

test "ByteArena basic alloc" {
    var buf: [128]u8 = undefined;
    var arena = ByteArena{ .storage = &buf };
    const a = arena.alloc(16).?;
    const b = arena.alloc(32).?;
    try std.testing.expect(a.ptr != b.ptr);
    try std.testing.expectEqual(@as(usize, 48), arena.used()); // 16 + 32, 8-aligned
    arena.reset();
    try std.testing.expectEqual(@as(usize, 0), arena.used());
}
