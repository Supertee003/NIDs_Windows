// PATCH-35 - Replay Integrity & Comparison
// AEGIS NIDS v5.0+ -- Replay hash tracking, comparison, and integrity verification
//
// Provides:
//   - ReplayHashTracker: per-packet hash chain during replay
//   - ReplayComparison: compare two replays for determinism
//   - ReplayResult: full replay output with integrity proof

const std = @import("std");

// ============================================================================
// ReplayResult -- complete output of a single replay run
// ============================================================================
pub const ReplayResult = struct {
    packet_count: u64 = 0,
    byte_count: u64 = 0,
    start_ns: i128 = 0,
    end_ns: i128 = 0,
    first_pkt_ns: i128 = 0,
    last_pkt_ns: i128 = 0,
    replay_hash: [32]u8, // SHA-256 of all packet hashes
    error_count: u32 = 0,

    pub fn init() ReplayResult {
        return .{
            .replay_hash = [_]u8{0} ** 32,
        };
    }

    pub fn durationNs(self: *const ReplayResult) i128 {
        return self.end_ns - self.start_ns;
    }
};

// ============================================================================
// ReplayHashTracker -- accumulates a hash chain over replayed packets
// ============================================================================
pub const ReplayHashTracker = struct {
    hasher: std.crypto.hash.sha2.Sha256,
    packet_hashes: std.ArrayList([32]u8),
    packet_count: u64,

    pub fn init(allocator: std.mem.Allocator) ReplayHashTracker {
        return .{
            .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
            .packet_hashes = std.ArrayList([32]u8).init(allocator),
            .packet_count = 0,
        };
    }

    pub fn deinit(self: *ReplayHashTracker) void {
        self.packet_hashes.deinit();
    }

    /// Feed a single packet into the hash tracker.
    pub fn feedPacket(self: *ReplayHashTracker, ts_ns: i128, data: []const u8) !void {
        // Hash this packet: timestamp (16 bytes) + data length (8 bytes) + data
        var pkt_hash: [32]u8 = undefined;
        var pkt_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        pkt_hasher.update(std.mem.asBytes(&ts_ns));
        const data_len: u64 = data.len;
        pkt_hasher.update(std.mem.asBytes(&data_len));
        pkt_hasher.update(data);
        pkt_hasher.final(&pkt_hash);

        // Append per-packet hash to our chain
        try self.packet_hashes.append(pkt_hash);

        // Feed into the aggregate hasher
        self.hasher.update(&pkt_hash);
        self.packet_count += 1;
    }

    /// Finalize and return the replay hash.
    pub fn finalize(self: *ReplayHashTracker) [32]u8 {
        var final_hash: [32]u8 = undefined;
        self.hasher.final(&final_hash);
        return final_hash;
    }

    /// Get the count of packets tracked.
    pub fn count(self: *const ReplayHashTracker) u64 {
        return self.packet_count;
    }

    /// Get a specific packet hash by index.
    pub fn getPacketHash(self: *const ReplayHashTracker, index: usize) ?*const [32]u8 {
        if (index >= self.packet_hashes.items.len) return null;
        return &self.packet_hashes.items[index];
    }
};

// ============================================================================
// ReplayComparison -- compare two replay runs
// ============================================================================
pub const ReplayMismatch = struct {
    packet_index: u64,
    expected_hash: [32]u8,
    actual_hash: [32]u8,
};

pub const ReplayComparison = struct {
    match: bool,
    total_packets: u64,
    mismatch_count: u32,
    mismatches: std.ArrayList(ReplayMismatch),

    pub fn init(allocator: std.mem.Allocator) ReplayComparison {
        return .{
            .match = true,
            .total_packets = 0,
            .mismatch_count = 0,
            .mismatches = std.ArrayList(ReplayMismatch).init(allocator),
        };
    }

    pub fn deinit(self: *ReplayComparison) void {
        self.mismatches.deinit();
    }

    /// Compare two hash trackers and return the comparison result.
    pub fn compare(expected: *const ReplayHashTracker, actual: *const ReplayHashTracker) ReplayComparison {
        // This is a placeholder; real implementation needs an allocator.
        // Use compareAlloc instead.
        _ = expected;
        _ = actual;
        return .{
            .match = true,
            .total_packets = 0,
            .mismatch_count = 0,
            .mismatches = undefined, // caller must use compareAlloc
        };
    }

    /// Compare two hash trackers, returning full comparison with allocator.
    pub fn compareAlloc(
        allocator: std.mem.Allocator,
        expected: *const ReplayHashTracker,
        actual: *const ReplayHashTracker,
    ) !ReplayComparison {
        var comp = ReplayComparison.init(allocator);
        errdefer comp.deinit();

        const count = @min(expected.packet_hashes.items.len, actual.packet_hashes.items.len);
        comp.total_packets = @intCast(count);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (!std.mem.eql(u8, &expected.packet_hashes.items[i], &actual.packet_hashes.items[i])) {
                comp.match = false;
                comp.mismatch_count += 1;
                try comp.mismatches.append(.{
                    .packet_index = @intCast(i),
                    .expected_hash = expected.packet_hashes.items[i],
                    .actual_hash = actual.packet_hashes.items[i],
                });
            }
        }

        // If lengths differ, that's also a mismatch
        if (expected.packet_hashes.items.len != actual.packet_hashes.items.len) {
            comp.match = false;
        }

        return comp;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ReplayResult init" {
    const r = ReplayResult.init();
    try std.testing.expectEqual(@as(u64, 0), r.packet_count);
    try std.testing.expectEqual(@as(u32, 0), r.error_count);
    const zero_hash = [_]u8{0} ** 32;
    try std.testing.expectEqual(zero_hash, r.replay_hash);
}

test "ReplayResult duration" {
    var r = ReplayResult.init();
    r.start_ns = 1000;
    r.end_ns = 2000;
    try std.testing.expectEqual(@as(i128, 1000), r.durationNs());
}

test "ReplayHashTracker feeds packets" {
    var tracker = ReplayHashTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.feedPacket(1000, "packet1");
    try tracker.feedPacket(2000, "packet2");
    try std.testing.expectEqual(@as(u64, 2), tracker.count());

    const h = tracker.finalize();
    // Hash should be non-zero
    var all_zero = true;
    for (h) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "ReplayHashTracker deterministic" {
    var t1 = ReplayHashTracker.init(std.testing.allocator);
    defer t1.deinit();
    var t2 = ReplayHashTracker.init(std.testing.allocator);
    defer t2.deinit();

    try t1.feedPacket(1000, "data");
    try t2.feedPacket(1000, "data");

    const h1 = t1.finalize();
    const h2 = t2.finalize();
    try std.testing.expectEqual(h1, h2);
}

test "ReplayHashTracker different packets produce different hashes" {
    var t1 = ReplayHashTracker.init(std.testing.allocator);
    defer t1.deinit();
    var t2 = ReplayHashTracker.init(std.testing.allocator);
    defer t2.deinit();

    try t1.feedPacket(1000, "data_a");
    try t2.feedPacket(1000, "data_b");

    const h1 = t1.finalize();
    const h2 = t2.finalize();
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "ReplayHashTracker per-packet hash access" {
    var tracker = ReplayHashTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.feedPacket(1000, "pkt");
    const h0 = tracker.getPacketHash(0);
    try std.testing.expect(h0 != null);
    const h1 = tracker.getPacketHash(1);
    try std.testing.expect(h1 == null);
}

test "ReplayComparison identical replays match" {
    var t1 = ReplayHashTracker.init(std.testing.allocator);
    defer t1.deinit();
    var t2 = ReplayHashTracker.init(std.testing.allocator);
    defer t2.deinit();

    try t1.feedPacket(1000, "data");
    try t2.feedPacket(1000, "data");

    var comp = try ReplayComparison.compareAlloc(std.testing.allocator, &t1, &t2);
    defer comp.deinit();

    try std.testing.expect(comp.match);
    try std.testing.expectEqual(@as(u32, 0), comp.mismatch_count);
}

test "ReplayComparison different replays mismatch" {
    var t1 = ReplayHashTracker.init(std.testing.allocator);
    defer t1.deinit();
    var t2 = ReplayHashTracker.init(std.testing.allocator);
    defer t2.deinit();

    try t1.feedPacket(1000, "data_a");
    try t2.feedPacket(1000, "data_b");

    var comp = try ReplayComparison.compareAlloc(std.testing.allocator, &t1, &t2);
    defer comp.deinit();

    try std.testing.expect(!comp.match);
    try std.testing.expectEqual(@as(u32, 1), comp.mismatch_count);
}

test "ReplayComparison different lengths mismatch" {
    var t1 = ReplayHashTracker.init(std.testing.allocator);
    defer t1.deinit();
    var t2 = ReplayHashTracker.init(std.testing.allocator);
    defer t2.deinit();

    try t1.feedPacket(1000, "data");
    try t1.feedPacket(2000, "data2");
    try t2.feedPacket(1000, "data");

    var comp = try ReplayComparison.compareAlloc(std.testing.allocator, &t1, &t2);
    defer comp.deinit();

    try std.testing.expect(!comp.match);
}
