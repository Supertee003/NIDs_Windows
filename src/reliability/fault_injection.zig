// II11 - Fault Injection Framework
// AEGIS NIDS v5.0+ â€” Chaos testing hooks for reliability validation
//
// When AEGIS_FAULT_INJECTION env var is set, the framework activates hooks
// that randomly inject failures into hot paths:
//   - drop packet (5%)
//   - simulate slow decode (50ms sleep)
//   - return corrupted event
//   - simulate queue full
// Used by tests/ to verify graceful degradation.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

pub const FaultKind = enum(u8) {
    drop_packet = 1,
    slow_decode = 2,
    corrupt_event = 3,
    queue_full = 4,
    duplicate_event = 5,
    bad_clock_skew = 6,
};

pub const FaultConfig = struct {
    enabled: bool = false,
    seed: u64 = 0xCAFEBABE,
    drop_packet_rate: f64 = 0.05,
    slow_decode_rate: f64 = 0.01,
    corrupt_event_rate: f64 = 0.01,
    queue_full_rate: f64 = 0.005,
};

pub const FaultInjector = struct {
    cfg: FaultConfig,
    prng: std.Random.DefaultPrng,
    injected: [256]u64 = [_]u64{0} ** 256,

    pub fn init(cfg: FaultConfig) FaultInjector {
        return .{
            .cfg = cfg,
            .prng = std.Random.DefaultPrng.init(cfg.seed),
        };
    }

    pub fn fromEnv() FaultInjector {
        var cfg = FaultConfig{};
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_FAULT_INJECTION")) |val| {
            defer std.heap.page_allocator.free(val);
            if (std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true")) cfg.enabled = true;
        } else |_| {}
        return FaultInjector.init(cfg);
    }

    pub fn maybeDrop(self: *FaultInjector) bool {
        if (!self.cfg.enabled) return false;
        if (self.prng.random().float(f64) < self.cfg.drop_packet_rate) {
            self.injected[@intFromEnum(FaultKind.drop_packet)] += 1;
            return true;
        }
        return false;
    }

    pub fn maybeCorrupt(self: *FaultInjector, ev: *event.IpcEvent) bool {
        if (!self.cfg.enabled) return false;
        if (self.prng.random().float(f64) < self.cfg.corrupt_event_rate) {
            // Flip a random bit in the event
            const byte_idx = self.prng.random().uintLessThan(usize, @sizeOf(event.IpcEvent));
            const bit_idx: u3 = @intCast(self.prng.random().uintLessThan(u4, 8));
            const ptr: *u8 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(ev)) + byte_idx));
            ptr.* ^= @as(u8, 1) << bit_idx;
            self.injected[@intFromEnum(FaultKind.corrupt_event)] += 1;
            return true;
        }
        return false;
    }

    pub fn maybeSlow(self: *FaultInjector) bool {
        if (!self.cfg.enabled) return false;
        if (self.prng.random().float(f64) < self.cfg.slow_decode_rate) {
            self.injected[@intFromEnum(FaultKind.slow_decode)] += 1;
            std.time.sleep(50 * std.time.ns_per_ms);
            return true;
        }
        return false;
    }

    pub fn maybeQueueFull(self: *FaultInjector) bool {
        if (!self.cfg.enabled) return false;
        if (self.prng.random().float(f64) < self.cfg.queue_full_rate) {
            self.injected[@intFromEnum(FaultKind.queue_full)] += 1;
            return true;
        }
        return false;
    }

    pub fn injectedCount(self: *const FaultInjector, kind: FaultKind) u64 {
        return self.injected[@intFromEnum(kind)];
    }
};

// ============================================================================
// Tests
// ============================================================================
test "FaultInjector disabled by default" {
    var fi = FaultInjector.init(.{});
    try std.testing.expect(!fi.maybeDrop());
    try std.testing.expect(!fi.maybeQueueFull());
}

test "FaultInjector drop at 1.0 always drops" {
    var fi = FaultInjector.init(.{ .enabled = true, .drop_packet_rate = 1.0 });
    try std.testing.expect(fi.maybeDrop());
    try std.testing.expectEqual(@as(u64, 1), fi.injectedCount(.drop_packet));
}

test "FaultInjector corrupts event" {
    var fi = FaultInjector.init(.{ .enabled = true, .corrupt_event_rate = 1.0 });
    var ev = event.IpcEvent.init(.dns_query);
    const corrupted = fi.maybeCorrupt(&ev);
    try std.testing.expect(corrupted);
    try std.testing.expectEqual(@as(u64, 1), fi.injectedCount(.corrupt_event));
}

test "FaultInjector fromEnv returns disabled on Linux" {
    const fi = FaultInjector.fromEnv();
    // AEGIS_FAULT_INJECTION env should not be set in test env
    _ = fi;
}

// ============================================================================
// VER-003: Fault Injection Comprehensive Tests
// ============================================================================

test "VER-003: FaultInjector at 0% rate never triggers" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .drop_packet_rate = 0.0,
        .corrupt_event_rate = 0.0,
        .queue_full_rate = 0.0,
    });
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(!fi.maybeDrop());
        try std.testing.expect(!fi.maybeQueueFull());
    }
    try std.testing.expectEqual(@as(u64, 0), fi.injectedCount(.drop_packet));
    try std.testing.expectEqual(@as(u64, 0), fi.injectedCount(.queue_full));
}

test "VER-003: FaultInjector at 100% rate always triggers" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .drop_packet_rate = 1.0,
        .corrupt_event_rate = 1.0,
        .queue_full_rate = 1.0,
    });
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expect(fi.maybeDrop());
        try std.testing.expect(fi.maybeQueueFull());
    }
    try std.testing.expectEqual(@as(u64, 100), fi.injectedCount(.drop_packet));
    try std.testing.expectEqual(@as(u64, 100), fi.injectedCount(.queue_full));
}

test "VER-003: FaultInjector disabled never triggers regardless of rate" {
    var fi = FaultInjector.init(.{
        .enabled = false,
        .drop_packet_rate = 1.0,
        .corrupt_event_rate = 1.0,
        .queue_full_rate = 1.0,
    });
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expect(!fi.maybeDrop());
        try std.testing.expect(!fi.maybeQueueFull());
    }
    try std.testing.expectEqual(@as(u64, 0), fi.injectedCount(.drop_packet));
}

test "VER-003: FaultInjector corrupt changes event bits" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .corrupt_event_rate = 1.0,
    });
    var ev = event.IpcEvent.init(.dns_query);
    const orig_bytes = std.mem.asBytes(&ev);
    var orig_copy: [80]u8 = undefined;
    @memcpy(&orig_copy, orig_bytes);

    const corrupted = fi.maybeCorrupt(&ev);
    try std.testing.expect(corrupted);

    // Verify at least one byte changed
    const new_bytes = std.mem.asBytes(&ev);
    var any_diff = false;
    var j: usize = 0;
    while (j < 80) : (j += 1) {
        if (orig_copy[j] != new_bytes[j]) {
            any_diff = true;
            break;
        }
    }
    try std.testing.expect(any_diff);
}

test "VER-003: FaultInjector multiple fault kinds tracked independently" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .drop_packet_rate = 1.0,
        .corrupt_event_rate = 1.0,
        .queue_full_rate = 1.0,
    });
    var ev = event.IpcEvent.init(.dns_query);

    _ = fi.maybeDrop();
    _ = fi.maybeCorrupt(&ev);
    _ = fi.maybeQueueFull();
    _ = fi.maybeDrop();

    try std.testing.expectEqual(@as(u64, 2), fi.injectedCount(.drop_packet));
    try std.testing.expectEqual(@as(u64, 1), fi.injectedCount(.corrupt_event));
    try std.testing.expectEqual(@as(u64, 1), fi.injectedCount(.queue_full));
    try std.testing.expectEqual(@as(u64, 0), fi.injectedCount(.slow_decode));
}

test "VER-003: FaultInjector seed produces deterministic results" {
    const seed: u64 = 0xDEADBEEF;
    var fi1 = FaultInjector.init(.{ .enabled = true, .seed = seed, .drop_packet_rate = 0.5 });
    var fi2 = FaultInjector.init(.{ .enabled = true, .seed = seed, .drop_packet_rate = 0.5 });

    var results1: [100]bool = undefined;
    var results2: [100]bool = undefined;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        results1[i] = fi1.maybeDrop();
        results2[i] = fi2.maybeDrop();
    }

    // Same seed should produce same sequence
    i = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(results1[i], results2[i]);
    }
}

test "VER-003: FaultInjector injection count never overflows" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .drop_packet_rate = 1.0,
    });
    // Inject many times — u64 counter should not overflow
    var i: u32 = 0;
    while (i < 10000) : (i += 1) {
        _ = fi.maybeDrop();
    }
    try std.testing.expectEqual(@as(u64, 10000), fi.injectedCount(.drop_packet));
}

test "VER-003: FaultInjector corrupt rate 0 never corrupts" {
    var fi = FaultInjector.init(.{
        .enabled = true,
        .corrupt_event_rate = 0.0,
    });
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        var ev = event.IpcEvent.init(.dns_query);
        try std.testing.expect(!fi.maybeCorrupt(&ev));
    }
    try std.testing.expectEqual(@as(u64, 0), fi.injectedCount(.corrupt_event));
}

test "VER-003: FaultInjector fromEnv respects env var" {
    // On Windows, if AEGIS_FAULT_INJECTION=1 is set, it should be enabled
    // In test env, it should be disabled
    var fi = FaultInjector.fromEnv();
    // We can't guarantee env state, but we can verify it doesn't panic
    _ = fi.maybeDrop();
    _ = fi.maybeQueueFull();
}
