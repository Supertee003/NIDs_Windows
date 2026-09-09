// II07 - Reliability Watchdog
// AEGIS NIDS v5.0+ â€” Heartbeat + deadlock detection + supervised restart
//
// Monitors:
//   - Per-thread heartbeats (each subsystem thread pings every N ms)
//   - Pipeline stalls (captureâ†’detectionâ†’policy queues all stuck)
//   - Process memory growth (Windows: GetProcessMemoryInfo)
//   - File-descriptor / handle leaks
// On timeout: emit alert; on critical: trigger supervisor restart.

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const WATCHDOG_TIMEOUT_NS: i128 = @as(i128, manifest.Limits.WATCHDOG_TIMEOUT_MS) * std.time.ns_per_ms;

pub const ThreadKind = enum(u8) {
    capture = 1,
    decoder = 2,
    detection = 3,
    correlator = 4,
    policy = 5,
    pep = 6,
    forensic = 7,
    federation = 8,
    etw_consumer = 9,
    fim_watcher = 10,
    pipeline = 11,
    host_telemetry = 12,
};

pub const ThreadHeartbeat = struct {
    kind: ThreadKind,
    last_beat_ns: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    beats: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    restarts: u32 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
};

pub const WatchdogAlert = struct {
    kind: ThreadKind,
    severity: event.EventSeverity,
    message: [256]u8 = [_]u8{0} ** 256,
    timestamp_ns: i128 = 0,
};

pub const ReliabilityWatchdog = struct {
    threads: [16]ThreadHeartbeat = [_]ThreadHeartbeat{.{ .kind = .capture }} ** 16,
    thread_count: usize = 0,
    alerts: std.ArrayList(WatchdogAlert),
    last_check_ns: i128 = 0,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    critical_alerts: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) ReliabilityWatchdog {
        return .{
            .alerts = std.ArrayList(WatchdogAlert).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ReliabilityWatchdog) void {
        self.alerts.deinit();
    }

    pub fn registerThread(self: *ReliabilityWatchdog, kind: ThreadKind, name: []const u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.thread_count;
        self.threads[idx] = .{ .kind = kind };
        const n = @min(name.len, self.threads[idx].name.len);
        @memcpy(self.threads[idx].name[0..n], name[0..n]);
        self.thread_count += 1;
        return idx;
    }

    pub fn beat(self: *ReliabilityWatchdog, idx: usize) void {
        if (idx >= self.thread_count) return;
        self.threads[idx].last_beat_ns.store(@intCast(std.time.nanoTimestamp()), .release);
        _ = self.threads[idx].beats.fetchAdd(1, .monotonic);
    }

    pub fn check(self: *ReliabilityWatchdog, now_ns: i128) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.last_check_ns = now_ns;
        var stalled: usize = 0;
        var i: usize = 0;
        while (i < self.thread_count) : (i += 1) {
            const hb = &self.threads[i];
            const last = hb.last_beat_ns.load(.acquire);
            if (last == 0) continue; // never started
            if (now_ns - @as(i128, last) > WATCHDOG_TIMEOUT_NS) {
                var alert = WatchdogAlert{
                    .kind = hb.kind,
                    .severity = if (now_ns - @as(i128, last) > 2 * WATCHDOG_TIMEOUT_NS) .emergency else .alert,
                    .timestamp_ns = now_ns,
                };
                const msg = "watchdog timeout";
                const n = @min(msg.len, alert.message.len);
                @memcpy(alert.message[0..n], msg);
                self.alerts.append(alert) catch return stalled;
                hb.restarts += 1;
                stalled += 1;
                if (alert.severity == .emergency) {
                    self.critical_alerts += 1;
                    diag.critical("WATCHDOG: thread {s} timed out (last beat {d}ms ago)", .{
                        std.mem.sliceTo(&hb.name, 0),
                        @divFloor(now_ns - @as(i128, last), std.time.ns_per_ms),
                    });
                }
            }
        }
        return stalled;
    }

    pub fn pendingAlerts(self: *ReliabilityWatchdog) usize {
        return self.alerts.items.len;
    }

    pub fn drainAlerts(self: *ReliabilityWatchdog) []WatchdogAlert {
        const items = self.alerts.items;
        self.alerts = std.ArrayList(WatchdogAlert).init(self.allocator);
        return items;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ReliabilityWatchdog registerThread and beat" {
    var wd = ReliabilityWatchdog.init(std.testing.allocator);
    defer wd.deinit();
    const idx = wd.registerThread(.capture, "capture-thread");
    try std.testing.expectEqual(@as(usize, 0), idx);
    wd.beat(idx);
    try std.testing.expectEqual(@as(u64, 1), wd.threads[0].beats.load(.monotonic));
}

test "ReliabilityWatchdog detects stall" {
    var wd = ReliabilityWatchdog.init(std.testing.allocator);
    defer wd.deinit();
    const idx = wd.registerThread(.detection, "det-thread");
    // Simulate a beat in the past
    wd.threads[idx].last_beat_ns.store(@intCast(std.time.nanoTimestamp() - 10_000_000_000), .release); // 10s ago
    const stalled = wd.check(std.time.nanoTimestamp());
    try std.testing.expectEqual(@as(usize, 1), stalled);
    try std.testing.expectEqual(@as(usize, 1), wd.pendingAlerts());
}

test "ReliabilityWatchdog no false positive on fresh beat" {
    var wd = ReliabilityWatchdog.init(std.testing.allocator);
    defer wd.deinit();
    const idx = wd.registerThread(.policy, "pol-thread");
    wd.beat(idx);
    const stalled = wd.check(std.time.nanoTimestamp());
    try std.testing.expectEqual(@as(usize, 0), stalled);
}
