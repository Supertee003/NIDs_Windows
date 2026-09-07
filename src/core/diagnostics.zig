// I05 - Logging & Diagnostics
// AEGIS NIDS v5.0+ â€” Structured logging, runtime metrics, error reporting
//
// Goals:
//   - Zero allocation in hot path
//   - Structured key=value output (JSON when feasible)
//   - Severity filtering at runtime
//   - Optional sink to file/stderr/Windows EventLog/ETW provider

const std = @import("std");
const event = @import("../contract/event.zig");

// ============================================================================
// Log levels â€” mapped 1:1 to EventSeverity
// ============================================================================
pub const Level = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    notice = 3,
    warning = 4,
    @"error" = 5,
    critical = 6,
    alert = 7,
    emergency = 8,

    pub fn toEventSeverity(self: Level) event.EventSeverity {
        return @enumFromInt(@intFromEnum(self));
    }
};

// ============================================================================
// Logger â€” global singleton
// ============================================================================
pub const Logger = struct {
    var min_level: Level = .info;
    var sink: ?Sink = null;
    var mutex: std.Thread.Mutex = .{};
    var drop_count: u64 = 0;

    pub fn setLevel(level: Level) void {
        min_level = level;
    }

    pub fn setSink(s: Sink) void {
        sink = s;
    }

    pub fn enabled(level: Level) bool {
        return @intFromEnum(level) >= @intFromEnum(min_level);
    }

    pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
        if (!enabled(level)) return;
        mutex.lock();
        defer mutex.unlock();
        var buf: [4096]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch {
            drop_count += 1;
            return;
        };
        if (sink) |*s| {
            s.write(level, msg) catch {
                drop_count += 1;
            };
        }
    }
};

// ============================================================================
// Sink â€” pluggable output destination
// ============================================================================
pub const Sink = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, level: Level, msg: []const u8) anyerror!void,

    pub fn write(self: *Sink, level: Level, msg: []const u8) !void {
        try self.writeFn(self.ctx, level, msg);
    }
};

var stderr_ctx: u8 = 0;

pub const StderrSink = struct {
    pub fn init() Sink {
        return .{ .ctx = @ptrCast(&stderr_ctx), .writeFn = writeStderr };
    }

    fn writeStderr(_: *anyopaque, level: Level, msg: []const u8) !void {
        const level_str = switch (level) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .notice => "NOTICE",
            .warning => "WARN",
            .@"error" => "ERROR",
            .critical => "CRIT",
            .alert => "ALERT",
            .emergency => "EMERG",
        };
        const stderr = std.io.getStdErr().writer();
        try stderr.print("[{s}] {s}\n", .{ level_str, msg });
    }
};

pub const FileSink = struct {
    file: std.fs.File,

    pub fn init(path: []const u8) !FileSink {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = false });
        try f.seekFromEnd(0);
        return .{ .file = f };
    }

    pub fn deinit(self: *FileSink) void {
        self.file.close();
    }

    pub fn sink(self: *FileSink) Sink {
        return .{ .ctx = @ptrCast(self), .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, level: Level, msg: []const u8) !void {
        const self: *FileSink = @ptrCast(@alignCast(ctx));
        const ts = std.time.timestamp();
        try self.file.writer().print("{d} [{s}] {s}\n", .{ ts, @tagName(level), msg });
    }
};

// ============================================================================
// Macros â€” these are the primary interface
// ============================================================================
pub fn trace(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.trace, fmt, args);
}
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.debug, fmt, args);
}
pub fn info(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.info, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.warning, fmt, args);
}
pub fn err(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.@"error", fmt, args);
}
pub fn critical(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.critical, fmt, args);
}
pub fn alert(comptime fmt: []const u8, args: anytype) void {
    Logger.log(.alert, fmt, args);
}

// ============================================================================
// Metrics counter â€” atomic, low-overhead
// ============================================================================
pub const Counter = struct {
    value: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn inc(self: *Counter) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn add(self: *Counter, n: u64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }

    pub fn get(self: *const Counter) u64 {
        return self.value.load(.monotonic);
    }

    pub fn reset(self: *Counter) void {
        self.value.store(0, .monotonic);
    }
};

pub const Gauge = struct {
    value: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    pub fn set(self: *Gauge, v: i64) void {
        self.value.store(v, .release);
    }

    pub fn inc(self: *Gauge) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn dec(self: *Gauge) void {
        _ = self.value.fetchSub(1, .monotonic);
    }

    pub fn get(self: *const Gauge) i64 {
        return self.value.load(.acquire);
    }
};

// ============================================================================
// Global metrics registry
// ============================================================================
pub var metrics = struct {
    packets_captured: Counter = .{},
    packets_dropped: Counter = .{},
    events_emitted: Counter = .{},
    events_dropped: Counter = .{},
    flows_active: Gauge = .{},
    signatures_matched: Counter = .{},
    anomalies_detected: Counter = .{},
    blocks_issued: Counter = .{},
    federation_messages: Counter = .{},
    errors: Counter = .{},
}{};

// ============================================================================
// Tests
// ============================================================================
test "Logger filtering" {
    Logger.setLevel(.warning);
    try std.testing.expect(!Logger.enabled(.info));
    try std.testing.expect(Logger.enabled(.warning));
    try std.testing.expect(Logger.enabled(.@"error"));
    Logger.setLevel(.trace);
    try std.testing.expect(Logger.enabled(.trace));
}

test "Counter increments" {
    var c = Counter{};
    c.inc();
    c.inc();
    c.add(10);
    try std.testing.expectEqual(@as(u64, 12), c.get());
    c.reset();
    try std.testing.expectEqual(@as(u64, 0), c.get());
}

test "Gauge set and get" {
    var g = Gauge{};
    g.set(42);
    try std.testing.expectEqual(@as(i64, 42), g.get());
    g.inc();
    try std.testing.expectEqual(@as(i64, 43), g.get());
    g.dec();
    try std.testing.expectEqual(@as(i64, 42), g.get());
}

test "StderrSink does not panic" {
    Logger.setSink(StderrSink.init());
    Logger.setLevel(.trace);
    info("test message {d}", .{42});
}
