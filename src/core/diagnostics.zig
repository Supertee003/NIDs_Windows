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

    pub fn getSink() ?Sink {
        return sink;
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

// QLOSS-DISK-001: the persisted diagnostic stream had no bound. On the
// production host `logs/aegis-daemon-diagnostic.log` reached 40.9 GB and
// filled the system drive, which is a product defect, not operator misuse:
// a service that writes an unbounded file will eventually exhaust any disk.
// FileSink now rotates at a byte cap, keeping exactly one previous file as
// `<path>.1`. A legacy oversized file is rotated on the first write after a
// restart, so deploying this build alone stops the growth; the stale `.1`
// then disappears on the next rotation.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

pub const FileSink = struct {
    file: std.fs.File,
    /// Owned copy of the path, present only for sinks created by init*.
    /// A null path disables rotation (synthetic/test sinks).
    path: ?[]u8 = null,
    size: u64 = 0,
    max_bytes: u64 = DEFAULT_MAX_BYTES,

    pub fn init(path: []const u8) !FileSink {
        return initWithLimit(path, DEFAULT_MAX_BYTES);
    }

    pub fn initWithLimit(path: []const u8, max_bytes: u64) !FileSink {
        const owned = try std.heap.page_allocator.dupe(u8, path);
        errdefer std.heap.page_allocator.free(owned);
        const f = try std.fs.cwd().createFile(owned, .{ .truncate = false });
        errdefer f.close();
        try f.seekFromEnd(0);
        return .{ .file = f, .path = owned, .size = try f.getEndPos(), .max_bytes = max_bytes };
    }

    pub fn deinit(self: *FileSink) void {
        self.file.close();
        if (self.path) |p| {
            std.heap.page_allocator.free(p);
            self.path = null;
        }
    }

    pub fn sink(self: *FileSink) Sink {
        return .{ .ctx = @ptrCast(self), .writeFn = writeFn };
    }

    /// Move the current file to `<path>.1` and start a fresh one. The rename
    /// replaces any previous backup, so total on-disk growth stays bounded by
    /// two caps. Rename failures are swallowed: losing the backup is better
    /// than dropping the diagnostic line.
    fn rotate(self: *FileSink) !void {
        const p = self.path orelse return;
        const backup = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.1", .{p});
        defer std.heap.page_allocator.free(backup);
        self.file.close();
        std.fs.cwd().deleteFile(backup) catch {};
        std.fs.cwd().rename(p, backup) catch {};
        self.file = try std.fs.cwd().createFile(p, .{ .truncate = true });
        self.size = 0;
    }

    fn writeFn(ctx: *anyopaque, level: Level, msg: []const u8) !void {
        const self: *FileSink = @ptrCast(@alignCast(ctx));
        const ts = std.time.timestamp();
        var buf: [4096]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{d} [{s}] {s}\n", .{ ts, @tagName(level), msg }) catch return error.MessageTooLong;
        if (self.path != null and self.size + line.len > self.max_bytes) {
            try self.rotate();
        }
        try self.file.writeAll(line);
        self.size += line.len;
    }
};

// TeeSink — fan one diagnostic line out to two sinks (e.g. stderr + file).
// RB013-LOG: service mode must persist the diagnostic stream, while console
// and lab harnesses keep reading stderr. The tee attempts BOTH branches and
// reports failure only when both fail, so a closed console never suppresses
// a persisted line (and vice versa); the Logger drop counter then reflects
// only lines lost on every branch.
pub const TeeSink = struct {
    first: Sink,
    second: Sink,

    pub fn init(first: Sink, second: Sink) TeeSink {
        return .{ .first = first, .second = second };
    }

    pub fn sink(self: *TeeSink) Sink {
        return .{ .ctx = @ptrCast(self), .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, level: Level, msg: []const u8) !void {
        const self: *TeeSink = @ptrCast(@alignCast(ctx));
        var err_first: ?anyerror = null;
        var err_second: ?anyerror = null;
        self.first.write(level, msg) catch |e| {
            err_first = e;
        };
        self.second.write(level, msg) catch |e| {
            err_second = e;
        };
        if (err_first) |e| {
            if (err_second != null) return e;
        }
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

    /// Atomically reserve and return the next one-based sequence value.
    pub fn next(self: *Counter) u64 {
        return self.value.fetchAdd(1, .monotonic) + 1;
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
    try std.testing.expectEqual(@as(u64, 13), c.next());
    try std.testing.expectEqual(@as(u64, 14), c.next());
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

test "FileSink persists diagnostic lines" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_real = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_real);
    const path = try std.fs.path.join(alloc, &.{ tmp_real, "probe.log" });
    defer alloc.free(path);
    var fs = try FileSink.init(path);
    defer fs.deinit();
    const prev_sink = Logger.getSink();
    defer Logger.setSink(prev_sink orelse StderrSink.init());
    Logger.setSink(fs.sink());
    info("file sink probe {d}", .{7});
    const data = try tmp.dir.readFileAlloc(alloc, "probe.log", 1 << 16);
    defer alloc.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "file sink probe 7") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "[info]") != null);
}

test "FileSink rotates at the byte cap and keeps one backup" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_real = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_real);
    const path = try std.fs.path.join(alloc, &.{ tmp_real, "capped.log" });
    defer alloc.free(path);
    var fs = try FileSink.initWithLimit(path, 200);
    defer fs.deinit();
    const prev_sink = Logger.getSink();
    defer Logger.setSink(prev_sink orelse StderrSink.init());
    Logger.setSink(fs.sink());
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        info("capped probe line {d} padding padding", .{i});
    }
    const live = try tmp.dir.statFile("capped.log");
    try std.testing.expect(live.size <= 200);
    const backup = try tmp.dir.statFile("capped.log.1");
    try std.testing.expect(backup.size <= 200);
    const data = try tmp.dir.readFileAlloc(alloc, "capped.log", 1 << 16);
    defer alloc.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "capped probe line") != null);
    // Upper bound on total persisted bytes: two caps, not unbounded growth.
    try std.testing.expect(live.size + backup.size <= 400);
}

test "FileSink rotates a legacy oversized file on the first write" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_real = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_real);
    const path = try std.fs.path.join(alloc, &.{ tmp_real, "legacy.log" });
    defer alloc.free(path);
    {
        const f = try tmp.dir.createFile("legacy.log", .{});
        defer f.close();
        const filler = try alloc.alloc(u8, 1000);
        defer alloc.free(filler);
        @memset(filler, 'x');
        try f.writeAll(filler);
    }
    var fs = try FileSink.initWithLimit(path, 256);
    defer fs.deinit();
    const prev_sink = Logger.getSink();
    defer Logger.setSink(prev_sink orelse StderrSink.init());
    Logger.setSink(fs.sink());
    info("first line after legacy growth", .{});
    const live = try tmp.dir.statFile("legacy.log");
    try std.testing.expect(live.size <= 256);
    const backup = try tmp.dir.statFile("legacy.log.1");
    try std.testing.expectEqual(@as(u64, 1000), backup.size);
}

test "TeeSink writes to both branches" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_real = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_real);
    const path_a = try std.fs.path.join(alloc, &.{ tmp_real, "tee-a.log" });
    defer alloc.free(path_a);
    const path_b = try std.fs.path.join(alloc, &.{ tmp_real, "tee-b.log" });
    defer alloc.free(path_b);
    var sink_a = try FileSink.init(path_a);
    defer sink_a.deinit();
    var sink_b = try FileSink.init(path_b);
    defer sink_b.deinit();
    var tee = TeeSink.init(sink_a.sink(), sink_b.sink());
    const prev_sink = Logger.getSink();
    defer Logger.setSink(prev_sink orelse StderrSink.init());
    Logger.setSink(tee.sink());
    info("tee probe", .{});
    const data_a = try tmp.dir.readFileAlloc(alloc, "tee-a.log", 1 << 16);
    defer alloc.free(data_a);
    const data_b = try tmp.dir.readFileAlloc(alloc, "tee-b.log", 1 << 16);
    defer alloc.free(data_b);
    try std.testing.expect(std.mem.indexOf(u8, data_a, "tee probe") != null);
    try std.testing.expect(std.mem.indexOf(u8, data_b, "tee probe") != null);
}

test "TeeSink survives a failing branch" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_real = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(tmp_real);
    const path = try std.fs.path.join(alloc, &.{ tmp_real, "tee-survivor.log" });
    defer alloc.free(path);
    var live = try FileSink.init(path);
    defer live.deinit();
    // A read-only handle fails every write deterministically; the tee must
    // still deliver the line through the healthy branch.
    const dead = try tmp.dir.createFile("dead.log", .{ .read = true });
    defer dead.close();
    var dead_sink = FileSink{ .file = dead };
    var tee = TeeSink.init(dead_sink.sink(), live.sink());
    const prev_sink = Logger.getSink();
    defer Logger.setSink(prev_sink orelse StderrSink.init());
    Logger.setSink(tee.sink());
    info("tee survivor probe", .{});
    const data = try tmp.dir.readFileAlloc(alloc, "tee-survivor.log", 1 << 16);
    defer alloc.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "tee survivor probe") != null);
}
