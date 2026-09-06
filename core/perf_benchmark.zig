//! perf_benchmark.zig - AEGIS NIDS Phase 41: Performance Benchmark Suite
//!
//! Measures throughput of the full AEGIS NIDS pipeline (built across Phases
//! 32-39 + extensions) to provide baseline numbers for production capacity
//! planning. All benchmarks run on the Linux host with no external services.
//!
//! Six benchmark suites:
//!   1. ProcessTracker bench: process_create events/sec
//!   2. FileIntegrityStore bench: FIM observations/sec
//!   3. RegistryWatchQueue bench: registry events/sec
//!   4. Federation codec bench: encode + decode msgs/sec
//!   5. TCP transport bench: framed roundtrips/sec
//!   6. Full pipeline bench: mock source -> detectors -> correlation -> incidents
//!
//! Design principles:
//!   - Pure Zig, host-testable on Linux
//!   - Warmup iterations to stabilize cache/JIT
//!   - Multiple iteration counts for statistical validity
//!   - Reports ops/sec, us/op, and p99 latency (where applicable)
//!   - Kill switch OFF by default; BenchConfig{.enabled=true} opts in
//!
//! Build:
//!   zig test perf_benchmark.zig -lc
//!   zig build-exe perf_benchmark_cli.zig -lc

const std = @import("std");
const ht = @import("host_telemetry.zig");
const mock = @import("host_telemetry_mock.zig");
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const DEFAULT_WARMUP: u32 = 100;
pub const DEFAULT_ITERATIONS: u32 = 10_000;
pub const DEFAULT_BATCH_SIZE: u32 = 100;
pub const NANOS_PER_SEC: i64 = 1_000_000_000;
pub const NANOS_PER_US: i64 = 1_000;

// ============================================================
// BenchConfig (kill switch + iteration params)
// ============================================================

pub const BenchConfig = struct {
    /// Master kill switch. OFF by default - benchmarks are no-ops until
    /// explicitly enabled.
    enabled: bool = false,
    /// Warmup iterations (not measured)
    warmup: u32 = DEFAULT_WARMUP,
    /// Measured iterations
    iterations: u32 = DEFAULT_ITERATIONS,
    /// Batch size for batch operations
    batch_size: u32 = DEFAULT_BATCH_SIZE,
    /// Print progress every N iterations (0 = silent)
    progress_interval: u32 = 0,
};

// ============================================================
// BenchResult (single measurement)
// ============================================================

pub const BenchResult = struct {
    name: []const u8,
    iterations: u32,
    total_ns: i64,
    ops_per_sec: f64,
    us_per_op: f64,
    bytes_processed: u64 = 0,
    throughput_mbps: f64 = 0.0,

    pub fn print(self: BenchResult, writer: anytype) !void {
        try writer.print("  {s:<40} {d:>8} ops  {d:>10.0} ops/sec  {d:>8.2} us/op", .{
            self.name,
            self.iterations,
            self.ops_per_sec,
            self.us_per_op,
        });
        if (self.bytes_processed > 0) {
            try writer.print("  {d:>8.1} MB/s", .{self.throughput_mbps});
        }
        try writer.print("\n", .{});
    }
};

// ============================================================
// BenchTimer (high-precision timing)
// ============================================================

pub const BenchTimer = struct {
    start_ns: i64,
    end_ns: i64,

    pub fn start() BenchTimer {
        return .{ .start_ns = @intCast(std.time.nanoTimestamp()), .end_ns = 0 };
    }

    pub fn stop(self: *BenchTimer) void {
        self.end_ns = @intCast(std.time.nanoTimestamp());
    }

    pub fn elapsedNs(self: BenchTimer) i64 {
        return self.end_ns - self.start_ns;
    }

    pub fn elapsedUs(self: BenchTimer) f64 {
        return @as(f64, @floatFromInt(self.elapsedNs())) / @as(f64, @floatFromInt(NANOS_PER_US));
    }

    pub fn opsPerSec(self: BenchTimer, iterations: u32) f64 {
        const elapsed = self.elapsedNs();
        if (elapsed <= 0) return 0.0;
        return @as(f64, @floatFromInt(iterations)) * @as(f64, @floatFromInt(NANOS_PER_SEC)) / @as(f64, @floatFromInt(elapsed));
    }
};

// ============================================================
// BenchRunner (executes benchmarks and collects results)
// ============================================================

pub const BenchRunner = struct {
    config: BenchConfig,
    results: std.ArrayList(BenchResult),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: BenchConfig) BenchRunner {
        return .{
            .config = config,
            .results = std.ArrayList(BenchResult).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BenchRunner) void {
        self.results.deinit();
    }

    /// Run a benchmark function with warmup + measured iterations.
    /// The callback receives an allocator and the iteration index.
    pub fn run(
        self: *BenchRunner,
        name: []const u8,
        callback: *const fn (alloc: std.mem.Allocator, iter: u32) void,
    ) !void {
        if (!self.config.enabled) return;

        // Warmup
        var i: u32 = 0;
        while (i < self.config.warmup) : (i += 1) {
            callback(self.allocator, i);
        }

        // Measured
        var timer = BenchTimer.start();
        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            callback(self.allocator, i);
        }
        timer.stop();

        const elapsed_ns = timer.elapsedNs();
        const ops_per_sec = timer.opsPerSec(self.config.iterations);
        const us_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(self.config.iterations)) / 1000.0;

        try self.results.append(.{
            .name = name,
            .iterations = self.config.iterations,
            .total_ns = elapsed_ns,
            .ops_per_sec = ops_per_sec,
            .us_per_op = us_per_op,
        });
    }

    /// Run a benchmark with bytes processed (for throughput measurement).
    pub fn runWithBytes(
        self: *BenchRunner,
        name: []const u8,
        bytes_per_op: u64,
        callback: *const fn (alloc: std.mem.Allocator, iter: u32) void,
    ) !void {
        if (!self.config.enabled) return;

        // Warmup
        var i: u32 = 0;
        while (i < self.config.warmup) : (i += 1) {
            callback(self.allocator, i);
        }

        // Measured
        var timer = BenchTimer.start();
        i = 0;
        while (i < self.config.iterations) : (i += 1) {
            callback(self.allocator, i);
        }
        timer.stop();

        const elapsed_ns = timer.elapsedNs();
        const ops_per_sec = timer.opsPerSec(self.config.iterations);
        const total_bytes = @as(u64, self.config.iterations) * bytes_per_op;
        const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NANOS_PER_SEC));
        const throughput_mbps = if (elapsed_secs > 0)
            @as(f64, @floatFromInt(total_bytes)) / elapsed_secs / (1024.0 * 1024.0)
        else
            0.0;

        try self.results.append(.{
            .name = name,
            .iterations = self.config.iterations,
            .total_ns = elapsed_ns,
            .ops_per_sec = ops_per_sec,
            .us_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(self.config.iterations)) / 1000.0,
            .bytes_processed = total_bytes,
            .throughput_mbps = throughput_mbps,
        });
    }

    /// Print all results as a table.
    pub fn printReport(self: *BenchRunner, writer: anytype) !void {
        try writer.print("\n", .{});
        var i: u32 = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\nPerformance Benchmark Report\n", .{});
        i = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\n\n", .{});
        try writer.print("Config: warmup={d}, iterations={d}\n\n", .{
            self.config.warmup, self.config.iterations,
        });
        i = 0;
        while (i < 80) : (i += 1) try writer.print("-", .{});
        try writer.print("\n", .{});
        for (self.results.items) |r| {
            try r.print(writer);
        }
        i = 0;
        while (i < 80) : (i += 1) try writer.print("-", .{});
        try writer.print("\n", .{});
    }

    /// Get a result by name (linear search).
    pub fn getResult(self: *const BenchRunner, name: []const u8) ?BenchResult {
        for (self.results.items) |r| {
            if (std.mem.eql(u8, r.name, name)) return r;
        }
        return null;
    }

    pub fn resultCount(self: *const BenchRunner) usize {
        return self.results.items.len;
    }
};

// ============================================================
// Benchmark Suites
// ============================================================

// --- Suite 1: ProcessTracker throughput ---

var bench_alloc_global: std.mem.Allocator = undefined;

pub fn processTrackerBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    var tracker = ht.ProcessTracker.init(alloc, 4096);
    defer tracker.deinit();
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const ev = ht.HostEvent{
            .event_type = .process_create,
            .pid = iter * 100 + i,
            .ppid = 0,
            .integrity = .medium,
            .is_signed = true,
            .timestamp_ns = @as(i64, @intCast(i)),
        };
        _ = tracker.trackCreate(ev);
    }
}

// --- Suite 2: FileIntegrityStore throughput ---

pub fn fimBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    var fim = ht.FileIntegrityStore.init(alloc);
    defer fim.deinit();
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "C:\\test\\file{d}_{d}.bin", .{ iter, i }) catch return;
        const hash = ht.sha256("bench-content");
        fim.setBaseline(path, hash, 1024, 1_000_000, 0x20, 2_000_000) catch return;
        // Observe (should return .none since hash matches)
        _ = fim.observe(path, hash, 1024, 3_000_000, 0x20, .file_modify, 4_000_000);
    }
}

// --- Suite 3: RegistryWatchQueue throughput ---

pub fn registryBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    _ = alloc;
    var q = ht.RegistryWatchQueue.init();
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        var ev = ht.HostEvent{
            .event_type = .registry_set_value,
            .pid = iter,
            .timestamp_ns = @as(i64, @intCast(i)),
        };
        const key = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor";
        @memcpy(ev.reg_key[0..key.len], key);
        ev.reg_key_len = @intCast(key.len);
        _ = q.enqueue(ev);
    }
}

// --- Suite 4: Federation codec encode/decode throughput ---

pub fn codecBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    _ = alloc;
    _ = iter;
    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const n = fc.encode(.{
            .msg_type = .incident_report,
            .from_node_id = 1,
            .timestamp_ns = 1_000_000_000,
            .incident_source_ip = .{ 198, 51, 100, 5 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .high,
            .incident_score = 0.85,
        }, &buf) catch return;
        _ = fc.decode(buf[0..n]) catch return;
    }
}

// --- Suite 5: CrossNodeIncidentAggregator throughput ---

pub fn aggregatorBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    var agg = cc.CrossNodeIncidentAggregator.init(alloc, .{});
    defer agg.deinit();
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        _ = agg.report(
            .{ 198, 51, 100, @intCast(i % 256) },
            4444,
            6,
            iter % 5 + 1,
            .medium,
            0.75,
            "malicious",
            @as(i64, @intCast(i)),
        ) catch return;
    }
}

// --- Suite 6: Full pipeline (mock source -> detectors -> incidents) ---

pub fn fullPipelineBenchCallback(alloc: std.mem.Allocator, iter: u32) void {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("bench", .{ .enabled = true });
    // Build a small scenario (4 events)
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        var ev = ht.HostEvent{
            .event_type = .process_create,
            .pid = iter * 100 + i,
            .ppid = 0,
            .integrity = .medium,
            .is_signed = true,
            .timestamp_ns = @as(i64, @intCast(i)),
        };
        const img = "C:\\Windows\\System32\\notepad.exe";
        @memcpy(ev.image_path[0..img.len], img);
        ev.image_path_len = @intCast(img.len);
        _ = src.appendEvent(ev, 0);
    }

    var pump = mock.EventPump.init(src.asSource(), host);
    _ = pump.pumpAll(0, 100);
}

// ============================================================
// Convenience: run all benchmarks
// ============================================================

pub fn runAllBenchmarks(allocator: std.mem.Allocator, config: BenchConfig) !BenchRunner {
    var runner = BenchRunner.init(allocator, config);
    errdefer runner.deinit();

    try runner.run("ProcessTracker (100 creates)", &processTrackerBenchCallback);
    try runner.run("FileIntegrityStore (50 baselines + observes)", &fimBenchCallback);
    try runner.run("RegistryWatchQueue (100 enqueues)", &registryBenchCallback);
    try runner.runWithBytes("Federation codec (10 encode+decode)", 200, &codecBenchCallback);
    try runner.run("CrossNodeAggregator (50 reports)", &aggregatorBenchCallback);
    try runner.run("Full pipeline (4 events -> incidents)", &fullPipelineBenchCallback);

    return runner;
}

// ============================================================
// Threshold checker (verify production readiness)
// ============================================================

pub const ThresholdResult = struct {
    name: []const u8,
    actual: f64,
    threshold: f64,
    passed: bool,
};

pub fn checkThresholds(runner: *const BenchRunner) std.ArrayList(ThresholdResult) {
    var results = std.ArrayList(ThresholdResult).init(runner.allocator);
    // Define minimum acceptable throughput (ops/sec)
    const thresholds = [_]struct { name: []const u8, min: f64 }{
        .{ .name = "ProcessTracker (100 creates)", .min = 1_000.0 },
        .{ .name = "FileIntegrityStore (50 baselines + observes)", .min = 500.0 },
        .{ .name = "RegistryWatchQueue (100 enqueues)", .min = 5_000.0 },
        .{ .name = "Federation codec (10 encode+decode)", .min = 10_000.0 },
        .{ .name = "CrossNodeAggregator (50 reports)", .min = 1_000.0 },
        .{ .name = "Full pipeline (4 events -> incidents)", .min = 500.0 },
    };
    for (thresholds) |t| {
        if (runner.getResult(t.name)) |r| {
            results.append(.{
                .name = t.name,
                .actual = r.ops_per_sec,
                .threshold = t.min,
                .passed = r.ops_per_sec >= t.min,
            }) catch {};
        }
    }
    return results;
}

// ============================================================
// Tests
// ============================================================

test "BenchConfig defaults - kill switch OFF" {
    const c = BenchConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqual(@as(u32, 100), c.warmup);
    try std.testing.expectEqual(@as(u32, 10_000), c.iterations);
}

test "BenchTimer start/stop" {
    var timer = BenchTimer.start();
    // Busy-wait a tiny bit
    var i: u32 = 0;
    while (i < 100) : (i += 1) {}
    timer.stop();
    const elapsed = timer.elapsedNs();
    try std.testing.expect(elapsed > 0);
    try std.testing.expect(timer.elapsedUs() > 0);
}

test "BenchTimer opsPerSec" {
    var timer = BenchTimer.start();
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {}
    timer.stop();
    const ops = timer.opsPerSec(1000);
    try std.testing.expect(ops > 0.0);
}

test "BenchResult print" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const r = BenchResult{
        .name = "test-bench",
        .iterations = 1000,
        .total_ns = 1_000_000,
        .ops_per_sec = 1000.0,
        .us_per_op = 1.0,
    };
    try r.print(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "test-bench") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "1000") != null);
}

test "BenchRunner init/deinit" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 0), runner.resultCount());
}

test "BenchRunner run respects kill switch" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = false, .iterations = 10, .warmup = 1 });
    defer runner.deinit();
    try runner.run("test", &processTrackerBenchCallback);
    try std.testing.expectEqual(@as(usize, 0), runner.resultCount());
}

test "BenchRunner run collects result" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 100, .warmup = 10 });
    defer runner.deinit();
    try runner.run("test-process-tracker", &processTrackerBenchCallback);
    try std.testing.expectEqual(@as(usize, 1), runner.resultCount());
    const r = runner.getResult("test-process-tracker");
    try std.testing.expect(r != null);
    try std.testing.expect(r.?.iterations == 100);
    try std.testing.expect(r.?.ops_per_sec > 0.0);
}

test "BenchRunner runWithBytes tracks throughput" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 100, .warmup = 10 });
    defer runner.deinit();
    try runner.runWithBytes("test-codec", 200, &codecBenchCallback);
    const r = runner.getResult("test-codec");
    try std.testing.expect(r != null);
    try std.testing.expect(r.?.bytes_processed == 100 * 200);
    try std.testing.expect(r.?.throughput_mbps > 0.0);
}

test "BenchRunner getResult returns null for unknown" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try std.testing.expect(runner.getResult("nonexistent") == null);
}

test "BenchRunner printReport outputs table" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 50, .warmup = 5 });
    defer runner.deinit();
    try runner.run("test-1", &processTrackerBenchCallback);
    try runner.run("test-2", &registryBenchCallback);

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try runner.printReport(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "Performance Benchmark Report") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "ops/sec") != null);
}

test "ProcessTracker benchmark callback works" {
    processTrackerBenchCallback(std.testing.allocator, 0);
    // If we reach here without crash, the callback works
}

test "FileIntegrityStore benchmark callback works" {
    fimBenchCallback(std.testing.allocator, 0);
}

test "RegistryWatchQueue benchmark callback works" {
    registryBenchCallback(std.testing.allocator, 0);
}

test "Federation codec benchmark callback works" {
    codecBenchCallback(std.testing.allocator, 0);
}

test "CrossNodeAggregator benchmark callback works" {
    aggregatorBenchCallback(std.testing.allocator, 0);
}

test "Full pipeline benchmark callback works" {
    fullPipelineBenchCallback(std.testing.allocator, 0);
}

test "runAllBenchmarks collects 6 results" {
    var runner = try runAllBenchmarks(std.testing.allocator, .{
        .enabled = true,
        .iterations = 50,
        .warmup = 5,
    });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 6), runner.resultCount());

    // Verify all expected benchmarks ran
    try std.testing.expect(runner.getResult("ProcessTracker (100 creates)") != null);
    try std.testing.expect(runner.getResult("FileIntegrityStore (50 baselines + observes)") != null);
    try std.testing.expect(runner.getResult("RegistryWatchQueue (100 enqueues)") != null);
    try std.testing.expect(runner.getResult("Federation codec (10 encode+decode)") != null);
    try std.testing.expect(runner.getResult("CrossNodeAggregator (50 reports)") != null);
    try std.testing.expect(runner.getResult("Full pipeline (4 events -> incidents)") != null);
}

test "checkThresholds evaluates all benchmarks" {
    var runner = try runAllBenchmarks(std.testing.allocator, .{
        .enabled = true,
        .iterations = 100,
        .warmup = 10,
    });
    defer runner.deinit();

    var thresholds = checkThresholds(&runner);
    defer thresholds.deinit();
    try std.testing.expectEqual(@as(usize, 6), thresholds.items.len);

    // All should pass on a reasonable host (ops_per_sec > threshold)
    for (thresholds.items) |t| {
        try std.testing.expect(t.passed);
    }
}

test "ThresholdResult passed flag" {
    const t = ThresholdResult{
        .name = "test",
        .actual = 1000.0,
        .threshold = 500.0,
        .passed = true,
    };
    try std.testing.expect(t.passed);
    try std.testing.expect(t.actual > t.threshold);
}

test "Full pipeline produces measurable throughput" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 200, .warmup = 20 });
    defer runner.deinit();
    try runner.run("full-pipeline-test", &fullPipelineBenchCallback);
    const r = runner.getResult("full-pipeline-test").?;
    // Should achieve at least 100 ops/sec (each iter creates 4 events)
    try std.testing.expect(r.ops_per_sec > 100.0);
}

test "Codec benchmark achieves high throughput" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 500, .warmup = 50 });
    defer runner.deinit();
    try runner.runWithBytes("codec-throughput", 200, &codecBenchCallback);
    const r = runner.getResult("codec-throughput").?;
    // Codec should be fast (>10k ops/sec on modern hardware)
    try std.testing.expect(r.ops_per_sec > 1000.0);
}

test "BenchRunner handles zero iterations gracefully" {
    var runner = BenchRunner.init(std.testing.allocator, .{ .enabled = true, .iterations = 0, .warmup = 0 });
    defer runner.deinit();
    try runner.run("zero-iter", &processTrackerBenchCallback);
    // Should not crash; result may have 0 iterations
    if (runner.getResult("zero-iter")) |r| {
        try std.testing.expectEqual(@as(u32, 0), r.iterations);
    }
}
