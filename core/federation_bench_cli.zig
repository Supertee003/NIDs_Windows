// federation_bench_cli.zig - AEGIS Phase 43: Cross-Node Federation Benchmark CLI.
// Builds with `zig build-exe federation_bench_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - run all 5 benchmarks + threshold check
//   quick                             - fast run (100 iters, 10 warmup)
//   full                              - full run (5000 iters, 100 warmup)
//   scenario <name>                   - run a single named benchmark

const std = @import("std");
const fed_bench = @import("federation_bench.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 43: Cross-Node Federation Benchmark CLI\n", .{});
    std.debug.print("=========================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "quick")) {
        try runBenchmarks(alloc, .{ .enabled = true, .iterations = 100, .warmup = 10 });
        return;
    }

    if (std.mem.eql(u8, mode, "full")) {
        try runBenchmarks(alloc, .{ .enabled = true, .iterations = 5000, .warmup = 100 });
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        try runBenchmarks(alloc, .{ .enabled = true, .iterations = 1000, .warmup = 50 });
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: federation_bench_cli scenario <name>\n", .{});
            std.debug.print("Names: heartbeat | incident | threat-intel | multi-stream | failover\n", .{});
            return;
        }
        try runSingleBenchmark(alloc, args[2]);
        return;
    }

    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  federation_bench_cli help                          - this screen\n", .{});
    std.debug.print("  federation_bench_cli quick                          - fast run (100 iters)\n", .{});
    std.debug.print("  federation_bench_cli demo                          - balanced run (1000 iters)\n", .{});
    std.debug.print("  federation_bench_cli full                          - full run (5000 iters)\n", .{});
    std.debug.print("  federation_bench_cli scenario <name>               - single benchmark\n", .{});
    std.debug.print("\nBenchmark names:\n", .{});
    std.debug.print("  heartbeat       - HEARTBEAT message roundtrip (47 bytes)\n", .{});
    std.debug.print("  incident        - INCIDENT_REPORT roundtrip (56 bytes)\n", .{});
    std.debug.print("  threat-intel    - THREAT_INTEL_SHARE roundtrip (72 bytes)\n", .{});
    std.debug.print("  multi-stream    - 10-message batch stream\n", .{});
    std.debug.print("  failover        - bind+connect+close cycle time\n", .{});
}

fn runBenchmarks(alloc: std.mem.Allocator, config: fed_bench.FedBenchConfig) !void {
    std.debug.print("Running federation benchmarks (warmup={d}, iterations={d})...\n", .{
        config.warmup, config.iterations,
    });
    std.debug.print("Using real TCP sockets on 127.0.0.1 (ephemeral ports)...\n\n", .{});

    var runner = try fed_bench.runAllFederationBenchmarks(alloc, config);
    defer runner.deinit();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_stream = std.io.fixedBufferStream(&stdout_buf);
    try runner.printReport(stdout_stream.writer());
    std.debug.print("{s}\n", .{stdout_stream.getWritten()});

    // Threshold check
    var thresholds = fed_bench.checkFedThresholds(&runner);
    defer thresholds.deinit();

    std.debug.print("Threshold check:\n", .{});
    var all_passed = true;
    for (thresholds.items) |t| {
        const tag = if (t.passed) "PASS" else "FAIL";
        std.debug.print("  [{s}] {s:<50} actual={d:>10.0} threshold={d:>10.0}\n", .{
            tag, t.name, t.actual, t.threshold,
        });
        if (!t.passed) all_passed = false;
    }
    std.debug.print("\n", .{});
    if (all_passed) {
        std.debug.print("All thresholds passed - federation ready for production traffic.\n", .{});
    } else {
        std.debug.print("Some thresholds failed - review federation performance.\n", .{});
    }
}

fn runSingleBenchmark(alloc: std.mem.Allocator, name: []const u8) !void {
    const config = fed_bench.FedBenchConfig{ .enabled = true, .iterations = 1000, .warmup = 50 };
    var runner = fed_bench.FedBenchRunner.init(alloc, config);
    defer runner.deinit();

    var result: ?fed_bench.FedBenchResult = null;

    if (std.mem.eql(u8, name, "heartbeat")) {
        result = try fed_bench.benchHeartbeat(alloc, config);
    } else if (std.mem.eql(u8, name, "incident")) {
        result = try fed_bench.benchIncidentReport(alloc, config);
    } else if (std.mem.eql(u8, name, "threat-intel")) {
        result = try fed_bench.benchThreatIntel(alloc, config);
    } else if (std.mem.eql(u8, name, "multi-stream")) {
        result = try fed_bench.benchMultiMessageStream(alloc, config);
    } else if (std.mem.eql(u8, name, "failover")) {
        result = try fed_bench.benchFailoverReconnect(alloc, config);
    } else {
        std.debug.print("Unknown benchmark: {s}\n", .{name});
        printHelp();
        return;
    }

    if (result) |r| {
        try runner.results.append(r);
    }

    var stdout_buf: [2048]u8 = undefined;
    var stdout_stream = std.io.fixedBufferStream(&stdout_buf);
    try runner.printReport(stdout_stream.writer());
    std.debug.print("{s}\n", .{stdout_stream.getWritten()});
}
