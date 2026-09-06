// perf_benchmark_cli.zig - AEGIS Phase 41: Performance Benchmark CLI.
// Builds with `zig build-exe perf_benchmark_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - run all 6 benchmarks + threshold check
//   quick                             - fast run (100 iters, 10 warmup)
//   full                              - full run (10000 iters, 100 warmup)
//   scenario <name>                   - run a single named benchmark

const std = @import("std");
const perf = @import("perf_benchmark.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 41: Performance Benchmark Suite\n", .{});
    std.debug.print("=================================================\n\n", .{});

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
        try runBenchmarks(alloc, .{ .enabled = true, .iterations = 10_000, .warmup = 100 });
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        try runBenchmarks(alloc, .{ .enabled = true, .iterations = 1000, .warmup = 50 });
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: perf_benchmark_cli scenario <name>\n", .{});
            std.debug.print("Names: process-tracker | fim | registry | codec | aggregator | pipeline\n", .{});
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
    std.debug.print("  perf_benchmark_cli help                          - this screen\n", .{});
    std.debug.print("  perf_benchmark_cli quick                        - fast run (100 iters)\n", .{});
    std.debug.print("  perf_benchmark_cli demo                          - balanced run (1000 iters)\n", .{});
    std.debug.print("  perf_benchmark_cli full                          - full run (10000 iters)\n", .{});
    std.debug.print("  perf_benchmark_cli scenario <name>               - single benchmark\n", .{});
    std.debug.print("\nBenchmark names:\n", .{});
    std.debug.print("  process-tracker   - ProcessTracker throughput (100 creates)\n", .{});
    std.debug.print("  fim               - FileIntegrityStore throughput (50 baselines + observes)\n", .{});
    std.debug.print("  registry          - RegistryWatchQueue throughput (100 enqueues)\n", .{});
    std.debug.print("  codec             - Federation codec encode+decode throughput\n", .{});
    std.debug.print("  aggregator        - CrossNodeIncidentAggregator throughput (50 reports)\n", .{});
    std.debug.print("  pipeline          - Full pipeline (4 events -> incidents)\n", .{});
}

fn runBenchmarks(alloc: std.mem.Allocator, config: perf.BenchConfig) !void {
    std.debug.print("Running benchmarks (warmup={d}, iterations={d})...\n", .{
        config.warmup, config.iterations,
    });

    var runner = try perf.runAllBenchmarks(alloc, config);
    defer runner.deinit();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_stream = std.io.fixedBufferStream(&stdout_buf);
    try runner.printReport(stdout_stream.writer());
    std.debug.print("{s}\n", .{stdout_stream.getWritten()});

    // Threshold check
    var thresholds = perf.checkThresholds(&runner);
    defer thresholds.deinit();

    std.debug.print("Threshold check:\n", .{});
    var all_passed = true;
    for (thresholds.items) |t| {
        const tag = if (t.passed) "PASS" else "FAIL";
        std.debug.print("  [{s}] {s:<45} actual={d:>10.0} threshold={d:>10.0}\n", .{
            tag, t.name, t.actual, t.threshold,
        });
        if (!t.passed) all_passed = false;
    }
    std.debug.print("\n", .{});
    if (all_passed) {
        std.debug.print("All thresholds passed - pipeline ready for production traffic.\n", .{});
    } else {
        std.debug.print("Some thresholds failed - review performance.\n", .{});
    }
}

fn runSingleBenchmark(alloc: std.mem.Allocator, name: []const u8) !void {
    var runner = perf.BenchRunner.init(alloc, .{ .enabled = true, .iterations = 1000, .warmup = 50 });
    defer runner.deinit();

    if (std.mem.eql(u8, name, "process-tracker")) {
        try runner.run("ProcessTracker (100 creates)", &perf.processTrackerBenchCallback);
    } else if (std.mem.eql(u8, name, "fim")) {
        try runner.run("FileIntegrityStore (50 baselines + observes)", &perf.fimBenchCallback);
    } else if (std.mem.eql(u8, name, "registry")) {
        try runner.run("RegistryWatchQueue (100 enqueues)", &perf.registryBenchCallback);
    } else if (std.mem.eql(u8, name, "codec")) {
        try runner.runWithBytes("Federation codec (10 encode+decode)", 200, &perf.codecBenchCallback);
    } else if (std.mem.eql(u8, name, "aggregator")) {
        try runner.run("CrossNodeAggregator (50 reports)", &perf.aggregatorBenchCallback);
    } else if (std.mem.eql(u8, name, "pipeline")) {
        try runner.run("Full pipeline (4 events -> incidents)", &perf.fullPipelineBenchCallback);
    } else {
        std.debug.print("Unknown benchmark: {s}\n", .{name});
        printHelp();
        return;
    }

    var stdout_buf: [2048]u8 = undefined;
    var stdout_stream = std.io.fixedBufferStream(&stdout_buf);
    try runner.printReport(stdout_stream.writer());
    std.debug.print("{s}\n", .{stdout_stream.getWritten()});
}
