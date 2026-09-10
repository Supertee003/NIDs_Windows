// integration_test_cli.zig - AEGIS Phase 44: End-to-End Integration Test CLI.
// Builds with `zig build-exe integration_test_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - run all 6 integration scenarios + summary
//   scenario <name>                   - run a single named scenario

const std = @import("std");
const integ = @import("integration_test.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 44: End-to-End Integration Test CLI\n", .{});
    std.debug.print("========================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        try runAllScenarios(alloc);
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: integration_test_cli scenario <name>\n", .{});
            printHelp();
            return;
        }
        try runSingleScenario(alloc, args[2]);
        return;
    }

    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  integration_test_cli help                          - this screen\n", .{});
    std.debug.print("  integration_test_cli demo                          - all 6 scenarios + summary\n", .{});
    std.debug.print("  integration_test_cli scenario <name>               - single scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  single-node-attack        - macro-dropper -> correlated incident\n", .{});
    std.debug.print("  cross-node-campaign       - 3 nodes -> CRITICAL escalation\n", .{});
    std.debug.print("  federation-failover       - encode/decode roundtrip (3 msg types)\n", .{});
    std.debug.print("  full-kill-chain           - webshell -> ransomware (8 events)\n", .{});
    std.debug.print("  detector-aggregation      - multiple detectors fire on one event\n", .{});
    std.debug.print("  multi-source-correlation  - process + socket -> attributed incident\n", .{});
}

fn runAllScenarios(alloc: std.mem.Allocator) !void {
    std.debug.print("Running 6 end-to-end integration scenarios...\n\n", .{});

    var runner = try integ.runAllIntegrationTests(alloc, .{ .enabled = true });
    defer runner.deinit();

    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try runner.printReport(stream.writer());
    std.debug.print("{s}\n", .{stream.getWritten()});

    if (!runner.allPassed()) {
        std.process.exit(1);
    }
}

fn runSingleScenario(alloc: std.mem.Allocator, name: []const u8) !void {
    const config = integ.IntegrationConfig{ .enabled = true };
    var result: integ.IntegrationResult = undefined;

    if (std.mem.eql(u8, name, "single-node-attack")) {
        result = try integ.scenarioSingleNodeAttack(alloc, config);
    } else if (std.mem.eql(u8, name, "cross-node-campaign")) {
        result = try integ.scenarioCrossNodeCampaign(alloc, config);
    } else if (std.mem.eql(u8, name, "federation-failover")) {
        result = try integ.scenarioFederationFailover(alloc, config);
    } else if (std.mem.eql(u8, name, "full-kill-chain")) {
        result = try integ.scenarioFullKillChain(alloc, config);
    } else if (std.mem.eql(u8, name, "detector-aggregation")) {
        result = try integ.scenarioDetectorAggregation(alloc, config);
    } else if (std.mem.eql(u8, name, "multi-source-correlation")) {
        result = try integ.scenarioMultiSourceCorrelation(alloc, config);
    } else {
        std.debug.print("Unknown scenario: {s}\n", .{name});
        printHelp();
        return;
    }

    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try result.print(stream.writer());
    std.debug.print("{s}\n", .{stream.getWritten()});

    if (!result.passed) {
        std.process.exit(1);
    }
}
