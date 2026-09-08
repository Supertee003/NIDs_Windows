// windows_adapters_cli.zig - AEGIS Phase 37 Ext 4: Windows Telemetry Adapter CLI.
// Builds with `zig build-exe windows_adapters_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - run all 5 scenarios + summary
//   scenario <name>                   - run a single named scenario

const std = @import("std");
const wa = @import("windows_adapters.zig");
const ht = @import("host_telemetry.zig");
const mock = @import("host_telemetry_mock.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 4: Windows Telemetry Adapter CLI\n", .{});
    std.debug.print("=============================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "platform-detection", .ok = scenarioPlatformDetection() },
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff() },
            .{ .name = "process-source", .ok = scenarioProcessSource() },
            .{ .name = "fim-source", .ok = scenarioFimSource() },
            .{ .name = "registry-source", .ok = scenarioRegistrySource() },
            .{ .name = "bundle-multi-source", .ok = scenarioBundleMultiSource() },
        };
        var passed: usize = 0;
        for (results) |r| {
            const tag = if (r.ok) "PASS" else "FAIL";
            std.debug.print("  [{s}] {s}\n", .{ tag, r.name });
            if (r.ok) passed += 1;
        }
        std.debug.print("\n{d}/{d} scenarios passed\n", .{ passed, results.len });
        if (passed != results.len) std.process.exit(1);
        return;
    }

    if (std.mem.eql(u8, mode, "scenario")) {
        if (args.len < 3) {
            std.debug.print("Usage: windows_adapters_cli scenario <name>\n", .{});
            printHelp();
            return;
        }
        const name = args[2];
        const ok = runScenarioByName(name);
        const tag = if (ok) "PASS" else "FAIL";
        std.debug.print("\n  [{s}] {s}\n", .{ tag, name });
        if (!ok) std.process.exit(1);
        return;
    }

    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  windows_adapters_cli help                          - this screen\n", .{});
    std.debug.print("  windows_adapters_cli demo                          - all 6 scenarios + summary\n", .{});
    std.debug.print("  windows_adapters_cli scenario <name>               - single scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  platform-detection      - detect platform + print capabilities\n", .{});
    std.debug.print("  kill-switch-off          - adapters respect kill switch\n", .{});
    std.debug.print("  process-source          - EtwProcessSource lifecycle\n", .{});
    std.debug.print("  fim-source               - FimReadDirectorySource lifecycle\n", .{});
    std.debug.print("  registry-source         - RegNotifySource with watched keys\n", .{});
    std.debug.print("  bundle-multi-source      - all 3 adapters via MultiSourcePump\n", .{});
}

fn runScenarioByName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "platform-detection")) return scenarioPlatformDetection();
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff();
    if (std.mem.eql(u8, name, "process-source")) return scenarioProcessSource();
    if (std.mem.eql(u8, name, "fim-source")) return scenarioFimSource();
    if (std.mem.eql(u8, name, "registry-source")) return scenarioRegistrySource();
    if (std.mem.eql(u8, name, "bundle-multi-source")) return scenarioBundleMultiSource();
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioPlatformDetection() bool {
    const caps = wa.PlatformCapabilities.detect();
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    caps.print(stream.writer()) catch return false;
    std.debug.print("{s}\n", .{stream.getWritten()});

    // On Linux: all capabilities should be false (stubs)
    // On Windows: all capabilities should be true (real adapters)
    const expected_real = wa.isWindows();
    const ok = caps.process_tracking == expected_real and
        caps.file_integrity == expected_real and
        caps.registry_watch == expected_real;
    std.debug.print("  -> platform={s}, expected_real={}, caps_match={}\n", .{
        wa.platformName(), expected_real, ok,
    });
    return ok;
}

fn scenarioKillSwitchOff() bool {
    var proc = wa.EtwProcessSource.init("test", .{ .enabled = false });
    const err = proc.start();
    const ok = if (err) |_| false else |e| e == error.SourceDisabled;
    std.debug.print("  -> kill switch off; start returned {s}\n", .{
        if (ok) "SourceDisabled (expected)" else "unexpected-success",
    });
    return ok;
}

fn scenarioProcessSource() bool {
    var proc = wa.EtwProcessSource.init("etw-proc", .{ .enabled = true });
    proc.start() catch return false;

    // Poll a few times (stub returns null on Linux)
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        _ = proc.nextEventImpl(@as(i64, @intCast(i)) * 1_000_000) catch return false;
    }
    const ok = proc.poll_count == 3 and !proc.isExhaustedImpl();
    std.debug.print("  -> polled {d} times; poll_count={d}, exhausted={}\n", .{
        3, proc.poll_count, proc.isExhaustedImpl(),
    });
    return ok;
}

fn scenarioFimSource() bool {
    var fim = wa.FimReadDirectorySource.init("fim", "C:\\Windows\\System32", .{ .enabled = true });
    fim.start() catch return false;

    const ev = fim.nextEventImpl(0) catch return false;
    const ok = ev == null; // stub returns null on Linux
    std.debug.print("  -> FIM watching '{s}'; first poll event={s}\n", .{
        fim.watchPath(), if (ok) "null (stub expected)" else "unexpected-event",
    });
    return ok;
}

fn scenarioRegistrySource() bool {
    var reg = wa.RegNotifySource.init("reg", .{ .enabled = true });
    _ = reg.addWatchedKey("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    _ = reg.addWatchedKey("\\REGISTRY\\MACHINE\\SAM\\SAM");
    reg.start() catch return false;

    const ev = reg.nextEventImpl(0) catch return false;
    const ok = ev == null and reg.watchedKeyCount() == 2;
    std.debug.print("  -> watching {d} registry keys; first poll event={s}\n", .{
        reg.watchedKeyCount(), if (ev == null) "null (stub expected)" else "unexpected-event",
    });
    return ok;
}

fn scenarioBundleMultiSource() bool {
    var bundle = wa.WindowsAdapterBundle.init("node1", "C:\\Windows\\System32", .{ .enabled = true });
    bundle.installDefaultRegistryKeys();
    bundle.start() catch return false;

    const srcs = bundle.sources();
    const ok = srcs[0].name().len > 0 and
        srcs[1].name().len > 0 and
        srcs[2].name().len > 0 and
        bundle.registry_source.watchedKeyCount() == 6;
    std.debug.print("  -> bundle sources: [{s}, {s}, {s}]; registry_keys={d}\n", .{
        srcs[0].name(), srcs[1].name(), srcs[2].name(),
        bundle.registry_source.watchedKeyCount(),
    });
    return ok;
}
