// host_telemetry_mock_cli.zig - AEGIS Phase 37 Ext 1: Mock Telemetry Source CLI.
// Builds with `zig build-exe host_telemetry_mock_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 6 scenarios + PASS/FAIL summary (exit 0)
//   scenario <name>                   - run a single named scenario
//
// Scenarios (uses scripted attack scenarios, no Win32 API needed):
//   kill-switch-off         - mock source disabled -> no events emitted
//   macro-dropper           - WINWORD -> cmd -> dropper -> C2 socket (full chain)
//   persistence             - FIM tamper + HKLM Run key set
//   unsigned-system         - unsigned SYSTEM binary in System32
//   lateral-movement        - 5 TCP sockets to internal ports (SMB/RDP/SSH/etc)
//   full-attack-chain       - macro-dropper + ML verdict -> CRITICAL incident
//   multi-source            - 2 sources pump round-robin into same host

const std = @import("std");
const ht = @import("host_telemetry.zig");
const mock = @import("host_telemetry_mock.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 1: Mock Telemetry Source CLI\n", .{});
    std.debug.print("=======================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff(alloc) },
            .{ .name = "macro-dropper", .ok = scenarioMacroDropper(alloc) },
            .{ .name = "persistence", .ok = scenarioPersistence(alloc) },
            .{ .name = "unsigned-system", .ok = scenarioUnsignedSystem(alloc) },
            .{ .name = "lateral-movement", .ok = scenarioLateralMovement(alloc) },
            .{ .name = "full-attack-chain", .ok = scenarioFullAttackChain(alloc) },
            .{ .name = "multi-source", .ok = scenarioMultiSource(alloc) },
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
            std.debug.print("Usage: host_telemetry_mock_cli scenario <name>\n", .{});
            printHelp();
            return;
        }
        const name = args[2];
        const ok = runScenarioByName(alloc, name);
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
    std.debug.print("  host_telemetry_mock_cli help                          - this screen\n", .{});
    std.debug.print("  host_telemetry_mock_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  host_telemetry_mock_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  kill-switch-off         - mock source disabled -> no events emitted\n", .{});
    std.debug.print("  macro-dropper           - WINWORD -> cmd -> dropper -> C2 socket (full chain)\n", .{});
    std.debug.print("  persistence             - FIM tamper + HKLM Run key set\n", .{});
    std.debug.print("  unsigned-system         - unsigned SYSTEM binary in System32\n", .{});
    std.debug.print("  lateral-movement        - 5 TCP sockets to internal ports (SMB/RDP/SSH/etc)\n", .{});
    std.debug.print("  full-attack-chain       - macro-dropper + ML verdict -> CRITICAL incident\n", .{});
    std.debug.print("  multi-source            - 2 sources pump round-robin into same host\n", .{});
}

fn runScenarioByName(alloc: std.mem.Allocator, name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff(alloc);
    if (std.mem.eql(u8, name, "macro-dropper")) return scenarioMacroDropper(alloc);
    if (std.mem.eql(u8, name, "persistence")) return scenarioPersistence(alloc);
    if (std.mem.eql(u8, name, "unsigned-system")) return scenarioUnsignedSystem(alloc);
    if (std.mem.eql(u8, name, "lateral-movement")) return scenarioLateralMovement(alloc);
    if (std.mem.eql(u8, name, "full-attack-chain")) return scenarioFullAttackChain(alloc);
    if (std.mem.eql(u8, name, "multi-source")) return scenarioMultiSource(alloc);
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = false }) catch return false;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("test", .{ .enabled = true });
    _ = src.appendEvent(.{ .event_type = .process_create, .pid = 1, .timestamp_ns = 0 }, 0);

    var pump = mock.EventPump.init(src.asSource(), host);
    const r = pump.pumpOnce(0);
    const ok = switch (r) {
        .disabled => true,
        else => false,
    };
    std.debug.print("  -> kill switch off; pump returned {s}; total_pumped={d}\n", .{
        if (ok) "disabled (expected)" else "unexpected",
        pump.total_pumped,
    });
    return ok;
}

fn scenarioMacroDropper(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("macro-dropper", .{ .enabled = true });
    mock.buildMacroDropperScenario(&src) catch return false;

    var pump = mock.EventPump.init(src.asSource(), host);
    const count = pump.pumpAll(0, 100);

    const ok = count == 4 and
        pump.total_suspicion_emitted >= 2 and
        host.tracker.suspicious_parent_pairs == 1;
    std.debug.print("  -> pumped {d} events; suspicion_emitted={d}; parent_anomalies={d}\n", .{
        count, pump.total_suspicion_emitted, host.tracker.suspicious_parent_pairs,
    });
    return ok;
}

fn scenarioPersistence(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    // Pre-establish FIM baseline so the tamper is detected
    const path = "C:\\Windows\\System32\\svchost.exe";
    const clean = ht.sha256("clean-svchost-binary-content");
    host.fim.setBaseline(path, clean, 50_000, 1_000_000, 0x20, 1_500_000) catch return false;

    var src = mock.MockTelemetrySource.init("persistence", .{ .enabled = true });
    mock.buildPersistenceScenario(&src) catch return false;

    var pump = mock.EventPump.init(src.asSource(), host);
    const count = pump.pumpAll(0, 100);

    const ok = count == 2 and
        host.fim.total_mismatch == 1 and
        host.reg.total_persistence_hits == 1;
    std.debug.print("  -> pumped {d} events; FIM mismatches={d}; persistence_hits={d}\n", .{
        count, host.fim.total_mismatch, host.reg.total_persistence_hits,
    });
    return ok;
}

fn scenarioUnsignedSystem(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("unsigned-system", .{ .enabled = true });
    mock.buildUnsignedSystemScenario(&src) catch return false;

    var pump = mock.EventPump.init(src.asSource(), host);
    const count = pump.pumpAll(0, 100);

    const ok = count == 1 and
        host.tracker.total_suspicious == 1;
    std.debug.print("  -> pumped {d} events; suspicious_processes={d}\n", .{
        count, host.tracker.total_suspicious,
    });
    return ok;
}

fn scenarioLateralMovement(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("lateral", .{ .enabled = true });
    mock.buildLateralMovementScenario(&src) catch return false;

    var pump = mock.EventPump.init(src.asSource(), host);
    const count = pump.pumpAll(0, 100);

    const sockets = host.sockets.socketsForPid(4321);
    const ok = count == 5 and sockets.len == 5;
    std.debug.print("  -> pumped {d} events; sockets_for_pid_4321={d}\n", .{
        count, sockets.len,
    });
    return ok;
}

fn scenarioFullAttackChain(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var src = mock.MockTelemetrySource.init("full-chain", .{ .enabled = true });
    mock.buildMacroDropperScenario(&src) catch return false;

    var pump = mock.EventPump.init(src.asSource(), host);
    _ = pump.pumpAll(0, 100);

    // Now emit a malicious flow verdict for the dropper's C2 socket
    const idx = host.pushFlowVerdict(.{
        .timestamp_ns = 30_000_000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .score = 0.95,
    }) orelse return false;

    const inc = host.correlator.getIncident(idx).?;
    const ok = inc.attributed_pid == 300 and
        inc.severity == .critical and
        inc.reason_count >= 2;
    std.debug.print("  -> attributed to PID={d}, image='{s}', severity={s}, reasons={d}\n", .{
        inc.attributed_pid, inc.attributedImage(), inc.severity.toString(), inc.reason_count,
    });
    return ok;
}

fn scenarioMultiSource(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var src1 = mock.MockTelemetrySource.init("proc-source", .{ .enabled = true });
    var src2 = mock.MockTelemetrySource.init("socket-source", .{ .enabled = true });

    // src1 emits 2 process-create events (delay=0 for deterministic test)
    _ = src1.appendEvent(.{
        .event_type = .process_create,
        .pid = 100,
        .ppid = 4,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 0,
    }, 0);
    _ = src1.appendEvent(.{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 0,
    }, 0);

    // src2 emits 2 socket-open events for PID 200 (delay=0)
    _ = src2.appendEvent(.{
        .event_type = .socket_open,
        .pid = 200,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 50000,
        .remote_ip = .{ 8, 8, 8, 8 },
        .remote_port = 53,
        .timestamp_ns = 0,
    }, 0);
    _ = src2.appendEvent(.{
        .event_type = .socket_open,
        .pid = 200,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 50001,
        .remote_ip = .{ 1, 1, 1, 1 },
        .remote_port = 53,
        .timestamp_ns = 0,
    }, 0);

    var sources = [_]mock.HostTelemetrySource{ src1.asSource(), src2.asSource() };
    var pump = mock.MultiSourcePump.init(&sources, host);

    var count: u32 = 0;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const r = pump.pumpOnce(0);
        switch (r) {
            .emitted => count += 1,
            .all_exhausted => break,
            else => {},
        }
    }

    const ok = count == 4 and host.tracker.count() == 2 and host.sockets.socketsForPid(200).len == 2;
    std.debug.print("  -> pumped {d} events round-robin; processes_tracked={d}; sockets_pid_200={d}\n", .{
        count, host.tracker.count(), host.sockets.socketsForPid(200).len,
    });
    return ok;
}
