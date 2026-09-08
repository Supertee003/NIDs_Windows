// host_telemetry_scenarios_cli.zig - AEGIS Phase 37 Ext 2: Scenario Library CLI.
// Builds with `zig build-exe host_telemetry_scenarios_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 7 scenarios + PASS/FAIL summary (exit 0)
//   scenario <name>                   - run a single named scenario
//
// Scenarios (5 MITRE techniques + 2 combined attack chains):
//   credential-dump          - T1003 LSASS dump + exfil socket
//   command-execution        - T1059 powershell -enc + curl download
//   ransomware               - T1486 mass file_modify + ransom note
//   valid-accounts           - T1078 admin logon + lateral SMB
//   webshell                 - T1190 webshell drop + reverse shell
//   full-kill-chain          - T1190+T1486 combined attack chain
//   multi-technique          - 5 scenarios concurrently via MultiSourcePump

const std = @import("std");
const ht = @import("host_telemetry.zig");
const mock = @import("host_telemetry_mock.zig");
const scn = @import("host_telemetry_scenarios.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 2: Scenario Library CLI\n", .{});
    std.debug.print("=================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "credential-dump", .ok = scenarioCredentialDump(alloc) },
            .{ .name = "command-execution", .ok = scenarioCommandExecution(alloc) },
            .{ .name = "ransomware", .ok = scenarioRansomware(alloc) },
            .{ .name = "valid-accounts", .ok = scenarioValidAccounts(alloc) },
            .{ .name = "webshell", .ok = scenarioWebshell(alloc) },
            .{ .name = "full-kill-chain", .ok = scenarioFullKillChain(alloc) },
            .{ .name = "multi-technique", .ok = scenarioMultiTechnique(alloc) },
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
            std.debug.print("Usage: host_telemetry_scenarios_cli scenario <name>\n", .{});
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
    std.debug.print("  host_telemetry_scenarios_cli help                          - this screen\n", .{});
    std.debug.print("  host_telemetry_scenarios_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  host_telemetry_scenarios_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names (5 MITRE techniques + 2 combined):\n", .{});
    std.debug.print("  credential-dump          - T1003 LSASS dump + exfil socket\n", .{});
    std.debug.print("  command-execution        - T1059 powershell -enc + curl download\n", .{});
    std.debug.print("  ransomware               - T1486 mass file_modify + ransom note\n", .{});
    std.debug.print("  valid-accounts           - T1078 admin logon + lateral SMB\n", .{});
    std.debug.print("  webshell                 - T1190 webshell drop + reverse shell\n", .{});
    std.debug.print("  full-kill-chain          - T1190+T1486 combined attack chain\n", .{});
    std.debug.print("  multi-technique          - 5 scenarios concurrently via MultiSourcePump\n", .{});
}

fn runScenarioByName(alloc: std.mem.Allocator, name: []const u8) bool {
    if (std.mem.eql(u8, name, "credential-dump")) return scenarioCredentialDump(alloc);
    if (std.mem.eql(u8, name, "command-execution")) return scenarioCommandExecution(alloc);
    if (std.mem.eql(u8, name, "ransomware")) return scenarioRansomware(alloc);
    if (std.mem.eql(u8, name, "valid-accounts")) return scenarioValidAccounts(alloc);
    if (std.mem.eql(u8, name, "webshell")) return scenarioWebshell(alloc);
    if (std.mem.eql(u8, name, "full-kill-chain")) return scenarioFullKillChain(alloc);
    if (std.mem.eql(u8, name, "multi-technique")) return scenarioMultiTechnique(alloc);
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioCredentialDump(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("credential-dump", .{ .enabled = true });
    scn.buildCredentialDumpScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 3 events pumped, 1 unsigned HIGH process triggers suspicion,
    // 1 socket tracked for exfiltration
    const ok = count == 3 and
        pump.total_suspicion_emitted == 1 and
        host.sockets.socketsForPid(1500).len == 1;
    std.debug.print("  -> pumped {d} events; suspicion={d}; exfil_socket_tracked={}\n", .{
        count, pump.total_suspicion_emitted, host.sockets.socketsForPid(1500).len == 1,
    });
    return ok;
}

fn scenarioCommandExecution(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("command-execution", .{ .enabled = true });
    scn.buildCommandExecutionScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 4 events pumped, 3 processes tracked (cmd/ps/curl),
    // 1 outbound socket (port 80)
    const ok = count == 4 and
        host.tracker.count() == 3 and
        host.sockets.socketsForPid(2200).len == 1;
    std.debug.print("  -> pumped {d} events; processes_tracked={d}; download_socket={}\n", .{
        count, host.tracker.count(), host.sockets.socketsForPid(2200).len == 1,
    });
    return ok;
}

fn scenarioRansomware(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("ransomware", .{ .enabled = true });
    scn.buildRansomwareScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 7 events pumped (1 proc + 5 file_modify + 1 file_create),
    // unsigned HIGH process triggers suspicion, 6 FIM observations
    const ok = count == 7 and
        pump.total_suspicion_emitted == 1 and
        host.fim.total_created == 6;
    std.debug.print("  -> pumped {d} events; suspicion={d}; FIM_creates={d}\n", .{
        count, pump.total_suspicion_emitted, host.fim.total_created,
    });
    return ok;
}

fn scenarioValidAccounts(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("valid-accounts", .{ .enabled = true });
    scn.buildValidAccountsScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 3 events pumped, 2 processes tracked (svchost + cmd),
    // 1 lateral movement socket to port 445 (SMB)
    const ok = count == 3 and
        host.tracker.count() == 2 and
        host.sockets.socketsForPid(4000).len == 1;
    std.debug.print("  -> pumped {d} events; processes_tracked={d}; lateral_socket={}\n", .{
        count, host.tracker.count(), host.sockets.socketsForPid(4000).len == 1,
    });
    return ok;
}

fn scenarioWebshell(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("webshell", .{ .enabled = true });
    scn.buildWebshellScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 4 events pumped, 2 processes tracked (w3wp + cmd),
    // 1 reverse shell socket to C2 (port 4444)
    const ok = count == 4 and
        host.tracker.count() == 2 and
        host.sockets.socketsForPid(5100).len == 1;
    std.debug.print("  -> pumped {d} events; processes_tracked={d}; reverse_shell={}\n", .{
        count, host.tracker.count(), host.sockets.socketsForPid(5100).len == 1,
    });
    return ok;
}

fn scenarioFullKillChain(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s = mock.MockTelemetrySource.init("full-kill-chain", .{ .enabled = true });
    scn.buildFullKillChainScenario(&s) catch return false;

    var pump = mock.EventPump.init(s.asSource(), host);
    const count = pump.pumpAll(0, 100);

    // Verify: 8 events pumped (4 webshell + 1 rw_proc + 3 file_modify),
    // 3 processes tracked (w3wp + cmd + rw_proc), 1 reverse shell
    const ok = count == 8 and
        host.tracker.count() == 3 and
        host.sockets.socketsForPid(5100).len == 1;
    std.debug.print("  -> pumped {d} events; processes_tracked={d}; reverse_shell={}\n", .{
        count, host.tracker.count(), host.sockets.socketsForPid(5100).len == 1,
    });
    return ok;
}

fn scenarioMultiTechnique(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();

    var s1 = mock.MockTelemetrySource.init("cred-dump", .{ .enabled = true });
    scn.buildCredentialDumpScenario(&s1) catch return false;
    var s2 = mock.MockTelemetrySource.init("cmd-exec", .{ .enabled = true });
    scn.buildCommandExecutionScenario(&s2) catch return false;
    var s3 = mock.MockTelemetrySource.init("ransomware", .{ .enabled = true });
    scn.buildRansomwareScenario(&s3) catch return false;
    var s4 = mock.MockTelemetrySource.init("valid-accts", .{ .enabled = true });
    scn.buildValidAccountsScenario(&s4) catch return false;
    var s5 = mock.MockTelemetrySource.init("webshell", .{ .enabled = true });
    scn.buildWebshellScenario(&s5) catch return false;

    var sources = [_]mock.HostTelemetrySource{
        s1.asSource(),
        s2.asSource(),
        s3.asSource(),
        s4.asSource(),
        s5.asSource(),
    };
    var pump = mock.MultiSourcePump.init(&sources, host);

    var count: u32 = 0;
    var i: u32 = 0;
    while (i < 500) : (i += 1) {
        const t_ns: i64 = @as(i64, @intCast(i)) * 1_000_000;
        const r = pump.pumpOnce(t_ns);
        switch (r) {
            .emitted => count += 1,
            .all_exhausted => break,
            else => {},
        }
    }

    // Verify: all 21 events pumped across 5 concurrent scenarios
    const ok = count == 21;
    std.debug.print("  -> pumped {d} events across 5 scenarios round-robin\n", .{count});
    return ok;
}
