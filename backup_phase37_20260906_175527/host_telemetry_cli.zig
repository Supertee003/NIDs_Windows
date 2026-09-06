// host_telemetry_cli.zig - AEGIS Phase 37 HIDS/XDR Endpoint Correlation
// CLI demo. Builds with `zig build-exe host_telemetry_cli.zig -lc`.
//
// Modes:
//   help                          - this screen
//   demo                          - 6 scenarios + PASS/FAIL summary (exit 0
//                                  iff all expected verdicts match)
//   scenario <name>               - run a single named scenario
//
// Scenarios (matches README + test suite):
//   kill-switch-off               - telemetry disabled -> no incidents
//   normal-proc                   - signed notepad -> no suspicion
//   parent-child-anomaly          - WINWORD -> cmd.exe -> PARENT_CHILD_ANOMALY
//   unsigned-system-path          - unsigned binary in System32 -> CRITICAL
//   fim-mismatch                  - svchost.exe hash changes -> MISMATCH
//   registry-persistence          - HKLM Run key set -> PERSISTENCE_KEY
//   network-correlation           - dropper -> socket -> C2 verdict -> incident

const std = @import("std");
const ht = @import("host_telemetry.zig");

const ScenarioFn = *const fn (alloc: std.mem.Allocator) bool;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 HIDS/XDR Endpoint Correlation CLI\n", .{});
    std.debug.print("=========================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, mode, "help")) {
        printHelp();
        return;
    }

    if (std.mem.eql(u8, mode, "demo")) {
        const results = [_]struct { name: []const u8, ok: bool }{
            .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff(alloc) },
            .{ .name = "normal-proc", .ok = scenarioNormalProc(alloc) },
            .{ .name = "parent-child-anomaly", .ok = scenarioParentChildAnomaly(alloc) },
            .{ .name = "unsigned-system-path", .ok = scenarioUnsignedSystemPath(alloc) },
            .{ .name = "fim-mismatch", .ok = scenarioFimMismatch(alloc) },
            .{ .name = "registry-persistence", .ok = scenarioRegistryPersistence(alloc) },
            .{ .name = "network-correlation", .ok = scenarioNetworkCorrelation(alloc) },
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
            std.debug.print("Usage: host_telemetry_cli scenario <name>\n", .{});
            std.debug.print("Names: kill-switch-off | normal-proc | parent-child-anomaly |\n", .{});
            std.debug.print("       unsigned-system-path | fim-mismatch | registry-persistence |\n", .{});
            std.debug.print("       network-correlation\n", .{});
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
    std.debug.print("  host_telemetry_cli help                          - this screen\n", .{});
    std.debug.print("  host_telemetry_cli demo                          - all 7 scenarios + summary\n", .{});
    std.debug.print("  host_telemetry_cli scenario <name>               - one scenario\n", .{});
    std.debug.print("\nScenario names:\n", .{});
    std.debug.print("  kill-switch-off       - telemetry disabled -> no incidents\n", .{});
    std.debug.print("  normal-proc           - signed notepad -> no suspicion\n", .{});
    std.debug.print("  parent-child-anomaly   - WINWORD -> cmd.exe -> PARENT_CHILD_ANOMALY\n", .{});
    std.debug.print("  unsigned-system-path   - unsigned System32 binary -> UNSIGNED_SYSTEM_PATH\n", .{});
    std.debug.print("  fim-mismatch           - svchost.exe hash changes -> FILE_INTEGRITY_MISMATCH\n", .{});
    std.debug.print("  registry-persistence   - HKLM Run key set -> REGISTRY_PERSISTENCE_KEY\n", .{});
    std.debug.print("  network-correlation   - dropper -> socket -> C2 verdict -> CRITICAL incident\n", .{});
}

fn runScenarioByName(alloc: std.mem.Allocator, name: []const u8) bool {
    if (std.mem.eql(u8, name, "kill-switch-off")) return scenarioKillSwitchOff(alloc);
    if (std.mem.eql(u8, name, "normal-proc")) return scenarioNormalProc(alloc);
    if (std.mem.eql(u8, name, "parent-child-anomaly")) return scenarioParentChildAnomaly(alloc);
    if (std.mem.eql(u8, name, "unsigned-system-path")) return scenarioUnsignedSystemPath(alloc);
    if (std.mem.eql(u8, name, "fim-mismatch")) return scenarioFimMismatch(alloc);
    if (std.mem.eql(u8, name, "registry-persistence")) return scenarioRegistryPersistence(alloc);
    if (std.mem.eql(u8, name, "network-correlation")) return scenarioNetworkCorrelation(alloc);
    std.debug.print("[ERR] unknown scenario: {s}\n", .{name});
    return false;
}

// --------------------------------------------------------------
// Scenario implementations
// --------------------------------------------------------------

fn scenarioKillSwitchOff(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = false }) catch return false;
    defer ht_inst.shutdown();

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Windows\\System32\\evil.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = ht_inst.ingestEvent(ev);
    const ok = r == .none and ht_inst.tracker.count() == 0;
    std.debug.print("  -> ingestEvent returned {s}, tracker.count={d}\n", .{
        r.toString(), ht_inst.tracker.count(),
    });
    return ok;
}

fn scenarioNormalProc(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Windows\\System32\\notepad.exe";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = ht_inst.ingestEvent(ev);
    const ok = r == .none and ht_inst.tracker.count() == 1;
    std.debug.print("  -> ingestEvent returned {s}, tracker.count={d}\n", .{
        r.toString(), ht_inst.tracker.count(),
    });
    return ok;
}

fn scenarioParentChildAnomaly(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    var parent = ht.HostEvent{
        .event_type = .process_create,
        .pid = 100,
        .ppid = 4,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 1000,
    };
    const pimg = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
    @memcpy(parent.image_path[0..pimg.len], pimg);
    parent.image_path_len = @intCast(pimg.len);
    _ = ht_inst.ingestEvent(parent);

    var child = ht.HostEvent{
        .event_type = .process_create,
        .pid = 200,
        .ppid = 100,
        .integrity = .medium,
        .is_signed = true,
        .timestamp_ns = 2000,
    };
    const cimg = "C:\\Windows\\System32\\cmd.exe";
    @memcpy(child.image_path[0..cimg.len], cimg);
    child.image_path_len = @intCast(cimg.len);
    const r = ht_inst.ingestEvent(child);

    const ok = r == .parent_child_anomaly;
    std.debug.print("  -> child spawned by WINWORD; reason={s}\n", .{r.toString()});
    return ok;
}

fn scenarioUnsignedSystemPath(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    var ev = ht.HostEvent{
        .event_type = .process_create,
        .pid = 1234,
        .ppid = 0,
        .integrity = .system,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Windows\\System32\\malware.dll";
    @memcpy(ev.image_path[0..img.len], img);
    ev.image_path_len = @intCast(img.len);

    const r = ht_inst.ingestEvent(ev);
    const ok = r == .unsigned_system_path;
    std.debug.print("  -> unsigned SYSTEM binary; reason={s}\n", .{r.toString()});
    return ok;
}

fn scenarioFimMismatch(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    const path = "C:\\Windows\\System32\\svchost.exe";
    const clean = ht.sha256("clean-svchost-binary-content");
    ht_inst.fim.setBaseline(path, clean, 50_000, 1_000_000, 0x20, 1_500_000) catch return false;

    var ev = ht.HostEvent{
        .event_type = .file_modify,
        .pid = 1234,
        .timestamp_ns = 2_000_000,
        .file_size = 52_000,
        .file_attrs = 0x20,
    };
    @memcpy(ev.file_path[0..path.len], path);
    ev.file_path_len = @intCast(path.len);
    const tampered = ht.sha256("tampered-svchost-binary-content");
    @memcpy(ev.file_hash[0..ht.SHA256_LEN], &tampered);

    const r = ht_inst.ingestEvent(ev);
    const ok = r == .file_integrity_mismatch;
    std.debug.print("  -> svchost.exe tampered; reason={s}, mismatch_count={d}\n", .{
        r.toString(), ht_inst.fim.total_mismatch,
    });
    return ok;
}

fn scenarioRegistryPersistence(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    var ev = ht.HostEvent{
        .event_type = .registry_set_value,
        .pid = 1234,
        .timestamp_ns = 1000,
    };
    const k = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor";
    @memcpy(ev.reg_key[0..k.len], k);
    ev.reg_key_len = @intCast(k.len);
    const vn = "Updater";
    @memcpy(ev.reg_value_name[0..vn.len], vn);
    ev.reg_value_name_len = vn.len;

    const r = ht_inst.ingestEvent(ev);
    const ok = r == .registry_persistence_key;
    std.debug.print("  -> HKLM Run\\Backdoor set; reason={s}, persistence_hits={d}\n", .{
        r.toString(), ht_inst.reg.total_persistence_hits,
    });
    return ok;
}

fn scenarioNetworkCorrelation(alloc: std.mem.Allocator) bool {
    var ht_inst = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer ht_inst.shutdown();

    // 1. Process launches (unsigned, suspicious)
    var pe = ht.HostEvent{
        .event_type = .process_create,
        .pid = 999,
        .ppid = 4,
        .integrity = .high,
        .is_signed = false,
        .timestamp_ns = 1000,
    };
    const img = "C:\\Users\\Public\\dropper.exe";
    @memcpy(pe.image_path[0..img.len], img);
    pe.image_path_len = @intCast(img.len);
    const pr = ht_inst.ingestEvent(pe);

    // 2. Process opens TCP socket to C2
    const se = ht.HostEvent{
        .event_type = .socket_open,
        .pid = 999,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .timestamp_ns = 2000,
    };
    _ = ht_inst.ingestEvent(se);

    // 3. ML detector emits malicious verdict for that 4-tuple
    var v = ht.NetworkFlowVerdict{
        .timestamp_ns = 3000,
        .proto = .tcp,
        .local_ip = .{ 192, 168, 1, 41 },
        .local_port = 51000,
        .remote_ip = .{ 198, 51, 100, 7 },
        .remote_port = 4444,
        .score = 0.93,
    };
    const lbl = "malicious";
    @memcpy(v.label[0..lbl.len], lbl);
    v.label_len = lbl.len;

    const idx = ht_inst.pushFlowVerdict(v) orelse {
        std.debug.print("  -> pushFlowVerdict returned null (no incident)\n", .{});
        return false;
    };
    const inc = ht_inst.correlator.getIncident(idx).?;

    const ok = inc.attributed_pid == 999 and
        inc.severity == .critical and
        inc.reason_count >= 2 and
        std.mem.eql(u8, inc.attributedImage(), "C:\\Users\\Public\\dropper.exe");

    std.debug.print("  -> proc-reason={s}, PID={d}, image={s}\n", .{
        pr.toString(), inc.attributed_pid, inc.attributedImage(),
    });
    std.debug.print("  -> incident.severity={s}, reason_count={d}, flow_score={d:.2}\n", .{
        inc.severity.toString(), inc.reason_count, inc.flow_score,
    });
    std.debug.print("  -> flow: {d}.{d}.{d}.{d}:{d} -> {d}.{d}.{d}.{d}:{d} ({s})\n", .{
        inc.flow_local_ip[0], inc.flow_local_ip[1], inc.flow_local_ip[2], inc.flow_local_ip[3],
        inc.flow_local_port,
        inc.flow_remote_ip[0], inc.flow_remote_ip[1], inc.flow_remote_ip[2], inc.flow_remote_ip[3],
        inc.flow_remote_port, inc.flow_proto.toString(),
    });
    return ok;
}
