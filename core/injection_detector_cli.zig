// injection_detector_cli.zig - AEGIS Phase 37 Ext 7: Full T1055 Injection Detection CLI.
const std = @import("std");
const inj = @import("injection_detector.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 7: Full T1055 Process Injection Detection CLI\n", .{});
    std.debug.print("====================================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";
    if (std.mem.eql(u8, mode, "help")) { printHelp(); return; }
    if (std.mem.eql(u8, mode, "demo")) { try runDemo(); return; }
    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n  injection_detector_cli help  - this screen\n  injection_detector_cli demo  - run 6 scenarios\n", .{});
}

fn runDemo() !void {
    const results = [_]struct { name: []const u8, ok: bool }{
        .{ .name = "kill-switch-off", .ok = scenarioKillSwitchOff() },
        .{ .name = "create-remote-thread", .ok = scenarioCreateRemoteThread() },
        .{ .name = "virtual-alloc-rwx", .ok = scenarioVirtualAllocRwx() },
        .{ .name = "apc-injection", .ok = scenarioApcInjection() },
        .{ .name = "dll-injection-chain", .ok = scenarioDllInjectionChain() },
        .{ .name = "pe-injection-chain", .ok = scenarioPeInjectionChain() },
    };
    var passed: usize = 0;
    for (results) |r| {
        const tag = if (r.ok) "PASS" else "FAIL";
        std.debug.print("  [{s}] {s}\n", .{ tag, r.name });
        if (r.ok) passed += 1;
    }
    std.debug.print("\n{d}/{d} scenarios passed\n", .{ passed, results.len });
    if (passed != results.len) std.process.exit(1);
}

fn scenarioKillSwitchOff() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = false });
    const alert = d.ingest(.{ .event_type = .create_remote_thread, .source_pid = 1, .target_pid = 2 });
    const ok = alert == null;
    std.debug.print("  -> kill switch off; alert={s}\n", .{if (ok) "null (expected)" else "unexpected"});
    return ok;
}

fn scenarioCreateRemoteThread() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = true });
    const alert = d.ingest(.{ .event_type = .create_remote_thread, .source_pid = 100, .target_pid = 200, .timestamp_ns = 1_000_000 });
    const ok = alert != null and alert.?.technique == .create_remote_thread;
    std.debug.print("  -> CreateRemoteThread; technique={s}, confidence={d}\n", .{ alert.?.technique.toString(), alert.?.confidence });
    return ok;
}

fn scenarioVirtualAllocRwx() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = true });
    const alert = d.ingest(.{ .event_type = .virtual_alloc_ex, .source_pid = 100, .target_pid = 200, .alloc_size = 8192, .alloc_protection = 0x40, .timestamp_ns = 1_000_000 });
    const ok = alert != null and alert.?.technique == .pe_injection;
    std.debug.print("  -> VirtualAllocEx RWX; technique={s}\n", .{alert.?.technique.toString()});
    return ok;
}

fn scenarioApcInjection() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = true });
    const alert = d.ingest(.{ .event_type = .queue_user_apc, .source_pid = 100, .target_pid = 200, .timestamp_ns = 1_000_000 });
    const ok = alert != null and alert.?.technique == .apc_injection;
    std.debug.print("  -> QueueUserAPC; technique={s}, MITRE={s}\n", .{ alert.?.technique.toString(), alert.?.technique.mitreId() });
    return ok;
}

fn scenarioDllInjectionChain() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = true });
    _ = d.ingest(.{ .event_type = .virtual_alloc_ex, .source_pid = 1000, .target_pid = 2000, .alloc_size = 65536, .alloc_protection = 0x04, .timestamp_ns = 1_000_000 });
    _ = d.ingest(.{ .event_type = .write_process_memory, .source_pid = 1000, .target_pid = 2000, .write_size = 32768, .timestamp_ns = 1_500_000 });
    const alert = d.ingest(.{ .event_type = .create_remote_thread, .source_pid = 1000, .target_pid = 2000, .timestamp_ns = 2_000_000 });
    const ok = alert != null and alert.?.technique == .dll_injection and alert.?.confidence == 95;
    std.debug.print("  -> 3-step DLL injection chain; technique={s}, confidence={d}, chain={d}\n", .{ alert.?.technique.toString(), alert.?.confidence, alert.?.chain_count });
    return ok;
}

fn scenarioPeInjectionChain() bool {
    var d = inj.InjectionDetector.init(.{ .enabled = true });
    _ = d.ingest(.{ .event_type = .virtual_alloc_ex, .source_pid = 100, .target_pid = 200, .alloc_size = 32768, .alloc_protection = 0x40, .timestamp_ns = 1_000_000 });
    const alert = d.ingest(.{ .event_type = .create_remote_thread, .source_pid = 100, .target_pid = 200, .timestamp_ns = 2_000_000 });
    const ok = alert != null and alert.?.technique == .pe_injection and alert.?.confidence == 90;
    std.debug.print("  -> PE injection chain (RWX+CRT); technique={s}, confidence={d}\n", .{ alert.?.technique.toString(), alert.?.confidence });
    return ok;
}
