// etw_realtime_cli.zig - AEGIS Phase 37 Ext 5: Full ETW Real-time CLI.
const std = @import("std");
const etw = @import("etw_realtime.zig");
const ht = @import("host_telemetry.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    std.debug.print("AEGIS NIDS - Phase 37 Ext 5: Full ETW Real-time Capture CLI\n", .{});
    std.debug.print("============================================================\n\n", .{});

    const mode: []const u8 = if (args.len >= 2) args[1] else "help";
    if (std.mem.eql(u8, mode, "help")) { printHelp(); return; }
    if (std.mem.eql(u8, mode, "demo")) { try runDemo(alloc); return; }
    if (std.mem.eql(u8, mode, "scenario") and args.len >= 3) { try runSingle(alloc, args[2]); return; }
    std.debug.print("Unknown mode: {s}\n", .{mode});
    printHelp();
}

fn printHelp() void {
    std.debug.print("Usage:\n  etw_realtime_cli help  - this screen\n  etw_realtime_cli demo  - run 5 scenarios\n  etw_realtime_cli scenario <name>\n", .{});
}

fn runDemo(alloc: std.mem.Allocator) !void {
    const results = [_]struct { name: []const u8, ok: bool }{
        .{ .name = "session-lifecycle", .ok = scenarioSessionLifecycle(alloc) },
        .{ .name = "event-callback", .ok = scenarioEventCallback(alloc) },
        .{ .name = "queue-overflow", .ok = scenarioQueueOverflow(alloc) },
        .{ .name = "multi-provider", .ok = scenarioMultiProvider(alloc) },
        .{ .name = "integration-pump", .ok = scenarioIntegrationPump(alloc) },
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

fn runSingle(alloc: std.mem.Allocator, name: []const u8) !void {
    const ok = if (std.mem.eql(u8, name, "session-lifecycle")) scenarioSessionLifecycle(alloc)
        else if (std.mem.eql(u8, name, "event-callback")) scenarioEventCallback(alloc)
        else if (std.mem.eql(u8, name, "queue-overflow")) scenarioQueueOverflow(alloc)
        else if (std.mem.eql(u8, name, "multi-provider")) scenarioMultiProvider(alloc)
        else if (std.mem.eql(u8, name, "integration-pump")) scenarioIntegrationPump(alloc)
        else { std.debug.print("Unknown: {s}\n", .{name}); return; };
    std.debug.print("  [{s}] {s}\n", .{ if (ok) "PASS" else "FAIL", name });
}

fn scenarioSessionLifecycle(alloc: std.mem.Allocator) bool {
    var s = etw.EtwRealtimeSource.init(alloc, "etw-session", .{ .enabled = true });
    defer s.deinit();
    s.start() catch return false;
    const running = s.state == .running;
    s.stop();
    const stopped = s.state == .stopped;
    std.debug.print("  -> session start->stop; was_running={} stopped={}\n", .{ running, stopped });
    return running and stopped;
}

fn scenarioEventCallback(alloc: std.mem.Allocator) bool {
    var s = etw.EtwRealtimeSource.init(alloc, "cb-test", .{ .enabled = true });
    defer s.deinit();
    s.start() catch return false;
    s.onEventCallback(.{ .process_id = 42, .provider_guid = etw.KERNEL_PROCESS_GUID.guid, .event_id = 1 });
    const ev = s.nextEventImpl(0) catch return false;
    const ok = ev != null and ev.?.pid == 42;
    std.debug.print("  -> callback -> queue -> HostEvent; pid={d}\n", .{if (ev) |e| e.pid else 0});
    return ok;
}

fn scenarioQueueOverflow(alloc: std.mem.Allocator) bool {
    var s = etw.EtwRealtimeSource.init(alloc, "overflow-test", .{ .enabled = true, .max_event_buffer = 4 });
    defer s.deinit();
    s.start() catch return false;
    var i: u32 = 0;
    while (i < 10) : (i += 1) s.onEventCallback(.{ .process_id = i });
    const ok = s.pendingEvents() == 4; // buffer caps at 4
    std.debug.print("  -> enqueued 10, pending={d} (capped at 4)\n", .{s.pendingEvents()});
    return ok;
}

fn scenarioMultiProvider(alloc: std.mem.Allocator) bool {
    var s = etw.EtwRealtimeSource.init(alloc, "multi-prov", .{ .enabled = true });
    defer s.deinit();
    s.start() catch return false;
    s.onEventCallback(.{ .process_id = 1, .provider_guid = etw.KERNEL_PROCESS_GUID.guid, .event_id = 1 });
    s.onEventCallback(.{ .process_id = 2, .provider_guid = etw.KERNEL_NETWORK_GUID.guid, .protocol = 6 });
    s.onEventCallback(.{ .process_id = 3, .provider_guid = etw.KERNEL_FILE_GUID.guid });
    var count: usize = 0;
    while (s.nextEventImpl(0) catch null) |_| count += 1;
    const ok = count == 3;
    std.debug.print("  -> 3 providers -> {d} HostEvents converted\n", .{count});
    return ok;
}

fn scenarioIntegrationPump(alloc: std.mem.Allocator) bool {
    var host = ht.HostTelemetry.init(alloc, .{ .enabled = true }) catch return false;
    defer host.shutdown();
    var s = etw.EtwRealtimeSource.init(alloc, "integration", .{ .enabled = true });
    defer s.deinit();
    s.start() catch return false;
    // Simulate ETW delivering a process_create event
    var record = etw.EtwEventRecord{
        .process_id = 999,
        .parent_process_id = 4,
        .provider_guid = etw.KERNEL_PROCESS_GUID.guid,
        .event_id = 1,
    };
    const img = "C:\\Windows\\System32\\notepad.exe";
    @memcpy(record.image_path[0..img.len], img);
    record.image_path_len = @intCast(img.len);
    s.onEventCallback(record);
    // Pump the event through HostTelemetry
    const ev = s.nextEventImpl(0) catch return false;
    if (ev == null) return false;
    const reason = host.ingestEvent(ev.?);
    const ok = host.tracker.count() == 1 and reason == .none; // notepad is benign
    std.debug.print("  -> ETW event -> HostTelemetry; tracked={d}, reason={s}\n", .{ host.tracker.count(), reason.toString() });
    return ok;
}
