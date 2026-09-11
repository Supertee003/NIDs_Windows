//! Windows Data Plane adapter threads (PATCH-20, Phase 3).
//!
//! Extracted from main.zig. Each adapter runs on its own thread and pushes
//! real Windows telemetry (ETW kernel events, file-integrity changes,
//! registry changes) into the pipeline queue.

const std = @import("std");
const builtin = @import("builtin");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const etw = @import("../windows/etw_realtime.zig");
const fim_mod = @import("../windows/fim.zig");
const reg_mon = @import("../windows/registry_monitor.zig");
const state = @import("runtime_state.zig");
const queue = @import("event_queue.zig");

/// ETW thread: receives Windows kernel events via ETW session.
/// Converts EtwEventRecord to IpcEvent and pushes to pipeline.
pub fn etwThread(source: *etw.EtwSource) void {
    diag.info("ETW thread starting", .{});
    if (builtin.os.tag != .windows) {
        diag.info("ETW: non-Windows platform, skipping", .{});
        return;
    }
    // Start ETW with kernel process provider
    const providers = [_][16]u8{
        etw.PROVIDER_KERNEL_PROCESS,
        etw.PROVIDER_KERNEL_FILE,
        etw.PROVIDER_KERNEL_REGISTRY,
    };
    source.start(&providers) catch |err| {
        diag.warn("ETW start failed: {} — ETW disabled", .{err});
        return;
    };
    defer source.stop();

    // Set callback to push ETW events into pipeline
    source.setCallback(undefined, etwCallback) catch |err| {
        diag.warn("ETW setCallback failed: {}", .{err});
        return;
    };

    // ETW runs on its own thread via ProcessTrace; just keep alive
    while (!state.g_stop_requested.load(.acquire) and source.running.load(.acquire)) {
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    diag.info("ETW thread stopped", .{});
}

/// ETW callback: converts ETW event record to IpcEvent and pushes to pipeline.
fn etwCallback(ctx: *anyopaque, rec: *const etw.EtwEventRecord, ext_data: []const u8) void {
    _ = ctx;
    var ev = event.IpcEvent.init(.etw_process_create);
    ev.source = .capture_etw;
    ev.timestamp_ns = @intCast(rec.timestamp_ns);
    ev.event_id = diag.metrics.events_emitted.get();

    // Determine event kind from ETW opcode
    // (new EtwEventRecord carries event_id instead of ETW opcode; map by id)
    const opcode: u16 = rec.event_id;
    if (opcode == 1) { // Process Start
        ev.kind = .etw_process_create;
    } else if (opcode == 2) { // Process Stop
        ev.kind = .etw_process_exit;
    } else if (opcode == 0x0A or opcode == 0x0B) { // File Create/Delete
        ev.kind = .fim_change;
    } else if (opcode == 0x0E or opcode == 0x0F) { // Registry Create/Delete
        ev.kind = .reg_change;
    }

    // Push event + extended data as payload
    if (ext_data.len > 0) {
        _ = queue.pushEvent(ev, ext_data);
    } else {
        _ = queue.pushEvent(ev, &[_]u8{});
    }
    diag.metrics.events_emitted.inc();
}

/// FIM thread: polls file integrity changes and pushes to pipeline.
pub fn fimThread(watcher: *fim_mod.FimWatcher) void {
    diag.info("FIM thread starting", .{});
    if (builtin.os.tag != .windows) {
        diag.info("FIM: non-Windows platform, skipping", .{});
        return;
    }

    // Add default FIM rules (monitor Windows system directories)
    watcher.addRule("C:\\Windows\\System32", true) catch {};
    watcher.addRule("C:\\Windows\\SysWOW64", true) catch {};
    watcher.startAll() catch |err| {
        diag.warn("FIM startAll failed: {} — FIM disabled", .{err});
        return;
    };
    defer watcher.stopAll();

    while (!state.g_stop_requested.load(.acquire)) {
        const data = watcher.poll();
        if (data.len > 0) {
            var ev = event.IpcEvent.init(.fim_change);
            ev.source = .capture_fim;
            ev.timestamp_ns = @intCast(std.time.nanoTimestamp());
            _ = queue.pushEvent(ev, data);
            diag.metrics.events_emitted.inc();
        }
        std.time.sleep(500 * std.time.ns_per_ms); // poll every 500ms
    }
    diag.info("FIM thread stopped", .{});
}

/// Registry thread: polls registry changes and pushes to pipeline.
pub fn registryThread(monitor: *reg_mon.RegistryMonitor) void {
    diag.info("Registry thread starting", .{});
    if (builtin.os.tag != .windows) {
        diag.info("Registry: non-Windows platform, skipping", .{});
        return;
    }

    // Add default registry monitoring rules
    monitor.addRule("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 1) catch {};
    monitor.addRule("HKLM\\SYSTEM\\CurrentControlSet\\Services", 2) catch {};

    while (!state.g_stop_requested.load(.acquire)) {
        const events = monitor.drain();
        for (events) |reg_ev| {
            var ev = event.IpcEvent.init(.dns_query); // reuse kind for registry
            ev.source = .capture_registry;
            ev.timestamp_ns = @intCast(reg_ev.timestamp_ns);
            _ = queue.pushEvent(ev, &[_]u8{});
            diag.metrics.events_emitted.inc();
        }
        std.time.sleep(500 * std.time.ns_per_ms); // poll every 500ms
    }
    diag.info("Registry thread stopped", .{});
}
