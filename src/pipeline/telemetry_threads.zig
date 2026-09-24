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
        state.markWorkerFailure(.etw);
        return;
    };
    defer source.stop();

    // Set callback to push ETW events into pipeline
    source.setCallback(undefined, etwCallback) catch |err| {
        diag.warn("ETW setCallback failed: {}", .{err});
        state.markWorkerFailure(.etw);
        return;
    };
    state.g_etw_ready.store(true, .release);
    defer state.g_etw_ready.store(false, .release);

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
    // Provider event_id is local to the ETW provider. Reserve a monotonic
    // AEGIS event identity separately for downstream trace/forensic joins.
    ev.event_id = diag.metrics.events_emitted.next();

    // Event IDs are provider-local. Always gate the mapping by provider GUID;
    // otherwise an ID=1 from a file/registry provider could be misreported as
    // PROCESS_CREATE and poison host correlation.
    const is_process = std.mem.eql(u8, &rec.provider_guid, &etw.KERNEL_PROCESS_GUID.guid);
    const is_file = std.mem.eql(u8, &rec.provider_guid, &etw.KERNEL_FILE_GUID.guid);
    const is_registry = std.mem.eql(u8, &rec.provider_guid, &etw.KERNEL_REGISTRY_GUID.guid);
    const opcode: u16 = rec.event_id;
    if (is_process and opcode == 1) {
        ev.kind = .etw_process_create;
    } else if (is_process and opcode == 2) {
        ev.kind = .etw_process_exit;
    } else if (is_file and (opcode == 0x0A or opcode == 0x0B)) {
        ev.kind = .fim_change;
    } else if (is_registry and (opcode == 0x0E or opcode == 0x0F)) {
        ev.kind = .reg_change;
    } else {
        // Unknown provider/event combinations are not safe to classify.
        return;
    }

    // Queue storage is bounded; hash and measure the exact bytes that will be
    // copied so forensic metadata cannot claim more payload than was retained.
    const payload_len = @min(ext_data.len, queue.MAX_PAYLOAD_BYTES);
    const payload = ext_data[0..payload_len];
    ev.setPayload(payload);
    _ = queue.pushEvent(ev, payload);
}

/// FIM thread: polls file integrity changes and pushes to pipeline.
pub fn fimThread(watcher: *fim_mod.FimWatcher) void {
    diag.info("FIM thread starting", .{});
    if (builtin.os.tag != .windows) {
        diag.info("FIM: non-Windows platform, skipping", .{});
        return;
    }

    // Production defaults remain the Windows system directories. For a
    // controlled observe-only proof, an operator may opt in to one temporary
    // directory through AEGIS_FIM_PROOF_ROOT. This avoids mutating System32
    // while exercising the real ReadDirectoryChangesW -> queue path.
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_FIM_PROOF_ROOT")) |proof_root| {
        defer std.heap.page_allocator.free(proof_root);
        diag.info("FIM observe-only proof root enabled: {s}", .{proof_root});
        watcher.addRule(proof_root, true) catch |err| {
            diag.warn("FIM proof root rule failed: {}", .{err});
        };
    } else |_| {
        watcher.addRule("C:\\Windows\\System32", true) catch {};
        watcher.addRule("C:\\Windows\\SysWOW64", true) catch {};
    }
    watcher.startAll() catch |err| {
        diag.warn("FIM startAll failed: {} — FIM disabled", .{err});
        state.markWorkerFailure(.fim);
        return;
    };
    defer watcher.stopAll();
    state.g_fim_ready.store(true, .release);
    defer state.g_fim_ready.store(false, .release);

    while (!state.g_stop_requested.load(.acquire)) {
        const data = watcher.poll();
        if (data.len > 0) {
            var offset: usize = 0;
            while (offset < data.len) {
                var fim_event: fim_mod.FimEvent = .{ .kind = .modified };
                const used = fim_mod.parseNotifyRecord(data[offset..], &fim_event) catch |err| {
                    diag.warn("FIM notification normalization failed: {} offset={d} bytes={d}", .{ err, offset, data.len });
                    break;
                };
                var relative_buf: [512]u8 = undefined;
                const relative_len = fim_event.path_len;
                @memcpy(relative_buf[0..relative_len], fim_event.path[0..relative_len]);
                const relative_path = relative_buf[0..relative_len];
                fim_mod.qualifyPath(watcher.activeRoot(), relative_path, &fim_event) catch |err| {
                    diag.warn("FIM path qualification failed: {}", .{err});
                    if (used == 0) break;
                    offset += used;
                    continue;
                };
                const path = fim_event.path[0..fim_event.path_len];
                var ev = event.IpcEvent.init(.fim_change);
                ev.source = .capture_fim;
                ev.timestamp_ns = @intCast(fim_event.timestamp_ns);
                ev.setPayload(path);
                _ = queue.pushEvent(ev, path);
                diag.metrics.events_emitted.inc();
                if (used == 0) break;
                offset += used;
            }
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

    // Add default registry monitoring rules and open the native notify keys.
    monitor.addRule("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 1) catch |err| {
        diag.warn("Registry Run rule failed: {}", .{err});
        state.markWorkerFailure(.registry);
        return;
    };
    monitor.addRule("HKLM\\SYSTEM\\CurrentControlSet\\Services", 2) catch |err| {
        diag.warn("Registry Services rule failed: {}", .{err});
        state.markWorkerFailure(.registry);
        return;
    };
    monitor.startAll() catch |err| {
        diag.warn("Registry native watcher start failed: {}", .{err});
        state.markWorkerFailure(.registry);
        return;
    };
    defer monitor.stopAll();
    state.g_registry_ready.store(true, .release);
    defer state.g_registry_ready.store(false, .release);

    while (!state.g_stop_requested.load(.acquire)) {
        monitor.pollNative();
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
