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

    // ETW runs on its own thread via ProcessTrace; just keep alive.
    // WD-BEAT-049: 100ms cadence, well under the 5s watchdog timeout.
    while (!state.g_stop_requested.load(.acquire) and source.running.load(.acquire)) {
        state.g_wd.beatLazy(&state.g_wd_etw_slot, .host_telemetry, "etw");
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

    // Event IDs are provider-local. Always gate the mapping by provider
    // GUID; otherwise an ID=1 from a file/registry provider could be
    // misreported as PROCESS_CREATE and poison host correlation.
    const kind = classifyEtwEvent(&rec.provider_guid, rec.event_id) orelse {
        // Unknown provider/event combinations are not safe to classify.
        return;
    };
    ev.kind = kind;

    // Queue storage is bounded; hash and measure the exact bytes that will be
    // copied so forensic metadata cannot claim more payload than was retained.
    const payload_len = @min(ext_data.len, queue.MAX_PAYLOAD_BYTES);
    const payload = ext_data[0..payload_len];
    ev.setPayload(payload);
    _ = queue.pushEvent(ev, payload);
}

/// Classify one ETW record: provider GUID + provider-local event Id -> pipeline kind.
///
/// Ground truth is host evidence (EVT-091: `wevtutil gp <provider>` task and
/// opcode names plus the raw EVENT_DESCRIPTOR dump), pinned by the test at
/// the bottom of this file:
///   Kernel-Process: Id 1 = ProcessStart, Id 2 = ProcessStop (tasks 1/2)
///   Kernel-File:    Id 0x0A = NameCreate, 0x0B = NameDelete (tasks 10/11,
///                   keyword FILENAME 0x10), Id 0x10 = Write (task 16,
///                   keyword WRITE 0x200)
///   Kernel-Registry: Id 1 = CreateKey (keyword 0x1000), Id 5 = SetValueKey
///                   (keyword 0x100)
/// Returns null when the pair is unrecognized — the caller drops such
/// records instead of guessing a kind.
fn classifyEtwEvent(provider_guid: *const [16]u8, event_id: u16) ?event.EventKind {
    if (std.mem.eql(u8, provider_guid, &etw.KERNEL_PROCESS_GUID.guid)) {
        return switch (event_id) {
            1 => .etw_process_create,
            2 => .etw_process_exit,
            else => null,
        };
    } else if (std.mem.eql(u8, provider_guid, &etw.KERNEL_FILE_GUID.guid)) {
        // file_create/file_delete arrive as name-level events; file_modify
        // as Write. Handle-level Create/Read/Cleanup and rename tasks are
        // intentionally unmapped: redundant with the name events or too
        // noisy for the bounded queue.
        return switch (event_id) {
            0x0A, 0x0B, 0x10 => .fim_change,
            else => null,
        };
    } else if (std.mem.eql(u8, provider_guid, &etw.KERNEL_REGISTRY_GUID.guid)) {
        // configs/test/etw_realtime_config.json intent: registry_create_key
        // (Id 1) and registry_set_value (Id 5). The pre-fix gate 0x0E/0x0F
        // was refuted by wevtutil gp: opcodes 45/46 = QuerySecurityKey /
        // SetSecurityKey (ACL operations) — it could never fire on the
        // value writes persistence detection needs.
        return switch (event_id) {
            1, 5 => .reg_change,
            else => null,
        };
    }
    return null;
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
        state.g_wd.beatLazy(&state.g_wd_fim_slot, .host_telemetry, "fim");
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
        state.g_wd.beatLazy(&state.g_wd_registry_slot, .host_telemetry, "registry");
        monitor.pollNative();
        const events = monitor.drain();
        for (events) |reg_ev| {
            var ev = event.IpcEvent.init(.reg_change);
            ev.source = .capture_registry;
            ev.rule_id = reg_ev.rule_id;
            ev.timestamp_ns = @intCast(reg_ev.timestamp_ns);
            _ = queue.pushEvent(ev, &[_]u8{});
            diag.metrics.events_emitted.inc();
        }
        std.time.sleep(500 * std.time.ns_per_ms); // poll every 500ms
    }
    diag.info("Registry thread stopped", .{});
}

test "ETW classifier gates pinned to host manifest ground truth (EVT-091)" {
    const proc_guid = &etw.KERNEL_PROCESS_GUID.guid;
    const file_guid = &etw.KERNEL_FILE_GUID.guid;
    const reg_guid = &etw.KERNEL_REGISTRY_GUID.guid;
    const unknown: [16]u8 = [_]u8{0} ** 16;

    // Kernel-Process tasks 1/2 (wevtutil gp): ProcessStart/ProcessStop.
    try std.testing.expectEqual(event.EventKind.etw_process_create, classifyEtwEvent(proc_guid, 1).?);
    try std.testing.expectEqual(event.EventKind.etw_process_exit, classifyEtwEvent(proc_guid, 2).?);
    // ThreadStart (task 3) has no pipeline kind — must not be guessed.
    try std.testing.expect(classifyEtwEvent(proc_guid, 3) == null);

    // Kernel-File tasks 10/11/16: NameCreate / NameDelete / Write.
    try std.testing.expectEqual(event.EventKind.fim_change, classifyEtwEvent(file_guid, 0x0A).?);
    try std.testing.expectEqual(event.EventKind.fim_change, classifyEtwEvent(file_guid, 0x0B).?);
    try std.testing.expectEqual(event.EventKind.fim_change, classifyEtwEvent(file_guid, 0x10).?);
    // Handle-level Create (task 12) stays unmapped (see classifyEtwEvent).
    try std.testing.expect(classifyEtwEvent(file_guid, 0x0C) == null);

    // Kernel-Registry: CreateKey (Id 1), SetValueKey (Id 5).
    try std.testing.expectEqual(event.EventKind.reg_change, classifyEtwEvent(reg_guid, 1).?);
    try std.testing.expectEqual(event.EventKind.reg_change, classifyEtwEvent(reg_guid, 5).?);
    // Refuted pre-fix gate: 0x0E/0x0F = Query/SetSecurityKey (ACL ops,
    // wevtutil opcodes 45/46) — must not classify as registry change.
    try std.testing.expect(classifyEtwEvent(reg_guid, 0x0E) == null);
    try std.testing.expect(classifyEtwEvent(reg_guid, 0x0F) == null);

    // Provider gating: a matching Id from the wrong provider never classifies.
    try std.testing.expect(classifyEtwEvent(file_guid, 1) == null);
    try std.testing.expect(classifyEtwEvent(reg_guid, 2) == null);
    // Unknown provider is dropped, not guessed.
    try std.testing.expect(classifyEtwEvent(&unknown, 1) == null);
}
