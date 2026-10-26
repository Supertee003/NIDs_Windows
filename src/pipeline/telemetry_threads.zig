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

/// GAP-015 G3: ETW composition accounting. The 4096→16k queue plus tail
/// fixes did not survive storm load (687k ETW drops in one storm), so the
/// next slice needs measured composition, not guesses. One counter per
/// kept class plus unmapped drops; no allocator, no mutex, monotonic.
/// Read by queue.stats; never read by any push/drop decision.
pub const EtwClasses = struct {
    process_start: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    file_name_create: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    file_name_delete: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    file_write: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    reg_create: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    reg_set: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped_unmapped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};
pub var g_etw_classes = EtwClasses{};
/// Deliberate storm shed (see shouldShedWrite): counted apart from
/// queue-full drops so operators can tell policy from overflow.
pub var g_shed_overload: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// GAP-015 G4.1: first-write exemption. Storm shed must never blind a
/// file the pipeline has never seen (new DLL drop amid a write storm is
/// exactly the attacker-relevant case): the first sighting of a payload
/// passes even at depth, repeats shed. Bounded 4096-hash FIFO ring plus
/// a 200-token / 100-per-second bucket so distinct-path floods cannot
/// launder themselves through the exemption either. State is plain
/// statics: the native layer invokes this callback serialized under its
/// critical section, so no two exemptions interleave.
pub const SHED_SEEN_SIZE: usize = 4096;
pub const SHED_BUCKET_CAP: f64 = 200.0;
pub const SHED_REFILL_PER_S: f64 = 100.0;
var g_shed_seen: [SHED_SEEN_SIZE]u64 = [_]u64{0} ** SHED_SEEN_SIZE;
var g_shed_seen_idx: usize = 0;
var g_shed_tokens: f64 = SHED_BUCKET_CAP;
var g_shed_last_ms: i64 = 0;
pub var g_shed_exempted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub fn fnv1a64(bytes: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (bytes) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}

/// Refill overdue tokens (pure math on explicit state, tested).
pub fn shedRefill(tokens: f64, cap: f64, rate_per_s: f64, elapsed_ms: i64) f64 {
    if (elapsed_ms <= 0) return tokens;
    const add = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0 * rate_per_s;
    return @min(cap, tokens + add);
}

/// Full exemption decision: first sighting spends one token and passes;
/// repeats, or an empty bucket, shed. Returns true when the caller must
/// push despite the storm.
pub fn tryExempt(payload: []const u8, now_ms: i64) bool {
    g_shed_tokens = shedRefill(g_shed_tokens, SHED_BUCKET_CAP, SHED_REFILL_PER_S, now_ms - g_shed_last_ms);
    g_shed_last_ms = now_ms;
    if (g_shed_tokens < 1.0) return false;
    const h = fnv1a64(payload);
    for (g_shed_seen) |seen| {
        if (seen == h) return false;
    }
    g_shed_seen[g_shed_seen_idx % SHED_SEEN_SIZE] = h;
    g_shed_seen_idx +%= 1;
    g_shed_tokens -= 1.0;
    _ = g_shed_exempted.fetchAdd(1, .monotonic);
    return true;
}

/// GAP-015 G3/G4: shed storm classes only once the queue is 3/4 full.
/// G3 covered File-Write (per-write IRP firehose); G4 adds NameDelete
/// (400/s of deletions the FIM watcher duplicates anyway, near-worthless
/// for R1001/R1004). NameCreate still catches every new file (R1004's
/// new-DLL signal) and overwrites resume after the storm. Pure: depth in,
/// decision out.
pub fn shouldShedWrite(depth: u64) bool {
    return depth >= queue.PIPELINE_QUEUE_SIZE * 3 / 4;
}

/// True for Kernel-File Write (Id 0x10) and NameDelete (Id 0x0B) only.
/// The classifier owns the opcode mapping; this predicate mirrors its
/// arms and the parity test below fails if the two ever disagree.
fn isStormSheddable(provider_guid: *const [16]u8, event_id: u16) bool {
    if (!std.mem.eql(u8, provider_guid, &etw.KERNEL_FILE_GUID.guid)) return false;
    return event_id == 0x10 or event_id == 0x0B;
}

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
    source.setCallback(etwCallback) catch |err| {
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

    // GAP-015 G3/G4.1: storm shed — File-Write and NameDelete into a
    // nearly-full queue are discarded here (counted as shed policy, not
    // overflow) instead of evicting NameCreate/Process/Registry events
    // downstream. First sightings are exempt (tryExempt) so a new file's
    // content is always evaluated once even mid-storm; FIM duplicates
    // deletes regardless.
    if (isStormSheddable(&rec.provider_guid, rec.event_id) and shouldShedWrite(queue.queueDepth())) {
        if (!tryExempt(payload, std.time.milliTimestamp())) {
            _ = g_shed_overload.fetchAdd(1, .monotonic);
            return;
        }
    }

    ev.setPayload(payload);
    _ = queue.pushEvent(ev, payload);
}

/// Classify one ETW record: provider GUID + provider-local event Id -> pipeline kind.
///
/// Ground truth is host evidence (EVT-091: `wevtutil gp <provider>` task and
/// opcode names plus the raw EVENT_DESCRIPTOR dump), pinned by the test at
/// the bottom of this file:
///   Kernel-Process: Id 1 = ProcessStart (task 1). Id 2 = ProcessStop is
///                   deliberately UNMAPPED (G3: exit carries no path TLV,
///                   zero consumers, storm cost) — see the parity test.
///   Kernel-File:    Id 0x0A = NameCreate, 0x0B = NameDelete (tasks 10/11,
///                   keyword FILENAME 0x10), Id 0x10 = Write (task 16,
///                   keyword WRITE 0x200)
///   Kernel-Registry: Id 1 = CreateKey (keyword 0x1000), Id 5 = SetValueKey
///                   (keyword 0x100)
/// Returns null when the pair is unrecognized — the caller drops such
/// records instead of guessing a kind. Every outcome is counted into
/// g_etw_classes for queue.stats composition (GAP-015 G3).
fn classifyEtwEvent(provider_guid: *const [16]u8, event_id: u16) ?event.EventKind {
    if (std.mem.eql(u8, provider_guid, &etw.KERNEL_PROCESS_GUID.guid)) {
        return switch (event_id) {
            1 => blk: {
                _ = g_etw_classes.process_start.fetchAdd(1, .monotonic);
                break :blk .etw_process_create;
            },
            else => blk: {
                _ = g_etw_classes.dropped_unmapped.fetchAdd(1, .monotonic);
                break :blk null;
            },
        };
    } else if (std.mem.eql(u8, provider_guid, &etw.KERNEL_FILE_GUID.guid)) {
        // file_create/file_delete arrive as name-level events; file_modify
        // as Write. Handle-level Create/Read/Cleanup and rename tasks are
        // intentionally unmapped: redundant with the name events or too
        // noisy for the bounded queue.
        return switch (event_id) {
            0x0A => blk: {
                _ = g_etw_classes.file_name_create.fetchAdd(1, .monotonic);
                break :blk .fim_change;
            },
            0x0B => blk: {
                _ = g_etw_classes.file_name_delete.fetchAdd(1, .monotonic);
                break :blk .fim_change;
            },
            0x10 => blk: {
                _ = g_etw_classes.file_write.fetchAdd(1, .monotonic);
                break :blk .fim_change;
            },
            else => blk: {
                _ = g_etw_classes.dropped_unmapped.fetchAdd(1, .monotonic);
                break :blk null;
            },
        };
    } else if (std.mem.eql(u8, provider_guid, &etw.KERNEL_REGISTRY_GUID.guid)) {
        // configs/test/etw_realtime_config.json intent: registry_create_key
        // (Id 1) and registry_set_value (Id 5). The pre-fix gate 0x0E/0x0F
        // was refuted by wevtutil gp: opcodes 45/46 = QuerySecurityKey /
        // SetSecurityKey (ACL operations) — it could never fire on the
        // value writes persistence detection needs.
        return switch (event_id) {
            1 => blk: {
                _ = g_etw_classes.reg_create.fetchAdd(1, .monotonic);
                break :blk .reg_change;
            },
            5 => blk: {
                _ = g_etw_classes.reg_set.fetchAdd(1, .monotonic);
                break :blk .reg_change;
            },
            else => blk: {
                _ = g_etw_classes.dropped_unmapped.fetchAdd(1, .monotonic);
                break :blk null;
            },
        };
    }
    _ = g_etw_classes.dropped_unmapped.fetchAdd(1, .monotonic);
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

    // Kernel-Process task 1 (wevtutil gp): ProcessStart.
    try std.testing.expectEqual(event.EventKind.etw_process_create, classifyEtwEvent(proc_guid, 1).?);
    // G3: ProcessStop (task 2) is deliberately unmapped — exit carries no
    // path TLV (R1001/R1004 cannot fire), zero consumers read the kind,
    // and every exit cost queue slots in storms.
    try std.testing.expect(classifyEtwEvent(proc_guid, 2) == null);
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

test "GAP-015 G3/G4 shed predicate mirrors the classifier storm arms" {
    // Parity: exactly the (provider, Id) pairs the classifier maps to
    // Write/Delete pushes are sheddable — nothing more, nothing less.
    try std.testing.expect(isStormSheddable(&etw.KERNEL_FILE_GUID.guid, 0x10));
    try std.testing.expect(isStormSheddable(&etw.KERNEL_FILE_GUID.guid, 0x0B));
    try std.testing.expect(!isStormSheddable(&etw.KERNEL_FILE_GUID.guid, 0x0A));
    try std.testing.expect(!isStormSheddable(&etw.KERNEL_PROCESS_GUID.guid, 1));
    try std.testing.expect(!isStormSheddable(&etw.KERNEL_REGISTRY_GUID.guid, 5));
    const unknown: [16]u8 = [_]u8{0} ** 16;
    try std.testing.expect(!isStormSheddable(&unknown, 0x10));
    // Threshold: below 3/4 the queue absorbs bursts untouched; at and
    // above it Write sheds. Symbolic so queue resizes move the line.
    try std.testing.expect(!shouldShedWrite(0));
    try std.testing.expect(!shouldShedWrite(queue.PIPELINE_QUEUE_SIZE * 3 / 4 - 1));
    try std.testing.expect(shouldShedWrite(queue.PIPELINE_QUEUE_SIZE * 3 / 4));
    try std.testing.expect(shouldShedWrite(queue.PIPELINE_QUEUE_SIZE * 3));
}

test "GAP-015 G3 classifier counts every outcome" {
    // Delta-based: the EVT-091 test above also classifies, sharing globals.
    const before = g_etw_classes.file_write.load(.acquire);
    const file_guid = &etw.KERNEL_FILE_GUID.guid;
    _ = classifyEtwEvent(file_guid, 0x10);
    _ = classifyEtwEvent(file_guid, 0x10);
    try std.testing.expectEqual(before + 2, g_etw_classes.file_write.load(.acquire));
    const drops = g_etw_classes.dropped_unmapped.load(.acquire);
    _ = classifyEtwEvent(file_guid, 0x0C);
    try std.testing.expectEqual(drops + 1, g_etw_classes.dropped_unmapped.load(.acquire));
}

test "GAP-015 G4.1 exemption passes first sighting, sheds repeats, respects bucket" {
    // Test-owned globals, single-threaded runner: reset first.
    g_shed_tokens = SHED_BUCKET_CAP;
    g_shed_last_ms = 0;
    g_shed_seen_idx = 0;
    for (&g_shed_seen) |*s| s.* = 0;
    const exempt0 = g_shed_exempted.load(.acquire);
    const t0: i64 = 1000000;
    try std.testing.expect(tryExempt("payload-A", t0));
    try std.testing.expect(!tryExempt("payload-A", t0 + 10));
    try std.testing.expect(tryExempt("payload-B", t0 + 20));
    try std.testing.expectEqual(exempt0 + 2, g_shed_exempted.load(.acquire));
    // Empty bucket refuses even novelty.
    g_shed_tokens = 0.0;
    g_shed_last_ms = t0 + 20;
    try std.testing.expect(!tryExempt("payload-C", t0 + 20));
    // Refill over wall time reopens (20s at 100/s refills past cap).
    try std.testing.expect(tryExempt("payload-C", t0 + 20 + 20000));
    try std.testing.expectEqual(exempt0 + 3, g_shed_exempted.load(.acquire));
    // Refill math: capped, zero-elapsed passthrough, avalanche bit.
    try std.testing.expectEqual(200.0, shedRefill(150.0, 200.0, 100.0, 1000));
    try std.testing.expectEqual(50.0, shedRefill(50.0, 200.0, 100.0, 0));
    try std.testing.expect(fnv1a64("abc") != fnv1a64("abd"));
}
