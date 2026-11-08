//! minifilter_reader.zig - AEGIS NIDS Minifilter Reader (Thread 4)
//!
//! Kernel host telemetry consumer for the AegisMinifilter driver
//! (drivers/minifilter/). PULL model, deliberately:
//!
//!   - The driver records file-create (PostCreate) and process create/exit
//!     events into a 64 KiB kernel ring (aegis_minifilter_comm.c) inside the
//!     file-system callbacks. It never calls FltSendMessage from a callback,
//!     so a slow or absent reader can never stall file I/O.
//!   - This thread connects to \AegisMinifilterPort (filter communication
//!     port) and drains the ring with bounded FilterSendMessage(READ_EVENTS)
//!     pulls (64 KiB per pull = up to 138 fixed 472-byte records), then
//!     submits each record as a canonical host event (source=.minifilter)
//!     into the pipeline queue.
//!   - Kernel ring overflow is NOT silent: the ring's DroppedEvents counter
//!     is polled (GET_STATS) into runtime_state.g_minifilter_dropped and
//!     rendered by control/queue.stats.
//!
//! Wire record: _AEGIS_EVENT_RECORD in drivers/minifilter/aegis_minifilter.h.
//! Layout parity (472 bytes, Path at offset 30, NameLen = WCHAR count) is
//! pinned by comptime checks + tests; any kernel-side change must update
//! this file in the same patch ("one schema, N codecs").
//!
//! Observe-only by construction: this module submits detection input and
//! never calls any enforcement path.

const std = @import("std");
const bridge_init = @import("../core/bridge_init.zig");
const diag = @import("../core/diagnostics.zig");
const runtime_state = @import("../pipeline/runtime_state.zig");
const pipeline_queue = @import("../pipeline/event_queue.zig");
const fim_dedup = @import("../pipeline/fim_dedup.zig");
const canonical = @import("../contract/canonical_event.zig");
const hids = @import("../windows/hids_engine.zig");

// ====== Kernel wire record (matches _AEGIS_EVENT_RECORD) ======
/// Fixed-size event record written by the driver's ring buffer.
/// x64 natural alignment: EventType@0, Size@4, ProcessId@8, ParentPid@12,
/// Timestamp@16 (LARGE_INTEGER, 100ns since 1601), Status@24, NameLen@28
/// (WCHAR count, no NUL), Path@30 (220 WCHARs), total 472 bytes.
pub const AegisEventRecord = extern struct {
    event_type: u32,
    size: u32,
    process_id: u32,
    parent_pid: u32,
    timestamp: i64,
    status: i32,
    name_len: u16,
    path: [220]u16,
};

pub const RECORD_SIZE: usize = @sizeOf(AegisEventRecord);

comptime {
    if (@sizeOf(AegisEventRecord) != 472) {
        @compileError("AegisEventRecord must be 472 bytes (kernel _AEGIS_EVENT_RECORD parity)");
    }
    if (@offsetOf(AegisEventRecord, "timestamp") != 16 or
        @offsetOf(AegisEventRecord, "name_len") != 28 or
        @offsetOf(AegisEventRecord, "path") != 30)
    {
        @compileError("AegisEventRecord field offsets drift from the kernel record");
    }
}

// ====== Kernel event type constants (aegis_minifilter.h) ======
pub const AEGIS_EVT_FILE: u32 = 1;
pub const AEGIS_EVT_PROC_CREATE: u32 = 2;
pub const AEGIS_EVT_PROC_EXIT: u32 = 3;

/// Map a kernel event_type ordinal to a human-readable string.
pub fn eventTypeToString(event_type: u32) []const u8 {
    return switch (event_type) {
        AEGIS_EVT_FILE => "FILE",
        AEGIS_EVT_PROC_CREATE => "PROC_CREATE",
        AEGIS_EVT_PROC_EXIT => "PROC_EXIT",
        else => "UNKNOWN",
    };
}

/// Map a kernel event_type ordinal to the HIDS ProcessEventType ordinal
/// stored at canonical reserved[RES_OFF_PROC_TYPE]. File-create events and
/// any unknown ordinal classify as file_create (fail toward the file
/// domain, never toward process escalation).
pub fn processTypeFor(event_type: u32) u8 {
    return switch (event_type) {
        AEGIS_EVT_PROC_CREATE => @intFromEnum(hids.ProcessEventType.create),
        AEGIS_EVT_PROC_EXIT => @intFromEnum(hids.ProcessEventType.terminate),
        else => @intFromEnum(hids.ProcessEventType.file_create),
    };
}

// ====== Windows FILETIME -> unix ms ======
const FILETIME_EPOCH_MS: i64 = 11_644_473_600_000; // ms between 1601 and 1970
const TICKS_PER_MS: i64 = 10_000; // 100ns ticks per millisecond

/// Convert a kernel KeQuerySystemTime value (100ns since 1601) to unix
/// epoch milliseconds. Garbage/zero clamps to 0 (caller keeps its own
/// timestamp then).
pub fn filetimeToUnixMs(filetime: i64) u64 {
    if (filetime <= 0) return 0;
    const ms_since_1601 = @divTrunc(filetime, TICKS_PER_MS);
    if (ms_since_1601 <= FILETIME_EPOCH_MS) return 0;
    return @intCast(ms_since_1601 - FILETIME_EPOCH_MS);
}

// ====== Path conversion (UTF-16LE -> UTF-8, lossy-safe) ======
pub const PATH_UTF8_MAX: usize = 220 * 3; // worst-case UTF-8 for 220 UTF-16 units

/// Decode the record's inline UTF-16LE path into `buf`. Unpaired
/// surrogates become U+FFFD; output is truncated (never overflowed) if
/// `buf` is too small.
pub fn pathToUtf8(rec: *align(1) const AegisEventRecord, buf: []u8) []const u8 {
    const n: usize = @min(@as(usize, rec.name_len), rec.path.len);
    var out_len: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const unit = rec.path[i];
        var cp: u21 = unit;
        if (unit >= 0xD800 and unit <= 0xDBFF) {
            if (i + 1 < n and rec.path[i + 1] >= 0xDC00 and rec.path[i + 1] <= 0xDFFF) {
                cp = 0x10000 + ((@as(u21, unit) - 0xD800) << 10) + (@as(u21, rec.path[i + 1]) - 0xDC00);
                i += 1;
            } else {
                cp = 0xFFFD;
            }
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            cp = 0xFFFD;
        }
        var tmp: [4]u8 = undefined;
        const l: usize = std.unicode.utf8Encode(cp, &tmp) catch continue;
        if (out_len + l > buf.len) break;
        @memcpy(buf[out_len..][0..l], tmp[0..l]);
        out_len += l;
    }
    return buf[0..out_len];
}

/// Byte-offset view of one fixed record inside a pull buffer.
pub fn recordAt(buf: []const u8, off: usize) *align(1) const AegisEventRecord {
    std.debug.assert(off + RECORD_SIZE <= buf.len);
    return @ptrCast(&buf[off]);
}

// ====== fltlib.dll bindings ======
const win = std.os.windows;
const HANDLE = win.HANDLE;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const HRESULT = i32;

extern "fltlib" fn FilterConnectCommunicationPort(
    lpPortName: [*:0]const u16,
    dwOptions: u32,
    lpContext: ?*const anyopaque,
    dwSizeOfContext: u32,
    lpOverlapped: ?*anyopaque,
    hPort: *HANDLE,
) HRESULT;

extern "fltlib" fn FilterSendMessage(
    hPort: HANDLE,
    lpInBuffer: ?*anyopaque,
    dwInBufferSize: u32,
    lpOutBuffer: ?*anyopaque,
    dwOutBufferSize: u32,
    lpBytesReturned: *u32,
) HRESULT;

/// Port name as UTF-16LE. SINGLE leading backslash: the kernel defines it
/// as L"\\AegisMinifilterPort" in C source (the WDK minispy sample uses
/// the identical L"\\MiniSpyPort" form); both sides must present the same
/// runtime string "\AegisMinifilterPort". The previous reader declared two
/// backslashes and could never have connected to a correctly-registered
/// kernel port.
const MINIFILTER_PORT = [_:0]u16{ '\\', 'A', 'e', 'g', 'i', 's', 'M', 'i', 'n', 'i', 'f', 'i', 'l', 't', 'e', 'r', 'P', 'o', 'r', 't' };

comptime {
    if (MINIFILTER_PORT[0] != 0x5C) {
        @compileError("MINIFILTER_PORT[0] must be 0x5C (backslash)");
    }
}

// ====== Message commands (aegis_minifilter.h) ======
const AEGIS_MSG_READ_EVENTS: u32 = 1;
const AEGIS_MSG_GET_STATS: u32 = 2;

// ====== Loop pacing ======
// EVT-230 hardening: 256 KiB pull buffer (554 records per pull; the kernel
// ring is 1 MiB so a saturated ring drains in 4 pulls) and a 50 ms idle
// wake (was 250 ms - the old cadence left burst capacity on the table and
// widened the ring's overflow window). Grounded in measured queue.stats
// data from the EVT-230 incident, not guessed.
const READ_BUF_SIZE: usize = 256 * 1024; // 554 records per pull
const IDLE_SLEEP_MS: u64 = 50;
const CONNECT_RETRY_MS: u64 = 10_000;
const ERROR_SLEEP_MS: u64 = 1_000;
const STATS_POLL_EVERY: u64 = 64;

// ====== Statistics ======
var g_events_received: u64 = 0;
var g_events_processed: u64 = 0;

fn stopRequested() bool {
    return bridge_init.g_shutdown.load(.seq_cst) or runtime_state.g_stop_requested.load(.acquire);
}

/// Sleep that wakes early (50ms granularity) when shutdown is requested.
fn interruptibleSleep(ms: u64) void {
    var slept: u64 = 0;
    while (slept < ms and !stopRequested()) : (slept += 50) {
        std.time.sleep(50 * std.time.ns_per_ms);
    }
}

fn markUnavailable() void {
    runtime_state.g_minifilter_state.store(
        @intFromEnum(runtime_state.MinifilterState.unavailable),
        .release,
    );
}

/// Convert one kernel record into a canonical host event and submit it to
/// the pipeline queue. Returns false when the queue is full (row dropped
/// at ingress; counted).
fn submitRecord(rec: *align(1) const AegisEventRecord, path_utf8: []const u8) bool {
    var ce = canonical.create(.minifilter);
    canonical.setProcessIdentity(&ce, rec.process_id, rec.parent_pid);
    ce.reserved[canonical.RES_OFF_PROC_TYPE] = processTypeFor(rec.event_type);
    const kernel_ms = filetimeToUnixMs(rec.timestamp);
    if (kernel_ms > 0) ce.timestamp_ms = kernel_ms;
    ce.direction = 0;
    ce.layer_id = 2; // kernel provenance (canonical_event.zig: 0=TCP, 1=WFP, 2=kernel, 3=pipe)
    ce.is_pipe = 0;
    ce.payload_length = @intCast(path_utf8.len);
    var frame = canonical.DecodedFrame{ .event = ce, .src_ipv6 = null, .dst_ipv6 = null };
    return pipeline_queue.pushDecodedFrame(&frame, path_utf8);
}

/// Poll the kernel ring health (GET_STATS) and surface DroppedEvents so
/// kernel-side loss is operator-visible, never silent.
fn pollKernelStats(hPort: HANDLE) void {
    var cmd: u32 = AEGIS_MSG_GET_STATS;
    var stats: [4]u32 = undefined;
    var out_len: u32 = 0;
    const hr = FilterSendMessage(hPort, &cmd, @sizeOf(u32), &stats, @as(u32, @sizeOf(@TypeOf(stats))), &out_len);
    if (hr < 0 or out_len < @sizeOf(@TypeOf(stats))) return;
    runtime_state.g_minifilter_dropped.store(stats[1], .monotonic);
}

// ====== Main minifilter reader loop (Thread 4) ======
pub fn minifilterReaderLoop() void {
    diag.info("[MINI] Thread 4 started - minifilter host telemetry (pull model)", .{});

    // ADR-0012 measurement: one probe per pull batch. READ_BUF_SIZE is
    // 256 KiB = at most 554 fixed records per pull, so 1,024 keys represent
    // any real batch; overflow is counted, never silently evicted.
    var probe_store: [1024]fim_dedup.Entry = undefined;
    var probe = fim_dedup.Probe.init(&probe_store);
    var probe_pid_store: [1024]fim_dedup.Entry = undefined;
    var probe_pid = fim_dedup.Probe.init(&probe_pid_store);
    var probe_ts_store: [1024]fim_dedup.Entry = undefined;
    var probe_ts = fim_dedup.Probe.init(&probe_ts_store);

    while (!stopRequested()) {
        // ---- connect (retry while the driver is absent/not loaded) ----
        var hPort: HANDLE = INVALID_HANDLE_VALUE;
        var retry_count: u32 = 0;
        while (!stopRequested()) {
            const hr = FilterConnectCommunicationPort(&MINIFILTER_PORT, 0, null, 0, null, &hPort);
            if (hr >= 0) break;
            retry_count += 1;
            if (retry_count == 1 or retry_count % 6 == 0) {
                diag.warn("[MINI] \\AegisMinifilterPort not available (hr=0x{x}) - retrying (labeled in queue.stats, never silent)", .{@as(u32, @bitCast(hr))});
            }
            markUnavailable();
            interruptibleSleep(CONNECT_RETRY_MS);
        }
        if (stopRequested()) break;

        runtime_state.g_minifilter_state.store(
            @intFromEnum(runtime_state.MinifilterState.ok),
            .release,
        );
        diag.info("[MINI] connected to \\AegisMinifilterPort - draining kernel file/process events", .{});

        var ring: [READ_BUF_SIZE]u8 align(8) = undefined;
        var pulls: u64 = 0;
        while (!stopRequested()) {
            var cmd: u32 = AEGIS_MSG_READ_EVENTS;
            var out_len: u32 = 0;
            const hr = FilterSendMessage(hPort, &cmd, @sizeOf(u32), &ring, @intCast(ring.len), &out_len);
            if (hr < 0) {
                diag.warn("[MINI] FilterSendMessage failed (hr=0x{x}) - reconnecting", .{@as(u32, @bitCast(hr))});
                markUnavailable();
                break;
            }
            pulls += 1;
            _ = runtime_state.g_minifilter_reads.fetchAdd(1, .monotonic);
            runtime_state.g_minifilter_last_bytes.store(out_len, .monotonic);

            if (out_len == 0) {
                interruptibleSleep(IDLE_SLEEP_MS);
            } else {
                var off: usize = 0;
                probe.beginBatch();
                probe_pid.beginBatch();
                probe_ts.beginBatch();
                var overflow_counted = false;
                while (off + RECORD_SIZE <= @as(usize, out_len)) : (off += RECORD_SIZE) {
                    const rec = recordAt(ring[0..out_len], off);
                    g_events_received += 1;
                    if (rec.size != @as(u32, @sizeOf(AegisEventRecord))) {
                        diag.warn("[MINI] malformed ring record (size={d}) - skipped", .{rec.size});
                        continue;
                    }
                    var path_buf: [PATH_UTF8_MAX]u8 = undefined;
                    const path = pathToUtf8(rec, &path_buf);
                    // ADR-0012 probe (measurement only; nothing is suppressed).
                    // Two identities: raw (path, kind) and attributed
                    // (path, kind, pid). The driver emits one event per
                    // IRP_MJ_CREATE completion, i.e. per file *open*, so a
                    // same-path repeat is not necessarily redundant.
                    _ = runtime_state.g_fim_batch_records.fetchAdd(1, .monotonic);
                    _ = runtime_state.g_fim_minifilter_batch_records.fetchAdd(1, .monotonic);
                    if (probe.observe(path, rec.event_type, 0, 0)) {
                        _ = runtime_state.g_fim_batch_duplicates.fetchAdd(1, .monotonic);
                        _ = runtime_state.g_fim_minifilter_batch_duplicates.fetchAdd(1, .monotonic);
                    }
                    if (probe_pid.observe(path, rec.event_type, rec.process_id, 0)) {
                        _ = runtime_state.g_fim_batch_duplicates_per_pid.fetchAdd(1, .monotonic);
                        _ = runtime_state.g_fim_minifilter_batch_duplicates_per_pid.fetchAdd(1, .monotonic);
                    }
                    // Same path, same process, same kernel timestamp: the
                    // identical callback delivered twice, not two opens.
                    if (probe_ts.observe(path, rec.event_type, rec.process_id, rec.timestamp)) {
                        _ = runtime_state.g_fim_minifilter_batch_duplicates_same_ts.fetchAdd(1, .monotonic);
                    }
                    if ((probe.overflowed or probe_pid.overflowed or probe_ts.overflowed) and !overflow_counted) {
                        overflow_counted = true;
                        _ = runtime_state.g_fim_batch_overflow.fetchAdd(1, .monotonic);
                    }
                    if (submitRecord(rec, path)) {
                        g_events_processed += 1;
                        _ = runtime_state.g_minifilter_rows.fetchAdd(1, .monotonic);
                        if (g_events_processed == 1 or g_events_processed % 4096 == 0) {
                            diag.info("[MINI] {d} kernel events drained (last: {s} pid={d} {s})", .{
                                g_events_processed, eventTypeToString(rec.event_type), rec.process_id, path,
                            });
                        } else {
                            diag.debug("[MINI] {s} pid={d} {s}", .{ eventTypeToString(rec.event_type), rec.process_id, path });
                        }
                    } else {
                        const dropped = runtime_state.g_minifilter_pipeline_dropped.fetchAdd(1, .monotonic) + 1;
                        if (dropped == 1 or dropped % 1024 == 0) {
                            diag.warn("[MINI] pipeline queue full - {d} kernel rows dropped at ingress", .{dropped});
                        }
                    }
                }
            }

            if (pulls % STATS_POLL_EVERY == 0) pollKernelStats(hPort);
        }

        if (hPort != INVALID_HANDLE_VALUE) {
            // FilterCloseCommunicationPort is not exported by fltlib.dll on
            // this platform; the port handle is a regular kernel handle.
            _ = win.CloseHandle(hPort);
            hPort = INVALID_HANDLE_VALUE;
        }
        interruptibleSleep(ERROR_SLEEP_MS);
    }

    diag.info("[MINI] reader stopped (shutdown requested)", .{});
}

// ====== Tests (hermetic; no driver, no host effects) ======

test "MINIFILTER_PORT is the single-backslash canonical name" {
    try std.testing.expectEqual(@as(u16, 0x5C), MINIFILTER_PORT[0]);
    try std.testing.expectEqual(@as(u16, 'A'), MINIFILTER_PORT[1]);
    try std.testing.expectEqual(@as(u16, 'r'), MINIFILTER_PORT[15]);
    try std.testing.expectEqual(@as(u16, 'P'), MINIFILTER_PORT[16]);
    try std.testing.expectEqual(@as(u16, 't'), MINIFILTER_PORT[19]);
    try std.testing.expectEqual(@as(u16, 0), MINIFILTER_PORT[20]); // NUL sentinel
}

test "record layout pinned to kernel AEGIS_EVENT_RECORD" {
    try std.testing.expectEqual(@as(usize, 472), @sizeOf(AegisEventRecord));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(AegisEventRecord, "timestamp"));
    try std.testing.expectEqual(@as(usize, 28), @offsetOf(AegisEventRecord, "name_len"));
    try std.testing.expectEqual(@as(usize, 30), @offsetOf(AegisEventRecord, "path"));
}

test "processTypeFor maps kernel ordinals to HIDS process types" {
    try std.testing.expectEqual(@intFromEnum(hids.ProcessEventType.file_create), processTypeFor(AEGIS_EVT_FILE));
    try std.testing.expectEqual(@intFromEnum(hids.ProcessEventType.create), processTypeFor(AEGIS_EVT_PROC_CREATE));
    try std.testing.expectEqual(@intFromEnum(hids.ProcessEventType.terminate), processTypeFor(AEGIS_EVT_PROC_EXIT));
    // Unknown ordinals fail toward the file domain, never process escalation.
    try std.testing.expectEqual(@intFromEnum(hids.ProcessEventType.file_create), processTypeFor(99));
}

test "filetimeToUnixMs converts kernel system time and clamps garbage" {
    try std.testing.expectEqual(@as(u64, 0), filetimeToUnixMs(0));
    try std.testing.expectEqual(@as(u64, 0), filetimeToUnixMs(-5));
    try std.testing.expectEqual(@as(u64, 0), filetimeToUnixMs(116_444_736_000_000_000));
    try std.testing.expectEqual(@as(u64, 1000), filetimeToUnixMs(116_444_736_000_000_000 + 10_000_000));
}

test "pathToUtf8 decodes ASCII, CJK, and surrogate pairs" {
    var buf: [PATH_UTF8_MAX]u8 = undefined;

    var rec = std.mem.zeroes(AegisEventRecord);
    const ascii = "C:\\Temp\\marker.txt";
    for (ascii, 0..) |c, i| rec.path[i] = c;
    rec.name_len = @intCast(ascii.len);
    try std.testing.expectEqualStrings(ascii, pathToUtf8(&rec, &buf));

    rec = std.mem.zeroes(AegisEventRecord);
    rec.path[0] = 0x4E2D; // U+4E2D CJK
    rec.path[1] = 0xD83D; // U+1F600 surrogate pair
    rec.path[2] = 0xDE00;
    rec.name_len = 3;
    try std.testing.expectEqualStrings("\xE4\xB8\xAD\xF0\x9F\x98\x80", pathToUtf8(&rec, &buf));

    rec = std.mem.zeroes(AegisEventRecord);
    rec.path[0] = 0xD83D; // lone high surrogate -> U+FFFD
    rec.name_len = 1;
    try std.testing.expectEqualStrings("\xEF\xBF\xBD", pathToUtf8(&rec, &buf));

    rec = std.mem.zeroes(AegisEventRecord);
    rec.name_len = 0;
    try std.testing.expectEqualStrings("", pathToUtf8(&rec, &buf));
}

test "recordAt reads a synthetic two-record pull buffer field-for-field" {
    var pull_buf: [RECORD_SIZE * 2]u8 = undefined;
    const rec_a = AegisEventRecord{
        .event_type = AEGIS_EVT_PROC_CREATE,
        .size = @sizeOf(AegisEventRecord),
        .process_id = 4242,
        .parent_pid = 100,
        .timestamp = 116_444_736_000_000_000 + 10_000_000,
        .status = 0,
        .name_len = 6,
        .path = blk: {
            var p = std.mem.zeroes([220]u16);
            const s = "\\srvcs";
            for (s, 0..) |c, i| p[i] = c;
            break :blk p;
        },
    };
    const rec_b = AegisEventRecord{
        .event_type = AEGIS_EVT_FILE,
        .size = @sizeOf(AegisEventRecord),
        .process_id = 777,
        .parent_pid = 0,
        .timestamp = 0,
        .status = -1073741773, // STATUS_OBJECT_NAME_NOT_FOUND
        .name_len = 0,
        .path = std.mem.zeroes([220]u16),
    };
    @memcpy(pull_buf[0..RECORD_SIZE], std.mem.asBytes(&rec_a));
    @memcpy(pull_buf[RECORD_SIZE..][0..RECORD_SIZE], std.mem.asBytes(&rec_b));

    const got_a = recordAt(&pull_buf, 0);
    try std.testing.expectEqual(AEGIS_EVT_PROC_CREATE, got_a.event_type);
    try std.testing.expectEqual(@as(u32, 4242), got_a.process_id);
    try std.testing.expectEqual(@as(u32, 100), got_a.parent_pid);
    try std.testing.expectEqual(@as(u64, 1000), filetimeToUnixMs(got_a.timestamp));

    const got_b = recordAt(&pull_buf, RECORD_SIZE);
    try std.testing.expectEqual(AEGIS_EVT_FILE, got_b.event_type);
    try std.testing.expectEqual(@as(u32, 777), got_b.process_id);
    try std.testing.expectEqual(@as(i32, -1073741773), got_b.status);
    try std.testing.expectEqual(@as(u64, 0), filetimeToUnixMs(got_b.timestamp));
}

test "eventTypeToString covers every kernel ordinal" {
    try std.testing.expectEqualStrings("FILE", eventTypeToString(AEGIS_EVT_FILE));
    try std.testing.expectEqualStrings("PROC_CREATE", eventTypeToString(AEGIS_EVT_PROC_CREATE));
    try std.testing.expectEqualStrings("PROC_EXIT", eventTypeToString(AEGIS_EVT_PROC_EXIT));
    try std.testing.expectEqualStrings("UNKNOWN", eventTypeToString(99));
}
