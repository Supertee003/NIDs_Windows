// nose_pipe_reader.zig Î“Ã‡Ã¶ AEGIS Nose Î“Ã¥Ã† Event Fabric pipe bridge (T2, Step 12)
//
// Windows named pipe server that reads frames from the Go Nose capture
// process and feeds CanonicalEvents into the Zig fabric (nose_contract).
//
// Frame protocol (matches nose/pipe_writer.go):
//   u32 LE length (always 109) + 109 raw canonical event bytes.
//
// After each frame the reader validates schema via canonical.validate()
// and submits through nose_contract.submitEvent(), routing the event
// into the priority queue fabric.  Policy / detection stays downstream.
//
// The pipe server handles backpressure gracefully: if the fabric is
// full the event is dropped with an increment (NIDS never blocks capture
// on a full consumer).
//
// Production: started by daemon.zig as the canonical Go Nose ingress path.
// Windows-only (named pipe API); compiles on other platforms with stubs.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const pipeline_queue = @import("../pipeline/event_queue.zig");
const runtime_state = @import("../pipeline/runtime_state.zig");

// ============================================================
// Win32 Pipe Constants
// ============================================================

const PIPE_ACCESS_INBOUND = 0x00000001;
const PIPE_TYPE_BYTE = 0x00000000;
const PIPE_READMODE_BYTE = 0x00000000;
// Non-blocking connect lets the worker observe stopSignal while no Go Nose
// client is connected. A blocking ConnectNamedPipe(NULL) cannot be released
// by the runtime stop flag and would make supervisor.join() hang forever.
const PIPE_NOWAIT = 0x00000001;
const INFINITE = 0xFFFFFFFF;
const INVALID_HANDLE = @as(usize, @bitCast(@as(isize, -1)));
const ERROR_BROKEN_PIPE = 109;
const ERROR_NO_DATA = 232;
const ERROR_PIPE_BUSY = 231;
// Returned by ConnectNamedPipe in NOWAIT mode when the previous client has
// disconnected. The instance must be reset with DisconnectNamedPipe before
// it can accept the next client.
const ERROR_NO_DATA_CONNECT = 232;
const ERROR_PIPE_CONNECTED = 535;
const ERROR_PIPE_LISTENING = 536;

const FRAME_SIZE: usize = 109; // canonical.WIRE_PAYLOAD_SIZE

// ============================================================
// Win32 Extern (kernel32) Î“Ã‡Ã¶ Pipe functions not in Zig std
// ============================================================

extern "kernel32" fn CreateNamedPipeW(
    lpName: [*:0]const u16,
    openMode: u32,
    pipeMode: u32,
    nMaxInstances: u32,
    nOutBufferSize: u32,
    nInBufferSize: u32,
    nDefaultTimeOut: u32,
    lpSecurityAttributes: ?*anyopaque,
) callconv(.C) usize;

extern "kernel32" fn ConnectNamedPipe(
    hNamedPipe: usize,
    lpOverlapped: ?*anyopaque,
) callconv(.C) i32;

extern "kernel32" fn SetNamedPipeHandleState(
    hNamedPipe: usize,
    lpMode: *u32,
    lpMaxCollectionCount: ?*u32,
    lpCollectDataTimeout: ?*u32,
) callconv(.C) i32;

extern "kernel32" fn ReadFile(
    hFile: usize,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *u32,
    lpOverlapped: ?*anyopaque,
) callconv(.C) i32;

extern "kernel32" fn CloseHandle(
    hObject: usize,
) callconv(.C) i32;

extern "kernel32" fn DisconnectNamedPipe(
    hNamedPipe: usize,
) callconv(.C) i32;

extern "kernel32" fn GetLastError() callconv(.C) u32;

// ============================================================
// Helpers
// ============================================================

const PIPE_NAME: [20:0]u16 = .{ '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 'a', 'e', 'g', 'i', 's', '_', 'n', 'o', 's', 'e', 0 };

fn createPipeServer() !usize {
    // During orderly lifecycle recovery the previous owner can have closed
    // its control pipe while the Nose pipe handle is still draining. Keep the
    // single-instance authority (nMaxInstances=1), but give that owner a
    // bounded handoff window instead of converting a transient ERROR_PIPE_BUSY
    // into nose_init_failed immediately.
    var attempt: u32 = 0;
    while (attempt < 120) { // 60 seconds at 500 ms intervals
        const handle = CreateNamedPipeW(
            &PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
            1, // single instance: never allow duplicate Nose authorities
            0, // no output buffer
            FRAME_SIZE * 256, // input buffer: 256 frames
            0, // default timeout
            null,
        );
        if (handle != INVALID_HANDLE) return handle;

        const err = GetLastError();
        if (err != ERROR_PIPE_BUSY) return error.CreatePipeFailed;
        if (attempt == 0 or attempt % 10 == 0) {
            std.log.warn("[NOSE PIPE] pipe busy during owner handoff; retry {d}/120", .{attempt + 1});
        }
        std.time.sleep(500 * std.time.ns_per_ms);
        attempt += 1;
    }
    std.log.err("[NOSE PIPE] pipe remained busy for 60 seconds", .{});
    return error.CreatePipeFailed;
}

/// Read exactly buf.len bytes. ReadFile may return a short read even for a
/// byte-mode named pipe, so callers must never treat one read as one frame.
fn readExact(server: usize, buf: []u8, stopSignal: *std.atomic.Value(bool)) bool {
    var total: usize = 0;
    while (total < buf.len) {
        var n: u32 = 0;
        const remaining: u32 = @intCast(buf.len - total);
        if (ReadFile(server, buf.ptr + total, remaining, &n, null) == 0) {
            const err = GetLastError();
            if (err == ERROR_NO_DATA) {
                // The listener is created with PIPE_NOWAIT so shutdown can
                // be observed without an overlapped handle. In this mode
                // ReadFile reports ERROR_NO_DATA when no bytes are available
                // yet; that is not a disconnect. Poll until data arrives or
                // the supervisor requests shutdown.
                if (stopSignal.load(.acquire)) return false;
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            return false;
        }
        if (n == 0) return false;
        total += @intCast(n);
    }
    return true;
}

// ============================================================
// Reader Stats
// ============================================================

pub const PipeReaderStats = struct {
    frames_read: u64 = 0,
    frames_dropped: u64 = 0,
    frames_submitted: u64 = 0,
    frames_rejected: u64 = 0,
    pipe_errors: u64 = 0,
};

var g_reader_stats = PipeReaderStats{};
// This is the last event ID observed by the runtime, retained for health and
// forensic observability.  Monotonicity is checked per producer connection
// below, because Go Nose currently starts a new process-local sequence after
// reconnect/restart.  Comparing a new connection with the previous process
// would report a false regression while still accepting the frame.
var g_last_event_id: u64 = 0;

pub fn getReaderStats() PipeReaderStats {
    return g_reader_stats;
}

// ============================================================
// Read loop (blocking, for background thread)
// ============================================================

/// Run the pipe reader loop.  Blocks until stopSignal is set.
/// Creates the named pipe, accepts clients, reads frames, and feeds
/// them into the fabric.  After a client disconnects, reconnects
/// (AcceptEx pattern via DisconnectNamedPipe + ConnectNamedPipe).
///
/// Call from a dedicated thread at startup:
///   const t = try std.Thread.spawn(.{}, runPipeReaderLoop, .{&stop_flag});
pub fn runPipeReaderLoop(stopSignal: *std.atomic.Value(bool)) void {
    const server = createPipeServer() catch |e| {
        std.log.err("[NOSE PIPE] create pipe server failed: {} (GetLastError={d})", .{ e, GetLastError() });
        runtime_state.markWorkerFailure(.nose);
        return;
    };
    defer _ = CloseHandle(server);
    runtime_state.g_nose_ready.store(true, .release);
    defer runtime_state.g_nose_ready.store(false, .release);

    std.log.info("[NOSE PIPE] pipe server created, waiting for client...", .{});

    while (!stopSignal.load(.acquire)) {
        // Wait for client
        if (ConnectNamedPipe(server, null) == 0) {
            const err = GetLastError();
            if (err == ERROR_PIPE_LISTENING) {
                // No client yet; poll so shutdown can terminate promptly.
                std.time.sleep(50 * std.time.ns_per_ms);
                continue;
            }
            if (err == ERROR_NO_DATA_CONNECT or err == ERROR_BROKEN_PIPE) {
                // A NOWAIT named-pipe instance remains disconnected after a
                // client closes. Without this reset, ConnectNamedPipe keeps
                // returning ERROR_NO_DATA and all subsequent Nose clients
                // are rejected even though the pipe name is still present.
                _ = DisconnectNamedPipe(server);
                if (!stopSignal.load(.acquire)) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                }
                continue;
            }
            if (err != ERROR_PIPE_CONNECTED) {
                if (stopSignal.load(.acquire)) break;
                std.log.err("[NOSE PIPE] ConnectNamedPipe error: {d}", .{err});
                g_reader_stats.pipe_errors += 1;
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
        }
        // The listener uses NOWAIT only to make ConnectNamedPipe pollable.
        // Restore blocking byte-mode reads once a client is connected so a
        // partial frame cannot be mistaken for a disconnect.
        var wait_mode: u32 = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | 0x00000000;
        _ = SetNamedPipeHandleState(server, &wait_mode, null, null);
        std.log.info("[NOSE PIPE] client connected", .{});
        runtime_state.g_nose_connected = true;

        // Read frames until disconnect
        readClientLoop(server, stopSignal);

        _ = DisconnectNamedPipe(server);
        runtime_state.g_nose_connected = false;
        std.log.info("[NOSE PIPE] client disconnected, waiting for next...", .{});
    }

    std.log.info("[NOSE PIPE] reader loop exiting (read={d} drop={d} submitted={d})",
        .{ g_reader_stats.frames_read, g_reader_stats.frames_dropped, g_reader_stats.frames_submitted });
}

fn readClientLoop(server: usize, stopSignal: *std.atomic.Value(bool)) void {
    // A connection is a producer generation boundary for the current wire
    // contract.  Keep duplicate/non-monotonic checks strict within that
    // connection, but do not compare a restarted Nose sequence with the old
    // connection's final event ID.  Cross-generation identity continuity is
    // a separate contract task requiring an epoch/durable identity field.
    var previous_connection_event_id: u64 = 0;
    while (!stopSignal.load(.acquire)) {
        // Read length header (u32 LE)
        var lenBuf: [4]u8 = undefined;
        if (!readExact(server, &lenBuf, stopSignal)) {
            const err = GetLastError();
            std.log.warn("[NOSE PIPE] frame header read failed: GetLastError={d}", .{err});
            if (err == ERROR_BROKEN_PIPE or err == ERROR_NO_DATA) break;
            g_reader_stats.pipe_errors += 1;
            runtime_state.g_nose_pipe_errors += 1;
            break;
        }
        const frameLen = @as(u32, lenBuf[0]) |
            (@as(u32, lenBuf[1]) << 8) |
            (@as(u32, lenBuf[2]) << 16) |
            (@as(u32, lenBuf[3]) << 24);

        if (frameLen != FRAME_SIZE) {
            std.log.warn("[NOSE PIPE] rejected frame length: {d}, expected {d}", .{ frameLen, FRAME_SIZE });
            // Skip malformed frame: read and discard
            var discard: [256]u8 = undefined;
            var remaining = frameLen;
            while (remaining > 0) {
                const toRead: usize = @intCast(@min(remaining, 256));
                if (!readExact(server, discard[0..toRead], stopSignal)) break;
                remaining -= @intCast(toRead);
            }
            g_reader_stats.frames_dropped += 1;
            runtime_state.g_nose_frames_dropped += 1;
            continue;
        }

        // Read payload
        var payload: [FRAME_SIZE]u8 = undefined;
        if (!readExact(server, &payload, stopSignal)) {
            std.log.warn("[NOSE PIPE] frame payload read failed: GetLastError={d}", .{GetLastError()});
            g_reader_stats.pipe_errors += 1;
            break;
        }

        g_reader_stats.frames_read += 1;
        runtime_state.g_nose_frames_read += 1;
        std.log.info("[NOSE PIPE] frame received: {d} bytes", .{FRAME_SIZE});

        // Deserialize and validate
        const event = canonical.deserializeFromBytes(&payload) orelse {
            std.log.warn("[NOSE PIPE] canonical frame rejected by deserializer", .{});
            g_reader_stats.frames_rejected += 1;
            runtime_state.g_nose_frames_rejected += 1;
            continue;
        };

        if (event.event_id == previous_connection_event_id) {
            runtime_state.g_nose_duplicate_event_ids += 1;
            std.log.warn("[NOSE PIPE] duplicate event_id={d}", .{event.event_id});
        } else if (previous_connection_event_id != 0 and event.event_id < previous_connection_event_id) {
            runtime_state.g_nose_non_monotonic_event_ids += 1;
            std.log.warn("[NOSE PIPE] non-monotonic event_id={d}, previous={d}", .{ event.event_id, previous_connection_event_id });
        }
        previous_connection_event_id = event.event_id;
        g_last_event_id = event.event_id;
        runtime_state.g_nose_last_event_id = event.event_id;

        // Submit directly to the queue consumed by event_processor. There is
        // no second acquisition queue between canonical validation and detect.
        if (pipeline_queue.pushCanonicalEvent(&event)) {
            g_reader_stats.frames_submitted += 1;
            runtime_state.g_nose_frames_submitted += 1;
            std.log.info("[NOSE PIPE] canonical event submitted: event_id={d}", .{event.event_id});
        } else {
            g_reader_stats.frames_dropped += 1;
            runtime_state.g_nose_frames_dropped += 1;
        }
    }
}

// ============================================================
// Tests (no Win32 calls, validates the reader contract)
// ============================================================

test "PipeReaderStats default zeros" {
    const stats = PipeReaderStats{};
    try std.testing.expect(stats.frames_read == 0);
    try std.testing.expect(stats.frames_dropped == 0);
}

test "FRAME_SIZE matches canonical wire payload" {
    try std.testing.expectEqual(canonical.WIRE_PAYLOAD_SIZE, FRAME_SIZE);
}
