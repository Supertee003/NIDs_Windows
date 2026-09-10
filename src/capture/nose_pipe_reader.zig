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
// Build: only used by core/ build tests, not build.zig main target (deferred T3).
// Windows-only (named pipe API); compiles on other platforms with stubs.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const nose_contract = @import("nose_contract.zig");

// ============================================================
// Win32 Pipe Constants
// ============================================================

const PIPE_ACCESS_INBOUND = 0x00000001;
const PIPE_TYPE_BYTE = 0x00000000;
const PIPE_READMODE_BYTE = 0x00000000;
const PIPE_WAIT = 0x00000000;
const INFINITE = 0xFFFFFFFF;
const INVALID_HANDLE = @as(usize, @bitCast(@as(isize, -1)));
const ERROR_BROKEN_PIPE = 109;
const ERROR_NO_DATA = 232;

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
    const handle = CreateNamedPipeW(
        &PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, // single instance
        0, // no output buffer
        FRAME_SIZE * 256, // input buffer: 256 frames
        0, // default timeout
        null,
    );
    if (handle == INVALID_HANDLE) return error.CreatePipeFailed;
    return handle;
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
        return;
    };
    defer _ = CloseHandle(server);

    std.log.info("[NOSE PIPE] pipe server created, waiting for client...", .{});

    while (!stopSignal.load(.acquire)) {
        // Wait for client
        if (ConnectNamedPipe(server, null) == 0) {
            const err = GetLastError();
            if (err != 535) { // ERROR_PIPE_CONNECTED
                if (stopSignal.load(.acquire)) break;
                std.log.err("[NOSE PIPE] ConnectNamedPipe error: {d}", .{err});
                g_reader_stats.pipe_errors += 1;
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
        }
        std.log.info("[NOSE PIPE] client connected", .{});

        // Read frames until disconnect
        readClientLoop(server, stopSignal);

        _ = DisconnectNamedPipe(server);
        std.log.info("[NOSE PIPE] client disconnected, waiting for next...", .{});
    }

    std.log.info("[NOSE PIPE] reader loop exiting (read={d} drop={d} submitted={d})",
        .{ g_reader_stats.frames_read, g_reader_stats.frames_dropped, g_reader_stats.frames_submitted });
}

fn readClientLoop(server: usize, stopSignal: *std.atomic.Value(bool)) void {
    while (!stopSignal.load(.acquire)) {
        // Read length header (u32 LE)
        var lenBuf: [4]u8 = undefined;
        var bytesRead: u32 = 0;
        if (ReadFile(server, &lenBuf, 4, &bytesRead, null) == 0) {
            const err = GetLastError();
            if (err == ERROR_BROKEN_PIPE or err == ERROR_NO_DATA) break;
            g_reader_stats.pipe_errors += 1;
            break;
        }
        if (bytesRead < 4) break;

        const frameLen = @as(u32, lenBuf[0]) |
            (@as(u32, lenBuf[1]) << 8) |
            (@as(u32, lenBuf[2]) << 16) |
            (@as(u32, lenBuf[3]) << 24);

        if (frameLen != FRAME_SIZE) {
            // Skip malformed frame: read and discard
            var discard: [256]u8 = undefined;
            var remaining = frameLen;
            while (remaining > 0) {
                const toRead: u32 = @intCast(@min(remaining, 256));
                if (ReadFile(server, &discard, toRead, &bytesRead, null) == 0) break;
                if (bytesRead == 0) break;
                remaining -= bytesRead;
            }
            g_reader_stats.frames_dropped += 1;
            continue;
        }

        // Read payload
        var payload: [FRAME_SIZE]u8 = undefined;
        bytesRead = 0;
        if (ReadFile(server, &payload, FRAME_SIZE, &bytesRead, null) == 0) {
            g_reader_stats.pipe_errors += 1;
            break;
        }
        if (bytesRead < FRAME_SIZE) {
            g_reader_stats.frames_dropped += 1;
            continue;
        }

        g_reader_stats.frames_read += 1;

        // Deserialize and validate
        const event = canonical.deserializeFromBytes(&payload) orelse {
            g_reader_stats.frames_rejected += 1;
            continue;
        };

        // Submit to fabric (policy-free acquisition path)
        const result = nose_contract.submitEvent(event);
        switch (result) {
            .accepted => g_reader_stats.frames_submitted += 1,
            else => {
                g_reader_stats.frames_rejected += 1;
            },
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