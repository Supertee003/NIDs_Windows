// nose_pipe_reader.zig Î“Ã‡Ã¶ AEGIS Nose Î“Ã¥Ã† Event Fabric pipe bridge (T2, Step 12)
//
// Windows named pipe server that reads frames from the Go Nose capture
// process and feeds CanonicalEvents into the Zig fabric (nose_contract).
//
// Frame protocol (matches nose/pipe_writer.go):
//   u32 LE length (109 v1, 133 v2, or 165..1189 v3) + raw canonical event
//   bytes. v3 (PAYLOAD-ENVELOPE-V3-001) appends a 32-byte provenance/payload
//   envelope and bounded payload bytes to the frozen v2 base layout.
// v2 frames (T2-V6-022a) carry the full IPv6 tail; DecodedFrame sidecars
// survive the queue to the flow/anomaly stages (V6-FLOW-036/V6-DETECT-037)
// while detection/policy/forensic identity stays u32 + bit2.
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
const source_arbiter = @import("source_arbiter.zig");
const producer_identity = @import("producer_identity.zig");

// ============================================================
// OBSERVABILITY-001: bounded Nose backpressure (PACE-MF-001 pattern)
// ============================================================
// The reader used to drop immediately on a full queue share. The Go pipe
// writer is the natural upstream buffer, so a short bounded pause lets the
// consumer drain and turns a would-be real loss into a counted wait. The hard
// bound matters: a stuck consumer must end in a counted drop, never a hung
// reader. Same strict limits and stop-signal check as the minifilter pacer.
const NOSE_PACE_MARGIN: u64 = 256;
const NOSE_PACE_MAX_WAITS_MS: u32 = 5;

/// Pure gate: wait when our own Npcap ingress share is within `margin` of cap.
pub fn noseShouldPace(occupancy: u64, cap: u64, margin: u64) bool {
    return occupancy + margin >= cap;
}

fn paceBeforeSubmit(stopSignal: *std.atomic.Value(bool)) void {
    var waits: u32 = 0;
    while (waits < NOSE_PACE_MAX_WAITS_MS and !stopSignal.load(.acquire) and
        noseShouldPace(
        pipeline_queue.sourceOccupancy(.capture_npcap),
        pipeline_queue.SOURCE_OCCUPANCY_CAP,
        NOSE_PACE_MARGIN,
    )) {
        std.time.sleep(1 * std.time.ns_per_ms);
        waits += 1;
        _ = runtime_state.g_nose_pace_waits.fetchAdd(1, .monotonic);
    }
}

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
/// v3 frames are variable length: 165-byte fixed header + 0..1024 payload.
const V3_MIN_FRAME: u32 = @intCast(canonical.WIRE_V3_HEADER_SIZE);
const V3_MAX_FRAME: u32 = @intCast(canonical.WIRE_V3_MAX_SIZE);

/// Bound for drain-and-continue on a malformed length (NOSE-DISC-042). A
/// corrupt length header is a u32 with no credibility: draining more than
/// this to "resync" lets one bad header stall the reader for gigabytes and
/// the stream position after garbage is unknowable anyway. Larger lengths
/// break the connection instead — nose reconnects and framing restarts
/// clean. Legitimate frames are 109/133 bytes, orders below this bound.
pub const MAX_DISCARD_BYTES: u32 = 64 * 1024;

/// Pure frame-length classifier so the resync policy is unit-pinned
/// without a pipe handle. drain = skip-and-continue, resync = drop the
/// connection and let nose reconnect.
pub const LengthVerdict = enum { accept_v1, accept_v2, accept_v3, drain, resync };

pub fn classifyFrameLen(frameLen: u32) LengthVerdict {
    if (frameLen == FRAME_SIZE) return .accept_v1;
    if (frameLen == canonical.WIRE_V2_PAYLOAD_SIZE) return .accept_v2;
    if (frameLen >= V3_MIN_FRAME and frameLen <= V3_MAX_FRAME) return .accept_v3;
    if (frameLen <= MAX_DISCARD_BYTES) return .drain;
    return .resync;
}

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

extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
    StringSecurityDescriptor: [*:0]const u16,
    StringSDRevision: u32,
    SecurityDescriptor: *?*anyopaque,
    SecurityDescriptorSize: ?*u32,
) callconv(.C) i32;

extern "kernel32" fn LocalFree(
    hMem: ?*anyopaque,
) callconv(.C) ?*anyopaque;

// G6: explicit SDDL identical to the sensor pipe (BA+AU). The previous
// null descriptor inherited a restrictive default DACL that rejected
// non-SYSTEM writers (proven live: medium-IL client got ERROR_ACCESS_DENIED
// while the daemon waited forever), so Go nose could never deliver.
// Authenticated-user writers match the sensor pipe posture: pipe input is
// untrusted sensor data by design (observe-only, trust-gated enforcement).
const SDDL_NOSE_PIPE: [*:0]const u16 = @import("std").unicode.utf8ToUtf16LeStringLiteral("D:(A;;GA;;;BA)(A;;GA;;;AU)");
const SDDL_REVISION: u32 = 1;

const NoseSecurityAttributes = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: i32,
};

extern "kernel32" fn DisconnectNamedPipe(
    hNamedPipe: usize,
) callconv(.C) i32;

extern "kernel32" fn GetLastError() callconv(.C) u32;

// ============================================================
// Helpers
// ============================================================

const DEFAULT_PIPE_NAME: [20:0]u16 = .{ '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 'a', 'e', 'g', 'i', 's', '_', 'n', 'o', 's', 'e', 0 };

fn createPipeServer(pipe_name: [*:0]const u16) !usize {
    // During orderly lifecycle recovery the previous owner can have closed
    // its control pipe while the Nose pipe handle is still draining. Keep the
    // single-instance authority (nMaxInstances=1), but give that owner a
    // bounded handoff window instead of converting a transient ERROR_PIPE_BUSY
    // into nose_init_failed immediately.
    var attempt: u32 = 0;
    // G6: explicit SDDL (fail-closed like the sensor pipe). The old null
    // descriptor inherited a restrictive default DACL that rejected
    // non-SYSTEM writers (proven live: medium-IL client got
    // ERROR_ACCESS_DENIED while the daemon waited forever), so Go nose
    // could never deliver. AU writers match the sensor pipe posture.
    var pipe_sd: ?*anyopaque = null;
    var sec_attr = NoseSecurityAttributes{
        .nLength = @sizeOf(NoseSecurityAttributes),
        .lpSecurityDescriptor = null,
        .bInheritHandle = 0,
    };
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        SDDL_NOSE_PIPE,
        SDDL_REVISION,
        &pipe_sd,
        null,
    ) != 0) {
        sec_attr.lpSecurityDescriptor = pipe_sd;
    } else {
        std.log.err("[NOSE PIPE] CRITICAL: SDDL conversion failed - REFUSING to create pipe (fail-closed)", .{});
        runtime_state.markWorkerFailure(.nose);
        return error.CreatePipeFailed;
    }
    defer _ = LocalFree(pipe_sd);
    while (attempt < 120) { // 60 seconds at 500 ms intervals
        const handle = CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
            1, // single instance: never allow duplicate Nose authorities
            0, // no output buffer
            canonical.WIRE_V3_MAX_SIZE * 64, // input buffer: 64 max-size frames
            0, // default timeout
            @ptrCast(&sec_attr),
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
    identity_rejected: u64 = 0,
    pipe_errors: u64 = 0,
};

var g_reader_stats = PipeReaderStats{};
// V3-PRODUCER-IDENTITY-001: the guard persists across pipe reconnects so a
// restarted Nose with a NEW generation can resume sequence 1 without being
// confused with the previous process, while a replayed old tuple is refused.
var g_producer_guard = producer_identity.Guard{};
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
    runPipeReaderLoopNamed(stopSignal, &DEFAULT_PIPE_NAME);
}

/// I44-E3-SEAM: identical production reader loop with an explicit pipe name.
/// The runtime entrypoint above is unchanged and still binds the canonical
/// \\.\pipe\aegis_nose. This seam exists only so an isolated exact-delta
/// harness can own its own single-instance pipe without displacing a live
/// daemon; it adds no new ingress path, authority or wire contract.
pub fn runPipeReaderLoopNamed(stopSignal: *std.atomic.Value(bool), pipe_name: [*:0]const u16) void {
    const server = createPipeServer(pipe_name) catch |e| {
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
                // OBSERVABILITY-001 (issue #44): local stats are invisible to
                // health; the authoritative counter must move too.
                _ = runtime_state.g_nose_pipe_errors.fetchAdd(1, .monotonic);
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
        runtime_state.g_nose_connected.store(true, .monotonic);

        // Read frames until disconnect
        readClientLoop(server, stopSignal);

        _ = DisconnectNamedPipe(server);
        runtime_state.g_nose_connected.store(false, .monotonic);
        std.log.info("[NOSE PIPE] client disconnected, waiting for next...", .{});
    }

    std.log.info("[NOSE PIPE] reader loop exiting (read={d} drop={d} submitted={d})", .{ g_reader_stats.frames_read, g_reader_stats.frames_dropped, g_reader_stats.frames_submitted });
}

fn readClientLoop(server: usize, stopSignal: *std.atomic.Value(bool)) void {
    // V3-PRODUCER-IDENTITY-001: identity is keyed by the v3 tuple, not by pipe
    // connection. The legacy event_id anomaly counters remain for telemetry,
    // but admission now uses the persistent producer guard below.
    var previous_connection_event_id: u64 = 0;
    while (!stopSignal.load(.acquire)) {
        // Read length header (u32 LE)
        var lenBuf: [4]u8 = undefined;
        if (!readExact(server, &lenBuf, stopSignal)) {
            const err = GetLastError();
            std.log.warn("[NOSE PIPE] frame header read failed: GetLastError={d}", .{err});
            if (err == ERROR_BROKEN_PIPE or err == ERROR_NO_DATA) break;
            g_reader_stats.pipe_errors += 1;
            _ = runtime_state.g_nose_pipe_errors.fetchAdd(1, .monotonic);
            break;
        }
        const frameLen = @as(u32, lenBuf[0]) |
            (@as(u32, lenBuf[1]) << 8) |
            (@as(u32, lenBuf[2]) << 16) |
            (@as(u32, lenBuf[3]) << 24);

        const verdict = classifyFrameLen(frameLen);
        if (verdict == .resync) {
            std.log.err("[NOSE PIPE] absurd frame length {d}: dropping connection to resync (nose will reconnect)", .{frameLen});
            g_reader_stats.frames_dropped += 1;
            g_reader_stats.pipe_errors += 1;
            runtime_state.recordNoseFrameDrop(.framing);
            _ = runtime_state.g_nose_pipe_errors.fetchAdd(1, .monotonic);
            break;
        }
        if (verdict == .drain) {
            std.log.warn("[NOSE PIPE] rejected frame length: {d}, expected {d}/{d} or v3 {d}..{d}", .{ frameLen, FRAME_SIZE, canonical.WIRE_V2_PAYLOAD_SIZE, V3_MIN_FRAME, V3_MAX_FRAME });
            // Skip malformed frame: read and discard (bounded by classifier)
            var discard: [256]u8 = undefined;
            var remaining = frameLen;
            while (remaining > 0) {
                const toRead: usize = @intCast(@min(remaining, 256));
                if (!readExact(server, discard[0..toRead], stopSignal)) break;
                remaining -= @intCast(toRead);
            }
            g_reader_stats.frames_dropped += 1;
            runtime_state.recordNoseFrameDrop(.framing);
            continue;
        }

        // Read payload (v1 109, v2 133, or v3 165..1189 bytes, length-delimited)
        var payload: [canonical.WIRE_V3_MAX_SIZE]u8 = undefined;
        const payload_slice = payload[0..frameLen];
        if (!readExact(server, payload_slice, stopSignal)) {
            std.log.warn("[NOSE PIPE] frame payload read failed: GetLastError={d}", .{GetLastError()});
            g_reader_stats.pipe_errors += 1;
            g_reader_stats.frames_dropped += 1;
            // OBSERVABILITY-001 (issue #44): the length header committed us to
            // a frame, so an aborted payload is both an I/O error and a lost
            // frame (local + authoritative, same dual accounting as resync).
            // The cause is `midframe`, not framing: the header was valid and
            // the payload read failed.
            _ = runtime_state.g_nose_pipe_errors.fetchAdd(1, .monotonic);
            runtime_state.recordNoseFrameDrop(.midframe);
            break;
        }

        g_reader_stats.frames_read += 1;
        _ = runtime_state.g_nose_frames_read.fetchAdd(1, .monotonic);
        // LOG-FLOOD-062: per-frame routine logs are debug, not info. At
        // capture rates info-level per-frame lines flood the log sink on
        // this hot thread; volume stays visible via frames_read/submitted
        // counters (stats + metrics). Reject/duplicate/error lines below
        // stay warn: they signal data-plane anomalies, not routine flow.
        std.log.debug("[NOSE PIPE] frame received: {d} bytes", .{frameLen});

        // Deserialize with version dispatch (v1 frozen path, v2 full-IPv6
        // tail). v2 sidecars ride the DecodedFrame into the queue
        // (V6-FLOW-036); v1 frames carry null sidecars by construction.
        const frame = canonical.deserializeDispatch(payload_slice) orelse {
            std.log.warn("[NOSE PIPE] canonical frame rejected by deserializer", .{});
            g_reader_stats.frames_rejected += 1;
            _ = runtime_state.g_nose_frames_rejected.fetchAdd(1, .monotonic);
            continue;
        };
        const event = frame.event;

        // Legacy telemetry only: event_id is a base-event identity, not the
        // producer key. It is still counted/anomalied but never gates a v3
        // provenance-bearing frame.
        if (event.event_id == previous_connection_event_id) {
            _ = runtime_state.g_nose_duplicate_event_ids.fetchAdd(1, .monotonic);
            std.log.warn("[NOSE PIPE] duplicate event_id={d}", .{event.event_id});
        } else if (previous_connection_event_id != 0 and event.event_id < previous_connection_event_id) {
            _ = runtime_state.g_nose_non_monotonic_event_ids.fetchAdd(1, .monotonic);
            std.log.warn("[NOSE PIPE] non-monotonic event_id={d}, previous={d}", .{ event.event_id, previous_connection_event_id });
        }
        previous_connection_event_id = event.event_id;
        g_last_event_id = event.event_id;
        runtime_state.g_nose_last_event_id.store(event.event_id, .monotonic);

        // V3-PRODUCER-IDENTITY-001: fail closed on a partial tuple, an exact
        // replay, or a regression. Gaps/evictions are visible but admitted.
        const identity_eval = g_producer_guard.evaluate(frame.envelope);
        switch (identity_eval.decision) {
            .invalid => {
                _ = runtime_state.g_nose_producer_invalid.fetchAdd(1, .monotonic);
                g_reader_stats.identity_rejected += 1;
                runtime_state.recordNoseFrameDrop(.identity);
                std.log.warn("[NOSE PIPE] v3 provenance tuple incomplete: event_id={d}", .{event.event_id});
                continue;
            },
            .duplicate => {
                _ = runtime_state.g_nose_producer_duplicate.fetchAdd(1, .monotonic);
                g_reader_stats.identity_rejected += 1;
                runtime_state.recordNoseFrameDrop(.identity);
                std.log.warn("[NOSE PIPE] duplicate producer sequence: event_id={d}", .{event.event_id});
                continue;
            },
            .regression => {
                _ = runtime_state.g_nose_producer_regression.fetchAdd(1, .monotonic);
                g_reader_stats.identity_rejected += 1;
                runtime_state.recordNoseFrameDrop(.identity);
                std.log.warn("[NOSE PIPE] non-monotonic producer sequence: event_id={d}", .{event.event_id});
                continue;
            },
            .gap => _ = runtime_state.g_nose_producer_gap.fetchAdd(1, .monotonic),
            .evicted => _ = runtime_state.g_nose_producer_evictions.fetchAdd(1, .monotonic),
            .accepted, .legacy => {},
        }
        if (identity_eval.identity) |id| {
            runtime_state.g_nose_last_capture_sequence.store(id.capture_sequence, .monotonic);
            runtime_state.g_nose_last_producer_epoch.store(id.producer_epoch, .monotonic);
            runtime_state.g_nose_last_producer_generation.store(id.producer_generation, .monotonic);
            runtime_state.g_nose_last_interface_id.store(id.interface_id, .monotonic);
        }

        // VISIBILITY-001: enforce the arbiter's packet-side permission AT THE
        // SUBMIT POINT (it used to be log-only). In kernel-primary ingress the
        // frame is drained and counted as shadow — visible, never a silent
        // loss, and never a second detection authority alongside WFP. Every
        // other mode, including the pre-publish `undecided` state, submits
        // exactly as before (so the running soak is unaffected).
        if (source_arbiter.noseFrameIsShadowed(
            runtime_state.g_capture_mode.load(.acquire),
            runtime_state.g_wfp_provider_state.load(.acquire),
        )) {
            _ = runtime_state.g_nose_shadow_frames.fetchAdd(1, .monotonic);
            std.log.debug("[NOSE PIPE] frame shadowed (kernel-primary ingress): event_id={d}", .{event.event_id});
            continue;
        }

        // Submit directly to the queue consumed by event_processor. There is
        // no second acquisition queue between canonical validation and detect.
        // The full DecodedFrame goes in so v2 sidecars survive to the flow
        // stage (V6-FLOW-036) and v3 payload/provenance reaches Zig detection.
        // v1/v2 frames carry no wire payload (metadata-only compatibility);
        // legacy v3-unaware callers still supply an empty slice.
        // OBSERVABILITY-001: bounded backpressure before the admission attempt.
        // A pause is not a loss (the Go pipe buffers upstream); after the hard
        // 5 ms bound the existing counted-drop path below still applies.
        paceBeforeSubmit(stopSignal);
        switch (pipeline_queue.pushDecodedFrameDetailed(&frame, frame.payload)) {
            .accepted => {
                g_reader_stats.frames_submitted += 1;
                _ = runtime_state.g_nose_frames_submitted.fetchAdd(1, .monotonic);
                std.log.debug("[NOSE PIPE] canonical event submitted: event_id={d}", .{event.event_id});
            },
            .rejected_shape => {
                // Codec-impossible shape (bad magic/version, mixed sidecars,
                // direction > 1): a codec defect, not a full queue.
                g_reader_stats.frames_dropped += 1;
                runtime_state.recordNoseFrameDrop(.shape);
            },
            .dropped_capacity => {
                g_reader_stats.frames_dropped += 1;
                runtime_state.recordNoseFrameDrop(.capacity);
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

test "OBSERVABILITY-001 noseShouldPace gates on the near-full share" {
    const cap: u64 = 1000;
    const margin: u64 = NOSE_PACE_MARGIN;
    // Well below the cap: no backpressure.
    try std.testing.expect(!noseShouldPace(100, cap, margin));
    try std.testing.expect(!noseShouldPace(cap - margin - 1, cap, margin));
    // At/inside the margin: pause. Boundary is inclusive (occupancy+margin>=cap).
    try std.testing.expect(noseShouldPace(cap - margin, cap, margin));
    try std.testing.expect(noseShouldPace(cap - 1, cap, margin));
    try std.testing.expect(noseShouldPace(cap, cap, margin));
}

test "FRAME_SIZE matches canonical wire payload" {
    try std.testing.expectEqual(canonical.WIRE_PAYLOAD_SIZE, FRAME_SIZE);
}

test "reader accepts v1, v2, and v3 frame lengths" {
    // Contract pin: the length-delimited pipe carries 109 (v1, frozen),
    // 133 (v2, full IPv6 tail), or a bounded v3 frame (165..1189).
    try std.testing.expectEqual(@as(usize, 109), canonical.WIRE_PAYLOAD_SIZE);
    try std.testing.expectEqual(@as(usize, 133), canonical.WIRE_V2_PAYLOAD_SIZE);
    try std.testing.expectEqual(@as(usize, 165), canonical.WIRE_V3_HEADER_SIZE);
    try std.testing.expectEqual(@as(usize, 1189), canonical.WIRE_V3_MAX_SIZE);
}

test "classifyFrameLen bounds the drain and resyncs on absurd lengths" {
    // NOSE-DISC-042: legitimate frames pass; small garbage is drained; a
    // corrupt u32 must never stall the reader draining gigabytes — the
    // connection drops and nose reconnects instead.
    try std.testing.expectEqual(LengthVerdict.accept_v1, classifyFrameLen(109));
    try std.testing.expectEqual(LengthVerdict.accept_v2, classifyFrameLen(133));
    try std.testing.expectEqual(LengthVerdict.accept_v3, classifyFrameLen(165));
    try std.testing.expectEqual(LengthVerdict.accept_v3, classifyFrameLen(1189));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(0));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(108));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(134));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(164));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(1190));
    try std.testing.expectEqual(LengthVerdict.drain, classifyFrameLen(MAX_DISCARD_BYTES));
    try std.testing.expectEqual(LengthVerdict.resync, classifyFrameLen(MAX_DISCARD_BYTES + 1));
    try std.testing.expectEqual(LengthVerdict.resync, classifyFrameLen(std.math.maxInt(u32)));
}

test "G6 nose pipe SDDL converts (fail-closed path would refuse)" {
    // A typo in the SDDL string makes createPipeServer refuse to create
    // the pipe at all; pin the conversion itself so the constant cannot
    // silently rot. Windows-only API — skip cleanly elsewhere.
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    var sd: ?*anyopaque = null;
    try std.testing.expect(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        SDDL_NOSE_PIPE,
        SDDL_REVISION,
        &sd,
        null,
    ) != 0);
    try std.testing.expect(sd != null);
    _ = LocalFree(sd);
}
