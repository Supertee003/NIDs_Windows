// nose_pipe_e2e_cli.zig - T2 E2E harness: named-pipe server + fabric sink
//
// USAGE: `src/tests/cli/nose_pipe_e2e_cli.zig` must be compiled with `src/` as
// the module root (Zig 0.13 rejects its `../../` imports when this file is the
// standalone root); `zig run src/tests/cli/nose_pipe_e2e_cli.zig` is NOT valid.
// Compile via a `src/`-root wrapper (or a build.zig step), then pass:
//   [-inject] [-seconds N]
//
// Creates \\.\pipe\aegis_nose, spawns the reader loop, waits N seconds
// (default 10), then prints fabric + reader stats and exits 1 if no
// event made it into the fabric (so E2E scripts can gate on success).
//
// `-inject` is the issue #44 exact-delta proof. It opens a real named-pipe
// client and feeds three failing frames (close-before-payload, absurd length,
// invalid-but-drainable length followed by a valid frame), asserting the exact
// authoritative + local counter delta for each. It needs no Go producer.
//
// ISOLATED HOST ONLY: stop the AegisNids service before `-inject` so the
// harness owns \\.\pipe\aegis_nose; never inject failing frames into a live
// daemon. Without `-inject`, runs alongside:  cd nose && go run . -capture

const std = @import("std");
const win = std.os.windows;
const pipe_reader = @import("../../capture/nose_pipe_reader.zig");
const nose_contract = @import("../../capture/nose_contract.zig");
const canonical = @import("../../contract/canonical_event.zig");
const runtime_state = @import("../../pipeline/runtime_state.zig");

var stop_flag = std.atomic.Value(bool).init(false);

extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: win.DWORD,
    dwShareMode: win.DWORD,
    lpSecurityAttributes: ?*win.SECURITY_ATTRIBUTES,
    dwCreationDisposition: win.DWORD,
    dwFlagsAndAttributes: win.DWORD,
    hTemplateFile: ?win.HANDLE,
) callconv(.C) win.HANDLE;

const PIPE_NAME: [20:0]u16 = .{ '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 'a', 'e', 'g', 'i', 's', '_', 'n', 'o', 's', 'e', 0 };
const GENERIC_WRITE_V: win.DWORD = 0x40000000;
const OPEN_EXISTING_V: win.DWORD = 3;
const FILE_ATTRIBUTE_NORMAL_V: win.DWORD = 0x80;

fn openClient() !win.HANDLE {
    const h = CreateFileW(&PIPE_NAME, GENERIC_WRITE_V, 0, null, OPEN_EXISTING_V, FILE_ATTRIBUTE_NORMAL_V, null);
    if (h == win.INVALID_HANDLE_VALUE) return error.OpenPipeFailed;
    return h;
}

fn waitForPipe(timeout_ms: i64) !win.HANDLE {
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (std.time.milliTimestamp() < deadline) {
        if (openClient()) |h| return h else |_| std.time.sleep(20 * std.time.ns_per_ms);
    }
    return error.PipeUnavailable;
}

fn writeAllPipe(h: win.HANDLE, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try win.WriteFile(h, bytes[offset..], null);
        if (written == 0) return error.WriteFailed;
        offset += @intCast(written);
    }
}

fn writeU32Le(h: win.HANDLE, value: u32) !void {
    var buf: [4]u8 = undefined;
    buf[0] = @truncate(value);
    buf[1] = @truncate(value >> 8);
    buf[2] = @truncate(value >> 16);
    buf[3] = @truncate(value >> 24);
    try writeAllPipe(h, &buf);
}

const CounterSnap = struct {
    total: u64,
    framing: u64,
    midframe: u64,
    shape: u64,
    capacity: u64,
    pipe_errors: u64,
    local_dropped: u64,
    local_pipe_errors: u64,
    submitted: u64,
};

const Expected = struct {
    total: u64 = 0,
    framing: u64 = 0,
    midframe: u64 = 0,
    shape: u64 = 0,
    capacity: u64 = 0,
    pipe_errors: u64 = 0,
    local_dropped: u64 = 0,
    local_pipe_errors: u64 = 0,
    submitted: u64 = 0,
};

fn snapshot() CounterSnap {
    const local = pipe_reader.getReaderStats();
    return .{
        .total = runtime_state.g_nose_frames_dropped.load(.acquire),
        .framing = runtime_state.g_nose_frames_dropped_framing.load(.acquire),
        .midframe = runtime_state.g_nose_frames_dropped_midframe.load(.acquire),
        .shape = runtime_state.g_nose_frames_dropped_shape.load(.acquire),
        .capacity = runtime_state.g_nose_frames_dropped_capacity.load(.acquire),
        .pipe_errors = runtime_state.g_nose_pipe_errors.load(.acquire),
        .local_dropped = local.frames_dropped,
        .local_pipe_errors = local.pipe_errors,
        .submitted = runtime_state.g_nose_frames_submitted.load(.acquire),
    };
}

fn deltasMatch(before: CounterSnap, now: CounterSnap, exp: Expected) bool {
    return now.total == before.total + exp.total and
        now.framing == before.framing + exp.framing and
        now.midframe == before.midframe + exp.midframe and
        now.shape == before.shape + exp.shape and
        now.capacity == before.capacity + exp.capacity and
        now.pipe_errors == before.pipe_errors + exp.pipe_errors and
        now.local_dropped == before.local_dropped + exp.local_dropped and
        now.local_pipe_errors == before.local_pipe_errors + exp.local_pipe_errors and
        now.submitted == before.submitted + exp.submitted;
}

fn waitForDelta(label: []const u8, before: CounterSnap, exp: Expected) !CounterSnap {
    const deadline = std.time.milliTimestamp() + 5_000;
    var now = snapshot();
    while (std.time.milliTimestamp() < deadline) {
        now = snapshot();
        if (deltasMatch(before, now, exp)) return now;
        std.time.sleep(20 * std.time.ns_per_ms);
    }
    std.debug.print(
        "[INJECT] {s} FAILED: expected total+{d} framing+{d} midframe+{d} shape+{d} capacity+{d} pipe_errors+{d} submitted+{d}; got {d}/{d}/{d}/{d}/{d}/{d}/{d}\n",
        .{
            label,
            exp.total, exp.framing, exp.midframe, exp.shape, exp.capacity, exp.pipe_errors, exp.submitted,
            now.total - before.total, now.framing - before.framing, now.midframe - before.midframe,
            now.shape - before.shape, now.capacity - before.capacity, now.pipe_errors - before.pipe_errors,
            now.submitted - before.submitted,
        },
    );
    return error.CounterDeltaTimeout;
}

fn injectExactDeltaCases() !void {
    // 1. Valid length header, then close before the payload. The reader has
    //    committed to a frame: pipe error + midframe drop, exactly once each.
    var before = snapshot();
    var h = try waitForPipe(5_000);
    try writeU32Le(h, @intCast(canonical.WIRE_PAYLOAD_SIZE));
    win.CloseHandle(h);
    _ = try waitForDelta("close-before-payload", before, .{
        .total = 1,
        .midframe = 1,
        .pipe_errors = 1,
        .local_dropped = 1,
        .local_pipe_errors = 1,
    });
    std.debug.print("[INJECT] close-before-payload OK: +1 midframe, +1 pipe error\n", .{});

    // 2. Absurd length (above MAX_DISCARD_BYTES): resync branch. Framing drop
    //    plus pipe error; no midframe, shape or capacity movement.
    std.time.sleep(50 * std.time.ns_per_ms);
    before = snapshot();
    h = try waitForPipe(5_000);
    try writeU32Le(h, pipe_reader.MAX_DISCARD_BYTES + 1);
    win.CloseHandle(h);
    _ = try waitForDelta("absurd-length", before, .{
        .total = 1,
        .framing = 1,
        .pipe_errors = 1,
        .local_dropped = 1,
        .local_pipe_errors = 1,
    });
    std.debug.print("[INJECT] absurd-length OK: +1 framing, +1 pipe error\n", .{});

    // 3. Invalid-but-drainable length, then a real v1 frame on the same
    //    connection. Framing drop only; the following frame must be accepted.
    std.time.sleep(50 * std.time.ns_per_ms);
    before = snapshot();
    h = try waitForPipe(5_000);
    const bad_len: u32 = @intCast(canonical.WIRE_PAYLOAD_SIZE - 1);
    try writeU32Le(h, bad_len);
    var garbage: [canonical.WIRE_PAYLOAD_SIZE]u8 = [_]u8{0} ** canonical.WIRE_PAYLOAD_SIZE;
    try writeAllPipe(h, garbage[0..bad_len]);
    var frame_buf: [canonical.WIRE_V3_MAX_SIZE]u8 = undefined;
    var ce = canonical.create(.npcap_sensor);
    ce.event_id = 0xF44D;
    const n = try canonical.serializeToBytes(&ce, &frame_buf);
    if (n != canonical.WIRE_PAYLOAD_SIZE) return error.BadFrameSize;
    try writeU32Le(h, @intCast(n));
    try writeAllPipe(h, frame_buf[0..n]);
    _ = try waitForDelta("drain-then-valid", before, .{
        .total = 1,
        .framing = 1,
        .submitted = 1,
        .local_dropped = 1,
    });
    win.CloseHandle(h);
    std.debug.print("[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var seconds: u64 = 10;
    var inject = false;
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.next(); // program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-inject")) {
            inject = true;
        } else if (std.mem.eql(u8, arg, "-seconds")) {
            if (args.next()) |v| seconds = std.fmt.parseInt(u64, v, 10) catch 10;
        }
    }

    // Initialize the fabric with room for events.
    try nose_contract.initFabric(alloc, .{ .capacity_per_priority = 256 });
    defer nose_contract.shutdownFabric(alloc);

    // Blocks on accept; run in a worker thread.
    const reader = try std.Thread.spawn(.{}, pipe_reader.runPipeReaderLoop, .{&stop_flag});

    if (inject) try injectExactDeltaCases();

    const deadline: i128 = std.time.nanoTimestamp() + @as(i128, @intCast(seconds)) * std.time.ns_per_s;

    while (std.time.nanoTimestamp() < deadline) {
        std.time.sleep(200 * std.time.ns_per_ms);
    }

    stop_flag.store(true, .release);
    reader.join();

    const stats = pipe_reader.getReaderStats();
    const fabric_stats = nose_contract.getStats();

    std.debug.print(
        \\
        \\[E2E] reader frames_read={d} submitted={d} rejected={d} dropped={d} pipe_errors={d}
        \\[E2E] fabric pending={d} accepted={d} rejected={d} dropped={d}
        \\
    , .{
        stats.frames_read,
        stats.frames_submitted,
        stats.frames_rejected,
        stats.frames_dropped,
        stats.pipe_errors,
        fabric_stats.pending,
        fabric_stats.accepted,
        fabric_stats.rejected,
        fabric_stats.dropped,
    });

    if (stats.frames_submitted == 0) {
        std.process.exit(1);
    }
}
