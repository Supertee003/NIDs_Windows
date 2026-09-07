// nose_pipe_e2e_cli.zig - T2 E2E harness: named-pipe server + fabric sink
//
// USAGE:
//   zig run core/nose_pipe_e2e_cli.zig -- [-seconds N]
//
// Creates \\.\pipe\aegis_nose, spawns the reader loop, waits N seconds
// (default 10), then prints fabric + reader stats and exits 1 if no
// event made it into the fabric (so CI/E2E scripts can gate on success).
//
// Runs alongside:  cd nose && go run . -capture

const std = @import("std");
const pipe_reader = @import("nose_pipe_reader.zig");
const nose_contract = @import("nose_contract.zig");

var stop_flag = std.atomic.Value(bool).init(false);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var seconds: u64 = 10;
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.next(); // program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-seconds")) {
            if (args.next()) |v| seconds = std.fmt.parseInt(u64, v, 10) catch 10;
        }
    }

    // Initialize the fabric with room for events.
    try nose_contract.initFabric(alloc, .{ .capacity_per_priority = 256 });
    defer nose_contract.shutdownFabric(alloc);

    // Blocks on accept; run in a worker thread.
    const reader = try std.Thread.spawn(.{}, pipe_reader.runPipeReaderLoop, .{&stop_flag});

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