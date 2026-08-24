//! windows_capture.zig - AEGIS NIDS WFP Kernel Traffic Reader (Thread 3)
//!
//! M4+BP2: Uses wfp_ioctl.read_events(). If WFP device was already
//! opened by bridge_init.initAll(), skips re-opening.

const std = @import("std");
const bridge_init = @import("bridge_init.zig");
const nids_analyze = @import("nids_analyze.zig");
const wfp_ioctl = @import("wfp_ioctl.zig");

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = address;
    _ = allocator;

    std.debug.print("[SENSOR 2] WFP Capture - connecting to kernel driver...\n", .{});

    // BP2: If bridge_init already opened the WFP device, don't reopen
    var did_open = false;
    if (!wfp_ioctl.isConnected()) {
        if (!wfp_ioctl.init()) {
            std.debug.print("[SENSOR 2] WFP Driver not available. Waiting...\n", .{});
            while (true) {
                if (bridge_init.g_shutdown.load(.seq_cst)) break;
                std.time.sleep(10 * std.time.ns_per_s);
                if (wfp_ioctl.init()) break;
            }
            did_open = true;
        } else {
            did_open = true;
        }
    } else {
        std.debug.print("[SENSOR 2] WFP device already connected via bridge_init\n", .{});
    }
    if (did_open) defer wfp_ioctl.shutdown();

    std.debug.print("[SENSOR 2] Reading events from kernel ring buffer...\n", .{});

    var event_buf: [65536]u8 = undefined;
    var poll_count: u64 = 0;

    while (true) {

        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const bytes_read = wfp_ioctl.read_events(&event_buf);

        if (bytes_read == 0) {
            poll_count += 1;
            if (poll_count % 300 == 0) {
                if (wfp_ioctl.get_stats()) |stats| {
                    std.debug.print("[SENSOR 2] WFP ring: {d}/{} bytes\n", .{
                        stats.currentUsedBytes, stats.capacity
                    });
                }
            }
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        }

        poll_count = 0;
        const header_size = @sizeOf(wfp_ioctl.WfpEventHeader);
        var offset: usize = 0;

        while (offset + header_size <= bytes_read) {
            const header: *align(1) const wfp_ioctl.WfpEventHeader =
                @ptrCast(event_buf[offset..][0..header_size]);

            const ctx = nids_analyze.PacketContext{
                .source_ip = header.source_ip,
                .dest_ip = header.dest_ip,
                .source_port = header.source_port,
                .dest_port = header.dest_port,
                .protocol = header.protocol,
                .direction = header.direction,
                .layer_id = header.layer_id,
                .is_pipe = false,
            };

            const payload_start = offset + header_size;
            const payload_end = @min(@as(usize, bytes_read),
                payload_start + header.payload_length);

            if (payload_end > payload_start) {
                const payload = event_buf[payload_start..payload_end];
                const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |err| blk: {
                    std.log.warn("[WFP SENSOR] Analyze error: {} - fail-open", .{err});
                    break :blk true;
                };

                if (!is_safe) {
                    const a = (ctx.source_ip >> 0) & 0xFF;
                    const b = (ctx.source_ip >> 8) & 0xFF;
                    const c = (ctx.source_ip >> 16) & 0xFF;
                    const d = (ctx.source_ip >> 24) & 0xFF;
                    std.debug.print("\x1b[31;1m[WFP SENSOR] BLOCKED {}.{}.{}.{}:{} rule={d}\x1b[0m\n", .{
                        a, b, c, d, ctx.dest_port, header.rule_id
                    });
                    if (header.severity >= 2) {
                        _ = wfp_ioctl.block_ip(ctx.source_ip);
                    }
                }
            }
            offset = payload_end;
        }
    }
}