const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) @compileError("windows_capture requires Windows target — uses WFP kernel driver");
}

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = allocator;
    _ = address;

    std.debug.print("[SENSOR 2] Kernel WFP Capture Ready - Waiting for real traffic...\n", .{});
    const wfp_device_name = "\\\\.\\AegisWfpDevice";

    const wfp_file = std.fs.openFileAbsolute(wfp_device_name, .{}) catch |err| {
        std.debug.print("[!] WFP Driver not found (Error: {}). Pausing sensor...\n", .{err});
        while (true) {
            std.time.sleep(10 * std.time.ns_per_s);
        }
        return;
    };
    defer wfp_file.close();

    const reader = wfp_file.reader();
    var buffer: [8192]u8 = undefined;

    while (true) {
        const bytes_read = reader.read(&buffer) catch 0;
        if (bytes_read > 0) {
            const payload = buffer[0..bytes_read];

            // ส่ง Payload ดิบเข้าไปให้ระบบตรวจสอบ (is_pipe = false เพราะมาจาก WFP/Network)
            const is_safe = nids_analyze.inspect_packet(payload, false) catch |err| {
                std.debug.print("\x1b[31m[!] Analyze Error: {}\x1b[0m\n", .{err});
                return; // ออกจากลูปนี้ชั่วคราว
            };

                // สร้าง PacketContext จาก 5-tuple ที่ได้จาก kernel driver
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

                // Payload อยู่หลัง EventHeader
                const payload_start = @sizeOf(nids_analyze.WfpEventHeader);
                const payload_end = @min(bytes_read, payload_start + @as(usize, header.payload_length));
                if (payload_end > payload_start) {
                    const payload = buffer[payload_start..payload_end];

                    const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |err| {
                        std.debug.print("\x1b[31m[!] Analyze Error: {}\x1b[0m\n", .{err});
                        return;
                    };

                    if (!is_safe) {
                        std.debug.print("\x1b[31;1m[WFP SENSOR] 🚨 Dropped Malicious Network Packet! src_ip=0x{x}\x1b[0m\n", .{header.source_ip});
                    }
                }
            } else {
                // ข้อมูลน้อยกว่า EventHeader — ส่งเป็น raw payload แบบเดิม
                const payload = buffer[0..bytes_read];
                const ctx = nids_analyze.PacketContext{
                    .protocol = 6,  // assume TCP
                    .is_pipe = false,
                };
                const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |err| {
                    std.debug.print("\x1b[31m[!] Analyze Error: {}\x1b[0m\n", .{err});
                    return;
                };
                if (!is_safe) {
                    std.debug.print("\x1b[31;1m[WFP SENSOR] 🚨 Dropped Malicious Network Packet!\x1b[0m\n", .{});
                }
            }
        } else {
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}
