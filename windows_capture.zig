const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = allocator;
    _ = address;

    std.debug.print("[SENSOR 2] Kernel WFP Capture Ready - Waiting for real traffic...\n", .{});
    const wfp_device_name = "\\\\.\\AegisWfpDevice";

    const wfp_file = std.fs.openFileAbsolute(wfp_device_name, .{ .mode = .read_only }) catch |err| {
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

            if (!is_safe) {
                std.debug.print("\\x1b[31;1m[WFP SENSOR] 🚨 Dropped Malicious Network Packet!\\x1b[0m\\n", .{});
            }
        } else {
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}
