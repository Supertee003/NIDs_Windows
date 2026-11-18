//! windows_capture.zig - AEGIS NIDS WFP Kernel Traffic Reader (Thread 3)
//!
//! M4+BP2: Uses rust_pep.read_events(). If WFP device was already
//! opened by bridge_init.initAll(), skips re-opening.

const std = @import("std");
const bridge_init = @import("../core/bridge_init.zig");
const nids_analyze = @import("../core/nids_analyze.zig");
const rust_pep = @import("../core/rust_pep.zig");
// Phase 28: Blueprint Nose Contract for event submission
const nose = @import("nose_contract.zig");
const l7 = @import("l7_classifier.zig");

const WFP_EVENT_BUFFER_SIZE: usize = 65536;
// BP-L13: Stats poll interval (iterations between stats prints)
const WFP_STATS_POLL_INTERVAL: u64 = 300;

/// P-05: Validate that a source IP is safe to block via WFP.
/// Prevents attacker from spoofing source IP to use NIDS as L3 DoS amplifier
/// against arbitrary LAN hosts (including localhost, broadcast, multicast).
/// Returns true only for routable unicast IPs (not loopback/broadcast/multicast).
fn isBlockableSourceIp(source_ip_net: u32) bool {
    // Convert from network byte order (big-endian) to host byte order
    const ip = std.mem.bigToNative(u32, source_ip_net);
    const a = (ip >> 24) & 0xFF;
    const b = (ip >> 16) & 0xFF;

    // 0.0.0.0/8 - "This host" (don't block)
    if (a == 0) return false;
    // 127.0.0.0/8 - loopback (don't block - would break local services)
    if (a == 127) return false;
    // 169.254.0.0/16 - link-local (don't block - DHCP/ARP context)
    if (a == 169 and b == 254) return false;
    // 224.0.0.0/4 - multicast (don't block)
    if (a >= 224 and a <= 239) return false;
    // 240.0.0.0/4 - reserved (don't block)
    if (a >= 240) return false;
    // 255.255.255.255 - broadcast (don't block)
    if (ip == 0xFFFFFFFF) return false;

    // Only block routable unicast IPs (RFC1918 + public)
    return true;
}

fn beU32(octets: [4]u8) u32 {
    // Test helper: build the memory-layout u32 the driver ring and the
    // packet path hand us (raw network-order bytes in memory).
    return std.mem.readInt(u32, &octets, .little);
}

test "ipv4OctetsFromMemoryLayout preserves wire order (BYTE-ORDER-096)" {
    // 127.0.0.1 on the wire is bytes [7F,00,00,01]; as a u32 on a
    // little-endian host that reads 0x0100007F. Octets must come out in
    // wire order regardless of what the numeric value looks like.
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, ipv4OctetsFromMemoryLayout(beU32(.{ 0x7F, 0x00, 0x00, 0x01 })));
    try std.testing.expectEqual([4]u8{ 224, 0, 0, 1 }, ipv4OctetsFromMemoryLayout(beU32(.{ 0xE0, 0x00, 0x00, 0x01 })));
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 5 }, ipv4OctetsFromMemoryLayout(beU32(.{ 0x0A, 0x00, 0x00, 0x05 })));
}

test "isBlockableSourceIp refuses non-routable sources (P-05)" {
    // Non-routable: this-host, loopback, link-local, multicast, reserved,
    // directed broadcast. Addresses are deliberately non-palindromic so a
    // byte-order regression cannot hide behind symmetric values.
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 0, 0, 0, 0 })));
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 127, 0, 0, 1 })));
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 169, 254, 10, 20 })));
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 224, 0, 0, 1 })));
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 240, 0, 0, 1 })));
    try std.testing.expect(!isBlockableSourceIp(beU32(.{ 255, 255, 255, 255 })));
    // Routable unicast (RFC1918 + public) stays blockable.
    try std.testing.expect(isBlockableSourceIp(beU32(.{ 10, 0, 0, 5 })));
    try std.testing.expect(isBlockableSourceIp(beU32(.{ 192, 168, 1, 1 })));
    try std.testing.expect(isBlockableSourceIp(beU32(.{ 8, 8, 8, 8 })));
}

/// Octets of an IPv4 address held as raw network-order bytes in memory
/// (see drivers/wfp_callout/aegis_wfp.h: `UINT32 source_ip` is documented
/// network byte order, i.e. bytes [a,b,c,d] in memory). On little-endian
/// hosts the u32 VALUE looks reversed (127.0.0.1 reads as 0x0100007F) —
/// do NOT reorder the value itself: isBlockableSourceIp converts with
/// bigToNative, the PEP read-back compares the same representation, and
/// the packet_callback path bit-casts wire bytes identically. This helper
/// exists so log formatting never drifts from that convention again.
fn ipv4OctetsFromMemoryLayout(source_ip_net: u32) [4]u8 {
    return .{
        @intCast((source_ip_net >> 0) & 0xFF),
        @intCast((source_ip_net >> 8) & 0xFF),
        @intCast((source_ip_net >> 16) & 0xFF),
        @intCast((source_ip_net >> 24) & 0xFF),
    };
}

/// Thread 3 entry point: WFP Kernel Traffic Sensor.
///
/// Reads network events from the AEGIS WFP kernel driver ring buffer via
/// DeviceIoControl (IOCTL_AEGIS_READ_EVENTS). Each event is parsed as
/// WfpEventHeader + payload, then forwarded to nids_analyze.inspect_packet().
///
/// If the WFP device is not available, retries every 10 seconds until the
/// driver loads. If a packet matches a high-severity rule (severity >= 2),
/// calls rust_pep.block_ip() to install a kernel WFP block filter.
///
/// Parameters `allocator` and `address` are currently unused (reserved for
/// future filtering features).
///
/// Loops forever until bridge_init.g_shutdown is set by CTRL+C handler.
pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = address;
    _ = allocator;

    std.log.info("[SENSOR 2] WFP Capture - connecting to kernel driver", .{});
    std.debug.print("[SENSOR 2] WFP Capture - connecting to kernel driver...\n", .{});

    // BP2: If bridge_init already opened the WFP device, don't reopen
    var did_open = false;
    if (!rust_pep.wfpIsConnected()) {
        if (!rust_pep.wfpInit()) {
            std.log.warn("[SENSOR 2] WFP Driver not available, retrying every 10s", .{});
            std.debug.print("[SENSOR 2] WFP Driver not available. Waiting...\n", .{});
            while (true) {
                if (bridge_init.g_shutdown.load(.seq_cst)) break;
                std.time.sleep(10 * std.time.ns_per_s);
                if (rust_pep.wfpInit()) break;
            }
            did_open = true;
        } else {
            did_open = true;
        }
    } else {
        std.log.info("[SENSOR 2] WFP device already connected via bridge_init", .{});
        std.debug.print("[SENSOR 2] WFP device already connected via bridge_init\n", .{});
    }
    if (did_open) {
        defer rust_pep.wfpShutdown();
    }

    std.log.info("[SENSOR 2] Reading events from kernel ring buffer", .{});
    std.debug.print("[SENSOR 2] Reading events from kernel ring buffer...\n", .{});

    var event_buf: [WFP_EVENT_BUFFER_SIZE]u8 = undefined;
    var poll_count: u64 = 0;

    while (true) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const bytes_read = rust_pep.read_events(&event_buf);

        if (bytes_read == 0) {
            poll_count += 1;
            if (poll_count % WFP_STATS_POLL_INTERVAL == 0) {
                if (rust_pep.get_stats()) |stats| {
                    std.log.info("[SENSOR 2] WFP ring: {d}/{d} bytes", .{ stats.currentUsedBytes, stats.capacity });
                    std.debug.print("[SENSOR 2] WFP ring: {d}/{d} bytes\n", .{ stats.currentUsedBytes, stats.capacity });
                }
            }
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        }

        poll_count = 0;
        const header_size = @sizeOf(rust_pep.WfpEventHeader);
        var offset: usize = 0;

        while (offset + header_size <= bytes_read) {
            const header: *align(1) const rust_pep.WfpEventHeader =
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
            const payload_end = @min(@as(usize, bytes_read), payload_start + header.payload_length);

            if (payload_end > payload_start) {
                const payload = event_buf[payload_start..payload_end];

                // Phase 28: Submit event to Event Fabric (Nose Contract)
                {
                    var sensor_event = nose.createEvent(.wfp_sensor);
                    sensor_event.event_type = .forward;
                    sensor_event.source_ip = ctx.source_ip;
                    sensor_event.source_port = ctx.source_port;
                    sensor_event.payload_length = @intCast(payload.len);
                    sensor_event.protocol = ctx.protocol;
                    sensor_event.layer_id = ctx.layer_id;
                    // L7 metadata is advisory only and uses the frozen v1
                    // context_flags extension area. Unknown remains zero.
                    const l7_class = l7.classify(payload, ctx.dest_port, ctx.protocol);
                    sensor_event.context_flags |= l7_class.context_flag;
                    sensor_event.timestamp_ms = @intCast(std.time.milliTimestamp());
                    const submit_result = nose.submitEvent(sensor_event);
                    if (submit_result != .accepted) {
                        std.log.warn("[WFP SENSOR] Event Fabric submit failed: {s}", .{@tagName(submit_result)});
                    }
                }

                const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |err| blk: {
                    std.log.warn("[WFP SENSOR] Analyze error: {any} - fail-open", .{err});
                    break :blk true;
                };

                if (!is_safe) {
                    // Human-readable octets in wire order (memory layout —
                    // see ipv4OctetsFromMemoryLayout; the raw u32 value
                    // looks byte-reversed on little-endian hosts).
                    const oct = ipv4OctetsFromMemoryLayout(ctx.source_ip);
                    const a = oct[0];
                    const b = oct[1];
                    const c = oct[2];
                    const d = oct[3];
                    // BP-L13: BLOCKED alert visible in release builds via std.log
                    std.log.warn("[BLOCK] WFP SENSOR {d}.{d}.{d}.{d}:{any} rule={d} (BLOCKED)", .{ a, b, c, d, ctx.dest_port, header.rule_id });
                    std.debug.print("\x1b[31;1m[WFP SENSOR] BLOCKED {d}.{d}.{d}.{d}:{any} rule={d}\x1b[0m\n", .{ a, b, c, d, ctx.dest_port, header.rule_id });
                    // P-05 CRITICAL FIX: Validate source IP before blocking
                    // Prevents attacker from spoofing source to use NIDS as DoS amplifier
                    if (header.severity >= 2) {
                        if (isBlockableSourceIp(ctx.source_ip)) {
                            _ = rust_pep.block_ip(ctx.source_ip);
                        } else {
                            std.log.warn("[WFP] Refusing to block non-routable source IP: {d}.{d}.{d}.{d}", .{ a, b, c, d });
                        }
                    }
                }
            }
            offset = payload_end;
        }
    }
}
