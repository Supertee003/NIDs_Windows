// npcap_test_live.zig - AEGIS Phase 32 live capture verification tool
//
// Verifies that Npcap real traffic capture works on this machine:
//   1. Loads the capture library (wpcap.dll / libpcap.so) dynamically
//   2. Lists all capture devices with IP addresses
//   3. Opens the selected device, captures packets, prints canonical events
//
// Usage:
//   npcap_test_live.exe                      - list devices only
//   npcap_test_live.exe <device_index>       - capture 20 packets on device
//   npcap_test_live.exe <device_index> <N>   - capture up to N packets
//   npcap_test_live.exe <device_index> <N> "<bpf>" - with BPF filter
//
// Build:
//   zig build-exe npcap_test_live.zig -lc
//
// Notes:
//   - Windows: run as Administrator (Npcap admin-only mode restricts capture)
//   - Capture is PASSIVE - nothing is transmitted by this tool

const std = @import("std");
const npcap = @import("npcap_capture.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    std.debug.print("AEGIS NIDS - Phase 32 Npcap Live Capture Test\n", .{});
    std.debug.print("==============================================\n\n", .{});

    // ---- Step 1: load capture library ----
    var loader = npcap.NpcapLoader.load();
    defer loader.deinit();

    if (!loader.available) {
        std.debug.print("[FAIL] Capture library not available (error={s})\n", .{
            loader.loadErrorName(),
        });
        std.debug.print("       Install Npcap from https://npcap.com/\n", .{});
        std.debug.print("       (check 'Install Npcap in WinPcap API-compatible Mode')\n", .{});
        return;
    }
    std.debug.print("[OK]   Capture library: {s}\n\n", .{loader.loadedPath()});

    // ---- Step 2: enumerate devices ----
    var devices: [npcap.MAX_DEVICES]npcap.DeviceInfo = undefined;
    const count = npcap.enumerateDevices(&loader, &devices) catch |err| {
        std.debug.print("[FAIL] Device enumeration failed: {s}\n", .{@errorName(err)});
        return;
    };

    std.debug.print("[OK]   {d} capture device(s):\n", .{count});
    for (devices[0..count], 0..) |*dev, i| {
        var ip_buf: [16]u8 = undefined;
        const ip_str = if (dev.has_ipv4) npcap.formatIp(&ip_buf, dev.ipv4) else "-";
        const desc = if (dev.desc_len > 0) dev.description() else "";
        const virt = isVirtualAdapter(desc);
        std.debug.print("       [{d}] {s}\n", .{ i, dev.name() });
        std.debug.print("           desc=\"{s}\" ip={s} loopback={} up={}{s}\n\n", .{
            if (dev.desc_len > 0) dev.description() else "-",
            ip_str,
            dev.is_loopback,
            dev.is_up,
            if (virt) "  [virtual/no-traffic?]" else "",
        });
    }

    // Recommend the best real adapter for capture
    const auto_idx = pickAutoDevice(devices[0..count]);
    if (auto_idx) |ai| {
        std.debug.print("Recommendation: .\\npcap_test_live.exe auto 30   (picks [{d}] {s})\n\n", .{
            ai, devices[ai].description(),
        });
    }

    if (args.len < 2) {
        std.debug.print("Usage: npcap_test_live.exe auto [max_packets] [\"bpf filter\"]\n", .{});
        std.debug.print("       npcap_test_live.exe <device_index> [max_packets] [\"bpf filter\"]\n", .{});
        std.debug.print("Example: npcap_test_live.exe auto 50 \"tcp port 80\"\n", .{});
        return;
    }

    // ---- Step 3: resolve target device (auto / index / name) ----
    const target = args[1];
    var chosen_idx: ?usize = null;
    if (std.ascii.eqlIgnoreCase(target, "auto")) {
        chosen_idx = auto_idx;
        if (chosen_idx == null) {
            std.debug.print("[FAIL] auto: no suitable capture device found\n", .{});
            return;
        }
        std.debug.print("[AUTO] Picked [{d}] {s}\n", .{
            chosen_idx.?, devices[chosen_idx.?].description(),
        });
    } else {
        const idx = std.fmt.parseInt(usize, target, 10) catch null;
        if (idx) |i| {
            if (i < count) chosen_idx = i;
        } else {
            for (devices[0..count], 0..) |*dev, i| {
                if (std.mem.eql(u8, dev.name(), target)) {
                    chosen_idx = i;
                    break;
                }
            }
        }
    }
    if (chosen_idx == null) {
        std.debug.print("[FAIL] Device not found: {s}\n", .{target});
        return;
    }
    var dev = devices[chosen_idx.?];

    // ---- Step 4: open sensor ----
    var sensor = npcap.NpcapSensor.init(allocator, &loader, dev.name()) catch |err| {
        std.debug.print("[FAIL] Sensor init failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer sensor.deinit();

    sensor.open(npcap.SNAPLEN, true, 500) catch |err| {
        std.debug.print("[FAIL] open({s}) failed: {s}\n", .{ dev.name(), @errorName(err) });
        std.debug.print("       Windows: try running as Administrator\n", .{});
        return;
    };
    sensor.setAdapterIp(if (dev.has_ipv4) dev.ipv4 else null);
    std.debug.print("[OK]   Sensor open (dlt={d})\n", .{sensor.link_type});

    // ---- Step 5: optional BPF filter ----
    if (args.len >= 4) {
        sensor.setBpfFilter(args[3]) catch |err| {
            std.debug.print("[WARN] BPF filter rejected: {s}\n", .{@errorName(err)});
        };
    }

    // ---- Step 6: capture loop ----
    var max_packets: usize = 20;
    if (args.len >= 3) {
        max_packets = std.fmt.parseInt(usize, args[2], 10) catch 20;
    }

    const frame_buf = try allocator.alloc(u8, npcap.MAX_FRAME_SIZE);
    defer allocator.free(frame_buf);

    var events: [16]npcap.CanonicalEvent = undefined;
    var printed: usize = 0;
    const deadline_ms = std.time.milliTimestamp() + 30_000; // 30s hard cap

    std.debug.print("\nCapturing up to {d} packets (30s timeout)...\n\n", .{max_packets});

    while (printed < max_packets and std.time.milliTimestamp() < deadline_ms) {
        const n = sensor.pollEvents(events[0..], frame_buf) catch |err| {
            std.debug.print("[FAIL] pollEvents error: {s}\n", .{@errorName(err)});
            break;
        };
        for (events[0..n]) |ev| {
            printed += 1;
            printEvent(ev, printed);
        }
    }

    // ---- Step 7: stats ----
    const stats = sensor.getStats();
    std.debug.print("\n--- Capture statistics ---\n", .{});
    std.debug.print("packets_seen      {d}\n", .{stats.packets_seen});
    std.debug.print("packets_captured  {d}\n", .{stats.packets_captured});
    std.debug.print("packets_parsed    {d} (rate {d:.1}%)\n", .{ stats.packets_parsed, stats.parseRate() });
    std.debug.print("  tcp             {d}\n", .{stats.tcp_packets});
    std.debug.print("  udp             {d}\n", .{stats.udp_packets});
    std.debug.print("  icmp            {d}\n", .{stats.icmp_packets});
    std.debug.print("  other           {d}\n", .{stats.other_packets});
    std.debug.print("malformed         {d}\n", .{stats.packets_malformed});
    std.debug.print("timeouts          {d}\n", .{stats.timeouts});
    std.debug.print("events_emitted    {d}\n", .{stats.events_emitted});

    if (printed == 0) {
        std.debug.print("\n[INFO] No packets captured. Generate traffic (browse the web) or\n", .{});
        std.debug.print("       check that the selected device carries traffic.\n", .{});
    }
}

fn protoName(protocol: u8) []const u8 {
    return switch (protocol) {
        npcap.PROTO_TCP => "TCP",
        npcap.PROTO_UDP => "UDP",
        npcap.PROTO_ICMP => "ICMP",
        else => "OTHER",
    };
}

fn dirName(direction: npcap.CanonicalEvent.Direction) []const u8 {
    return switch (direction) {
        .inbound => "in ",
        .outbound => "out",
        .unknown => "?? ",
    };
}

fn flagString(flags: u8, buf: *[6]u8) []const u8 {
    const chars = [_]u8{ 'F', 'S', 'R', 'P', 'A', 'U' };
    const masks = [_]u8{
        npcap.TCP_FLAG_FIN, npcap.TCP_FLAG_SYN, npcap.TCP_FLAG_RST,
        npcap.TCP_FLAG_PSH, npcap.TCP_FLAG_ACK, npcap.TCP_FLAG_URG,
    };
    var len: usize = 0;
    for (masks, 0..) |m, i| {
        if (flags & m != 0) {
            buf[len] = chars[i];
            len += 1;
        }
    }
    if (len == 0) {
        buf[0] = '-';
        len = 1;
    }
    return buf[0..len];
}

fn isVirtualAdapter(desc: []const u8) bool {
    const keywords = [_][]const u8{
        "WAN Miniport", "Virtual",     "VPN",        "Bluetooth",
        "Wi-Fi Direct", "Loopback",    "TeamViewer", "Hyper-V",
        "VMware",       "TAP",         "Tunnel",     "QoS",
    };
    for (keywords) |kw| {
        if (std.ascii.indexOfIgnoreCase(desc, kw) != null) return true;
    }
    return false;
}

fn isApipa(ip: [4]u8) bool {
    return ip[0] == 169 and ip[1] == 254;
}

/// Pick the best capture device automatically:
/// 1st choice: physical adapter (not virtual) with a real routable IPv4
/// 2nd choice: virtual adapter that still carries a real IPv4
fn pickAutoDevice(devices: []npcap.DeviceInfo) ?usize {
    var fallback: ?usize = null;
    for (devices, 0..) |*dev, i| {
        if (!dev.is_up or !dev.has_ipv4 or dev.is_loopback) continue;
        if (isApipa(dev.ipv4)) continue; // 169.254.x.x = disconnected/link-local
        if (!isVirtualAdapter(dev.description())) return i;
        if (fallback == null) fallback = i;
    }
    return fallback;
}

fn printEvent(ev: npcap.CanonicalEvent, num: usize) void {
    var s_ip_buf: [16]u8 = undefined;
    var d_ip_buf: [16]u8 = undefined;
    var flags_buf: [6]u8 = undefined;

    const s_ip = npcap.formatIp(&s_ip_buf, ev.src_ip);
    const d_ip = npcap.formatIp(&d_ip_buf, ev.dst_ip);

    switch (ev.event_type) {
        .packet_tcp => {
            const fl = flagString(ev.tcp_flags, &flags_buf);
            std.debug.print("#{d:<4} {s} {s}:{d} -> {s}:{d} [{s}] len={d}\n", .{
                num, protoName(ev.protocol), s_ip,  ev.src_port,
                d_ip, ev.dst_port,            fl,   ev.payload_len,
            });
        },
        .packet_udp => {
            std.debug.print("#{d:<4} {s} {s}:{d} -> {s}:{d} len={d}\n", .{
                num, protoName(ev.protocol), s_ip, ev.src_port,
                d_ip, ev.dst_port,           ev.payload_len,
            });
        },
        .packet_icmp => {
            std.debug.print("#{d:<4} {s} {s} -> {s} len={d}\n", .{
                num, protoName(ev.protocol), s_ip, d_ip, ev.payload_len,
            });
        },
        .packet_other => {
            var s_mac_buf: [18]u8 = undefined;
            var d_mac_buf: [18]u8 = undefined;
            const s_mac = npcap.formatMac(&s_mac_buf, ev.src_mac);
            const d_mac = npcap.formatMac(&d_mac_buf, ev.dst_mac);
            std.debug.print("#{d:<4} L2  {s} -> {s} ethertype=0x{x} len={d}\n", .{
                num, s_mac, d_mac, ev.protocol, ev.payload_len,
            });
        },
    }
    _ = dirName(ev.direction); // direction available for pipeline integration
}
