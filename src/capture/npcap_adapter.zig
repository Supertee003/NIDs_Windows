// I06 - Npcap Adapter (Real Packet Capture)
// AEGIS NIDS v5.0+ â€” Production Npcap binding for live packet capture
//
// On Windows: links against wpcap.dll/Packet.dll, calls pcap_create/activate/next_ex
// On Linux (test only): stubs out the API so the rest of the code compiles.

const std = @import("std");
const builtin = @import("builtin");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const manifest = @import("../contract/runtime_manifest.zig");

// ============================================================================
// Npcap FFI (only declared; linked by build.zig on Windows)
// ============================================================================
const pcap_t = opaque {};
const pcap_if_t = extern struct {
    next: ?*pcap_if_t,
    name: ?[*:0]const u8,
    description: ?[*:0]const u8,
    addresses: ?*anyopaque,
    flags: u32,
};

extern "c" fn pcap_findalldevs(alldevs: *?*pcap_if_t, errbuf: [*]u8) c_int;
extern "c" fn pcap_freealldevs(alldevs: ?*pcap_if_t) void;
extern "c" fn pcap_create(source: [*:0]const u8, errbuf: [*]u8) ?*pcap_t;
extern "c" fn pcap_activate(p: *pcap_t) c_int;
extern "c" fn pcap_set_snaplen(p: *pcap_t, snaplen: c_int) c_int;
extern "c" fn pcap_set_promisc(p: *pcap_t, promisc: c_int) c_int;
extern "c" fn pcap_set_timeout(p: *pcap_t, to_ms: c_int) c_int;
extern "c" fn pcap_set_buffer_size(p: *pcap_t, buffer_size: c_int) c_int;
extern "c" fn pcap_next_ex(p: *pcap_t, hdr: *pcap_pkthdr, data: *[*]const u8) c_int;
extern "c" fn pcap_close(p: *pcap_t) void;
extern "c" fn pcap_geterr(p: *pcap_t) [*:0]const u8;
extern "c" fn pcap_datalink(p: *pcap_t) c_int;

pub const pcap_pkthdr = extern struct {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
};

pub const DLT_EN10MB: c_int = 1; // Ethernet
pub const DLT_RAW: c_int = 12; // Raw IP
pub const DLT_NULL: c_int = 0;

// ============================================================================
// CaptureConfig
// ============================================================================
pub const CaptureConfig = struct {
    device: [256]u8 = [_]u8{0} ** 256,
    snaplen: u32 = 65535,
    promiscuous: bool = true,
    read_timeout_ms: u32 = 100,
    buffer_size: u32 = 16 * 1024 * 1024, // 16 MiB kernel ring
};

// ============================================================================
// PacketCallback â€” invoked per packet
// ============================================================================
pub const PacketCallback = *const fn (ctx: *anyopaque, hdr: *const pcap_pkthdr, data: []const u8) void;

// ============================================================================
// NpcapAdapter â€” live capture handle
// ============================================================================
pub const NpcapAdapter = struct {
    handle: ?*pcap_t = null,
    device: [256]u8 = [_]u8{0} ** 256,
    datalink: c_int = DLT_EN10MB,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    packets_captured: u64 = 0,
    packets_dropped: u64 = 0,

    pub fn open(cfg: CaptureConfig) !NpcapAdapter {
        var ad = NpcapAdapter{ .device = cfg.device };
        if (builtin.os.tag != .windows) {
            // Non-Windows: cannot open real pcap (Npcap is Windows-only)
            return error.UnsupportedPlatform;
        }
        var errbuf: [256]u8 = undefined;
        @memset(&errbuf, 0);
        const dev_z = std.mem.sliceTo(&cfg.device, 0);
        const handle = pcap_create(dev_z.ptr, &errbuf) orelse {
            diag.err("pcap_create failed: {s}", .{std.mem.sliceTo(&errbuf, 0)});
            return error.PcapCreateFailed;
        };
        _ = pcap_set_snaplen(handle, @intCast(cfg.snaplen));
        _ = pcap_set_promisc(handle, if (cfg.promiscuous) 1 else 0);
        _ = pcap_set_timeout(handle, @intCast(cfg.read_timeout_ms));
        _ = pcap_set_buffer_size(handle, @intCast(cfg.buffer_size));
        const rc = pcap_activate(handle);
        if (rc < 0) {
            diag.err("pcap_activate failed: rc={d}", .{rc});
            pcap_close(handle);
            return error.PcapActivateFailed;
        }
        ad.handle = handle;
        ad.datalink = pcap_datalink(handle);
        @memcpy(&ad.device, &cfg.device);
        diag.info("NpcapAdapter opened on {s} (datalink={d})", .{ dev_z, ad.datalink });
        return ad;
    }

    pub fn close(self: *NpcapAdapter) void {
        self.running.store(false, .release);
        if (self.handle) |h| {
            pcap_close(h);
            self.handle = null;
        }
    }

    pub fn run(self: *NpcapAdapter, ctx: *anyopaque, cb: PacketCallback) !void {
        const h = self.handle orelse return error.NotOpen;
        self.running.store(true, .release);
        diag.info("capture loop starting on {s}", .{std.mem.sliceTo(&self.device, 0)});
        while (self.running.load(.acquire)) {
            var hdr: pcap_pkthdr = undefined;
            var data_ptr: [*]const u8 = undefined;
            const rc = pcap_next_ex(h, &hdr, &data_ptr);
            if (rc == 0) continue; // timeout, no packet
            if (rc < 0) {
                diag.err("pcap_next_ex returned {d}", .{rc});
                self.packets_dropped += 1;
                break;
            }
            const slice = data_ptr[0..hdr.caplen];
            self.packets_captured += 1;
            diag.metrics.packets_captured.inc();
            cb(ctx, &hdr, slice);
        }
    }

    pub fn stop(self: *NpcapAdapter) void {
        self.running.store(false, .release);
    }

    pub fn listDevices(allocator: std.mem.Allocator) ![][]u8 {
        if (builtin.os.tag != .windows) {
            return &[_][]u8{};
        }
        var errbuf: [256]u8 = undefined;
        @memset(&errbuf, 0);
        var alldevs: ?*pcap_if_t = null;
        if (pcap_findalldevs(&alldevs, &errbuf) < 0) {
            return error.PcapFindalldevsFailed;
        }
        defer pcap_freealldevs(alldevs);
        var list = std.ArrayList([]u8).init(allocator);
        var cur = alldevs;
        while (cur) |d| : (cur = d.next) {
            if (d.name) |n| {
                const name = std.mem.span(n);
                try list.append(try allocator.dupe(u8, name));
            }
        }
        return list.toOwnedSlice();
    }
};

// ============================================================================
// Linux stub for unit testing the non-capture paths
// ============================================================================
pub const StubAdapter = struct {
    packets: []const []const u8 = &[_][]const u8{},
    pos: usize = 0,

    pub fn run(self: *StubAdapter, ctx: *anyopaque, cb: PacketCallback) !void {
        var hdr = pcap_pkthdr{ .ts_sec = 0, .ts_usec = 0, .caplen = 0, .len = 0 };
        while (self.pos < self.packets.len) : (self.pos += 1) {
            const p = self.packets[self.pos];
            hdr.caplen = @intCast(p.len);
            hdr.len = @intCast(p.len);
            hdr.ts_sec += 1;
            cb(ctx, &hdr, p);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================
test "StubAdapter emits all packets" {
    const ctx_calls: u32 = 0;
    const cb: PacketCallback = struct {
        fn cb_impl(_: *anyopaque, _: *const pcap_pkthdr, _: []const u8) void {
            // counter is captured by closure-like pattern via global
            _ = cb_impl;
        }
    }.cb_impl;
    _ = cb;
    var ad = StubAdapter{ .packets = &[_][]const u8{ "a", "bb", "ccc" } };
    var dummy: u8 = 0;
    try ad.run(@ptrCast(&dummy), struct {
        fn cb_impl(_: *anyopaque, _: *const pcap_pkthdr, _: []const u8) void {}
    }.cb_impl);
    try std.testing.expectEqual(@as(usize, 3), ad.pos);
    _ = ctx_calls;
}

test "CaptureConfig defaults are sane" {
    const cfg = CaptureConfig{};
    try std.testing.expect(cfg.snaplen >= 1500);
    try std.testing.expect(cfg.buffer_size >= 1024 * 1024);
}
