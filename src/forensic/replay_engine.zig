// I21 - Replay Engine (PCAP Replay with Deterministic Timing)
// AEGIS NIDS v5.0+ â€” Offline PCAP replay that feeds the pipeline at the
// original packet inter-arrival times.
//
// Use cases:
//   - Rule regression testing
//   - Throughput benchmarking
//   - Forensic reconstruction ("what would AEGIS have seen on this traffic?")

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

// ============================================================================
// PCAP file format (libpcap classic)
// ============================================================================
pub const PCAP_MAGIC_LE: u32 = 0xA1B2C3D4;
pub const PCAP_MAGIC_BE: u32 = 0xD4C3B2A1;

pub const PcapGlobalHeader = extern struct {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    linktype: u32,
};

pub const PcapRecordHeader = extern struct {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
};

// ============================================================================
// ReplayEngine
// ============================================================================
pub const ReplayConfig = struct {
    speed_multiplier: f64 = 1.0, // 1.0 = real-time, 2.0 = 2x faster
    loop_count: u32 = 1,
    real_time: bool = true, // false = as-fast-as-possible (benchmark mode)
    max_packets: u64 = 0, // 0 = unlimited
};

pub const ReplayStats = struct {
    packets_sent: u64 = 0,
    bytes_sent: u64 = 0,
    start_ns: i128 = 0,
    end_ns: i128 = 0,
    first_pkt_ts_ns: i128 = 0,
    last_pkt_ts_ns: i128 = 0,
    skipped: u64 = 0,
};

pub const ReplayEngine = struct {
    config: ReplayConfig,
    stats: ReplayStats = .{},
    packet_cb: ?*const fn (ctx: *anyopaque, ts_ns: i128, data: []const u8) void = null,
    ctx: *anyopaque,

    pub fn init(config: ReplayConfig, ctx: *anyopaque, cb: *const fn (ctx: *anyopaque, ts_ns: i128, data: []const u8) void) ReplayEngine {
        return .{ .config = config, .packet_cb = cb, .ctx = ctx };
    }

    pub fn replayFile(self: *ReplayEngine, path: []const u8) !ReplayStats {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        var hdr_buf: [@sizeOf(PcapGlobalHeader)]u8 = undefined;
        const n = try file.read(&hdr_buf);
        if (n < @sizeOf(PcapGlobalHeader)) return error.TruncatedPcapHeader;
        const gh: *const PcapGlobalHeader = @ptrCast(@alignCast(&hdr_buf));
        const magic_le = std.mem.readInt(u32, std.mem.asBytes(&gh.magic), .little);
        const is_le = (magic_le == PCAP_MAGIC_LE);
        if (!is_le) {
            // Check BE
            const magic_be = std.mem.readInt(u32, std.mem.asBytes(&gh.magic), .big);
            if (magic_be != PCAP_MAGIC_LE) return error.UnknownPcapMagic;
        }
        // Read packets
        self.stats.start_ns = std.time.nanoTimestamp();
        var first_pkt_seen = false;
        var first_pkt_wall_ns: i128 = 0;
        var first_pkt_pcap_ns: i128 = 0;
        var loop_i: u32 = 0;
        while (loop_i < self.config.loop_count) : (loop_i += 1) {
            try file.seekTo(@sizeOf(PcapGlobalHeader));
            while (true) {
                var rec_buf: [@sizeOf(PcapRecordHeader)]u8 = undefined;
                const rn = try file.read(&rec_buf);
                if (rn == 0) break;
                if (rn < @sizeOf(PcapRecordHeader)) return error.TruncatedRecord;
                const rh: *const PcapRecordHeader = @ptrCast(@alignCast(&rec_buf));
                const ts_sec = std.mem.readInt(u32, std.mem.asBytes(&rh.ts_sec), if (is_le) .little else .big);
                const ts_usec = std.mem.readInt(u32, std.mem.asBytes(&rh.ts_usec), if (is_le) .little else .big);
                const incl_len = std.mem.readInt(u32, std.mem.asBytes(&rh.incl_len), if (is_le) .little else .big);
                _ = std.mem.readInt(u32, std.mem.asBytes(&rh.orig_len), if (is_le) .little else .big);
                if (incl_len == 0 or incl_len > 1 << 24) {
                    self.stats.skipped += 1;
                    continue;
                }
                const data = try self.allocator().alloc(u8, incl_len);
                defer self.allocator().free(data);
                const dn = try file.read(data);
                if (dn < incl_len) return error.TruncatedPacket;
                const pkt_ts_ns = @as(i128, ts_sec) * std.time.ns_per_s + @as(i128, ts_usec) * 1000;
                if (!first_pkt_seen) {
                    first_pkt_seen = true;
                    self.stats.first_pkt_ts_ns = pkt_ts_ns;
                    first_pkt_wall_ns = std.time.nanoTimestamp();
                    first_pkt_pcap_ns = pkt_ts_ns;
                } else if (self.config.real_time) {
                    const elapsed_pcap_ns = pkt_ts_ns - first_pkt_pcap_ns;
                    const elapsed_wall_ns = std.time.nanoTimestamp() - first_pkt_wall_ns;
                    const target_wait_ns: f64 = @as(f64, @floatFromInt(elapsed_pcap_ns)) / self.config.speed_multiplier;
                    const delta_ns: i128 = @intFromFloat(target_wait_ns);
                    if (delta_ns > elapsed_wall_ns) {
                        const sleep_ns: u64 = @intCast(delta_ns - elapsed_wall_ns);
                        std.time.sleep(sleep_ns);
                    }
                }
                if (self.config.max_packets > 0 and self.stats.packets_sent >= self.config.max_packets) break;
                if (self.packet_cb) |cb| {
                    cb(self.ctx, pkt_ts_ns, data);
                }
                self.stats.packets_sent += 1;
                self.stats.bytes_sent += incl_len;
                self.stats.last_pkt_ts_ns = pkt_ts_ns;
            }
        }
        self.stats.end_ns = std.time.nanoTimestamp();
        return self.stats;
    }

    fn allocator(self: *ReplayEngine) std.mem.Allocator {
        _ = self;
        return std.heap.page_allocator;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ReplayConfig defaults" {
    const cfg = ReplayConfig{};
    try std.testing.expectEqual(@as(f64, 1.0), cfg.speed_multiplier);
    try std.testing.expectEqual(@as(u32, 1), cfg.loop_count);
    try std.testing.expect(cfg.real_time);
}

test "ReplayEngine replay empty file fails" {
    var dummy: u8 = 0;
    const cb: *const fn (ctx: *anyopaque, ts_ns: i128, data: []const u8) void = struct {
        fn cb(_: *anyopaque, _: i128, _: []const u8) void {}
    }.cb;
    var re = ReplayEngine.init(.{}, @ptrCast(&dummy), cb);
    const r = re.replayFile("/tmp/nonexistent.pcap");
    try std.testing.expectError(error.FileNotFound, r);
}

test "ReplayEngine replay synthetic pcap" {
    // Build a minimal 1-packet pcap file in the current working directory
    const path = "aegis_replay_test.pcap";
    defer std.fs.cwd().deleteFile(path) catch {};
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var gh = PcapGlobalHeader{
        .magic = PCAP_MAGIC_LE,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .linktype = 1, // Ethernet
    };
    try file.writeAll(std.mem.asBytes(&gh));
    var rh = PcapRecordHeader{ .ts_sec = 1000, .ts_usec = 0, .incl_len = 4, .orig_len = 4 };
    try file.writeAll(std.mem.asBytes(&rh));
    try file.writeAll("test");
    // Replay (real_time = false â†’ benchmark mode)
    var counter: u32 = 0;
    const cb: *const fn (ctx: *anyopaque, ts_ns: i128, data: []const u8) void = struct {
        fn cb(ctx: *anyopaque, _: i128, data: []const u8) void {
            const c: *u32 = @ptrCast(@alignCast(ctx));
            c.* += 1;
            _ = data;
        }
    }.cb;
    var re = ReplayEngine.init(.{ .real_time = false }, @ptrCast(&counter), cb);
    const stats = try re.replayFile(path);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    try std.testing.expectEqual(@as(u32, 1), counter);
}
