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
// EVT-216 (RB-021 follow-up): Npcap SDK pcap/pcap.h:574 declares
//   PCAP_API int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
// Both out-params are POINTER-TO-POINTER: the DLL stores its own header
// and data pointers into the caller's variables; the caller reads through
// them. The previous declaration took `*pcap_pkthdr` (one indirection
// short): the returned header pointer landed in the first 8 bytes of our
// struct, and caplen/len (offsets 8/12) were never written -- in a
// safety-checked build they read the 0xAA undefined fill (2863311530),
// padding every direct-capture window to the 1500-byte queue cap and
// letting trailing buffer bytes match text rules (RB-021 lab anomaly:
// a plain frame matching R9064 via a following frame's ;whoami bytes).
// Same shape as npcap_capture.zig's PcapNextExFn; the header behind the
// pointer is the 16-byte layout below (live-measured 2026-10-17:
// caplen == len == true frame size on captured frames).
pub extern "c" fn pcap_next_ex(p: *pcap_t, hdr: *?*const pcap_pkthdr, data: *?[*]const u8) c_int;
extern "c" fn pcap_close(p: *pcap_t) void;
extern "c" fn pcap_geterr(p: *pcap_t) [*:0]const u8;
extern "c" fn pcap_datalink(p: *pcap_t) c_int;

pub const pcap_pkthdr = extern struct {
    // Npcap's Windows timeval uses C `long`, which is 32-bit on Win64.
    // Using i64 here shifts caplen/len by 8 bytes and corrupts every header.
    ts_sec: i32,
    ts_usec: i32,
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

fn isVirtualOrUnsupportedDescription(description: ?[*:0]const u8) bool {
    const desc = if (description) |d| std.mem.span(d) else return true;
    return std.mem.indexOf(u8, desc, "WAN Miniport") != null or
        std.mem.indexOf(u8, desc, "Loopback") != null or
        std.mem.indexOf(u8, desc, "Hyper-V") != null or
        std.mem.indexOf(u8, desc, "VMware") != null or
        std.mem.indexOf(u8, desc, "Wi-Fi Direct") != null or
        std.mem.indexOf(u8, desc, "TeamViewer") != null or
        std.mem.indexOf(u8, desc, "Bluetooth") != null;
}

// ============================================================================
// NpcapAdapter â€” live capture handle
// ============================================================================
// Lab capture selection (EVT-200).
//
// AEGIS_DAEMON_IFACE pins daemon-side capture to one Npcap device by
// exact canonical name or case-insensitive description substring
// (e.g. "VMnet1"). Empty/unset keeps the historical auto-select,
// byte for byte. A SET but unmatched value FAILS CLOSED (no capture +
// loud error) -- silently sniffing the wrong interface would blind the
// operator while reporting healthy.
//
// Deliberately NOT AEGIS_CAPTURE_IFACE / AEGIS_NOSE_IFACE: the opener
// reads those for the Go nose process, and sharing one knob would swing
// the prod nose onto the lab interface on the next keeper restart.
pub const DAEMON_IFACE_ENV = "AEGIS_DAEMON_IFACE";
/// Exact interface selector passed to the Go Nose `--iface` capture process.
/// Required when the direct lab sensor is enabled; absence means overlap is
/// unknown and the direct sensor must remain disabled.
pub const NOSE_IFACE_ENV = "AEGIS_NOSE_IFACE";

/// Pure matcher, unit-tested without Npcap hardware. Empty filter never
/// matches (unset means auto-select, handled by the caller).
pub fn deviceMatchesFilter(name: []const u8, desc: []const u8, filter: []const u8) bool {
    if (filter.len == 0) return false;
    if (std.mem.eql(u8, name, filter)) return true;
    var name_lower: [256]u8 = undefined;
    var desc_lower: [256]u8 = undefined;
    var filter_lower: [256]u8 = undefined;
    if (filter.len > filter_lower.len) return std.mem.eql(u8, name, filter);
    const nl = @min(name.len, name_lower.len);
    const dl = @min(desc.len, desc_lower.len);
    _ = std.ascii.lowerString(name_lower[0..nl], name[0..nl]);
    _ = std.ascii.lowerString(desc_lower[0..dl], desc[0..dl]);
    _ = std.ascii.lowerString(filter_lower[0..filter.len], filter);
    const fl = filter_lower[0..filter.len];
    return std.mem.indexOf(u8, name_lower[0..nl], fl) != null or
        std.mem.indexOf(u8, desc_lower[0..dl], fl) != null;
}

/// Prove that two operator-declared interface selectors cannot identify the
/// same Npcap adapter. The predicate is intentionally conservative: equal or
/// substring-overlapping selectors are treated as unsafe because daemon-side
/// selectors may be friendly descriptions while Nose uses an exact name.
/// Empty means "unknown", so it is never considered disjoint.
pub fn interfaceSelectorsDisjoint(direct: []const u8, nose: []const u8) bool {
    if (direct.len == 0 or nose.len == 0) return false;
    var direct_lower: [256]u8 = undefined;
    var nose_lower: [256]u8 = undefined;
    if (direct.len > direct_lower.len or nose.len > nose_lower.len) return false;
    _ = std.ascii.lowerString(direct_lower[0..direct.len], direct);
    _ = std.ascii.lowerString(nose_lower[0..nose.len], nose);
    const d = direct_lower[0..direct.len];
    const n = nose_lower[0..nose.len];
    return std.mem.indexOf(u8, d, n) == null and std.mem.indexOf(u8, n, d) == null;
}

pub const NpcapAdapter = struct {
    handle: ?*pcap_t = null,
    device: [256]u8 = [_]u8{0} ** 256,
    datalink: c_int = DLT_EN10MB,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    packets_captured: u64 = 0,
    packets_dropped: u64 = 0,

    pub fn open(cfg: CaptureConfig) !NpcapAdapter {
        if (builtin.os.tag != .windows) {
            // Non-Windows: cannot open real pcap (Npcap is Windows-only)
            return error.UnsupportedPlatform;
        }

        // A zero-filled config means "auto-select". Never pass an empty or
        // friendly Windows adapter name (for example, "Wi-Fi") to Npcap;
        // pcap_create requires the canonical name returned by
        // pcap_findalldevs (normally a \Device\NPF_{GUID} path).
        var device = cfg.device;
        if (std.mem.sliceTo(&device, 0).len == 0) {
            var alldevs: ?*pcap_if_t = null;
            var find_errbuf: [256]u8 = undefined;
            @memset(&find_errbuf, 0);
            if (pcap_findalldevs(&alldevs, &find_errbuf) < 0) {
                diag.err("pcap_findalldevs failed: {s}", .{std.mem.sliceTo(&find_errbuf, 0)});
                return error.PcapFindalldevsFailed;
            }
            defer pcap_freealldevs(alldevs);

            // EVT-200: explicit lab pin. Env-gated and fail-closed; the
            // historical auto-select below runs byte-identically when unset.
            var env_buf: [512]u8 = undefined;
            var env_fba = std.heap.FixedBufferAllocator.init(&env_buf);
            const env_filter = std.process.getEnvVarOwned(env_fba.allocator(), DAEMON_IFACE_ENV) catch null;
            if (env_filter) |filter| {
                if (filter.len > 0) {
                    var pinned: ?[*:0]const u8 = null;
                    var mcur = alldevs;
                    while (mcur) |mdev| : (mcur = mdev.next) {
                        if (mdev.name) |mname| {
                            const mdesc: []const u8 = if (mdev.description) |md| std.mem.span(md) else "";
                            if (deviceMatchesFilter(std.mem.span(mname), mdesc, filter)) {
                                pinned = mname;
                                break;
                            }
                        }
                    }
                    const pinned_name = pinned orelse {
                        diag.err("AEGIS_DAEMON_IFACE={s} matches no Npcap device -- capture disabled (refusing silent wrong-iface)", .{filter});
                        return error.CaptureIfaceNotFound;
                    };
                    const pinned_slice = std.mem.span(pinned_name);
                    if (pinned_slice.len >= device.len) return error.PcapDeviceNameTooLong;
                    @memset(&device, 0);
                    @memcpy(device[0..pinned_slice.len], pinned_slice);
                    diag.info("Npcap pinned device via {s}: {s}", .{ DAEMON_IFACE_ENV, pinned_slice });
                }
            }
            if (std.mem.sliceTo(&device, 0).len == 0) {
                var selected: ?[*:0]const u8 = null;
                var fallback: ?[*:0]const u8 = null;
                var cur = alldevs;
                while (cur) |dev| : (cur = dev.next) {
                    if (dev.name) |name| {
                        // Npcap's first "up" device is frequently WAN Miniport
                        // (Network Monitor), which opens successfully but carries
                        // no ordinary host traffic. Prefer a real Wi-Fi/Ethernet
                        // adapter and retain a non-virtual fallback only.
                        if (isVirtualOrUnsupportedDescription(dev.description)) continue;
                        if (fallback == null) fallback = name;
                        if ((dev.flags & 0x1) == 0 and (dev.flags & 0x6) != 0) {
                            selected = name;
                            break;
                        }
                    }
                }
                const selected_name = selected orelse fallback orelse return error.PcapNoDevices;
                const selected_slice = std.mem.span(selected_name);
                if (selected_slice.len >= device.len) return error.PcapDeviceNameTooLong;
                @memset(&device, 0);
                @memcpy(device[0..selected_slice.len], selected_slice);
                diag.info("Npcap auto-selected device: {s}", .{selected_slice});
            }
        }

        var ad = NpcapAdapter{ .device = device };
        var errbuf: [256]u8 = undefined;
        @memset(&errbuf, 0);
        const dev_z = std.mem.sliceTo(&device, 0);
        const handle = pcap_create(@ptrCast(dev_z.ptr), &errbuf) orelse {
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
        @memcpy(&ad.device, &device);
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
            // EVT-216: both out-params are pointers the DLL publishes;
            // read through them, never from a local header struct.
            var hdr_ptr: ?*const pcap_pkthdr = null;
            var data_ptr: ?[*]const u8 = null;
            const rc = pcap_next_ex(h, &hdr_ptr, &data_ptr);
            if (rc == 0) continue; // timeout, no packet
            if (rc < 0) {
                diag.err("pcap_next_ex returned {d}", .{rc});
                self.packets_dropped += 1;
                break;
            }
            // rc == 1: both pointers are set. A missing one is a drop,
            // not a reason to slice stale memory.
            const hdr = hdr_ptr orelse {
                self.packets_dropped += 1;
                continue;
            };
            const data = data_ptr orelse {
                self.packets_dropped += 1;
                continue;
            };
            const slice = data[0..hdr.caplen];
            self.packets_captured += 1;
            diag.metrics.packets_captured.inc();
            cb(ctx, hdr, slice);
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

test "deviceMatchesFilter pins lab selection without hardware" {
    const guid = "\\Device\\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}";
    const desc = "VMware Virtual Ethernet Adapter for VMnet1";
    // Exact canonical name always wins.
    try std.testing.expect(deviceMatchesFilter(guid, desc, guid));
    // Case-insensitive description substring (operator-friendly).
    try std.testing.expect(deviceMatchesFilter(guid, desc, "vmnet1"));
    try std.testing.expect(deviceMatchesFilter(guid, desc, "VMNET1"));
    // Non-matches and the empty (unset) filter never match.
    try std.testing.expect(!deviceMatchesFilter(guid, desc, "VMnet2"));
    try std.testing.expect(!deviceMatchesFilter(guid, desc, "Wi-Fi"));
    try std.testing.expect(!deviceMatchesFilter(guid, desc, ""));
    // Overlong filters fall back to exact compare only (no truncation).
    var long: [300]u8 = [_]u8{'x'} ** 300;
    try std.testing.expect(!deviceMatchesFilter(guid, desc, &long));
}

test "interfaceSelectorsDisjoint fails closed for missing or overlapping selectors" {
    try std.testing.expect(!interfaceSelectorsDisjoint("VMnet1", ""));
    try std.testing.expect(!interfaceSelectorsDisjoint("", "Ethernet 2"));
    try std.testing.expect(!interfaceSelectorsDisjoint("VMnet1", "vmNET1"));
    try std.testing.expect(!interfaceSelectorsDisjoint("VMnet1", "VMnet"));
    try std.testing.expect(!interfaceSelectorsDisjoint("Ethernet 2", "Ethernet"));
    try std.testing.expect(interfaceSelectorsDisjoint("VMnet1", "Ethernet 2"));
    try std.testing.expect(interfaceSelectorsDisjoint("Wi-Fi", "Ethernet"));
}

test "Windows pcap_pkthdr matches Npcap ABI" {
    // timeval (long sec + long usec) + caplen + len = 16 bytes on Win64,
    // because Windows long remains 32-bit even for a 64-bit process.
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(pcap_pkthdr));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(pcap_pkthdr, "caplen"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(pcap_pkthdr, "len"));
}

test "pcap_next_ex declaration matches Npcap C ABI (EVT-216)" {
    // Npcap SDK pcap/pcap.h:574:
    //   int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
    // The DLL writes ITS pointers into the caller's variables. This pin
    // exists because RB-021's 1500-byte window over-read came from this
    // declaration being one indirection short (see the declaration
    // comment): a future "simplification" back to *pcap_pkthdr must fail
    // to compile right here.
    comptime {
        const P = @typeInfo(@TypeOf(pcap_next_ex)).Fn.params;
        if (P.len != 3) @compileError("pcap_next_ex arity changed (Npcap pcap/pcap.h:574)");
        if (P[1].type.? != *?*const pcap_pkthdr) @compileError(
            "pcap_next_ex header out-param must be *?*const pcap_pkthdr (struct pcap_pkthdr **)",
        );
        if (P[2].type.? != *?[*]const u8) @compileError(
            "pcap_next_ex data out-param must be *?[*]const u8 (const u_char **)",
        );
    }
}
