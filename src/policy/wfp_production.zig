//! wfp_production.zig - AEGIS WFP Production Path (P4 / Phase S)
//!
//! Userspace mirror of the production WFP driver contract
//! (kernel/wfp/aegis_wfp.c) plus the capture -> normalize -> validate ->
//! emit pipeline and the filter-set lifecycle state machine.
//!
//! Self-contained: imports std only. All layout constants below are
//! byte-for-byte parity with the driver C source (packed structures):
//!
//!   AEGIS_RING_HEADER  = 20 bytes  (5 x ULONG)
//!   AEGIS_PKT_META     = 49 bytes  (pragma pack(1))
//!   SEMI_NIDS_THRESHOLDS = 12 bytes (3 x LONG)
//!   SEMI_NIDS_IP_ENTRY = 25 bytes   (pragma pack(1))
//!   SEMI_NIDS_STATE    = 30779 bytes (pragma pack(1))
//!
//! IOCTL codes (0x800..0x807) and their payload sizes mirror the
//! aegis_dispatch_device_control handler exactly.
//!
//! Fail-soft rules:
//!   - Malformed ring records are counted and skipped, never crash.
//!   - Fail-open (cpu >= 85% or queue >= 95%) forces allow decisions.
//!   - Filter install/remove is idempotent and records partial state.

const std = @import("std");

// ============================================================
// Driver constants (mirrored from aegis_wfp.c)
// ============================================================

/// Shared ring buffer capacity: 64 MiB.
pub const RING_BUF_SIZE: u32 = 64 * 1024 * 1024;

/// Max bytes the driver copies per packet (FIXED: was 65535 on stack).
pub const MAX_PACKET_COPY: u32 = 4096;

/// Largest legal ring record: metadata + max payload copy.
pub const MAX_RECORD_SIZE: u32 = PKT_META_SIZE + MAX_PACKET_COPY;

/// Semi-NIDS default thresholds (driver defaults, score is x10 fixed point).
pub const DEFAULT_BLOCK_THRESHOLD: i32 = 600; // score >= 60.0 + High conf = block
pub const DEFAULT_RATELIMIT_THRESHOLD: i32 = 400; // score >= 40.0 + Med conf = rate limit
pub const DEFAULT_ALERT_THRESHOLD: i32 = 200; // score >= 20.0 = alert only

/// Temporary block duration (seconds) and table capacities.
pub const BLOCK_DURATION_SEC: u32 = 300;
pub const MAX_TEMP_BLOCKS: usize = 1024;
pub const MAX_WHITELIST: usize = 256;

/// Fail-open thresholds (Property 2 in the driver).
pub const FAIL_OPEN_CPU_THRESHOLD: u8 = 85;
pub const FAIL_OPEN_QUEUE_THRESHOLD: u8 = 95;

/// Device names as created by DriverEntry.
pub const SERVICE_NAME: []const u8 = "AegisWfp";
pub const DEVICE_SYMLINK: []const u8 = "\\\\.\\AegisWfp";

// ============================================================
// Packed layout mirrors (parity proven by tests)
// ============================================================

/// Mirror of AEGIS_RING_HEADER (pragma pack(1), 5 x ULONG = 20 bytes).
pub const RingHeader = extern struct {
    write_pos: u32,
    read_pos: u32,
    capacity: u32,
    packet_count: u32,
    dropped_count: u32,
};

/// Mirror of SEMI_NIDS_THRESHOLDS (pragma pack(1), 3 x LONG = 12 bytes).
pub const Thresholds = extern struct {
    block_threshold: i32,
    ratelimit_threshold: i32,
    alert_threshold: i32,
};

/// Mirror of SEMI_NIDS_IP_ENTRY (pragma pack(1), 25 bytes).
pub const SemiNidsIpEntry = packed struct {
    ip: u32,
    blocked_at: u64,
    expires_at: u64, // 0 = permanent
    reason: u32,
    confidence: u8,
};

/// Mirror of SEMI_NIDS_STATE (pragma pack(1)) total size.
/// Composition, in driver field order:
///   3 x LONG thresholds      = 12
///   BOOLEAN fail_open        =  1
///   2 x UCHAR load pcts      =  2
///   temp_blocks[1024] x 25   = 25600
///   temp_block_count         =  4
///   perm_blocks[1024] x 4    = 4096
///   perm_block_count         =  4
///   whitelist[256] x 4       = 1024
///   whitelist_count          =  4
///   4 x ULONG64 stats        = 32
pub const SEMI_NIDS_IP_ENTRY_SIZE: usize = 25;
pub const SEMI_NIDS_STATE_SIZE: usize = 12 + 3 +
    (MAX_TEMP_BLOCKS * SEMI_NIDS_IP_ENTRY_SIZE) + 4 +
    (MAX_TEMP_BLOCKS * @sizeOf(u32)) + 4 +
    (MAX_WHITELIST * @sizeOf(u32)) + 4 + 32;

/// Wire offsets of AEGIS_PKT_META fields (pragma pack(1)).
/// Kept explicit because the record is decoded field-wise.
pub const PKT_META_SIZE: u32 = 49;

pub const PktMeta = struct {
    size: u32, // total record bytes including this header
    orig_len: u32, // original packet length before truncation
    timestamp: u64, // KeQueryPerformanceCounter value
    layer_id: u16, // WFP layer that captured this packet
    direction: u16, // 0 = inbound, 1 = outbound
    process_id: u32, // PID from WFP classify
    ip_proto: u16, // 6 = TCP, 17 = UDP, ...
    src_ip: u32, // network byte order
    dst_ip: u32, // network byte order
    src_port: u16, // host byte order
    dst_port: u16, // host byte order
    threat_score: i32, // 0..1000 (x10 fixed point: 600 = 60.0)
    confidence: u8, // 0=unknown 1=low 2=medium 3=high 4=critical
    risk_flags: u32, // bitfield of matched rules
};

// ============================================================
// IOCTL contract (mirrors aegis_dispatch_device_control)
// ============================================================

pub const IoctlCode = enum(u32) {
    get_ring_addr = 0x800,
    get_stats = 0x801,
    semi_block_ip = 0x802,
    semi_unblock_ip = 0x803,
    semi_set_thresholds = 0x804,
    semi_get_state = 0x805,
    semi_set_failopen = 0x806,
    semi_whitelist_ip = 0x807,
};

/// Input payload size the driver requires (in_len >= check in the handler).
pub fn ioctlInputSize(code: IoctlCode) usize {
    return switch (code) {
        .get_ring_addr => 0,
        .get_stats => 0,
        .semi_block_ip => @sizeOf(u32),
        .semi_unblock_ip => @sizeOf(u32),
        .semi_set_thresholds => @sizeOf(Thresholds),
        .semi_get_state => 0,
        .semi_set_failopen => 1, // kernel BOOLEAN = BYTE
        .semi_whitelist_ip => @sizeOf(u32),
    };
}

/// Output payload size the driver returns (out_len >= check in the handler).
pub fn ioctlOutputSize(code: IoctlCode) usize {
    return switch (code) {
        .get_ring_addr => @sizeOf(usize), // PVOID (x64)
        .get_stats => @sizeOf(RingHeader),
        .semi_block_ip => @sizeOf(u32),
        .semi_unblock_ip => @sizeOf(u32),
        .semi_set_thresholds => @sizeOf(Thresholds),
        .semi_get_state => SEMI_NIDS_STATE_SIZE,
        .semi_set_failopen => 1,
        .semi_whitelist_ip => @sizeOf(u32),
    };
}

// ============================================================
// Decision plane (must stay in parity with the driver + Rust PEP)
// ============================================================

pub const EnforceAction = enum(u8) {
    allow = 0,
    alert = 1,
    rate_limit = 2,
    block = 3,
};

pub const Confidence = enum(u8) {
    unknown = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,
};

/// Fail-open rule: Property 2 of the driver.
/// cpu >= 85% OR queue >= 95% -> fail-open passes traffic.
pub fn failOpenActive(cpu_pct: u8, queue_pct: u8) bool {
    return cpu_pct >= FAIL_OPEN_CPU_THRESHOLD or queue_pct >= FAIL_OPEN_QUEUE_THRESHOLD;
}

/// Deterministic enforcement decision (mirrors driver semantics):
///   fail-open                     -> allow (never block)
///   score >= block   + conf >= 3  -> block
///   score >= ratelimit + conf >= 2 -> rate_limit
///   score >= alert                -> alert
///   otherwise                     -> allow
pub fn enforcementDecision(score_x10: i32, conf: Confidence, fail_open: bool) EnforceAction {
    if (fail_open) return .allow;
    if (score_x10 >= DEFAULT_BLOCK_THRESHOLD and
        @intFromEnum(conf) >= @intFromEnum(Confidence.high)) return .block;
    if (score_x10 >= DEFAULT_RATELIMIT_THRESHOLD and
        @intFromEnum(conf) >= @intFromEnum(Confidence.medium)) return .rate_limit;
    if (score_x10 >= DEFAULT_ALERT_THRESHOLD) return .alert;
    return .allow;
}

// ============================================================
// Ring buffer producer (replay/testing twin of the kernel writer)
// ============================================================

pub const RingError = error{
    RingTooSmall,
    RingFull,
    PayloadTooLarge,
};

/// Producer side: exact mirror of the ring write path in
/// aegis_classify (aegis_wfp.c):
///   - write_pos/read_pos are RELATIVE indices in [0, capacity)
///   - free space keeps a 1-byte reserve (empty = wp == rp)
///   - records MAY straddle the ring end (chunk1/chunk2 copies)
///   - write_pos advances mod capacity; drop when free < total
pub const RingWriter = struct {
    buf: []u8, // header (20) + records region

    pub fn init(buf: []u8) RingError!RingWriter {
        if (buf.len < @sizeOf(RingHeader) + 64) return RingError.RingTooSmall;
        const cap: u32 = @intCast(buf.len - @sizeOf(RingHeader));
        writeInt(buf, 0, @as(u32, 0)); // write_pos
        writeInt(buf, 4, @as(u32, 0)); // read_pos
        writeInt(buf, 8, cap); // capacity
        writeInt(buf, 12, @as(u32, 0)); // packet_count
        writeInt(buf, 16, @as(u32, 0)); // dropped_count
        return .{ .buf = buf };
    }

    pub fn writePos(self: *const RingWriter) u32 {
        return readInt(u32, self.buf, 0);
    }

    pub fn packetCount(self: *const RingWriter) u32 {
        return readInt(u32, self.buf, 12);
    }

    pub fn droppedCount(self: *const RingWriter) u32 {
        return readInt(u32, self.buf, 16);
    }

    /// Write one packet record. Returns false when free space is
    /// insufficient (dropped_count increments; unread data is never
    /// overwritten - identical to the driver).
    pub fn writePacket(
        self: *RingWriter,
        meta: PktMeta,
        payload: []const u8,
    ) bool {
        const cap = readInt(u32, self.buf, 8);
        const wp = readInt(u32, self.buf, 0);
        const rp = readInt(u32, self.buf, 4);
        const total: u32 = PKT_META_SIZE + @as(u32, @intCast(payload.len));
        if (payload.len > MAX_PACKET_COPY) return false;

        // Free-space check (driver: wp >= rp ? cap-(wp-rp)-1 : rp-wp-1).
        const free: u32 = if (wp >= rp) cap - (wp - rp) - 1 else rp - wp - 1;
        if (free < total) {
            bump(self.buf, 16); // dropped_count++
            return false;
        }

        const rec = self.buf[@sizeOf(RingHeader)..];
        // Serialize meta + payload across the wrap boundary exactly
        // like the driver (chunk1 into [offset..cap), chunk2 into [0..)).
        // Encode the fixed meta fields little-endian into a scratch
        // image of the 49-byte metadata header.
        var img: [PKT_META_SIZE]u8 = undefined;
        writeInt(&img, 0, total);
        writeInt(&img, 4, meta.orig_len);
        writeInt(&img, 8, meta.timestamp);
        writeInt(&img, 16, meta.layer_id);
        writeInt(&img, 18, meta.direction);
        writeInt(&img, 20, meta.process_id);
        writeInt(&img, 24, meta.ip_proto);
        writeInt(&img, 28, meta.src_ip);
        writeInt(&img, 32, meta.dst_ip);
        writeInt(&img, 36, meta.src_port);
        writeInt(&img, 38, meta.dst_port);
        writeInt(&img, 40, meta.threat_score);
        img[44] = meta.confidence;
        writeInt(&img, 45, meta.risk_flags);

        var off: u32 = wp;
        for (img) |b| {
            rec[off] = b;
            off = (off + 1) % cap;
        }
        for (payload) |b| {
            rec[off] = b;
            off = (off + 1) % cap;
        }
        writeInt(self.buf, 0, off); // write_pos = (wp + total) % cap
        bump(self.buf, 12); // packet_count++
        return true;
    }
};

fn writeInt(buf: []u8, off: u32, value: anytype) void {
    const T = @TypeOf(value);
    std.mem.writeInt(
        T,
        buf[off..][0..@sizeOf(T)],
        value,
        .little,
    );
}

fn bump(buf: []u8, off: u32) void {
    const v = readInt(u32, buf, off);
    writeInt(buf, off, v +% 1);
}

// ============================================================
// Capture -> normalize -> validate -> emit pipeline
// ============================================================

pub const RejectReason = enum {
    record_too_small,
    record_too_large,
    bad_direction,
    bad_confidence,
    bad_score,
    bad_proto,
};

pub const CapturedEvent = struct {
    timestamp: u64,
    direction: u16, // 0 inbound, 1 outbound
    ip_proto: u16,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    process_id: u32,
    threat_score: i32,
    confidence: Confidence,
    risk_flags: u32,
    /// Payload view. Records may straddle the ring end (driver wraps
    /// mid-record), so the payload is up to two contiguous slices;
    /// logical payload = a ++ b. Valid until the next poll.
    payload_a: []const u8 = &.{},
    payload_b: []const u8 = &.{},

    pub fn payloadLen(self: CapturedEvent) usize {
        return self.payload_a.len + self.payload_b.len;
    }
};

pub const PollStats = struct {
    scanned: u32 = 0,
    emitted: u32 = 0,
    rejected: u32 = 0,
    last_reject: ?RejectReason = null,
};

/// Consumer side: mirrors the userspace reader protocol.
///   - read_pos is a RELATIVE index in [0, capacity); empty = rp == wp
///   - decode is wrap-safe (records may straddle the ring end)
///   - malformed records are skipped deterministically: whole frame if
///     the declared size is plausible, else one metadata step
///   - a per-poll step bound prevents runaway scans on garbage rings
///   - validation: size bounds, direction <= 1, confidence <= 4,
///     threat_score in 0..1000, ip_proto in {1,6,17,47,50,58,132}
pub const RingConsumer = struct {
    buf: []u8, // mutable: poll publishes read_pos back to the header
    read_pos: u32, // relative index mirror

    pub fn init(buf: []u8) RingError!RingConsumer {
        if (buf.len < @sizeOf(RingHeader) + 64) return RingError.RingTooSmall;
        const cap: u32 = @intCast(buf.len - @sizeOf(RingHeader));
        if (readInt(u32, buf, 8) != cap) return RingError.RingTooSmall;
        return .{ .buf = buf, .read_pos = readInt(u32, buf, 4) };
    }

    fn capacity(self: *const RingConsumer) u32 {
        return readInt(u32, self.buf, 8);
    }

    /// Decode and validate one record starting at relative offset
    /// `rel` in the records region. Wrap-safe for all field reads.
    pub fn decodeAt(
        buf: []const u8,
        rel: u32,
    ) union(enum) {
        ok: struct { meta: PktMeta, payload_a: []const u8, payload_b: []const u8 },
        reject: RejectReason,
    } {
        const cap: u32 = @intCast(buf.len - @sizeOf(RingHeader));
        const rec = buf[@sizeOf(RingHeader)..];

        // Declared frame size (straddle-safe read).
        const m_size = readWrap(u32, rec, cap, rel);
        if (m_size < PKT_META_SIZE) return .{ .reject = .record_too_small };
        if (m_size > MAX_RECORD_SIZE) return .{ .reject = .record_too_large };

        const meta = PktMeta{
            .size = m_size,
            .orig_len = readWrap(u32, rec, cap, rel + 4),
            .timestamp = readWrap(u64, rec, cap, rel + 8),
            .layer_id = readWrap(u16, rec, cap, rel + 16),
            .direction = readWrap(u16, rec, cap, rel + 18),
            .process_id = readWrap(u32, rec, cap, rel + 20),
            .ip_proto = readWrap(u16, rec, cap, rel + 24),
            .src_ip = readWrap(u32, rec, cap, rel + 28),
            .dst_ip = readWrap(u32, rec, cap, rel + 32),
            .src_port = readWrap(u16, rec, cap, rel + 36),
            .dst_port = readWrap(u16, rec, cap, rel + 38),
            .threat_score = readWrap(i32, rec, cap, rel + 40),
            .confidence = rec[(rel + 44) % cap],
            .risk_flags = readWrap(u32, rec, cap, rel + 45),
        };

        // Normalize + validate (fail-soft: reject, never crash).
        if (meta.direction > 1) return .{ .reject = .bad_direction };
        if (meta.confidence > 4) return .{ .reject = .bad_confidence };
        if (meta.threat_score < 0 or meta.threat_score > 1000) {
            return .{ .reject = .bad_score };
        }
        switch (meta.ip_proto) {
            1, 6, 17, 47, 50, 58, 132 => {},
            else => return .{ .reject = .bad_proto },
        }

        // Payload view: up to two slices across the wrap boundary.
        const p_start: u32 = rel + PKT_META_SIZE;
        const p_end: u32 = rel + m_size; // <= cap + cap (cannot wrap twice)
        var pa: []const u8 = &.{};
        var pb: []const u8 = &.{};
        if (p_end <= cap) {
            pa = rec[p_start..p_end];
        } else if (p_start < cap) {
            pa = rec[p_start..cap];
            pb = rec[0 .. p_end - cap];
        } else {
            pb = rec[(p_start % cap)..(p_end - cap)];
        }
        return .{ .ok = .{ .meta = meta, .payload_a = pa, .payload_b = pb } };
    }

    /// Poll up to out.len normalized events. Returns stats; payload
    /// slices are valid until the next poll. read_pos is published
    /// back to the shared header after every poll.
    pub fn poll(self: *RingConsumer, out: []CapturedEvent) PollStats {
        var stats = PollStats{};
        const cap = self.capacity();
        var rp = self.read_pos;
        const wp = readInt(u32, self.buf, 0);

        // Step bound: a corrupt ring can desync framing; never scan
        // more than the theoretical maximum number of records + slack.
        const max_steps = (cap / PKT_META_SIZE) + 2;
        var steps: u32 = 0;

        while (stats.emitted < out.len and steps < max_steps) {
            if (rp == wp) break; // empty (driver semantics)
            steps += 1;
            switch (decodeAt(self.buf, rp)) {
                .ok => |res| {
                    out[stats.emitted] = CapturedEvent{
                        .timestamp = res.meta.timestamp,
                        .direction = res.meta.direction,
                        .ip_proto = res.meta.ip_proto,
                        .src_ip = res.meta.src_ip,
                        .dst_ip = res.meta.dst_ip,
                        .src_port = res.meta.src_port,
                        .dst_port = res.meta.dst_port,
                        .process_id = res.meta.process_id,
                        .threat_score = res.meta.threat_score,
                        .confidence = @enumFromInt(res.meta.confidence),
                        .risk_flags = res.meta.risk_flags,
                        .payload_a = res.payload_a,
                        .payload_b = res.payload_b,
                    };
                    stats.emitted += 1;
                    rp = (rp + res.meta.size) % cap;
                },
                .reject => |reason| {
                    stats.rejected += 1;
                    stats.last_reject = reason;
                    // Deterministic resync: trust the declared frame
                    // length when plausible, else advance one meta step.
                    const declared = readWrap(u32, self.buf[@sizeOf(RingHeader)..], cap, rp);
                    if (declared >= PKT_META_SIZE and declared <= MAX_RECORD_SIZE) {
                        rp = (rp + declared) % cap;
                    } else {
                        rp = (rp + PKT_META_SIZE) % cap;
                    }
                },
            }
            stats.scanned += 1;
        }

        self.read_pos = rp;
        writeInt(self.buf, 4, rp); // publish read cursor to the driver
        return stats;
    }
};

/// Little-endian integer read that wraps around the records region.
fn readWrap(comptime T: type, rec: []const u8, cap: u32, start: u32) T {
    const U = std.meta.Int(.unsigned, @bitSizeOf(T));
    var v: U = 0;
    inline for (0..@sizeOf(T)) |k| {
        v |= @as(U, rec[(start + @as(u32, @intCast(k))) % cap]) << (8 * k);
    }
    return @bitCast(v);
}

fn readInt(comptime T: type, buf: []const u8, off: u32) T {
    return std.mem.readInt(T, buf[off..][0..@sizeOf(T)], .little);
}

// ============================================================
// Filter-set lifecycle (Phase S state machine)
// ============================================================

/// WFP inspection layers used by the production filter set.
/// Symbolic names match fwpmu.h layer GUID identifiers.
pub const FilterLayer = enum(u8) {
    inbound_ippacket_v4 = 0, // FWPM_LAYER_INBOUND_IPPACKET_V4
    outbound_ippacket_v4 = 1, // FWPM_LAYER_OUTBOUND_IPPACKET_V4
    ale_auth_connect_v4 = 2, // FWPM_LAYER_ALE_AUTH_CONNECT_V4
    ale_auth_recv_accept_v4 = 3, // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
    ale_flow_established_v4 = 4, // FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4

    pub fn symbol(self: FilterLayer) []const u8 {
        return switch (self) {
            .inbound_ippacket_v4 => "FWPM_LAYER_INBOUND_IPPACKET_V4",
            .outbound_ippacket_v4 => "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
            .ale_auth_connect_v4 => "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            .ale_auth_recv_accept_v4 => "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            .ale_flow_established_v4 => "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4",
        };
    }
};

pub const FILTER_SET_COUNT: usize = 5;

pub const FilterSpec = struct {
    layer: FilterLayer,
    weight: u8, // 0..15 sublayer weight (lower = earlier)
    enabled: bool = true,
};

/// Production filter set: packet inspection both directions + ALE
/// connection tracking. Order defines install sequence.
pub fn defaultFilterSet() [FILTER_SET_COUNT]FilterSpec {
    return .{
        .{ .layer = .inbound_ippacket_v4, .weight = 0 },
        .{ .layer = .outbound_ippacket_v4, .weight = 1 },
        .{ .layer = .ale_auth_connect_v4, .weight = 2 },
        .{ .layer = .ale_auth_recv_accept_v4, .weight = 3 },
        .{ .layer = .ale_flow_established_v4, .weight = 4 },
    };
}

pub const ServicePhase = enum {
    missing, // service not installed
    stopped, // installed but not started
    running, // started, device not verified
    device_ready, // \\.\\AegisWfp opened OK
    filters_installed, // filter set active
};

pub const LifecycleError = error{
    FiltersStillInstalled,
    NotReady,
    AlreadyInstalled,
    NothingInstalled,
    InstallerFailed,
};

/// Injectable installer boundary: production binds FwpmFilterAdd0 /
/// FwpmFilterDelete0ById; tests bind a scripted fake.
pub const Installer = struct {
    ctx: ?*anyopaque = null,
    addFn: *const fn (ctx: ?*anyopaque, layer: FilterLayer) anyerror!u64,
    delFn: *const fn (ctx: ?*anyopaque, layer: FilterLayer, filter_id: u64) anyerror!void,

    pub fn add(self: *const Installer, layer: FilterLayer) anyerror!u64 {
        return self.addFn(self.ctx, layer);
    }
    pub fn del(self: *const Installer, layer: FilterLayer, filter_id: u64) anyerror!void {
        return self.delFn(self.ctx, layer, filter_id);
    }
};

pub const InstallEntry = struct {
    layer: FilterLayer,
    filter_id: u64 = 0,
    ok: bool = false,
};

/// Filter lifecycle state machine (fail-soft, idempotent).
pub const FilterLifecycle = struct {
    phase: ServicePhase = .missing,
    installed: [FILTER_SET_COUNT]bool = .{false} ** FILTER_SET_COUNT,
    ids: [FILTER_SET_COUNT]u64 = .{0} ** FILTER_SET_COUNT,
    log: [FILTER_SET_COUNT]InstallEntry = undefined,
    log_len: usize = 0,
    device_open_failures: u32 = 0,

    /// Service presence/refresh (sc query result).
    pub fn onServiceQuery(self: *FilterLifecycle, found: bool, started: bool) void {
        if (self.phase == .filters_installed and !started) {
            // Service died under us: filters are gone with the engine.
            self.resetInstalled();
            self.phase = if (found) .stopped else .missing;
            return;
        }
        if (!found) {
            self.phase = .missing;
        } else if (started) {
            if (self.phase == .missing or self.phase == .stopped) self.phase = .running;
        } else {
            if (self.phase != .filters_installed) self.phase = .stopped;
        }
    }

    /// Device open attempt on \\.\\AegisWfp.
    pub fn onDeviceOpen(self: *FilterLifecycle, ok: bool) void {
        if (ok) {
            if (self.phase == .running) self.phase = .device_ready;
            self.device_open_failures = 0;
        } else {
            self.device_open_failures += 1;
        }
    }

    /// Install the full filter set. Partial failures leave the mask
    /// recording exactly which layers are live (never lies).
    pub fn installFilters(self: *FilterLifecycle, installer: *const Installer) LifecycleError!void {
        if (self.phase != .device_ready) return LifecycleError.NotReady;
        if (self.phase == .filters_installed or self.installed[0]) {
            return LifecycleError.AlreadyInstalled;
        }
        self.log_len = 0;
        var all_ok = true;
        for (defaultFilterSet()) |spec| {
            const idx = @intFromEnum(spec.layer);
            if (self.installed[idx]) continue;
            var entry = InstallEntry{ .layer = spec.layer };
            if (installer.add(spec.layer)) |id| {
                entry.ok = true;
                entry.filter_id = id;
                self.installed[idx] = true;
                self.ids[idx] = id;
            } else |_| {
                entry.ok = false;
                all_ok = false;
            }
            if (self.log_len < FILTER_SET_COUNT) {
                self.log[self.log_len] = entry;
                self.log_len += 1;
            }
        }
        if (all_ok) {
            self.phase = .filters_installed;
        } else {
            return LifecycleError.InstallerFailed;
        }
    }

    /// Remove installed filters in reverse install order. Idempotent.
    pub fn removeFilters(self: *FilterLifecycle, installer: *const Installer) void {
        var i: usize = FILTER_SET_COUNT;
        while (i > 0) {
            i -= 1;
            const idx = @intFromEnum(@as(FilterLayer, @enumFromInt(@as(u8, @intCast(i)))));
            if (!self.installed[idx]) continue;
            installer.del(@enumFromInt(@as(u8, @intCast(i))), self.ids[idx]) catch {
                // Keep mask true: the filter may still be live (no lies).
                continue;
            };
            self.installed[idx] = false;
            self.ids[idx] = 0;
        }
        if (self.phase == .filters_installed) self.phase = .device_ready;
    }

    /// Guard: service must not stop while filters are installed.
    pub fn onServiceStopRequest(self: *FilterLifecycle) LifecycleError!void {
        for (self.installed) |live| {
            if (live) return LifecycleError.FiltersStillInstalled;
        }
    }

    pub fn installedCount(self: *const FilterLifecycle) usize {
        var n: usize = 0;
        for (self.installed) |live| {
            if (live) n += 1;
        }
        return n;
    }

    fn resetInstalled(self: *FilterLifecycle) void {
        self.installed = .{false} ** FILTER_SET_COUNT;
        self.ids = .{0} ** FILTER_SET_COUNT;
        self.log_len = 0;
    }
};

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "layout parity: header 20, meta 49, thresholds 12, ip entry 25, state 30779" {
    try testing.expectEqual(@as(usize, 20), @sizeOf(RingHeader));
    try testing.expectEqual(@as(u32, 49), PKT_META_SIZE);
    try testing.expectEqual(@as(usize, 12), @sizeOf(Thresholds));
    try testing.expectEqual(@as(usize, 25), SEMI_NIDS_IP_ENTRY_SIZE);
    try testing.expectEqual(@as(usize, 30779), SEMI_NIDS_STATE_SIZE);
}

test "ioctl contract: codes and payload sizes mirror the driver handler" {
    try testing.expectEqual(@as(u32, 0x800), @intFromEnum(IoctlCode.get_ring_addr));
    try testing.expectEqual(@as(u32, 0x801), @intFromEnum(IoctlCode.get_stats));
    try testing.expectEqual(@as(u32, 0x802), @intFromEnum(IoctlCode.semi_block_ip));
    try testing.expectEqual(@as(u32, 0x803), @intFromEnum(IoctlCode.semi_unblock_ip));
    try testing.expectEqual(@as(u32, 0x804), @intFromEnum(IoctlCode.semi_set_thresholds));
    try testing.expectEqual(@as(u32, 0x805), @intFromEnum(IoctlCode.semi_get_state));
    try testing.expectEqual(@as(u32, 0x806), @intFromEnum(IoctlCode.semi_set_failopen));
    try testing.expectEqual(@as(u32, 0x807), @intFromEnum(IoctlCode.semi_whitelist_ip));

    try testing.expectEqual(@as(usize, 0), ioctlInputSize(.get_ring_addr));
    try testing.expectEqual(@as(usize, 8), ioctlOutputSize(.get_ring_addr));
    try testing.expectEqual(@as(usize, 20), ioctlOutputSize(.get_stats));
    try testing.expectEqual(@as(usize, 4), ioctlInputSize(.semi_block_ip));
    try testing.expectEqual(@as(usize, 4), ioctlInputSize(.semi_unblock_ip));
    try testing.expectEqual(@as(usize, 12), ioctlInputSize(.semi_set_thresholds));
    try testing.expectEqual(@as(usize, SEMI_NIDS_STATE_SIZE), ioctlOutputSize(.semi_get_state));
    try testing.expectEqual(@as(usize, 1), ioctlInputSize(.semi_set_failopen));
    try testing.expectEqual(@as(usize, 4), ioctlInputSize(.semi_whitelist_ip));
}

test "driver constants parity" {
    try testing.expectEqual(@as(u32, 64 * 1024 * 1024), RING_BUF_SIZE);
    try testing.expectEqual(@as(u32, 4096), MAX_PACKET_COPY);
    try testing.expectEqual(@as(u32, 4145), MAX_RECORD_SIZE);
    try testing.expectEqual(@as(i32, 600), DEFAULT_BLOCK_THRESHOLD);
    try testing.expectEqual(@as(i32, 400), DEFAULT_RATELIMIT_THRESHOLD);
    try testing.expectEqual(@as(i32, 200), DEFAULT_ALERT_THRESHOLD);
    try testing.expectEqual(@as(u32, 300), BLOCK_DURATION_SEC);
    try testing.expectEqual(@as(usize, 1024), MAX_TEMP_BLOCKS);
    try testing.expectEqual(@as(usize, 256), MAX_WHITELIST);
    try testing.expectEqual(@as(u8, 85), FAIL_OPEN_CPU_THRESHOLD);
    try testing.expectEqual(@as(u8, 95), FAIL_OPEN_QUEUE_THRESHOLD);
    try testing.expectEqualStrings("AegisWfp", SERVICE_NAME);
    try testing.expectEqualStrings("\\\\.\\AegisWfp", DEVICE_SYMLINK);
}

test "enforcement decision matrix (driver parity vectors)" {
    // Block: score >= 600 AND confidence >= high.
    try testing.expectEqual(EnforceAction.block, enforcementDecision(600, .high, false));
    try testing.expectEqual(EnforceAction.block, enforcementDecision(950, .critical, false));
    // High score but medium confidence -> only rate limit.
    try testing.expectEqual(EnforceAction.rate_limit, enforcementDecision(900, .medium, false));
    // Rate limit: >= 400 AND confidence >= medium.
    try testing.expectEqual(EnforceAction.rate_limit, enforcementDecision(400, .medium, false));
    try testing.expectEqual(EnforceAction.alert, enforcementDecision(400, .low, false));
    // Alert: >= 200 any confidence.
    try testing.expectEqual(EnforceAction.alert, enforcementDecision(200, .unknown, false));
    try testing.expectEqual(EnforceAction.allow, enforcementDecision(199, .critical, false));
    // Fail-open forces allow (never block).
    try testing.expectEqual(EnforceAction.allow, enforcementDecision(990, .critical, true));
}

test "fail-open triggers at cpu 85 or queue 95" {
    try testing.expect(failOpenActive(85, 0));
    try testing.expect(failOpenActive(86, 10));
    try testing.expect(failOpenActive(10, 95));
    try testing.expect(failOpenActive(100, 100));
    try testing.expect(!failOpenActive(84, 94));
    try testing.expect(!failOpenActive(0, 0));
}

const testutil = struct {
    fn mkMeta(size: u32, ts: u64, dir: u16, score: i32, conf: u8) PktMeta {
        return .{
            .size = size,
            .orig_len = size - PKT_META_SIZE,
            .timestamp = ts,
            .layer_id = 0,
            .direction = dir,
            .process_id = 4242,
            .ip_proto = 6,
            .src_ip = 0x0100007F, // 127.0.0.1
            .dst_ip = 0x08080808, // 8.8.8.8
            .src_port = 4444,
            .dst_port = 80,
            .threat_score = score,
            .confidence = conf,
            .risk_flags = 0x3,
        };
    }
};

test "ring writer + consumer roundtrip preserves records" {
    var buf: [@sizeOf(RingHeader) + 8192]u8 = undefined;
    var w = try RingWriter.init(&buf);
    var c = try RingConsumer.init(&buf);

    const p1 = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const p2 = "aegis-payload";
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + p1.len, 100, 0, 650, 3), &p1));
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + p2.len, 200, 1, 420, 2), p2));

    var out: [4]CapturedEvent = undefined;
    const stats = c.poll(&out);
    try testing.expectEqual(@as(u32, 2), stats.emitted);
    try testing.expectEqual(@as(u32, 0), stats.rejected);
    try testing.expectEqual(@as(u64, 100), out[0].timestamp);
    try testing.expectEqual(p1.len, out[0].payloadLen());
    try testing.expectEqualSlices(u8, &p1, out[0].payload_a);
    try testing.expectEqual(EnforceAction.block, enforcementDecision(
        out[0].threat_score,
        out[0].confidence,
        false,
    ));
    try testing.expectEqual(EnforceAction.rate_limit, enforcementDecision(
        out[1].threat_score,
        out[1].confidence,
        false,
    ));
}

test "ring fills, drops when full, then straddles the end after drain" {
    var buf: [@sizeOf(RingHeader) + 4096]u8 = undefined;
    var w = try RingWriter.init(&buf);
    var c = try RingConsumer.init(&buf);
    // cap = 4076, record = 49 + 64 = 113.
    const payload = [_]u8{0xA5} ** 64;

    // Phase 1: fill until full. 36 records fit (36 x 113 = 4068),
    // the remaining 4 of 40 drop.
    var written: u32 = 0;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        if (w.writePacket(testutil.mkMeta(PKT_META_SIZE + payload.len, @as(u64, i), 0, 250, 1), &payload)) {
            written += 1;
        }
    }
    try testing.expectEqual(@as(u32, 36), written);
    try testing.expectEqual(@as(u32, 4), w.droppedCount());
    try testing.expectEqual(@as(u32, 36), w.packetCount());

    var out: [64]CapturedEvent = undefined;
    var s1 = c.poll(&out);
    try testing.expectEqual(written, s1.emitted);

    // Phase 2: drained ring - write cursor sits 8 bytes before the end.
    // The next record MUST straddle the boundary (driver chunk1/chunk2).
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + payload.len, 777, 1, 250, 1), &payload));
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + payload.len, 888, 0, 250, 1), &payload));

    s1 = c.poll(&out);
    try testing.expectEqual(@as(u32, 2), s1.emitted);
    try testing.expectEqual(@as(u64, 777), out[0].timestamp);
    // Record 777 wrapped mid-record: payload lives entirely in the
    // wrapped part (payload_b), zero bytes in payload_a.
    try testing.expectEqual(@as(usize, 64), out[0].payloadLen());
    try testing.expectEqualSlices(u8, &payload, out[0].payload_b);
    try testing.expectEqual(@as(usize, 0), out[0].payload_a.len);
    // Record 888 wrote wholly inside the ring.
    try testing.expectEqual(@as(usize, 64), out[1].payloadLen());
    try testing.expectEqualSlices(u8, &payload, out[1].payload_a);
    try testing.expectEqual(@as(u32, 38), w.packetCount());
}

test "ring writer drops when consumer lags and never overwrites unread" {
    var buf: [@sizeOf(RingHeader) + 2048]u8 = undefined;
    var w = try RingWriter.init(&buf);
    var c = try RingConsumer.init(&buf);

    const payload = [_]u8{0x11} ** 512; // 561-byte records
    var accepted: u32 = 0;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        if (w.writePacket(testutil.mkMeta(PKT_META_SIZE + payload.len, @as(u64, i), 1, 100, 0), &payload)) {
            accepted += 1;
        }
    }
    try testing.expectEqual(@as(u32, 3), accepted); // 3 x 561 = 1683 <= 2027
    try testing.expectEqual(@as(u32, 13), w.droppedCount());

    // Consumer still reads exactly the accepted packets, uncorrupted.
    var total: u32 = 0;
    var out: [8]CapturedEvent = undefined;
    while (true) {
        const stats = c.poll(&out);
        total += stats.emitted;
        if (stats.emitted == 0) break;
    }
    try testing.expectEqual(accepted, total);
}

test "consumer resyncs deterministically on bad then good records" {
    var buf: [@sizeOf(RingHeader) + 4096]u8 = undefined;
    var w = try RingWriter.init(&buf);
    var c = try RingConsumer.init(&buf);
    const rec = buf[@sizeOf(RingHeader)..];

    // Record 1: sane frame (53 bytes) but invalid direction (=2).
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + 4, 1, 2, 300, 2), "abcd"));
    std.mem.writeInt(u16, rec[18..20], 2, .little); // corrupt direction
    // Record 2: valid.
    try testing.expect(w.writePacket(testutil.mkMeta(PKT_META_SIZE + 2, 2, 1, 800, 4), "ok"));

    var out: [4]CapturedEvent = undefined;
    const stats = c.poll(&out);
    // Declared size was plausible -> whole-frame skip lands exactly on
    // the next record, so the valid packet survives the garbage.
    try testing.expectEqual(@as(u32, 1), stats.emitted);
    try testing.expectEqual(@as(u32, 1), stats.rejected);
    try testing.expectEqual(RejectReason.bad_direction, stats.last_reject.?);
    try testing.expectEqual(@as(u64, 2), out[0].timestamp);
}

test "consumer steps one meta on implausible declared size" {
    var buf: [@sizeOf(RingHeader) + 1024]u8 = undefined;
    const rec = buf[@sizeOf(RingHeader)..];

    // Ring header: rp = 0, wp = end of the good record below.
    const cap: u32 = 1024;
    std.mem.writeInt(u32, buf[0..4], 0, .little); // write_pos (patched below)
    std.mem.writeInt(u32, buf[4..8], 0, .little); // read_pos
    std.mem.writeInt(u32, buf[8..12], cap, .little); // capacity
    var c = try RingConsumer.init(&buf);

    // Garbage meta: declared size 0xFFFFFFFF (implausible).
    std.mem.writeInt(u32, rec[0..4], 0xFFFFFFFF, .little);
    // Hand-crafted valid record right after the meta step (offset 49).
    const good_at: u32 = 49;
    @memset(rec[good_at..][0..PKT_META_SIZE], 0); // zero all fields
    std.mem.writeInt(u32, rec[good_at..][0..4], PKT_META_SIZE + 2, .little); // size
    std.mem.writeInt(u32, rec[good_at + 4 ..][0..4], 2, .little); // orig_len
    std.mem.writeInt(u64, rec[good_at + 8 ..][0..8], 555, .little); // ts
    std.mem.writeInt(u16, rec[good_at + 18 ..][0..2], 0, .little); // dir
    std.mem.writeInt(u16, rec[good_at + 24 ..][0..2], 17, .little); // proto
    std.mem.writeInt(i32, rec[good_at + 40 ..][0..4], 300, .little); // score
    rec[good_at + 44] = 3; // confidence
    std.mem.writeInt(u32, buf[0..4], good_at + PKT_META_SIZE + 2, .little); // wp

    var out: [4]CapturedEvent = undefined;
    const stats = c.poll(&out);
    try testing.expectEqual(@as(u32, 1), stats.emitted);
    try testing.expectEqual(@as(u32, 1), stats.rejected);
    try testing.expectEqual(RejectReason.record_too_large, stats.last_reject.?);
    try testing.expectEqual(@as(u64, 555), out[0].timestamp);
}

test "consumer validates score and confidence bounds" {
    const cases = [_]struct { score: i32, conf: u8, want: RejectReason }{
        .{ .score = -1, .conf = 3, .want = .bad_score },
        .{ .score = 1001, .conf = 3, .want = .bad_score },
        .{ .score = 500, .conf = 5, .want = .bad_confidence },
    };
    for (cases) |tc| {
        var buf: [@sizeOf(RingHeader) + 1024]u8 = undefined;
        var w = try RingWriter.init(&buf);
        var c = try RingConsumer.init(&buf);
        // Writer path cannot produce out-of-range values through
        // normal use for confidence, so inject raw for score only
        // when needed (threat_score is i32 in the wire copy).
        _ = w.writePacket(testutil.mkMeta(PKT_META_SIZE + 1, 9, 0, tc.score, tc.conf), "x");
        var out: [1]CapturedEvent = undefined;
        const stats = c.poll(&out);
        try testing.expectEqual(@as(u32, 0), stats.emitted);
        try testing.expectEqual(tc.want, stats.last_reject.?);
    }
}

test "default filter set: five unique enabled layers in order" {
    const set = defaultFilterSet();
    try testing.expectEqual(@as(usize, 5), set.len);
    var seen: [5]bool = .{false} ** 5;
    for (set, 0..) |spec, i| {
        try testing.expect(spec.enabled);
        try testing.expectEqual(@as(u8, @intCast(i)), spec.weight);
        const idx = @intFromEnum(spec.layer);
        try testing.expect(!seen[idx]);
        seen[idx] = true;
        try testing.expect(spec.layer.symbol().len > "FWPM_".len);
    }
    for (seen) |s| try testing.expect(s);
}

const FakeInstaller = struct {
    const max = FILTER_SET_COUNT;
    fail_at: ?u8 = null, // index that fails during add
    added: [max]FilterLayer = undefined,
    deleted: [max]u64 = undefined,
    added_n: usize = 0,
    deleted_n: usize = 0,
    next_id: u64 = 1000,

    fn addFn(ctx: ?*anyopaque, layer: FilterLayer) anyerror!u64 {
        const self: *FakeInstaller = @ptrCast(@alignCast(ctx.?));
        if (self.fail_at) |fi| {
            if (self.added_n == fi) return error.FwpmCallFailed;
        }
        self.added[self.added_n] = layer;
        self.added_n += 1;
        self.next_id += 1;
        return self.next_id - 1;
    }
    fn delFn(ctx: ?*anyopaque, layer: FilterLayer, filter_id: u64) anyerror!void {
        _ = layer;
        const self: *FakeInstaller = @ptrCast(@alignCast(ctx.?));
        self.deleted[self.deleted_n] = filter_id;
        self.deleted_n += 1;
    }
    fn installer(self: *FakeInstaller) Installer {
        return .{ .ctx = self, .addFn = addFn, .delFn = delFn };
    }
};

test "lifecycle: full install success path" {
    var lc = FilterLifecycle{};
    var fake = FakeInstaller{};

    lc.onServiceQuery(true, true);
    try testing.expectEqual(ServicePhase.running, lc.phase);
    lc.onDeviceOpen(true);
    try testing.expectEqual(ServicePhase.device_ready, lc.phase);

    try lc.installFilters(&fake.installer());
    try testing.expectEqual(ServicePhase.filters_installed, lc.phase);
    try testing.expectEqual(@as(usize, 5), lc.installedCount());
    try testing.expectEqual(@as(usize, 5), fake.added_n);
    try testing.expectEqual(@as(usize, 5), lc.log_len);
    // Install order follows the filter set order.
    try testing.expectEqual(FilterLayer.inbound_ippacket_v4, lc.log[0].layer);
    try testing.expectEqual(FilterLayer.ale_flow_established_v4, lc.log[4].layer);
    // Device open before ready must not pass.
    var lc2 = FilterLifecycle{};
    lc2.onServiceQuery(true, true);
    try testing.expectError(LifecycleError.NotReady, lc2.installFilters(&fake.installer()));
}

test "lifecycle: partial failure records mask, remove reverses, guards hold" {
    var lc = FilterLifecycle{};
    var fake = FakeInstaller{ .fail_at = 2 }; // third layer fails

    lc.onServiceQuery(true, true);
    lc.onDeviceOpen(true);
    try testing.expectError(LifecycleError.InstallerFailed, lc.installFilters(&fake.installer()));
    // Mask records exactly the first two layers as live.
    try testing.expect(lc.installed[0]);
    try testing.expect(lc.installed[1]);
    try testing.expect(!lc.installed[2]);
    try testing.expect(!lc.installed[3]);
    try testing.expect(!lc.installed[4]);
    try testing.expectEqual(@as(usize, 2), lc.installedCount());

    // Stop guard: filters live -> refuse.
    try testing.expectError(LifecycleError.FiltersStillInstalled, lc.onServiceStopRequest());

    // Remove: only installed ones, reverse order (ids 1001 then 1000).
    lc.removeFilters(&fake.installer());
    try testing.expectEqual(@as(usize, 2), fake.deleted_n);
    try testing.expectEqual(@as(u64, 1001), fake.deleted[0]);
    try testing.expectEqual(@as(u64, 1000), fake.deleted[1]);
    try testing.expectEqual(@as(usize, 0), lc.installedCount());

    // Double remove is a no-op.
    lc.removeFilters(&fake.installer());
    try testing.expectEqual(@as(usize, 2), fake.deleted_n);

    // Now stop request passes.
    try lc.onServiceStopRequest();
}

test "lifecycle: service death under filters resets mask, missing service detected" {
    var lc = FilterLifecycle{};
    lc.onServiceQuery(true, true);
    lc.onDeviceOpen(true);
    var fake = FakeInstaller{};
    try lc.installFilters(&fake.installer());
    try testing.expectEqual(ServicePhase.filters_installed, lc.phase);

    // Service crashed: query reports found but not started.
    lc.onServiceQuery(true, false);
    try testing.expectEqual(ServicePhase.stopped, lc.phase);
    try testing.expectEqual(@as(usize, 0), lc.installedCount());

    // Service uninstalled entirely.
    lc.onServiceQuery(false, false);
    try testing.expectEqual(ServicePhase.missing, lc.phase);

    // Device open failures are counted but never crash.
    lc.onServiceQuery(true, true);
    lc.onDeviceOpen(false);
    lc.onDeviceOpen(false);
    try testing.expectEqual(@as(u32, 2), lc.device_open_failures);
    try testing.expectEqual(ServicePhase.running, lc.phase);
}
