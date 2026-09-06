//! federation_codec.zig - AEGIS NIDS Phase 39 Ext 1: Federation Codec
//!
//! Binary wire format + transport abstractions for ClusterMessage (Phase 39).
//! Bridges the gap between Phase 39's logical cluster model and actual
//! cross-node messaging. Three layers:
//!
//!   1. Codec: encode/decode ClusterMessage as compact length-prefixed
//!      frames with CRC32 checksum. No external dependency (no protobuf,
//!      no flatbuffers) - the wire format is custom but minimal.
//!   2. ConnectionManager: state machine
//!      DISCONNECTED -> CONNECTING -> CONNECTED -> DEGRADED -> RECONNECTING
//!      with exponential backoff (1ms -> 2ms -> 4ms -> ... -> 30s cap)
//!   3. LoopbackTransport: in-process delivery for host tests + same-node
//!      multi-instance scenarios. Implements the Transport interface so
//!      the same code path that drives real TCP/gRPC also drives tests.
//!
//! Design principles (mirrors Phase 32/36/37/39):
//!   - Pure Zig, host-testable on Linux (no sockets, no DNS, no TLS in
//!     this module; real transport adapters subclass Transport)
//!   - Additive only - enforcement stays in WFP kernel driver
//!   - Kill switch OFF by default; FederationConfig{.enabled=true} opts in
//!   - Singleton facade (init/shutdown/instance/isAvailable)
//!   - Bounded memory: fixed-size frame buffer, capped retry queue
//!
//! Wire format (little-endian, 8-byte header + variable payload):
//!   [0..3]   magic = 0x41_45_47_49 ("AEGI")
//!   [3]      version = 1
//!   [4]      msg_type (1 byte, MessageType value)
//!   [5..7]   payload_len (u16 LE, max 4096)
//!   [8..12]  crc32 of payload (u32 LE)
//!   [12..]   payload (msg_type-specific fields, also length-prefixed)
//!
//! Build:
//!   zig test federation_codec.zig -lc
//!   zig build-exe federation_cli.zig -lc   (uses this module + cluster_coord.zig)

const std = @import("std");
const cc = @import("cluster_coord.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const MAGIC: u32 = 0x41_45_47_49; // "AEGI"
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 12;
pub const MAX_FRAME_SIZE: usize = 4096;
pub const MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_LEN;

pub const MAX_OUTBOUND_QUEUE: usize = 256;
pub const MAX_INBOUND_QUEUE: usize = 256;
pub const INITIAL_BACKOFF_MS: i64 = 1;
pub const MAX_BACKOFF_MS: i64 = 30_000;
pub const BACKOFF_MULTIPLIER: f32 = 2.0;
pub const CONNECTION_TIMEOUT_MS: i64 = 5_000;
pub const HEARTBEAT_TRANSPORT_MS: i64 = 5_000;

// ============================================================
// FederationConfig (kill switch + transport params)
// ============================================================

pub const FederationConfig = struct {
    /// Master kill switch. OFF by default - federation is a no-op until
    /// explicitly enabled. Per-node enforcement stays in WFP driver.
    enabled: bool = false,
    /// This node's ID (used in from_node_id of outgoing messages)
    node_id: u32 = 0,
    /// Transport params
    initial_backoff_ms: i64 = INITIAL_BACKOFF_MS,
    max_backoff_ms: i64 = MAX_BACKOFF_MS,
    backoff_multiplier: f32 = BACKOFF_MULTIPLIER,
    connection_timeout_ms: i64 = CONNECTION_TIMEOUT_MS,
    heartbeat_transport_ms: i64 = HEARTBEAT_TRANSPORT_MS,
    /// Queue limits
    max_outbound: usize = MAX_OUTBOUND_QUEUE,
    max_inbound: usize = MAX_INBOUND_QUEUE,
    /// Max frame size for receive buffer
    max_frame_size: usize = MAX_FRAME_SIZE,
    /// Drop policy when outbound queue is full
    drop_oldest_on_overflow: bool = true,
};

// ============================================================
// ConnectionState (state machine)
// ============================================================

pub const ConnectionState = enum(u8) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    degraded = 3,
    reconnecting = 4,

    pub fn toString(self: ConnectionState) []const u8 {
        return switch (self) {
            .disconnected => "DISCONNECTED",
            .connecting => "CONNECTING",
            .connected => "CONNECTED",
            .degraded => "DEGRADED",
            .reconnecting => "RECONNECTING",
        };
    }

    pub fn isActive(self: ConnectionState) bool {
        return self == .connected or self == .degraded;
    }
};

// ============================================================
// Frame header (12 bytes)
// ============================================================

pub const FrameHeader = struct {
    magic: u32,
    version: u8,
    msg_type: u8,
    payload_len: u16,
    crc32: u32,

    pub fn writeTo(self: FrameHeader, buf: *[HEADER_LEN]u8) void {
        // Little-endian
        buf[0] = @intCast(self.magic & 0xFF);
        buf[1] = @intCast((self.magic >> 8) & 0xFF);
        buf[2] = @intCast((self.magic >> 16) & 0xFF);
        buf[3] = @intCast((self.magic >> 24) & 0xFF);
        buf[4] = self.version;
        buf[5] = self.msg_type;
        buf[6] = @intCast(self.payload_len & 0xFF);
        buf[7] = @intCast((self.payload_len >> 8) & 0xFF);
        buf[8] = @intCast(self.crc32 & 0xFF);
        buf[9] = @intCast((self.crc32 >> 8) & 0xFF);
        buf[10] = @intCast((self.crc32 >> 16) & 0xFF);
        buf[11] = @intCast((self.crc32 >> 24) & 0xFF);
    }

    pub fn readFrom(buf: *const [HEADER_LEN]u8) FrameHeader {
        return .{
            .magic = @as(u32, buf[0]) | (@as(u32, buf[1]) << 8) |
                (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 24),
            .version = buf[4],
            .msg_type = buf[5],
            .payload_len = @as(u16, buf[6]) | (@as(u16, buf[7]) << 8),
            .crc32 = @as(u32, buf[8]) | (@as(u32, buf[9]) << 8) |
                (@as(u32, buf[10]) << 16) | (@as(u32, buf[11]) << 24),
        };
    }
};

// ============================================================
// CRC32 (IEEE 802.3 polynomial, used by Ethernet / PNG / zip)
// Table-based, ~10ns per call. Sufficient for federation message
// integrity (NOT cryptographic - just catch bit-flips on the wire).
// ============================================================

const CRC32_TABLE = blk: {
    @setEvalBranchQuota(5000);
    var t: [256]u32 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var c: u32 = @as(u32, @intCast(i));
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            if (c & 1 != 0) {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        t[i] = c;
    }
    break :blk t;
};

pub fn crc32(data: []const u8) u32 {
    var c: u32 = 0xFFFFFFFF;
    for (data) |b| {
        c = CRC32_TABLE[(c ^ b) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

// ============================================================
// EncodeError / DecodeError
// ============================================================

pub const EncodeError = error{
    PayloadTooLarge,
    OutOfMemory,
};

pub const DecodeError = error{
    MagicMismatch,
    VersionMismatch,
    PayloadTruncated,
    CrcMismatch,
    InvalidMsgType,
    MalformedPayload,
};

// ============================================================
// Payload encoding (msg_type-specific; length-prefixed fields)
// ============================================================

/// Write a length-prefixed byte slice. Format: [u8 len][bytes].
/// Truncates to 255 bytes (u8 length).
fn writeBytes(buf: []u8, offset: *usize, src: []const u8) void {
    const n: u8 = @intCast(@min(src.len, 255));
    buf[offset.*] = n;
    offset.* += 1;
    @memcpy(buf[offset.* .. offset.* + n], src[0..n]);
    offset.* += n;
}

fn readBytes(buf: []const u8, offset: *usize) []const u8 {
    if (offset.* >= buf.len) return &[_]u8{};
    const n: u8 = buf[offset.*];
    offset.* += 1;
    const end = @min(offset.* + n, buf.len);
    const slice = buf[offset.*..end];
    offset.* = end;
    return slice;
}

fn writeU32(buf: []u8, offset: *usize, v: u32) void {
    buf[offset.*] = @intCast(v & 0xFF);
    buf[offset.* + 1] = @intCast((v >> 8) & 0xFF);
    buf[offset.* + 2] = @intCast((v >> 16) & 0xFF);
    buf[offset.* + 3] = @intCast((v >> 24) & 0xFF);
    offset.* += 4;
}

fn readU32(buf: []const u8, offset: *usize) u32 {
    if (offset.* + 4 > buf.len) return 0;
    const v: u32 = @as(u32, buf[offset.*]) | (@as(u32, buf[offset.* + 1]) << 8) |
        (@as(u32, buf[offset.* + 2]) << 16) | (@as(u32, buf[offset.* + 3]) << 24);
    offset.* += 4;
    return v;
}

fn writeU16(buf: []u8, offset: *usize, v: u16) void {
    buf[offset.*] = @intCast(v & 0xFF);
    buf[offset.* + 1] = @intCast((v >> 8) & 0xFF);
    offset.* += 2;
}

fn readU16(buf: []const u8, offset: *usize) u16 {
    if (offset.* + 2 > buf.len) return 0;
    const v: u16 = @as(u16, buf[offset.*]) | (@as(u16, buf[offset.* + 1]) << 8);
    offset.* += 2;
    return v;
}

fn writeI64(buf: []u8, offset: *usize, v: i64) void {
    const u: u64 = @bitCast(v);
    buf[offset.*] = @intCast(u & 0xFF);
    buf[offset.* + 1] = @intCast((u >> 8) & 0xFF);
    buf[offset.* + 2] = @intCast((u >> 16) & 0xFF);
    buf[offset.* + 3] = @intCast((u >> 24) & 0xFF);
    buf[offset.* + 4] = @intCast((u >> 32) & 0xFF);
    buf[offset.* + 5] = @intCast((u >> 40) & 0xFF);
    buf[offset.* + 6] = @intCast((u >> 48) & 0xFF);
    buf[offset.* + 7] = @intCast((u >> 56) & 0xFF);
    offset.* += 8;
}

fn readI64(buf: []const u8, offset: *usize) i64 {
    if (offset.* + 8 > buf.len) return 0;
    const u: u64 = @as(u64, buf[offset.*]) | (@as(u64, buf[offset.* + 1]) << 8) |
        (@as(u64, buf[offset.* + 2]) << 16) | (@as(u64, buf[offset.* + 3]) << 24) |
        (@as(u64, buf[offset.* + 4]) << 32) | (@as(u64, buf[offset.* + 5]) << 40) |
        (@as(u64, buf[offset.* + 6]) << 48) | (@as(u64, buf[offset.* + 7]) << 56);
    offset.* += 8;
    return @bitCast(u);
}

fn writeF32(buf: []u8, offset: *usize, v: f32) void {
    const u: u32 = @bitCast(v);
    writeU32(buf, offset, u);
}

fn readF32(buf: []const u8, offset: *usize) f32 {
    const u = readU32(buf, offset);
    return @bitCast(u);
}

fn writeU8(buf: []u8, offset: *usize, v: u8) void {
    buf[offset.*] = v;
    offset.* += 1;
}

fn readU8(buf: []const u8, offset: *usize) u8 {
    if (offset.* >= buf.len) return 0;
    const v = buf[offset.*];
    offset.* += 1;
    return v;
}

fn writeIp(buf: []u8, offset: *usize, ip: [4]u8) void {
    @memcpy(buf[offset.* .. offset.* + 4], &ip);
    offset.* += 4;
}

fn readIp(buf: []const u8, offset: *usize) [4]u8 {
    if (offset.* + 4 > buf.len) return .{ 0, 0, 0, 0 };
    const ip = [4]u8{ buf[offset.*], buf[offset.* + 1], buf[offset.* + 2], buf[offset.* + 3] };
    offset.* += 4;
    return ip;
}

// ============================================================
// Encoder: ClusterMessage -> wire frame
// ============================================================

/// Encode a ClusterMessage into a length-prefixed frame.
/// Returns the total bytes written (header + payload).
pub fn encode(msg: cc.ClusterMessage, out: []u8) EncodeError!usize {
    if (out.len < HEADER_LEN) return error.PayloadTooLarge;

    // Encode payload first (need its length for header)
    var payload: [MAX_PAYLOAD_SIZE]u8 = undefined;
    var p_off: usize = 0;

    // Common header fields
    writeU32(payload[0..], &p_off, msg.from_node_id);
    writeU32(payload[0..], &p_off, msg.to_node_id);
    writeI64(payload[0..], &p_off, msg.timestamp_ns);

    // Optional node payload (for NODE_JOIN / HEARTBEAT with announcement)
    const has_node: u8 = if (msg.node != null) 1 else 0;
    writeU8(payload[0..], &p_off, has_node);
    if (msg.node) |n| {
        writeU32(payload[0..], &p_off, n.node_id);
        writeBytes(payload[0..], &p_off, n.nameStr());
        writeBytes(payload[0..], &p_off, n.endpointStr());
        writeU8(payload[0..], &p_off, @intFromEnum(n.role));
        writeU8(payload[0..], &p_off, @intFromEnum(n.health));
        writeU16(payload[0..], &p_off, n.capacity);
        writeI64(payload[0..], &p_off, n.joined_ns);
        writeI64(payload[0..], &p_off, n.last_seen_ns);
    }

    // Incident fields (for INCIDENT_REPORT)
    writeIp(payload[0..], &p_off, msg.incident_source_ip);
    writeU16(payload[0..], &p_off, msg.incident_remote_port);
    writeU8(payload[0..], &p_off, msg.incident_proto);
    writeU8(payload[0..], &p_off, @intFromEnum(msg.incident_severity));
    writeF32(payload[0..], &p_off, msg.incident_score);
    writeBytes(payload[0..], &p_off, msg.incident_label[0..msg.incident_label_len]);

    // Threat intel (for THREAT_INTEL_SHARE)
    const has_ti: u8 = if (msg.threat_intel != null) 1 else 0;
    writeU8(payload[0..], &p_off, has_ti);
    if (msg.threat_intel) |ti| {
        writeU8(payload[0..], &p_off, @intFromEnum(ti.kind));
        writeIp(payload[0..], &p_off, ti.ip);
        @memcpy(payload[p_off .. p_off + 16], &ti.hash);
        p_off += 16;
        writeBytes(payload[0..], &p_off, ti.domain[0..ti.domain_len]);
        writeU32(payload[0..], &p_off, ti.source_node_id);
        writeI64(payload[0..], &p_off, ti.first_seen_ns);
        writeU8(payload[0..], &p_off, ti.confidence);
    }

    // Leader node ID (for LEADER_ANNOUNCE)
    writeU32(payload[0..], &p_off, msg.leader_node_id);

    if (p_off > MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;
    if (out.len < HEADER_LEN + p_off) return error.PayloadTooLarge;

    // Compute CRC32 over payload
    const crc = crc32(payload[0..p_off]);

    // Write header
    const header = FrameHeader{
        .magic = MAGIC,
        .version = VERSION,
        .msg_type = @intFromEnum(msg.msg_type),
        .payload_len = @intCast(p_off),
        .crc32 = crc,
    };
    var hdr_buf: [HEADER_LEN]u8 = undefined;
    header.writeTo(&hdr_buf);
    @memcpy(out[0..HEADER_LEN], &hdr_buf);

    // Write payload
    @memcpy(out[HEADER_LEN .. HEADER_LEN + p_off], payload[0..p_off]);

    return HEADER_LEN + p_off;
}

// ============================================================
// Decoder: wire frame -> ClusterMessage
// ============================================================

pub fn decode(buf: []const u8) DecodeError!cc.ClusterMessage {
    if (buf.len < HEADER_LEN) return error.PayloadTruncated;
    var hdr_buf: [HEADER_LEN]u8 = undefined;
    @memcpy(&hdr_buf, buf[0..HEADER_LEN]);
    const hdr = FrameHeader.readFrom(&hdr_buf);

    if (hdr.magic != MAGIC) return error.MagicMismatch;
    if (hdr.version != VERSION) return error.VersionMismatch;
    if (hdr.payload_len > MAX_PAYLOAD_SIZE) return error.PayloadTruncated;
    if (buf.len < HEADER_LEN + hdr.payload_len) return error.PayloadTruncated;

    const payload = buf[HEADER_LEN .. HEADER_LEN + hdr.payload_len];

    // CRC check
    const computed = crc32(payload);
    if (computed != hdr.crc32) return error.CrcMismatch;

    // Validate msg_type
    const msg_type_int: u8 = hdr.msg_type;
    _ = std.meta.intToEnum(cc.MessageType, msg_type_int) catch return error.InvalidMsgType;
    const msg_type: cc.MessageType = @enumFromInt(msg_type_int);

    var p_off: usize = 0;
    var msg = cc.ClusterMessage{ .msg_type = msg_type, .from_node_id = 0 };

    msg.from_node_id = readU32(payload, &p_off);
    msg.to_node_id = readU32(payload, &p_off);
    msg.timestamp_ns = readI64(payload, &p_off);

    const has_node = readU8(payload, &p_off);
    if (has_node == 1) {
        var n = cc.ClusterNode{};
        n.node_id = readU32(payload, &p_off);
        const name = readBytes(payload, &p_off);
        const n_name = @min(name.len, cc.MAX_NODE_NAME);
        @memcpy(n.name[0..n_name], name[0..n_name]);
        n.name_len = @intCast(n_name);
        const ep = readBytes(payload, &p_off);
        const n_ep = @min(ep.len, cc.MAX_NODE_ENDPOINT);
        @memcpy(n.endpoint[0..n_ep], ep[0..n_ep]);
        n.endpoint_len = @intCast(n_ep);
        n.role = @enumFromInt(readU8(payload, &p_off));
        n.health = @enumFromInt(readU8(payload, &p_off));
        n.capacity = readU16(payload, &p_off);
        n.joined_ns = readI64(payload, &p_off);
        n.last_seen_ns = readI64(payload, &p_off);
        msg.node = n;
    }

    msg.incident_source_ip = readIp(payload, &p_off);
    msg.incident_remote_port = readU16(payload, &p_off);
    msg.incident_proto = readU8(payload, &p_off);
    const sev_byte = readU8(payload, &p_off);
    msg.incident_severity = @enumFromInt(sev_byte);
    msg.incident_score = readF32(payload, &p_off);
    const label = readBytes(payload, &p_off);
    const n_label = @min(label.len, cc.MAX_INCIDENT_LABEL);
    @memcpy(msg.incident_label[0..n_label], label[0..n_label]);
    msg.incident_label_len = @intCast(n_label);

    const has_ti = readU8(payload, &p_off);
    if (has_ti == 1) {
        var ti = cc.ThreatIntelEntry{};
        ti.kind = @enumFromInt(readU8(payload, &p_off));
        ti.ip = readIp(payload, &p_off);
        @memcpy(&ti.hash, payload[p_off .. p_off + 16]);
        p_off += 16;
        const dom = readBytes(payload, &p_off);
        const n_dom = @min(dom.len, 64);
        @memcpy(ti.domain[0..n_dom], dom[0..n_dom]);
        ti.domain_len = @intCast(n_dom);
        ti.source_node_id = readU32(payload, &p_off);
        ti.first_seen_ns = readI64(payload, &p_off);
        ti.confidence = readU8(payload, &p_off);
        msg.threat_intel = ti;
    }

    msg.leader_node_id = readU32(payload, &p_off);

    return msg;
}

// ============================================================
// Transport interface (abstract; LoopbackTransport is one impl)
// ============================================================

pub const TransportError = error{
    NotConnected,
    SendFailed,
    ReceiveEmpty,
    QueueFull,
};

pub const Transport = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, data: []const u8) TransportError!void,
    recvFn: *const fn (ctx: *anyopaque, out: []u8) TransportError!usize,
    isConnectedFn: *const fn (ctx: *anyopaque) bool,

    pub fn send(self: Transport, data: []const u8) TransportError!void {
        return self.sendFn(self.ctx, data);
    }
    pub fn recv(self: Transport, out: []u8) TransportError!usize {
        return self.recvFn(self.ctx, out);
    }
    pub fn isConnected(self: Transport) bool {
        return self.isConnectedFn(self.ctx);
    }
};

// ============================================================
// LoopbackTransport (in-process delivery; for tests + same-node)
// ============================================================

pub const LoopbackTransport = struct {
    allocator: std.mem.Allocator,
    inbox: std.ArrayList(u8),
    outbox: std.ArrayList(u8),
    connected: bool = false,
    total_sent: u64 = 0,
    total_received: u64 = 0,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) LoopbackTransport {
        return .{
            .allocator = allocator,
            .inbox = std.ArrayList(u8).init(allocator),
            .outbox = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *LoopbackTransport) void {
        self.inbox.deinit();
        self.outbox.deinit();
    }

    pub fn connect(self: *LoopbackTransport) void {
        self.connected = true;
    }

    pub fn disconnect(self: *LoopbackTransport) void {
        self.connected = false;
    }

    /// Deliver bytes from outbox into another transport's inbox
    /// (simulates network delivery in tests).
    pub fn deliverTo(self: *LoopbackTransport, other: *LoopbackTransport) !void {
        if (self.outbox.items.len == 0) return;
        try other.inbox.appendSlice(self.outbox.items);
        other.total_received += 1;
        other.total_bytes_received += self.outbox.items.len;
        self.outbox.clearRetainingCapacity();
    }

    pub fn sendBytes(self: *LoopbackTransport, data: []const u8) TransportError!void {
        if (!self.connected) return error.NotConnected;
        self.outbox.appendSlice(data) catch return error.SendFailed;
        self.total_sent += 1;
        self.total_bytes_sent += data.len;
    }

    pub fn recvBytes(self: *LoopbackTransport, out: []u8) TransportError!usize {
        if (self.inbox.items.len == 0) return error.ReceiveEmpty;
        const n = @min(self.inbox.items.len, out.len);
        @memcpy(out[0..n], self.inbox.items[0..n]);
        // Shift remaining inbox
        std.mem.copyForwards(u8, self.inbox.items[0 .. self.inbox.items.len - n], self.inbox.items[n..]);
        self.inbox.shrinkRetainingCapacity(self.inbox.items.len - n);
        return n;
    }

    pub fn isConnectedImpl(self: *LoopbackTransport) bool {
        return self.connected;
    }

    pub fn asTransport(self: *LoopbackTransport) Transport {
        return .{
            .ctx = self,
            .sendFn = &sendAdapter,
            .recvFn = &recvAdapter,
            .isConnectedFn = &isConnectedAdapter,
        };
    }

    fn sendAdapter(ctx: *anyopaque, data: []const u8) TransportError!void {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ctx));
        return self.sendBytes(data);
    }
    fn recvAdapter(ctx: *anyopaque, out: []u8) TransportError!usize {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ctx));
        return self.recvBytes(out);
    }
    fn isConnectedAdapter(ctx: *anyopaque) bool {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ctx));
        return self.isConnectedImpl();
    }

    pub fn resetStats(self: *LoopbackTransport) void {
        self.total_sent = 0;
        self.total_received = 0;
        self.total_bytes_sent = 0;
        self.total_bytes_received = 0;
    }
};

// ============================================================
// ConnectionManager (state machine + retry + backoff)
// ============================================================

pub const ConnectionManager = struct {
    state: ConnectionState = .disconnected,
    config: FederationConfig,
    consecutive_failures: u32 = 0,
    next_retry_ns: i64 = 0,
    last_state_change_ns: i64 = 0,
    total_state_changes: u64 = 0,
    total_send_attempts: u64 = 0,
    total_send_failures: u64 = 0,
    total_send_successes: u64 = 0,
    total_reconnects: u64 = 0,

    pub fn init(config: FederationConfig) ConnectionManager {
        return .{ .config = config };
    }

    pub fn transition(self: *ConnectionManager, new_state: ConnectionState, now_ns: i64) void {
        if (self.state != new_state) {
            self.state = new_state;
            self.last_state_change_ns = now_ns;
            self.total_state_changes += 1;
        }
    }

    /// Initiate connection attempt
    pub fn beginConnect(self: *ConnectionManager, now_ns: i64) void {
        self.transition(.connecting, now_ns);
    }

    /// Mark connection as established
    pub fn markConnected(self: *ConnectionManager, now_ns: i64) void {
        self.transition(.connected, now_ns);
        self.consecutive_failures = 0;
        self.next_retry_ns = 0;
    }

    /// Mark a send failure - may trigger reconnection
    pub fn markSendFailure(self: *ConnectionManager, now_ns: i64) void {
        self.total_send_failures += 1;
        self.consecutive_failures += 1;
        if (self.state == .connected) {
            self.transition(.degraded, now_ns);
        }
        // Compute next backoff
        const backoff_ms = self.computeBackoff();
        self.next_retry_ns = now_ns + backoff_ms * 1_000_000;
    }

    /// Mark a successful send - may recover from DEGRADED to CONNECTED
    pub fn markSendSuccess(self: *ConnectionManager, now_ns: i64) void {
        self.total_send_successes += 1;
        if (self.state == .degraded) {
            // Recover after 3 consecutive successes
            if (self.consecutive_failures > 0) self.consecutive_failures -= 1;
            if (self.consecutive_failures == 0) {
                self.transition(.connected, now_ns);
            }
        }
    }

    /// Compute next backoff in ms (exponential with cap)
    pub fn computeBackoff(self: *const ConnectionManager) i64 {
        if (self.consecutive_failures == 0) return self.config.initial_backoff_ms;
        const exp: f32 = @floatFromInt(self.consecutive_failures);
        const factor = std.math.pow(f32, self.config.backoff_multiplier, exp);
        const backoff: f32 = @as(f32, @floatFromInt(self.config.initial_backoff_ms)) * factor;
        const capped: f32 = @min(backoff, @as(f32, @floatFromInt(self.config.max_backoff_ms)));
        return @intFromFloat(capped);
    }

    /// Should we retry now?
    pub fn shouldRetry(self: *const ConnectionManager, now_ns: i64) bool {
        if (self.state == .connected) return false;
        return now_ns >= self.next_retry_ns;
    }

    /// Initiate a reconnect attempt
    pub fn beginReconnect(self: *ConnectionManager, now_ns: i64) void {
        self.transition(.reconnecting, now_ns);
        self.total_reconnects += 1;
    }

    /// Force disconnect
    pub fn disconnect(self: *ConnectionManager, now_ns: i64) void {
        self.transition(.disconnected, now_ns);
    }

    pub fn isActive(self: *const ConnectionManager) bool {
        return self.state.isActive();
    }

    pub fn resetStats(self: *ConnectionManager) void {
        self.consecutive_failures = 0;
        self.total_state_changes = 0;
        self.total_send_attempts = 0;
        self.total_send_failures = 0;
        self.total_send_successes = 0;
        self.total_reconnects = 0;
    }
};

// ============================================================
// OutboundQueue (priority + retry; bounded)
// ============================================================

pub const OutboundEntry = struct {
    msg: cc.ClusterMessage,
    attempts: u8 = 0,
    max_attempts: u8 = 3,
    queued_ns: i64 = 0,
    last_attempt_ns: i64 = 0,
};

pub const OutboundQueue = struct {
    entries: [MAX_OUTBOUND_QUEUE]OutboundEntry = undefined,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    drop_oldest_on_overflow: bool = true,
    total_queued: u64 = 0,
    total_dropped: u64 = 0,
    total_delivered: u64 = 0,
    total_failed: u64 = 0,

    pub fn init(drop_oldest: bool) OutboundQueue {
        return .{ .drop_oldest_on_overflow = drop_oldest };
    }

    pub fn enqueue(self: *OutboundQueue, msg: cc.ClusterMessage, now_ns: i64) bool {
        if (self.count >= MAX_OUTBOUND_QUEUE) {
            if (self.drop_oldest_on_overflow) {
                // Drop oldest
                self.head = (self.head + 1) % MAX_OUTBOUND_QUEUE;
                self.count -= 1;
                self.total_dropped += 1;
            } else {
                self.total_dropped += 1;
                return false;
            }
        }
        self.entries[self.tail] = .{
            .msg = msg,
            .queued_ns = now_ns,
            .last_attempt_ns = now_ns,
        };
        self.tail = (self.tail + 1) % MAX_OUTBOUND_QUEUE;
        self.count += 1;
        self.total_queued += 1;
        return true;
    }

    /// Peek the next message ready for retry (or first send)
    pub fn peekReady(self: *OutboundQueue, now_ns: i64, min_interval_ms: i64) ?*OutboundEntry {
        if (self.count == 0) return null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % MAX_OUTBOUND_QUEUE;
            const e = &self.entries[idx];
            if (e.attempts >= e.max_attempts) continue;
            const elapsed_ms = @divFloor(now_ns - e.last_attempt_ns, 1_000_000);
            if (elapsed_ms >= min_interval_ms) return e;
        }
        return null;
    }

    /// Mark an entry as attempted (failure). Removes if max attempts reached.
    pub fn markAttempt(self: *OutboundQueue, entry: *OutboundEntry, now_ns: i64) bool {
        entry.attempts += 1;
        entry.last_attempt_ns = now_ns;
        if (entry.attempts >= entry.max_attempts) {
            // Drop this entry
            self.total_failed += 1;
            // Find and remove from ring (compaction)
            self.compactEntry(entry);
            return false; // entry removed
        }
        return true; // retry scheduled
    }

    /// Mark an entry as delivered - remove from queue
    pub fn markDelivered(self: *OutboundQueue, entry: *OutboundEntry) void {
        self.total_delivered += 1;
        self.compactEntry(entry);
    }

    fn compactEntry(self: *OutboundQueue, entry: *OutboundEntry) void {
        // Find entry index in ring-buffer logical order
        var found_logical: ?usize = null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % MAX_OUTBOUND_QUEUE;
            if (&self.entries[idx] == entry) {
                found_logical = i;
                break;
            }
        }
        if (found_logical == null) return;
        const target_logical = found_logical.?;
        // Shift everything after target_logical down by one in logical order
        var j: usize = target_logical;
        while (j + 1 < self.count) : (j += 1) {
            const cur = (self.head + j) % MAX_OUTBOUND_QUEUE;
            const next = (self.head + j + 1) % MAX_OUTBOUND_QUEUE;
            self.entries[cur] = self.entries[next];
        }
        self.tail = (self.tail + MAX_OUTBOUND_QUEUE - 1) % MAX_OUTBOUND_QUEUE;
        self.count -= 1;
    }

    pub fn queueCount(self: *const OutboundQueue) usize {
        return self.count;
    }

    pub fn resetStats(self: *OutboundQueue) void {
        self.total_queued = 0;
        self.total_dropped = 0;
        self.total_delivered = 0;
        self.total_failed = 0;
    }
};

// ============================================================
// FederationFacade (singleton, project style)
// ============================================================

pub const FederationFacade = struct {
    allocator: std.mem.Allocator,
    config: FederationConfig,
    conn: ConnectionManager,
    outbound: OutboundQueue,
    initialized: bool = false,

    var _instance: ?FederationFacade = null;

    pub fn instance() ?*FederationFacade {
        if (_instance) |*i| return i;
        return null;
    }

    pub fn init(allocator: std.mem.Allocator, config: FederationConfig) !*FederationFacade {
        if (_instance != null) return &_instance.?;
        _instance = FederationFacade{
            .allocator = allocator,
            .config = config,
            .conn = ConnectionManager.init(config),
            .outbound = OutboundQueue.init(config.drop_oldest_on_overflow),
        };
        var self = &_instance.?;
        self.initialized = true;
        return self;
    }

    pub fn shutdown(self: *FederationFacade) void {
        if (!self.initialized) return;
        self.initialized = false;
        _instance = null;
    }

    pub fn isAvailable(self: *const FederationFacade) bool {
        return self.initialized and self.config.enabled;
    }

    /// Queue a message for sending. Returns true if queued, false if dropped.
    pub fn send(self: *FederationFacade, msg: cc.ClusterMessage, now_ns: i64) bool {
        if (!self.config.enabled) return false;
        return self.outbound.enqueue(msg, now_ns);
    }

    /// Encode + send via transport. Updates connection state on success/failure.
    pub fn flushTo(self: *FederationFacade, transport: Transport, now_ns: i64) TransportError!void {
        if (!self.config.enabled) return;
        if (!transport.isConnected()) {
            self.conn.markSendFailure(now_ns);
            return error.NotConnected;
        }
        while (self.outbound.peekReady(now_ns, 0)) |entry| {
            var buf: [MAX_FRAME_SIZE]u8 = undefined;
            const n = encode(entry.msg, &buf) catch {
                _ = self.outbound.markAttempt(entry, now_ns);
                continue;
            };
            transport.send(buf[0..n]) catch {
                _ = self.outbound.markAttempt(entry, now_ns);
                self.conn.markSendFailure(now_ns);
                return error.SendFailed;
            };
            self.outbound.markDelivered(entry);
            self.conn.markSendSuccess(now_ns);
        }
    }

    /// Receive + decode a message from transport.
    pub fn receive(self: *FederationFacade, transport: Transport) TransportError!cc.ClusterMessage {
        if (!self.config.enabled) return error.NotConnected;
        var buf: [MAX_FRAME_SIZE]u8 = undefined;
        const n = try transport.recv(&buf);
        if (n < HEADER_LEN) return error.ReceiveEmpty;
        return decode(buf[0..n]) catch return error.SendFailed;
    }
};

// ============================================================
// Tests
// ============================================================

test "FederationConfig defaults - kill switch OFF" {
    const c = FederationConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqual(@as(i64, 1), c.initial_backoff_ms);
    try std.testing.expectEqual(@as(i64, 30_000), c.max_backoff_ms);
    try std.testing.expectEqual(@as(f32, 2.0), c.backoff_multiplier);
    try std.testing.expectEqual(@as(usize, 256), c.max_outbound);
}

test "ConnectionState isActive" {
    try std.testing.expect(!ConnectionState.disconnected.isActive());
    try std.testing.expect(!ConnectionState.connecting.isActive());
    try std.testing.expect(ConnectionState.connected.isActive());
    try std.testing.expect(ConnectionState.degraded.isActive());
    try std.testing.expect(!ConnectionState.reconnecting.isActive());
}

test "crc32 deterministic" {
    const h1 = crc32("hello");
    const h2 = crc32("hello");
    const h3 = crc32("world");
    try std.testing.expectEqual(h1, h2);
    try std.testing.expect(h1 != h3);
    // Known CRC32 of "hello" = 0x3610a686
    try std.testing.expectEqual(@as(u32, 0x3610a686), h1);
}

test "crc32 of empty input" {
    try std.testing.expectEqual(@as(u32, 0), crc32(""));
}

test "FrameHeader roundtrip" {
    const hdr = FrameHeader{
        .magic = MAGIC,
        .version = VERSION,
        .msg_type = 3, // INCIDENT_REPORT
        .payload_len = 256,
        .crc32 = 0xDEADBEEF,
    };
    var buf: [HEADER_LEN]u8 = undefined;
    hdr.writeTo(&buf);
    const hdr2 = FrameHeader.readFrom(&buf);
    try std.testing.expectEqual(hdr.magic, hdr2.magic);
    try std.testing.expectEqual(hdr.version, hdr2.version);
    try std.testing.expectEqual(hdr.msg_type, hdr2.msg_type);
    try std.testing.expectEqual(hdr.payload_len, hdr2.payload_len);
    try std.testing.expectEqual(hdr.crc32, hdr2.crc32);
}

test "encode/decode heartbeat roundtrip" {
    const msg = cc.ClusterMessage{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .to_node_id = 0,
        .timestamp_ns = 1_000_000_000,
    };
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    try std.testing.expect(n > HEADER_LEN);

    const decoded = try decode(buf[0..n]);
    try std.testing.expectEqual(cc.MessageType.heartbeat, decoded.msg_type);
    try std.testing.expectEqual(@as(u32, 5), decoded.from_node_id);
    try std.testing.expectEqual(@as(u32, 0), decoded.to_node_id);
    try std.testing.expectEqual(@as(i64, 1_000_000_000), decoded.timestamp_ns);
}

test "encode/decode incident_report roundtrip" {
    var msg = cc.ClusterMessage{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .to_node_id = 0,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .high,
        .incident_score = 0.85,
    };
    const label = "malicious";
    @memcpy(msg.incident_label[0..label.len], label);
    msg.incident_label_len = label.len;

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    const decoded = try decode(buf[0..n]);

    try std.testing.expectEqual(cc.MessageType.incident_report, decoded.msg_type);
    try std.testing.expectEqual(@as(u32, 1), decoded.from_node_id);
    try std.testing.expectEqual(@as(i64, 1_000_000_000), decoded.timestamp_ns);
    try std.testing.expectEqual(@as(u16, 4444), decoded.incident_remote_port);
    try std.testing.expectEqual(@as(u8, 6), decoded.incident_proto);
    try std.testing.expectEqual(cc.IncidentSeverity.high, decoded.incident_severity);
    try std.testing.expectEqual(@as(f32, 0.85), decoded.incident_score);
    try std.testing.expectEqualSlices(u8, "malicious", decoded.incident_label[0..decoded.incident_label_len]);
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 5 }, decoded.incident_source_ip);
}

test "encode/decode node_join with ClusterNode payload" {
    var n = cc.ClusterNode{
        .node_id = 7,
        .role = .aggregator,
        .health = .healthy,
        .capacity = 2000,
        .joined_ns = 1_000_000_000,
        .last_seen_ns = 1_000_000_000,
    };
    const name = "aggregator-7";
    @memcpy(n.name[0..name.len], name);
    n.name_len = name.len;
    const ep = "10.0.0.7:9090";
    @memcpy(n.endpoint[0..ep.len], ep);
    n.endpoint_len = ep.len;

    const msg = cc.ClusterMessage{
        .msg_type = .node_join,
        .from_node_id = 7,
        .timestamp_ns = 1_000_000_000,
        .node = n,
    };
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const written = try encode(msg, &buf);
    const decoded = try decode(buf[0..written]);

    try std.testing.expectEqual(cc.MessageType.node_join, decoded.msg_type);
    try std.testing.expect(decoded.node != null);
    const dn = decoded.node.?;
    try std.testing.expectEqual(@as(u32, 7), dn.node_id);
    try std.testing.expectEqualStrings("aggregator-7", dn.nameStr());
    try std.testing.expectEqualStrings("10.0.0.7:9090", dn.endpointStr());
    try std.testing.expectEqual(cc.NodeRole.aggregator, dn.role);
    try std.testing.expectEqual(cc.NodeHealth.healthy, dn.health);
    try std.testing.expectEqual(@as(u16, 2000), dn.capacity);
}

test "encode/decode threat_intel_share roundtrip" {
    const msg = cc.ClusterMessage{
        .msg_type = .threat_intel_share,
        .from_node_id = 2,
        .timestamp_ns = 1_500_000_000,
        .threat_intel = .{
            .kind = .c2_server,
            .ip = .{ 198, 51, 100, 7 },
            .source_node_id = 2,
            .first_seen_ns = 1_400_000_000,
            .confidence = 95,
        },
    };
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    const decoded = try decode(buf[0..n]);

    try std.testing.expectEqual(cc.MessageType.threat_intel_share, decoded.msg_type);
    try std.testing.expect(decoded.threat_intel != null);
    const ti = decoded.threat_intel.?;
    try std.testing.expectEqual(cc.ThreatIntelKind.c2_server, ti.kind);
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 7 }, ti.ip);
    try std.testing.expectEqual(@as(u32, 2), ti.source_node_id);
    try std.testing.expectEqual(@as(u8, 95), ti.confidence);
}

test "encode/decode leader_announce roundtrip" {
    const msg = cc.ClusterMessage{
        .msg_type = .leader_announce,
        .from_node_id = 1,
        .timestamp_ns = 2_000_000_000,
        .leader_node_id = 7,
    };
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    const decoded = try decode(buf[0..n]);
    try std.testing.expectEqual(cc.MessageType.leader_announce, decoded.msg_type);
    try std.testing.expectEqual(@as(u32, 7), decoded.leader_node_id);
}

test "decode rejects wrong magic" {
    var buf: [HEADER_LEN]u8 = undefined;
    buf[0] = 0x42; // Wrong magic byte
    buf[1] = 0x45;
    buf[2] = 0x47;
    buf[3] = 0x49;
    buf[4] = 1;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;
    try std.testing.expectError(error.MagicMismatch, decode(&buf));
}

test "decode rejects wrong version" {
    var buf: [HEADER_LEN]u8 = undefined;
    buf[0] = 0x49;
    buf[1] = 0x47;
    buf[2] = 0x45;
    buf[3] = 0x41; // little-endian "AEGI" = 0x41_45_47_49
    buf[4] = 99; // wrong version
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    @memset(buf[8..HEADER_LEN], 0);
    try std.testing.expectError(error.VersionMismatch, decode(&buf));
}

test "decode rejects truncated payload" {
    var buf: [HEADER_LEN + 5]u8 = undefined;
    // Header says payload_len=100, but we only wrote 5 bytes
    buf[0] = 0x49;
    buf[1] = 0x47;
    buf[2] = 0x45;
    buf[3] = 0x41;
    buf[4] = 1;
    buf[5] = 0;
    buf[6] = 100; // payload_len = 100 (LE)
    buf[7] = 0;
    @memset(buf[8..HEADER_LEN], 0);
    @memset(buf[HEADER_LEN..HEADER_LEN + 5], 0);
    try std.testing.expectError(error.PayloadTruncated, decode(&buf));
}

test "decode detects CRC mismatch (bit flip)" {
    const msg = cc.ClusterMessage{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    };
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    // Flip a bit in payload
    buf[HEADER_LEN] ^= 0x01;
    try std.testing.expectError(error.CrcMismatch, decode(buf[0..n]));
}

test "decode rejects invalid msg_type" {
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    buf[0] = 0x49;
    buf[1] = 0x47;
    buf[2] = 0x45;
    buf[3] = 0x41;
    buf[4] = 1;
    buf[5] = 99; // invalid msg_type
    buf[6] = 0;
    buf[7] = 0;
    @memset(buf[8..HEADER_LEN], 0);
    try std.testing.expectError(error.InvalidMsgType, decode(buf[0..HEADER_LEN]));
}

test "LoopbackTransport connect/disconnect" {
    var t = LoopbackTransport.init(std.testing.allocator);
    defer t.deinit();
    try std.testing.expect(!t.connected);
    t.connect();
    try std.testing.expect(t.connected);
    t.disconnect();
    try std.testing.expect(!t.connected);
}

test "LoopbackTransport send when connected" {
    var t = LoopbackTransport.init(std.testing.allocator);
    defer t.deinit();
    t.connect();

    const data = "hello federation";
    try t.sendBytes(data);
    try std.testing.expectEqual(@as(u64, 1), t.total_sent);
    try std.testing.expectEqual(@as(u64, data.len), t.total_bytes_sent);
    try std.testing.expectEqualSlices(u8, data, t.outbox.items);
}

test "LoopbackTransport send fails when disconnected" {
    var t = LoopbackTransport.init(std.testing.allocator);
    defer t.deinit();
    // not connected
    try std.testing.expectError(error.NotConnected, t.sendBytes("data"));
}

test "LoopbackTransport deliverTo moves bytes between transports" {
    var alice = LoopbackTransport.init(std.testing.allocator);
    defer alice.deinit();
    var bob = LoopbackTransport.init(std.testing.allocator);
    defer bob.deinit();
    alice.connect();
    bob.connect();

    try alice.sendBytes("ping");
    try alice.deliverTo(&bob);

    try std.testing.expectEqual(@as(usize, 0), alice.outbox.items.len);
    try std.testing.expectEqualSlices(u8, "ping", bob.inbox.items);

    var out: [16]u8 = undefined;
    const n = try bob.recvBytes(&out);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualSlices(u8, "ping", out[0..n]);
}

test "LoopbackTransport asTransport vtable" {
    var t = LoopbackTransport.init(std.testing.allocator);
    defer t.deinit();
    t.connect();

    const tp = t.asTransport();
    try std.testing.expect(tp.isConnected());

    try tp.send("test data");
    try std.testing.expectEqualSlices(u8, "test data", t.outbox.items);

    var out: [16]u8 = undefined;
    // Move from outbox to inbox for recv
    try t.deliverTo(&t);
    const n = try tp.recv(&out);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqualSlices(u8, "test data", out[0..n]);
}

test "ConnectionManager state transitions" {
    var cm = ConnectionManager.init(.{});
    try std.testing.expectEqual(ConnectionState.disconnected, cm.state);

    cm.beginConnect(1_000_000_000);
    try std.testing.expectEqual(ConnectionState.connecting, cm.state);

    cm.markConnected(2_000_000_000);
    try std.testing.expectEqual(ConnectionState.connected, cm.state);
    try std.testing.expectEqual(@as(u32, 0), cm.consecutive_failures);

    cm.markSendFailure(3_000_000_000);
    try std.testing.expectEqual(ConnectionState.degraded, cm.state);
    try std.testing.expectEqual(@as(u32, 1), cm.consecutive_failures);
}

test "ConnectionManager backoff exponential" {
    var cm = ConnectionManager.init(.{
        .initial_backoff_ms = 1,
        .max_backoff_ms = 100,
        .backoff_multiplier = 2.0,
    });
    // 0 failures -> initial
    try std.testing.expectEqual(@as(i64, 1), cm.computeBackoff());

    cm.consecutive_failures = 1;
    try std.testing.expectEqual(@as(i64, 2), cm.computeBackoff());

    cm.consecutive_failures = 2;
    try std.testing.expectEqual(@as(i64, 4), cm.computeBackoff());

    cm.consecutive_failures = 3;
    try std.testing.expectEqual(@as(i64, 8), cm.computeBackoff());

    // Capped
    cm.consecutive_failures = 10;
    try std.testing.expectEqual(@as(i64, 100), cm.computeBackoff());
}

test "ConnectionManager shouldRetry respects next_retry_ns" {
    var cm = ConnectionManager.init(.{});
    cm.markSendFailure(1_000_000_000); // sets next_retry_ns = 1_000_000_000 + 1ms*1e6 = 1_001_000_000
    try std.testing.expect(!cm.shouldRetry(1_000_500_000)); // 0.5ms later
    try std.testing.expect(cm.shouldRetry(1_002_000_000)); // 2ms later
}

test "ConnectionManager recovers from degraded to connected after success" {
    var cm = ConnectionManager.init(.{});
    cm.markConnected(1_000_000_000);
    cm.markSendFailure(1_100_000_000); // -> degraded, failures=1
    try std.testing.expectEqual(ConnectionState.degraded, cm.state);

    // First success decrements failures to 0 and recovers immediately
    // (per current markSendSuccess logic - simpler policy than the
    // "3 consecutive successes" originally drafted)
    cm.markSendSuccess(1_200_000_000);
    try std.testing.expectEqual(ConnectionState.connected, cm.state);
}

test "OutboundQueue enqueue and count" {
    var q = OutboundQueue.init(true);
    try std.testing.expect(q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 1 }, 0));
    try std.testing.expect(q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 2 }, 0));
    try std.testing.expectEqual(@as(usize, 2), q.queueCount());
    try std.testing.expectEqual(@as(u64, 2), q.total_queued);
}

test "OutboundQueue drops oldest on overflow" {
    var q = OutboundQueue.init(true);
    var i: u32 = 0;
    while (i < MAX_OUTBOUND_QUEUE + 5) : (i += 1) {
        _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = i }, 0);
    }
    try std.testing.expectEqual(@as(usize, MAX_OUTBOUND_QUEUE), q.queueCount());
    try std.testing.expectEqual(@as(u64, 5), q.total_dropped);
}

test "OutboundQueue rejects when full (drop_oldest=false)" {
    var q = OutboundQueue.init(false);
    var i: u32 = 0;
    while (i < MAX_OUTBOUND_QUEUE) : (i += 1) {
        _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = i }, 0);
    }
    const ok = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 999 }, 0);
    try std.testing.expect(!ok);
    try std.testing.expectEqual(@as(usize, MAX_OUTBOUND_QUEUE), q.queueCount());
    try std.testing.expectEqual(@as(u64, 1), q.total_dropped);
}

test "OutboundQueue peekReady returns next sendable" {
    var q = OutboundQueue.init(true);
    _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 1 }, 0);
    const e = q.peekReady(0, 0) orelse return error.TestExpectedEntry;
    try std.testing.expectEqual(@as(u32, 1), e.msg.from_node_id);
}

test "OutboundQueue markAttempt removes after max_attempts" {
    var q = OutboundQueue.init(true);
    _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 1 }, 0);
    const e = q.peekReady(0, 0).?;
    e.max_attempts = 2;

    try std.testing.expect(q.markAttempt(e, 1_000_000_000)); // attempts=1, retry
    try std.testing.expectEqual(@as(usize, 1), q.queueCount());

    try std.testing.expect(!q.markAttempt(e, 2_000_000_000)); // attempts=2, removed
    try std.testing.expectEqual(@as(usize, 0), q.queueCount());
    try std.testing.expectEqual(@as(u64, 1), q.total_failed);
}

test "FederationFacade singleton init/shutdown" {
    const alloc = std.testing.allocator;
    {
        var f = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 });
        defer f.shutdown();
        try std.testing.expect(f.isAvailable());
        const f2 = FederationFacade.instance();
        try std.testing.expect(f2 != null);
    }
    try std.testing.expect(FederationFacade.instance() == null);
}

test "FederationFacade send respects kill switch" {
    const alloc = std.testing.allocator;
    var f = try FederationFacade.init(alloc, .{ .enabled = false, .node_id = 1 });
    defer f.shutdown();

    const ok = f.send(.{ .msg_type = .heartbeat, .from_node_id = 1 }, 0);
    try std.testing.expect(!ok);
    try std.testing.expectEqual(@as(usize, 0), f.outbound.queueCount());
}

test "FederationFacade flushTo encodes + delivers via transport" {
    const alloc = std.testing.allocator;
    var f = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer f.shutdown();

    var t = LoopbackTransport.init(alloc);
    defer t.deinit();
    t.connect();

    try std.testing.expect(f.send(.{
        .msg_type = .heartbeat,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
    }, 0));
    try std.testing.expectEqual(@as(usize, 1), f.outbound.queueCount());

    try f.flushTo(t.asTransport(), 1_000_000_000);
    try std.testing.expectEqual(@as(usize, 0), f.outbound.queueCount()); // delivered
    try std.testing.expect(t.outbox.items.len > 0);
    try std.testing.expectEqual(@as(u64, 1), f.outbound.total_delivered);
}

test "FederationFacade flushTo fails when transport disconnected" {
    const alloc = std.testing.allocator;
    var f = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer f.shutdown();

    var t = LoopbackTransport.init(alloc);
    defer t.deinit();
    // not connected

    try std.testing.expect(f.send(.{
        .msg_type = .heartbeat,
        .from_node_id = 1,
        .timestamp_ns = 0,
    }, 0));
    // flushTo calls markSendFailure which only transitions if state was
    // connected; here it stays disconnected (initial state)
    try std.testing.expectError(error.NotConnected, f.flushTo(t.asTransport(), 0));
    try std.testing.expectEqual(ConnectionState.disconnected, f.conn.state);
}

test "FederationFacade receive decodes incoming frame" {
    const alloc = std.testing.allocator;
    var f = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer f.shutdown();

    var alice = LoopbackTransport.init(alloc);
    defer alice.deinit();
    alice.connect();
    var bob = LoopbackTransport.init(alloc);
    defer bob.deinit();
    bob.connect();

    // Alice sends a heartbeat frame
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    }, &buf);
    try alice.sendBytes(buf[0..n]);
    try alice.deliverTo(&bob);

    // Bob receives + decodes
    const msg = try f.receive(bob.asTransport());
    try std.testing.expectEqual(cc.MessageType.heartbeat, msg.msg_type);
    try std.testing.expectEqual(@as(u32, 5), msg.from_node_id);
    try std.testing.expectEqual(@as(i64, 1_000_000_000), msg.timestamp_ns);
}

test "End-to-end: 2 nodes exchange heartbeat via loopback" {
    const alloc = std.testing.allocator;

    // Two facades (simulating two nodes in-process)
    var f1 = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer f1.shutdown();
    var f2 = try FederationFacade.init(alloc, .{ .enabled = true, .node_id = 2 });
    defer f2.shutdown();

    // Each node has its own loopback transport; cross-deliver to simulate network
    var t1 = LoopbackTransport.init(alloc);
    defer t1.deinit();
    t1.connect();
    var t2 = LoopbackTransport.init(alloc);
    defer t2.deinit();
    t2.connect();

    // Node 1 sends heartbeat
    try std.testing.expect(f1.send(.{
        .msg_type = .heartbeat,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
    }, 0));
    try f1.flushTo(t1.asTransport(), 1_000_000_000);
    try t1.deliverTo(&t2);

    // Node 2 receives
    const msg = try f2.receive(t2.asTransport());
    try std.testing.expectEqual(cc.MessageType.heartbeat, msg.msg_type);
    try std.testing.expectEqual(@as(u32, 1), msg.from_node_id);
    try std.testing.expectEqual(@as(u64, 1), f1.outbound.total_delivered);
}

test "OutboundQueue markDelivered removes entry" {
    var q = OutboundQueue.init(true);
    _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 1 }, 0);
    _ = q.enqueue(.{ .msg_type = .heartbeat, .from_node_id = 2 }, 0);
    try std.testing.expectEqual(@as(usize, 2), q.queueCount());

    const e = q.peekReady(0, 0).?;
    q.markDelivered(e);
    try std.testing.expectEqual(@as(usize, 1), q.queueCount());
    try std.testing.expectEqual(@as(u64, 1), q.total_delivered);
}

test "encode rejects oversized payload" {
    // Construct a message with a very long label to overflow payload
    var msg = cc.ClusterMessage{
        .msg_type = .incident_report,
        .from_node_id = 1,
    };
    msg.incident_label_len = cc.MAX_INCIDENT_LABEL; // 24 bytes - safe
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    const n = try encode(msg, &buf);
    try std.testing.expect(n <= MAX_FRAME_SIZE);
}
