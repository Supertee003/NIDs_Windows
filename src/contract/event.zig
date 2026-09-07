// I02 - Canonical Event Schema
// AEGIS NIDS v5.0+ â€” Fixed-layout IPC event (76 bytes, cache-line friendly)
//
// This struct is the *contract* between capture, detection, policy, forensic,
// and federation. It MUST remain binary-stable across releases.

const std = @import("std");
const builtin = @import("builtin");

pub const EVENT_MAGIC: u32 = 0xAE615011;
pub const EVENT_VERSION: u16 = 5;
pub const EVENT_SIZE: usize = 80;

pub const EventKind = enum(u8) {
    packet_captured = 1,
    flow_created = 2,
    flow_expired = 3,
    flow_teardown = 4,
    arp_seen = 5,
    dns_query = 20,
    dns_response = 21,
    http_request = 22,
    http_response = 23,
    tls_hello = 24,
    tls_certificate = 25,
    smb_negotiate = 26,
    rdp_connect = 27,
    kerberos_asreq = 28,
    kerberos_asrep = 29,
    signature_match = 40,
    anomaly_detected = 41,
    protocol_anomaly = 42,
    correlation_match = 43,
    threat_incident = 44,
    policy_decision = 60,
    action_block = 61,
    action_allow = 62,
    action_rate_limit = 63,
    action_log = 64,
    etw_process_create = 70,
    etw_process_exit = 71,
    etw_image_load = 72,
    etw_file_write = 73,
    etw_registry_set = 74,
    fim_change = 75,
    reg_change = 76,
    injection_detected = 77,
    federation_heartbeat = 90,
    federation_aggregate = 91,
    federation_leader_change = 92,
    system_start = 100,
    system_shutdown = 101,
    system_error = 102,
    _,
};

pub const EventSeverity = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    notice = 3,
    warning = 4,
    @"error" = 5,
    critical = 6,
    alert = 7,
    emergency = 8,
};

pub const EventFate = enum(u8) {
    unknown = 0,
    observed = 1,
    tracked = 2,
    flagged = 3,
    blocked = 4,
    rate_limited = 5,
    quarantined = 6,
    escalated = 7,
    dropped = 8,
    _,
};

pub const EventSource = enum(u8) {
    capture_npcap = 1,
    capture_etw = 2,
    capture_fim = 3,
    capture_registry = 4,
    detection_sig = 10,
    detection_anom = 11,
    detection_corr = 12,
    policy = 20,
    federation = 30,
    system = 99,
    _,
};

pub const IpcEvent = extern struct {
    magic: u32,
    version: u16,
    kind: EventKind,
    severity: EventSeverity,
    source: EventSource,
    fate: EventFate,
    flags: u32,
    timestamp_ns: u64,
    event_id: u64,
    trace_id: u64,
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    iface: u8,
    rule_id: u32,
    policy_id: u32,
    payload_len: u32,
    payload_hash: u32,

    comptime {
        if (@sizeOf(IpcEvent) != EVENT_SIZE) {
            @compileError("IpcEvent must be exactly 76 bytes");
        }
    }

    pub fn init(kind: EventKind) IpcEvent {
        return .{
            .magic = EVENT_MAGIC,
            .version = EVENT_VERSION,
            .kind = kind,
            .severity = .info,
            .source = .system,
            .fate = .unknown,
            .flags = 0,
            .timestamp_ns = 0,
            .event_id = 0,
            .trace_id = 0,
            .flow_id = 0,
            .src_ip = 0,
            .dst_ip = 0,
            .src_port = 0,
            .dst_port = 0,
            .protocol = 0,
            .iface = 0,
            .rule_id = 0,
            .policy_id = 0,
            .payload_len = 0,
            .payload_hash = 0,
        };
    }

    pub fn validate(self: *const IpcEvent) bool {
        return self.magic == EVENT_MAGIC and self.version == EVENT_VERSION;
    }

    pub fn now(self: *IpcEvent) void {
        self.timestamp_ns = @intCast(std.time.nanoTimestamp());
    }

    pub fn setPayload(self: *IpcEvent, payload: []const u8) void {
        self.payload_len = @intCast(payload.len);
        self.payload_hash = fnv1a32(payload);
    }

    pub fn isBlocked(self: *const IpcEvent) bool {
        return self.fate == .blocked or self.fate == .quarantined;
    }

    pub fn isThreat(self: *const IpcEvent) bool {
        return @intFromEnum(self.severity) >= @intFromEnum(EventSeverity.alert);
    }
};

pub fn fnv1a32(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (data) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

test "IpcEvent is 80 bytes" {
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(IpcEvent));
}

test "IpcEvent init and validate" {
    var e = IpcEvent.init(.packet_captured);
    try std.testing.expect(e.validate());
    e.now();
    try std.testing.expect(e.timestamp_ns > 0);
}

test "FNV-1a 32-bit known vectors" {
    try std.testing.expectEqual(@as(u32, 0x811c9dc5), fnv1a32(""));
    try std.testing.expectEqual(@as(u32, 0xe40c292c), fnv1a32("a"));
    try std.testing.expectEqual(@as(u32, 0xbf9cf968), fnv1a32("foobar"));
}

test "EventKind round-trip" {
    const k: EventKind = .dns_query;
    const v: u8 = @intFromEnum(k);
    const back: EventKind = @enumFromInt(v);
    try std.testing.expectEqual(k, back);
}
