//! Bounded L7 classification for WFP payloads.
//!
//! This is metadata only: it does not make policy or enforcement decisions.
//! The result is encoded in CanonicalEvent.context_flags so the frozen v1
//! event layout is unchanged.

const std = @import("std");

pub const ContextFlag = struct {
    pub const dns: u32 = 1 << 8;
    pub const http: u32 = 1 << 9;
    pub const tls: u32 = 1 << 10;
    pub const smb: u32 = 1 << 11;
    pub const rdp: u32 = 1 << 12;
    pub const kerberos: u32 = 1 << 13;
};

pub const Protocol = enum {
    unknown,
    dns,
    http,
    tls,
    smb,
    rdp,
    kerberos,
};

pub const Classification = struct {
    protocol: Protocol = .unknown,
    context_flag: u32 = 0,

    pub fn known(self: Classification) bool {
        return self.protocol != .unknown;
    }
};

fn startsWith(payload: []const u8, prefix: []const u8) bool {
    return payload.len >= prefix.len and std.mem.eql(u8, payload[0..prefix.len], prefix);
}

fn isHttpMethod(payload: []const u8) bool {
    const methods = [_][]const u8{
        "GET ", "POST ", "PUT ", "HEAD ", "PATCH ", "DELETE ", "OPTIONS ", "CONNECT ",
    };
    for (methods) |method| {
        if (startsWith(payload, method)) return true;
    }
    return false;
}

/// Classify only strong, bounded signatures. Ports are hints, never proof.
pub fn classify(payload: []const u8, dst_port: u16, protocol: u8) Classification {
    if (protocol == 17 and (dst_port == 53 or dst_port == 5353 or dst_port == 5355) and payload.len >= 12) {
        return .{ .protocol = .dns, .context_flag = ContextFlag.dns };
    }
    if (protocol == 6 and isHttpMethod(payload)) {
        return .{ .protocol = .http, .context_flag = ContextFlag.http };
    }
    if (protocol == 6 and payload.len >= 3 and payload[0] == 0x16 and payload[1] == 0x03 and payload[2] <= 0x04) {
        return .{ .protocol = .tls, .context_flag = ContextFlag.tls };
    }
    if (startsWith(payload, "\xffSMB") or startsWith(payload, "\xfeSMB") or startsWith(payload, "\xfdSMB")) {
        return .{ .protocol = .smb, .context_flag = ContextFlag.smb };
    }
    if (protocol == 6 and dst_port == 3389 and payload.len >= 4 and payload[0] == 0x03 and payload[1] == 0x00) {
        return .{ .protocol = .rdp, .context_flag = ContextFlag.rdp };
    }
    if (payload.len >= 4 and payload[0] == 0x6a and payload[1] == 0x82) {
        return .{ .protocol = .kerberos, .context_flag = ContextFlag.kerberos };
    }
    return .{};
}

test "classifies strong L7 signatures without changing unknown payloads" {
    try std.testing.expectEqual(Protocol.http, classify("GET / HTTP/1.1\r\n", 80, 6).protocol);
    try std.testing.expectEqual(Protocol.tls, classify(&[_]u8{ 0x16, 0x03, 0x03, 0x00 }, 443, 6).protocol);
    try std.testing.expectEqual(Protocol.dns, classify(&([_]u8{0} ** 12), 53, 17).protocol);
    try std.testing.expectEqual(Protocol.smb, classify("\xffSMB\x72", 445, 6).protocol);
    try std.testing.expectEqual(Protocol.rdp, classify(&[_]u8{ 0x03, 0x00, 0x00, 0x13 }, 3389, 6).protocol);
    try std.testing.expectEqual(Protocol.unknown, classify("GET ", 443, 17).protocol);
}

 test "classification flags are disjoint" {
    const tls = classify(&[_]u8{ 0x16, 0x03, 0x01 }, 443, 6);
    try std.testing.expect(tls.known());
    try std.testing.expectEqual(ContextFlag.tls, tls.context_flag);
}
