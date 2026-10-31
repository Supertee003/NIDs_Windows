// I13 - Protocol Anomaly Detector
// AEGIS NIDS v5.0+ â€” RFC-compliance checks for HTTP/DNS/TLS/SMB
//
// Detects:
//   - Malformed HTTP methods / oversize URIs / invalid versions
//   - DNS label loops / oversize names / illegal chars
//   - TLS ClientHello anomalies (zero-length cipher suites, etc.)
//   - SMB malformed negotiate

const std = @import("std");
const parsers = @import("../capture/proto/parsers.zig");

pub const AnomalyKind = enum(u8) {
    http_invalid_method = 1,
    http_oversize_uri = 2,
    http_invalid_version = 3,
    http_missing_host = 4,
    dns_oversize_label = 5,
    dns_illegal_char = 6,
    dns_loop = 7,
    tls_zero_ciphers = 8,
    tls_zero_ext = 9,
    tls_oversize_sni = 10,
    smb_malformed = 11,
    smb_oversize_dialect = 12,
    _,
};

pub const Anomaly = struct {
    kind: AnomalyKind,
    severity: u8, // 0-7 (0=trace, 7=emergency)
    detail: [128]u8 = [_]u8{0} ** 128,
    detail_len: u8 = 0,
};

pub const RULE_ID_BASE: u32 = 10_000;

/// Stable IDS rule identity for protocol anomalies. These IDs are deliberately
/// outside the policy/signature and correlation ranges; the event processor
/// records them as observe-only evidence and does not make them policy hits.
pub fn ruleId(kind: AnomalyKind) u32 {
    return RULE_ID_BASE + @as(u32, @intFromEnum(kind));
}

/// Inspect a transport payload only when its port identifies a supported
/// application protocol. Parsing is defensive and returns at most one
/// anomaly, preserving deterministic receipt identity and bounded work.
pub fn inspect(protocol: u8, src_port: u16, dst_port: u16, payload: []const u8, dns_name_scratch: []u8) ?Anomaly {
    const port = if (dst_port != 0) dst_port else src_port;
    if (protocol == 6 and (port == 80 or port == 8080 or port == 8000 or port == 8081)) {
        if (parsers.parseHttpRequest(payload)) |request| return checkHttp(request);
    }
    if ((protocol == 6 or protocol == 17) and port == 53) {
        if (parsers.parseDns(payload, dns_name_scratch)) |query| return checkDns(query);
    }
    if (protocol == 6 and (port == 443 or port == 8443)) {
        if (parsers.parseTlsClientHello(payload)) |hello| return checkTls(hello);
    }
    if (protocol == 6 and (port == 445 or port == 139)) {
        if (parsers.parseSmbNegotiate(payload)) |negotiate| return checkSmb(negotiate);
    }
    return null;
}

pub fn checkHttp(req: parsers.HttpRequest) ?Anomaly {
    // Method must be a known token; "other" alone is not an anomaly unless other red flags
    if (req.method == .other) {
        // Check: is the method alphabetic and reasonable length?
        if (req.method_str.len == 0 or req.method_str.len > 16) {
            return .{ .kind = .http_invalid_method, .severity = 4 };
        }
        for (req.method_str) |c| {
            if (!std.ascii.isAlphabetic(c)) return .{ .kind = .http_invalid_method, .severity = 4 };
        }
    }
    if (req.uri.len > 8192) {
        return .{ .kind = .http_oversize_uri, .severity = 4 };
    }
    if (!std.mem.startsWith(u8, req.version, "HTTP/")) {
        return .{ .kind = .http_invalid_version, .severity = 5 };
    }
    if (req.host == null and req.method != .CONNECT) {
        return .{ .kind = .http_missing_host, .severity = 3 };
    }
    return null;
}

pub fn checkDns(q: parsers.DnsQuery) ?Anomaly {
    if (q.name.len > 253) {
        return .{ .kind = .dns_oversize_label, .severity = 4 };
    }
    for (q.name) |c| {
        // Allow letters, digits, dot, hyphen
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-' and c != '_') {
            return .{ .kind = .dns_illegal_char, .severity = 4 };
        }
    }
    return null;
}

pub fn checkTls(hello: parsers.TlsClientHello) ?Anomaly {
    if (hello.cipher_suites.len == 0 or hello.cipher_suites.len % 2 != 0) {
        return .{ .kind = .tls_zero_ciphers, .severity = 5 };
    }
    if (hello.sni) |sni| {
        if (sni.len > 253) {
            return .{ .kind = .tls_oversize_sni, .severity = 4 };
        }
    }
    return null;
}

pub fn checkSmb(neg: parsers.SmbNegotiate) ?Anomaly {
    if (!neg.is_smb2 and neg.dialects == 0) {
        return .{ .kind = .smb_malformed, .severity = 5 };
    }
    if (neg.dialects > 16) {
        return .{ .kind = .smb_oversize_dialect, .severity = 4 };
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================
test "checkHttp valid request" {
    const r = parsers.HttpRequest{
        .method = .GET,
        .method_str = "GET",
        .uri = "/",
        .version = "HTTP/1.1",
        .host = "example.com",
    };
    try std.testing.expect(checkHttp(r) == null);
}

test "checkHttp invalid version" {
    const r = parsers.HttpRequest{
        .method = .GET,
        .method_str = "GET",
        .uri = "/",
        .version = "WRONG/1.0",
        .host = "example.com",
    };
    const a = checkHttp(r).?;
    try std.testing.expectEqual(AnomalyKind.http_invalid_version, a.kind);
}

test "checkHttp oversize URI" {
    var buf: [9000]u8 = undefined;
    @memset(&buf, 'A');
    const r = parsers.HttpRequest{
        .method = .GET,
        .method_str = "GET",
        .uri = &buf,
        .version = "HTTP/1.1",
        .host = "example.com",
    };
    const a = checkHttp(r).?;
    try std.testing.expectEqual(AnomalyKind.http_oversize_uri, a.kind);
}

test "checkDns illegal char" {
    const q = parsers.DnsQuery{
        .name = "bad;dns;chars",
        .qtype = 1,
        .qclass = 1,
        .is_response = false,
        .answers = 0,
    };
    const a = checkDns(q).?;
    try std.testing.expectEqual(AnomalyKind.dns_illegal_char, a.kind);
}

test "checkTls zero ciphers" {
    const hello = parsers.TlsClientHello{
        .version = 0x0303,
        .session_id_len = 0,
        .cipher_suites = &[_]u8{},
        .sni = null,
    };
    const a = checkTls(hello).?;
    try std.testing.expectEqual(AnomalyKind.tls_zero_ciphers, a.kind);
}

test "checkSmb malformed" {
    const neg = parsers.SmbNegotiate{ .dialects = 0, .is_smb2 = false };
    const a = checkSmb(neg).?;
    try std.testing.expectEqual(AnomalyKind.smb_malformed, a.kind);
}

test "inspect maps HTTP anomaly to stable IDS rule ID" {
    var scratch: [256]u8 = undefined;
    const a = inspect(6, 1234, 80, "GET / WRONG/1.0\r\nHost: example.com\r\n\r\n", &scratch).?;
    try std.testing.expectEqual(AnomalyKind.http_invalid_version, a.kind);
    try std.testing.expectEqual(RULE_ID_BASE + 3, ruleId(a.kind));
}

test "inspect ignores unsupported ports" {
    var scratch: [256]u8 = undefined;
    try std.testing.expect(inspect(6, 1234, 22, "not HTTP", &scratch) == null);
}
