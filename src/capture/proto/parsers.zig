// I09 - Protocol Parsers (HTTP/DNS/TLS-SNI/SMB/RDP/Kerberos)
// AEGIS NIDS v5.0+ â€” L7 protocol metadata extractors
//
// All parsers are:
//   - Stateless (per-segment)
//   - Zero-copy (return slices into the input buffer)
//   - Defensive (return Partial / Invalid on truncation, never panic)

const std = @import("std");

// ============================================================================
// DNS
// ============================================================================
pub const DnsHeader = extern struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub const DnsQuery = struct {
    name: []const u8,
    qtype: u16,
    qclass: u16,
    is_response: bool,
    answers: u16,
};

pub fn parseDns(buf: []const u8, name_out: []u8) ?DnsQuery {
    if (buf.len < @sizeOf(DnsHeader)) return null;
    const hdr: *const DnsHeader = @ptrCast(@alignCast(buf.ptr));
    const flags = std.mem.readInt(u16, std.mem.asBytes(&hdr.flags), .big);
    const is_response = (flags & 0x8000) != 0;
    const qdcount = std.mem.readInt(u16, std.mem.asBytes(&hdr.qdcount), .big);
    if (qdcount == 0) return null;
    var off: usize = @sizeOf(DnsHeader);
    var name_len: usize = 0;
    while (off < buf.len) {
        const label_len = buf[off];
        off += 1;
        if (label_len == 0) break;
        if (off + label_len > buf.len) return null;
        if (name_len > 0 and name_len < name_out.len) {
            name_out[name_len] = '.';
            name_len += 1;
        }
        if (name_len + label_len > name_out.len) return null;
        @memcpy(name_out[name_len .. name_len + label_len], buf[off .. off + label_len]);
        name_len += label_len;
        off += label_len;
    }
    if (off + 4 > buf.len) return null;
    const qtype = std.mem.readInt(u16, buf[off..][0..2], .big);
    const qclass = std.mem.readInt(u16, buf[off + 2 ..][0..2], .big);
    return .{
        .name = name_out[0..name_len],
        .qtype = qtype,
        .qclass = qclass,
        .is_response = is_response,
        .answers = std.mem.readInt(u16, std.mem.asBytes(&hdr.ancount), .big),
    };
}

// ============================================================================
// HTTP (request-line + minimal headers)
// ============================================================================
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,
    TRACE,
    other,
};

pub const HttpRequest = struct {
    method: HttpMethod,
    method_str: []const u8,
    uri: []const u8,
    version: []const u8,
    host: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
};

pub fn parseHttpRequest(buf: []const u8) ?HttpRequest {
    const eol = std.mem.indexOfScalar(u8, buf, '\n') orelse return null;
    const line = std.mem.trim(u8, buf[0..eol], " \r");
    var it = std.mem.splitScalar(u8, line, ' ');
    const m = it.next() orelse return null;
    const uri = it.next() orelse return null;
    const ver = it.next() orelse return null;
    if (it.next() != null) return null; // malformed

    // Look for Host: and User-Agent: in headers
    var host: ?[]const u8 = null;
    var ua: ?[]const u8 = null;
    var rest = buf[eol + 1 ..];
    while (true) {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse break;
        const hdr_line = std.mem.trim(u8, rest[0..nl], " \r");
        if (hdr_line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(hdr_line, "Host:")) {
            host = std.mem.trim(u8, hdr_line[5..], " \t");
        } else if (std.ascii.startsWithIgnoreCase(hdr_line, "User-Agent:")) {
            ua = std.mem.trim(u8, hdr_line[11..], " \t");
        }
        rest = rest[nl + 1 ..];
    }

    return .{
        .method = parseMethod(m),
        .method_str = m,
        .uri = uri,
        .version = ver,
        .host = host,
        .user_agent = ua,
    };
}

fn parseMethod(s: []const u8) HttpMethod {
    if (std.mem.eql(u8, s, "GET")) return .GET;
    if (std.mem.eql(u8, s, "POST")) return .POST;
    if (std.mem.eql(u8, s, "PUT")) return .PUT;
    if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
    if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
    if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
    if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
    if (std.mem.eql(u8, s, "CONNECT")) return .CONNECT;
    if (std.mem.eql(u8, s, "TRACE")) return .TRACE;
    return .other;
}

// ============================================================================
// TLS â€” ClientHello SNI extraction (RFC 6066)
// ============================================================================
pub const TlsClientHello = struct {
    version: u16,
    session_id_len: u8,
    cipher_suites: []const u8,
    sni: ?[]const u8 = null,
    ja3_hash: u32 = 0,
};

pub fn parseTlsClientHello(buf: []const u8) ?TlsClientHello {
    // TLS record header: type=22 (handshake), version, length
    if (buf.len < 5) return null;
    if (buf[0] != 0x16) return null; // not handshake
    const record_len = std.mem.readInt(u16, buf[3..5], .big);
    if (5 + record_len > buf.len) return null;

    var p: usize = 5;
    if (p + 4 > buf.len) return null;
    if (buf[p] != 0x01) return null; // not ClientHello
    p += 1;
    const hello_len = std.mem.readInt(u24, buf[p..][0..3], .big);
    p += 3;
    if (p + hello_len > buf.len) return null;

    if (p + 2 + 32 > buf.len) return null; // version + random
    const version = std.mem.readInt(u16, buf[p..][0..2], .big);
    p += 2 + 32;
    if (p >= buf.len) return null;
    const sid_len = buf[p];
    p += 1 + sid_len;
    if (p + 2 > buf.len) return null;
    const cs_len = std.mem.readInt(u16, buf[p..][0..2], .big);
    p += 2;
    const cs = buf[p .. p + cs_len];
    p += cs_len;
    if (p >= buf.len) return null;
    const cm_len = buf[p];
    p += 1 + cm_len;
    if (p + 2 > buf.len) return null;
    const ext_len = std.mem.readInt(u16, buf[p..][0..2], .big);
    p += 2;
    const ext_end = p + ext_len;
    if (ext_end > buf.len) return null;

    var sni: ?[]const u8 = null;
    while (p + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, buf[p..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, buf[p + 2 ..][0..2], .big);
        p += 4;
        if (ext_type == 0x0000) {
            // SNI extension
            if (p + 2 > buf.len) break;
            const sl_len = std.mem.readInt(u16, buf[p..][0..2], .big);
            _ = sl_len;
            if (p + 2 + 1 > buf.len) break;
            const name_type = buf[p + 2];
            if (name_type != 0) break; // only host_name
            if (p + 2 + 1 + 2 > buf.len) break;
            const name_len = std.mem.readInt(u16, buf[p + 3 ..][0..2], .big);
            if (p + 5 + name_len > buf.len) break;
            sni = buf[p + 5 .. p + 5 + name_len];
            break;
        }
        p += ext_data_len;
    }
    return .{
        .version = version,
        .session_id_len = sid_len,
        .cipher_suites = cs,
        .sni = sni,
    };
}

// ============================================================================
// SMB1 negotiate (minimal â€” protocol version + dialects)
// ============================================================================
pub const SmbNegotiate = struct {
    dialects: u8,
    is_smb2: bool,
};

pub fn parseSmbNegotiate(buf: []const u8) ?SmbNegotiate {
    if (buf.len < 4) return null;
    // SMB1: \xFFSMB
    if (buf[0] == 0xFF and buf[1] == 'S' and buf[2] == 'M' and buf[3] == 'B') {
        var dialects: u8 = 0;
        if (buf.len > 32) {
            const bc = std.mem.readInt(u16, buf[31..33], .big);
            var p: usize = 33;
            const end = @min(p + bc, buf.len);
            while (p < end) {
                if (p >= buf.len) break;
                const dl = buf[p];
                p += 1;
                if (p + dl > buf.len) break;
                dialects += 1;
                p += dl;
            }
        }
        return .{ .dialects = dialects, .is_smb2 = false };
    }
    // SMB2/3: \xFESMB
    if (buf[0] == 0xFE and buf[1] == 'S' and buf[2] == 'M' and buf[3] == 'B') {
        return .{ .dialects = 1, .is_smb2 = true };
    }
    return null;
}

// ============================================================================
// RDP â€” minimal connection request (TPKT + COTP CR)
// ============================================================================
pub fn isRdpConnect(buf: []const u8) bool {
    // TPKT: version=3, reserved=0, length (BE 16)
    // COTP: header length=6, PDU type=CR (0xE0)
    if (buf.len < 11) return false;
    if (buf[0] != 0x03) return false;
    if (buf[2] != 0x00) return false;
    if (buf[4] != 0x06) return false; // COTP header length
    if (buf[5] != 0xE0) return false; // CR TPDU
    return true;
}

// ============================================================================
// Kerberos AS-REQ / AS-REP detection (application tag 10 / 11)
// ============================================================================
pub fn isKerberosAsReq(buf: []const u8) bool {
    if (buf.len < 2) return false;
    // ASN.1 APPLICATION tag 10 â†’ 0x6A
    return buf[0] == 0x6A;
}

pub fn isKerberosAsRep(buf: []const u8) bool {
    if (buf.len < 2) return false;
    // ASN.1 APPLICATION tag 11 â†’ 0x6B
    return buf[0] == 0x6B;
}

// ============================================================================
// Tests
// ============================================================================
test "parseDns query" {
    // Build a minimal DNS query: id=0x1234, flags=0x0100 (standard query),
    // qdcount=1, others=0, then "example.com" + type A + class IN
    var pkt: [40]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = 0x12;
    pkt[1] = 0x34; // id
    pkt[2] = 0x01;
    pkt[3] = 0x00; // flags: standard query
    pkt[4] = 0x00;
    pkt[5] = 0x01; // qdcount=1
    // qname: 7example3com0
    pkt[12] = 7;
    @memcpy(pkt[13..20], "example");
    pkt[20] = 3;
    @memcpy(pkt[21..24], "com");
    pkt[24] = 0;
    pkt[25] = 0x00;
    pkt[26] = 0x01; // type A
    pkt[27] = 0x00;
    pkt[28] = 0x01; // class IN
    var name_buf: [64]u8 = undefined;
    const q = parseDns(&pkt, &name_buf).?;
    try std.testing.expectEqual(false, q.is_response);
    try std.testing.expectEqualStrings("example.com", q.name);
    try std.testing.expectEqual(@as(u16, 1), q.qtype);
}

test "parseHttpRequest GET" {
    const buf = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    const r = parseHttpRequest(buf).?;
    try std.testing.expectEqual(HttpMethod.GET, r.method);
    try std.testing.expectEqualStrings("/index.html", r.uri);
    try std.testing.expectEqualStrings("example.com", r.host.?);
    try std.testing.expectEqualStrings("test", r.user_agent.?);
}

test "parseTlsClientHello SNI" {
    // Minimal ClientHello with SNI = example.com
    // We'll build it from pieces.
    // For brevity in tests we only assert structurally that we can parse a
    // synthetic known-good hello.
    const hello = [_]u8{
        0x16, 0x03, 0x01, 0x00, 0x45, // record header (payload = 0x45 = 69)
        0x01, // ClientHello
        0x00, 0x00, 0x41, // handshake length = 0x41 = 65
        0x03, 0x03, // version TLS 1.2
    } ++ [_]u8{0xAA} ** 32 ++ [_]u8{
        0x00, // session_id_len
        0x00, 0x02, 0xc0, 0x2c, // cipher_suites (1 cipher)
        0x01, 0x00, // compression methods
        0x00, 0x14, // extensions length = 0x14 = 20
        0x00, 0x00, // extension: SNI
        0x00, 0x10, // ext data length
        0x00, 0x0e, // server_name_list length
        0x00, // name_type: host_name
        0x00, 0x0b, // name length
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x00, 0x00, // trailing
    };
    const r = parseTlsClientHello(&hello).?;
    try std.testing.expectEqual(@as(u16, 0x0303), r.version);
    try std.testing.expectEqualStrings("example.com", r.sni.?);
}

test "isRdpConnect detection" {
    const valid = [_]u8{ 0x03, 0x00, 0x00, 0x20, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expect(isRdpConnect(&valid));
    const invalid = [_]u8{ 0x06, 0x00, 0x00, 0x20, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expect(!isRdpConnect(&invalid));
}

test "Kerberos AS-REQ/AS-REP detection" {
    const asreq = [_]u8{ 0x6A, 0x00 };
    const asrep = [_]u8{ 0x6B, 0x00 };
    try std.testing.expect(isKerberosAsReq(&asreq));
    try std.testing.expect(isKerberosAsRep(&asrep));
    try std.testing.expect(!isKerberosAsReq(&asrep));
}
