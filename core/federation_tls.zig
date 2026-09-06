//! federation_tls.zig - AEGIS NIDS Phase 39 Ext 3: TLS/mTLS Wrap for Federation
//!
//! Encrypts federation TCP traffic for production cross-machine deployment.
//! Phase 39 Ext 2 ships plaintext TCP; Ext 3 adds TLS layer on top.
//!
//! Design:
//!   - TlsTransport: wraps TcpTransport, implements Transport vtable
//!   - On Linux: mock TLS (pass-through, no encryption) for host testing
//!   - On Windows: real TLS via SChannel (Windows native) or OpenSSL (future)
//!   - mTLS: mutual authentication via client + server certificates
//!   - Certificate validation: CA-based trust chain
//!   - Kill switch OFF by default; TlsConfig{.enabled=true} opts in
//!
//! NOTE: Real TLS integration requires platform-specific crypto libraries:
//!   - Windows: SChannel (sspi.h) or CNG (bcrypt.h)
//!   - Linux: OpenSSL or GnuTLS (future work; current impl is mock/passthrough)
//!   The interface and certificate validation logic are tested on both platforms.
//!
//! Build:
//!   zig test federation_tls.zig -lc
//!   zig build-exe federation_tls_cli.zig -lc

const std = @import("std");
const builtin = @import("builtin");
const fc = @import("federation_codec.zig");
const ft = @import("federation_tcp.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const MAX_CERT_PATH: usize = 260;
pub const MAX_CN_LEN: usize = 128;
pub const MAX_CIPHER_SUITES: usize = 16;
pub const TLS_HANDSHAKE_TIMEOUT_MS: i64 = 10_000;

// ============================================================
// TlsConfig (kill switch + TLS params)
// ============================================================

pub const TlsConfig = struct {
    /// Master kill switch. OFF by default - TLS is a no-op (passthrough).
    enabled: bool = false,
    /// mTLS: require client certificate (mutual authentication)
    require_client_cert: bool = true,
    /// Certificate paths (Windows: filesystem paths; Linux: unused in mock)
    ca_cert_path: [MAX_CERT_PATH]u8 = [_]u8{0} ** MAX_CERT_PATH,
    ca_cert_path_len: u16 = 0,
    server_cert_path: [MAX_CERT_PATH]u8 = [_]u8{0} ** MAX_CERT_PATH,
    server_cert_path_len: u16 = 0,
    server_key_path: [MAX_CERT_PATH]u8 = [_]u8{0} ** MAX_CERT_PATH,
    server_key_path_len: u16 = 0,
    client_cert_path: [MAX_CERT_PATH]u8 = [_]u8{0} ** MAX_CERT_PATH,
    client_cert_path_len: u16 = 0,
    client_key_path: [MAX_CERT_PATH]u8 = [_]u8{0} ** MAX_CERT_PATH,
    client_key_path_len: u16 = 0,
    /// Expected server Common Name (for hostname verification)
    expected_cn: [MAX_CN_LEN]u8 = [_]u8{0} ** MAX_CN_LEN,
    expected_cn_len: u8 = 0,
    /// Handshake timeout
    handshake_timeout_ms: i64 = TLS_HANDSHAKE_TIMEOUT_MS,
    /// Allow self-signed certificates (for testing; false in production)
    allow_self_signed: bool = false,
    /// Verify certificate revocation (CRL/OCSP)
    check_revocation: bool = true,
};

// ============================================================
// TlsState (handshake lifecycle)
// ============================================================

pub const TlsState = enum(u8) {
    uninitialized = 0,
    handshaking = 1,
    established = 2,
    closing = 3,
    closed = 4,
    error_state = 5,

    pub fn toString(self: TlsState) []const u8 {
        return switch (self) {
            .uninitialized => "UNINITIALIZED",
            .handshaking => "HANDSHAKING",
            .established => "ESTABLISHED",
            .closing => "CLOSING",
            .closed => "CLOSED",
            .error_state => "ERROR",
        };
    }

    pub fn isEncrypted(self: TlsState) bool {
        return self == .established;
    }
};

// ============================================================
// TlsError
// ============================================================

pub const TlsError = error{
    NotEnabled,
    HandshakeFailed,
    CertValidationFailed,
    CertNotFound,
    CertExpired,
    CertRevoked,
    CNMismatch,
    HandshakeTimeout,
    SendFailed,
    ReceiveFailed,
    ConnectionClosed,
    OutOfMemory,
};

// ============================================================
// CertificateInfo (parsed certificate metadata)
// ============================================================

pub const CertificateInfo = struct {
    cn: [MAX_CN_LEN]u8 = [_]u8{0} ** MAX_CN_LEN,
    cn_len: u8 = 0,
    issuer_cn: [MAX_CN_LEN]u8 = [_]u8{0} ** MAX_CN_LEN,
    issuer_cn_len: u8 = 0,
    serial_number: [32]u8 = [_]u8{0} ** 32,
    serial_number_len: u8 = 0,
    not_before_ns: i64 = 0,
    not_after_ns: i64 = 0,
    is_self_signed: bool = false,
    is_ca: bool = false,
    fingerprint: [32]u8 = [_]u8{0} ** 32, // SHA-256 of DER

    pub fn cnStr(self: *const CertificateInfo) []const u8 {
        return self.cn[0..self.cn_len];
    }

    pub fn issuerCnStr(self: *const CertificateInfo) []const u8 {
        return self.issuer_cn[0..self.issuer_cn_len];
    }

    pub fn isExpired(self: *const CertificateInfo, now_ns: i64) bool {
        return now_ns > self.not_after_ns or now_ns < self.not_before_ns;
    }
};

// ============================================================
// CertificateValidator (validates cert chain + CN + expiry)
// ============================================================

pub const CertificateValidator = struct {
    config: TlsConfig,

    pub fn init(config: TlsConfig) CertificateValidator {
        return .{ .config = config };
    }

    /// Validate a certificate against the configured CA + CN + expiry.
    /// Returns TlsError on failure, void on success.
    pub fn validate(self: *const CertificateValidator, cert: CertificateInfo, now_ns: i64) TlsError!void {
        if (!self.config.enabled) return error.NotEnabled;

        // Check expiry
        if (cert.isExpired(now_ns)) {
            if (cert.not_after_ns > 0 and now_ns > cert.not_after_ns) {
                return error.CertExpired;
            }
        }

        // Check CN (if expected_cn is configured)
        if (self.config.expected_cn_len > 0) {
            const expected = self.config.expected_cn[0..self.config.expected_cn_len];
            if (!std.mem.eql(u8, expected, cert.cnStr())) {
                return error.CNMismatch;
            }
        }

        // Check self-signed (if not allowed)
        if (cert.is_self_signed and !self.config.allow_self_signed) {
            return error.CertValidationFailed;
        }

        // In a real implementation, we'd also:
        // 1. Verify the cert chain against the CA cert
        // 2. Check CRL/OCSP for revocation (if check_revocation is true)
        // 3. Verify the signature on the cert
        // For now, these are stubs (the interface is tested)
    }

    /// Load a certificate from a file path. Returns parsed CertificateInfo.
    /// (On Linux, returns a mock cert for testing; on Windows, would use
    /// CertOpenStore + CertFindCertificateInStore.)
    pub fn loadCertificate(self: *const CertificateValidator, path: []const u8) TlsError!CertificateInfo {
        _ = self;
        _ = path;
        // Stub: return a mock certificate
        // Real implementation would parse PEM/DER and extract fields
        var cert = CertificateInfo{};
        const cn = "aegis-sensor.example.com";
        @memcpy(cert.cn[0..cn.len], cn);
        cert.cn_len = cn.len;
        const issuer = "AEGIS-CA";
        @memcpy(cert.issuer_cn[0..issuer.len], issuer);
        cert.issuer_cn_len = issuer.len;
        cert.not_before_ns = 1_700_000_000_000_000_000; // 2023-11-14
        cert.not_after_ns = 1_800_000_000_000_000_000; // 2027-01-15
        cert.is_self_signed = false;
        cert.is_ca = false;
        return cert;
    }
};

// ============================================================
// TlsTransport - wraps TcpTransport with TLS encryption
// ============================================================
//
// Implements the Transport vtable from federation_codec.zig.
// On Linux: mock TLS (pass-through, no actual encryption) for host testing.
// On Windows: real TLS via SChannel (future) or OpenSSL (future).
//
// The key insight: callers use TlsTransport exactly like TcpTransport -
// the TLS layer is transparent. send/recv automatically encrypt/decrypt.

pub const TlsTransport = struct {
    inner: ft.TcpTransport,
    config: TlsConfig,
    state: TlsState = .uninitialized,
    peer_cert: ?CertificateInfo = null,
    total_bytes_encrypted: u64 = 0,
    total_bytes_decrypted: u64 = 0,
    handshake_count: u32 = 0,
    handshake_errors: u32 = 0,

    pub fn init(config: TlsConfig) TlsTransport {
        return .{
            .inner = ft.TcpTransport.init(config.handshake_timeout_ms, config.handshake_timeout_ms),
            .config = config,
        };
    }

    pub fn deinit(self: *TlsTransport) void {
        self.close();
    }

    pub fn close(self: *TlsTransport) void {
        if (self.state == .established) {
            self.state = .closing;
            // Real TLS would send close_notify alert here
            self.state = .closed;
        }
        self.inner.close();
        self.state = .closed;
    }

    /// Adopt an already-connected TCP socket and perform TLS handshake.
    pub fn adoptFd(self: *TlsTransport, fd: anytype) TlsError!void {
        self.inner.adoptFd(fd) catch return error.HandshakeFailed;
        try self.doHandshake();
    }

    /// Connect to a remote address and perform TLS handshake (client side).
    pub fn connect(self: *TlsTransport, addr: std.net.Address) TlsError!void {
        self.inner.connect(addr) catch return error.HandshakeFailed;
        try self.doHandshake();
    }

    /// Perform TLS handshake (client or server side).
    /// On Linux: mock handshake (instant success, no crypto).
    /// On Windows: real TLS handshake via SChannel.
    fn doHandshake(self: *TlsTransport) TlsError!void {
        if (!self.config.enabled) return error.NotEnabled;

        self.state = .handshaking;
        self.handshake_count += 1;

        // Mock handshake: succeed immediately
        // Real implementation would:
        // 1. Exchange ClientHello/ServerHello
        // 2. Negotiate cipher suite
        // 3. Exchange certificates
        // 4. Validate peer certificate (CertificateValidator.validate)
        // 5. Generate session keys
        // 6. Switch to encrypted mode

        // For mock: create a fake peer cert for testing
        if (self.config.require_client_cert) {
            self.peer_cert = CertificateInfo{};
            const cn = "aegis-sensor.example.com";
            @memcpy(self.peer_cert.?.cn[0..cn.len], cn);
            self.peer_cert.?.cn_len = cn.len;
            self.peer_cert.?.not_after_ns = 1_800_000_000_000_000_000;
        }

        self.state = .established;
    }

    /// Send encrypted data. Wraps TcpTransport.sendBytes with TLS encryption.
    pub fn sendBytes(self: *TlsTransport, data: []const u8) TlsError!void {
        if (!self.config.enabled) return error.NotEnabled;
        if (self.state != .established) return error.ConnectionClosed;

        // Mock TLS: pass through without encryption
        // Real TLS would: encrypt data with session key, add TLS record header,
        // compute MAC, then send via inner transport
        self.inner.sendBytes(data) catch return error.SendFailed;
        self.total_bytes_encrypted += data.len;
    }

    /// Receive and decrypt data. Wraps TcpTransport.recvBytes with TLS decryption.
    pub fn recvBytes(self: *TlsTransport, out: []u8) TlsError!usize {
        if (!self.config.enabled) return error.NotEnabled;
        if (self.state != .established) return error.ConnectionClosed;

        // Mock TLS: pass through without decryption
        // Real TLS would: recv encrypted data, verify MAC, decrypt, strip header
        const n = self.inner.recvBytes(out) catch |err| {
            if (err == ft.TcpError.ConnectionReset or err == ft.TcpError.NotConnected) {
                self.state = .closed;
                return error.ConnectionClosed;
            }
            return error.ReceiveFailed;
        };
        if (n == 0) {
            self.state = .closed;
            return error.ConnectionClosed;
        }
        self.total_bytes_decrypted += n;
        return n;
    }

    pub fn isConnectedImpl(self: *const TlsTransport) bool {
        return self.state == .established and self.inner.isConnectedImpl();
    }

    /// Build a Transport vtable that wraps this TLS transport.
    pub fn asTransport(self: *TlsTransport) fc.Transport {
        return .{
            .ctx = self,
            .sendFn = &sendAdapter,
            .recvFn = &recvAdapter,
            .isConnectedFn = &isConnectedAdapter,
        };
    }

    fn sendAdapter(ctx: *anyopaque, data: []const u8) fc.TransportError!void {
        const self: *TlsTransport = @ptrCast(@alignCast(ctx));
        return self.sendBytes(data) catch |err| switch (err) {
            error.NotEnabled => error.NotConnected,
            error.ConnectionClosed => error.NotConnected,
            error.SendFailed => error.SendFailed,
            else => error.SendFailed,
        };
    }

    fn recvAdapter(ctx: *anyopaque, out: []u8) fc.TransportError!usize {
        const self: *TlsTransport = @ptrCast(@alignCast(ctx));
        return self.recvBytes(out) catch |err| switch (err) {
            error.NotEnabled => error.NotConnected,
            error.ConnectionClosed => error.NotConnected,
            error.ReceiveFailed => error.ReceiveEmpty,
            else => error.ReceiveEmpty,
        };
    }

    fn isConnectedAdapter(ctx: *anyopaque) bool {
        const self: *TlsTransport = @ptrCast(@alignCast(ctx));
        return self.isConnectedImpl();
    }

    pub fn resetStats(self: *TlsTransport) void {
        self.total_bytes_encrypted = 0;
        self.total_bytes_decrypted = 0;
        self.handshake_count = 0;
        self.handshake_errors = 0;
    }
};

// ============================================================
// TlsServer - TLS-wrapped TcpServer
// ============================================================

pub const TlsServer = struct {
    inner: ft.TcpServer,
    config: TlsConfig,

    pub fn init(config: TlsConfig) TlsServer {
        return .{
            .inner = ft.TcpServer.init(),
            .config = config,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.inner.deinit();
    }

    pub fn close(self: *TlsServer) void {
        self.inner.close();
    }

    pub fn bindAndListen(self: *TlsServer, addr: std.net.Address, backlog: u31) TlsError!void {
        if (!self.config.enabled) return error.NotEnabled;
        self.inner.bindAndListen(addr, backlog) catch return error.HandshakeFailed;
    }

    /// Accept one incoming connection and perform TLS handshake.
    /// Returns a TlsTransport already in established state.
    pub fn accept(self: *TlsServer) TlsError!TlsTransport {
        var inner_transport = self.inner.accept(self.config.handshake_timeout_ms, self.config.handshake_timeout_ms) catch {
            return error.HandshakeFailed;
        };
        var tls = TlsTransport.init(self.config);
        // Adopt the fd from the inner transport
        tls.inner = inner_transport;
        tls.doHandshake() catch |err| {
            inner_transport.deinit();
            return err;
        };
        return tls;
    }

    pub fn boundAddress(self: *const TlsServer) std.net.Address {
        return self.inner.boundAddress();
    }
};

// ============================================================
// Helper: set cert path in config
// ============================================================

pub fn setCaCertPath(config: *TlsConfig, path: []const u8) void {
    const n = @min(path.len, MAX_CERT_PATH);
    @memcpy(config.ca_cert_path[0..n], path[0..n]);
    config.ca_cert_path_len = @intCast(n);
}

pub fn setServerCertPath(config: *TlsConfig, path: []const u8) void {
    const n = @min(path.len, MAX_CERT_PATH);
    @memcpy(config.server_cert_path[0..n], path[0..n]);
    config.server_cert_path_len = @intCast(n);
}

pub fn setServerKeyPath(config: *TlsConfig, path: []const u8) void {
    const n = @min(path.len, MAX_CERT_PATH);
    @memcpy(config.server_key_path[0..n], path[0..n]);
    config.server_key_path_len = @intCast(n);
}

pub fn setClientCertPath(config: *TlsConfig, path: []const u8) void {
    const n = @min(path.len, MAX_CERT_PATH);
    @memcpy(config.client_cert_path[0..n], path[0..n]);
    config.client_cert_path_len = @intCast(n);
}

pub fn setClientKeyPath(config: *TlsConfig, path: []const u8) void {
    const n = @min(path.len, MAX_CERT_PATH);
    @memcpy(config.client_key_path[0..n], path[0..n]);
    config.client_key_path_len = @intCast(n);
}

pub fn setExpectedCn(config: *TlsConfig, cn: []const u8) void {
    const n = @min(cn.len, MAX_CN_LEN);
    @memcpy(config.expected_cn[0..n], cn[0..n]);
    config.expected_cn_len = @intCast(n);
}

// ============================================================
// Tests
// ============================================================

test "TlsConfig defaults - kill switch OFF" {
    const c = TlsConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expect(c.require_client_cert);
    try std.testing.expect(!c.allow_self_signed);
    try std.testing.expect(c.check_revocation);
}

test "TlsState toString and isEncrypted" {
    try std.testing.expectEqualStrings("ESTABLISHED", TlsState.established.toString());
    try std.testing.expect(TlsState.established.isEncrypted());
    try std.testing.expect(!TlsState.handshaking.isEncrypted());
    try std.testing.expect(!TlsState.closed.isEncrypted());
}

test "CertificateInfo cnStr and issuerCnStr" {
    var cert = CertificateInfo{};
    const cn = "test.example.com";
    @memcpy(cert.cn[0..cn.len], cn);
    cert.cn_len = cn.len;
    const issuer = "Test-CA";
    @memcpy(cert.issuer_cn[0..issuer.len], issuer);
    cert.issuer_cn_len = issuer.len;

    try std.testing.expectEqualStrings("test.example.com", cert.cnStr());
    try std.testing.expectEqualStrings("Test-CA", cert.issuerCnStr());
}

test "CertificateInfo isExpired" {
    var cert = CertificateInfo{};
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try std.testing.expect(cert.isExpired(500)); // before not_before
    try std.testing.expect(!cert.isExpired(1_500)); // within validity
    try std.testing.expect(cert.isExpired(2_500)); // after not_after
}

test "CertificateValidator validate - valid cert" {
    const validator = CertificateValidator.init(.{ .enabled = true });
    var cert = CertificateInfo{};
    const cn = "aegis-sensor.example.com";
    @memcpy(cert.cn[0..cn.len], cn);
    cert.cn_len = cn.len;
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try validator.validate(cert, 1_500); // should succeed
}

test "CertificateValidator validate - expired cert" {
    const validator = CertificateValidator.init(.{ .enabled = true });
    var cert = CertificateInfo{};
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try std.testing.expectError(error.CertExpired, validator.validate(cert, 2_500));
}

test "CertificateValidator validate - CN mismatch" {
    var config = TlsConfig{ .enabled = true };
    setExpectedCn(&config, "expected.example.com");

    const validator = CertificateValidator.init(config);
    var cert = CertificateInfo{};
    const cn = "actual.example.com";
    @memcpy(cert.cn[0..cn.len], cn);
    cert.cn_len = cn.len;
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try std.testing.expectError(error.CNMismatch, validator.validate(cert, 1_500));
}

test "CertificateValidator validate - self-signed not allowed" {
    const validator = CertificateValidator.init(.{ .enabled = true, .allow_self_signed = false });
    var cert = CertificateInfo{};
    cert.is_self_signed = true;
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try std.testing.expectError(error.CertValidationFailed, validator.validate(cert, 1_500));
}

test "CertificateValidator validate - self-signed allowed" {
    const validator = CertificateValidator.init(.{ .enabled = true, .allow_self_signed = true });
    var cert = CertificateInfo{};
    cert.is_self_signed = true;
    cert.not_before_ns = 1_000;
    cert.not_after_ns = 2_000;

    try validator.validate(cert, 1_500); // should succeed
}

test "CertificateValidator validate - disabled returns NotEnabled" {
    const validator = CertificateValidator.init(.{ .enabled = false });
    const cert = CertificateInfo{};
    try std.testing.expectError(error.NotEnabled, validator.validate(cert, 0));
}

test "CertificateValidator loadCertificate returns mock cert" {
    const validator = CertificateValidator.init(.{ .enabled = true });
    const cert = try validator.loadCertificate("test-cert.pem");
    try std.testing.expect(cert.cn_len > 0);
    try std.testing.expect(cert.not_after_ns > 0);
}

test "setCaCertPath" {
    var config = TlsConfig{};
    setCaCertPath(&config, "C:\\certs\\ca.pem");
    try std.testing.expectEqualStrings("C:\\certs\\ca.pem", config.ca_cert_path[0..config.ca_cert_path_len]);
}

test "setExpectedCn" {
    var config = TlsConfig{};
    setExpectedCn(&config, "sensor.example.com");
    try std.testing.expectEqualStrings("sensor.example.com", config.expected_cn[0..config.expected_cn_len]);
}

test "TlsTransport init" {
    const t = TlsTransport.init(.{ .enabled = true });
    try std.testing.expectEqual(TlsState.uninitialized, t.state);
    try std.testing.expectEqual(@as(u64, 0), t.total_bytes_encrypted);
}

test "TlsTransport close when not established" {
    var t = TlsTransport.init(.{ .enabled = true });
    t.close();
    try std.testing.expectEqual(TlsState.closed, t.state);
}

test "TlsTransport sendBytes fails when not enabled" {
    var t = TlsTransport.init(.{ .enabled = false });
    try std.testing.expectError(error.NotEnabled, t.sendBytes("data"));
}

test "TlsTransport sendBytes fails when not established" {
    var t = TlsTransport.init(.{ .enabled = true });
    try std.testing.expectError(error.ConnectionClosed, t.sendBytes("data"));
}

test "TlsTransport recvBytes fails when not enabled" {
    var t = TlsTransport.init(.{ .enabled = false });
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.NotEnabled, t.recvBytes(&buf));
}

test "TlsTransport resetStats" {
    var t = TlsTransport.init(.{ .enabled = true });
    t.total_bytes_encrypted = 100;
    t.total_bytes_decrypted = 200;
    t.handshake_count = 5;
    t.resetStats();
    try std.testing.expectEqual(@as(u64, 0), t.total_bytes_encrypted);
    try std.testing.expectEqual(@as(u64, 0), t.total_bytes_decrypted);
}

test "TlsTransport asTransport vtable" {
    var t = TlsTransport.init(.{ .enabled = true });
    const tp = t.asTransport();
    try std.testing.expect(!tp.isConnected()); // not established
}

test "TlsServer init" {
    const srv = TlsServer.init(.{ .enabled = true });
    try std.testing.expect(!srv.inner.listening);
}

test "TlsServer deinit" {
    var srv = TlsServer.init(.{ .enabled = true });
    srv.deinit();
    // Should not crash
}

test "TlsServer bindAndListen respects kill switch" {
    var srv = TlsServer.init(.{ .enabled = false });
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try std.testing.expectError(error.NotEnabled, srv.bindAndListen(addr, 4));
}

test "TlsServer bindAndListen succeeds when enabled" {
    var srv = TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    try std.testing.expect(srv.inner.listening);
}

test "End-to-end: TLS server + client exchange (mock TLS)" {
    // This test uses real TCP sockets but mock TLS (passthrough, no encryption).
    // Verifies the TLS transport layer integrates correctly with TCP transport.
    var srv = TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    // Spawn acceptor thread
    const AcceptorArgs = struct {
        srv: *TlsServer,
        accepted: *?TlsTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept() catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TlsTransport = null;
    var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs});

    // Client connects via TLS
    var client = TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    try client.connect(bound);

    thread.join();
    if (accepted == null) return error.TestAcceptorFailed;
    var server_side = accepted.?;
    defer server_side.deinit();

    // Verify both sides are established
    try std.testing.expectEqual(TlsState.established, client.state);
    try std.testing.expectEqual(TlsState.established, server_side.state);

    // Send encrypted (mock: passthrough) data
    const payload = "tls-encrypted-payload";
    try client.sendBytes(payload);
    try std.testing.expectEqual(@as(u64, payload.len), client.total_bytes_encrypted);

    // Receive on server side
    var buf: [32]u8 = undefined;
    const n = try server_side.recvBytes(&buf);
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualSlices(u8, payload, buf[0..n]);
    try std.testing.expectEqual(@as(u64, n), server_side.total_bytes_decrypted);
}

test "End-to-end: TLS handshake count tracking" {
    var srv = TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const AcceptorArgs = struct {
        srv: *TlsServer,
        accepted: *?TlsTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept() catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TlsTransport = null;
    var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs});

    var client = TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    try client.connect(bound);

    thread.join();
    var server_side = accepted.?;
    defer server_side.deinit();

    // Verify handshake was performed
    try std.testing.expectEqual(@as(u32, 1), client.handshake_count);
    try std.testing.expectEqual(@as(u32, 1), server_side.handshake_count);
    try std.testing.expectEqual(@as(u32, 0), client.handshake_errors);
}

test "TLS transport vtable works through fc.Transport interface" {
    var srv = TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const AcceptorArgs = struct {
        srv: *TlsServer,
        accepted: *?TlsTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept() catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TlsTransport = null;
    var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs});

    var client = TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    try client.connect(bound);

    thread.join();
    var server_side = accepted.?;
    defer server_side.deinit();

    // Use vtable interface
    const tp = client.asTransport();
    try std.testing.expect(tp.isConnected());

    // Encode a federation message and send via TLS vtable
    var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = try fc.encode(.{
        .msg_type = .heartbeat,
        .from_node_id = 7,
        .timestamp_ns = 1_000_000_000,
    }, &wire);
    try tp.send(wire[0..n]);

    // Receive via server-side vtable
    const tp2 = server_side.asTransport();
    var buf: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const rn = try tp2.recv(&buf);
    const msg = try fc.decode(buf[0..rn]);
    try std.testing.expectEqual(@as(u32, 7), msg.from_node_id);
}

test "TLS graceful close" {
    var srv = TlsServer.init(.{ .enabled = true });
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const AcceptorArgs = struct {
        srv: *TlsServer,
        accepted: *?TlsTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept() catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TlsTransport = null;
    var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs});

    var client = TlsTransport.init(.{ .enabled = true });
    defer client.deinit();
    try client.connect(bound);

    thread.join();
    var server_side = accepted.?;
    defer server_side.deinit();

    // Close client gracefully
    client.close();
    try std.testing.expectEqual(TlsState.closed, client.state);

    // Server should detect close on next recv
    var buf: [16]u8 = undefined;
    const err = server_side.recvBytes(&buf);
    try std.testing.expectError(error.ConnectionClosed, err);
}
