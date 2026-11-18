//! federation_rust_tls.zig - FED-P2B2: Rust-rustls delegate Transport.
//!
//! One-stack cutover (owner verdict, ADR-0007 P2): the Zig mock TLS
//! (passthrough, no encryption) is deleted; this Transport vtable
//! delegates every byte through the narrow `aegis_fed_*` C ABI in the
//! Rust PEP crate, where rustls 0.23 performs the real handshake with
//! pinned trust anchors and mutual authentication (FED-P2A, 8 loopback
//! proofs). Transport only, never policy: this module carries bytes,
//! makes no decisions, and holds no enforcement capability.
//!
//! Kill switch OFF by default; `RustTlsConfig{.enabled=true}` opts in.
//! No plaintext path exists here at all (AC4).

const std = @import("std");
const fc = @import("federation_codec.zig");

extern fn aegis_fed_connect(
    host: [*:0]const u8,
    port: u16,
    roots_pem: [*]const u8,
    roots_len: usize,
    chain_pem: [*]const u8,
    chain_len: usize,
    key_pem: [*]const u8,
    key_len: usize,
    server_name: [*:0]const u8,
    out_handle: *u64,
) c_int;
extern fn aegis_fed_send(handle: u64, data: [*]const u8, len: usize) c_int;
extern fn aegis_fed_recv(handle: u64, buf: [*]u8, cap: usize, out_n: *usize) c_int;
extern fn aegis_fed_close(handle: u64) c_int;
extern fn aegis_fed_listen(
    port: u16,
    roots_pem: [*]const u8,
    roots_len: usize,
    chain_pem: [*]const u8,
    chain_len: usize,
    key_pem: [*]const u8,
    key_len: usize,
    require_client_auth: c_int,
    out_listener: *u64,
) c_int;
extern fn aegis_fed_listen_port(listener: u64, out_port: *u16) c_int;
extern fn aegis_fed_accept(listener: u64, out_session: *u64) c_int;
extern fn aegis_fed_listen_close(listener: u64) c_int;

pub const RustTlsConfig = struct {
    /// Master kill switch. OFF by default - the delegate never dials
    /// unless explicitly enabled. Test-only until the P4 wiring slice.
    enabled: bool = false,
    host: []const u8 = "127.0.0.1",
    port: u16 = 9001,
    server_name: []const u8 = "localhost",
    roots_pem: []const u8 = &.{},
    chain_pem: []const u8 = &.{},
    key_pem: []const u8 = &.{},
};

pub const RustTlsError = error{
    NotEnabled,
    InvalidArgument,
    ConnectFailed,
    SendFailed,
    ReceiveFailed,
    NotConnected,
};

pub const RustTlsTransport = struct {
    cfg: RustTlsConfig,
    handle: u64 = 0,
    connected: bool = false,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,

    pub fn init(cfg: RustTlsConfig) RustTlsTransport {
        return .{ .cfg = cfg };
    }

    pub fn deinit(self: *RustTlsTransport) void {
        if (self.connected) {
            _ = aegis_fed_close(self.handle);
            self.connected = false;
            self.handle = 0;
        }
    }

    fn failClosed(rc: c_int) RustTlsError {
        return switch (rc) {
            -1 => RustTlsError.InvalidArgument,
            -2 => RustTlsError.ConnectFailed,
            -3 => RustTlsError.NotConnected,
            else => RustTlsError.ConnectFailed,
        };
    }

    pub fn connect(self: *RustTlsTransport) RustTlsError!void {
        if (!self.cfg.enabled) return error.NotEnabled;
        if (self.connected) return;
        var host_buf: [256]u8 = undefined;
        var name_buf: [256]u8 = undefined;
        if (self.cfg.host.len == 0 or self.cfg.host.len >= host_buf.len) return error.InvalidArgument;
        if (self.cfg.server_name.len == 0 or self.cfg.server_name.len >= name_buf.len) return error.InvalidArgument;
        @memcpy(host_buf[0..self.cfg.host.len], self.cfg.host);
        host_buf[self.cfg.host.len] = 0;
        @memcpy(name_buf[0..self.cfg.server_name.len], self.cfg.server_name);
        name_buf[self.cfg.server_name.len] = 0;
        var handle: u64 = 0;
        const rc = aegis_fed_connect(
            @ptrCast(host_buf[0..self.cfg.host.len :0]),
            self.cfg.port,
            self.cfg.roots_pem.ptr, self.cfg.roots_pem.len,
            self.cfg.chain_pem.ptr, self.cfg.chain_pem.len,
            self.cfg.key_pem.ptr, self.cfg.key_pem.len,
            @ptrCast(name_buf[0..self.cfg.server_name.len :0]),
            &handle,
        );
        if (rc != 0) return failClosed(rc);
        self.handle = handle;
        self.connected = true;
    }

    pub fn disconnect(self: *RustTlsTransport) void {
        self.deinit();
    }

    pub fn sendBytes(self: *RustTlsTransport, data: []const u8) RustTlsError!void {
        if (!self.connected) return error.NotConnected;
        const rc = aegis_fed_send(self.handle, data.ptr, data.len);
        if (rc != 0) return error.SendFailed;
        self.total_bytes_sent += data.len;
    }

    pub fn recvBytes(self: *RustTlsTransport, out: []u8) RustTlsError!usize {
        if (!self.connected) return error.NotConnected;
        var n: usize = 0;
        const rc = aegis_fed_recv(self.handle, out.ptr, out.len, &n);
        if (rc != 0) return error.ReceiveFailed;
        self.total_bytes_received += n;
        return n;
    }

    pub fn isConnectedImpl(self: *RustTlsTransport) bool {
        return self.connected;
    }

    pub fn asTransport(self: *RustTlsTransport) fc.Transport {
        return .{
            .ctx = self,
            .sendFn = &sendAdapter,
            .recvFn = &recvAdapter,
            .isConnectedFn = &isConnectedAdapter,
        };
    }

    fn sendAdapter(ctx: *anyopaque, data: []const u8) fc.TransportError!void {
        const self: *RustTlsTransport = @ptrCast(@alignCast(ctx));
        self.sendBytes(data) catch return error.SendFailed;
    }

    fn recvAdapter(ctx: *anyopaque, out: []u8) fc.TransportError!usize {
        const self: *RustTlsTransport = @ptrCast(@alignCast(ctx));
        return self.recvBytes(out) catch return error.ReceiveEmpty;
    }

    fn isConnectedAdapter(ctx: *anyopaque) bool {
        const self: *RustTlsTransport = @ptrCast(@alignCast(ctx));
        return self.isConnectedImpl();
    }
};

// ============================================================
// Tests (kill-switch, config validation, FFI linkage; crypto is
// proven in-crate by the Rust fed_tls_* loopback proofs)
// ============================================================

test "rust delegate kill switch off refuses to dial" {
    var t = RustTlsTransport.init(.{ .enabled = false });
    defer t.deinit();
    try std.testing.expectError(error.NotEnabled, t.connect());
    try std.testing.expect(!t.isConnectedImpl());
}

test "rust delegate rejects empty host and server name" {
    var t = RustTlsTransport.init(.{ .enabled = true, .host = "" });
    defer t.deinit();
    try std.testing.expectError(error.InvalidArgument, t.connect());
    var t2 = RustTlsTransport.init(.{ .enabled = true, .server_name = "" });
    defer t2.deinit();
    try std.testing.expectError(error.InvalidArgument, t2.connect());
}

test "rust delegate send/recv without connect fail closed" {
    var t = RustTlsTransport.init(.{ .enabled = true });
    defer t.deinit();
    try std.testing.expectError(error.NotConnected, t.sendBytes("x"));
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.NotConnected, t.recvBytes(&buf));
}

test "rust delegate plugs into the Transport vtable" {
    var t = RustTlsTransport.init(.{ .enabled = false });
    defer t.deinit();
    const tp = t.asTransport();
    try std.testing.expect(!tp.isConnected());
    try std.testing.expectError(error.SendFailed, tp.send("x"));
}

// ============================================================
// Server side (FED-LSTN-085): loopback-only listener + accept.
// ============================================================
//
// The bind address is loopback by Rust construction (no wildcard
// option exists in the FFI), mTLS honors the same require_client_auth
// path as the client side, and nothing in the daemon calls this:
// no listener runs unless a future wiring slice explicitly starts
// one. Sessions accepted here work with the shared send/recv/close
// FFI (one handle namespace, uniform close).

pub const RustTlsServer = struct {
    cfg: RustTlsConfig,
    listener: u64 = 0,
    listening: bool = false,

    pub fn init(cfg: RustTlsConfig) RustTlsServer {
        return .{ .cfg = cfg };
    }

    pub fn deinit(self: *RustTlsServer) void {
        if (self.listening) {
            _ = aegis_fed_listen_close(self.listener);
            self.listening = false;
            self.listener = 0;
        }
    }

    pub fn listen(self: *RustTlsServer, port: u16, require_client_auth: bool) RustTlsError!void {
        if (!self.cfg.enabled) return error.NotEnabled;
        if (self.listening) return;
        var handle: u64 = 0;
        const rc = aegis_fed_listen(
            port,
            self.cfg.roots_pem.ptr, self.cfg.roots_pem.len,
            self.cfg.chain_pem.ptr, self.cfg.chain_pem.len,
            self.cfg.key_pem.ptr, self.cfg.key_pem.len,
            if (require_client_auth) @as(c_int, 1) else @as(c_int, 0),
            &handle,
        );
        if (rc != 0) return RustTlsTransport.failClosed(rc);
        self.listener = handle;
        self.listening = true;
    }

    pub fn boundPort(self: *RustTlsServer) RustTlsError!u16 {
        if (!self.listening) return error.NotConnected;
        var port: u16 = 0;
        const rc = aegis_fed_listen_port(self.listener, &port);
        if (rc != 0) return RustTlsTransport.failClosed(rc);
        return port;
    }

    /// Accept one session; the returned handle works with
    /// aegis_fed_send/recv/close (same namespace as client sessions).
    pub fn acceptSession(self: *RustTlsServer) RustTlsError!u64 {
        if (!self.listening) return error.NotConnected;
        var handle: u64 = 0;
        const rc = aegis_fed_accept(self.listener, &handle);
        if (rc != 0) return RustTlsTransport.failClosed(rc);
        return handle;
    }

    pub fn closeListener(self: *RustTlsServer) void {
        self.deinit();
    }
};

// ============================================================
// Tests (server fail-closed paths; positive loopback lives in the
// Rust fed_lstn_* proofs, which own test PKI via rcgen)
// ============================================================

test "rust server kill switch off refuses to listen" {
    var s = RustTlsServer.init(.{ .enabled = false });
    defer s.deinit();
    try std.testing.expectError(error.NotEnabled, s.listen(0, true));
    try std.testing.expectError(error.NotConnected, s.boundPort());
    try std.testing.expectError(error.NotConnected, s.acceptSession());
}

test "rust server without material fails closed" {
    var s = RustTlsServer.init(.{ .enabled = true });
    defer s.deinit();
    // Empty roots/chain/key: Rust construction fails closed.
    try std.testing.expectError(error.ConnectFailed, s.listen(0, true));
    try std.testing.expect(!s.listening);
}

test "rust server unknown handles fail closed" {
    // Direct FFI misuse without a server: unknown listener ids.
    var port: u16 = 0;
    try std.testing.expect(aegis_fed_listen_port(0xDEAD_BEEF_F00D, &port) == -3);
    var sess: u64 = 0;
    try std.testing.expect(aegis_fed_accept(0xDEAD_BEEF_F00D, &sess) == -3);
    try std.testing.expect(aegis_fed_listen_close(0xDEAD_BEEF_F00D) == -3);
}
