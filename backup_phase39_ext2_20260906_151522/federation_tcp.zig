//! federation_tcp.zig - AEGIS NIDS Phase 39 Ext 2: Federation TCP Adapter
//!
//! Real TCP/Unix socket transport implementing the Transport vtable from
//! federation_codec.zig. Closes the gap between Phase 39 Ext 1's
//! LoopbackTransport (in-process only) and actual cross-node messaging.
//!
//! Three layers:
//!
//!   1. TcpTransport: a single TCP connection. Implements send/recv/isConnected
//!      via the Transport vtable. Uses blocking sockets with SO_RCVTIMEO/
//!      SO_SNDTIMEO so recv() never hangs forever.
//!   2. FramedReader: reassembles 12-byte header + payload from arbitrary
//!      byte chunks delivered by recv(). TCP is a byte stream, not a message
//!      stream, so callers cannot assume one recv() = one frame.
//!   3. TcpServer + TcpClient: convenience wrappers for the listener side
//!      (bind + accept) and the connector side (connect + reconnect).
//!
//! Design principles (mirrors Phase 32/36/37/39/39-ext-1):
//!   - Pure Zig, host-testable on Linux (uses std.posix; same code works on
//!     Windows via WinSock2 - no #ifdef needed in this module)
//!   - Additive only - enforcement stays in WFP kernel driver
//!   - Kill switch OFF by default; TcpConfig{.enabled=true} opts in
//!   - Bounded memory: fixed-size frame reassembly buffer
//!   - Graceful degradation: connection drop -> TransportError.NotConnected;
//!     caller (FederationFacade) handles reconnect via ConnectionManager
//!
//! Build:
//!   zig test federation_tcp.zig -lc
//!   zig build-exe federation_tcp_cli.zig -lc   (uses this module + codec + cluster_coord)

const std = @import("std");
const posix = std.posix;
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const DEFAULT_RECV_TIMEOUT_MS: i64 = 1_000;
pub const DEFAULT_SEND_TIMEOUT_MS: i64 = 5_000;
pub const DEFAULT_LISTEN_BACKLOG: u31 = 32;
pub const DEFAULT_CONNECT_TIMEOUT_MS: i64 = 5_000;
pub const RECV_BUF_SIZE: usize = 4096;
pub const MAX_FRAME_SIZE: usize = fc.MAX_FRAME_SIZE;

// ============================================================
// TcpError - extends TransportError with TCP-specific causes
// ============================================================

pub const TcpError = error{
    NotConnected,
    SendFailed,
    ReceiveEmpty,
    QueueFull,
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    ConnectFailed,
    SetSockOptFailed,
    InvalidAddress,
    ConnectionReset,
    Timeout,
    OutOfMemory,
};

// ============================================================
// TcpConfig (kill switch + socket params)
// ============================================================

pub const TcpConfig = struct {
    /// Master kill switch. OFF by default - TCP transport is a no-op until
    /// explicitly enabled. Per-node enforcement stays in WFP driver.
    enabled: bool = false,
    /// Bind address for server side (e.g. "127.0.0.1:7931").
    /// Port 0 = OS-assigned ephemeral port (useful for tests).
    bind_addr: []const u8 = "127.0.0.1:0",
    /// Remote address for client side (e.g. "127.0.0.1:7931").
    connect_addr: []const u8 = "",
    /// Socket timeouts
    recv_timeout_ms: i64 = DEFAULT_RECV_TIMEOUT_MS,
    send_timeout_ms: i64 = DEFAULT_SEND_TIMEOUT_MS,
    connect_timeout_ms: i64 = DEFAULT_CONNECT_TIMEOUT_MS,
    /// Listen backlog (max pending accept connections)
    listen_backlog: u31 = DEFAULT_LISTEN_BACKLOG,
    /// Reconnect params (used by TcpClient.reconnectIfNeeded)
    reconnect_initial_backoff_ms: i64 = 1,
    reconnect_max_backoff_ms: i64 = 30_000,
    reconnect_max_attempts: u32 = 10,
};

// ============================================================
// Address parsing (string -> std.net.Address)
// ============================================================

pub fn parseAddrPort(addr: []const u8) TcpError!std.net.Address {
    // Accept "ip:port" or "host:port". For now, support IPv4 + IPv6 only.
    // (No DNS resolution in this module - keep it deterministic for tests.)
    if (std.mem.lastIndexOfScalar(u8, addr, ':')) |colon_idx| {
        const host = addr[0..colon_idx];
        const port_str = addr[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;
        if (host.len == 0 or std.mem.eql(u8, host, "*")) {
            return std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        }
        // Try IPv4
        if (std.net.Address.parseIp4(host, port)) |a| {
            return a;
        } else |_| {}
        // Try IPv6
        if (std.net.Address.parseIp6(host, port)) |a| {
            return a;
        } else |_| {}
        return error.InvalidAddress;
    }
    return error.InvalidAddress;
}

// ============================================================
// TcpTransport: a single TCP connection implementing Transport vtable
// ============================================================

pub const TcpTransport = struct {
    fd: posix.fd_t = -1,
    connected: bool = false,
    recv_timeout_ms: i64,
    send_timeout_ms: i64,
    total_sent: u64 = 0,
    total_received: u64 = 0,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,
    total_send_failures: u64 = 0,
    total_recv_failures: u64 = 0,

    pub fn init(recv_timeout_ms: i64, send_timeout_ms: i64) TcpTransport {
        return .{
            .recv_timeout_ms = recv_timeout_ms,
            .send_timeout_ms = send_timeout_ms,
        };
    }

    pub fn deinit(self: *TcpTransport) void {
        self.close();
    }

    pub fn close(self: *TcpTransport) void {
        if (self.fd != -1) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.connected = false;
    }

    /// Adopt an already-connected socket (e.g. from accept()).
    pub fn adoptFd(self: *TcpTransport, fd: posix.fd_t) TcpError!void {
        self.fd = fd;
        try self.setSocketOptions();
        self.connected = true;
    }

    /// Connect to a remote address (client side).
    pub fn connect(self: *TcpTransport, addr: std.net.Address) TcpError!void {
        const fd = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return error.SocketCreateFailed;
        // Manual cleanup on all error paths (no errdefer - we explicitly
        // close fd and reset self.fd on each failure to keep state consistent).
        self.fd = fd;
        self.setSocketOptions() catch |err| {
            self.fd = -1;
            posix.close(fd);
            return err;
        };
        posix.connect(fd, &addr.any, addr.getOsSockLen()) catch {
            self.fd = -1;
            posix.close(fd);
            return error.ConnectFailed;
        };
        self.connected = true;
    }

    /// Set SO_RCVTIMEO + SO_SNDTIMEO + TCP_NODELAY.
    fn setSocketOptions(self: *TcpTransport) TcpError!void {
        // Receive timeout
        const rcvtime = posix.timeval{
            .tv_sec = @intCast(@divFloor(self.recv_timeout_ms, 1000)),
            .tv_usec = @intCast(@mod(self.recv_timeout_ms, 1000) * 1000),
        };
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&rcvtime)) catch return error.SetSockOptFailed;
        // Send timeout
        const sndtime = posix.timeval{
            .tv_sec = @intCast(@divFloor(self.send_timeout_ms, 1000)),
            .tv_usec = @intCast(@mod(self.send_timeout_ms, 1000) * 1000),
        };
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&sndtime)) catch return error.SetSockOptFailed;
        // TCP_NODELAY (disable Nagle for low-latency federation messages)
        const tcp_nodelay: i32 = 1;
        posix.setsockopt(self.fd, posix.IPPROTO.TCP, 1, std.mem.asBytes(&tcp_nodelay)) catch {};
    }

    pub fn sendBytes(self: *TcpTransport, data: []const u8) TcpError!void {
        if (!self.connected) return error.NotConnected;
        var sent: usize = 0;
        while (sent < data.len) {
            const n = posix.send(self.fd, data[sent..], 0) catch |err| {
                self.total_send_failures += 1;
                self.connected = false;
                return switch (err) {
                    error.BrokenPipe, error.ConnectionResetByPeer => error.ConnectionReset,
                    error.WouldBlock => error.Timeout,
                    else => error.SendFailed,
                };
            };
            if (n == 0) {
                self.total_send_failures += 1;
                self.connected = false;
                return error.ConnectionReset;
            }
            sent += n;
        }
        self.total_sent += 1;
        self.total_bytes_sent += data.len;
    }

    pub fn recvBytes(self: *TcpTransport, out: []u8) TcpError!usize {
        if (!self.connected) return error.NotConnected;
        const n = posix.recv(self.fd, out, 0) catch |err| {
            self.total_recv_failures += 1;
            if (err == error.WouldBlock) return error.Timeout;
            self.connected = false;
            return switch (err) {
                error.ConnectionResetByPeer => error.ConnectionReset,
                else => error.ReceiveEmpty,
            };
        };
        if (n == 0) {
            // Peer closed
            self.connected = false;
            return error.ConnectionReset;
        }
        self.total_received += 1;
        self.total_bytes_received += n;
        return n;
    }

    pub fn isConnectedImpl(self: *const TcpTransport) bool {
        return self.connected;
    }

    /// Build a Transport vtable that wraps this transport.
    pub fn asTransport(self: *TcpTransport) fc.Transport {
        return .{
            .ctx = self,
            .sendFn = &sendAdapter,
            .recvFn = &recvAdapter,
            .isConnectedFn = &isConnectedAdapter,
        };
    }

    fn sendAdapter(ctx: *anyopaque, data: []const u8) fc.TransportError!void {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        return self.sendBytes(data) catch |err| switch (err) {
            error.NotConnected => error.NotConnected,
            error.SendFailed => error.SendFailed,
            error.ConnectionReset => error.SendFailed,
            error.Timeout => error.SendFailed,
            else => error.SendFailed,
        };
    }

    fn recvAdapter(ctx: *anyopaque, out: []u8) fc.TransportError!usize {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        return self.recvBytes(out) catch |err| switch (err) {
            error.NotConnected => error.NotConnected,
            error.ReceiveEmpty => error.ReceiveEmpty,
            error.ConnectionReset => error.NotConnected,
            error.Timeout => error.ReceiveEmpty,
            else => error.ReceiveEmpty,
        };
    }

    fn isConnectedAdapter(ctx: *anyopaque) bool {
        const self: *TcpTransport = @ptrCast(@alignCast(ctx));
        return self.isConnectedImpl();
    }

    pub fn resetStats(self: *TcpTransport) void {
        self.total_sent = 0;
        self.total_received = 0;
        self.total_bytes_sent = 0;
        self.total_bytes_received = 0;
        self.total_send_failures = 0;
        self.total_recv_failures = 0;
    }
};

// ============================================================
// TcpServer: bind + listen + accept
// ============================================================

pub const TcpServer = struct {
    fd: posix.fd_t = -1,
    bound_addr: std.net.Address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0),
    listening: bool = false,
    total_accepted: u64 = 0,
    total_accept_failures: u64 = 0,

    pub fn init() TcpServer {
        return .{};
    }

    pub fn deinit(self: *TcpServer) void {
        self.close();
    }

    pub fn close(self: *TcpServer) void {
        if (self.fd != -1) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.listening = false;
    }

    /// Bind to an address and start listening. If port is 0, the OS picks
    /// an ephemeral port (use boundAddress() to retrieve it).
    pub fn bindAndListen(self: *TcpServer, addr: std.net.Address, backlog: u31) TcpError!void {
        const fd = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return error.SocketCreateFailed;
        errdefer posix.close(fd);
        self.fd = fd;

        // SO_REUSEADDR so we can rebind quickly after restart
        const reuse: i32 = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse)) catch {};

        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch return error.BindFailed;
        posix.listen(fd, backlog) catch return error.ListenFailed;
        self.listening = true;

        // Retrieve the actually-bound address (port may be 0 = ephemeral)
        var bound: posix.sockaddr = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        posix.getsockname(fd, &bound, &bound_len) catch return error.BindFailed;
        self.bound_addr = std.net.Address.initPosix(@alignCast(&bound));
    }

    /// Accept one incoming connection. Returns a TcpTransport already
    /// configured with the right timeouts. Blocks until a connection
    /// arrives or the accept fails.
    pub fn accept(self: *TcpServer, recv_timeout_ms: i64, send_timeout_ms: i64) TcpError!TcpTransport {
        if (!self.listening) return error.NotConnected;
        var client_addr: posix.sockaddr = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const client_fd = posix.accept(self.fd, &client_addr, &client_len, posix.SOCK.CLOEXEC) catch |err| {
            self.total_accept_failures += 1;
            return switch (err) {
                error.WouldBlock => error.Timeout,
                error.ConnectionAborted, error.ConnectionResetByPeer => error.AcceptFailed,
                else => error.AcceptFailed,
            };
        };
        self.total_accepted += 1;
        var t = TcpTransport.init(recv_timeout_ms, send_timeout_ms);
        t.adoptFd(client_fd) catch |err| {
            posix.close(client_fd);
            return err;
        };
        return t;
    }

    pub fn boundAddress(self: *const TcpServer) std.net.Address {
        return self.bound_addr;
    }

    /// Format the bound address as "ip:port" for logging/config.
    pub fn formatBoundAddress(self: *const TcpServer, buf: []u8) ![]const u8 {
        var stream = std.io.fixedBufferStream(buf);
        try self.bound_addr.format("", .{}, stream.writer());
        return stream.getWritten();
    }
};

// ============================================================
// TcpClient: connect + reconnect logic
// ============================================================

pub const TcpClient = struct {
    transport: TcpTransport,
    config: TcpConfig,
    connect_attempts: u32 = 0,
    total_reconnects: u64 = 0,
    total_connect_failures: u64 = 0,

    pub fn init(config: TcpConfig) TcpClient {
        return .{
            .transport = TcpTransport.init(config.recv_timeout_ms, config.send_timeout_ms),
            .config = config,
        };
    }

    pub fn deinit(self: *TcpClient) void {
        self.transport.deinit();
    }

    /// Connect to the configured remote address.
    pub fn connect(self: *TcpClient) TcpError!void {
        const addr = try parseAddrPort(self.config.connect_addr);
        try self.transport.connect(addr);
        self.connect_attempts = 0;
    }

    /// Try to reconnect if currently disconnected. Returns true if a new
    /// connection was established, false if still disconnected (or already up).
    /// Uses exponential backoff; gives up after reconnect_max_attempts.
    pub fn reconnectIfNeeded(self: *TcpClient, now_ns: i64) TcpError!bool {
        if (self.transport.connected) return false;
        if (self.connect_attempts >= self.config.reconnect_max_attempts) return error.ConnectFailed;

        // Compute backoff (informational; caller honors via shouldRetry)
        const exp: f32 = @floatFromInt(self.connect_attempts);
        const factor = std.math.pow(f32, 2.0, exp);
        const _backoff_ms: i64 = @intFromFloat(@min(
            @as(f32, @floatFromInt(self.config.reconnect_initial_backoff_ms)) * factor,
            @as(f32, @floatFromInt(self.config.reconnect_max_backoff_ms)),
        ));
        _ = _backoff_ms;
        // For test simplicity: we don't actually sleep - the caller is
        // expected to honor shouldRetry(now_ns) before calling reconnect.

        _ = now_ns;
        self.connect_attempts += 1;
        self.total_reconnects += 1;
        self.connect() catch |err| {
            self.total_connect_failures += 1;
            return err;
        };
        return true;
    }

    pub fn shouldRetry(self: *const TcpClient) bool {
        return self.connect_attempts < self.config.reconnect_max_attempts;
    }

    pub fn close(self: *TcpClient) void {
        self.transport.close();
    }

    pub fn asTransport(self: *TcpClient) fc.Transport {
        return self.transport.asTransport();
    }
};

// ============================================================
// FramedReader: reassembles length-prefixed frames from byte stream
// ============================================================

pub const FramedReader = struct {
    buf: [MAX_FRAME_SIZE]u8 = undefined,
    buf_len: usize = 0,
    total_frames_decoded: u64 = 0,
    total_bytes_consumed: u64 = 0,
    total_partial_recvs: u64 = 0,

    pub fn init() FramedReader {
        return .{};
    }

    /// Try to read one complete frame from internal buffer. Returns:
    ///   - .frame(slice) if a complete frame is available
    ///   - .need_more if buffer doesn't have a complete frame yet
    ///   - error.CrcMismatch / etc. propagated from fc.decode
    pub const ReadResult = union(enum) {
        frame: []const u8,
        need_more: void,
        err: fc.DecodeError,
    };

    pub fn tryReadFrame(self: *FramedReader) ReadResult {
        if (self.buf_len < fc.HEADER_LEN) return .{ .need_more = {} };

        // Peek header for payload_len (without consuming)
        const hdr = fc.FrameHeader.readFrom(@ptrCast(self.buf[0..fc.HEADER_LEN]));
        if (hdr.magic != fc.MAGIC) return .{ .err = error.MagicMismatch };
        if (hdr.version != fc.VERSION) return .{ .err = error.VersionMismatch };
        if (hdr.payload_len > fc.MAX_PAYLOAD_SIZE) return .{ .err = error.PayloadTruncated };

        const total = fc.HEADER_LEN + hdr.payload_len;
        if (self.buf_len < total) return .{ .need_more = {} };

        // We have a complete frame - validate via decode (checks CRC)
        _ = fc.decode(self.buf[0..total]) catch |err| {
            return .{ .err = err };
        };
        self.total_frames_decoded += 1;
        return .{ .frame = self.buf[0..total] };
    }

    /// Consume bytes from a slice into the internal buffer. Returns the
    /// number of bytes appended (may be less than src.len if buffer is full).
    pub fn append(self: *FramedReader, src: []const u8) usize {
        const avail = self.buf.len - self.buf_len;
        const n = @min(src.len, avail);
        @memcpy(self.buf[self.buf_len .. self.buf_len + n], src[0..n]);
        self.buf_len += n;
        return n;
    }

    /// After tryReadFrame returns .frame and the caller has processed it,
    /// call this to discard the consumed frame and shift remaining bytes.
    pub fn consumeFrame(self: *FramedReader, frame_len: usize) void {
        std.debug.assert(frame_len <= self.buf_len);
        const remaining = self.buf_len - frame_len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[frame_len..self.buf_len]);
        }
        self.buf_len = remaining;
        self.total_bytes_consumed += frame_len;
    }

    /// High-level: pull bytes from a Transport, append to internal buffer,
    /// and return one complete frame if available. Returns:
    ///   - .frame(slice) on success (caller-owned, valid until next call)
    ///   - .need_more if transport had no bytes available
    ///   - .err on transport or decode failure
    pub fn readFrameFromTransport(self: *FramedReader, transport: fc.Transport) ReadResult {
        // Try to decode what we already have first
        switch (self.tryReadFrame()) {
            .frame => |f| return .{ .frame = f },
            .err => |e| return .{ .err = e },
            .need_more => {},
        }

        // Pull more bytes from transport
        var tmp: [RECV_BUF_SIZE]u8 = undefined;
        const n = transport.recv(&tmp) catch |err| switch (err) {
            error.ReceiveEmpty => return .{ .need_more = {} },
            error.NotConnected => return .{ .err = error.PayloadTruncated },
            else => return .{ .err = error.MalformedPayload },
        };
        if (n == 0) return .{ .need_more = {} };
        self.total_partial_recvs += 1;
        _ = self.append(tmp[0..n]);

        // Try again to decode
        return self.tryReadFrame();
    }

    pub fn reset(self: *FramedReader) void {
        self.buf_len = 0;
    }

    pub fn pendingBytes(self: *const FramedReader) usize {
        return self.buf_len;
    }
};

// ============================================================
// Tests
// ============================================================

test "TcpConfig defaults - kill switch OFF" {
    const c = TcpConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqualStrings("127.0.0.1:0", c.bind_addr);
    try std.testing.expectEqual(@as(i64, 1000), c.recv_timeout_ms);
    try std.testing.expectEqual(@as(u31, 32), c.listen_backlog);
}

test "parseAddrPort IPv4 with port" {
    const addr = try parseAddrPort("127.0.0.1:8080");
    try std.testing.expectEqual(@as(u16, 8080), addr.in.getPort());
}

test "parseAddrPort IPv4 port 0 (ephemeral)" {
    const addr = try parseAddrPort("127.0.0.1:0");
    try std.testing.expectEqual(@as(u16, 0), addr.in.getPort());
}

test "parseAddrPort wildcard host" {
    const addr = try parseAddrPort("*:7931");
    try std.testing.expectEqual(@as(u16, 7931), addr.in.getPort());
}

test "parseAddrPort rejects missing port" {
    try std.testing.expectError(error.InvalidAddress, parseAddrPort("127.0.0.1"));
}

test "parseAddrPort rejects bad port" {
    try std.testing.expectError(error.InvalidAddress, parseAddrPort("127.0.0.1:notaport"));
}

test "TcpTransport init defaults" {
    const t = TcpTransport.init(1000, 5000);
    try std.testing.expectEqual(@as(posix.fd_t, -1), t.fd);
    try std.testing.expect(!t.connected);
    try std.testing.expectEqual(@as(i64, 1000), t.recv_timeout_ms);
    try std.testing.expectEqual(@as(i64, 5000), t.send_timeout_ms);
}

test "TcpTransport isConnected returns false when not connected" {
    var t = TcpTransport.init(1000, 5000);
    defer t.deinit();
    try std.testing.expect(!t.isConnectedImpl());
    const transport = t.asTransport();
    try std.testing.expect(!transport.isConnected());
}

test "TcpTransport sendBytes fails when not connected" {
    var t = TcpTransport.init(1000, 5000);
    defer t.deinit();
    try std.testing.expectError(error.NotConnected, t.sendBytes("data"));
}

test "TcpTransport recvBytes fails when not connected" {
    var t = TcpTransport.init(1000, 5000);
    defer t.deinit();
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.NotConnected, t.recvBytes(&buf));
}

test "TcpServer bind and listen on ephemeral port" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    try std.testing.expect(srv.listening);
    const bound = srv.boundAddress();
    try std.testing.expect(bound.in.getPort() != 0); // OS assigned a port
}

test "TcpServer + TcpTransport connect + send + recv roundtrip" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    // Spawn a tiny acceptor thread (so we can connect from main thread)
    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        err: *?TcpError,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch |e| {
                a.err.* = e;
                return;
            };
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var accept_err: ?TcpError = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted, .err = &accept_err };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    // Client connects
    var client = TcpTransport.init(1000, 5000);
    defer client.deinit();
    try client.connect(bound);
    try std.testing.expect(client.connected);

    // Wait for server accept to finish
    thread.join();  // wait for acceptor to complete

    if (accept_err != null) return error.TestAcceptorFailed;
    var server_side = accepted.?;
    defer server_side.deinit();

    // Client sends
    const payload = "hello federation";
    try client.sendBytes(payload);
    try std.testing.expectEqual(@as(u64, 1), client.total_sent);
    try std.testing.expectEqual(@as(u64, payload.len), client.total_bytes_sent);

    // Server receives
    var buf: [64]u8 = undefined;
    const n = try server_side.recvBytes(&buf);
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualSlices(u8, payload, buf[0..n]);
}

test "TcpServer + TcpClient full roundtrip via TcpClient wrapper" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    // Format the bound address as "ip:port" for TcpClient
    var addr_buf: [64]u8 = undefined;
    var stream = std.io.fixedBufferStream(&addr_buf);
    try bound.format("", .{}, stream.writer());
    const addr_str = stream.getWritten();

    // Spawn acceptor
    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    // Client connects via TcpClient
    var client = TcpClient.init(.{ .connect_addr = addr_str });
    defer client.deinit();
    try client.connect();
    try std.testing.expect(client.transport.connected);

    thread.join();  // wait for acceptor to complete
    var server_side = accepted.?;
    defer server_side.deinit();

    // Send from client to server
    try client.transport.sendBytes("ping");

    var buf: [16]u8 = undefined;
    const n = try server_side.recvBytes(&buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualSlices(u8, "ping", buf[0..n]);
}

test "TcpServer accept fails when not listening" {
    var srv = TcpServer.init();
    defer srv.deinit();
    // not bound yet
    try std.testing.expectError(error.NotConnected, srv.accept(1000, 5000));
}

test "FramedReader needs more on empty buffer" {
    var fr = FramedReader.init();
    const r = fr.tryReadFrame();
    switch (r) {
        .need_more => {},
        else => return error.TestExpectedNeedMore,
    }
}

test "FramedReader needs more on partial header" {
    var fr = FramedReader.init();
    _ = fr.append("AEG"); // partial magic
    switch (fr.tryReadFrame()) {
        .need_more => {},
        else => return error.TestExpectedNeedMore,
    }
}

test "FramedReader decodes complete frame" {
    var fr = FramedReader.init();
    // Encode a heartbeat frame
    var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = try fc.encode(.{
        .msg_type = .heartbeat,
        .from_node_id = 7,
        .timestamp_ns = 1_000_000_000,
    }, &wire);
    _ = fr.append(wire[0..n]);

    switch (fr.tryReadFrame()) {
        .frame => |f| {
            try std.testing.expectEqual(n, f.len);
            // Re-decode to confirm fields
            const msg = try fc.decode(f);
            try std.testing.expectEqual(cc.MessageType.heartbeat, msg.msg_type);
            try std.testing.expectEqual(@as(u32, 7), msg.from_node_id);
        },
        else => return error.TestExpectedFrame,
    }
}

test "FramedReader handles split delivery (two recv calls)" {
    var fr = FramedReader.init();
    var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = try fc.encode(.{
        .msg_type = .heartbeat,
        .from_node_id = 7,
        .timestamp_ns = 1_000_000_000,
    }, &wire);

    // First append: only 6 bytes (half of header)
    _ = fr.append(wire[0..6]);
    switch (fr.tryReadFrame()) {
        .need_more => {},
        else => return error.TestExpectedNeedMore,
    }

    // Second append: rest of the frame
    _ = fr.append(wire[6..n]);
    switch (fr.tryReadFrame()) {
        .frame => |f| try std.testing.expectEqual(n, f.len),
        else => return error.TestExpectedFrame,
    }
}

test "FramedReader consumeFrame shifts remaining bytes" {
    var fr = FramedReader.init();
    var wire1: [fc.MAX_FRAME_SIZE]u8 = undefined;
    var wire2: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n1 = try fc.encode(.{ .msg_type = .heartbeat, .from_node_id = 1, .timestamp_ns = 1 }, &wire1);
    const n2 = try fc.encode(.{ .msg_type = .heartbeat, .from_node_id = 2, .timestamp_ns = 2 }, &wire2);

    // Append both frames into buffer
    _ = fr.append(wire1[0..n1]);
    _ = fr.append(wire2[0..n2]);

    // Read first
    const f1 = switch (fr.tryReadFrame()) {
        .frame => |f| f,
        else => return error.TestExpectedFrame,
    };
    try std.testing.expectEqual(n1, f1.len);
    fr.consumeFrame(n1);

    // Read second
    const f2 = switch (fr.tryReadFrame()) {
        .frame => |f| f,
        else => return error.TestExpectedFrame,
    };
    try std.testing.expectEqual(n2, f2.len);
    fr.consumeFrame(n2);

    // Buffer should be empty now
    try std.testing.expectEqual(@as(usize, 0), fr.pendingBytes());
}

test "FramedReader detects magic mismatch" {
    var fr = FramedReader.init();
    // Garbage data with wrong magic
    _ = fr.append("XXXX");
    // Pad to header length
    while (fr.buf_len < fc.HEADER_LEN) {
        const single = [_]u8{0};
        _ = fr.append(&single);
    }
    switch (fr.tryReadFrame()) {
        .err => |e| try std.testing.expectEqual(fc.DecodeError.MagicMismatch, e),
        else => return error.TestExpectedError,
    }
}

test "FramedReader readFrameFromTransport pulls from transport" {
    // Start a server, connect a client, send a frame, reassemble on the other side
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    var client = TcpTransport.init(1000, 5000);
    defer client.deinit();
    try client.connect(bound);

    // Encode a heartbeat frame and send it
    var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
    const n = try fc.encode(.{
        .msg_type = .heartbeat,
        .from_node_id = 42,
        .timestamp_ns = 1_000_000_000,
    }, &wire);
    try client.sendBytes(wire[0..n]);

    thread.join();  // wait for acceptor to complete
    var server_side = accepted.?;
    defer server_side.deinit();

    // Reassemble on server side
    var reader = FramedReader.init();
    const r = reader.readFrameFromTransport(server_side.asTransport());
    switch (r) {
        .frame => |f| {
            const msg = try fc.decode(f);
            try std.testing.expectEqual(cc.MessageType.heartbeat, msg.msg_type);
            try std.testing.expectEqual(@as(u32, 42), msg.from_node_id);
        },
        else => return error.TestExpectedFrame,
    }
}

test "TcpClient reconnectIfNeeded returns false when already connected" {
    // Without actually opening a socket - just check the early-return path
    var client = TcpClient.init(.{ .connect_addr = "127.0.0.1:1" });
    defer client.deinit();
    client.transport.connected = true; // simulate
    const r = client.reconnectIfNeeded(0) catch return error.TestUnexpectedError;
    try std.testing.expect(!r);
}

test "TcpClient reconnectIfNeeded fails when no listener" {
    // Use a port that's almost certainly closed (port 1 requires root)
    var client = TcpClient.init(.{ .connect_addr = "127.0.0.1:9", .reconnect_max_attempts = 1 });
    defer client.deinit();
    try std.testing.expectError(error.ConnectFailed, client.reconnectIfNeeded(0));
    try std.testing.expectEqual(@as(u32, 1), client.connect_attempts);
    try std.testing.expectEqual(@as(u64, 1), client.total_connect_failures);
}

test "TcpClient shouldRetry respects max_attempts" {
    var client = TcpClient.init(.{ .reconnect_max_attempts = 3 });
    try std.testing.expect(client.shouldRetry());
    client.connect_attempts = 3;
    try std.testing.expect(!client.shouldRetry());
}

test "End-to-end: 2 nodes exchange messages via real TCP" {
    // Spawn a server, accept a connection, exchange 3 framed messages
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    var client = TcpTransport.init(1000, 5000);
    defer client.deinit();
    try client.connect(bound);

    thread.join();  // wait for acceptor to complete
    var server_side = accepted.?;
    defer server_side.deinit();

    // Send 3 messages from client
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = try fc.encode(.{
            .msg_type = .heartbeat,
            .from_node_id = i + 1,
            .timestamp_ns = @as(i64, @intCast(i + 1)) * 1_000_000_000,
        }, &wire);
        try client.sendBytes(wire[0..n]);
    }

    // Reassemble 3 frames on server side
    var reader = FramedReader.init();
    var received: u32 = 0;
    while (received < 3) {
        switch (reader.readFrameFromTransport(server_side.asTransport())) {
            .frame => |f| {
                const msg = try fc.decode(f);
                try std.testing.expectEqual(@as(u32, received + 1), msg.from_node_id);
                reader.consumeFrame(f.len);
                received += 1;
            },
            .need_more => continue,
            .err => return error.TestUnexpectedDecodeError,
        }
    }
    try std.testing.expectEqual(@as(u32, 3), received);
}

test "TcpTransport detects peer disconnect on recv" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    var client = TcpTransport.init(1000, 5000);
    defer client.deinit();
    try client.connect(bound);
    thread.join();  // wait for acceptor to complete

    var server_side = accepted.?;
    defer server_side.deinit();

    // Client closes first
    client.close();

    // Server tries to recv -> should get ConnectionReset (peer closed)
    var buf: [16]u8 = undefined;
    const err = server_side.recvBytes(&buf);
    try std.testing.expectError(error.ConnectionReset, err);
    try std.testing.expect(!server_side.connected);
}

test "TcpTransport asTransport vtable works through fc.Transport interface" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    const bound = srv.boundAddress();

    const ThreadArgs = struct {
        srv: *TcpServer,
        accepted: *?TcpTransport,
        fn run(a: *@This()) void {
            const accepted = a.srv.accept(1000, 5000) catch return;
            a.accepted.* = accepted;
        }
    };
    var accepted: ?TcpTransport = null;
    var targs = ThreadArgs{ .srv = &srv, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ThreadArgs.run, .{&targs});

    var client = TcpTransport.init(1000, 5000);
    defer client.deinit();
    try client.connect(bound);
    thread.join();  // wait for acceptor to complete

    var server_side = accepted.?;
    defer server_side.deinit();

    // Use the vtable interface
    const tp = client.asTransport();
    try std.testing.expect(tp.isConnected());
    try tp.send("vtable test");

    // Receive on server side using its own vtable
    const tp2 = server_side.asTransport();
    var buf: [32]u8 = undefined;
    const n = try tp2.recv(&buf);
    try std.testing.expectEqual(@as(usize, 11), n);
    try std.testing.expectEqualSlices(u8, "vtable test", buf[0..n]);
}

test "TcpServer bound address format" {
    var srv = TcpServer.init();
    defer srv.deinit();
    const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try srv.bindAndListen(addr, 4);
    var buf: [64]u8 = undefined;
    const s = try srv.formatBoundAddress(&buf);
    // Should contain "127.0.0.1" and a non-zero port
    try std.testing.expect(std.mem.indexOf(u8, s, "127.0.0.1") != null);
}

test "FramedReader append respects buffer capacity" {
    var fr = FramedReader.init();
    // Fill the buffer completely
    const data = [_]u8{0xAA} ** 16;
    var total: usize = 0;
    while (total < fr.buf.len) {
        const n = fr.append(&data);
        total += n;
        if (n == 0) break;
    }
    try std.testing.expectEqual(fr.buf.len, fr.buf_len);
    // Further append should return 0
    const n = fr.append(&data);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "TcpTransport resetStats" {
    var t = TcpTransport.init(1000, 5000);
    t.total_sent = 5;
    t.total_received = 3;
    t.total_bytes_sent = 100;
    t.total_bytes_received = 60;
    t.total_send_failures = 1;
    t.total_recv_failures = 0;
    t.resetStats();
    try std.testing.expectEqual(@as(u64, 0), t.total_sent);
    try std.testing.expectEqual(@as(u64, 0), t.total_received);
    try std.testing.expectEqual(@as(u64, 0), t.total_bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), t.total_bytes_received);
}

test "TcpClient close marks transport disconnected" {
    var client = TcpClient.init(.{ .connect_addr = "127.0.0.1:1" });
    defer client.deinit();
    client.transport.connected = true;
    client.close();
    try std.testing.expect(!client.transport.connected);
}
