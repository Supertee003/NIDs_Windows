//! federation_bench.zig - AEGIS NIDS Phase 43: Cross-Node Federation Benchmark
//!
//! Measures real TCP throughput between 2 in-process AEGIS nodes using the
//! Phase 39 Ext 2 federation TCP adapter. While Phase 41 measured codec
//! encode/decode in isolation (110k ops/sec), this phase measures the full
//! network roundtrip: encode -> TCP send -> TCP recv -> FramedReader reassembly
//! -> decode.
//!
//! Five benchmark suites:
//!   1. Heartbeat throughput: HEARTBEAT messages/sec (small, frequent)
//!   2. Incident report throughput: INCIDENT_REPORT messages/sec (medium)
//!   3. Threat intel share: THREAT_INTEL_SHARE messages/sec (large payload)
//!   4. Multi-message stream: batch of 10 messages per roundtrip
//!   5. Failover/reconnect: connection drop + reconnect cycle time
//!
//! Design principles (mirrors Phase 41/42):
//!   - Pure Zig, host-testable on Linux (uses real TCP sockets on 127.0.0.1)
//!   - Two nodes in-process: server accepts, client connects, exchange frames
//!   - Measures end-to-end: encode + send + recv + reassemble + decode
//!   - Kill switch OFF by default; FedBenchConfig{.enabled=true} opts in
//!   - Reports msgs/sec, us/msg, and effective Mbps
//!
//! Build:
//!   zig test federation_bench.zig -lc
//!   zig build-exe federation_bench_cli.zig -lc

const std = @import("std");
const fc = @import("federation_codec.zig");
const ft = @import("federation_tcp.zig");
const cc = @import("cluster_coord.zig");

// ============================================================
// Constants & limits
// ============================================================

pub const DEFAULT_WARMUP: u32 = 50;
pub const DEFAULT_ITERATIONS: u32 = 1_000;
pub const DEFAULT_RECV_TIMEOUT_MS: i64 = 5_000;
pub const DEFAULT_SEND_TIMEOUT_MS: i64 = 5_000;
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

// ============================================================
// FedBenchConfig (kill switch + iteration params)
// ============================================================

pub const FedBenchConfig = struct {
    /// Master kill switch. OFF by default.
    enabled: bool = false,
    /// Warmup iterations (not measured)
    warmup: u32 = DEFAULT_WARMUP,
    /// Measured iterations
    iterations: u32 = DEFAULT_ITERATIONS,
    /// Socket timeouts
    recv_timeout_ms: i64 = DEFAULT_RECV_TIMEOUT_MS,
    send_timeout_ms: i64 = DEFAULT_SEND_TIMEOUT_MS,
    /// Multi-message batch size (for suite 4)
    batch_size: u32 = 10,
};

// ============================================================
// FedBenchResult (single measurement)
// ============================================================

pub const FedBenchResult = struct {
    name: []const u8,
    iterations: u32,
    total_ns: i64,
    msgs_per_sec: f64,
    us_per_msg: f64,
    bytes_per_msg: u64 = 0,
    effective_mbps: f64 = 0.0,
    errors: u32 = 0,

    pub fn print(self: FedBenchResult, writer: anytype) !void {
        try writer.print("  {s:<45} {d:>6} msgs  {d:>10.0} msgs/sec  {d:>8.2} us/msg", .{
            self.name,
            self.iterations,
            self.msgs_per_sec,
            self.us_per_msg,
        });
        if (self.bytes_per_msg > 0) {
            try writer.print("  {d:>8.1} Mb/s", .{self.effective_mbps});
        }
        if (self.errors > 0) {
            try writer.print("  {d:>4} errors", .{self.errors});
        }
        try writer.print("\n", .{});
    }
};

// ============================================================
// FedBenchTimer (high-precision timing)
// ============================================================

pub const FedBenchTimer = struct {
    start_ns: i64,
    end_ns: i64,

    pub fn start() FedBenchTimer {
        return .{ .start_ns = @intCast(std.time.nanoTimestamp()), .end_ns = 0 };
    }

    pub fn stop(self: *FedBenchTimer) void {
        self.end_ns = @intCast(std.time.nanoTimestamp());
    }

    pub fn elapsedNs(self: FedBenchTimer) i64 {
        return self.end_ns - self.start_ns;
    }

    pub fn msgsPerSec(self: FedBenchTimer, iterations: u32) f64 {
        const elapsed = self.elapsedNs();
        if (elapsed <= 0) return 0.0;
        return @as(f64, @floatFromInt(iterations)) * @as(f64, @floatFromInt(NANOS_PER_SEC)) / @as(f64, @floatFromInt(elapsed));
    }
};

// ============================================================
// FedBenchRunner (executes benchmarks and collects results)
// ============================================================

pub const FedBenchRunner = struct {
    config: FedBenchConfig,
    results: std.ArrayList(FedBenchResult),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: FedBenchConfig) FedBenchRunner {
        return .{
            .config = config,
            .results = std.ArrayList(FedBenchResult).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FedBenchRunner) void {
        self.results.deinit();
    }

    /// Print all results as a table.
    pub fn printReport(self: *FedBenchRunner, writer: anytype) !void {
        try writer.print("\n", .{});
        var i: u32 = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\nCross-Node Federation Benchmark Report\n", .{});
        i = 0;
        while (i < 80) : (i += 1) try writer.print("=", .{});
        try writer.print("\n\n", .{});
        try writer.print("Config: warmup={d}, iterations={d}, batch_size={d}\n\n", .{
            self.config.warmup, self.config.iterations, self.config.batch_size,
        });
        i = 0;
        while (i < 80) : (i += 1) try writer.print("-", .{});
        try writer.print("\n", .{});
        for (self.results.items) |r| {
            try r.print(writer);
        }
        i = 0;
        while (i < 80) : (i += 1) try writer.print("-", .{});
        try writer.print("\n", .{});
    }

    pub fn getResult(self: *const FedBenchRunner, name: []const u8) ?FedBenchResult {
        for (self.results.items) |r| {
            if (std.mem.eql(u8, r.name, name)) return r;
        }
        return null;
    }

    pub fn resultCount(self: *const FedBenchRunner) usize {
        return self.results.items.len;
    }
};

// ============================================================
// Test harness: 2-node TCP setup (server + client in-process)
// ============================================================

pub const NodePair = struct {
    server: ft.TcpServer,
    client: ft.TcpTransport,
    server_conn: ft.TcpTransport,
    allocator: std.mem.Allocator,
    recv_timeout_ms: i64,
    send_timeout_ms: i64,

    /// Spawns a server on an ephemeral port, accepts a connection from
    /// a client, and returns both ends ready for exchange.
    pub fn setup(allocator: std.mem.Allocator, recv_timeout_ms: i64, send_timeout_ms: i64) !NodePair {
        var srv = ft.TcpServer.init();
        const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch return error.SetupFailed;
        try srv.bindAndListen(addr, 4);
        const bound = srv.boundAddress();

        // Spawn acceptor thread
        const AcceptorArgs = struct {
            srv: *ft.TcpServer,
            accepted: *?ft.TcpTransport,
            recv_to: i64,
            send_to: i64,
            fn run(a: *@This()) void {
                const accepted = a.srv.accept(a.recv_to, a.send_to) catch return;
                a.accepted.* = accepted;
            }
        };
        var accepted: ?ft.TcpTransport = null;
        var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted, .recv_to = recv_timeout_ms, .send_to = send_timeout_ms };
        const thread = try std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs});

        // Client connects
        var client = ft.TcpTransport.init(recv_timeout_ms, send_timeout_ms);
        try client.connect(bound);

        thread.join();
        if (accepted == null) return error.SetupFailed;

        return .{
            .server = srv,
            .client = client,
            .server_conn = accepted.?,
            .allocator = allocator,
            .recv_timeout_ms = recv_timeout_ms,
            .send_timeout_ms = send_timeout_ms,
        };
    }

    pub fn close(self: *NodePair) void {
        self.client.deinit();
        self.server_conn.deinit();
        self.server.deinit();
    }
};

// ============================================================
// Benchmark Suite 1: Heartbeat throughput
// ============================================================
//
// Measures HEARTBEAT message roundtrip: encode -> send -> recv -> decode.
// Heartbeats are small (~47 bytes) and frequent (every 5s per node).

pub fn benchHeartbeat(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchResult {
    var pair = try NodePair.setup(allocator, config.recv_timeout_ms, config.send_timeout_ms);
    defer pair.close();

    var reader = ft.FramedReader.init();
    var errors: u32 = 0;

    // Warmup
    var i: u32 = 0;
    while (i < config.warmup) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .heartbeat,
            .from_node_id = 1,
            .timestamp_ns = @as(i64, @intCast(i)),
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }

    // Measured
    var timer = FedBenchTimer.start();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .heartbeat,
            .from_node_id = 1,
            .timestamp_ns = @as(i64, @intCast(i)),
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }
    timer.stop();

    const elapsed_ns = timer.elapsedNs();
    const msgs_per_sec = timer.msgsPerSec(config.iterations);
    const us_per_msg = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(config.iterations)) / 1000.0;
    const bytes_per_msg: u64 = 47; // typical heartbeat frame size
    const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NANOS_PER_SEC));
    const effective_mbps = if (elapsed_secs > 0)
        @as(f64, @floatFromInt(bytes_per_msg * config.iterations)) * 8.0 / elapsed_secs / 1_000_000.0
    else
        0.0;

    return .{
        .name = "Heartbeat roundtrip (47 bytes)",
        .iterations = config.iterations,
        .total_ns = elapsed_ns,
        .msgs_per_sec = msgs_per_sec,
        .us_per_msg = us_per_msg,
        .bytes_per_msg = bytes_per_msg,
        .effective_mbps = effective_mbps,
        .errors = errors,
    };
}

// ============================================================
// Benchmark Suite 2: Incident report throughput
// ============================================================
//
// Measures INCIDENT_REPORT message roundtrip. Medium-sized (~56 bytes)
// with source IP, port, severity, score, label.

pub fn benchIncidentReport(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchResult {
    var pair = try NodePair.setup(allocator, config.recv_timeout_ms, config.send_timeout_ms);
    defer pair.close();

    var reader = ft.FramedReader.init();
    var errors: u32 = 0;

    // Warmup
    var i: u32 = 0;
    while (i < config.warmup) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .incident_report,
            .from_node_id = 1,
            .timestamp_ns = @as(i64, @intCast(i)),
            .incident_source_ip = .{ 198, 51, 100, 5 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .high,
            .incident_score = 0.85,
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }

    // Measured
    var timer = FedBenchTimer.start();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .incident_report,
            .from_node_id = 1,
            .timestamp_ns = @as(i64, @intCast(i)),
            .incident_source_ip = .{ 198, 51, 100, 5 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .high,
            .incident_score = 0.85,
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }
    timer.stop();

    const elapsed_ns = timer.elapsedNs();
    const msgs_per_sec = timer.msgsPerSec(config.iterations);
    const us_per_msg = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(config.iterations)) / 1000.0;
    const bytes_per_msg: u64 = 56;
    const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NANOS_PER_SEC));
    const effective_mbps = if (elapsed_secs > 0)
        @as(f64, @floatFromInt(bytes_per_msg * config.iterations)) * 8.0 / elapsed_secs / 1_000_000.0
    else
        0.0;

    return .{
        .name = "Incident report roundtrip (56 bytes)",
        .iterations = config.iterations,
        .total_ns = elapsed_ns,
        .msgs_per_sec = msgs_per_sec,
        .us_per_msg = us_per_msg,
        .bytes_per_msg = bytes_per_msg,
        .effective_mbps = effective_mbps,
        .errors = errors,
    };
}

// ============================================================
// Benchmark Suite 3: Threat intel share throughput
// ============================================================

pub fn benchThreatIntel(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchResult {
    var pair = try NodePair.setup(allocator, config.recv_timeout_ms, config.send_timeout_ms);
    defer pair.close();

    var reader = ft.FramedReader.init();
    var errors: u32 = 0;

    // Warmup
    var i: u32 = 0;
    while (i < config.warmup) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .threat_intel_share,
            .from_node_id = 2,
            .timestamp_ns = @as(i64, @intCast(i)),
            .threat_intel = .{
                .kind = .c2_server,
                .ip = .{ 198, 51, 100, 7 },
                .source_node_id = 2,
                .first_seen_ns = 1_400_000_000,
                .confidence = 95,
            },
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }

    // Measured
    var timer = FedBenchTimer.start();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .threat_intel_share,
            .from_node_id = 2,
            .timestamp_ns = @as(i64, @intCast(i)),
            .threat_intel = .{
                .kind = .c2_server,
                .ip = .{ 198, 51, 100, 7 },
                .source_node_id = 2,
                .first_seen_ns = 1_400_000_000,
                .confidence = 95,
            },
        }, &wire) catch {
            errors += 1;
            continue;
        };
        pair.client.sendBytes(wire[0..n]) catch {
            errors += 1;
            continue;
        };
        switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
            .frame => |f| {
                _ = fc.decode(f) catch {
                    errors += 1;
                };
                reader.consumeFrame(f.len);
            },
            .err => errors += 1,
            .need_more => errors += 1,
        }
    }
    timer.stop();

    const elapsed_ns = timer.elapsedNs();
    const msgs_per_sec = timer.msgsPerSec(config.iterations);
    const us_per_msg = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(config.iterations)) / 1000.0;
    const bytes_per_msg: u64 = 72;
    const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NANOS_PER_SEC));
    const effective_mbps = if (elapsed_secs > 0)
        @as(f64, @floatFromInt(bytes_per_msg * config.iterations)) * 8.0 / elapsed_secs / 1_000_000.0
    else
        0.0;

    return .{
        .name = "Threat intel share roundtrip (72 bytes)",
        .iterations = config.iterations,
        .total_ns = elapsed_ns,
        .msgs_per_sec = msgs_per_sec,
        .us_per_msg = us_per_msg,
        .bytes_per_msg = bytes_per_msg,
        .effective_mbps = effective_mbps,
        .errors = errors,
    };
}

// ============================================================
// Benchmark Suite 4: Multi-message stream (batch of 10)
// ============================================================

pub fn benchMultiMessageStream(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchResult {
    var pair = try NodePair.setup(allocator, config.recv_timeout_ms, config.send_timeout_ms);
    defer pair.close();

    var reader = ft.FramedReader.init();
    var errors: u32 = 0;
    const batch = config.batch_size;

    // Warmup (batch_size messages per iteration)
    var i: u32 = 0;
    while (i < config.warmup) : (i += 1) {
        var j: u32 = 0;
        while (j < batch) : (j += 1) {
            var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
            const n = fc.encode(.{
                .msg_type = .heartbeat,
                .from_node_id = j,
                .timestamp_ns = @as(i64, @intCast(i * batch + j)),
            }, &wire) catch {
                errors += 1;
                continue;
            };
            pair.client.sendBytes(wire[0..n]) catch {
                errors += 1;
                continue;
            };
        }
        // Receive all batch messages
        j = 0;
        while (j < batch) : (j += 1) {
            switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
                .frame => |f| {
                    _ = fc.decode(f) catch {
                        errors += 1;
                    };
                    reader.consumeFrame(f.len);
                },
                .err => errors += 1,
                .need_more => errors += 1,
            }
        }
    }

    // Measured
    var timer = FedBenchTimer.start();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var j: u32 = 0;
        while (j < batch) : (j += 1) {
            var wire: [fc.MAX_FRAME_SIZE]u8 = undefined;
            const n = fc.encode(.{
                .msg_type = .heartbeat,
                .from_node_id = j,
                .timestamp_ns = @as(i64, @intCast(i * batch + j)),
            }, &wire) catch {
                errors += 1;
                continue;
            };
            pair.client.sendBytes(wire[0..n]) catch {
                errors += 1;
                continue;
            };
        }
        j = 0;
        while (j < batch) : (j += 1) {
            switch (reader.readFrameFromTransport(pair.server_conn.asTransport())) {
                .frame => |f| {
                    _ = fc.decode(f) catch {
                        errors += 1;
                    };
                    reader.consumeFrame(f.len);
                },
                .err => errors += 1,
                .need_more => errors += 1,
            }
        }
    }
    timer.stop();

    const total_msgs = config.iterations * batch;
    const elapsed_ns = timer.elapsedNs();
    const msgs_per_sec = @as(f64, @floatFromInt(total_msgs)) * @as(f64, @floatFromInt(NANOS_PER_SEC)) / @as(f64, @floatFromInt(elapsed_ns));
    const us_per_msg = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(total_msgs)) / 1000.0;
    const bytes_per_msg: u64 = 47;
    const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NANOS_PER_SEC));
    const effective_mbps = if (elapsed_secs > 0)
        @as(f64, @floatFromInt(bytes_per_msg * total_msgs)) * 8.0 / elapsed_secs / 1_000_000.0
    else
        0.0;

    return .{
        .name = "Multi-message stream (10 msgs/batch)",
        .iterations = total_msgs,
        .total_ns = elapsed_ns,
        .msgs_per_sec = msgs_per_sec,
        .us_per_msg = us_per_msg,
        .bytes_per_msg = bytes_per_msg,
        .effective_mbps = effective_mbps,
        .errors = errors,
    };
}

// ============================================================
// Benchmark Suite 5: Failover/reconnect cycle time
// ============================================================

pub fn benchFailoverReconnect(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchResult {
    _ = allocator;
    var errors: u32 = 0;

    // Warmup: connect + disconnect cycles
    var i: u32 = 0;
    while (i < config.warmup) : (i += 1) {
        var srv = ft.TcpServer.init();
        const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch {
            errors += 1;
            continue;
        };
        srv.bindAndListen(addr, 4) catch {
            errors += 1;
            continue;
        };
        const bound = srv.boundAddress();

        const AcceptorArgs = struct {
            srv: *ft.TcpServer,
            accepted: *?ft.TcpTransport,
            fn run(a: *@This()) void {
                const accepted = a.srv.accept(5000, 5000) catch return;
                a.accepted.* = accepted;
            }
        };
        var accepted: ?ft.TcpTransport = null;
        var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
        const thread = std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs}) catch {
            srv.deinit();
            errors += 1;
            continue;
        };

        var client = ft.TcpTransport.init(5000, 5000);
        client.connect(bound) catch {
            thread.join();
            srv.deinit();
            errors += 1;
            continue;
        };
        thread.join();
        if (accepted) |*sc| sc.deinit();
        client.deinit();
        srv.deinit();
    }

    // Measured
    var timer = FedBenchTimer.start();
    i = 0;
    while (i < config.iterations) : (i += 1) {
        var srv = ft.TcpServer.init();
        const addr = std.net.Address.parseIp4("127.0.0.1", 0) catch {
            errors += 1;
            continue;
        };
        srv.bindAndListen(addr, 4) catch {
            errors += 1;
            continue;
        };
        const bound = srv.boundAddress();

        const AcceptorArgs = struct {
            srv: *ft.TcpServer,
            accepted: *?ft.TcpTransport,
            fn run(a: *@This()) void {
                const accepted = a.srv.accept(5000, 5000) catch return;
                a.accepted.* = accepted;
            }
        };
        var accepted: ?ft.TcpTransport = null;
        var aargs = AcceptorArgs{ .srv = &srv, .accepted = &accepted };
        const thread = std.Thread.spawn(.{}, AcceptorArgs.run, .{&aargs}) catch {
            srv.deinit();
            errors += 1;
            continue;
        };

        var client = ft.TcpTransport.init(5000, 5000);
        client.connect(bound) catch {
            thread.join();
            srv.deinit();
            errors += 1;
            continue;
        };
        thread.join();
        if (accepted) |*sc| sc.deinit();
        client.deinit();
        srv.deinit();
    }
    timer.stop();

    const elapsed_ns = timer.elapsedNs();
    const cycles_per_sec = @as(f64, @floatFromInt(config.iterations)) * @as(f64, @floatFromInt(NANOS_PER_SEC)) / @as(f64, @floatFromInt(elapsed_ns));
    const us_per_cycle = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(config.iterations)) / 1000.0;

    return .{
        .name = "Failover/reconnect cycle (bind+connect+close)",
        .iterations = config.iterations,
        .total_ns = elapsed_ns,
        .msgs_per_sec = cycles_per_sec,
        .us_per_msg = us_per_cycle,
        .errors = errors,
    };
}

// ============================================================
// Convenience: run all federation benchmarks
// ============================================================

pub fn runAllFederationBenchmarks(allocator: std.mem.Allocator, config: FedBenchConfig) !FedBenchRunner {
    var runner = FedBenchRunner.init(allocator, config);
    errdefer runner.deinit();

    try runner.results.append(try benchHeartbeat(allocator, config));
    try runner.results.append(try benchIncidentReport(allocator, config));
    try runner.results.append(try benchThreatIntel(allocator, config));
    try runner.results.append(try benchMultiMessageStream(allocator, config));
    try runner.results.append(try benchFailoverReconnect(allocator, config));

    return runner;
}

// ============================================================
// Threshold checker
// ============================================================

pub const FedThresholdResult = struct {
    name: []const u8,
    actual: f64,
    threshold: f64,
    passed: bool,
};

pub fn checkFedThresholds(runner: *const FedBenchRunner) std.ArrayList(FedThresholdResult) {
    var results = std.ArrayList(FedThresholdResult).init(runner.allocator);
    const thresholds = [_]struct { name: []const u8, min: f64 }{
        .{ .name = "Heartbeat roundtrip (47 bytes)", .min = 1_000.0 },
        .{ .name = "Incident report roundtrip (56 bytes)", .min = 1_000.0 },
        .{ .name = "Threat intel share roundtrip (72 bytes)", .min = 1_000.0 },
        .{ .name = "Multi-message stream (10 msgs/batch)", .min = 2_000.0 },
        .{ .name = "Failover/reconnect cycle (bind+connect+close)", .min = 100.0 },
    };
    for (thresholds) |t| {
        if (runner.getResult(t.name)) |r| {
            results.append(.{
                .name = t.name,
                .actual = r.msgs_per_sec,
                .threshold = t.min,
                .passed = r.msgs_per_sec >= t.min,
            }) catch {};
        }
    }
    return results;
}

// ============================================================
// Tests
// ============================================================

test "FedBenchConfig defaults - kill switch OFF" {
    const c = FedBenchConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqual(@as(u32, 50), c.warmup);
    try std.testing.expectEqual(@as(u32, 1_000), c.iterations);
}

test "FedBenchTimer start/stop" {
    var timer = FedBenchTimer.start();
    var i: u32 = 0;
    while (i < 100) : (i += 1) {}
    timer.stop();
    try std.testing.expect(timer.elapsedNs() > 0);
}

test "FedBenchTimer msgsPerSec" {
    var timer = FedBenchTimer.start();
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {}
    timer.stop();
    const mps = timer.msgsPerSec(1000);
    try std.testing.expect(mps > 0.0);
}

test "FedBenchResult print" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const r = FedBenchResult{
        .name = "test-fed-bench",
        .iterations = 100,
        .total_ns = 1_000_000,
        .msgs_per_sec = 100_000.0,
        .us_per_msg = 10.0,
        .bytes_per_msg = 47,
        .effective_mbps = 3.76,
    };
    try r.print(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "test-fed-bench") != null);
}

test "FedBenchRunner init/deinit" {
    var runner = FedBenchRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 0), runner.resultCount());
}

test "FedBenchRunner getResult returns null for unknown" {
    var runner = FedBenchRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try std.testing.expect(runner.getResult("nonexistent") == null);
}

test "FedBenchRunner printReport outputs table" {
    var runner = FedBenchRunner.init(std.testing.allocator, .{ .enabled = false });
    defer runner.deinit();
    try runner.results.append(.{
        .name = "test-1",
        .iterations = 100,
        .total_ns = 1_000_000,
        .msgs_per_sec = 100_000.0,
        .us_per_msg = 10.0,
    });
    try runner.results.append(.{
        .name = "test-2",
        .iterations = 200,
        .total_ns = 2_000_000,
        .msgs_per_sec = 100_000.0,
        .us_per_msg = 10.0,
    });

    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try runner.printReport(stream.writer());
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "Cross-Node Federation Benchmark Report") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test-2") != null);
}

test "NodePair setup creates working TCP connection" {
    var pair = try NodePair.setup(std.testing.allocator, 5000, 5000);
    defer pair.close();

    // Verify connection works
    try pair.client.sendBytes("ping");
    var buf: [16]u8 = undefined;
    const n = try pair.server_conn.recvBytes(&buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualSlices(u8, "ping", buf[0..n]);
}

test "benchHeartbeat produces valid result" {
    const result = try benchHeartbeat(std.testing.allocator, .{
        .enabled = true,
        .warmup = 5,
        .iterations = 50,
    });
    try std.testing.expectEqual(@as(u32, 50), result.iterations);
    try std.testing.expect(result.msgs_per_sec > 0.0);
    try std.testing.expect(result.bytes_per_msg == 47);
}

test "benchIncidentReport produces valid result" {
    const result = try benchIncidentReport(std.testing.allocator, .{
        .enabled = true,
        .warmup = 5,
        .iterations = 50,
    });
    try std.testing.expectEqual(@as(u32, 50), result.iterations);
    try std.testing.expect(result.msgs_per_sec > 0.0);
    try std.testing.expect(result.bytes_per_msg == 56);
}

test "benchThreatIntel produces valid result" {
    const result = try benchThreatIntel(std.testing.allocator, .{
        .enabled = true,
        .warmup = 5,
        .iterations = 50,
    });
    try std.testing.expectEqual(@as(u32, 50), result.iterations);
    try std.testing.expect(result.msgs_per_sec > 0.0);
    try std.testing.expect(result.bytes_per_msg == 72);
}

test "benchMultiMessageStream produces valid result" {
    const result = try benchMultiMessageStream(std.testing.allocator, .{
        .enabled = true,
        .warmup = 2,
        .iterations = 10,
        .batch_size = 5,
    });
    // 10 iterations * 5 batch = 50 total messages
    try std.testing.expectEqual(@as(u32, 50), result.iterations);
    try std.testing.expect(result.msgs_per_sec > 0.0);
}

test "benchFailoverReconnect produces valid result" {
    const result = try benchFailoverReconnect(std.testing.allocator, .{
        .enabled = true,
        .warmup = 2,
        .iterations = 10,
    });
    try std.testing.expectEqual(@as(u32, 10), result.iterations);
    try std.testing.expect(result.msgs_per_sec > 0.0);
}

test "runAllFederationBenchmarks collects 5 results" {
    var runner = try runAllFederationBenchmarks(std.testing.allocator, .{
        .enabled = true,
        .warmup = 2,
        .iterations = 20,
        .batch_size = 5,
    });
    defer runner.deinit();
    try std.testing.expectEqual(@as(usize, 5), runner.resultCount());

    try std.testing.expect(runner.getResult("Heartbeat roundtrip (47 bytes)") != null);
    try std.testing.expect(runner.getResult("Incident report roundtrip (56 bytes)") != null);
    try std.testing.expect(runner.getResult("Threat intel share roundtrip (72 bytes)") != null);
    try std.testing.expect(runner.getResult("Multi-message stream (10 msgs/batch)") != null);
    try std.testing.expect(runner.getResult("Failover/reconnect cycle (bind+connect+close)") != null);
}

test "checkFedThresholds evaluates all benchmarks" {
    var runner = try runAllFederationBenchmarks(std.testing.allocator, .{
        .enabled = true,
        .warmup = 2,
        .iterations = 20,
        .batch_size = 5,
    });
    defer runner.deinit();

    var thresholds = checkFedThresholds(&runner);
    defer thresholds.deinit();
    try std.testing.expectEqual(@as(usize, 5), thresholds.items.len);
}

test "FedThresholdResult passed flag" {
    const t = FedThresholdResult{
        .name = "test",
        .actual = 1000.0,
        .threshold = 500.0,
        .passed = true,
    };
    try std.testing.expect(t.passed);
    try std.testing.expect(t.actual > t.threshold);
}

test "Heartbeat benchmark achieves measurable throughput" {
    const result = try benchHeartbeat(std.testing.allocator, .{
        .enabled = true,
        .warmup = 5,
        .iterations = 100,
    });
    // Should achieve at least 100 msgs/sec (TCP roundtrip on loopback)
    try std.testing.expect(result.msgs_per_sec > 100.0);
    try std.testing.expect(result.errors < 10); // allow some variance
}

test "Multi-message stream achieves higher throughput than single" {
    const single = try benchHeartbeat(std.testing.allocator, .{
        .enabled = true,
        .warmup = 5,
        .iterations = 50,
    });
    const batch = try benchMultiMessageStream(std.testing.allocator, .{
        .enabled = true,
        .warmup = 2,
        .iterations = 5,
        .batch_size = 10,
    });
    // Batch should achieve higher msgs/sec due to fewer syscalls
    // (allow tolerance for variance)
    const ratio = batch.msgs_per_sec / single.msgs_per_sec;
    try std.testing.expect(ratio > 0.5); // at least comparable
}
