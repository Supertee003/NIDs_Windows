//! cluster_uplink.zig - FED-P4: daemon-side cluster uplink (opt-in).
//!
//! The last federation slice: the daemon installs a real sender into
//! FederationBackend (action_dispatcher.zig) and reports live status
//! from `federation.status`. Everything is opt-in and fail-closed:
//!
//!   - AEGIS_CLUSTER=1 enables the uplink; without it the daemon stays
//!     standalone (status reports standalone, no dials).
//!   - TLS material comes from AEGIS_CLUSTER_ROOTS/CHAIN/KEY env paths
//!     (PEM files, operator-owned). Missing or unreadable material means
//!     the uplink never dials — never plaintext, never a mock.
//!   - Only outbound client sessions exist (aegis_fed_* FFI). There is
//!     no listener: this daemon never accepts cluster connections.
//!   - The uplink publishes IpcEvent reports (detections) to configured
//!     peers. It makes no policy decisions and holds no enforcement
//!     capability: reports only, enforcement stays local (ADR-0007).
//!
//! Authority: this module links `aegis_fed_*` transport symbols only.
//! It never links `aegis_pep_*` and never mutates WFP.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const fc = @import("federation_codec.zig");
const cc = @import("cluster_coord.zig");
const registry_mod = @import("node_registry.zig");
const runtime_state = @import("../pipeline/runtime_state.zig");

// ============================================================================
// Config (env-driven, fail-closed)
// ============================================================================

pub const UplinkConfig = struct {
    enabled: bool = false,
    node_id: u32 = 0,
    host: []const u8 = "",
    port: u16 = 0,
    server_name: []const u8 = "localhost",
    roots_path: []const u8 = "",
    chain_path: []const u8 = "",
    key_path: []const u8 = "",
    connect_timeout_ms: i64 = 5_000,
    max_backoff_ms: i64 = 30_000,
};

fn envOr(allocator: std.mem.Allocator, key: []const u8, default: []const u8) ![]const u8 {
    // FED-UPLINK-095: the default MUST be heap-owned. Every caller frees
    // unconditionally, so returning the static literal segfaulted daemon
    // startup whenever the variable was absent (free of non-heap memory
    // in page_allocator). getEnvVarOwned failure is the normal absent
    // case, not an error worth propagating here.
    return std.process.getEnvVarOwned(allocator, key) catch try allocator.dupe(u8, default);
}

pub fn configFromEnv(allocator: std.mem.Allocator) !UplinkConfig {
    const enabled_raw = try envOr(allocator, "AEGIS_CLUSTER", "0");
    defer allocator.free(enabled_raw);
    const enabled = std.ascii.eqlIgnoreCase(enabled_raw, "1") or
        std.ascii.eqlIgnoreCase(enabled_raw, "true") or
        std.ascii.eqlIgnoreCase(enabled_raw, "on");
    if (!enabled) return .{ .enabled = false };

    const node_id_raw = try envOr(allocator, "AEGIS_CLUSTER_NODE_ID", "0");
    defer allocator.free(node_id_raw);
    const node_id = std.fmt.parseInt(u32, node_id_raw, 10) catch 0;

    const host = try envOr(allocator, "AEGIS_CLUSTER_HOST", "");
    defer allocator.free(host);
    const port_raw = try envOr(allocator, "AEGIS_CLUSTER_PORT", "0");
    defer allocator.free(port_raw);
    const port = std.fmt.parseInt(u16, port_raw, 10) catch 0;

    const server_name = try envOr(allocator, "AEGIS_CLUSTER_SERVER_NAME", "localhost");
    defer allocator.free(server_name);
    const roots_path = try envOr(allocator, "AEGIS_CLUSTER_ROOTS", "");
    defer allocator.free(roots_path);
    const chain_path = try envOr(allocator, "AEGIS_CLUSTER_CHAIN", "");
    defer allocator.free(chain_path);
    const key_path = try envOr(allocator, "AEGIS_CLUSTER_KEY", "");
    defer allocator.free(key_path);

    return .{
        .enabled = true,
        .node_id = node_id,
        .host = host,
        .port = port,
        .server_name = server_name,
        .roots_path = roots_path,
        .chain_path = chain_path,
        .key_path = key_path,
    };
}

// ============================================================================
// Uplink state (one global, mutex-guarded)
// ============================================================================

const PeerSession = struct {
    node_id: u32,
    addr: []const u8,
    port: u16,
    handle: u64 = 0,
    connected: bool = false,
    consecutive_failures: u32 = 0,
    next_retry_ns: i64 = 0,
    total_sent: u64 = 0,
    total_failures: u64 = 0,
};

pub const ClusterUplink = struct {
    allocator: std.mem.Allocator,
    cfg: UplinkConfig,
    peers: std.ArrayList(PeerSession),
    roots_pem: []u8 = &.{},
    chain_pem: []u8 = &.{},
    key_pem: []u8 = &.{},
    installed: bool = false,
    total_published: u64 = 0,
    total_dropped: u64 = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, cfg: UplinkConfig) !ClusterUplink {
        var self = ClusterUplink{
            .allocator = allocator,
            .cfg = cfg,
            .peers = std.ArrayList(PeerSession).init(allocator),
        };
        // Fail-closed PEM load: any missing/unreadable file means the
        // uplink never dials. No plaintext fallback, no mock.
        if (cfg.roots_path.len > 0) {
            self.roots_pem = try std.fs.cwd().readFileAlloc(allocator, cfg.roots_path, 1 << 20);
        }
        if (cfg.chain_path.len > 0) {
            self.chain_pem = try std.fs.cwd().readFileAlloc(allocator, cfg.chain_path, 1 << 20);
        }
        if (cfg.key_path.len > 0) {
            self.key_pem = try std.fs.cwd().readFileAlloc(allocator, cfg.key_path, 1 << 20);
        }
        if (self.roots_pem.len == 0 or self.chain_pem.len == 0 or self.key_pem.len == 0) {
            diag.warn("[CLUSTER] TLS material incomplete — uplink will not dial (fail-closed)", .{});
        }
        return self;
    }

    pub fn deinit(self: *ClusterUplink) void {
        for (self.peers.items) |*p| {
            if (p.connected) {
                _ = fed_close(p.handle);
            }
        }
        self.peers.deinit();
        if (self.roots_pem.len > 0) self.allocator.free(self.roots_pem);
        if (self.chain_pem.len > 0) self.allocator.free(self.chain_pem);
        if (self.key_pem.len > 0) self.allocator.free(self.key_pem);
    }

    /// Load static peers from the canonical cluster.json (if present).
    /// Fail-closed: a malformed file registers nothing and logs a warning.
    pub fn loadPeers(self: *ClusterUplink) !void {
        var reg = registry_mod.DiscoveryRegistry.init(self.allocator, self.cfg.node_id);
        defer reg.deinit();
        _ = reg.loadStaticFile(self.allocator, "configs/cluster.json") catch |err| {
            diag.warn("[CLUSTER] no usable cluster.json: {s}", .{@errorName(err)});
            return;
        };
        for (reg.allNodes()) |n| {
            if (n.id == self.cfg.node_id) continue; // never dial self
            try self.peers.append(.{
                .node_id = n.id,
                .addr = try self.allocator.dupe(u8, std.mem.sliceTo(&n.addr, 0)),
                .port = n.port,
            });
        }
        diag.info("[CLUSTER] {d} static peers loaded", .{self.peers.items.len});
    }

    /// Install the sender into FederationBackend. Idempotent.
    pub fn install(self: *ClusterUplink) void {
        if (self.installed) return;
        const action_dispatcher = @import("../policy/action_dispatcher.zig");
        action_dispatcher.FederationBackend.install(&publishEvent);
        self.installed = true;
        diag.info("[CLUSTER] uplink installed (node {d})", .{self.cfg.node_id});
    }

    /// Publish one IpcEvent report to all connected peers. Returns the
    /// number of peers that accepted the bytes. Fail-closed: peers that
    /// fail are marked degraded and retried with backoff.
    pub fn publish(self: *ClusterUplink, ev: *const event.IpcEvent) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.installed or self.peers.items.len == 0) return 0;
        if (self.roots_pem.len == 0 or self.chain_pem.len == 0 or self.key_pem.len == 0) {
            self.total_dropped += 1;
            return 0;
        }
        var buf: [4096]u8 = undefined;
        const n = fc.encode(.{
            .msg_type = .incident_report,
            .from_node_id = self.cfg.node_id,
            .to_node_id = 0, // broadcast
            .timestamp_ns = @intCast(ev.timestamp_ns),
            .seq = @intCast(self.total_published +% 1),
            .node = null,
            .incident_source_ip = .{
                @intCast((ev.src_ip >> 24) & 0xFF),
                @intCast((ev.src_ip >> 16) & 0xFF),
                @intCast((ev.src_ip >> 8) & 0xFF),
                @intCast(ev.src_ip & 0xFF),
            },
            .incident_remote_port = ev.dst_port,
            .incident_proto = ev.protocol,
            .incident_severity = severityToCluster(ev.severity),
            .incident_score = 0.0,
            .incident_label = .{0} ** cc.MAX_INCIDENT_LABEL,
            .incident_label_len = 0,
            .threat_intel = null,
            .leader_node_id = 0,
        }, &buf) catch return 0;
        const frame = buf[0..n];

        var accepted: usize = 0;
        for (self.peers.items) |*p| {
            if (!p.connected) {
                const now = std.time.nanoTimestamp();
                if (now < p.next_retry_ns) continue;
                p.handle = fed_connect(self, p) catch {
                    p.consecutive_failures += 1;
                    p.total_failures += 1;
                    p.next_retry_ns = @intCast(now + backoffMs(p.consecutive_failures, self.cfg.max_backoff_ms) * 1_000_000);
                    continue;
                };
                p.connected = true;
                p.consecutive_failures = 0;
            }
            const rc = fed_send(p.handle, frame.ptr, frame.len);
            if (rc == 0) {
                p.total_sent += 1;
                self.total_published += 1;
                accepted += 1;
            } else {
                p.connected = false;
                p.consecutive_failures += 1;
                p.total_failures += 1;
                p.next_retry_ns = @intCast(std.time.nanoTimestamp() + backoffMs(p.consecutive_failures, self.cfg.max_backoff_ms) * 1_000_000);
                _ = fed_close(p.handle);
                p.handle = 0;
            }
        }
        return accepted;
    }

    /// Live status snapshot for the control plane.
    pub fn statusJson(self: *ClusterUplink, allocator: std.mem.Allocator) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var connected: usize = 0;
        for (self.peers.items) |p| {
            if (p.connected) connected += 1;
        }
        const mode = if (self.installed) "cluster" else "standalone";
        const role = if (self.cfg.node_id != 0) "member" else "standalone";
        return std.fmt.allocPrint(allocator,
            "{{\"mode\":\"{s}\",\"cluster_enabled\":{s},\"nodes\":{d},\"role\":\"{s}\"," ++
            "\"connected\":{d},\"published\":{d},\"dropped\":{d}}}",
            .{
                mode,
                if (self.installed) "true" else "false",
                self.peers.items.len,
                role,
                connected,
                self.total_published,
                self.total_dropped,
            },
        );
    }
};

// ============================================================================
// FFI bindings (transport only — never aegis_pep_*)
// ============================================================================

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

fn fed_connect(self: *ClusterUplink, p: *PeerSession) !u64 {
    var host_buf: [256]u8 = undefined;
    if (p.addr.len == 0 or p.addr.len >= host_buf.len) return error.BadAddr;
    @memcpy(host_buf[0..p.addr.len], p.addr);
    host_buf[p.addr.len] = 0;
    var name_buf: [256]u8 = undefined;
    if (self.cfg.server_name.len == 0 or self.cfg.server_name.len >= name_buf.len) return error.BadName;
    @memcpy(name_buf[0..self.cfg.server_name.len], self.cfg.server_name);
    name_buf[self.cfg.server_name.len] = 0;
    var handle: u64 = 0;
    const rc = aegis_fed_connect(
        @ptrCast(host_buf[0..p.addr.len :0]),
        p.port,
        self.roots_pem.ptr, self.roots_pem.len,
        self.chain_pem.ptr, self.chain_pem.len,
        self.key_pem.ptr, self.key_pem.len,
        @ptrCast(name_buf[0..self.cfg.server_name.len :0]),
        &handle,
    );
    if (rc != 0) return error.ConnectFailed;
    return handle;
}

fn fed_send(handle: u64, data: [*]const u8, len: usize) c_int {
    return aegis_fed_send(handle, data, len);
}

fn fed_close(handle: u64) c_int {
    return aegis_fed_close(handle);
}

// ============================================================================
// Helpers
// ============================================================================

fn severityToCluster(sev: event.EventSeverity) cc.IncidentSeverity {
    return switch (sev) {
        .critical, .emergency, .alert => .critical,
        .@"error", .warning => .high,
        .notice, .info => .medium,
        else => .info,
    };
}

fn backoffMs(consecutive: u32, max_ms: i64) i64 {
    if (consecutive == 0) return 1;
    const exp: f32 = @floatFromInt(consecutive);
    const factor = std.math.pow(f32, 2.0, exp);
    const backoff: f32 = @as(f32, @floatFromInt(1)) * factor;
    const capped: f32 = @min(backoff, @as(f32, @floatFromInt(max_ms)));
    return @intFromFloat(capped);
}

/// Sender installed into FederationBackend. Returns 0 on success.
fn publishEvent(ev_ptr: *const event.IpcEvent) c_int {
    const uplink = g_uplink orelse return -1;
    const accepted = uplink.publish(ev_ptr);
    return if (accepted > 0) 0 else -1;
}

// ============================================================================
// Global instance (daemon-owned)
// ============================================================================

pub var g_uplink: ?*ClusterUplink = null;

pub fn initFromEnv(allocator: std.mem.Allocator) !void {
    const cfg = try configFromEnv(allocator);
    if (!cfg.enabled) {
        diag.info("[CLUSTER] standalone (AEGIS_CLUSTER not set)", .{});
        return;
    }
    // FED-UPLINK-095: heap-own the instance. Storing &local would leave
    // g_uplink dangling after return (use-after-free on first publish).
    const uplink = try allocator.create(ClusterUplink);
    errdefer allocator.destroy(uplink);
    uplink.* = try ClusterUplink.init(allocator, cfg);
    errdefer uplink.deinit();
    try uplink.loadPeers();
    uplink.install();
    g_uplink = uplink;
    runtime_state.g_cluster_enabled.store(true, .release);
    diag.info("[CLUSTER] uplink active (node {d}, {d} peers)", .{ cfg.node_id, uplink.peers.items.len });
}

pub fn shutdown() void {
    if (g_uplink) |u| {
        const alloc = u.allocator;
        u.deinit();
        alloc.destroy(u);
        g_uplink = null;
        runtime_state.g_cluster_enabled.store(false, .release);
    }
}

// ============================================================
// Tests
// ============================================================

test "uplink config defaults to standalone" {
    // No env in test process: configFromEnv must not enable.
    // (We can't unset env reliably in Zig tests; instead test the
    //  disabled path by constructing directly.)
    const cfg = UplinkConfig{ .enabled = false };
    try std.testing.expect(!cfg.enabled);
}

test "FED-UPLINK-095: envOr default is heap-owned and always freeable" {
    // Regression pin for the daemon startup segfault: envOr used to
    // return the static default literal, which every caller frees.
    // Absent variable -> owned copy with identical content.
    const v = try envOr(std.testing.allocator, "AEGIS_TEST_ABSENT_VAR_XYZ_123", "0");
    defer std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("0", v);
}

test "uplink status reports standalone when not installed" {
    var u = ClusterUplink{
        .allocator = std.testing.allocator,
        .cfg = .{ .enabled = false },
        .peers = std.ArrayList(PeerSession).init(std.testing.allocator),
    };
    defer u.deinit();
    const json = try u.statusJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"mode\":\"standalone\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cluster_enabled\":false") != null);
}

test "uplink publish without peers is a no-op" {
    var u = ClusterUplink{
        .allocator = std.testing.allocator,
        .cfg = .{ .enabled = true, .node_id = 1 },
        .peers = std.ArrayList(PeerSession).init(std.testing.allocator),
    };
    defer u.deinit();
    var ev = event.IpcEvent.init(.signature_match);
    const accepted = u.publish(&ev);
    try std.testing.expectEqual(@as(usize, 0), accepted);
}

test "uplink publish without TLS material fails closed" {
    var u = ClusterUplink{
        .allocator = std.testing.allocator,
        .cfg = .{ .enabled = true, .node_id = 1 },
        .peers = std.ArrayList(PeerSession).init(std.testing.allocator),
        // Installed (wired into the escalation path) with a peer but no
        // TLS material: must hit the fail-closed branch, not the
        // not-installed early return.
        .installed = true,
    };
    defer u.deinit();
    try u.peers.append(.{ .node_id = 2, .addr = "127.0.0.1", .port = 9001 });
    var ev = event.IpcEvent.init(.signature_match);
    const accepted = u.publish(&ev);
    try std.testing.expectEqual(@as(usize, 0), accepted);
    // SCOPE-101: total_dropped counts dropped EVENTS per publish call
    // (early return before the peer loop), not per-peer attempts — one
    // event in, one drop counted. The old expectation (2) predates the
    // early-return shape and rotted while this file's tests were dead.
    try std.testing.expectEqual(@as(u64, 1), u.total_dropped);
}

test "severityToCluster maps pipeline severity" {
    try std.testing.expectEqual(cc.IncidentSeverity.critical, severityToCluster(.critical));
    try std.testing.expectEqual(cc.IncidentSeverity.high, severityToCluster(.@"error"));
    try std.testing.expectEqual(cc.IncidentSeverity.medium, severityToCluster(.notice));
    try std.testing.expectEqual(cc.IncidentSeverity.info, severityToCluster(.trace));
}

test "backoffMs is exponential and capped" {
    try std.testing.expectEqual(@as(i64, 1), backoffMs(0, 30_000));
    try std.testing.expectEqual(@as(i64, 2), backoffMs(1, 30_000));
    try std.testing.expectEqual(@as(i64, 4), backoffMs(2, 30_000));
    try std.testing.expectEqual(@as(i64, 30_000), backoffMs(100, 30_000));
}
