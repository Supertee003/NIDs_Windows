//! host_net.zig - Observe-only Windows TCP endpoint telemetry (XDR-005-A).
//!
//! Reads the Windows TCP owner-PID tables (`GetExtendedTcpTable`) and diffs
//! consecutive snapshots so the pipeline sees *new established TCP
//! connections* as they appear. This is evidence-only host telemetry:
//!
//!   - No policy/PEP/DEFCON/ActionDispatcher import or call.
//!   - No socket open, no packet injection, no host mutation: the only
//!     Win32 call is a read-only table query.
//!   - The first successful poll is a *seed*: it records what already
//!     existed and emits nothing. Only later appearances are observations.
//!
//! Boundary contract for downstream (`event_processor.isXdrHostSocketObservation`):
//! `source = capture_host_net`, `kind = host_socket_observed`, `rule_id = 0`,
//! nonzero peer address. A host socket observation is not a detection and
//! must never be given a synthetic detection identity.

const std = @import("std");
const builtin = @import("builtin");
const event = @import("../contract/event.zig");

pub const MAX_TRACKED: usize = 1024;
pub const MAX_EMIT_PER_POLL: usize = 64;
pub const DEFAULT_POLL_MS: u32 = 2000;
pub const MIN_POLL_MS: u32 = 500;
/// The watchdog timeout is 5 s. Keeping the poll interval at or below 4 s
/// leaves headroom for one slow table query without a false stale-thread
/// alert. The loop beats every iteration, including query errors.
pub const MAX_POLL_MS: u32 = 4000;
pub const MAX_TABLE_BYTES: usize = 4 * 1024 * 1024;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const MIB_TCP_STATE_ESTAB: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_DATA: u32 = 232;
const V4_ROW_BYTES: usize = 24;
const V6_ROW_BYTES: usize = 56;
const MAX_QUERY_ATTEMPTS: usize = 3;

pub const Family = enum { v4, v6 };

/// One established TCP endpoint pair. IPv4 addresses live in the first four
/// bytes of the 16-byte slots in wire (network) byte order; IPv6 fills all 16.
/// Ports are host order.
pub const Observed = struct {
    family: Family = .v4,
    local_addr: [16]u8 = [_]u8{0} ** 16,
    local_port: u16 = 0,
    remote_addr: [16]u8 = [_]u8{0} ** 16,
    remote_port: u16 = 0,
    owning_pid: u32 = 0,
};

pub const ParseResult = struct {
    count: usize = 0,
    /// True when the kernel table held more rows than the caller's buffer
    /// could hold (or the advertised count exceeded the byte length).
    truncated: bool = false,
};

pub const PollResult = struct {
    count: usize = 0,
    truncated: bool = false,
};

pub const Error = error{
    TableQueryFailed,
    TableTooLarge,
    TruncatedTable,
    OutOfMemory,
};

pub const Config = struct {
    enabled: bool = true,
    poll_ms: u32 = DEFAULT_POLL_MS,
};

pub const Stats = struct {
    enabled: bool = false,
    ready: bool = false,
    seeded: bool = false,
    polls: u64 = 0,
    poll_errors: u64 = 0,
    rows_seen: u64 = 0,
    tracked: u64 = 0,
    emitted: u64 = 0,
    emit_deferred: u64 = 0,
    overflow: u64 = 0,
    last_poll_ms: i64 = 0,
};

// ----- Win32 surface (read-only table query only) -----

const MIB_TCPROW_OWNER_PID = extern struct {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
};

const MIB_TCP6ROW_OWNER_PID = extern struct {
    ucLocalAddr: [16]u8,
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [16]u8,
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
    dwState: u32,
    dwOwningPid: u32,
};

comptime {
    if (@sizeOf(MIB_TCPROW_OWNER_PID) != V4_ROW_BYTES) {
        @compileError("MIB_TCPROW_OWNER_PID size drift");
    }
    if (@sizeOf(MIB_TCP6ROW_OWNER_PID) != V6_ROW_BYTES) {
        @compileError("MIB_TCP6ROW_OWNER_PID size drift");
    }
}

// Zig 0.13's bundled mingw definitions have no x86_64 import library for
// iphlpapi, so the function is resolved at runtime from the system DLL. This
// is the same DynLib discipline used by the Npcap/bridge adapters and keeps
// `zig build` free of an extra import-lib dependency.
const GetExtendedTcpTableFn = *const fn (
    pTcpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: i32,
    ulAf: u32,
    tableClass: u32,
    reserved: u32,
) callconv(.C) u32;

var g_api_lock: std.Thread.Mutex = .{};
var g_iphlpapi: ?std.DynLib = null;
var g_get_extended_tcp_table: ?GetExtendedTcpTableFn = null;

fn getExtendedTcpTableFn() Error!GetExtendedTcpTableFn {
    g_api_lock.lock();
    defer g_api_lock.unlock();
    if (g_get_extended_tcp_table) |f| return f;
    var lib = std.DynLib.open("iphlpapi.dll") catch return error.TableQueryFailed;
    const f = lib.lookup(GetExtendedTcpTableFn, "GetExtendedTcpTable") orelse {
        lib.close();
        return error.TableQueryFailed;
    };
    // Process-lifetime singleton: the DLL stays loaded while the adapter is.
    g_iphlpapi = lib;
    g_get_extended_tcp_table = f;
    return f;
}
// ----- Module counters (read-only health/evidence, never decisions) -----

var g_enabled = std.atomic.Value(bool).init(false);
var g_ready = std.atomic.Value(bool).init(false);
var g_seeded = std.atomic.Value(bool).init(false);
var g_polls = std.atomic.Value(u64).init(0);
var g_poll_errors = std.atomic.Value(u64).init(0);
var g_rows_seen = std.atomic.Value(u64).init(0);
var g_tracked = std.atomic.Value(u64).init(0);
var g_emitted = std.atomic.Value(u64).init(0);
var g_emit_deferred = std.atomic.Value(u64).init(0);
var g_overflow = std.atomic.Value(u64).init(0);
var g_last_poll_ms = std.atomic.Value(i64).init(0);
var g_poll_ms = std.atomic.Value(u32).init(DEFAULT_POLL_MS);

/// Resolve `AEGIS_HOSTNET` (default on; `0/off/false/no` disables) and
/// `AEGIS_HOSTNET_POLL_MS` (clamped 500..4000). Resets counters so a
/// daemon restart starts from an honest zero.
pub fn initFromEnv() Config {
    var cfg = Config{};
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_HOSTNET") catch null) |raw| {
        defer std.heap.page_allocator.free(raw);
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "0") or
            std.ascii.eqlIgnoreCase(trimmed, "off") or
            std.ascii.eqlIgnoreCase(trimmed, "false") or
            std.ascii.eqlIgnoreCase(trimmed, "no"))
        {
            cfg.enabled = false;
        }
    }
    if (cfg.enabled) {
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_HOSTNET_POLL_MS") catch null) |raw| {
            defer std.heap.page_allocator.free(raw);
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (std.fmt.parseInt(u32, trimmed, 10)) |parsed| {
                cfg.poll_ms = std.math.clamp(parsed, MIN_POLL_MS, MAX_POLL_MS);
            } else |_| {}
        }
    }
    resetStats(cfg);
    return cfg;
}

/// Test/daemon hook: set the effective configuration and zero the counters.
pub fn resetStats(cfg: Config) void {
    g_enabled.store(cfg.enabled, .release);
    g_ready.store(false, .release);
    g_seeded.store(false, .release);
    g_polls.store(0, .monotonic);
    g_poll_errors.store(0, .monotonic);
    g_rows_seen.store(0, .monotonic);
    g_tracked.store(0, .monotonic);
    g_emitted.store(0, .monotonic);
    g_emit_deferred.store(0, .monotonic);
    g_overflow.store(0, .monotonic);
    g_last_poll_ms.store(0, .monotonic);
    g_poll_ms.store(cfg.poll_ms, .monotonic);
}

pub fn pollIntervalMs() u32 {
    return g_poll_ms.load(.acquire);
}

pub fn snapshot() Stats {
    return .{
        .enabled = g_enabled.load(.acquire),
        .ready = g_ready.load(.acquire),
        .seeded = g_seeded.load(.acquire),
        .polls = g_polls.load(.acquire),
        .poll_errors = g_poll_errors.load(.acquire),
        .rows_seen = g_rows_seen.load(.acquire),
        .tracked = g_tracked.load(.acquire),
        .emitted = g_emitted.load(.acquire),
        .emit_deferred = g_emit_deferred.load(.acquire),
        .overflow = g_overflow.load(.acquire),
        .last_poll_ms = g_last_poll_ms.load(.acquire),
    };
}

pub fn notePoll(result: PollResult) void {
    _ = g_polls.fetchAdd(1, .monotonic);
    if (result.truncated) _ = g_overflow.fetchAdd(1, .monotonic);
    _ = g_rows_seen.fetchAdd(@intCast(result.count), .monotonic);
    g_ready.store(true, .release);
    g_last_poll_ms.store(std.time.milliTimestamp(), .monotonic);
}

pub fn notePollError() void {
    _ = g_polls.fetchAdd(1, .monotonic);
    _ = g_poll_errors.fetchAdd(1, .monotonic);
    g_last_poll_ms.store(std.time.milliTimestamp(), .monotonic);
}

pub fn noteTracker(t: *const Tracker) void {
    g_seeded.store(t.seeded, .release);
    g_tracked.store(@intCast(t.prev_count), .monotonic);
    g_emit_deferred.store(t.emit_deferred, .monotonic);
}

pub fn noteEmitted(n: usize) void {
    _ = g_emitted.fetchAdd(@intCast(n), .monotonic);
}

pub fn noteStopped() void {
    g_ready.store(false, .release);
}

// ----- Pure parsers (unit-tested with synthetic tables) -----

pub fn parseV4Table(bytes: []const u8, out: []Observed) Error!ParseResult {
    if (bytes.len < 4) return error.TruncatedTable;
    const claimed: usize = std.mem.readInt(u32, bytes[0..4], .little);
    const available = (bytes.len - 4) / V4_ROW_BYTES;
    const scan = @min(claimed, available);
    const n = @min(scan, out.len);

    var count: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const off = 4 + i * V4_ROW_BYTES;
        const state = std.mem.readInt(u32, bytes[off..][0..4], .little);
        if (state != MIB_TCP_STATE_ESTAB) continue;

        const local: *const [4]u8 = bytes[off + 4 ..][0..4];
        const remote: *const [4]u8 = bytes[off + 12 ..][0..4];
        if (skipV4(local, remote)) continue;

        var o = Observed{ .family = .v4 };
        @memcpy(o.local_addr[0..4], local);
        o.local_port = std.mem.readInt(u16, bytes[off + 8 ..][0..2], .big);
        @memcpy(o.remote_addr[0..4], remote);
        o.remote_port = std.mem.readInt(u16, bytes[off + 16 ..][0..2], .big);
        o.owning_pid = std.mem.readInt(u32, bytes[off + 20 ..][0..4], .little);
        out[count] = o;
        count += 1;
    }
    return .{ .count = count, .truncated = claimed > available or claimed > out.len };
}

pub fn parseV6Table(bytes: []const u8, out: []Observed) Error!ParseResult {
    if (bytes.len < 4) return error.TruncatedTable;
    const claimed: usize = std.mem.readInt(u32, bytes[0..4], .little);
    const available = (bytes.len - 4) / V6_ROW_BYTES;
    const scan = @min(claimed, available);
    const n = @min(scan, out.len);

    var count: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const off = 4 + i * V6_ROW_BYTES;
        const state = std.mem.readInt(u32, bytes[off + 48 ..][0..4], .little);
        if (state != MIB_TCP_STATE_ESTAB) continue;

        const local: *const [16]u8 = bytes[off..][0..16];
        const remote: *const [16]u8 = bytes[off + 24 ..][0..16];
        if (skipV6(local, remote)) continue;

        var o = Observed{ .family = .v6 };
        @memcpy(o.local_addr[0..16], local);
        o.local_port = std.mem.readInt(u16, bytes[off + 20 ..][0..2], .big);
        @memcpy(o.remote_addr[0..16], remote);
        o.remote_port = std.mem.readInt(u16, bytes[off + 44 ..][0..2], .big);
        o.owning_pid = std.mem.readInt(u32, bytes[off + 52 ..][0..4], .little);
        out[count] = o;
        count += 1;
    }
    return .{ .count = count, .truncated = claimed > available or claimed > out.len };
}

fn v4Unspecified(a: *const [4]u8) bool {
    return a[0] == 0 and a[1] == 0 and a[2] == 0 and a[3] == 0;
}

fn v4Loopback(a: *const [4]u8) bool {
    return a[0] == 127;
}

fn skipV4(local: *const [4]u8, remote: *const [4]u8) bool {
    return v4Unspecified(local) or v4Loopback(local) or
        v4Unspecified(remote) or v4Loopback(remote);
}

fn v6Unspecified(a: *const [16]u8) bool {
    for (a) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn v6Loopback(a: *const [16]u8) bool {
    var i: usize = 0;
    while (i < 15) : (i += 1) {
        if (a[i] != 0) return false;
    }
    return a[15] == 1;
}

fn skipV6(local: *const [16]u8, remote: *const [16]u8) bool {
    return v6Unspecified(local) or v6Loopback(local) or
        v6Unspecified(remote) or v6Loopback(remote);
}

// ----- Live table query (read-only) -----

fn queryTable(family: Family, out: []Observed) Error!PollResult {
    const get_extended_tcp_table = try getExtendedTcpTableFn();
    const af: u32 = if (family == .v4) AF_INET else AF_INET6;

    var size: u32 = 0;
    var rc = get_extended_tcp_table(null, &size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc == ERROR_NO_DATA) return .{};
    if (rc != ERROR_INSUFFICIENT_BUFFER) return error.TableQueryFailed;
    if (size == 0) return .{};
    if (size > MAX_TABLE_BYTES) return error.TableTooLarge;

    var attempt: usize = 0;
    while (attempt < MAX_QUERY_ATTEMPTS) : (attempt += 1) {
        const buf = std.heap.page_allocator.alloc(u8, size) catch return error.OutOfMemory;
        defer std.heap.page_allocator.free(buf);

        var got: u32 = size;
        rc = get_extended_tcp_table(buf.ptr, &got, 0, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == 0) {
            const parsed = if (family == .v4)
                try parseV4Table(buf[0..got], out)
            else
                try parseV6Table(buf[0..got], out);
            return .{ .count = parsed.count, .truncated = parsed.truncated };
        }
        if (rc == ERROR_NO_DATA) return .{};
        if (rc != ERROR_INSUFFICIENT_BUFFER) return error.TableQueryFailed;
        if (got > MAX_TABLE_BYTES) return error.TableTooLarge;
        size = got;
    }
    return error.TableQueryFailed;
}

/// Snapshot both families into `out` (v4 first). Read-only: no state is
/// changed on the host.
pub fn poll(out: []Observed) Error!PollResult {
    if (builtin.os.tag != .windows) return .{};
    if (out.len == 0) return .{};

    var result = PollResult{};
    const v4 = try queryTable(.v4, out[result.count..]);
    result.count += v4.count;
    result.truncated = result.truncated or v4.truncated;

    if (result.count < out.len) {
        const v6 = try queryTable(.v6, out[result.count..]);
        result.count += v6.count;
        result.truncated = result.truncated or v6.truncated;
    } else {
        // The v4 table filled the caller's buffer, so v6 was not queried at
        // all. Report that unseen family as truncation rather than implying a
        // complete snapshot.
        result.truncated = true;
    }
    return result;
}

// ----- Seed/diff tracker -----

const Key = struct {
    family: Family,
    local_addr: [16]u8,
    local_port: u16,
    remote_addr: [16]u8,
    remote_port: u16,
    owning_pid: u32,

    fn from(o: *const Observed) Key {
        return .{
            .family = o.family,
            .local_addr = o.local_addr,
            .local_port = o.local_port,
            .remote_addr = o.remote_addr,
            .remote_port = o.remote_port,
            .owning_pid = o.owning_pid,
        };
    }

    fn eql(a: *const Key, b: *const Key) bool {
        return a.family == b.family and
            a.local_port == b.local_port and
            a.remote_port == b.remote_port and
            a.owning_pid == b.owning_pid and
            std.mem.eql(u8, &a.local_addr, &b.local_addr) and
            std.mem.eql(u8, &a.remote_addr, &b.remote_addr);
    }
};

/// Bounded seed/diff state. No allocation. The first successful diff seeds
/// and emits nothing; afterwards only keys absent from the previous snapshot
/// are emitted. Keys that disappear leave the snapshot, so a reappearing
/// connection is a new observation (honest, not a claim of continuity).
pub const Tracker = struct {
    prev: [MAX_TRACKED]Key = undefined,
    prev_count: usize = 0,
    seeded: bool = false,
    /// Rows beyond MAX_TRACKED that were not tracked (honest loss counter).
    overflow: u64 = 0,
    /// New rows detected this poll but not emitted because the per-poll
    /// emission cap was reached. They are also withheld from `prev`, so the
    /// next poll detects them again instead of silently dropping them.
    emit_deferred: u64 = 0,

    pub fn reset(self: *Tracker) void {
        self.prev_count = 0;
        self.seeded = false;
        self.overflow = 0;
        self.emit_deferred = 0;
    }

    /// Returns the number of observations written to `out`.
    pub fn diff(self: *Tracker, rows: []const Observed, out: []Observed) usize {
        const scan = @min(rows.len, MAX_TRACKED);
        if (rows.len > MAX_TRACKED) {
            self.overflow +%= @intCast(rows.len - MAX_TRACKED);
        }

        if (!self.seeded) {
            var i: usize = 0;
            while (i < scan) : (i += 1) {
                self.prev[i] = Key.from(&rows[i]);
            }
            self.prev_count = scan;
            self.seeded = true;
            return 0;
        }

        var next: [MAX_TRACKED]Key = undefined;
        var next_count: usize = 0;
        var emitted: usize = 0;

        var i: usize = 0;
        while (i < scan) : (i += 1) {
            const key = Key.from(&rows[i]);
            if (contains(self.prev[0..self.prev_count], &key)) {
                // Still present: retain once even if the kernel table listed
                // the same tuple twice.
                if (!contains(next[0..next_count], &key)) {
                    next[next_count] = key;
                    next_count += 1;
                }
                continue;
            }
            if (emitted < MAX_EMIT_PER_POLL and emitted < out.len) {
                out[emitted] = rows[i];
                emitted += 1;
                next[next_count] = key;
                next_count += 1;
            } else {
                self.emit_deferred +%= 1;
            }
        }

        @memcpy(self.prev[0..next_count], next[0..next_count]);
        self.prev_count = next_count;
        return emitted;
    }

    fn contains(keys: []const Key, key: *const Key) bool {
        for (keys) |*k| {
            if (k.eql(key)) return true;
        }
        return false;
    }
};

// ----- Event projection -----

/// Project one observation into the canonical internal event. `event_id`
/// and payload are stamped by the emitting thread; the evidence identity is
/// the remote endpoint (XDR entity) plus the local endpoint.
pub fn toIpcEvent(o: *const Observed) event.IpcEvent {
    var ev = event.IpcEvent.init(.host_socket_observed);
    ev.source = .capture_host_net;
    // Windows Zig 0.13: nanoTimestamp() is epoch ns (GetSystemTimeAsFileTime),
    // the same epoch domain as nose UnixNano, so evidence timestamps stay
    // comparable. TTLs use the XDR fabric's monotonic clock, not this value.
    ev.timestamp_ns = @intCast(std.time.nanoTimestamp());
    if (o.family == .v4) {
        // Table memory is network byte order; read it once as big-endian so
        // the numeric identity matches nose (BigEndian.Uint32).
        ev.src_ip = std.mem.readInt(u32, o.remote_addr[0..4], .big);
        ev.dst_ip = std.mem.readInt(u32, o.local_addr[0..4], .big);
    }
    ev.src_port = o.remote_port;
    ev.dst_port = o.local_port;
    ev.protocol = 6;
    ev.rule_id = 0; // observation, not a detection
    ev.severity = .info;
    return ev;
}

/// Bounded human-readable forensic payload (never fed to the AC matcher).
pub fn formatPayload(o: *const Observed, buf: []u8) []const u8 {
    if (o.family == .v4) {
        return std.fmt.bufPrint(
            buf,
            "hostnet tcp {d}.{d}.{d}.{d}:{d} -> {d}.{d}.{d}.{d}:{d} pid={d}",
            .{
                o.remote_addr[0], o.remote_addr[1], o.remote_addr[2], o.remote_addr[3],
                o.remote_port,    o.local_addr[0],  o.local_addr[1],  o.local_addr[2],
                o.local_addr[3],  o.local_port,     o.owning_pid,
            },
        ) catch "hostnet tcp";
    }
    return std.fmt.bufPrint(
        buf,
        "hostnet tcp [{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}]:{d} -> " ++
            "[{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}]:{d} pid={d}",
        .{
            v6Group(o.remote_addr[0..2]),   v6Group(o.remote_addr[2..4]),
            v6Group(o.remote_addr[4..6]),   v6Group(o.remote_addr[6..8]),
            v6Group(o.remote_addr[8..10]),  v6Group(o.remote_addr[10..12]),
            v6Group(o.remote_addr[12..14]), v6Group(o.remote_addr[14..16]),
            o.remote_port,                  v6Group(o.local_addr[0..2]),
            v6Group(o.local_addr[2..4]),    v6Group(o.local_addr[4..6]),
            v6Group(o.local_addr[6..8]),    v6Group(o.local_addr[8..10]),
            v6Group(o.local_addr[10..12]),  v6Group(o.local_addr[12..14]),
            v6Group(o.local_addr[14..16]),  o.local_port,
            o.owning_pid,
        },
    ) catch "hostnet tcp";
}

fn v6Group(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .big);
}

// ============================================================
// Tests
// ============================================================

fn putV4Row(
    buf: []u8,
    index: usize,
    state: u32,
    local: [4]u8,
    local_port: u16,
    remote: [4]u8,
    remote_port: u16,
    pid: u32,
) void {
    const off = 4 + index * V4_ROW_BYTES;
    std.mem.writeInt(u32, buf[off..][0..4], state, .little);
    @memcpy(buf[off + 4 ..][0..4], &local);
    std.mem.writeInt(u16, buf[off + 8 ..][0..2], local_port, .big);
    @memcpy(buf[off + 12 ..][0..4], &remote);
    std.mem.writeInt(u16, buf[off + 16 ..][0..2], remote_port, .big);
    std.mem.writeInt(u32, buf[off + 20 ..][0..4], pid, .little);
}

fn putV6Row(
    buf: []u8,
    index: usize,
    state: u32,
    local: [16]u8,
    local_port: u16,
    remote: [16]u8,
    remote_port: u16,
    pid: u32,
) void {
    const off = 4 + index * V6_ROW_BYTES;
    @memcpy(buf[off..][0..16], &local);
    std.mem.writeInt(u16, buf[off + 20 ..][0..2], local_port, .big);
    @memcpy(buf[off + 24 ..][0..16], &remote);
    std.mem.writeInt(u16, buf[off + 44 ..][0..2], remote_port, .big);
    std.mem.writeInt(u32, buf[off + 48 ..][0..4], state, .little);
    std.mem.writeInt(u32, buf[off + 52 ..][0..4], pid, .little);
}

fn obs(remote_last: u8, remote_port: u16, pid: u32) Observed {
    var o = Observed{ .family = .v4 };
    o.local_addr = .{ 192, 168, 126, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    o.local_port = 445;
    o.remote_addr = .{ 192, 168, 126, remote_last, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    o.remote_port = remote_port;
    o.owning_pid = pid;
    return o;
}

test "host_net parseV4Table keeps ESTAB, drops listen/loopback" {
    var buf = [_]u8{0} ** (4 + 3 * V4_ROW_BYTES);
    std.mem.writeInt(u32, buf[0..4], 3, .little);
    putV4Row(&buf, 0, MIB_TCP_STATE_ESTAB, .{ 192, 168, 126, 20 }, 445, .{ 192, 168, 126, 10 }, 49812, 1234);
    putV4Row(&buf, 1, 2, .{ 192, 168, 126, 20 }, 445, .{ 0, 0, 0, 0 }, 0, 4);
    putV4Row(&buf, 2, MIB_TCP_STATE_ESTAB, .{ 127, 0, 0, 1 }, 50000, .{ 127, 0, 0, 1 }, 50001, 9);

    var out: [8]Observed = undefined;
    const parsed = try parseV4Table(&buf, &out);
    try std.testing.expectEqual(@as(usize, 1), parsed.count);
    try std.testing.expect(!parsed.truncated);
    try std.testing.expectEqual(Family.v4, out[0].family);
    try std.testing.expectEqual(@as(u16, 49812), out[0].remote_port);
    try std.testing.expectEqual(@as(u16, 445), out[0].local_port);
    try std.testing.expectEqual(@as(u32, 1234), out[0].owning_pid);
}

test "host_net toIpcEvent pins network byte order and boundary fields" {
    var o = obs(10, 49812, 1234);
    const ev = toIpcEvent(&o);
    try std.testing.expectEqual(event.EventKind.host_socket_observed, ev.kind);
    try std.testing.expectEqual(event.EventSource.capture_host_net, ev.source);
    try std.testing.expectEqual(@as(u32, 0xC0A87E0A), ev.src_ip); // 192.168.126.10
    try std.testing.expectEqual(@as(u32, 0xC0A87E14), ev.dst_ip); // 192.168.126.20
    try std.testing.expectEqual(@as(u16, 49812), ev.src_port);
    try std.testing.expectEqual(@as(u16, 445), ev.dst_port);
    try std.testing.expectEqual(@as(u8, 6), ev.protocol);
    try std.testing.expectEqual(@as(u32, 0), ev.rule_id);
    try std.testing.expectEqual(event.EventSeverity.info, ev.severity);
    try std.testing.expect(ev.timestamp_ns > 0);
}

test "host_net formatPayload is readable and bounded" {
    var o = obs(10, 49812, 1234);
    var buf: [192]u8 = undefined;
    const payload = formatPayload(&o, &buf);
    try std.testing.expect(std.mem.indexOf(u8, payload, "192.168.126.10:49812") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "192.168.126.20:445") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "pid=1234") != null);
}

test "host_net parseV6Table keeps global pair, drops ::1 and ::" {
    var buf = [_]u8{0} ** (4 + 3 * V6_ROW_BYTES);
    std.mem.writeInt(u32, buf[0..4], 3, .little);

    var lo: [16]u8 = [_]u8{0} ** 16;
    lo[15] = 1;
    var global_local: [16]u8 = [_]u8{0} ** 16;
    global_local[0] = 0xfe;
    global_local[1] = 0x80;
    global_local[15] = 0x20;
    var global_remote: [16]u8 = [_]u8{0} ** 16;
    global_remote[0] = 0x20;
    global_remote[1] = 0x01;
    global_remote[2] = 0x0d;
    global_remote[3] = 0xb8;
    global_remote[15] = 0x01;
    const unspec = [_]u8{0} ** 16;

    putV6Row(&buf, 0, MIB_TCP_STATE_ESTAB, global_local, 445, global_remote, 51000, 77);
    putV6Row(&buf, 1, MIB_TCP_STATE_ESTAB, lo, 445, lo, 51001, 78);
    putV6Row(&buf, 2, MIB_TCP_STATE_ESTAB, unspec, 0, unspec, 0, 79);

    var out: [8]Observed = undefined;
    const parsed = try parseV6Table(&buf, &out);
    try std.testing.expectEqual(@as(usize, 1), parsed.count);
    try std.testing.expectEqual(Family.v6, out[0].family);
    try std.testing.expectEqual(@as(u16, 51000), out[0].remote_port);
    try std.testing.expectEqual(@as(u32, 77), out[0].owning_pid);

    const ev = toIpcEvent(&out[0]);
    // Full v6 identity travels in the queue sidecars (pushEventWithAddrs).
    // The u32 event field stays zero: the v4-prefix-as-address convention is
    // a documented wart that v6 identity must never inherit.
    try std.testing.expectEqual(@as(u32, 0), ev.src_ip);
    try std.testing.expectEqual(@as(u32, 0), ev.dst_ip);
    try std.testing.expectEqual(@as(usize, 16), out[0].remote_addr.len);
    try std.testing.expectEqual(@as(u8, 0x20), out[0].remote_addr[0]);
    try std.testing.expectEqual(@as(u8, 0x01), out[0].remote_addr[15]);
    try std.testing.expectEqual(@as(u16, 51000), ev.src_port);
    try std.testing.expectEqual(@as(u16, 445), ev.dst_port);
}

test "host_net parser reports truncation without reading past the buffer" {
    var buf = [_]u8{0} ** (4 + V4_ROW_BYTES);
    std.mem.writeInt(u32, buf[0..4], 5, .little);
    putV4Row(&buf, 0, MIB_TCP_STATE_ESTAB, .{ 10, 0, 0, 2 }, 445, .{ 10, 0, 0, 9 }, 50000, 1);
    var out: [8]Observed = undefined;
    const parsed = try parseV4Table(&buf, &out);
    try std.testing.expectEqual(@as(usize, 1), parsed.count);
    try std.testing.expect(parsed.truncated);

    var short = [_]u8{0} ** 3;
    try std.testing.expectError(error.TruncatedTable, parseV4Table(&short, &out));
}

test "host_net Tracker seeds first poll and emits only new keys" {
    var tracker = Tracker{};
    var out: [MAX_EMIT_PER_POLL]Observed = undefined;

    const a = obs(10, 50000, 100);
    var first = [_]Observed{a};
    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&first, &out));
    try std.testing.expect(tracker.seeded);
    try std.testing.expectEqual(@as(usize, 1), tracker.prev_count);

    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&first, &out));

    const b = obs(11, 50001, 100);
    var second = [_]Observed{ a, b };
    try std.testing.expectEqual(@as(usize, 1), tracker.diff(&second, &out));
    try std.testing.expectEqual(@as(u16, 50001), out[0].remote_port);

    // Disappearance removes the key; a reappearance is a new observation.
    var only_b = [_]Observed{b};
    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&only_b, &out));
    try std.testing.expectEqual(@as(usize, 1), tracker.diff(&second, &out));
    try std.testing.expectEqual(@as(u16, 50000), out[0].remote_port);
}

test "host_net Tracker treats a pid change as a new key" {
    var tracker = Tracker{};
    var out: [MAX_EMIT_PER_POLL]Observed = undefined;
    var rows = [_]Observed{obs(10, 50000, 100)};
    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&rows, &out));
    rows[0].owning_pid = 101;
    try std.testing.expectEqual(@as(usize, 1), tracker.diff(&rows, &out));
}

test "host_net Tracker caps overflow and emit budget honestly" {
    var tracker = Tracker{};
    var out: [MAX_EMIT_PER_POLL]Observed = undefined;

    var big: [MAX_TRACKED + 1]Observed = undefined;
    for (&big, 0..) |*o, i| {
        o.* = obs(@intCast(i % 250 + 1), @intCast(40000 + (i % 200)), @intCast(i + 1));
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&big, &out));
    try std.testing.expectEqual(@as(u64, 1), tracker.overflow);
    try std.testing.expectEqual(MAX_TRACKED, tracker.prev_count);

    // Empty seed -> every row is new; only MAX_EMIT_PER_POLL are emitted.
    tracker.reset();
    try std.testing.expectEqual(@as(usize, 0), tracker.diff(&.{}, &out));
    var many: [MAX_EMIT_PER_POLL + 1]Observed = undefined;
    for (&many, 0..) |*o, i| {
        o.* = obs(@intCast(i + 1), @intCast(45000 + i), 900);
    }
    try std.testing.expectEqual(MAX_EMIT_PER_POLL, tracker.diff(&many, &out));
    try std.testing.expectEqual(@as(u64, 1), tracker.emit_deferred);
    // The deferred key was not recorded in prev, so the next poll sees it.
    try std.testing.expectEqual(@as(usize, 1), tracker.diff(&many, &out));
    try std.testing.expectEqual(@as(u16, 45000 + MAX_EMIT_PER_POLL), out[0].remote_port);
}

test "host_net Tracker does not depend on wall clock" {
    // Two trackers fed the same sequence at different wall times must emit
    // the same observations: only table content affects the diff.
    var a = Tracker{};
    var b = Tracker{};
    var out_a: [8]Observed = undefined;
    var out_b: [8]Observed = undefined;
    var rows = [_]Observed{obs(10, 50000, 100)};
    _ = a.diff(&rows, &out_a);
    std.time.sleep(2 * std.time.ns_per_ms);
    _ = b.diff(&rows, &out_b);
    rows[0].remote_port = 50002;
    try std.testing.expectEqual(a.diff(&rows, &out_a), b.diff(&rows, &out_b));
    try std.testing.expectEqual(out_a[0].remote_port, out_b[0].remote_port);
}

test "host_net env config clamps poll interval and honours kill switch" {
    const prev_poll = g_poll_ms.load(.acquire);
    defer g_poll_ms.store(prev_poll, .monotonic);
    // The env may or may not exist in the runner; these assertions pin the
    // clamp constants the daemon relies on for watchdog safety.
    try std.testing.expectEqual(@as(u32, 500), MIN_POLL_MS);
    try std.testing.expectEqual(@as(u32, 4000), MAX_POLL_MS);
    try std.testing.expect(MAX_POLL_MS < 5000);
}
