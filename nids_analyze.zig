const std = @import("std");
const net = std.net;
const win = std.os.windows;
const posix = std.posix;

// =================================================================
// [ EXTERN DECLARATIONS FOR WINDOWS NAMED PIPES ]
// ประกาศเพื่อดึงฟังก์ชันจาก kernel32.dll โดยตรง (แก้บั๊ก Zig 0.13.0)
// =================================================================
extern "kernel32" fn CreateNamedPipeA(
    lpName: [*:0]const u8,
    dwOpenMode: u32,
    dwPipeMode: u32,
    nMaxInstances: u32,
    nOutBufferSize: u32,
    nInBufferSize: u32,
    nDefaultTimeOut: u32,
    lpSecurityAttributes: ?*anyopaque,
) win.HANDLE;

extern "kernel32" fn ConnectNamedPipe(hNamedPipe: win.HANDLE, lpOverlapped: ?*anyopaque) i32;
extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: win.HANDLE) i32;
extern "kernel32" fn ReadFile(
    hFile: win.HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?*anyopaque,
) i32;

// =================================================================
// [ C++ IPC BRIDGE — RUNTIME DYNAMIC LOADING (std.DynLib) ]
// Instead of extern declarations (which require link-time DLL),
// we load aegis_ipc.dll at runtime using std.DynLib.
// This allows Zig to build standalone without the DLL.
// =================================================================

const AegisIpcEvent = extern struct {
    // ===== Core fields (bytes 0-39 — kernel AEGIS_EVENT_HEADER compatible) =====
    event_type: u32,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    tier_result: u8,
    payload_length: u32,
    rule_id: u32,
    severity: u32,
    reserved: u32,
    timestamp: u64,
    // ===== Extended fields (bytes 40-47 — backward compatible) =====
    source_pid: u32,
    defcon_impact: u32,
    // ===== G2 canonical extension (bytes 48-75 — NEW) =====
    event_id: u64 = 0,
    schema_version: u16 = 2,
    confidence: u8 = 0,
    provenance: u8 = 0,
    parent_pid: u32 = 0,
    evidence_offset: u32 = 0,
    evidence_length: u32 = 0,
};

// Bridge function signatures (for std.DynLib symbol lookup)
const FnBridgeInit = *const fn () callconv(.c) i32;
const FnBridgeShutdown = *const fn () callconv(.c) i32;
const FnBridgePushEvent = *const fn (*const AegisIpcEvent) callconv(.c) i32;
const FnBridgeGetDefcon = *const fn () callconv(.c) u8;
const FnBridgeGetEventCount = *const fn () callconv(.c) u32;

// Rust FFI function signature
const FnValidatePayloadSafety = *const fn ([*]const u8, usize) callconv(.c) bool;

// Runtime-loaded function pointers (null = not available)
var fn_bridge_init: ?FnBridgeInit = null;
var fn_bridge_shutdown: ?FnBridgeShutdown = null;
var fn_bridge_push_event: ?FnBridgePushEvent = null;
var fn_bridge_get_defcon: ?FnBridgeGetDefcon = null;
var fn_bridge_get_event_count: ?FnBridgeGetEventCount = null;
var fn_validate_payload_safety: ?FnValidatePayloadSafety = null;

var bridge_initialized: bool = false;
var bridge_dll: ?std.DynLib = null;
var rust_dll: ?std.DynLib = null;

// =================================================================
// [ G3: EVENT ACCOUNTING — Runtime Spine Metrics ]
// Tracks: input = processed + dropped + rejected + expired + failed
// Report v2.0 G4 requirement: "การ drop ต้องมีเหตุผลและ metric"
// =================================================================
pub const EventAccounting = struct {
    total_input: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_processed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_expired: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn recordInput(self: *EventAccounting) void {
        _ = self.total_input.fetchAdd(1, .monotonic);
    }
    pub fn recordProcessed(self: *EventAccounting) void {
        _ = self.total_processed.fetchAdd(1, .monotonic);
    }
    pub fn recordDropped(self: *EventAccounting, reason: []const u8) void {
        _ = self.total_dropped.fetchAdd(1, .monotonic);
        std.log.debug("[ACCOUNTING] dropped: {s}", .{reason});
    }
    pub fn recordRejected(self: *EventAccounting) void {
        _ = self.total_rejected.fetchAdd(1, .monotonic);
    }
    pub fn recordFailed(self: *EventAccounting) void {
        _ = self.total_failed.fetchAdd(1, .monotonic);
    }
    pub fn printStats(self: *const EventAccounting) void {
        const input = self.total_input.load(.monotonic);
        const processed = self.total_processed.load(.monotonic);
        const dropped = self.total_dropped.load(.monotonic);
        const rejected = self.total_rejected.load(.monotonic);
        const failed = self.total_failed.load(.monotonic);
        std.debug.print("[SPINE] input={d} processed={d} dropped={d} rejected={d} failed={d}\n",
            .{ input, processed, dropped, rejected, failed });
    }
};

pub var event_accounting: EventAccounting = .{};

/// Try to load aegis_ipc.dll at runtime
fn loadBridgeDll() void {
    const dll_names = [_][]const u8{
        "aegis_ipc.dll",
        "libaegis_ipc.so",
    };
    const search_paths = [_][]const u8{
        "bridge",
        "build",
        "build\\Release",
        "build\\Debug",
        "target\\release",
        ".",
    };

    for (dll_names) |dll_name| {
        // Try search paths first
        for (search_paths) |dir| {
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
            if (std.DynLib.open(path)) |lib| {
                bridge_dll = lib;
                std.debug.print("[BRIDGE] Loaded: {s}\n", .{path});
                break;
            } else |_| {}
        }
        // Try system path
        if (bridge_dll == null) {
            if (std.DynLib.open(dll_name)) |lib| {
                bridge_dll = lib;
                std.debug.print("[BRIDGE] Loaded from system path: {s}\n", .{dll_name});
            } else |_| {}
        }
        if (bridge_dll != null) break;
    }

    if (bridge_dll) |lib| {
        fn_bridge_init = lib.lookup(FnBridgeInit, "aegis_bridge_init");
        fn_bridge_shutdown = lib.lookup(FnBridgeShutdown, "aegis_bridge_shutdown");
        fn_bridge_push_event = lib.lookup(FnBridgePushEvent, "aegis_bridge_push_event");
        fn_bridge_get_defcon = lib.lookup(FnBridgeGetDefcon, "aegis_bridge_get_defcon");
        fn_bridge_get_event_count = lib.lookup(FnBridgeGetEventCount, "aegis_bridge_get_event_count");

        if (fn_bridge_init != null) {
            std.debug.print("\x1b[32m[BRIDGE] C++ IPC Bridge symbols resolved\x1b[0m\n", .{});
        } else {
            std.debug.print("\x1b[33m[BRIDGE] Warning: DLL loaded but symbols not found\x1b[0m\n", .{});
        }
    } else {
        std.debug.print("\x1b[33m[BRIDGE] Warning: aegis_ipc.dll not found — running without Bridge\x1b[0m\n", .{});
    }
}

/// Try to load sec_monitor.dll at runtime (Rust FFI)
fn loadRustDll() void {
    const dll_names = [_][]const u8{
        "sec_monitor.dll",
        "libsec_monitor.so",
    };
    const search_paths = [_][]const u8{
        "target\\release",
        "target\\debug",
        ".",
    };

    for (dll_names) |dll_name| {
        for (search_paths) |dir| {
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
            if (std.DynLib.open(path)) |lib| {
                rust_dll = lib;
                std.debug.print("[RUST] Loaded: {s}\n", .{path});
                break;
            } else |_| {}
        }
        if (rust_dll == null) {
            if (std.DynLib.open(dll_name)) |lib| {
                rust_dll = lib;
                std.debug.print("[RUST] Loaded from system path: {s}\n", .{dll_name});
            } else |_| {}
        }
        if (rust_dll != null) break;
    }

    if (rust_dll) |lib| {
        fn_validate_payload_safety = lib.lookup(FnValidatePayloadSafety, "validate_payload_safety");
        if (fn_validate_payload_safety != null) {
            std.debug.print("\x1b[32m[RUST] Tier-0 Memory Safety Shield active\x1b[0m\n", .{});
        }
    } else {
        std.debug.print("\x1b[33m[RUST] Warning: sec_monitor.dll not found — running without Memory Safety Shield\x1b[0m\n", .{});
    }
}

/// Initialize bridge at runtime
fn bridgeInit() i32 {
    if (fn_bridge_init) |f| {
        const rc = f();
        if (rc == 0) {
            bridge_initialized = true;
        }
        return rc;
    }
    return -1; // Not available
}

/// Shutdown bridge at runtime
fn bridgeShutdown() i32 {
    if (fn_bridge_shutdown) |f| {
        bridge_initialized = false;
        return f();
    }
    return 0;
}

// =================================================================
// [ PACKET CONTEXT — 5-tuple สำหรับส่งผ่านระบบ ]
// =================================================================
pub const PacketContext = struct {
    source_ip: u32 = 0,
    dest_ip: u32 = 0,
    source_port: u16 = 0,
    dest_port: u16 = 0,
    protocol: u8 = 0,
    direction: u8 = 0,
    layer_id: u8 = 0,
    is_pipe: bool = false,
};

// =================================================================
// [ G5: FLOW STATE — TCP/UDP session tracking ]
// Report v2.0 G5 requirement: ownership model, concurrency, memory bound,
// eviction latency, high-watermark.
//
// FlowState tracks active TCP/UDP flows by 5-tuple (proto, src_ip, src_port,
// dst_ip, dst_port). Each flow accumulates packet count, byte count, and
// first/last seen timestamps. Flows are evicted after 60s of inactivity.
// Memory is bounded: max 4096 concurrent flows; oldest evicted on overflow.
// =================================================================
pub const MAX_FLOWS: usize = 4096;
pub const FLOW_TIMEOUT_MS: i64 = 60_000; // 60 seconds inactivity → evict

pub const FlowEntry = struct {
    protocol: u8 = 0,
    src_ip: u32 = 0,
    src_port: u16 = 0,
    dst_ip: u32 = 0,
    dst_port: u16 = 0,
    pkt_count: u32 = 0,
    byte_count: u64 = 0,
    first_seen_ms: i64 = 0,
    last_seen_ms: i64 = 0,
    flow_id: u64 = 0, // Unique monotonic ID for correlation
    active: bool = false,
};

pub const FlowTable = struct {
    entries: [MAX_FLOWS]FlowEntry = [_]FlowEntry{.{}} ** MAX_FLOWS,
    count: usize = 0,
    next_flow_id: u64 = 1,
    total_created: u64 = 0,
    total_evicted: u64 = 0,
    total_overflow: u64 = 0,
    high_watermark: usize = 0,

    fn flowKey(proto: u8, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) u64 {
        // Simple hash: combine 5-tuple into u64 key
        return @as(u64, proto) << 56 |
            @as(u64, src_ip) << 24 |
            @as(u64, src_port) << 8 |
            @as(u64, dst_port) |
            @as(u64, dst_ip) << 40;
    }

    /// Look up or create a flow entry for the given 5-tuple.
    /// Returns a pointer to the flow entry (caller must not hold across yields).
    pub fn lookupOrCreate(self: *FlowTable, ctx: PacketContext, data_len: usize, now_ms: i64) *FlowEntry {
        // Try to find existing flow
        for (&self.entries, 0..) |*entry, i| {
            _ = i;
            if (entry.active and
                entry.protocol == ctx.protocol and
                entry.src_ip == ctx.source_ip and
                entry.src_port == ctx.source_port and
                entry.dst_ip == ctx.dest_ip and
                entry.dst_port == ctx.dest_port)
            {
                entry.pkt_count += 1;
                entry.byte_count += data_len;
                entry.last_seen_ms = now_ms;
                return entry;
            }
        }

        // Evict expired flows first
        self.evictExpired(now_ms);

        // Find a free slot
        for (&self.entries, 0..) |*entry, i| {
            _ = i;
            if (!entry.active) {
                entry.* = .{
                    .protocol = ctx.protocol,
                    .src_ip = ctx.source_ip,
                    .src_port = ctx.source_port,
                    .dst_ip = ctx.dest_ip,
                    .dst_port = ctx.dest_port,
                    .pkt_count = 1,
                    .byte_count = data_len,
                    .first_seen_ms = now_ms,
                    .last_seen_ms = now_ms,
                    .flow_id = self.next_flow_id,
                    .active = true,
                };
                self.next_flow_id += 1;
                self.count += 1;
                self.total_created += 1;
                if (self.count > self.high_watermark) self.high_watermark = self.count;
                return entry;
            }
        }

        // All slots full — overflow; evict oldest
        self.total_overflow += 1;
        var oldest_idx: usize = 0;
        var oldest_time: i64 = std.math.maxInt(i64);
        for (self.entries, 0..) |e, i| {
            if (e.last_seen_ms < oldest_time) {
                oldest_time = e.last_seen_ms;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx] = .{};
        self.count -= 1;
        self.total_evicted += 1;
        // Retry creation
        return self.lookupOrCreate(ctx, data_len, now_ms);
    }

    /// Evict flows that have been inactive for longer than FLOW_TIMEOUT_MS.
    pub fn evictExpired(self: *FlowTable, now_ms: i64) void {
        for (&self.entries, 0..) |*entry, i| {
            _ = i;
            if (entry.active and (now_ms - entry.last_seen_ms) > FLOW_TIMEOUT_MS) {
                entry.active = false;
                self.count -= 1;
                self.total_evicted += 1;
            }
        }
    }

    pub fn printStats(self: *const FlowTable) void {
        std.debug.print("[FLOWS] active={d} created={d} evicted={d} overflow={d} high_watermark={d}\n",
            .{ self.count, self.total_created, self.total_evicted, self.total_overflow, self.high_watermark });
    }
};

pub var flow_table: FlowTable = .{};

// =================================================================
// [ WFP EVENT HEADER — 44 bytes จาก kernel driver ]
// =================================================================
pub const WfpEventHeader = extern struct {
    event_type: u32,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    flags: u8,
    payload_length: u32,
    rule_id: u32,
    severity: u32,
    reserved: u32,
    timestamp: u64,
};

/// Helper: Push Tier-1 match result to C++ Bridge
fn pushTier1Match(
    ctx: PacketContext,
    rule_id: u32,
    severity: u32,
    payload_len: u32,
) i32 {
    if (fn_bridge_push_event == null) return -1;
    if (!bridge_initialized) return -1;
    const event: AegisIpcEvent = .{
        .event_type = if (ctx.is_pipe) 3 else 0,
        .source_ip = ctx.source_ip,
        .dest_ip = ctx.dest_ip,
        .source_port = ctx.source_port,
        .dest_port = ctx.dest_port,
        .protocol = ctx.protocol,
        .direction = ctx.direction,
        .layer_id = ctx.layer_id,
        .tier_result = 1,
        .payload_length = payload_len,
        .rule_id = rule_id,
        .severity = severity,
        .reserved = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .source_pid = 0,
        .defcon_impact = 4,
    };
    return fn_bridge_push_event.?(&event);
}

/// Helper: Push forwarded event to C++ Bridge
fn pushForwardedEvent(
    ctx: PacketContext,
    payload_len: u32,
) i32 {
    if (fn_bridge_push_event == null) return -1;
    if (!bridge_initialized) return -1;
    const event: AegisIpcEvent = .{
        .event_type = if (ctx.is_pipe) 3 else 0,
        .source_ip = ctx.source_ip,
        .dest_ip = ctx.dest_ip,
        .source_port = ctx.source_port,
        .dest_port = ctx.dest_port,
        .protocol = ctx.protocol,
        .direction = ctx.direction,
        .layer_id = ctx.layer_id,
        .tier_result = 0,
        .payload_length = payload_len,
        .rule_id = 0,
        .severity = 0,
        .reserved = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .source_pid = 0,
        .defcon_impact = 5,
    };
    return fn_bridge_push_event.?(&event);
}

/// Validate payload using Rust Memory Safety Shield (runtime loaded)
fn validatePayloadSafety(data: [*]const u8, len: usize) bool {
    if (fn_validate_payload_safety) |f| {
        return f(data, len);
    }
    // Rust Shield not available — allow by default
    return true;
}

// =================================================================
// [ TIER 1: AHO-CORASICK FAST PATTERN ENGINE ]
// =================================================================
const AhoCorasick = struct {
    pub const Node = struct {
        next: [256]usize,
        fail: usize,
        matches: std.ArrayList(usize),
    };
    nodes: std.ArrayList(Node),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !AhoCorasick {
        var ac = AhoCorasick{
            .nodes = std.ArrayList(Node).init(allocator),
            .allocator = allocator,
        };
        _ = try ac.addNode();
        return ac;
    }

    pub fn deinit(self: *AhoCorasick) void {
        for (self.nodes.items) |*node| {
            node.matches.deinit();
        }
        self.nodes.deinit();
    }

    fn addNode(self: *AhoCorasick) !usize {
        const idx = self.nodes.items.len;
        const node = Node{
            .next = [_]usize{std.math.maxInt(usize)} ** 256,
            .fail = 0,
            .matches = std.ArrayList(usize).init(self.allocator),
        };
        try self.nodes.append(node);
        return idx;
    }

    pub fn insert(self: *AhoCorasick, pattern: []const u8, rule_idx: usize) !void {
        if (pattern.len == 0) return;
        var curr: usize = 0;
        for (pattern) |char| {
            const c = @as(usize, char);
            if (self.nodes.items[curr].next[c] == std.math.maxInt(usize)) {
                const next_node = try self.addNode();
                self.nodes.items[curr].next[c] = next_node;
            }
            curr = self.nodes.items[curr].next[c];
        }
        try self.nodes.items[curr].matches.append(rule_idx);
    }

    pub fn buildFailureLinks(self: *AhoCorasick) !void {
        var queue = std.ArrayList(usize).init(self.allocator);
        defer queue.deinit();

        for (0..256) |c| {
            const next_node = self.nodes.items[0].next[c];
            if (next_node != std.math.maxInt(usize)) {
                self.nodes.items[next_node].fail = 0;
                try queue.append(next_node);
            } else {
                self.nodes.items[0].next[c] = 0;
            }
        }

        var head: usize = 0;
        while (head < queue.items.len) {
            const u = queue.items[head];
            head += 1;

            for (0..256) |c| {
                const v = self.nodes.items[u].next[c];
                if (v != std.math.maxInt(usize)) {
                    const fail_node = self.nodes.items[u].fail;
                    self.nodes.items[v].fail = self.nodes.items[fail_node].next[c];
                    try queue.append(v);
                } else {
                    self.nodes.items[u].next[c] = self.nodes.items[self.nodes.items[u].fail].next[c];
                }
            }
        }
    }
};

const ThreatState = enum(u8) { CLEAN = 0, SUSPICIOUS = 1, VERIFIED = 2, BLOCKED = 3 };

/// G7: Correlation entity — per-source-IP threat state machine.
/// Tracks: CLEAN → SUSPICIOUS (Tier-1 match) → VERIFIED (multiple matches) → BLOCKED (Block action)
/// This is the multi-event correlation engine: repeated matches from the same
/// source escalate the threat level.
const AtomicThreatTracker = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(ThreatState.CLEAN)),
    match_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    first_match_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    last_match_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    /// Step 1: First match from this source → mark SUSPICIOUS.
    /// Returns true if this is the first match (state was CLEAN).
    pub fn step1_markSuspicious(self: *AtomicThreatTracker, now_ms: i64) bool {
        const result = self.state.cmpxchgStrong(
            @intFromEnum(ThreatState.CLEAN),
            @intFromEnum(ThreatState.SUSPICIOUS),
            .acquire, .monotonic,
        ) == null;
        if (result) {
            _ = self.first_match_ms.store(now_ms, .release);
        }
        _ = self.match_count.fetchAdd(1, .monotonic);
        _ = self.last_match_ms.store(now_ms, .release);
        return result;
    }

    /// Step 2: Multiple matches → verify threat.
    /// Called when match_count >= 3 (heuristic: 3+ matches from same source = campaign).
    /// Returns true if state was SUSPICIOUS (now VERIFIED).
    pub fn step2_verifyThreat(self: *AtomicThreatTracker) bool {
        return self.state.cmpxchgStrong(
            @intFromEnum(ThreatState.SUSPICIOUS),
            @intFromEnum(ThreatState.VERIFIED),
            .acquire, .monotonic,
        ) == null;
    }

    /// Step 3: Block action → mark BLOCKED.
    pub fn step3_block(self: *AtomicThreatTracker) bool {
        return self.state.cmpxchgStrong(
            @intFromEnum(ThreatState.VERIFIED),
            @intFromEnum(ThreatState.BLOCKED),
            .acquire, .monotonic,
        ) == null;
    }

    pub fn getState(self: *const AtomicThreatTracker) ThreatState {
        return @enumFromInt(self.state.load(.acquire));
    }

    pub fn getMatchCount(self: *const AtomicThreatTracker) u32 {
        return self.match_count.load(.monotonic);
    }

    pub fn reset(self: *AtomicThreatTracker) void {
        self.state.store(@intFromEnum(ThreatState.CLEAN), .release);
        self.match_count.store(0, .release);
    }
};

/// G7: Global threat tracker (simplified: single tracker for all sources).
/// Future: per-source-IP hash map of trackers (requires G5 flow table integration).
var global_attacker_tracker: AtomicThreatTracker = .{};

pub const SecureRule = struct {
    name: []const u8,
    fast_pattern: []const u8,
    match_pattern: []const u8,
    regex_pattern: []const u8,
    severity: []const u8,
    action: []const u8,
    crc32: u32,
};

pub const SecureRuleSet = struct {
    allocator: std.mem.Allocator,
    signatures: []const SecureRule = &[_]SecureRule{},
    ac_engine: AhoCorasick,

    pub fn deinit(self: *SecureRuleSet) void {
        for (self.signatures) |sig| {
            self.allocator.free(sig.name);
            self.allocator.free(sig.fast_pattern);
            self.allocator.free(sig.match_pattern);
            self.allocator.free(sig.regex_pattern);
            self.allocator.free(sig.severity);
        }
        self.allocator.free(self.signatures);
        self.ac_engine.deinit();
        self.allocator.destroy(self);
    }
};

var active_ruleset: std.atomic.Value(?*SecureRuleSet) = std.atomic.Value(?*SecureRuleSet).init(null);
var connection_semaphore: std.Thread.Semaphore = .{ .permits = 100 };
var active_threads: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var udp_log_sock: posix.socket_t = undefined;
var udp_log_addr: net.Address = undefined;

// --- [ RULE LOADING ] ---
pub fn reload_rules_atomic(allocator: std.mem.Allocator) !void {
    const file = std.fs.cwd().openFile("Rules.json", .{}) catch |err| {
        std.debug.print("\x1b[31m[ERROR] Cannot open Rules.json: {}\x1b[0m\n", .{err});
        return;
    };
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 2 * 1024 * 1024);
    defer allocator.free(content);

    const TempRule = struct { name: []const u8, fast_pattern: []const u8 = "", match_pattern: []const u8 = "", regex_pattern: []const u8 = "", severity: []const u8 = "Alert", action: []const u8 = "Alert" };
    const TempRuleSet = struct { nids_rules: []TempRule };

    const parsed = std.json.parseFromSlice(TempRuleSet, allocator, content, .{ .ignore_unknown_fields = true }) catch |err| {
        std.debug.print("\x1b[31m[ERROR] JSON Parse Failed: {}\x1b[0m\n", .{err});
        return;
    };
    defer parsed.deinit();

    var new_set = try allocator.create(SecureRuleSet);
    new_set.allocator = allocator;
    new_set.ac_engine = try AhoCorasick.init(allocator);

    var temp_sig_list = std.ArrayListAligned(SecureRule, 8).init(allocator);
    errdefer {
        for (temp_sig_list.items) |*sig| {
            allocator.free(sig.name);
            allocator.free(sig.fast_pattern);
            allocator.free(sig.match_pattern);
            allocator.free(sig.regex_pattern);
            allocator.free(sig.severity);
        }
        temp_sig_list.deinit();
        new_set.ac_engine.deinit();
        allocator.destroy(new_set);
    }

    var valid_rule_count: usize = 0;
    for (parsed.value.nids_rules) |sig| {
        var active_fast_pattern: []const u8 = sig.fast_pattern;
        if (active_fast_pattern.len == 0) {
            if (sig.match_pattern.len > 0) {
                if (std.mem.indexOfAny(u8, sig.match_pattern, "|()[{\\.*+?^$")) |idx| {
                    active_fast_pattern = sig.match_pattern[0..idx];
                } else {
                    active_fast_pattern = sig.match_pattern;
                }
            } else {
                continue;
            }
        }

        if (active_fast_pattern.len < 3) continue;

        var hash = std.hash.Crc32.init();
        hash.update(active_fast_pattern);
        try temp_sig_list.append(.{
            .name = try allocator.dupe(u8, sig.name),
            .fast_pattern = try allocator.dupe(u8, active_fast_pattern),
            .match_pattern = try allocator.dupe(u8, sig.match_pattern),
            .regex_pattern = try allocator.dupe(u8, sig.regex_pattern),
            .severity = try allocator.dupe(u8, sig.severity),
            .action = try allocator.dupe(u8, sig.action),
            .crc32 = hash.final(),
        });

        try new_set.ac_engine.insert(temp_sig_list.items[valid_rule_count].fast_pattern, valid_rule_count);
        valid_rule_count += 1;
    }

    try new_set.ac_engine.buildFailureLinks();
    new_set.signatures = try temp_sig_list.toOwnedSlice();
    const old_set = active_ruleset.swap(new_set, .release);
    if (old_set) |old| {
        old.deinit();
    }

    std.debug.print("\x1b[32m[ENTERPRISE SECURITY] Successfully loaded {d} secure rules.\x1b[0m\n", .{valid_rule_count});
}
// UDP send to brain
fn send_to_brain(allocator: std.mem.Allocator, msg: anytype) !void {
    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();

    try std.json.stringify(msg, .{}, string.writer());
    _ = posix.sendto(udp_log_sock, string.items, 0, &udp_log_addr.any, udp_log_addr.getOsSockLen()) catch {};
}

// --- [ 3-TIER FAST THREAT ANALYSIS ENGINE (G3: Runtime Spine Dispatcher) ] ---
// inspect_packet is the canonical dispatcher entry point.
// All sensors (pipe, TCP, WFP) call this function to submit events.
// G3 accounting: input = processed + dropped + rejected + expired + failed
pub fn inspect_packet(data: []const u8, ctx: PacketContext) !bool {
    event_accounting.recordInput();

    // G5: Track flow state (5-tuple → flow entry with pkt/byte counts + flow_id)
    if (!ctx.is_pipe) {
        _ = flow_table.lookupOrCreate(ctx, data.len, std.time.milliTimestamp());
    }

    std.debug.print("[DEBUG] Analyzing data from {s}, size: {} bytes, src_ip=0x{x}, dst_port={d}\n", .{ if (ctx.is_pipe) "PIPE" else "TCP", data.len, ctx.source_ip, ctx.dest_port });

    // 🛡️ [Rust Memory Safety Check — runtime loaded]
    if (!validatePayloadSafety(data.ptr, data.len)) {
        event_accounting.recordRejected();
        return false;
    }

    const current_ruleset = active_ruleset.load(.acquire) orelse {
        event_accounting.recordDropped("no ruleset loaded");
        return false;
    };
    const allocator = current_ruleset.allocator;

    var curr: usize = 0;
    var final_matched_rule: ?*const SecureRule = null;

    // --- [ TIER 1: Aho-Corasick ] ---
    for (data) |char| {
        const c = @as(usize, char);
        curr = current_ruleset.ac_engine.nodes.items[curr].next[c];

        var temp = curr;
        while (temp != 0) {
            for (current_ruleset.ac_engine.nodes.items[temp].matches.items) |idx| {
                const rule = &current_ruleset.signatures[idx];
                var is_tier2_match = true;

                if (rule.match_pattern.len > 0) {
                    var match_iter = std.mem.splitSequence(u8, rule.match_pattern, "|");
                    while (match_iter.next()) |keyword| {
                        if (keyword.len == 0) continue;
                        if (std.mem.indexOfAny(u8, keyword, "()[{\\.*+?^$") != null) continue;
                        if (std.mem.indexOf(u8, data, keyword) == null) {
                            is_tier2_match = false;
                            break;
                        }
                    }
                }

                if (is_tier2_match) {
                    final_matched_rule = rule;
                    break;
                }
            }
            if (final_matched_rule != null) break;
            temp = current_ruleset.ac_engine.nodes.items[temp].fail;
        }
        if (final_matched_rule != null) break;
    }

    if (final_matched_rule) |rule| {
        // G7: Correlate — mark suspicious / verify / block based on match count
        const now_ms = std.time.milliTimestamp();
        _ = global_attacker_tracker.step1_markSuspicious(now_ms);
        if (global_attacker_tracker.getMatchCount() >= 3) {
            if (global_attacker_tracker.step2_verifyThreat()) {
                std.debug.print("[G7] Threat VERIFIED — {d} matches from source\n",
                    .{global_attacker_tracker.getMatchCount()});
            }
        }

        const alert = .{
            .timestamp = std.time.timestamp(),
            .attack_type = rule.name,
            .policy = rule.action,
            .reason = "Tier-1 Fast Pattern Match",
            .source = if (ctx.is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
            .source_ip = ctx.source_ip,
            .dest_ip = ctx.dest_ip,
            .source_port = ctx.source_port,
            .dest_port = ctx.dest_port,
            .protocol = ctx.protocol,
        };

        try send_to_brain(allocator, alert);

        const severity_val: u32 = val: {
            if (std.mem.eql(u8, rule.severity, "Critical")) break :val 3;
            if (std.mem.eql(u8, rule.severity, "High")) break :val 2;
            if (std.mem.eql(u8, rule.severity, "Medium")) break :val 1;
            break :val 0;
        };
        _ = pushTier1Match(ctx, rule.crc32, severity_val, @intCast(data.len));

        if (std.mem.eql(u8, rule.action, "Block")) {
            std.debug.print("\x1b[31;1m[ AEGIS CORE ] !!! BLOCK !!! Connection Terminated: {s}\x1b[0m\n", .{rule.name});
            // G7: Mark threat as BLOCKED
            _ = global_attacker_tracker.step3_block();
            event_accounting.recordProcessed();
            return false;
        }

        event_accounting.recordProcessed();
        return true;
    } else {
        const forward_msg = .{
            .timestamp = std.time.timestamp(),
            .attack_type = "Unmatched: Deep Inspection Required",
            .policy = "Pending",
            .reason = "Forwarded: No Tier-1 Match",
            .source = if (ctx.is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
            .source_ip = ctx.source_ip,
            .dest_ip = ctx.dest_ip,
            .source_port = ctx.source_port,
            .dest_port = ctx.dest_port,
            .protocol = ctx.protocol,
        };

        try send_to_brain(allocator, forward_msg);
        _ = pushForwardedEvent(ctx, @intCast(data.len));

        event_accounting.recordProcessed();
        return true;
    }
}

// ==========================================
// [ IPC & SOCKET LISTENERS ]
// ==========================================
fn handle_pipe_client(hPipe: win.HANDLE) void {
    defer {
        _ = DisconnectNamedPipe(hPipe);
        win.CloseHandle(hPipe);
    }
    defer connection_semaphore.post();
    defer _ = active_threads.fetchSub(1, .monotonic);
    _ = active_threads.fetchAdd(1, .monotonic);

    const ctx = PacketContext{
        .is_pipe = true,
        .layer_id = 3,
    };

    var buf: [4096]u8 = undefined;
    while (true) {
        var bytes_read: u32 = 0;
        const success = ReadFile(hPipe, &buf, buf.len, &bytes_read, null);
        if (success == 0 or bytes_read == 0) break;
        const is_safe = inspect_packet(buf[0..bytes_read], ctx) catch true;
        if (!is_safe) {
            break;
        }
    }
}

fn pipe_listener() !void {
    const pipe_name = "\\\\.\\pipe\\aegis_nids";
    while (true) {
        const hPipe = CreateNamedPipeA(pipe_name, 3, 0, 255, 4096, 4096, 0, null);
        if (hPipe == win.INVALID_HANDLE_VALUE) return;

        const connected = ConnectNamedPipe(hPipe, null);
        const err = win.kernel32.GetLastError();

        if (connected != 0 or @intFromEnum(err) == 535) {
            connection_semaphore.wait();
            const t = std.Thread.spawn(.{}, handle_pipe_client, .{hPipe}) catch {
                _ = DisconnectNamedPipe(hPipe);
                win.CloseHandle(hPipe);
                connection_semaphore.post();
                continue;
            };
            t.detach();
        } else {
            _ = DisconnectNamedPipe(hPipe);
            win.CloseHandle(hPipe);
        }
    }
}

fn handle_tcp_client(stream: net.Stream, remote_addr: net.Address) void {
    defer stream.close();
    defer connection_semaphore.post();
    defer _ = active_threads.fetchSub(1, .monotonic);
    _ = active_threads.fetchAdd(1, .monotonic);

    const src_ip: u32 = blk: {
        const sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&remote_addr.any)));
        break :blk sa.addr;
    };
    const src_port: u16 = blk: {
        const sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&remote_addr.any)));
        break :blk std.mem.bigToNative(u16, sa.port);
    };

    const ctx = PacketContext{
        .source_ip = src_ip,
        .source_port = src_port,
        .dest_port = 12345,
        .protocol = 6,
        .layer_id = 0,
        .is_pipe = false,
    };

    var buf: [16384]u8 = undefined;
    while (true) {
        const len = stream.read(&buf) catch break;
        if (len == 0) break;
        const is_safe = inspect_packet(buf[0..len], ctx) catch true;
        if (!is_safe) {
            break;
        }
    }
}

fn tcp_listener() !void {
    var addr = net.Address.parseIp4("0.0.0.0", 12345) catch return;
    var server = addr.listen(.{ .reuse_address = true }) catch return;
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        connection_semaphore.wait();
        const t = std.Thread.spawn(.{}, handle_tcp_client, .{ conn.stream, conn.address }) catch {
            conn.stream.close();
            connection_semaphore.post();
            continue;
        };
        t.detach();
    }
}

pub fn analyze_packets(allocator: std.mem.Allocator) void {
    std.debug.print("\n--- AEGIS CORE: 3-TIER ENGINE ACTIVE ---\n", .{});

    // 🔗 Load C++ IPC Bridge DLL at runtime (no link-time dependency)
    loadBridgeDll();
    loadRustDll();

    // Initialize Bridge if loaded
    const bridge_rc = bridgeInit();
    if (bridge_rc == 0) {
        std.debug.print("\x1b[32m[BRIDGE] C++ IPC Bridge initialized — Zig Core connected\x1b[0m\n", .{});
    } else if (fn_bridge_init != null) {
        std.debug.print("\x1b[33m[BRIDGE] Warning: Bridge init failed (rc={d}), running without Bridge\x1b[0m\n", .{bridge_rc});
    }
    defer {
        _ = bridgeShutdown();
        if (bridge_dll) |*lib| lib.close();
        if (rust_dll) |*lib| lib.close();
        std.debug.print("[BRIDGE] C++ IPC Bridge shutdown\n", .{});
    }

    udp_log_addr = net.Address.parseIp4("127.0.0.1", 9999) catch unreachable;
    udp_log_sock = posix.socket(udp_log_addr.any.family, posix.SOCK.DGRAM, 0) catch unreachable;

    reload_rules_atomic(allocator) catch |err| {
        std.debug.print("Failed to load rules: {}\n", .{err});
    };

    const t_bridge_status = std.Thread.spawn(.{}, bridgeStatusReporter, .{}) catch null;
    if (t_bridge_status) |t| t.detach();

    const t_pipe = std.Thread.spawn(.{}, pipe_listener, .{}) catch return;
    const t_tcp = std.Thread.spawn(.{}, tcp_listener, .{}) catch return;
    t_pipe.join();
    t_tcp.join();
}

/// Background thread: Print Bridge stats + G3 event accounting every 30 seconds
fn bridgeStatusReporter() void {
    while (true) {
        std.time.sleep(30 * std.time.ns_per_s);
        if (!bridge_initialized) continue;
        if (fn_bridge_get_event_count) |get_count| {
            if (fn_bridge_get_defcon) |get_defcon| {
                const count = get_count();
                const defcon = get_defcon();
                std.debug.print("[BRIDGE] Events in queue: {d} | DEFCON: {d}\n", .{ count, defcon });
            }
        }
        // G3: Print event accounting (runtime spine metrics)
        event_accounting.printStats();
        // G5: Print flow table stats
        flow_table.printStats();
    }
}
