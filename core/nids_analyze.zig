//! nids_analyze.zig - AEGIS NIDS 3-Tier Analysis Engine (Thread 1)
//!
//! Core threat analysis engine using Aho-Corasick pattern matching.
//! Loads rules from Rules.json, runs pipe + TCP listeners,
//! and delegates bridge/brain functions to bridge_init.zig.
//!
//! Bridge loading is handled by bridge_init.initAll() in nids_main.zig.
//! This module only uses bridge_init re-exports for runtime operations.

const std = @import("std");
const net = std.net;
const win = std.os.windows;
const posix = std.posix;
const bridge_init = @import("bridge_init.zig");

// =================================================================
// [ WIN32 NAMED PIPE FFI ]
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
) i32; // ====== BP19: Admin-Only Pipe ACL via SDDL ======

// BP192: PeekNamedPipe for shutdown-responsive pipe reads
extern "kernel32" fn PeekNamedPipe(
    hNamedPipe: win.HANDLE,
    lpBuffer: ?*anyopaque,
    nBufferSize: u32,
    lpBytesRead: ?*u32,
    lpTotalBytesAvail: ?*u32,
    lpBytesLeftThisMessage: ?*u32,
) i32;

// SIGINT (CTRL+C) handler for graceful shutdown
const HandlerRoutine = *const fn (u32) callconv(.C) i32;
extern "kernel32" fn SetConsoleCtrlHandler(handler: ?HandlerRoutine, add: i32) i32;

fn ctrlHandler(ctrl_type: u32) callconv(.C) i32 {
    // BP184: Handle all shutdown signals for graceful termination
    //   0=CTRL_C_EVENT, 1=CTRL_BREAK_EVENT, 2=CTRL_CLOSE_EVENT,
    //   5=CTRL_LOGOFF_EVENT, 6=CTRL_SHUTDOWN_EVENT
    if (ctrl_type == 0 or ctrl_type == 1 or ctrl_type == 2 or ctrl_type == 5 or ctrl_type == 6) {
        g_shutdown_requested.store(true, .release);
        bridge_init.requestShutdown(); // BP-FIX: also signal T2-T5 threads
        std.log.warn("[SHUTDOWN] Signal {} received -- draining connections", .{ctrl_type});
        std.debug.print("\x1b[33m[SHUTDOWN] Signal {} received -- draining connections...\x1b[0m\n", .{ctrl_type});
        return 1;
    }
    return 0;
}

/// Global shutdown flag set by SIGINT handler for graceful termination
pub var g_shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorA(
    StringSecurityDescriptor: [*:0]const u8,
    StringSDRevision: u32,
    SecurityDescriptor: *?*anyopaque,
    SecurityDescriptorSize: ?*u32,
) i32;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) ?*anyopaque;

const SDDL_ADMIN_ONLY = "D:(A;;GA;;;BA)";
const SDDL_REVISION: u32 = 1;

// BP-M13: Pipe mode constants (duplicated from nids_capture.zig — should be shared later)
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
const PIPE_WAIT: u32 = 0x00000000;

// BP-M15: Internet protocol numbers (IANA assignments)
const IPPROTO_TCP: u8 = 6;

const AegisSecurityAttributes = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: i32,
};


// =================================================================
// [ PACKET CONTEXT ]
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
// [ AHO-CORASICK FAST PATTERN ENGINE ]
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

// BP176: Removed dead code (ThreatState, AtomicThreatTracker, global_attacker_tracker)
// These were file-private, never referenced, and reduced attack surface.

// =================================================================
// [ SECURE RULE SET ]
// =================================================================

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
    // BP152: Atomic reference count for safe concurrent access during hot-reload
    ref_count: std.atomic.Value(u32),
    // BP161: Per-rule atomic match counters (same length as signatures)
    match_counts: []std.atomic.Value(u64),

    pub fn retain(self: *SecureRuleSet) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *SecureRuleSet) void {
        // BP152: Only free when last reference is dropped (prevents UAF)
        if (self.ref_count.fetchSub(1, .acq_rel) == 1) {
            for (self.signatures) |sig| {
                self.allocator.free(sig.name);
                self.allocator.free(sig.fast_pattern);
                self.allocator.free(sig.match_pattern);
                self.allocator.free(sig.regex_pattern);
                self.allocator.free(sig.severity);
                // BP164: Free action field (was leaked on every reload)
                self.allocator.free(sig.action);
            }
            // BP161: Free per-rule match counters
            self.allocator.free(self.match_counts);
            self.allocator.free(self.signatures);
            self.ac_engine.deinit();
            self.allocator.destroy(self);
        }
    }

    pub fn deinit(self: *SecureRuleSet) void {
        self.release();
    }
};

// =================================================================
// [ GLOBAL STATE ]
// =================================================================

var active_ruleset: std.atomic.Value(?*SecureRuleSet) = std.atomic.Value(?*SecureRuleSet).init(null);
const MAX_CONCURRENT_CONNECTIONS: u32 = 100;
var connection_semaphore: std.Thread.Semaphore = .{ .permits = MAX_CONCURRENT_CONNECTIONS };
var active_threads: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
pub var g_analyze_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP179: Global total bytes processed counter
var g_total_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP180: Pipe connection accept counter
var g_pipe_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP194: Global forwarded (unmatched) packet counter
var g_total_forwarded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP197: Global total match counter (avoids summing per-rule every 30s)
var g_total_matches: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP206: Bridge IPC push counter (for detecting IPC failures vs matches+forwards)
var g_bridge_ipc_pushes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_start_time_ns: i64 = 0;
// BP227: Connection rejection counter (security actions, separate from errors)
var g_rejected_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// BP223: TCP port configurable via AEGIS_TCP_PORT env var (default 12345)
var AEGIS_TCP_PORT: u16 = 12345;

// BP162: Ruleset version counter (incremented on each successful reload)
var g_ruleset_version: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// BP154: Guard against concurrent rule reloads (prevents double-free)
var g_rules_loading: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// BP152: Safe ruleset acquisition with hazard-pointer pattern
fn acquireRuleset() ?*SecureRuleSet {
    while (true) {
        const rs = active_ruleset.load(.acquire) orelse return null;
        rs.retain();
        // Verify it is still the active ruleset (prevent TOCTOU race)
        if (active_ruleset.load(.acquire) == rs) {
            return rs;
        }
        // Swapped out during retain, drop our extra reference and retry
        rs.release();
    }
}

// =================================================================
// [ NAMED LIMITS & TIMEOUTS ]
// =================================================================

// BP151: Named constants for all magic numbers
const ANALYZE_MAX_PAYLOAD: usize = 65536;
const TCP_MAX_SESSION_S: u64 = 300;
const TCP_IDLE_TIMEOUT_MS: u64 = 60000;
const TCP_MAX_PACKETS: u64 = 1_000_000;
const PIPE_BUFFER_SIZE: usize = 4096;
const TCP_BUFFER_SIZE: usize = 16384;
const RULES_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
const RULES_MAX_READ_SIZE: usize = 2 * 1024 * 1024;
const RULES_MIN_PATTERN_LEN: usize = 3;

// BP158: Remaining magic number constants
const PIPE_MAX_INSTANCES: u32 = 255;
const TCP_LISTEN_BACKLOG: u31 = 128;

// BP156: Per-IP connection rate limit configuration
const RATE_LIMIT_MAX_IPS: usize = 128;
const RATE_LIMIT_WINDOW_NS: i64 = 60 * std.time.ns_per_s;
const RATE_LIMIT_MAX_CONNS: u32 = 100;

// BP166: Per-client packet rate limit (per-connection, local state, no mutex)
const PKT_RATE_LIMIT_MAX: u64 = 5000;
const PKT_RATE_WINDOW_NS: i64 = 1 * std.time.ns_per_s;

// BP170: Maximum rule count cap (prevents OOM from malicious/huge rulesets)
const RULES_MAX_COUNT: usize = 10000;

// BP171: Pipe session packet limit (prevent unbounded admin pipe sessions)
const PIPE_MAX_PACKETS: u64 = 500_000;

// BP173: Pipe session byte limit (complements packet limit)
const PIPE_MAX_BYTES: u64 = 512 * 1024 * 1024;

// BP190: Max payload bytes included in match alerts (limits IPC size + data exposure)
const ALERT_MAX_PAYLOAD_PREVIEW: usize = 256;

// BP193: Pipe read poll interval (ms) - enables shutdown checks between reads
const PIPE_READ_POLL_MS: u64 = 100;

// =================================================================
// [ RULE LOADING ]
// =================================================================

// BP-F7: reload_rules_atomic should propagate errors (was silently swallowing)
//         Old behavior: catch -> return; (success) → caller thinks rules loaded
//         New behavior: catch -> log + return err → caller knows rules failed
pub fn reload_rules_atomic(allocator: std.mem.Allocator) !void {
    // BP154: Prevent concurrent reloads (avoid double-free / corruption)
    if (g_rules_loading.swap(true, .acq_rel)) {
        std.log.warn("[ANALYZE] Rule reload already in progress, skipping", .{});
        return;
    }
    defer g_rules_loading.store(false, .release);

    const file = std.fs.cwd().openFile("Rules.json", .{}) catch |open_err| {
        std.log.warn("[ANALYZE] Cannot open Rules.json: {}", .{open_err});
        std.debug.print("\x1b[33m[ANALYZE] Cannot open Rules.json: {}\x1b[0m\n", .{open_err});
        return open_err;
    };
    defer file.close();
    const content = try file.readToEndAlloc(allocator, RULES_MAX_READ_SIZE);
    std.log.info("[ANALYZE] Rule file: {d} bytes", .{content.len});
    defer allocator.free(content);

    const TempRule = struct {
        name: []const u8,
        fast_pattern: []const u8 = "",
        match_pattern: []const u8 = "",
        regex_pattern: []const u8 = "",
        severity: []const u8 = "Alert",
        action: []const u8 = "Alert",
    };
    const TempRuleSet = struct { nids_rules: []TempRule };

    const parsed = std.json.parseFromSlice(TempRuleSet, allocator, content, .{ .ignore_unknown_fields = true }) catch |parse_err| {
        std.log.warn("[ANALYZE] Rule parse error", .{});
        std.debug.print("\x1b[31m[ANALYZE] JSON Parse Failed: {}\x1b[0m\n", .{parse_err});
        return parse_err;
    };
    defer parsed.deinit();

    var new_set = try allocator.create(SecureRuleSet);
    new_set.allocator = allocator;
    new_set.ac_engine = try AhoCorasick.init(allocator);
    // BP152: Initialize reference count to 1 (held by active_ruleset slot)
    new_set.ref_count = std.atomic.Value(u32).init(1);
    std.log.info("[ANALYZE] Pattern engine initialized", .{});

    var temp_sig_list = std.ArrayListAligned(SecureRule, 8).init(allocator);
    errdefer {
        for (temp_sig_list.items) |*sig| {
            allocator.free(sig.name);
            allocator.free(sig.fast_pattern);
            allocator.free(sig.match_pattern);
            allocator.free(sig.regex_pattern);
            allocator.free(sig.severity);
            // BP164: Free action field in error path
            allocator.free(sig.action);
        }
        std.log.warn("[ANALYZE] Rule load failed after {d} rules", .{temp_sig_list.items.len});
        temp_sig_list.deinit();
        new_set.ac_engine.deinit();
        allocator.destroy(new_set);
    }

    var skipped_count: usize = 0;
    var valid_rule_count: usize = 0;
    // BP207: StringHashMap for O(1) duplicate detection (was O(n) per rule)
    var _seen_patterns = std.StringHashMap(usize).init(allocator);
    defer _seen_patterns.deinit();
    for (parsed.value.nids_rules) |sig| {
        // BP142: Validate rule fields before processing
        if (sig.name.len == 0) {
            std.log.warn("[ANALYZE] Skipping rule with empty name", .{});
            skipped_count += 1;
            continue;
        }
        const is_valid_sev = std.mem.eql(u8, sig.severity, "Critical") or
            std.mem.eql(u8, sig.severity, "High") or
            std.mem.eql(u8, sig.severity, "Medium") or
            std.mem.eql(u8, sig.severity, "Low") or
            std.mem.eql(u8, sig.severity, "Alert");
        if (!is_valid_sev) {
            std.log.warn("[ANALYZE] Rule \"{s}\" has unknown severity: {s}", .{ sig.name, sig.severity });
        }
        const is_valid_act = std.mem.eql(u8, sig.action, "Block") or
            std.mem.eql(u8, sig.action, "Alert") or
            std.mem.eql(u8, sig.action, "Log");
        if (!is_valid_act) {
            std.log.warn("[ANALYZE] Rule \"{s}\" has unknown action: {s}", .{ sig.name, sig.action });
        }

        var active_fast_pattern: []const u8 = sig.fast_pattern;
        if (active_fast_pattern.len == 0) {
            if (sig.match_pattern.len > 0) {
                if (std.mem.indexOfAny(u8, sig.match_pattern, "|()[{\\.*+?^$")) |idx| {
                    active_fast_pattern = sig.match_pattern[0..idx];
                } else {
                    active_fast_pattern = sig.match_pattern;
                }
            } else {
                skipped_count += 1;
                continue;
            }
        }

        if (active_fast_pattern.len < RULES_MIN_PATTERN_LEN) {
            skipped_count += 1;
            continue;
        }

        // BP146: Duplicate fast_pattern detection
        // BP200: Actually skip duplicate patterns (was logging but still inserting into AC engine)
        // BP207: O(1) lookup via StringHashMap (was O(n) per rule -> O(n^2) total)
        const _dup_gop = _seen_patterns.getOrPut(active_fast_pattern) catch {
            skipped_count += 1;
            continue;
        };
        if (_dup_gop.found_existing) {
            std.log.warn("[ANALYZE] Duplicate fast_pattern in \"{s}\" (also in \"{s}\") - skipping", .{
                sig.name, temp_sig_list.items[_dup_gop.value_ptr.*].name,
            });
            skipped_count += 1;
            continue;
        }
        _dup_gop.value_ptr.* = valid_rule_count;

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
        // BP170: Cap maximum rule count to prevent OOM from malicious rulesets
        if (valid_rule_count >= RULES_MAX_COUNT) {
            std.log.warn("[ANALYZE] Rule limit reached ({d}), stopping further processing", .{RULES_MAX_COUNT});
            break;
        }
    }

    // BP111: All signatures processed
    std.log.info("[ANALYZE] All signatures processed", .{});
    // BP127: Log skipped rule count
    const total_rules = parsed.value.nids_rules.len;
    if (skipped_count > 0) {
        std.log.warn("[ANALYZE] Skipped {d}/{d} rules (empty/short patterns)", .{ skipped_count, total_rules });
    }
    // BP116: Log rule count before building failure links
    std.log.info("[ANALYZE] Built pattern engine with {d} rules", .{valid_rule_count});
    // BP203: O(n) CRC32 collision detection using HashMap (was O(n^2) pairwise)
    var crc_map = std.AutoHashMap(u32, usize).init(allocator);
    defer crc_map.deinit();
    var collision_count: usize = 0;
    for (0..temp_sig_list.items.len) |i| {
        const crc = temp_sig_list.items[i].crc32;
        const gop = crc_map.getOrPut(crc) catch continue;
        if (gop.found_existing) {
            std.log.warn("[ANALYZE] CRC32 collision: \"{s}\" and \"{s}\" share hash 0x{x}", .{
                temp_sig_list.items[gop.value_ptr.*].name,
                temp_sig_list.items[i].name,
                crc,
            });
            collision_count += 1;
        } else {
            gop.value_ptr.* = i;
        }
    }
    if (collision_count > 0) {
        std.log.warn("[ANALYZE] {d} CRC32 collision(s) detected - consider migrating to stronger hash", .{collision_count});
    }

    // BP161: Pre-allocate per-rule match counters
    var match_counts_alloc = try allocator.alloc(std.atomic.Value(u64), valid_rule_count);
    errdefer allocator.free(match_counts_alloc);
    for (0..valid_rule_count) |i| {
        match_counts_alloc[i] = std.atomic.Value(u64).init(0);
    }

    // BP167: Validate non-empty ruleset before going live
    if (valid_rule_count == 0) {
        std.log.warn("[ANALYZE] WARNING: 0 valid rules loaded - all packets will be forwarded without inspection", .{});
        std.debug.print("\x1b[33m[ANALYZE] WARNING: Empty ruleset - no detection active!\x1b[0m\n", .{});
    }

    // BP195: Time the failure link construction (can be slow for large rule sets)
    const _bp195_bfl_start = std.time.nanoTimestamp();
    try new_set.ac_engine.buildFailureLinks();
    const _bp195_bfl_ms = @divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - _bp195_bfl_start), 1_000_000);
    std.log.info("[ANALYZE] Failure links built in {d}ms", .{_bp195_bfl_ms});
    new_set.signatures = try temp_sig_list.toOwnedSlice();
    new_set.match_counts = match_counts_alloc;
    const old_set = active_ruleset.swap(new_set, .release);
    if (old_set) |old| {
        // BP152: Release reference (will free only when all readers are done)
        old.release();
    }

    // BP162: Increment ruleset version on successful reload
    _ = g_ruleset_version.fetchAdd(1, .release);
    std.debug.print("\x1b[32m[ANALYZE] Loaded {d} secure rules (v{d})\x1b[0m\n", .{ valid_rule_count, g_ruleset_version.load(.acquire) });
    // BP229: Rule reload success via std.log.info (release-build visible)
    std.log.info("[ANALYZE] Loaded {d} rules (v{d})", .{ valid_rule_count, g_ruleset_version.load(.acquire) });
}

// =================================================================
// [ BRIDGE HELPERS - delegate to bridge_init ]
// =================================================================

/// Push Tier-1 match event to C++ Bridge via bridge_init
fn pushTier1Match(
    ctx: PacketContext,
    rule_id: u32,
    severity: u32,
    payload_len: u32,
) void {
    const event: bridge_init.AegisIpcEvent = .{
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
        .timestamp = @as(u64, @bitCast(std.time.milliTimestamp())),
        .source_pid = 0,
        .defcon_impact = 4,
    };
    // BP206: Count bridge IPC pushes for operational visibility
    _ = g_bridge_ipc_pushes.fetchAdd(1, .relaxed);
    const push_rc = bridge_init.pushEvent(&event);
    if (push_rc != 0) {
        std.log.warn("[BRIDGE] pushEvent failed (rc={d})", .{push_rc});
    }
}

/// Push forwarded (unmatched) event to C++ Bridge
fn pushForwardedEvent(
    ctx: PacketContext,
    payload_len: u32,
) void {
    const event: bridge_init.AegisIpcEvent = .{
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
        .timestamp = @as(u64, @bitCast(std.time.milliTimestamp())),
        .source_pid = 0,
        .defcon_impact = 5,
    };
    // BP206: Count bridge IPC pushes for operational visibility
    _ = g_bridge_ipc_pushes.fetchAdd(1, .relaxed);
    const push_rc = bridge_init.pushEvent(&event);
    if (push_rc != 0) {
        std.log.warn("[BRIDGE] pushEvent failed (rc={d})", .{push_rc});
    }
}

// =================================================================
// [ 3-TIER FAST THREAT ANALYSIS ENGINE ]
// =================================================================

pub fn inspect_packet(data: []const u8, ctx: PacketContext) !bool {
    // Rust Memory Safety Shield (via bridge_init)
    // BP196: Log payload safety validation failures for forensics
    if (!bridge_init.validatePayloadSafety(data.ptr, data.len)) {
        // BP217: Skip inspection but don't terminate connection (return true = continue session)
        std.log.warn("[ANALYZE] Payload safety check failed, skipping inspection ({}B from {}:{d})", .{
            data.len,
            if (ctx.is_pipe) "PIPE" else "TCP",
            ctx.source_port,
        });
        return true;
    }

    // BP21: Payload size sanity check
    if (data.len < 1) return true;
    if (data.len > ANALYZE_MAX_PAYLOAD) {
        std.log.warn("[ANALYZE] Payload {d} exceeds limit (max={d}) - skipping deep analysis", .{data.len, ANALYZE_MAX_PAYLOAD});
        std.debug.print("[WARN] Payload size {d} exceeds limit (max={d}B) - skipping deep analysis\n", .{data.len, ANALYZE_MAX_PAYLOAD});
        return true;
    }

    // BP152: Safe ruleset acquisition with reference counting
    // BP225: Log when ruleset is unavailable (diagnostic for unexpected null)
    const current_ruleset = acquireRuleset() orelse {
        std.log.warn("[ANALYZE] Ruleset unavailable, forwarding without inspection", .{});
        return true;
    };
    defer current_ruleset.release();
    const allocator = current_ruleset.allocator;

    var curr: usize = 0;
    var final_matched_rule: ?*const SecureRule = null;
    var matched_rule_idx: usize = 0;

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
                    matched_rule_idx = idx;
                    break;
                }
            }
            if (final_matched_rule != null) break;
            temp = current_ruleset.ac_engine.nodes.items[temp].fail;
        }
        if (final_matched_rule != null) break;
    }

    if (final_matched_rule) |rule| {
        // BP161: Increment per-rule match counter
        if (matched_rule_idx < current_ruleset.match_counts.len) {
            _ = current_ruleset.match_counts[matched_rule_idx].fetchAdd(1, .relaxed);
        }
        // BP197: Increment global match counter
        _ = g_total_matches.fetchAdd(1, .relaxed);
        // Alert to brain via UDP (bridge_init)
        const alert = .{
            .timestamp = std.time.timestamp(),
            .attack_type = rule.name,
            .policy = rule.action,
            .reason = "Tier-1 Fast Pattern Match",
            .source = if (ctx.is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            // BP190: Truncate payload in match alerts to limit IPC size and data exposure
            .raw_payload = if (data.len > ALERT_MAX_PAYLOAD_PREVIEW) data[0..ALERT_MAX_PAYLOAD_PREVIEW] else data,
            .source_ip = ctx.source_ip,
            .dest_ip = ctx.dest_ip,
            .source_port = ctx.source_port,
            .dest_port = ctx.dest_port,
            .protocol = ctx.protocol,
        };
        bridge_init.sendToBrain(allocator, @TypeOf(alert), alert);

        const severity_val: u32 = sev: {
            if (std.mem.eql(u8, rule.severity, "Critical")) break :sev 3;
            if (std.mem.eql(u8, rule.severity, "High")) break :sev 2;
            if (std.mem.eql(u8, rule.severity, "Medium")) break :sev 1;
            break :sev 0;
        };
        pushTier1Match(ctx, rule.crc32, severity_val, std.math.cast(u32, data.len) orelse ANALYZE_MAX_PAYLOAD);
        std.log.info("[MATCH] {s} (severity={s}, action={s}, payload={d}B)", .{
            rule.name, rule.severity, rule.action, data.len,
        });

        if (std.mem.eql(u8, rule.action, "Block")) {
            std.debug.print("\x1b[31;1m[ANALYZE] !!! BLOCK !!! {s}\x1b[0m\n", .{rule.name});
            // BP204: BLOCK action must be visible in release builds (debug.print compiled out)
            // BP208: Convert network byte order to host for correct IP display
            const _log_ip = std.mem.bigToNative(u32, ctx.source_ip);
            std.log.warn("[BLOCK] Rule matched: {s} (severity={s}) from {d}.{d}.{d}.{d}:{d}", .{
                rule.name, rule.severity,
                (_log_ip >> 24) & 0xFF, (_log_ip >> 16) & 0xFF,
                (_log_ip >> 8) & 0xFF, _log_ip & 0xFF, ctx.source_port,
            });
            return false;
        }

        return true;
    } else {
        // BP139: Log forwarded (unmatched) packets (debug-level, compiled out in release)
        std.log.debug("[FORWARD] No Tier-1 match, forwarding {d}B to brain", .{data.len});
        // Forward to brain for deep inspection
        const forward_msg = .{
            .timestamp = std.time.timestamp(),
            .attack_type = "Unmatched: Deep Inspection Required",
            .policy = "Pending",
            .reason = "Forwarded: No Tier-1 Match",
            .source = if (ctx.is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            // BP212: Truncate forward payload to limit IPC size and data exposure
            .raw_payload = if (data.len > ALERT_MAX_PAYLOAD_PREVIEW) data[0..ALERT_MAX_PAYLOAD_PREVIEW] else data,
            .source_ip = ctx.source_ip,
            .dest_ip = ctx.dest_ip,
            .source_port = ctx.source_port,
            .dest_port = ctx.dest_port,
            .protocol = ctx.protocol,
        };
        bridge_init.sendToBrain(allocator, @TypeOf(forward_msg), forward_msg);
        pushForwardedEvent(ctx, std.math.cast(u32, data.len) orelse ANALYZE_MAX_PAYLOAD);
        // BP194: Track forwarded packets for operational visibility
        _ = g_total_forwarded.fetchAdd(1, .relaxed);

        return true;
    }
}

// =================================================================
// [ NAMED PIPE LISTENER ]
// =================================================================

fn handle_pipe_client(hPipe: win.HANDLE, allocator: std.mem.Allocator) void {
    const start_ns = std.time.nanoTimestamp();
    std.debug.print("  [PIPE] Session started\n", .{});
    // BP112: Pipe client connected log
    std.log.info("[PIPE] Admin client connected via named pipe", .{});

    defer {
        const dur_s: u64 = @as(u64, @intCast(@max(0, std.time.nanoTimestamp() - start_ns))) / std.time.ns_per_s;
        std.debug.print("[PIPE] Session closed: dur={d}s\n", .{dur_s});
    }
    defer {
        _ = DisconnectNamedPipe(hPipe);
        win.CloseHandle(hPipe);
    }
    defer connection_semaphore.post();
    // BP188: Release ordering ensures handler writes visible before decrement
    defer _ = active_threads.fetchSub(1, .release);
    // BP188: Acquire ordering ensures handler sees parent's prior state
    _ = active_threads.fetchAdd(1, .acquire);

    const ctx = PacketContext{
        .is_pipe = true,
        .layer_id = 3,
    };

    var buf: [PIPE_BUFFER_SIZE]u8 = undefined;
    // BP171: Pipe session packet counter
    var pipe_pkt_count: u64 = 0;
    // BP173: Pipe session byte counter
    var pipe_byte_count: u64 = 0;
    // BP182: Pipe session stats log (defer executes before session close log)
    defer {
        std.log.info("[PIPE] Session stats: {d} packets, {d} bytes", .{ pipe_pkt_count, pipe_byte_count });
    }
    while (true) {
        // BP216: Check both shutdown flags (CTRL+C sets g_shutdown_requested, bridge sets g_shutdown)
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        if (g_shutdown_requested.load(.acquire)) break;
        // BP193: PeekNamedPipe polling for shutdown-responsive reads
        var _data_ready = false;
        while (!_data_ready) {
            if (bridge_init.g_shutdown.load(.seq_cst)) break;
            // BP220: Check CTRL+C flag in inner poll loop for responsive shutdown
            if (g_shutdown_requested.load(.acquire)) break;
            var _avail: u32 = 0;
            if (PeekNamedPipe(hPipe, null, 0, null, &_avail, null) == 0) break;
            if (_avail > 0) {
                _data_ready = true;
            } else {
                std.time.sleep(PIPE_READ_POLL_MS * std.time.ns_per_ms);
            }
        }
        if (!_data_ready) break;
        var bytes_read: u32 = 0;
        const success = ReadFile(hPipe, &buf, buf.len, &bytes_read, null);
        if (success == 0 or bytes_read == 0) break;
        pipe_pkt_count += 1;
        pipe_byte_count += bytes_read;
        // BP179: Track total bytes processed (pipe path)
        _ = g_total_bytes.fetchAdd(bytes_read, .relaxed);
        // BP171: Enforce pipe session packet limit
        if (pipe_pkt_count > PIPE_MAX_PACKETS) {
            std.log.warn("[PIPE] Session packet limit ({d}) reached, closing", .{PIPE_MAX_PACKETS});
            break;
        }
        // BP173: Enforce pipe session byte limit
        if (pipe_byte_count > PIPE_MAX_BYTES) {
            std.log.warn("[PIPE] Session byte limit ({}MB) reached, closing", .{PIPE_MAX_BYTES / (1024 * 1024)});
            break;
        }
        const is_safe = inspect_packet(buf[0..bytes_read], ctx) catch |analyze_err| blk: {
            std.log.warn("[PIPE] inspect_packet error: {}", .{analyze_err});
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            break :blk true;
        };
        // BP157: Zeroize buffer to reduce plaintext exposure in memory
        for (buf[0..bytes_read]) |*b| b.* = 0;
        if (!is_safe) break;
    }
    // BP111: Session duration log
    const _bp111_dur_ms = @divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - start_ns), 1_000_000);
    std.log.info("[PIPE] Session complete: {d}ms", .{_bp111_dur_ms});
}

fn pipe_listener(allocator: std.mem.Allocator) !void {
    std.log.info("[PIPE-LISTEN] Pipe listener started", .{});
    // BP19: Setup admin-only security descriptor (once, before loop)
    var pipe_sd: ?*anyopaque = null;
    var sec_attr = AegisSecurityAttributes{
        .nLength = @sizeOf(AegisSecurityAttributes),
        .lpSecurityDescriptor = null,
        .bInheritHandle = 0,
    };
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
        SDDL_ADMIN_ONLY, SDDL_REVISION, &pipe_sd, null,
    ) != 0) {
        sec_attr.lpSecurityDescriptor = pipe_sd;
        std.log.info("[PIPE] ACL: Admin-only (SDDL)", .{});
        std.debug.print("[PIPE_LISTENER] ACL: Admin-only (SDDL)\n", .{});
    } else {
        // BP192: Release-visible warning for security misconfiguration
        std.log.warn("[PIPE] Failed to set admin-only ACL - pipe may accept non-admin connections", .{});
    }
    defer if (pipe_sd) |sd| { _ = LocalFree(sd); };
    const pipe_name = "\\\\.\\pipe\\aegis_nids";
    // BP113: Pipe listener ready log
    std.debug.print("[PIPE] Listener ready, waiting for admin connections.\n", .{});
    // BP155: Exponential backoff for pipe creation retries
    var pipe_retry_ns: u64 = 1 * std.time.ns_per_s;
    const pipe_max_backoff_ns: u64 = 30 * std.time.ns_per_s;
    while (!g_shutdown_requested.load(.acquire)) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        // BP-M13: PIPE_WAIT preserves byte-stream mode (matches admin client expectations)
        const hPipe = CreateNamedPipeA(pipe_name, PIPE_ACCESS_DUPLEX, PIPE_WAIT, PIPE_MAX_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, @ptrCast(&sec_attr));
        if (hPipe == win.INVALID_HANDLE_VALUE) {
            // BP133: Log Windows error code on CreateNamedPipeA failure
            const pipe_err = win.kernel32.GetLastError();
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            const backoff_s = @divTrunc(pipe_retry_ns, std.time.ns_per_s);
            std.debug.print("[PIPE_LISTENER] CreateNamedPipeA failed (err={}), retrying in {d}s\n", .{pipe_err, backoff_s});
            // BP209: Pipe creation failure visible in release builds
            std.log.warn("[PIPE] CreateNamedPipeA failed (err={}), retrying in {d}s", .{pipe_err, backoff_s});
            // BP155: Exponential backoff (1s -> 2s -> 4s -> ... -> 30s max)
            std.time.sleep(pipe_retry_ns);
            pipe_retry_ns = @min(pipe_retry_ns * 2, pipe_max_backoff_ns);
            continue;
        }
        // BP155: Reset backoff on successful pipe creation
        pipe_retry_ns = 1 * std.time.ns_per_s;

        const connected = ConnectNamedPipe(hPipe, null);
        const err = win.kernel32.GetLastError();

        if (connected != 0 or err == win.Win32Error.PIPE_CONNECTED) {
            // BP187: Warn when connection limit is approaching
            // BP189: Acquire for fresh value in warning check
            const _pipe_active = active_threads.load(.acquire);
            if (_pipe_active >= MAX_CONCURRENT_CONNECTIONS * 9 / 10) {
                std.log.warn("[SEMAPHORE] Pipe: connection limit approaching ({d}/{} active)", .{ _pipe_active, MAX_CONCURRENT_CONNECTIONS });
            }
            // BP205: Use tryWait to prevent blocking during shutdown with full semaphore
            if (!connection_semaphore.tryWait()) {
                std.log.warn("[SEMAPHORE] Pipe: connection limit reached ({d}), rejecting client", .{MAX_CONCURRENT_CONNECTIONS});
                _ = DisconnectNamedPipe(hPipe);
                win.CloseHandle(hPipe);
                _ = g_analyze_errors.fetchAdd(1, .relaxed);
                _ = g_rejected_connections.fetchAdd(1, .relaxed);
                continue;
            }
            // BP189: Relaxed for pure counter (ordering not needed for increment)
            _ = g_total_connections.fetchAdd(1, .relaxed);
            // BP180: Track pipe connections
            _ = g_pipe_connections.fetchAdd(1, .relaxed);
            std.debug.print("[PIPE] Admin client connected via named pipe\n", .{});
            std.log.info("[PIPE-LISTEN] Spawned handler thread", .{});
            std.log.info("[PIPE] Handling pipe client", .{});
            const t = std.Thread.spawn(.{}, handle_pipe_client, .{ hPipe, allocator }) catch |err| {
                std.debug.print("\x1b[33m[ANALYZE] Failed to spawn handle_pipe_client: {}\x1b[0m\n", .{err});
                // BP215: Thread spawn failure visible in release (resource exhaustion = potential DoS)
                std.log.warn("[PIPE] Failed to spawn handler thread: {}", .{err});
                _ = g_analyze_errors.fetchAdd(1, .relaxed);
                _ = DisconnectNamedPipe(hPipe);
                win.CloseHandle(hPipe);
                connection_semaphore.post();
                continue;
            };
            t.detach();
        } else {
            // BP123: Log rejected non-admin pipe connection
            std.debug.print("[PIPE-LISTEN] Rejected non-admin pipe connection (err={})\n", .{err});
            // BP209: Security event visible in release builds
            std.log.warn("[PIPE] Rejected non-admin pipe connection (err={})", .{err});
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            _ = g_rejected_connections.fetchAdd(1, .relaxed);
            _ = DisconnectNamedPipe(hPipe);
            win.CloseHandle(hPipe);
        }
    }
    std.debug.print("[PIPE] Listener shut down gracefully.\n", .{});
    std.log.info("[PIPE] Pipe listener shutting down", .{});
}

// =================================================================
// [ TCP LISTENER ]
// =================================================================

fn handle_tcp_client(stream: net.Stream, remote_addr: net.Address, allocator: std.mem.Allocator) void {
    defer stream.close();
    defer connection_semaphore.post();
    // BP188: Release ordering ensures handler writes visible before decrement
    defer _ = active_threads.fetchSub(1, .release);
    // BP188: Acquire ordering ensures handler sees parent's prior state
    _ = active_threads.fetchAdd(1, .acquire);

    const src_ip_net: u32 = blk: {
        const sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&remote_addr.any)));
        break :blk sa.addr;
    };
    // BP208: Host byte order for log display (network byte order reserved for bridge IPC)
    const src_ip = std.mem.bigToNative(u32, src_ip_net);
    const src_port: u16 = blk: {
        const sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&remote_addr.any)));
        break :blk std.mem.bigToNative(u16, sa.port);
    };

    // BP112: TCP client connected log
    std.debug.print("[TCP] Opened: {d}.{d}.{d}.{d}:{d}\n", .{
        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
    });
    // BP210: Connection tracking visible in release builds
    std.log.info("[TCP] Opened: {d}.{d}.{d}.{d}:{d}", .{
        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
    });

    const start_ns = std.time.nanoTimestamp();
    var _bp92_ttfb_ns: i64 = 0;
    var _bp94_last_act_ns: i64 = std.time.nanoTimestamp();
    var bytes_read: u64 = 0;
    var packet_count: u64 = 0;
    var peak_buf: u64 = 0;
    // BP166: Per-client packet rate tracking (local state, no mutex needed)
    var pkt_rate_count: u64 = 0;
    var pkt_rate_window_ns: i64 = std.time.nanoTimestamp();

    defer {
        const dur_s: u64 = @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp() - start_ns))) / std.time.ns_per_s;
        std.debug.print("[TCP] Closed: {d}.{d}.{d}.{d}:{d} dur={d}s\n", .{
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port, dur_s,
        });
        // BP210: Connection close visible in release builds
        std.log.info("[TCP] Closed: {d}.{d}.{d}.{d}:{d} dur={d}s", .{
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port, dur_s,
        });
        std.debug.print("    Bytes: {d}\n", .{bytes_read});
        const bps: u64 = if (dur_s > 0) (bytes_read / dur_s) else 0;
        std.debug.print("    Avg throughput: {d} B/s\n", .{bps});
        std.debug.print("    Packets: {d}\n", .{packet_count});
        // BP86: Shutdown reason indicator
        if (bridge_init.g_shutdown.load(.seq_cst)) {
            std.debug.print("    Reason: shutdown signal\n", .{});
        }
        // BP88: Peak buffer log
        std.debug.print("    Peak buffer: {d} bytes\n", .{peak_buf});
        // BP88: Session stats (only meaningful after loop)
        if (packet_count > 0) {
            const _avg_pkt = bytes_read / packet_count;
            std.log.info("[TCP] Avg packet: {d} bytes", .{_avg_pkt});
        }
        if (peak_buf > 0) {
            // BP169: Use correct buffer size constant (was 65535, actual is TCP_BUFFER_SIZE)
            const _buf_pct = @divTrunc(peak_buf * 100, TCP_BUFFER_SIZE);
            std.log.info("[TCP] Buffer peak: {d}/{} ({d}%)", .{ peak_buf, TCP_BUFFER_SIZE, _buf_pct });
        }
        if (packet_count == 0) {
            std.log.warn("[TCP] Zero-packet connection from {d}.{d}.{d}.{d}", .{
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF,
            });
        }
    }

    const ctx = PacketContext{
        .source_ip = src_ip_net,
        .source_port = src_port,
        .dest_port = AEGIS_TCP_PORT,
        .protocol = IPPROTO_TCP, // BP-M15: named constant (was magic 6)
        .layer_id = 0,
        .is_pipe = false,
    };

    var buf: [TCP_BUFFER_SIZE]u8 = undefined;
    while (true) {
        // BP216: Check both shutdown flags for responsive CTRL+C shutdown
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        if (g_shutdown_requested.load(.acquire)) break;
        // BP94: Idle timeout check
        {
            const _idle_ms = @divTrunc(std.time.nanoTimestamp() - _bp94_last_act_ns, 1_000_000);
            if (_idle_ms > TCP_IDLE_TIMEOUT_MS) {
                std.log.warn("[TCP] Idle {d}.{d}.{d}.{d}:{d} for {d}ms, closing", .{
                    (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                    (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port, _idle_ms,
                });
                // BP168: Actually close idle connections (was warn-only, wasting semaphore permit)
                break;
            }
        }
        const len = stream.read(&buf) catch {
            std.debug.print("  [TCP] Read error, closing connection\n", .{});
            // BP209: TCP read error visible in release builds
            std.log.warn("[TCP] Read error, closing connection", .{});
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            break;
        };
        _bp94_last_act_ns = std.time.nanoTimestamp();
        if (len == 0) {
            std.debug.print("  [TCP] Connection closed by peer (EOF)\n", .{});
            break;
        }
        // BP88: Track peak buffer usage
        if (len > peak_buf) peak_buf = len;
        // BP92: TTFB tracking
        if (_bp92_ttfb_ns == 0) {
            _bp92_ttfb_ns = std.time.nanoTimestamp();
            const _bp92_ttfb_ms = @divTrunc(_bp92_ttfb_ns - start_ns, 1_000_000);
            std.log.info("[TCP] TTFB {d}ms from {d}.{d}.{d}.{d}", .{
                _bp92_ttfb_ms,
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF,
            });
        }
        const elapsed_s: u64 = @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp() - start_ns))) / std.time.ns_per_s;
        if (elapsed_s > TCP_MAX_SESSION_S) {
            std.debug.print("  [TCP] Max duration ({d}s) reached, closing\n", .{TCP_MAX_SESSION_S});
            // BP209: Session limit visible in release builds
            std.log.warn("[TCP] Max session duration ({d}s) reached", .{TCP_MAX_SESSION_S});
            break;
        }
        // BP172: Defense-in-depth oversized read (threshold matches actual buffer capacity)
        if (len > TCP_BUFFER_SIZE) {
            std.debug.print("  [TCP] Oversized read: {d} bytes (buf={d}), closing\n", .{ len, TCP_BUFFER_SIZE });
            // BP209: Defense-in-depth event visible in release builds
            std.log.warn("[TCP] Oversized read: {d}B (buf={d}), closing", .{ len, TCP_BUFFER_SIZE });
            break;
        }
        bytes_read += len;
        packet_count += 1;
        // BP179: Track total bytes processed
        _ = g_total_bytes.fetchAdd(len, .relaxed);
        // BP166: Per-client packet rate limiting
        pkt_rate_count += 1;
        {
            const _now_ns = std.time.nanoTimestamp();
            if (_now_ns - pkt_rate_window_ns >= PKT_RATE_WINDOW_NS) {
                if (pkt_rate_count > PKT_RATE_LIMIT_MAX) {
                    std.log.warn("[TCP] Packet rate exceeded: {d} pkt/s from {d}.{d}.{d}.{d}:{d}", .{
                        pkt_rate_count,
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                    });
                    break;
                }
                pkt_rate_count = 0;
                pkt_rate_window_ns = _now_ns;
            }
        }
        // BP136: Periodic packet count log for long-lived connections
        if (packet_count % 1000 == 0) {
            std.log.info("[TCP] {d}.{d}.{d}.{d}:{d}: {d} packets, {d} bytes", .{
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                packet_count, bytes_read,
            });
        }
        if (packet_count > TCP_MAX_PACKETS) {
            std.debug.print("  [TCP] Max packets ({d}) reached\n", .{TCP_MAX_PACKETS});
            // BP209: Packet limit visible in release builds
            std.log.warn("[TCP] Max packets ({d}) reached", .{TCP_MAX_PACKETS});
            break;
        }
        const is_safe = inspect_packet(buf[0..len], ctx) catch |analyze_err| blk: {
            std.log.warn("[TCP] inspect_packet error: {}", .{analyze_err});
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            break :blk true;
        };
        // BP157: Zeroize buffer to reduce plaintext exposure in memory
        for (buf[0..len]) |*b| b.* = 0;
        if (!is_safe) {
            // BP174: Consistent relaxed ordering (error counter needs no synchronization)
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            std.debug.print("  [TCP] Unsafe packet detected, closing connection\n", .{});
            // BP204: Log BLOCK events via std.log for release build visibility
            std.log.warn("[BLOCK] Unsafe packet from {d}.{d}.{d}.{d}:{d}, connection terminated", .{
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
            });
            break;
        }
    }
    const _bp110_dur_ms = @divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - start_ns), 1_000_000);
    std.log.info("[TCP] Session complete: {d}ms", .{_bp110_dur_ms});
}

// BP156: Per-IP connection rate limiting (single-threaded accept loop, no mutex needed)
const IpRateEntry = struct {
    ip: u32,
    count: u32,
    window_start_ns: i64,
};

const ip_rate_zero: IpRateEntry = .{ .ip = 0, .count = 0, .window_start_ns = 0 };
var ip_rate_table: [RATE_LIMIT_MAX_IPS]IpRateEntry = [_]IpRateEntry{ip_rate_zero} ** RATE_LIMIT_MAX_IPS;

fn checkIpRateLimit(raw_addr: u32) bool {
    const ip = std.mem.bigToNative(u32, raw_addr);
    const now = std.time.nanoTimestamp();
    var free_slot: ?usize = null;
    for (0..RATE_LIMIT_MAX_IPS) |i| {
        if (ip_rate_table[i].count > 0) {
            // BP186: Clean expired entries (opportunistic, reclaims slots for other IPs)
            if (now - ip_rate_table[i].window_start_ns > RATE_LIMIT_WINDOW_NS) {
                ip_rate_table[i] = ip_rate_zero;
                continue;
            }
            if (ip_rate_table[i].ip == ip) {
                ip_rate_table[i].count += 1;
                return ip_rate_table[i].count <= RATE_LIMIT_MAX_CONNS;
            }
        }
        if (ip_rate_table[i].count == 0 and free_slot == null) {
            free_slot = i;
        }
    }
    if (free_slot) |slot| {
        ip_rate_table[slot] = .{ .ip = ip, .count = 1, .window_start_ns = now };
        return true;
    }
    // BP191: Log when rate limit table is exhausted (fail-open security decision)
    std.log.warn("[RATELIMIT] IP table full ({d} entries), fail-open for new IP", .{RATE_LIMIT_MAX_IPS});
    return true; // Table full, fail-open
}

// BP153: TCP source IP allowlist -- only allow loopback and RFC1918 private ranges
fn isAllowedTcpSource(addr: net.Address) bool {
    // BP160: Reject non-IPv4 (IPv6 cast to sockaddr.in reads garbage bytes)
    if (addr.any.family != std.posix.AF.INET) return false;
    const sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
    // Convert from network byte order (big-endian) to host byte order
    const ip = std.mem.bigToNative(u32, sa.addr);
    const a = (ip >> 24) & 0xFF;
    const b = (ip >> 16) & 0xFF;
    // 127.0.0.0/8 (loopback)
    if (a == 127) return true;
    // 10.0.0.0/8 (RFC1918 Class A)
    if (a == 10) return true;
    // 172.16.0.0/12 (RFC1918 Class B)
    if (a == 172 and b >= 16 and b <= 31) return true;
    // 192.168.0.0/16 (RFC1918 Class C)
    if (a == 192 and b == 168) return true;
    // 169.254.0.0/16 (link-local)
    if (a == 169 and b == 254) return true;
    return false;
}

fn tcp_listener(allocator: std.mem.Allocator) !void {
    std.log.info("[TCP-LISTEN] Listener initialized", .{});
    // BP80: Listener startup log
    std.debug.print("[TCP-Listener] Started, accepting connections\n", .{});
    var addr = net.Address.parseIp4("0.0.0.0", AEGIS_TCP_PORT) catch return;
    // BP158: Explicit listen backlog
    var server = addr.listen(.{ .reuse_address = true, .backlog = TCP_LISTEN_BACKLOG }) catch |err| {
        std.debug.print("[TCP] Listen failed: {} - TCP listener not started\n", .{err});
        // BP218: TCP listen failure visible in release builds
        std.log.err("[TCP] Listen failed: {} - TCP listener not started", .{err});
        return;
    };
    // BP114: TCP listener ready log
    std.log.info("[TCP] Listening on 0.0.0.0:{d}", .{AEGIS_TCP_PORT});
    std.debug.print("[TCP] Listening on 0.0.0.0:{d}\n", .{AEGIS_TCP_PORT});
    defer server.deinit();

    var _bp93_accept_count: u64 = 0;
    while (!g_shutdown_requested.load(.acquire)) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const conn = server.accept() catch |err| {
            std.log.warn("[TCP] Accept error: {}", .{err});
            continue;
        };
        // BP153: Reject connections from non-private/non-loopback sources
        if (!isAllowedTcpSource(conn.address)) {
            std.log.warn("[TCP] Rejected non-private source: {}", .{conn.address});
            conn.stream.close();
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            _ = g_rejected_connections.fetchAdd(1, .relaxed);
            continue;
        }
        // BP156: Per-IP connection rate limiting
        const conn_sa = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&conn.address.any)));
        if (!checkIpRateLimit(conn_sa.addr)) {
            std.log.warn("[TCP] Rate-limited source: {}", .{conn.address});
            conn.stream.close();
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            _ = g_rejected_connections.fetchAdd(1, .relaxed);
            continue;
        }
        // BP187: Warn when connection limit is approaching
        // BP189: Acquire for fresh value in warning check
        const _tcp_active = active_threads.load(.acquire);
        if (_tcp_active >= MAX_CONCURRENT_CONNECTIONS * 9 / 10) {
            std.log.warn("[SEMAPHORE] TCP: connection limit approaching ({d}/{} active)", .{ _tcp_active, MAX_CONCURRENT_CONNECTIONS });
        }
        // BP205: Use tryWait to prevent blocking during shutdown with full semaphore
        if (!connection_semaphore.tryWait()) {
            std.log.warn("[SEMAPHORE] TCP: connection limit reached ({d}), rejecting {}", .{ MAX_CONCURRENT_CONNECTIONS, conn.address });
            conn.stream.close();
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            _ = g_rejected_connections.fetchAdd(1, .relaxed);
            continue;
        }
        // BP189: Relaxed for pure counter
        _ = g_total_connections.fetchAdd(1, .relaxed);
        _bp93_accept_count += 1;
        if (_bp93_accept_count % 100 == 0) {
            std.log.info("[TCP-LISTEN] Total accepted: {d} connections", .{_bp93_accept_count});
        }
        const t = std.Thread.spawn(.{}, handle_tcp_client, .{ conn.stream, conn.address, allocator }) catch |err| {
            std.debug.print("\x1b[33m[ANALYZE] Failed to spawn handle_tcp_client: {}\x1b[0m\n", .{err});
            // BP215: Thread spawn failure visible in release (resource exhaustion = potential DoS)
            std.log.warn("[TCP] Failed to spawn handler thread: {}", .{err});
            _ = g_analyze_errors.fetchAdd(1, .relaxed);
            conn.stream.close();
            connection_semaphore.post();
            continue;
        };
        t.detach();
    }
    // BP189: Acquire for visibility of handler final state at shutdown
    const _drain_active = active_threads.load(.acquire);
    std.log.info("[TCP-LISTEN] Accept loop ended, {d} connections still active", .{_drain_active});
    std.debug.print("[TCP] Listener shut down gracefully.\n", .{});
    std.log.info("[TCP] TCP listener shutting down", .{});
}

// =================================================================
// [ BRIDGE STATUS REPORTER ]
// =================================================================

fn bridgeStatusReporter() void {
    // Register CTRL+C handler for graceful shutdown
    while (true) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        // BP175: Also check g_shutdown_requested (CTRL+C sets this, not g_shutdown)
        if (g_shutdown_requested.load(.acquire)) break;
        std.time.sleep(30 * std.time.ns_per_s);
        std.debug.print("\n--- Status Report ---\n", .{});
        bridge_init.printStatus();
        // BP89: Epoch timestamp for log correlation
        const cycle_ts = std.time.timestamp();
        std.debug.print("  Timestamp: {d}s (epoch)\n", .{cycle_ts});
        std.debug.print("  Active threads: {d}  |  Analyze errors: {d}\n", .{
            // BP189: Acquire for visibility of handler state
            active_threads.load(.acquire),
            // BP174: Consistent relaxed ordering for error counter reads
            g_analyze_errors.load(.relaxed),
        });
        std.debug.print("  Total connections served: {d}\n", .{g_total_connections.load(.acquire)});
        const up_s: u64 = @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp() - g_start_time_ns))) / std.time.ns_per_s;
        std.debug.print("  Uptime: {d}m {d}s\n", .{up_s / 60, up_s % 60});
        // BP179: Report total bytes processed
        std.debug.print("  Total bytes processed: {d}\n", .{g_total_bytes.load(.relaxed)});
        // BP180: Report pipe connection count
        std.debug.print("  Pipe connections: {d}\n", .{g_pipe_connections.load(.relaxed)});
        // BP194: Report forwarded packet count
        std.debug.print("  Forwarded (unmatched): {d}\n", .{g_total_forwarded.load(.relaxed)});
        // BP206: Report bridge IPC push count
        std.debug.print("  Bridge IPC pushes: {d}\n", .{g_bridge_ipc_pushes.load(.relaxed)});
        // BP198: Detection efficiency metric
        const _m = g_total_matches.load(.relaxed);
        const _f = g_total_forwarded.load(.relaxed);
        const _det_rate: u64 = if (_m + _f > 0) _m * 100 / (_m + _f) else 0;
        std.debug.print("  Detection rate: {d}% ({d} matched / {d} total inspected)\n", .{_det_rate, _m, _m + _f});
        // BP183: Throughput metric
        const _total_b: u64 = g_total_bytes.load(.relaxed);
        const _kb_min: u64 = if (up_s > 0) (_total_b / 1024) * 60 / up_s else 0;
        std.debug.print("  Throughput: ~{d} KB/min\n", .{_kb_min});
        if (bridge_init.g_shutdown.load(.seq_cst)) {
            std.debug.print("  Status: SHUTTING DOWN\n", .{});
        } else {
            std.debug.print("  Status: ACTIVE\n", .{});
        }
        // BP91: Error rate and connection rate
        // BP174: Consistent relaxed ordering for error counter reads
        const errs: u64 = @intCast(g_analyze_errors.load(.relaxed));
        const err_per_min: u64 = if (up_s > 0) errs * 60 / up_s else 0;
        std.debug.print("  Error rate: ~{d} errors/min\n", .{err_per_min});
        const conn_per_min: u64 = if (up_s > 0) @intCast(g_total_connections.load(.acquire)) * 60 / up_s else 0;
        std.debug.print("  Conn rate: ~{d}/min\n", .{conn_per_min});
        // BP91: Total errors in periodic status
        std.debug.print("  Total errors: {d}\n", .{g_analyze_errors.load(.relaxed)});
        // BP227: Report security rejections separately from errors
        std.debug.print("  Security rejections: {d}\n", .{g_rejected_connections.load(.relaxed)});
        // BP165: Safe ruleset access via acquireRuleset (prevents UAF during reload)
        const rs165 = acquireRuleset();
        if (rs165) |rs| {
            defer rs.release();
            // BP197: Use global counter instead of summing per-rule (O(1) vs O(n))
            std.debug.print("  Rule matches: {d} (v{d})\n", .{ g_total_matches.load(.relaxed), g_ruleset_version.load(.acquire) });
            // BP181: Report AC engine size (memory usage proxy)
            std.debug.print("  AC engine nodes: {d}\n", .{rs.ac_engine.nodes.items.len});
            // BP199: Report top-5 matched rules for operational visibility
            var _reported: [5]usize = [_]usize{std.math.maxInt(usize)} ** 5;
            for (0..5) |rank| {
                var _bi: usize = 0;
                var _bc: u64 = 0;
                for (rs.match_counts, 0..) |*mc, i| {
                    var _skip = false;
                    for (0..rank) |r| {
                        if (_reported[r] == i) { _skip = true; break; }
                    }
                    if (_skip) continue;
                    const c = mc.load(.relaxed);
                    if (c > _bc) { _bc = c; _bi = i; }
                }
                if (_bc > 0) {
                    _reported[rank] = _bi;
                    std.debug.print("  #{d} {s} ({d} matches)\n", .{ rank + 1, rs.signatures[_bi].name, _bc });
                }
            }
        }
        // BP221: Key periodic metrics via std.log for release-build visibility
        // BP231: Added rej={d} for security rejection visibility
        std.log.info("[STATUS] threads={d} conn={d} errors={d} rej={d} matches={d} fwd={d} det={d}%", .{
            active_threads.load(.acquire),
            g_total_connections.load(.acquire),
            g_analyze_errors.load(.relaxed),
            g_rejected_connections.load(.relaxed),
            g_total_matches.load(.relaxed),
            g_total_forwarded.load(.relaxed),
            _det_rate,
        });
        std.debug.print("  ---\n", .{});
    }
    // Shutdown summary (runs once after while-loop exits)
    std.debug.print("\n=== AEGIS SHUTDOWN SUMMARY ===\n", .{});
    // BP219: Key shutdown metrics via std.log for release-build log persistence
    // BP231: Added rej={d} for security rejection visibility in shutdown summary
    // BP-L12: Add std.log for shutdown summary header and key metrics
    std.log.info("[SHUTDOWN] === AEGIS SHUTDOWN SUMMARY ===", .{});
    std.log.info("[SHUTDOWN] conn={d} bytes={d} errors={d} rej={d} matches={d} fwd={d} ipc={d} uptime={d}s", .{
        g_total_connections.load(.acquire),
        g_total_bytes.load(.relaxed),
        g_analyze_errors.load(.relaxed),
        g_rejected_connections.load(.relaxed),
        g_total_matches.load(.relaxed),
        g_total_forwarded.load(.relaxed),
        g_bridge_ipc_pushes.load(.relaxed),
        @intCast(@max(@as(i128, 0), std.time.nanoTimestamp() - g_start_time_ns) / std.time.ns_per_s),
    });
    std.debug.print("  Total connections: {d}\n", .{g_total_connections.load(.acquire)});
    // BP179: Total bytes in shutdown summary
    std.debug.print("  Total bytes processed: {d}\n", .{g_total_bytes.load(.relaxed)});
    std.debug.print("  Analyze errors: {d}\n", .{g_analyze_errors.load(.relaxed)});
    // BP227: Security rejections in shutdown summary
    std.debug.print("  Security rejections: {d}\n", .{g_rejected_connections.load(.relaxed)});
    const sh_conn: u64 = @intCast(g_total_connections.load(.acquire));
    const sh_err: u64 = @intCast(g_analyze_errors.load(.relaxed));
    const clean_rate: u64 = if (sh_conn > sh_err) (sh_conn - sh_err) * 100 / sh_conn else 0;
    std.debug.print("  Clean rate: {d}%\n", .{clean_rate});
    std.debug.print("  Active threads at exit: {d}\n", .{active_threads.load(.seq_cst)});
    const fin_s: u64 = @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp() - g_start_time_ns))) / std.time.ns_per_s;
    std.debug.print("  Uptime: {d}m {d}s\n", .{fin_s / 60, fin_s % 60});
    // BP185: Pipe connections and throughput in shutdown summary
    std.debug.print("  Pipe connections: {d}\n", .{g_pipe_connections.load(.relaxed)});
    // BP194: Forwarded packets in shutdown summary
    std.debug.print("  Forwarded (unmatched): {d}\n", .{g_total_forwarded.load(.relaxed)});
    // BP206: Bridge IPC pushes in shutdown summary
    std.debug.print("  Bridge IPC pushes: {d}\n", .{g_bridge_ipc_pushes.load(.relaxed)});
    // BP201: Matches and detection rate in shutdown summary
    const sh_matches: u64 = g_total_matches.load(.relaxed);
    const sh_fwd: u64 = g_total_forwarded.load(.relaxed);
    std.debug.print("  Rule matches: {d}\n", .{sh_matches});
    const sh_det: u64 = if (sh_matches + sh_fwd > 0) sh_matches * 100 / (sh_matches + sh_fwd) else 0;
    std.debug.print("  Detection rate: {d}%\n", .{sh_det});
    // BP202: Ruleset info in shutdown summary
    std.debug.print("  Ruleset version: v{d}\n", .{g_ruleset_version.load(.acquire)});
    // BP-L12: Ruleset version visible in release builds
    std.log.info("[SHUTDOWN] Ruleset version: v{d}", .{g_ruleset_version.load(.acquire)});
    const rs202 = acquireRuleset();
    if (rs202) |rs| {
        defer rs.release();
        std.debug.print("  AC engine nodes: {d}\n", .{rs.ac_engine.nodes.items.len});
    }
    const sh_bytes: u64 = g_total_bytes.load(.relaxed);
    const sh_kb_min: u64 = if (fin_s > 0) (sh_bytes / 1024) * 60 / fin_s else 0;
    std.debug.print("  Avg throughput: ~{d} KB/min\n", .{sh_kb_min});
    std.debug.print("================================\n", .{});
}

// =================================================================
// [ MAIN ENTRY: Thread 1 ]
// =================================================================

pub fn analyze_packets(allocator: std.mem.Allocator) void {
    std.debug.print("\n--- AEGIS CORE: 3-TIER ENGINE ACTIVE ---\n", .{});
    // BP222: Startup marker visible in release builds
    std.log.info("[INIT] AEGIS Core 3-Tier Engine starting", .{});
    g_start_time_ns = std.time.nanoTimestamp();
    std.debug.print("[INIT] All subsystems ready. Entering analysis loop.\n", .{});

    // Load rules from Rules.json
    std.debug.print("[INIT] Loading detection rules...\n", .{});

    // BP22: Pre-flight check for Rules.json
    std.debug.print("[RULES] Checking Rules.json...\n", .{});
    if (std.fs.cwd().statFile("Rules.json")) |stat| {
        if (stat.size > RULES_MAX_FILE_SIZE) {
            std.debug.print("\x1b[31m[ERROR] Rules.json exceeds 10MB ({d} bytes) - refusing to load\x1b[0m\n", .{stat.size});
            // BP224: Pre-flight failure visible in release builds
            std.log.err("[RULES] Rules.json exceeds 10MB ({d} bytes) - refusing to load", .{stat.size});
        } else if (stat.size == 0) {
            std.debug.print("\x1b[33m[WARN] Rules.json is empty (0 bytes)\x1b[0m\n", .{});
            // BP224: Pre-flight warning visible in release builds
            std.log.warn("[RULES] Rules.json is empty (0 bytes) - engine starts without rules", .{});
        } else {
            std.debug.print("[RULES] Rules.json found ({d} bytes)\n", .{stat.size});
        }
    } else |err| {
        std.debug.print("\x1b[33m[WARN] Rules.json not found ({}) - engine starts with empty ruleset\x1b[0m\n", .{err});
        // BP224: Pre-flight warning visible in release builds
        std.log.warn("[RULES] Rules.json not found ({}) - engine starts with empty ruleset", .{err});
    }

    const _bp91_rl_start = std.time.nanoTimestamp();
    reload_rules_atomic(allocator) catch |reload_err| {
        std.debug.print("[ANALYZE] Failed to load rules: {}\n", .{reload_err});
        // BP218: Rule load failure visible in release builds
        std.log.err("[ANALYZE] Failed to load rules: {}", .{reload_err});
    };
    const _bp91_rl_dur_ms = @divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - _bp91_rl_start), 1_000_000);
    std.log.info("[ANALYZE] Rules initialized in {d}ms", .{_bp91_rl_dur_ms});
    std.log.info("[ANALYZE] Rules ready, starting packet analysis", .{});

    // Background: print bridge stats every 30 seconds
    std.debug.print("[INIT] Rules loading completed\n", .{});
    // BP223: Override TCP port from environment variable (before listeners start)
    if (std.process.getenv("AEGIS_TCP_PORT")) |port_str| {
        AEGIS_TCP_PORT = std.fmt.parseInt(u16, port_str, 10) catch AEGIS_TCP_PORT;
        // BP226: Log port override for operational confirmation
        std.log.info("[INIT] TCP port overridden to {d} via AEGIS_TCP_PORT env", .{AEGIS_TCP_PORT});
    }
    // BP178: Log security configuration at startup for operational verification
    std.debug.print("\n--- AEGIS Security Configuration ---\n", .{});
    std.debug.print("  TCP Port: {d} (backlog={d})\n", .{AEGIS_TCP_PORT, TCP_LISTEN_BACKLOG});
    std.debug.print("  Max concurrent connections: {d} (semaphore)\n", .{MAX_CONCURRENT_CONNECTIONS});
    std.debug.print("  TCP buffer: {}B | Pipe buffer: {}B\n", .{TCP_BUFFER_SIZE, PIPE_BUFFER_SIZE});
    std.debug.print("  TCP idle timeout: {d}ms | Max session: {d}s\n", .{TCP_IDLE_TIMEOUT_MS, TCP_MAX_SESSION_S});
    std.debug.print("  TCP max packets: {d} | Pkt rate limit: {d}/s\n", .{TCP_MAX_PACKETS, PKT_RATE_LIMIT_MAX});
    std.debug.print("  Per-IP limit: {d} conns/60s (max {d} IPs)\n", .{RATE_LIMIT_MAX_CONNS, RATE_LIMIT_MAX_IPS});
    std.debug.print("  Rule limit: {d} | Pipe max: {d} pkts / {}MB\n", .{RULES_MAX_COUNT, PIPE_MAX_PACKETS, PIPE_MAX_BYTES / (1024 * 1024)});
    std.debug.print("  Max payload: {}B | Max rule file: {}MB\n", .{ANALYZE_MAX_PAYLOAD, RULES_MAX_FILE_SIZE / (1024 * 1024)});
    std.debug.print("-----------------------------------\n", .{});
    // BP228: Security config summary via std.log.info (release-build visible)
    std.log.info("[INIT] Security: port={d} sema={d} tcp_buf={}B pipe_buf={}B idle={d}ms max_sess={d}s", .{
        AEGIS_TCP_PORT, MAX_CONCURRENT_CONNECTIONS, TCP_BUFFER_SIZE, PIPE_BUFFER_SIZE, TCP_IDLE_TIMEOUT_MS, TCP_MAX_SESSION_S,
    });
    std.debug.print("[INIT] Starting network listeners...\n", .{});

    // BP213: Register CTRL+C handler in main thread (not just status reporter)
    // Ensures graceful shutdown even if status reporter thread fails to spawn
    _ = SetConsoleCtrlHandler(ctrlHandler, 1);

    const t_status_opt: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, bridgeStatusReporter, .{}) catch |err| {
            std.debug.print("\x1b[33m[ANALYZE] Status reporter failed to spawn: {}\x1b[0m\n", .{err});
            std.log.warn("[ANALYZE] Status reporter failed to spawn: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_status_opt) |t| t.detach();

    // Run accept-loop listeners (these block forever)
    std.log.info("[ANALYZE] Starting listener threads", .{});
    const t_pipe = std.Thread.spawn(.{}, pipe_listener, .{allocator}) catch |err| {
        std.log.warn("[ANALYZE] Pipe listener failed to spawn: {}", .{err});
        std.debug.print("\x1b[33m[ANALYZE] Pipe listener failed to spawn: {}\x1b[0m\n", .{err});
        // BP-F6: Signal shutdown so detached status reporter + T2-T5 threads exit cleanly
        // (was: return immediately, orphaning the already-spawned status reporter thread)
        bridge_init.requestShutdown();
        g_shutdown_requested.store(true, .release);
        return;
    };
    // BP214: TCP spawn failure should not orphan pipe listener thread
    const t_tcp_opt: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, tcp_listener, .{allocator}) catch |err| {
            std.debug.print("\x1b[33m[ANALYZE] TCP listener failed to spawn: {}\x1b[0m\n", .{err});
            std.log.warn("[ANALYZE] TCP listener failed to spawn: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };

    std.log.info("[ANALYZE] All listeners started", .{});
    std.log.info("[INIT] All systems operational", .{});
    std.debug.print("[INIT] All systems operational\n", .{});

    // BP140: Graceful shutdown drain with logging
    std.debug.print("[SHUTDOWN] Draining connections (waiting for listeners to stop)...\n", .{});
    const drain_start = std.time.nanoTimestamp();
    t_pipe.join();
    std.debug.print("[SHUTDOWN] Pipe listener stopped\n", .{});
    // BP214: Conditional join - TCP may not have spawned
    if (t_tcp_opt) |t_tcp| {
        t_tcp.join();
    }
    const drain_ms = @divTrunc(@max(@as(i128, 0), std.time.nanoTimestamp() - drain_start), 1_000_000);
    const drain_remaining = active_threads.load(.seq_cst);
    // BP163: Warn if drain took too long or handler threads remain
    if (drain_ms > 5000 or drain_remaining > 0) {
        std.log.warn("[SHUTDOWN] Drain: {d}ms, {d} handler threads still active", .{drain_ms, drain_remaining});
    }
    std.debug.print("[SHUTDOWN] All listeners stopped (drain: {d}ms, active threads: {d})\n", .{ drain_ms, drain_remaining });
}

// =================================================================
// [ UTILITY: payloadHex ]
// =================================================================

fn payloadHex(data: []const u8, comptime max_len: usize) [max_len * 2]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [max_len * 2]u8 = undefined;
    const len = @min(data.len, max_len);
    for (0..len) |i| {
        result[i * 2] = hex_chars[data[i] >> 4];
        result[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    for (len..max_len) |i| {
        result[i * 2] = '0';
        result[i * 2 + 1] = '0';
    }
    return result;
}

test "payloadHex converts bytes to lowercase hex" {
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const hex = payloadHex(&data, 4);
    try std.testing.expect(std.mem.eql(u8, &hex, "deadbeef"));
}

test "payloadHex truncates to max_len" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const hex = payloadHex(&data, 3);
    try std.testing.expect(std.mem.eql(u8, &hex, "010203"));
}

test "payloadHex handles empty input" {
    const data = [_]u8{};
    const hex = payloadHex(&data, 4);
    try std.testing.expect(std.mem.eql(u8, &hex, "00000000"));
}
