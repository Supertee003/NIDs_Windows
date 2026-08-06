const std = @import("std");
const net = std.net;
const win = std.os.windows;
const posix = std.posix;
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) @compileError("nids_analyze requires Windows target — uses kernel32 Named Pipes");
}

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

extern "kernel32" fn ConnectNamedPipe(hNamedPipe: win.HANDLE, lpOverlapped: ?*anyopaque) win.BOOL;
extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: win.HANDLE) win.BOOL;
extern "kernel32" fn ReadFile(
    hFile: win.HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?*anyopaque,
) win.BOOL;

// GetLastError — declared as extern for maximum Zig version compatibility
// (std.os.windows.GetLastError path changed between Zig versions)
extern "kernel32" fn GetLastError() u32;

// =================================================================
// [ C++ IPC BRIDGE — RUNTIME DYNAMIC LOADING (std.DynLib) ]
// Instead of extern declarations (which require link-time DLL),
// we load aegis_ipc.dll at runtime using std.DynLib.
// This allows Zig to build standalone without the DLL.
// =================================================================

const AegisIpcEvent = extern struct {
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
    source_pid: u32,
    defcon_impact: u32,
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

/// Try to load aegis_ipc.dll at runtime
fn loadBridgeDll() void {
    const dll_names = [_][:0]const u8{
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
            const path = std.fmt.bufPrintZ(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
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
    const dll_names = [_][:0]const u8{
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
            const path = std.fmt.bufPrintZ(&path_buf, "{s}\\{s}", .{ dir, dll_name }) catch continue;
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
    event_type: u32,
    rule_id: u32,
    severity: u32,
    payload_ptr: [*]const u8,
    payload_len: u32,
    is_pipe: bool,
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
        .timestamp = @bitCast(std.time.milliTimestamp()),
        .source_pid = 0,
        .defcon_impact = 4,
    };
    return fn_bridge_push_event.?(&event);
}

fn pushForwardedEvent(
    event_type: u32,
    payload_ptr: [*]const u8,
    payload_len: u32,
    is_pipe: bool,
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
        .timestamp = @bitCast(std.time.milliTimestamp()),
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
const AtomicThreatTracker = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(ThreatState.CLEAN)),
    pub fn step1_markSuspicious(self: *AtomicThreatTracker) bool {
        return self.state.cmpxchgStrong(@intFromEnum(ThreatState.CLEAN), @intFromEnum(ThreatState.SUSPICIOUS), .acquire, .monotonic) == null;
    }
    pub fn step2_verifyThreat(self: *AtomicThreatTracker) bool {
        return self.state.cmpxchgStrong(@intFromEnum(ThreatState.SUSPICIOUS), @intFromEnum(ThreatState.VERIFIED), .acquire, .monotonic) == null;
    }
    pub fn reset(self: *AtomicThreatTracker) void {
        self.state.store(@intFromEnum(ThreatState.CLEAN), .release);
    }
};

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
var connection_semaphore: std.Thread.Semaphore = std.Thread.Semaphore.init(100);
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

    var temp_sig_list = std.ArrayList(SecureRule).init(allocator);
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

        const crc = std.hash.Crc32.hash(active_fast_pattern);
        try temp_sig_list.append(.{
            .name = try allocator.dupe(u8, sig.name),
            .fast_pattern = try allocator.dupe(u8, active_fast_pattern),
            .match_pattern = try allocator.dupe(u8, sig.match_pattern),
            .regex_pattern = try allocator.dupe(u8, sig.regex_pattern),
            .severity = try allocator.dupe(u8, sig.severity),
            .action = try allocator.dupe(u8, sig.action),
            .crc32 = crc,
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
    const json_str = try std.json.stringifyAlloc(allocator, msg, .{});
    defer allocator.free(json_str);
    _ = posix.sendto(udp_log_sock, json_str, 0, &udp_log_addr.any, udp_log_addr.getOsSockLen()) catch {};
}

// --- [ 3-TIER FAST THREAT ANALYSIS ENGINE ] ---

pub fn inspect_packet(data: []const u8, ctx: PacketContext) !bool {
    std.debug.print("[DEBUG] Analyzing data from {s}, size: {} bytes, src_ip=0x{x}, dst_port={d}\n", .{ if (ctx.is_pipe) "PIPE" else "TCP", data.len, ctx.source_ip, ctx.dest_port });

    // 🛡️ [Rust Memory Safety Check — runtime loaded]
    if (!validatePayloadSafety(data.ptr, data.len)) return false;

    const current_ruleset = active_ruleset.load(.acquire) orelse return false;
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
        const alert = .{
            .timestamp = @as(u64, @bitCast(std.time.milliTimestamp())),
            .attack_type = rule.name,
            .policy = rule.action, // ส่งค่า "Block" หรือ "Drop" จาก Rules.json
            .reason = "Tier-1 Fast Pattern Match",
            .source = if (is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
        };

        try send_to_brain(allocator, alert);

        const severity_val: u32 = val: {
            if (std.mem.eql(u8, rule.severity, "Critical")) break :val 3;
            if (std.mem.eql(u8, rule.severity, "High")) break :val 2;
            if (std.mem.eql(u8, rule.severity, "Medium")) break :val 1;
            break :val 0;
        };
        _ = pushTier1Match(ctx, rule.crc32, severity_val, @intCast(u32, @min(data.len, std.math.maxInt(u32))));

        if (std.mem.eql(u8, rule.action, "Block")) {
            std.debug.print("\x1b[31;1m[ AEGIS CORE ] !!! BLOCK !!! Connection Terminated: {s}\x1b[0m\n", .{rule.name});
            return false;
        }

        return true;
    } else {
        const forward_msg = .{
            .timestamp = @as(u64, @bitCast(std.time.milliTimestamp())),
            .attack_type = "Unmatched: Deep Inspection Required",
            .policy = "Pending",
            .reason = "Forwarded: No Tier-1 Match",
            .source = if (is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
        };

        try send_to_brain(allocator, forward_msg);
        _ = pushForwardedEvent(ctx, @intCast(u32, @min(data.len, std.math.maxInt(u32))));

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
        // ใช้ ReadFile ที่ประกาศเป็น extern
        const success = ReadFile(hPipe, &buf, buf.len, &bytes_read, null);
        if (success == 0 or bytes_read == 0) break;
        const is_safe = inspect_packet(buf[0..bytes_read], true) catch true;
        if (!is_safe) {
            break;
        }
        // inspect_packet(buf[0..bytes_read], true) catch {};
    }
}

fn pipe_listener() !void {
    const pipe_name = "\\\\.\\pipe\\aegis_nids";
    while (true) {
        const hPipe = CreateNamedPipeA(pipe_name, 3, 0, 255, 4096, 4096, 0, null);
        if (hPipe == win.INVALID_HANDLE_VALUE) return;

        const connected = ConnectNamedPipe(hPipe, null);
        const err = GetLastError();

        if (connected != 0 or err == 535) {
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

fn handle_tcp_client(stream: net.Stream) void {
    defer stream.close();
    defer connection_semaphore.post();
    defer _ = active_threads.fetchSub(1, .monotonic);
    _ = active_threads.fetchAdd(1, .monotonic);
    const src_ip: u32 = blk: {
        const sa: *const std.posix.sockaddr_in = @ptrCast(@alignCast(&remote_addr.any));
        break :blk sa.addr;
    };
    const src_port: u16 = blk: {
        const sa: *const std.posix.sockaddr_in = @ptrCast(@alignCast(&remote_addr.any));
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
        const is_safe = inspect_packet(buf[0..len], false) catch true;
        if (!is_safe) {
            break;
        }
        // inspect_packet(buf[0..len], false) catch {};
    }
}

fn tcp_listener() !void {
    const addr = net.Address.parseIp4("0.0.0.0", 12345) catch return;
    var server = addr.listen(.{ .reuse_address = true }) catch return;
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        connection_semaphore.wait();
        const t = std.Thread.spawn(.{}, handle_tcp_client, .{conn.stream}) catch {
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

    // Note: Zig 0.13.0 std.posix.socket auto-initializes Winsock (WSAStartup)
    // on Windows. No explicit WSAStartup call needed.
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

/// Background thread: Print Bridge stats every 30 seconds
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
    }
}
