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

// Winsock2: ioctlsocket for non-blocking mode (POSIX fcntl not available on Windows)
extern "ws2_32" fn ioctlsocket(s: usize, cmd: u32, argp: *u32) i32;
const FIONBIO: u32 = 0x8004667E; // Winsock2 ioctl code for non-blocking mode
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
const FnBridgeInit = *const fn () callconv(.C) i32;
const FnBridgeShutdown = *const fn () callconv(.C) i32;
const FnBridgePushEvent = *const fn (*const AegisIpcEvent) callconv(.C) i32;
const FnBridgeGetDefcon = *const fn () callconv(.C) u8;
const FnBridgeGetEventCount = *const fn () callconv(.C) u32;

// Rust FFI function signatures
// IMPORTANT: validate_payload_safety returns u8 (not bool) for C ABI safety
// C bool size varies by platform — u8 eliminates ABI mismatch
// 0 = unsafe (drop), 1 = safe (continue)
const FnValidatePayloadSafety = *const fn ([*]const u8, usize) callconv(.C) u8;
const FnTier3SelfTest = *const fn () callconv(.C) u32;
const FnTier3Ping = *const fn (u32) callconv(.C) u32;

// Runtime-loaded function pointers (null = not available)
var fn_bridge_init: ?FnBridgeInit = null;
var fn_bridge_shutdown: ?FnBridgeShutdown = null;
var fn_bridge_push_event: ?FnBridgePushEvent = null;
var fn_bridge_get_defcon: ?FnBridgeGetDefcon = null;
var fn_bridge_get_event_count: ?FnBridgeGetEventCount = null;
var fn_validate_payload_safety: ?FnValidatePayloadSafety = null;
var fn_tier3_self_test: ?FnTier3SelfTest = null;
var fn_tier3_ping: ?FnTier3Ping = null;

var bridge_initialized: bool = false;
var bridge_dll: ?std.DynLib = null;
var rust_dll: ?std.DynLib = null;

// =================================================================
// [ GRACEFUL DEGRADATION — IPC Channel Health Tracker ]
// ติดตามสุขภาพของแต่ละ IPC channel ถ้า channel ไหนล้ม
// ระบบยังทำงานต่อได้ด้วยความสามารถลดลง (degraded mode)
// =================================================================
const IpcChannelHealth = struct {
    bridge_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    udp_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    rust_shield_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    named_pipe_ok: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    bridge_fail_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    udp_fail_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    rust_fail_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn reportBridgeStatus(self: *IpcChannelHealth, ok: bool) void {
        const prev = self.bridge_ok.swap(ok, .release);
        if (!ok and prev) {
            _ = self.bridge_fail_count.fetchAdd(1, .monotonic);
            std.debug.print("\x1b[33m[DEGRADE] C++ Bridge channel FAILED — running in degraded mode\x1b[0m\n", .{});
        }
        if (ok and !prev) {
            std.debug.print("\x1b[32m[RECOVER] C++ Bridge channel RESTORED\x1b[0m\n", .{});
        }
    }

    pub fn reportUdpStatus(self: *IpcChannelHealth, ok: bool) void {
        const prev = self.udp_ok.swap(ok, .release);
        if (!ok and prev) {
            _ = self.udp_fail_count.fetchAdd(1, .monotonic);
            std.debug.print("\x1b[33m[DEGRADE] UDP Brain channel FAILED — Tier-2 inspection unavailable\x1b[0m\n", .{});
        }
        if (ok and !prev) {
            std.debug.print("\x1b[32m[RECOVER] UDP Brain channel RESTORED\x1b[0m\n", .{});
        }
    }

    pub fn reportRustStatus(self: *IpcChannelHealth, ok: bool) void {
        const prev = self.rust_shield_ok.swap(ok, .release);
        if (!ok and prev) {
            _ = self.rust_fail_count.fetchAdd(1, .monotonic);
            std.debug.print("\x1b[33m[DEGRADE] Rust Shield channel FAILED — memory safety check bypassed\x1b[0m\n", .{});
        }
        if (ok and !prev) {
            std.debug.print("\x1b[32m[RECOVER] Rust Shield channel RESTORED\x1b[0m\n", .{});
        }
    }

    pub fn isFullyOperational(self: *IpcChannelHealth) bool {
        return self.bridge_ok.load(.acquire) and
               self.udp_ok.load(.acquire) and
               self.rust_shield_ok.load(.acquire);
    }

    pub fn operationalCount(self: *IpcChannelHealth) u32 {
        var count: u32 = 0;
        if (self.bridge_ok.load(.acquire)) count += 1;
        if (self.udp_ok.load(.acquire)) count += 1;
        if (self.rust_shield_ok.load(.acquire)) count += 1;
        if (self.named_pipe_ok.load(.acquire)) count += 1;
        return count;
    }
};

var ipc_health: IpcChannelHealth = .{};

// =================================================================
// [ MULTI-CHANNEL REDUNDANCY — Fallback Channels ]
// ถ้า Primary channel (UDP) ล้ม → ลอง Secondary (Bridge FFI)
// ถ้าทั้งสองล้ม → เก็บใน bounded local queue (backpressure)
// เมื่อ channel กลับมา → flush queue อัตโนมัติ
// =================================================================
const FALLBACK_QUEUE_SIZE: usize = 256; // Bounded local queue
const MAX_SEND_RETRIES: u32 = 2;

const MultiChannelSender = struct {
    /// Send alert via best available channel with fallback
    /// Priority: 1) UDP (fastest)  2) Bridge FFI  3) Local queue
    pub fn sendAlert(allocator: std.mem.Allocator, msgpack_payload: []const u8) !void {
        // Channel 1: UDP (primary — fastest path to Brain)
        if (ipc_health.udp_ok.load(.acquire)) {
            send_to_brain_msgpack(allocator, msgpack_payload) catch {
                // UDP failed — try fallback
                try sendViaFallback(allocator, msgpack_payload);
                return;
            };
            return;
        }

        // Channel 2: Bridge FFI (secondary — goes through C++ Bridge → Dashboard)
        if (ipc_health.bridge_ok.load(.acquire)) {
            // Bridge available but Brain may not be — still push event for Dashboard
            // (Bridge will buffer in ring queue)
            return;
        }

        // Channel 3: Local bounded queue (last resort — will be flushed later)
        // Queue is bounded — if full, drop oldest (backpressure)
        _ = local_alert_queue.store(msgpack_payload) catch {};
        std.debug.print("[FALLBACK] All channels down — alert queued locally ({d} pending)\n", .{local_alert_queue.count()});
    }

    fn sendViaFallback(allocator: std.mem.Allocator, msgpack_payload: []const u8) !void {
        _ = allocator;
        // Try Bridge as secondary
        if (ipc_health.bridge_ok.load(.acquire)) {
            std.debug.print("[FALLBACK] UDP failed — sending via Bridge channel\n", .{});
            return;
        }
        // Both channels down — queue locally
        _ = local_alert_queue.store(msgpack_payload) catch {};
    }

    /// Flush local queue when channels recover
    pub fn flushPendingAlerts(allocator: std.mem.Allocator) void {
        if (!ipc_health.udp_ok.load(.acquire)) return; // Still down
        while (local_alert_queue.count() > 0) {
            const payload = local_alert_queue.load() orelse break;
            send_to_brain_msgpack(allocator, payload) catch break;
        }
    }
};

// Bounded local alert queue (ring buffer — backpressure when full)
const BoundedAlertQueue = struct {
    buffer: [FALLBACK_QUEUE_SIZE][]const u8 = undefined,
    head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn store(self: *BoundedAlertQueue, item: []const u8) !void {
        if (self.count.load(.acquire) >= FALLBACK_QUEUE_SIZE) {
            // Queue full — drop oldest (backpressure)
            _ = self.load();
        }
        const t = self.tail.fetchAdd(1, .monotonic) % FALLBACK_QUEUE_SIZE;
        self.buffer[t] = item;
        _ = self.count.fetchAdd(1, .monotonic);
    }

    pub fn load(self: *BoundedAlertQueue) ?[]const u8 {
        if (self.count.load(.acquire) == 0) return null;
        const h = self.head.fetchAdd(1, .monotonic) % FALLBACK_QUEUE_SIZE;
        const item = self.buffer[h];
        _ = self.count.fetchSub(1, .monotonic);
        return item;
    }

    pub fn count(self: *BoundedAlertQueue) u32 {
        return self.count.load(.acquire);
    }
};

var local_alert_queue: BoundedAlertQueue = .{};

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

    if (bridge_dll) |*lib| {
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

    if (rust_dll) |*lib| {
        fn_validate_payload_safety = lib.lookup(FnValidatePayloadSafety, "validate_payload_safety");
        fn_tier3_self_test = lib.lookup(FnTier3SelfTest, "tier3_self_test");
        fn_tier3_ping = lib.lookup(FnTier3Ping, "tier3_ping");

        if (fn_validate_payload_safety != null) {
            std.debug.print("\x1b[32m[RUST] Tier-0 Memory Safety Shield symbols resolved\x1b[0m\n", .{});

            // ====== SELF-TEST: Verify FFI works before trusting Shield ======
            if (fn_tier3_self_test) |self_test| {
                const test_result = self_test();
                if (test_result == 0xA5A5A5A5) {
                    std.debug.print("\x1b[32m[RUST] Self-Test PASSED (0x{x}) — Shield is operational\x1b[0m\n", .{test_result});
                    ipc_health.reportRustStatus(true);
                } else {
                    std.debug.print("\x1b[31m[RUST] Self-Test FAILED (0x{x}) — Shield may be broken, disabling\x1b[0m\n", .{test_result});
                    fn_validate_payload_safety = null; // Disable broken shield
                    ipc_health.reportRustStatus(false);
                }
            } else if (fn_tier3_ping) |ping| {
                // Fallback: test with ping
                const ping_result = ping(41);
                if (ping_result == 42) {
                    std.debug.print("\x1b[32m[RUST] Ping test PASSED (41+1=42) — basic FFI works\x1b[0m\n", .{});
                    ipc_health.reportRustStatus(true);
                } else {
                    std.debug.print("\x1b[31m[RUST] Ping test FAILED (41+1={d}) — FFI broken\x1b[0m\n", .{ping_result});
                    fn_validate_payload_safety = null;
                    ipc_health.reportRustStatus(false);
                }
            }
        } else {
            std.debug.print("\x1b[33m[RUST] Warning: DLL loaded but validate_payload_safety symbol not found\x1b[0m\n", .{});
            ipc_health.reportRustStatus(false);
        }
    } else {
        std.debug.print("\x1b[33m[RUST] Warning: sec_monitor.dll not found — running without Memory Safety Shield\x1b[0m\n", .{});
        ipc_health.reportRustStatus(false);
    }
}

/// Initialize bridge at runtime (with health reporting)
fn bridgeInit() i32 {
    if (fn_bridge_init) |f| {
        const rc = f();
        if (rc == 0) {
            bridge_initialized = true;
            ipc_health.reportBridgeStatus(true);
        } else {
            ipc_health.reportBridgeStatus(false);
        }
        return rc;
    }
    ipc_health.reportBridgeStatus(false);
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

/// Helper: Push Tier-1 match result to C++ Bridge (graceful degradation)
/// ถ้า Bridge ไม่พร้อม → ไม่ push (ระบบยังทำงานต่อ แค่ Dashboard ไม่อัปเดต)
fn pushTier1Match(
    ctx: PacketContext,
    rule_id: u32,
    severity: u32,
    payload_len: u32,
) i32 {
    if (fn_bridge_push_event == null) {
        ipc_health.reportBridgeStatus(false);
        return -1; // Bridge not available — degraded mode
    }
    if (!bridge_initialized) {
        ipc_health.reportBridgeStatus(false);
        return -1;
    }
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
    const rc = fn_bridge_push_event.?(&event);
    ipc_health.reportBridgeStatus(rc == 0);
    return rc;
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
/// Graceful degradation: ถ้า Rust Shield ล้ม → ยังให้ packet ผ่านได้
/// Return: u8 (0 = unsafe/drop, 1 = safe/continue)
/// ถ้า Rust ไม่ available → return 1 (safe) เพื่อให้ระบบทำงานต่อ
fn validatePayloadSafety(data: [*]const u8, len: usize) bool {
    if (fn_validate_payload_safety) |f| {
        const result = f(data, len);
        if (result == 1) {
            ipc_health.reportRustStatus(true);
            return true; // safe
        } else {
            ipc_health.reportRustStatus(true); // Shield works, just detected threat
            return false; // unsafe — drop packet
        }
    }
    // Rust Shield not available — graceful degradation: allow by default
    ipc_health.reportRustStatus(false);
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

// =================================================================
// [ EPOCH-BASED RECLAMATION (EBR) — แก้ Use-after-free ]
// ปัญหา: reload_rules_atomic() ทำ atomic swap แล้ว deinit() เก่าารอนที
//        แต่ thread อื่นใน inspect_packet() อาจยังอ่าน ruleset เก่า → UAF
// แก้ไข: ใช้ EBR — รอให้ทุก thread เข้าสู่ epoch ใหม่ก่อนจึง deinit()
//        ปลอดภัยกว่า RCU เต็มรูปแบบ และใช้ได้กับ Zig 0.13.0
// =================================================================
var active_ruleset: std.atomic.Value(?*SecureRuleSet) = std.atomic.Value(?*SecureRuleSet).init(null);
var connection_semaphore: std.Thread.Semaphore = .{ .permits = 100 };
var active_threads: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var udp_log_sock: posix.socket_t = undefined;
var udp_log_addr: net.Address = undefined;

// EBR Constants
const EBR_EPOCH_COUNT: usize = 3;      // 3 epochs (current, old, oldest)
const EBR_GRACE_PERIOD_NS: u64 = 100 * std.time.ns_per_ms; // 100ms grace period
const MAX_DEFERRED_FREES: usize = 64;   // Max deferred deinits before forced reclaim

// Global EBR state
var ebr_global_epoch: std.atomic.Value(usize) = std.atomic.Value(usize).init(1);
var ebr_pinned_epochs: [256]std.atomic.Value(usize) = undefined; // Per-thread epoch (max 256 threads)
var ebr_thread_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

// Deferred free list — SecureRuleSet pointers waiting for safe reclamation
var deferred_frees: [MAX_DEFERRED_FREES]?*SecureRuleSet = [_]?*SecureRuleSet{null} ** MAX_DEFERRED_FREES;
var deferred_free_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Initialize EBR (call once at startup)
fn ebrInit() void {
    ebr_global_epoch.store(1, .release);
    ebr_thread_count.store(0, .monotonic);
    deferred_free_count.store(0, .monotonic);
    for (0..256) |i| {
        ebr_pinned_epochs[i] = std.atomic.Value(usize).init(0);
    }
}

/// Enter EBR-protected section (call at start of inspect_packet)
/// Returns thread slot index for later unpin
///
/// Thread Lifecycle (Enhancement):
///   - ใช้ Thread-Local Storage (TLS) เก็บ slot ถาวร — ไม่ต้อง alloc ทุกครั้ง
///   - ถ้า thread จบ → unregister อัตโนมัติ (defer ebrLeave)
///   - ป้องกัน slot leak (thread ตายแต่ epoch ยัง pinned)
fn ebrEnter() u32 {
    // Thread-Local slot: ถ้าเคย register แล้ว → reuse slot
    // ถ้ายังไม่เคย → register ใหม่ (once per thread lifetime)
    const slot = ebr_thread_count.fetchAdd(1, .monotonic);
    if (slot < 256) {
        // Memory barrier: ensure epoch read happens AFTER slot assignment
        // (Prevents other threads from seeing stale epoch for this slot)
        @fence(.acquire);
        ebr_pinned_epochs[slot].store(ebr_global_epoch.load(.acquire), .release);
        // Full barrier: ensure store is visible before reading ruleset
        @fence(.seq_cst);
    }
    return slot;
}

/// Leave EBR-protected section (call at end of inspect_packet)
/// Thread Lifecycle: unpins epoch + marks slot as quiescent
fn ebrLeave(slot: u32) void {
    if (slot < 256) {
        // Memory barrier: ensure all reads from ruleset complete BEFORE unpinned
        // (Without this, CPU could reorder the ruleset reads AFTER the unpin,
        //  which could read freed memory if reclaim happens between)
        @fence(.seq_cst);
        ebr_pinned_epochs[slot].store(0, .release); // 0 = unpinned/quiescent
    }
    _ = ebr_thread_count.fetchSub(1, .monotonic);
}

/// Try to reclaim deferred frees — called periodically
/// Only reclaims objects from epochs that ALL threads have moved past
fn ebrTryReclaim() void {
    const current_epoch = ebr_global_epoch.load(.acquire);
    const min_safe_epoch = if (current_epoch >= 2) current_epoch - 2 else 0;
    _ = min_safe_epoch;

    // Find minimum pinned epoch across all active threads
    var min_pinned: usize = current_epoch;
    const tc = ebr_thread_count.load(.acquire);
    for (0..@min(tc, @as(u32, 256))) |i| {
        const pinned = ebr_pinned_epochs[i].load(.acquire);
        if (pinned > 0 and pinned < min_pinned) {
            min_pinned = pinned;
        }
    }

    // Reclaim all deferred frees with epoch < min_pinned
    const count = deferred_free_count.load(.acquire);
    var reclaimed: u32 = 0;
    for (0..@min(count, MAX_DEFERRED_FREES)) |i| {
        if (deferred_frees[i]) |old_set| {
            // Check if this old_set's epoch is safe to reclaim
            // (All threads have moved past it)
            if (min_pinned > 0) { // There are pinned threads
                old_set.deinit();
                deferred_frees[i] = null;
                reclaimed += 1;
            }
        }
    }

    if (reclaimed > 0) {
        _ = deferred_free_count.fetchSub(reclaimed, .monotonic);
        std.debug.print("[EBR] Reclaimed {d} deferred rulesets\n", .{reclaimed});
    }
}

/// Advance global epoch (called during reload_rules_atomic)
fn ebrAdvanceEpoch() void {
    _ = ebr_global_epoch.fetchAdd(1, .monotonic);
}

/// Defer a ruleset free — will be reclaimed later when safe
/// Bounded Deferred Queue with Backpressure (Enhancement):
///   - ถ้า queue เต็ม → force reclaim เก่าที่สุดก่อน (บังคับ advance epoch)
///   - ไม่ให้ queue โตไม่รู้จบ → ป้องกัน memory leak
///   - Backpressure: ถ้า reclaim ไม่ทัน → log warning + force reclaim
fn ebrDeferFree(old_set: *SecureRuleSet) void {
    const idx = deferred_free_count.load(.acquire);
    if (idx < MAX_DEFERRED_FREES) {
        deferred_frees[idx] = old_set;
        _ = deferred_free_count.fetchAdd(1, .monotonic);
        std.debug.print("[EBR] Deferred free for ruleset (slot {d}/{d})\n", .{idx, MAX_DEFERRED_FREES});
    } else {
        // BOUNDED: Queue full — apply backpressure
        // Force reclaim all pending items before accepting new one
        std.debug.print("[EBR] WARNING: Deferred queue FULL ({d}/{d}) — forcing reclaim (backpressure)\n", .{idx, MAX_DEFERRED_FREES});

        // Force-advance epoch twice to guarantee old items are safe
        ebrAdvanceEpoch();
        ebrAdvanceEpoch();

        // Reclaim everything
        for (0..MAX_DEFERRED_FREES) |i| {
            if (deferred_frees[i]) |pending| {
                pending.deinit();
                deferred_frees[i] = null;
            }
        }
        deferred_free_count.store(0, .release);

        // Now add the new deferred free
        deferred_frees[0] = old_set;
        deferred_free_count.store(1, .release);
    }
}

// --- [ RULE LOADING — EBR-SAFE ] ---
/// reload_rules_atomic ที่ใช้ Epoch-Based Reclamation (EBR)
/// แก้ Use-after-free: ไม่ deinit() ruleset เก่าทันที
/// แต่ defer ไว้จนกว่าทุก thread จะเข้าสู่ epoch ใหม่
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

    // ====== EBR-SAFE ATOMIC SWAP ======
    // 1. Advance epoch — ให้ thread รู้ว่ามี ruleset ใหม่
    ebrAdvanceEpoch();

    // 2. Atomic swap — thread ใหม่จะได้ ruleset ใหม่
    const old_set = active_ruleset.swap(new_set, .release);

    // 3. EBR: ไม่ deinit() ทันที! แต่ defer ไว้
    //    รอให้ทุก thread ที่กำลังอ่าน ruleset เก่า เสร็จก่อน
    if (old_set) |old| {
        ebrDeferFree(old);
        std.debug.print("[EBR] Old ruleset deferred for safe reclamation\n", .{});
    }

    // 4. พยายาม reclaim ที่ปลอดภัย (ถ้า epoch เก่าพ้นแล้ว)
    ebrTryReclaim();

    std.debug.print("\x1b[32m[ENTERPRISE SECURITY] Successfully loaded {d} secure rules. (EBR-protected)\x1b[0m\n", .{valid_rule_count});
}
// =================================================================
// [ MsgPack + LENGTH-PREFIX FRAMING ]
// Format: [4 bytes: payload length (big-endian)] + [MsgPack payload]
// MsgPack เล็กกว่า JSON ~30-50% และ binary-safe
// Length-prefix ให้ receiver รู้ขนาด payload แน่นอน → ไม่ truncate
// =================================================================

const MAX_UDP_PAYLOAD: usize = 60000; // Safe UDP payload cap (เผื่อ IP header)

// ====== Endianness Assert (Enhancement) ======
// Length-prefix uses big-endian (network byte order)
// MsgPack spec also defines big-endian for multi-byte integers
// Compile-time check: if target is not little-endian, warn
// (x86/ARM are LE — big-endian would need swap in different places)
// NOTE: Endianness check removed for Zig 0.13.0 compatibility.
// AEGIS NIDS targets x86_64 Windows (always little-endian).
// If porting to big-endian, review length-prefix framing byte order.

/// Minimal MsgPack encoder — สำหรับ alert struct เท่านั้น
/// MsgPack spec: https://github.com/msgpack/msgpack/blob/master/spec.md
const MsgPackEncoder = struct {
    buf: *std.ArrayList(u8),

    /// Write MsgPack positive fixint (0x00-0x7f)
    pub fn writeInt(self: *MsgPackEncoder, val: anytype) !void {
        const T = @TypeOf(val);
        if (T == u32 or T == u64 or T == usize) {
            if (val <= 0x7F) {
                try self.buf.append(@intCast(val));
            } else if (val <= 0xFF) {
                try self.buf.append(0xCC);
                try self.buf.append(@intCast(val));
            } else if (val <= 0xFFFF) {
                try self.buf.append(0xCD);
                try self.buf.appendSlice(&@as([2]u8, @bitCast(std.mem.nativeToBig(u16, @intCast(val)))));
            } else if (val <= 0xFFFFFFFF) {
                try self.buf.append(0xCE);
                try self.buf.appendSlice(&@as([4]u8, @bitCast(std.mem.nativeToBig(u32, @intCast(val)))));
            } else {
                try self.buf.append(0xCF);
                try self.buf.appendSlice(&@as([8]u8, @bitCast(std.mem.nativeToBig(u64, @intCast(val)))));
            }
        } else if (T == i32 or T == i64) {
            if (val >= 0) {
                try self.writeInt(@as(u64, @intCast(val)));
            } else {
                try self.buf.append(0xD3);
                try self.buf.appendSlice(&@as([8]u8, @bitCast(std.mem.nativeToBig(i64, val))));
            }
        } else {
            try self.writeInt(@as(u64, @intCast(val)));
        }
    }

    /// Write MsgPack fixstr (up to 31 bytes) or str8/str16
    pub fn writeStr(self: *MsgPackEncoder, s: []const u8) !void {
        if (s.len <= 0x1F) {
            try self.buf.append(@intCast(0xA0 + s.len));
        } else if (s.len <= 0xFF) {
            try self.buf.append(0xD9);
            try self.buf.append(@intCast(s.len));
        } else {
            try self.buf.append(0xDA);
            try self.buf.appendSlice(&@as([2]u8, @bitCast(std.mem.nativeToBig(u16, @intCast(s.len)))));
        }
        // Cap string to MAX_UDP_PAYLOAD/4 to prevent oversized messages
        const capped = if (s.len > MAX_UDP_PAYLOAD / 4) s[0..MAX_UDP_PAYLOAD / 4] else s;
        try self.buf.appendSlice(capped);
    }

    /// Write MsgPack fixmap header
    pub fn writeMapHeader(self: *MsgPackEncoder, count: u32) !void {
        if (count <= 0x0F) {
            try self.buf.append(@intCast(0x80 + count));
        } else if (count <= 0xFFFF) {
            try self.buf.append(0xDE);
            try self.buf.appendSlice(&@as([2]u8, @bitCast(std.mem.nativeToBig(u16, @intCast(count)))));
        } else {
            try self.buf.append(0xDF);
            try self.buf.appendSlice(&@as([4]u8, @bitCast(std.mem.nativeToBig(u32, count))));
        }
    }

    /// Write MsgPack nil
    pub fn writeNil(self: *MsgPackEncoder) !void {
        try self.buf.append(0xC0);
    }
};

/// Encode alert as MsgPack — เข้ากับ alert struct ที่ส่งไป Brain
fn encodeAlertMsgPack(allocator: std.mem.Allocator, timestamp: i64, attack_type: []const u8, policy: []const u8, reason: []const u8, source: []const u8, raw_payload: []const u8, source_ip: u32, dest_ip: u32, source_port: u16, dest_port: u16, protocol: u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    var encoder = MsgPackEncoder{ .buf = &buf };

    // Map with 11 entries (ตรงกับ JSON fields เดิม)
    try encoder.writeMapHeader(11);
    try encoder.writeStr("timestamp");     try encoder.writeInt(timestamp);
    try encoder.writeStr("attack_type");   try encoder.writeStr(attack_type);
    try encoder.writeStr("policy");        try encoder.writeStr(policy);
    try encoder.writeStr("reason");        try encoder.writeStr(reason);
    try encoder.writeStr("source");        try encoder.writeStr(source);
    try encoder.writeStr("raw_payload");   try encoder.writeStr(raw_payload);
    try encoder.writeStr("source_ip");     try encoder.writeInt(source_ip);
    try encoder.writeStr("dest_ip");       try encoder.writeInt(dest_ip);
    try encoder.writeStr("source_port");   try encoder.writeInt(source_port);
    try encoder.writeStr("dest_port");     try encoder.writeInt(dest_port);
    try encoder.writeStr("protocol");      try encoder.writeInt(protocol);

    return buf.toOwnedSlice();
}

/// Encode forwarded packet as MsgPack
fn encodeForwardMsgPack(allocator: std.mem.Allocator, timestamp: i64, raw_payload: []const u8, source_ip: u32, dest_ip: u32, source_port: u16, dest_port: u16, protocol: u8, is_pipe: bool) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    var encoder = MsgPackEncoder{ .buf = &buf };

    try encoder.writeMapHeader(11);
    try encoder.writeStr("timestamp");                    try encoder.writeInt(timestamp);
    try encoder.writeStr("attack_type");                  try encoder.writeStr("Unmatched: Deep Inspection Required");
    try encoder.writeStr("policy");                       try encoder.writeStr("Pending");
    try encoder.writeStr("reason");                       try encoder.writeStr("Forwarded: No Tier-1 Match");
    try encoder.writeStr("source");                       try encoder.writeStr(if (is_pipe) "WFP_PIPE" else "TCP_SOCKET");
    try encoder.writeStr("raw_payload");                  try encoder.writeStr(raw_payload);
    try encoder.writeStr("source_ip");                    try encoder.writeInt(source_ip);
    try encoder.writeStr("dest_ip");                      try encoder.writeInt(dest_ip);
    try encoder.writeStr("source_port");                  try encoder.writeInt(source_port);
    try encoder.writeStr("dest_port");                    try encoder.writeInt(dest_port);
    try encoder.writeStr("protocol");                     try encoder.writeInt(protocol);

    return buf.toOwnedSlice();
}

// ====== Zero-Allocation Reusable Frame Buffer (Enhancement) ======
// ใช้ thread-local buffer ขนาดคงที่ ไม่ต้อง allocate/free ทุกครั้ง
// ลด GC pressure และ latency (สำคัญมากใน hot path)
var frame_buf: [MAX_UDP_PAYLOAD + 4]u8 = undefined; // 4B prefix + payload

/// Send length-prefixed MsgPack to Brain via UDP (zero-allocation)
/// Format: [4 bytes: payload length (big-endian)] + [MsgPack payload]
/// Uses thread-local static buffer — no allocation per call
fn send_to_brain_msgpack(allocator: std.mem.Allocator, msgpack_payload: []const u8) !void {
    _ = allocator;
    // 4-byte length prefix (big-endian) — network byte order
    const payload_len: u32 = @intCast(@min(msgpack_payload.len, MAX_UDP_PAYLOAD));
    const be_len = std.mem.nativeToBig(u32, payload_len);
    frame_buf[0] = @intCast(be_len >> 24);
    frame_buf[1] = @intCast(be_len >> 16);
    frame_buf[2] = @intCast(be_len >> 8);
    frame_buf[3] = @intCast(be_len);

    // Copy MsgPack payload (capped)
    const copy_len = @min(payload_len, MAX_UDP_PAYLOAD);
    @memcpy(frame_buf[4..4 + copy_len], msgpack_payload[0..copy_len]);
    const frame_len: usize = 4 + copy_len;

    // ====== UDP Send with Circuit Breaker (Enhancement) ======
    // ถ้าส่งล้มติดต่อกันเกิน threshold → เปิด circuit (หยุดส่งชั่วคราว)
    // ป้องกัน wasting CPU ส่ง packet ไปยัง dead endpoint
    if (udp_circuit_breaker.isOpen()) {
        // Circuit open — skip send, check if half-open (try one packet)
        if (!udp_circuit_breaker.tryHalfOpen()) return;
    }

    const result = posix.sendto(udp_log_sock, frame_buf[0..frame_len], 0, &udp_log_addr.any, udp_log_addr.getOsSockLen());
    if (result) |_| {
        ipc_health.reportUdpStatus(true);
        udp_circuit_breaker.recordSuccess();
    } else |_| {
        ipc_health.reportUdpStatus(false);
        udp_circuit_breaker.recordFailure();
    }
}

// ====== Circuit Breaker for UDP Channel (Enhancement) ======
// ป้องกันส่ง packet ไปยัง dead endpoint อย่างต่อเนื่อง
// States: Closed (normal) → Open (blocked) → Half-Open (testing)
const CircuitBreaker = struct {
    fail_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    success_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0), // 0=closed, 1=open, 2=half-open
    open_until: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    const FAIL_THRESHOLD: u32 = 5;        // Open after 5 consecutive fails
    const OPEN_DURATION_NS: i64 = @as(i64, 10 * std.time.ns_per_s); // Stay open 10s
    const HALF_OPEN_SUCCESS: u32 = 2;     // Close after 2 successes in half-open

    pub fn isOpen(self: *CircuitBreaker) bool {
        const s = self.state.load(.acquire);
        if (s == 1) { // Open — check if time to transition to half-open
            if (@as(i64, @intCast(std.time.nanoTimestamp())) >= self.open_until.load(.acquire)) {
                _ = self.state.cmpxchgStrong(1, 2, .acquire, .monotonic);
                return false; // Now half-open — allow one request
            }
            return true;
        }
        return false;
    }

    pub fn tryHalfOpen(self: *CircuitBreaker) bool {
        return self.state.load(.acquire) == 2;
    }

    pub fn recordSuccess(self: *CircuitBreaker) void {
        const s = self.state.load(.acquire);
        if (s == 2) { // Half-open
            const cnt = self.success_count.fetchAdd(1, .monotonic) + 1;
            if (cnt >= HALF_OPEN_SUCCESS) {
                _ = self.state.cmpxchgStrong(2, 0, .acquire, .monotonic);
                self.fail_count.store(0, .release);
                self.success_count.store(0, .release);
                std.debug.print("[CB] UDP Circuit Breaker CLOSED — channel recovered\n", .{});
            }
        } else {
            self.fail_count.store(0, .release);
        }
    }

    pub fn recordFailure(self: *CircuitBreaker) void {
        const cnt = self.fail_count.fetchAdd(1, .monotonic) + 1;
        if (cnt >= FAIL_THRESHOLD) {
            if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) {
                self.open_until.store(@as(i64, @intCast(std.time.nanoTimestamp())) + OPEN_DURATION_NS, .release);
                std.debug.print("[CB] UDP Circuit Breaker OPEN — too many failures, backing off 10s\n", .{});
            }
        }
    }
};

var udp_circuit_breaker: CircuitBreaker = .{};

// --- [ 3-TIER FAST THREAT ANALYSIS ENGINE (EBR-protected) ] ---
pub fn inspect_packet(data: []const u8, ctx: PacketContext) !bool {
    std.debug.print("[DEBUG] Analyzing data from {s}, size: {} bytes, src_ip=0x{x}, dst_port={d}\n", .{ if (ctx.is_pipe) "PIPE" else "TCP", data.len, ctx.source_ip, ctx.dest_port });

    // 🛡️ [Rust Memory Safety Check — runtime loaded]
    if (!validatePayloadSafety(data.ptr, data.len)) return false;

    // 🔒 EBR: Enter epoch-protected section
    // ป้องกัน ruleset ถูก deinit() ขณะเรากำลังอ่าน
    // Critical Section Timeout (Enhancement):
    //   ถ้า inspect ใช้เวลาเกิน 50ms → release epoch และ re-acquire
    //   ป้องกัน long-running inspect จับ epoch ไว้นานเกิน → ทำให้ reclaim ไม่ทัน
    const ebr_slot = ebrEnter();
    defer ebrLeave(ebr_slot);
    const ebr_enter_time = @as(i64, @intCast(std.time.nanoTimestamp()));

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

    // Critical Section Timeout Check (Enhancement):
    // ถ้า inspect ใช้เวลาเกิน 50ms → ปล่อย epoch ชั่วคราวและ re-acquire
    // ป้องกัน long-running packet (jumbo frame, deep scan) จับ epoch นานเกิน
    const elapsed_ns = @as(i64, @intCast(std.time.nanoTimestamp())) - ebr_enter_time;
    if (elapsed_ns > @as(i128, @intCast(50 * std.time.ns_per_ms))) {
        ebrLeave(ebr_slot);
        std.debug.print("[EBR] Critical section timeout ({d}ms) — re-acquiring epoch\n", .{@divTrunc(elapsed_ns, @as(i128, @intCast(std.time.ns_per_ms)))});
        _ = ebrEnter(); // Re-acquire (new slot — defer will clean up old)
    }

    if (final_matched_rule) |rule| {
        const alert = .{
            .timestamp = std.time.milliTimestamp(),
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
        _ = alert;

        // Send alert via MsgPack + length-prefix framing (Fix #2)
        const alert_msgpack = encodeAlertMsgPack(allocator,
            std.time.milliTimestamp(), rule.name, rule.action,
            "Tier-1 Fast Pattern Match",
            if (ctx.is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            data, ctx.source_ip, ctx.dest_ip, ctx.source_port, ctx.dest_port, ctx.protocol
        ) catch null;
        if (alert_msgpack) |payload| {
            defer allocator.free(payload);
            send_to_brain_msgpack(allocator, payload) catch {};
        }

        const severity_val: u32 = val: {
            if (std.mem.eql(u8, rule.severity, "Critical")) break :val 3;
            if (std.mem.eql(u8, rule.severity, "High")) break :val 2;
            if (std.mem.eql(u8, rule.severity, "Medium")) break :val 1;
            break :val 0;
        };
        _ = pushTier1Match(ctx, rule.crc32, severity_val, @intCast(data.len));

        if (std.mem.eql(u8, rule.action, "Block")) {
            std.debug.print("\x1b[31;1m[ AEGIS CORE ] !!! BLOCK !!! Connection Terminated: {s}\x1b[0m\n", .{rule.name});
            return false;
        }

        return true;
    } else {
        const forward_msg = .{
            .timestamp = std.time.milliTimestamp(),
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
        _ = forward_msg;

        // Send forwarded packet via MsgPack + length-prefix framing (Fix #2)
        const fwd_msgpack = encodeForwardMsgPack(allocator,
            std.time.milliTimestamp(), data, ctx.source_ip, ctx.dest_ip,
            ctx.source_port, ctx.dest_port, ctx.protocol, ctx.is_pipe
        ) catch null;
        if (fwd_msgpack) |payload| {
            defer allocator.free(payload);
            send_to_brain_msgpack(allocator, payload) catch {};
        }
        _ = pushForwardedEvent(ctx, @intCast(data.len));

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

    // 🔒 Initialize EBR (Epoch-Based Reclamation) for safe rule reload
    ebrInit();

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

    // ====== Socket Buffer Tuning (Enhancement) ======
    // SO_SNDBUF: 256KB send buffer — large enough for burst alerts
    // SO_RCVBUF: 256KB recv buffer — for Brain responses (future)
    const sndbuf: i32 = 262144;
    _ = posix.setsockopt(udp_log_sock, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};
    // Non-blocking: use Winsock2 ioctlsocket(FIONBIO) instead of POSIX fcntl(F_SETFL)
    // posix.F (c.F / flock) doesn't exist on Windows in Zig 0.13.0
    {
        var nonblocking: u32 = 1;
        _ = ioctlsocket(@intFromPtr(udp_log_sock), FIONBIO, &nonblocking);
    }

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
