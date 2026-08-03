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
// [ C++ IPC BRIDGE FFI — extern "C" ABI ]
// ประกาศฟังก์ชันจาก aegis_ipc.dll (C++ Bridge) สำหรับส่ง event
// จาก Zig Core (Tier-1) ไปยัง C++ Bridge → Python Brain → Dashboard
// =================================================================
const AegisIpcEvent = extern struct {
    event_type: u32,       // EventType: 0=NETWORK, 1=KERNEL_FILE, 2=KERNEL_PROCESS, 3=PIPE
    source_ip: u32,        // IPv4 source
    dest_ip: u32,          // IPv4 destination
    source_port: u16,      // Source port
    dest_port: u16,        // Destination port
    protocol: u8,          // 6=TCP, 17=UDP, 1=ICMP
    direction: u8,         // 0=inbound, 1=outbound
    layer_id: u8,          // Layer where event originated
    tier_result: u8,       // 0=NoMatch, 1=Tier1, 2=Tier2, 3=Tier3
    payload_length: u32,   // Length of payload
    rule_id: u32,          // Matched rule ID
    severity: u32,         // 0=Low, 1=Medium, 2=High, 3=Critical
    reserved: u32,         // Reserved
    timestamp: u64,        // Event timestamp (ms since epoch)
    source_pid: u32,       // PID of the process
    defcon_impact: u32,    // DEFCON level impact (1-5)
};

extern fn aegis_bridge_init() i32;
extern fn aegis_bridge_shutdown() i32;
extern fn aegis_bridge_push_event(event: *const AegisIpcEvent) i32;
extern fn aegis_bridge_get_defcon() u8;
extern fn aegis_bridge_get_event_count() u32;

var bridge_initialized: bool = false;

/// Helper: Push Tier-1 match result to C++ Bridge
fn pushTier1Match(
    event_type: u32,
    rule_id: u32,
    severity: u32,
    payload_ptr: [*]const u8,
    payload_len: u32,
    is_pipe: bool,
) i32 {
    if (!bridge_initialized) return -1;
    const event: AegisIpcEvent = .{
        .event_type = event_type,
        .source_ip = 0,               // ยังไม่มี 5-tuple ใน Phase 1
        .dest_ip = 0,
        .source_port = 0,
        .dest_port = 0,
        .protocol = if (is_pipe) 0 else 6, // TCP=6
        .direction = 0,                // inbound
        .layer_id = if (is_pipe) 3 else 0, // 3=PIPE, 0=NETWORK
        .tier_result = 1,              // Tier-1 fast match
        .payload_length = payload_len,
        .rule_id = rule_id,
        .severity = severity,
        .reserved = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .source_pid = 0,
        .defcon_impact = 4,            // ELEVATED (will be recalculated)
    };
    return aegis_bridge_push_event(&event);
}

/// Helper: Push forwarded (no Tier-1 match) event to C++ Bridge
fn pushForwardedEvent(
    event_type: u32,
    payload_ptr: [*]const u8,
    payload_len: u32,
    is_pipe: bool,
) i32 {
    if (!bridge_initialized) return -1;
    const event: AegisIpcEvent = .{
        .event_type = event_type,
        .source_ip = 0,
        .dest_ip = 0,
        .source_port = 0,
        .dest_port = 0,
        .protocol = if (is_pipe) 0 else 6,
        .direction = 0,
        .layer_id = if (is_pipe) 3 else 0,
        .tier_result = 0,              // No match — needs Tier-2
        .payload_length = payload_len,
        .rule_id = 0,
        .severity = 0,
        .reserved = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .source_pid = 0,
        .defcon_impact = 5,            // SAFE (no match yet)
    };
    return aegis_bridge_push_event(&event);
}

// =================================================================
// [ นำเข้าฟังก์ชันจาก RUST DLL (Memory Safety Shield) ]
// =================================================================
extern "c" fn validate_payload_safety(data: [*]const u8, len: usize) bool;

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
// --- ปรับปรุงฟังก์ชันส่งข้อมูลให้ใช้ Allocator ---
fn send_to_brain(allocator: std.mem.Allocator, msg: anytype) !void {
    // ใช้ ArrayList ร่วมกับ allocator เพื่อจองหน่วยความจำตามจริง
    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit(); // คืนหน่วยความจำเมื่อส่งเสร็จ

    try std.json.stringify(msg, .{}, string.writer());
    _ = posix.sendto(udp_log_sock, string.items, 0, &udp_log_addr.any, udp_log_addr.getOsSockLen()) catch {};
}

// --- [ 3-TIER FAST THREAT ANALYSIS ENGINE ] ---
pub fn inspect_packet(data: []const u8, is_pipe: bool) !bool {
    // Check TCP socket
    std.debug.print("[DEBUG] Analyzing data from {s}, size: {} bytes\n", .{ if (is_pipe) "PIPE" else "TCP", data.len });

    // 🛡️ [ด่านหน้าสุด: RUST MEMORY SAFETY CHECK] 🛡️
    if (!validate_payload_safety(data.ptr, data.len)) return false;

    const current_ruleset = active_ruleset.load(.acquire) orelse return false;
    const allocator = current_ruleset.allocator; // ดึง Allocator มาใช้

    var curr: usize = 0;
    var final_matched_rule: ?*const SecureRule = null;

    // --- [ TIER 1: สแกนความเร็วแสงด้วย Aho-Corasick ] ---
    for (data) |char| {
        const c = @as(usize, char);
        curr = current_ruleset.ac_engine.nodes.items[curr].next[c];

        var temp = curr;
        while (temp != 0) {
            for (current_ruleset.ac_engine.nodes.items[temp].matches.items) |idx| {
                const rule = &current_ruleset.signatures[idx];
                var is_tier2_match = true;

                // --- [ 🛡️ TIER 2: ยืนยัน Logical AND (Smart Hybrid Match) ] ---
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

        // 1. ส่งข้อมูลไปให้ Brain เขียน Log ก่อนเสมอ (เพื่อให้ 3 การแสดงผลทำงาน)
        const alert = .{
            .timestamp = std.time.timestamp(),
            .attack_type = rule.name,
            .policy = rule.action, // ส่งค่า "Block" หรือ "Drop" จาก Rules.json
            .reason = "Tier-1 Fast Pattern Match",
            .source = if (is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
        };

        // 2. ส่ง Log ด้วย Dynamic Allocator
        try send_to_brain(allocator, alert);

        // 3. 🔗 Push Tier-1 match to C++ Bridge (ส่ง event ไป Dashboard)
        const severity_val: u32 = val: {
            if (std.mem.eql(u8, rule.severity, "Critical")) break :val 3;
            if (std.mem.eql(u8, rule.severity, "High")) break :val 2;
            if (std.mem.eql(u8, rule.severity, "Medium")) break :val 1;
            break :val 0; // Low
        };
        const event_type_val: u32 = if (is_pipe) 3 else 0;
        _ = pushTier1Match(event_type_val, rule.crc32, severity_val, data.ptr, @intCast(data.len), is_pipe);

        // 4. 🛡️ หัวใจสำคัญ: แยกการทำงานตาม Policy ของคุณ
        if (std.mem.eql(u8, rule.action, "Block")) {
            // กรณี Block: Zig ตัดการเชื่อมต่อทันที
            std.debug.print("\x1b[31;1m[ AEGIS CORE ] !!! BLOCK !!! Connection Terminated: {s}\x1b[0m\n", .{rule.name});
            return false;
        }

        return true;
    } else {
        // 3. กรณีไม่พบ Fast Pattern -> ส่งต่อให้ Brain ตรวจ Regex ต่อ (Forward)
        const forward_msg = .{
            .timestamp = std.time.timestamp(),
            .attack_type = "Unmatched: Deep Inspection Required",
            .policy = "Pending",
            .reason = "Forwarded: No Tier-1 Match",
            .source = if (is_pipe) "WFP_PIPE" else "TCP_SOCKET",
            .raw_payload = data,
        };

        // ใช้ dynamic allocator ส่ง forward_msg (แก้ปัญหา Buffer เต็ม)
        try send_to_brain(allocator, forward_msg);

        // 🔗 Push forwarded event to C++ Bridge (ส่งให้ Tier-2 ตรวจสอบต่อ)
        const event_type_val: u32 = if (is_pipe) 3 else 0;
        _ = pushForwardedEvent(event_type_val, data.ptr, @intCast(data.len), is_pipe);

        return true;
    }
}

// ==========================================
// [ IPC & SOCKET LISTENERS ]
// ==========================================
fn handle_pipe_client(hPipe: win.HANDLE) void {
    defer {
        _ = DisconnectNamedPipe(hPipe);
        win.CloseHandle(hPipe); // ปิดท่อสื่อสาร
    }
    defer connection_semaphore.post();
    defer _ = active_threads.fetchSub(1, .monotonic);
    _ = active_threads.fetchAdd(1, .monotonic);

    var buf: [4096]u8 = undefined;
    while (true) {
        var bytes_read: u32 = 0;
        // ใช้ ReadFile ที่ประกาศเป็น extern
        const success = ReadFile(hPipe, &buf, buf.len, &bytes_read, null);
        if (success == 0 or bytes_read == 0) break;
        const is_safe = inspect_packet(buf[0..bytes_read], true) catch true;
        if (!is_safe) {
            break; // 💥 เตะ Hacker ออกจาก Named Pipe ทันที!
        }
        // inspect_packet(buf[0..bytes_read], true) catch {};
    }
}

fn pipe_listener() !void {
    const pipe_name = "\\\\.\\pipe\\aegis_nids";
    while (true) {
        // ใช้ CreateNamedPipeA ที่ประกาศเป็น extern
        const hPipe = CreateNamedPipeA(pipe_name, 3, 0, 255, 4096, 4096, 0, null);
        if (hPipe == win.INVALID_HANDLE_VALUE) return;

        // ใช้ ConnectNamedPipe ที่ประกาศเป็น extern
        const connected = ConnectNamedPipe(hPipe, null);
        const err = win.kernel32.GetLastError();

        if (connected != 0 or @intFromEnum(err) == 535) { // 535 = ERROR_PIPE_CONNECTED
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

    var buf: [16384]u8 = undefined;
    while (true) {
        const len = stream.read(&buf) catch break;
        if (len == 0) break;
        const is_safe = inspect_packet(buf[0..len], false) catch true;
        if (!is_safe) {
            break; // 💥 เตะ Hacker ออกจาก TCP ทันที!
        }
        // inspect_packet(buf[0..len], false) catch {};
    }
}

fn tcp_listener() !void {
    var addr = net.Address.parseIp4("0.0.0.0", 12345) catch return;
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

    // 🔗 Initialize C++ IPC Bridge
    const bridge_rc = aegis_bridge_init();
    if (bridge_rc == 0) {
        bridge_initialized = true;
        std.debug.print("\x1b[32m[BRIDGE] C++ IPC Bridge initialized — Zig Core connected\x1b[0m\n", .{});
    } else {
        std.debug.print("\x1b[33m[BRIDGE] Warning: Bridge init failed (rc={d}), running without Bridge\x1b[0m\n", .{bridge_rc});
    }
    defer {
        if (bridge_initialized) {
            _ = aegis_bridge_shutdown();
            std.debug.print("[BRIDGE] C++ IPC Bridge shutdown\n", .{});
        }
    }

    udp_log_addr = net.Address.parseIp4("127.0.0.1", 9999) catch unreachable;
    udp_log_sock = posix.socket(udp_log_addr.any.family, posix.SOCK.DGRAM, 0) catch unreachable;

    reload_rules_atomic(allocator) catch |err| {
        std.debug.print("Failed to load rules: {}\n", .{err});
    };

    // Show Bridge status periodically
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
        const count = aegis_bridge_get_event_count();
        const defcon = aegis_bridge_get_defcon();
        std.debug.print("[BRIDGE] Events in queue: {d} | DEFCON: {d}\n", .{ count, defcon });
    }
}
