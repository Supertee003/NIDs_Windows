const std = @import("std");
const net = std.net;
const win = std.os.windows;
const posix = std.posix;

// =================================================================
// [ HELPERS: case-insensitive compare ]
// =================================================================
fn ascii_eq_ignore_case(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        const lx = if (x >= 'A' and x <= 'Z') x + 32 else x;
        const ly = if (y >= 'A' and y <= 'Z') y + 32 else y;
        if (lx != ly) return false;
    }
    return true;
}

/// ตรวจว่า action เป็น "block" (Block / BLOCK / block) — ใช้สำหรับ IPS decision
fn is_block_action(action: []const u8) bool {
    return ascii_eq_ignore_case(action, "block") or ascii_eq_ignore_case(action, "drop");
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

// =================================================================
// [ EVENT MODEL — 3-LAYER UNIFIED HEADER ]
//   ใช้ร่วมกับ kernel AEGIS_EVENT_HEADER (WFP + Minifilter) และ
//   user-mode sources (TCP socket, named pipe IPC, pipe monitor)
// =================================================================

/// Event source types — ตรงกับ kernel AEGIS_EVENT_TYPE enum
pub const EventSource = enum(u32) {
    TCP_SOCKET      = 0,
    WFP_PACKET      = 1,
    KERNEL_FILE     = 2,
    KERNEL_PROCESS  = 3,
    KERNEL_REGISTRY = 4,
    PIPE_MONITOR    = 5,
    PIPE_IPC        = 6,
};

/// แปลง EventSource → layer string ที่ใช้ใน Rules.json
pub fn layer_name_for_source(source: EventSource) []const u8 {
    return switch (source) {
        .TCP_SOCKET, .WFP_PACKET, .PIPE_IPC => "NETWORK",
        .KERNEL_FILE      => "KERNEL_FILE",
        .KERNEL_PROCESS   => "KERNEL_PROCESS",
        .KERNEL_REGISTRY  => "KERNEL_REGISTRY",
        .PIPE_MONITOR     => "PIPE_MONITOR",
    };
}

/// Unified event header — ตรงกับ kernel AEGIS_EVENT_HEADER (packed, little-endian)
///   ขนาดรวม = 40 bytes (ตรงกับฝั่ง C)
pub const EventHeader = extern struct {
    event_type: u32,        // EventSource
    event_size: u32,        // total size including payload
    timestamp: u64,         // nanoseconds since epoch
    process_id: u32,        // PID
    // Network fields (zero if N/A)
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,           // TCP=6, UDP=17
    direction: u8,          // 0=inbound, 1=outbound
    payload_length: u16,
    // Extended fields for file/process events
    path_offset: u16,       // offset within payload where path string starts
    path_length: u16,       // length of path string
    operation: u16,         // IRP_MJ_CREATE=0, IRP_MJ_WRITE=1, etc.
    _reserved: u16,
};

pub const EVENT_HEADER_SIZE = @sizeOf(EventHeader);

/// IOCTL codes — ตรงกับฝั่ง kernel driver (aegis_wfp.h)
pub const IOCTL_AEGIS_READ_EVENTS: u32 = 0x222000; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
pub const IOCTL_AEGIS_BLOCK_FLOW: u32  = 0x222004; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
pub const IOCTL_AEGIS_GET_STATS: u32   = 0x222008; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

pub const SecureRule = struct {
    name: []const u8,
    layer: []const u8,           // "NETWORK", "KERNEL_FILE", "KERNEL_PROCESS", "KERNEL_REGISTRY", "PIPE_MONITOR"
    fast_pattern: []const u8,
    match_pattern: []const u8,
    regex_pattern: []const u8,
    severity: []const u8,
    action: []const u8,
    crc32: u32,
    // Optional extended fields (allocated by rule loader)
    file_operations: ?[][]const u8 = null,
    parent_exclude: ?[][]const u8 = null,
};

pub const SecureRuleSet = struct {
    allocator: std.mem.Allocator,
    signatures: []const SecureRule = &[_]SecureRule{},
    ac_engine: AhoCorasick,

    pub fn deinit(self: *SecureRuleSet) void {
        for (self.signatures) |sig| {
            self.allocator.free(sig.name);
            self.allocator.free(sig.layer);
            self.allocator.free(sig.fast_pattern);
            self.allocator.free(sig.match_pattern);
            self.allocator.free(sig.regex_pattern);
            self.allocator.free(sig.severity);
            self.allocator.free(sig.action);
            if (sig.file_operations) |ops| {
                for (ops) |op| self.allocator.free(op);
                self.allocator.free(ops);
            }
            if (sig.parent_exclude) |ex| {
                for (ex) |e| self.allocator.free(e);
                self.allocator.free(ex);
            }
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

    // รองรับ field ใหม่: layer, file_operations, parent_exclude
    const TempRule = struct {
        name: []const u8,
        layer: []const u8 = "NETWORK",
        fast_pattern: []const u8 = "",
        match_pattern: []const u8 = "",
        regex_pattern: []const u8 = "",
        severity: []const u8 = "Alert",
        action: []const u8 = "Alert",
        file_operations: ?[][]const u8 = null,
        parent_exclude: ?[][]const u8 = null,
    };
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
            allocator.free(sig.layer);
            allocator.free(sig.fast_pattern);
            allocator.free(sig.match_pattern);
            allocator.free(sig.regex_pattern);
            allocator.free(sig.severity);
            allocator.free(sig.action);
            if (sig.file_operations) |ops| {
                for (ops) |op| allocator.free(op);
                allocator.free(ops);
            }
            if (sig.parent_exclude) |ex| {
                for (ex) |e| allocator.free(e);
                allocator.free(ex);
            }
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

        // Deep-copy optional slices เพราะ JSON parser จะ deinit หลัง function return
        const file_ops_copy: ?[][]const u8 = if (sig.file_operations) |ops| blk: {
            const arr = try allocator.alloc([]const u8, ops.len);
            for (ops, 0..) |op, i| arr[i] = try allocator.dupe(u8, op);
            break :blk arr;
        } else null;
        const parent_excl_copy: ?[][]const u8 = if (sig.parent_exclude) |ex| blk: {
            const arr = try allocator.alloc([]const u8, ex.len);
            for (ex, 0..) |e, i| arr[i] = try allocator.dupe(u8, e);
            break :blk arr;
        } else null;

        try temp_sig_list.append(.{
            .name = try allocator.dupe(u8, sig.name),
            .layer = try allocator.dupe(u8, sig.layer),
            .fast_pattern = try allocator.dupe(u8, active_fast_pattern),
            .match_pattern = try allocator.dupe(u8, sig.match_pattern),
            .regex_pattern = try allocator.dupe(u8, sig.regex_pattern),
            .severity = try allocator.dupe(u8, sig.severity),
            .action = try allocator.dupe(u8, sig.action),
            .crc32 = hash.final(),
            .file_operations = file_ops_copy,
            .parent_exclude = parent_excl_copy,
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

/// Core network-packet inspection (TIER 1: Rust shield → AC → TIER 2: AND match)
/// คืนค่า true = ปลอดภัย (ผ่านได้), false = อันตราย (block)
fn inspect_network_payload(data: []const u8, source: EventSource) !bool {
    // 🛡️ [ด่านหน้าสุด: RUST MEMORY SAFETY CHECK] 🛡️
    if (!validate_payload_safety(data.ptr, data.len)) return false;

    const current_ruleset = active_ruleset.load(.acquire) orelse return false;
    const allocator = current_ruleset.allocator;

    const expected_layer = layer_name_for_source(source);

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

                // กรอง rule ตาม layer — ถ้า layer ไม่ตรงกับ source ให้ข้าม
                if (!ascii_eq_ignore_case(rule.layer, expected_layer) and
                    !ascii_eq_ignore_case(rule.layer, "NETWORK"))
                {
                    continue;
                }

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
        const alert = .{
            .timestamp = std.time.timestamp(),
            .attack_type = rule.name,
            .policy = rule.action,
            .reason = "Tier-1 Fast Pattern Match",
            .source = @tagName(source),
            .layer = rule.layer,
            .raw_payload = data,
        };

        try send_to_brain(allocator, alert);

        if (is_block_action(rule.action)) {
            if (global_attacker_tracker.step1_markSuspicious()) {
                _ = global_attacker_tracker.step2_verifyThreat();
                std.debug.print("\x1b[31;1m[ AEGIS CORE ] !!! BLOCK !!! {s} terminated: {s}\x1b[0m\n", .{ @tagName(source), rule.name });
                return false;
            }
            return false;
        }
        return true;
    } else {
        // Forward ไปให้ Brain ตรวจ Regex ต่อ
        const forward_msg = .{
            .timestamp = std.time.timestamp(),
            .attack_type = "Unmatched: Deep Inspection Required",
            .policy = "Pending",
            .reason = "Forwarded: No Tier-1 Match",
            .source = @tagName(source),
            .layer = expected_layer,
            .raw_payload = data,
        };
        try send_to_brain(allocator, forward_msg);
        return true;
    }
}

/// Path-based inspection สำหรับ kernel file/process/registry events
/// ใช้ substring match แบบ case-insensitive บน `path`
fn inspect_path_event(path: []const u8, source: EventSource, operation: u16) !bool {
    const current_ruleset = active_ruleset.load(.acquire) orelse return true;
    const allocator = current_ruleset.allocator;
    const expected_layer = layer_name_for_source(source);

    for (current_ruleset.signatures) |*rule| {
        // กรองเฉพาะ rule ของ layer นี้
        if (!ascii_eq_ignore_case(rule.layer, expected_layer)) continue;

        // ถ้า rule ระบุ file_operations ให้ตรวจ operation ตรงด้วย
        if (rule.file_operations) |ops| {
            var op_match = false;
            // operation: 0=CREATE, 1=WRITE, 2=RENAME, 3=DELETE
            const op_name: []const u8 = switch (operation) {
                0 => "CREATE",
                1 => "WRITE",
                2 => "RENAME",
                3 => "DELETE",
                else => "OTHER",
            };
            for (ops) |op| {
                if (ascii_eq_ignore_case(op, op_name)) {
                    op_match = true;
                    break;
                }
            }
            if (!op_match) continue;
        }

        // ตรวจ match_pattern เป็น list คั่นด้วย | แบบ case-insensitive substring
        if (rule.match_pattern.len == 0) continue;
        var match_iter = std.mem.splitSequence(u8, rule.match_pattern, "|");
        var any_match = false;
        while (match_iter.next()) |keyword| {
            if (keyword.len == 0) continue;
            if (contains_ignore_case(path, keyword)) {
                any_match = true;
                break;
            }
        }
        if (!any_match) continue;

        // Match! ส่ง alert ไป Brain
        const alert = .{
            .timestamp = std.time.timestamp(),
            .attack_type = rule.name,
            .policy = rule.action,
            .reason = "Kernel Path Match",
            .source = @tagName(source),
            .layer = rule.layer,
            .path = path,
            .operation = operation,
        };
        try send_to_brain(allocator, alert);

        std.debug.print("\x1b[33;1m[AEGIS KERNEL] {s} match: {s} (rule={s})\x1b[0m\n", .{ @tagName(source), path, rule.name });

        if (is_block_action(rule.action)) {
            return false;
        }
        return true;
    }

    // ไม่ match — อนุญาต
    return true;
}

/// Case-insensitive substring search
fn contains_ignore_case(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |n, j| {
            const h = haystack[i + j];
            const lh = if (h >= 'A' and h <= 'Z') h + 32 else h;
            const ln = if (n >= 'A' and n <= 'Z') n + 32 else n;
            if (lh != ln) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// ====================================================================
/// [ UNIFIED EVENT INSPECTOR — รองรับทุก source type ]
///
///   header : pointer ไปยัง EventHeader (อาจเป็น packed struct จาก kernel)
///   payload: payload bytes ที่ตามหลัง header (อาจเป็น network packet หรือ path+data)
///
///   return: true = ปลอดภัย (อนุญาต), false = อันตราย (block)
/// ====================================================================
pub fn inspect_event(header: *const EventHeader, payload: []const u8) !bool {
    if (header.event_size < EVENT_HEADER_SIZE) return true;
    const source = std.meta.intToEnum(EventSource, header.event_type) catch {
        std.debug.print("[AEGIS] Unknown event_type: {d}, treating as safe\n", .{header.event_type});
        return true;
    };

    switch (source) {
        .TCP_SOCKET, .WFP_PACKET, .PIPE_IPC => {
            // Network/IPC events: ใช้ flow เดิม (Rust shield → AC → AND → Brain)
            // ใช้ payload_length จาก header ถ้ามีข้อมูล
            const len = if (header.payload_length > 0 and header.payload_length <= payload.len)
                header.payload_length
            else
                @as(u16, @intCast(@min(payload.len, 65535)));
            return inspect_network_payload(payload[0..len], source);
        },
        .KERNEL_FILE, .KERNEL_PROCESS, .KERNEL_REGISTRY => {
            // Path-based events: ดึง path จาก payload โดยใช้ path_offset + path_length
            if (header.path_length == 0) return true;
            const end = @as(usize, header.path_offset) + @as(usize, header.path_length);
            if (end > payload.len) return true;
            const path = payload[header.path_offset..end];
            return inspect_path_event(path, source, header.operation);
        },
        .PIPE_MONITOR => {
            // Pipe monitor: ใช้ path (pipe name) เป็นเกณฑ์ — reuse inspect_path_event
            if (header.path_length == 0) return true;
            const end = @as(usize, header.path_offset) + @as(usize, header.path_length);
            if (end > payload.len) return true;
            const pipe_name = payload[header.path_offset..end];
            return inspect_path_event(pipe_name, .PIPE_MONITOR, header.operation);
        },
    }
}

/// Backward-compatible wrapper สำหรับ code เดิม (TCP/pipe IPC)
/// สร้าง synthetic EventHeader แล้วเรียก inspect_event
pub fn inspect_packet(data: []const u8, is_pipe: bool) !bool {
    std.debug.print("[DEBUG] Analyzing data ({s}), size: {} bytes\n", .{ if (is_pipe) "PIPE_IPC" else "TCP_SOCKET", data.len });

    var header = std.mem.zeroes(EventHeader);
    header.event_type = if (is_pipe) @intFromEnum(EventSource.PIPE_IPC) else @intFromEnum(EventSource.TCP_SOCKET);
    header.event_size = @intCast(EVENT_HEADER_SIZE + data.len);
    header.timestamp = @intCast(std.time.nanoTimestamp());
    header.payload_length = @intCast(@min(data.len, 65535));
    return inspect_event(&header, data);
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
    udp_log_addr = net.Address.parseIp4("127.0.0.1", 9999) catch unreachable;
    udp_log_sock = posix.socket(udp_log_addr.any.family, posix.SOCK.DGRAM, 0) catch unreachable;

    reload_rules_atomic(allocator) catch |err| {
        std.debug.print("Failed to load rules: {}\n", .{err});
    };

    const t_pipe = std.Thread.spawn(.{}, pipe_listener, .{}) catch return;
    const t_tcp = std.Thread.spawn(.{}, tcp_listener, .{}) catch return;
    t_pipe.join();
    t_tcp.join();
}
