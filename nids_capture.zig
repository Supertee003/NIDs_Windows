//! nids_capture.zig — AEGIS NIDS Packet Capture Layer (Layer 2: Zig)
//!
//! Consumes packets from the IPC Bridge DLL (C-ABI), runs them through
//! the C++ PacketParser for zero-copy field extraction, then feeds the
//! payload into the Aho-Corasick multi-pattern matcher for fast rule
//! matching. Matched packets are forwarded to the Rust shield layer
//! via C-ABI FFI for forensic hashing and safe shared-state access.
//!
//! Build: Zig 0.13+ (cross-compile for Windows x86_64)
//! Language: Zig

const std = @import("std");

// ═══════════════════════════════════════════════════════════
// [RUNTIME DYNAMIC LOADING] -- DLLs loaded via std.DynLib
// This allows the exe to start without aegis_ipc.dll, aegis_shield.dll, etc.
// Functions are resolved at runtime; if DLLs are missing, we degrade gracefully.
// ═══════════════════════════════════════════════════════════

var ipc_dll: ?std.DynLib = null;
var shield_dll: ?std.DynLib = null;
var parser_dll: ?std.DynLib = null;

// Function pointer types (matching the extern declarations)
const FnIpcInit = *const fn () i32;
const FnIpcReadPacket = *const fn (*AegisPktMeta, [*]u8, *u32) i32;
const FnIpcGetStats = *const fn (*u32, *u32) i32;
const FnIpcShutdown = *const fn () void;

const FnQuickClassify = *const fn ([*]const u8, u32, *u8, *u16, *u16) void;

const FnShieldSubmitPacket = *const fn (*const AegisPktMeta, [*]const u8, u32, [*]const u32, u32) i32;
const FnSemiNidsInit = *const fn () i32;
const FnSemiNidsEvaluate = *const fn (u32, u32, u16, u16, u8, f64, u8, u32, u32) u8;
const FnSemiNidsSetPolicy = *const fn (u64, u8) i32;
const FnSemiNidsGetPendingCount = *const fn () u32;
const FnSemiNidsFailOpenStatus = *const fn (*bool, *u8, *u8) u8;
const FnSemiNidsUpdateLoad = *const fn (u8, u8, u64) void;
const FnSemiNidsBlockIp = *const fn (u32, u32) i32;
const FnSemiNidsUnblockIp = *const fn (u32) i32;
const FnSemiNidsGetStats = *const fn (*SemiNidsStats) i32;
const FnSemiNidsMaintenance = *const fn () u32;
const FnSemiNidsShutdown = *const fn () void;
const FnCorrelationInit = *const fn () i32;

// Runtime-resolved function pointers (null = DLL not loaded)
var fn_ipc_init: ?FnIpcInit = null;
var fn_ipc_read_packet: ?FnIpcReadPacket = null;
var fn_ipc_get_stats: ?FnIpcGetStats = null;
var fn_ipc_shutdown: ?FnIpcShutdown = null;

var fn_quick_classify: ?FnQuickClassify = null;

var fn_shield_submit: ?FnShieldSubmitPacket = null;
var fn_semi_nids_init: ?FnSemiNidsInit = null;
var fn_semi_nids_evaluate: ?FnSemiNidsEvaluate = null;
var fn_semi_nids_set_policy: ?FnSemiNidsSetPolicy = null;
var fn_semi_nids_get_pending_count: ?FnSemiNidsGetPendingCount = null;
var fn_semi_nids_fail_open_status: ?FnSemiNidsFailOpenStatus = null;
var fn_semi_nids_update_load: ?FnSemiNidsUpdateLoad = null;
var fn_semi_nids_block_ip: ?FnSemiNidsBlockIp = null;
var fn_semi_nids_unblock_ip: ?FnSemiNidsUnblockIp = null;
var fn_semi_nids_get_stats: ?FnSemiNidsGetStats = null;
var fn_semi_nids_maintenance: ?FnSemiNidsMaintenance = null;
var fn_semi_nids_shutdown: ?FnSemiNidsShutdown = null;
var fn_correlation_init: ?FnCorrelationInit = null;

var dlls_loaded: bool = false;

fn loadDlls() void {
    if (dlls_loaded) return;
    dlls_loaded = true;

    const dll_search_paths = [_][]const u8{ "build", "build\\Release", "build\\Debug", ".", "zig-out\\bin" };

    // Load aegis_ipc.dll
    for (dll_search_paths) |dir| {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}\\aegis_ipc.dll", .{dir}) catch continue;
        ipc_dll = std.DynLib.open(path) catch null;
        if (ipc_dll) |*lib| {
            fn_ipc_init = lib.lookup(FnIpcInit, "aegis_ipc_init");
            fn_ipc_read_packet = lib.lookup(FnIpcReadPacket, "aegis_ipc_read_packet");
            fn_ipc_get_stats = lib.lookup(FnIpcGetStats, "aegis_ipc_get_stats");
            fn_ipc_shutdown = lib.lookup(FnIpcShutdown, "aegis_ipc_shutdown");
            std.log.info("Loaded: {s}", .{path});
            break;
        }
    }
    if (ipc_dll == null) std.log.warn("aegis_ipc.dll not found -- IPC bridge disabled", .{});

    // Load aegis_packet_parser.dll
    for (dll_search_paths) |dir| {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}\\aegis_packet_parser.dll", .{dir}) catch continue;
        parser_dll = std.DynLib.open(path) catch null;
        if (parser_dll) |*lib| {
            fn_quick_classify = lib.lookup(FnQuickClassify, "aegis_quick_classify");
            std.log.info("Loaded: {s}", .{path});
            break;
        }
    }
    if (parser_dll == null) std.log.warn("aegis_packet_parser.dll not found -- packet parser disabled", .{});

    // Load aegis_shield.dll
    for (dll_search_paths) |dir| {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}\\aegis_shield.dll", .{dir}) catch continue;
        shield_dll = std.DynLib.open(path) catch null;
        if (shield_dll) |*lib| {
            fn_shield_submit = lib.lookup(FnShieldSubmitPacket, "aegis_shield_submit_packet");
            fn_semi_nids_init = lib.lookup(FnSemiNidsInit, "aegis_semi_nids_init");
            fn_semi_nids_evaluate = lib.lookup(FnSemiNidsEvaluate, "aegis_semi_nids_evaluate");
            fn_semi_nids_set_policy = lib.lookup(FnSemiNidsSetPolicy, "aegis_semi_nids_set_policy");
            fn_semi_nids_get_pending_count = lib.lookup(FnSemiNidsGetPendingCount, "aegis_semi_nids_get_pending_count");
            fn_semi_nids_fail_open_status = lib.lookup(FnSemiNidsFailOpenStatus, "aegis_semi_nids_fail_open_status");
            fn_semi_nids_update_load = lib.lookup(FnSemiNidsUpdateLoad, "aegis_semi_nids_update_load");
            fn_semi_nids_block_ip = lib.lookup(FnSemiNidsBlockIp, "aegis_semi_nids_block_ip");
            fn_semi_nids_unblock_ip = lib.lookup(FnSemiNidsUnblockIp, "aegis_semi_nids_unblock_ip");
            fn_semi_nids_get_stats = lib.lookup(FnSemiNidsGetStats, "aegis_semi_nids_get_stats");
            fn_semi_nids_maintenance = lib.lookup(FnSemiNidsMaintenance, "aegis_semi_nids_maintenance");
            fn_semi_nids_shutdown = lib.lookup(FnSemiNidsShutdown, "aegis_semi_nids_shutdown");
            fn_correlation_init = lib.lookup(FnCorrelationInit, "aegis_correlation_init");
            std.log.info("Loaded: {s}", .{path});
            break;
        }
    }
    if (shield_dll == null) std.log.warn("aegis_shield.dll not found -- Rust shield disabled (fail-open)", .{});
}

fn closeDlls() void {
    if (ipc_dll) |*lib| lib.close();
    if (parser_dll) |*lib| lib.close();
    if (shield_dll) |*lib| lib.close();
    ipc_dll = null;
    parser_dll = null;
    shield_dll = null;
}

// Wrapper functions that call through runtime-resolved pointers
// (graceful fallback when DLLs are not available)

fn ipc_init() i32 {
    if (fn_ipc_init) |f| return f();
    return -1; // DLL not loaded
}

fn ipc_read_packet(out_meta: *AegisPktMeta, out_buf: [*]u8, buf_size: *u32) i32 {
    if (fn_ipc_read_packet) |f| return f(out_meta, out_buf, buf_size);
    return -1; // DLL not loaded
}

fn ipc_get_stats(out_packets: *u32, out_dropped: *u32) i32 {
    if (fn_ipc_get_stats) |f| return f(out_packets, out_dropped);
    return -1;
}

fn ipc_shutdown() void {
    if (fn_ipc_shutdown) |f| f();
}

fn shield_submit_packet(meta: *const AegisPktMeta, payload: [*]const u8, payload_len: u32, pattern_ids: [*]const u32, pattern_count: u32) i32 {
    if (fn_shield_submit) |f| return f(meta, payload, payload_len, pattern_ids, pattern_count);
    return 0; // DLL not loaded -- pass
}

fn semi_nids_evaluate(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, ip_proto: u8, threat_score: f64, confidence: u8, risk_flags: u32, process_id: u32) u8 {
    if (fn_semi_nids_evaluate) |f| return f(src_ip, dst_ip, src_port, dst_port, ip_proto, threat_score, confidence, risk_flags, process_id);
    return 0; // DLL not loaded -- default: Pass
}

fn semi_nids_init() i32 {
    if (fn_semi_nids_init) |f| return f();
    return 0; // DLL not loaded -- OK (fail-open)
}

fn correlation_init() i32 {
    if (fn_correlation_init) |f| return f();
    return 0; // DLL not loaded -- OK
}

fn semi_nids_shutdown() void {
    if (fn_semi_nids_shutdown) |f| f();
}

fn semi_nids_get_stats(out_stats: *SemiNidsStats) i32 {
    if (fn_semi_nids_get_stats) |f| return f(out_stats);
    return -1;
}


// ─── C-ABI Imports from IPC Bridge (aegis_ipc.dll) ───
pub const AegisPktMeta = extern struct {
    size: u32,
    orig_len: u32,
    timestamp: u64,
    layer_id: u16,
    direction: u16,
    process_id: u32,
    ip_proto: u16,
    _pad: u16,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    // Semi-NIDS fields (set by Rust correlation, read by WFP kernel)
    threat_score: i32,   // Threat score 0-100 (x10 fixed-point: 600 = 60.0)
    confidence: u8,     // 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical
    risk_flags: u32,    // Bitfield of matched detection rules
};


// ─── C-ABI Imports from Packet Parser (aegis_packet_parser.dll) ───

// ─── C-ABI Import from Rust Shield (libaegis_shield.so/.dll) ───

// ─── C-ABI Imports from Rust Semi-NIDS Engine (aegis_shield) ───
/// Semi-NIDS decision codes — must match Rust SemiNidsDecision enum
const SemiNidsDecision = enum(u8) {
    Pass = 0,
    AlertOnly = 1,
    RateLimit = 2,
    Block = 3,
    BlockAndPreserve = 4,
    PendingHuman = 5,
};

// SemiNidsStats struct — must match Rust SemiNidsStats #[repr(C)] layout exactly
pub const SemiNidsStats = extern struct {
    total_evaluated: u64,
    total_passed: u64,
    total_alerted: u64,
    total_blocked: u64,
    total_rate_limited: u64,
    total_fail_open_passes: u64,
    total_human_decisions: u64,
    permanent_blocks: u32,
    temporary_blocks: u32,
    fail_open_active: bool,
    load_state: u8,       // LoadState enum: 0-3
    current_pps: u64,
};


// ─── C-ABI Import from Rust Correlation Engine (aegis_shield) ───

// ─── Constants ───
const MAX_PAYLOAD_SIZE: u32 = 65535;
const MAX_PATTERN_MATCHES: usize = 64;
const AHOCORASICK_MAX_STATES: usize = 65536;
const AHOCORASICK_ALPHABET: usize = 256;
const CAPTURE_BATCH_SIZE: usize = 256;

// ─── Aho-Corasick Automaton ───
/// Multi-pattern string matching automaton for fast intrusion signature
/// detection. Precomputed goto/failure/output functions enable O(n)
/// scanning where n = payload length, independent of pattern count.
pub const AhoCorasick = struct {
    goto_fn: [][AHOCORASICK_ALPHABET]u16,
    failure: []u16,
    output: []std.DynamicBitSet,
    state_count: u16,
    pattern_count: u16,  // Total patterns added
    /// Maps terminal state → pattern ID. Indexed by state, value = pattern ID.
    /// Used during build() to populate output sets.
    terminal_pattern: []u16,
    allocator: std.mem.Allocator,


    /// init - Create empty automaton. Call addPattern() then build().
    fn init(allocator: std.mem.Allocator) !AhoCorasick {
        // Allocate large arrays on the HEAP to avoid stack overflow
        const goto_fn = try allocator.alloc([AHOCORASICK_ALPHABET]u16, AHOCORASICK_MAX_STATES);
        const failure = try allocator.alloc(u16, AHOCORASICK_MAX_STATES);
        const terminal_pattern = try allocator.alloc(u16, AHOCORASICK_MAX_STATES);

        @memset(failure, 0);
        @memset(terminal_pattern, 0);
        // Zero only goto_fn[0] (root state); rest left undefined until build()
        @memset(&goto_fn[0], 0);

        return .{
            .goto_fn = goto_fn,
            .failure = failure,
            .output = undefined,
            .state_count = 1, // State 0 = root
            .pattern_count = 0,
            .terminal_pattern = terminal_pattern,
            .allocator = allocator,
        };
    }

    /// addPattern - Add a pattern to the automaton (trie construction).
    /// Returns the pattern ID (0-indexed). The terminal state is recorded
    /// internally for output set population during build().
    fn addPattern(self: *AhoCorasick, pattern: []const u8) !u16 {
        const pat_id = self.pattern_count;
        var state: u16 = 0;
        for (pattern) |ch| {
            const next = self.goto_fn[state][ch];
            if (next == 0 and state != 0) {
                // New state needed
                if (self.state_count >= AHOCORASICK_MAX_STATES) return error.TooManyStates;
                const new_state = self.state_count;
                self.state_count += 1;

                self.goto_fn[state][ch] = new_state;
                @memset(&self.goto_fn[new_state], 0); // New state: all transitions → 0
                state = new_state;
            } else {
                state = if (next != 0) next else blk: {
                    // Root state: create new state for this character
                    if (self.state_count >= AHOCORASICK_MAX_STATES) return error.TooManyStates;
                    const new_state = self.state_count;
                    self.state_count += 1;
                    self.goto_fn[state][ch] = new_state;
                    @memset(&self.goto_fn[new_state], 0);
                    break :blk new_state;
                };
            }
        }
        // Record: this pattern (pat_id) ends at this terminal state
        self.terminal_pattern[state] = pat_id + 1; // +1 so 0 means "no pattern ends here"
        self.pattern_count += 1;
        return pat_id;
    }

    /// build - Compute failure links and output sets (BFS).
    /// Must be called after all patterns are added.
    /// FIX: Now properly populates output sets from terminal_pattern.
    fn build(self: *AhoCorasick) !void {
        // Allocate output bitsets
        self.output = try self.allocator.alloc(std.DynamicBitSet, self.state_count);
        for (self.output[0..self.state_count]) |*bs| {
            bs.* = try std.DynamicBitSet.initEmpty(self.allocator, 256);
        }

        // ── CRITICAL FIX: Populate output sets from terminal states ──
        // For each state that is a terminal state for some pattern,
        // set the corresponding pattern ID bit in the output set.
        for (0..self.state_count) |s| {
            if (self.terminal_pattern[s] != 0) {
                const pat_id: usize = self.terminal_pattern[s] - 1; // Undo +1 from addPattern
                self.output[s].set(pat_id);
            }
        }

        // BFS queue for failure link computation
        var queue = std.fifo.LinearFifo(u16, .Dynamic).init(self.allocator);
        defer queue.deinit();

        // Depth-1 states: failure = 0 (root)
        for (0..AHOCORASICK_ALPHABET) |ch| {
            const s = self.goto_fn[0][ch];
            if (s != 0) {
                self.failure[s] = 0;
                try queue.writeItem(s);
            }
        }

        // BFS for deeper states
        while (queue.readItem()) |r| {
            for (0..AHOCORASICK_ALPHABET) |ch| {
                const s = self.goto_fn[r][ch];
                if (s != 0) {
                    // Compute failure link: follow failure chain from r
                    var f = self.failure[r];
                    while (f != 0 and self.goto_fn[f][ch] == 0) {
                        f = self.failure[f];
                    }
                    self.failure[s] = if (self.goto_fn[f][ch] != s) self.goto_fn[f][ch] else 0;

                    // Merge output sets: output(s) = output(s) ∪ output(failure(s))
                    self.output[s].setUnion(self.output[self.failure[s]]);
                    try queue.writeItem(s);
                } else {
                    // Compress goto: transition to failure chain result
                    self.goto_fn[r][ch] = self.goto_fn[self.failure[r]][ch];
                }
            }
        }
    }

    /// scan - Scan payload and return matched pattern IDs.
    /// Returns slice of pattern IDs that matched (caller-owned).
    fn scan(self: *const AhoCorasick, payload: []const u8, out_matches: []u32) u32 {
        var state: u16 = 0;
        var match_count: u32 = 0;

        for (payload) |byte| {
            state = self.goto_fn[state][byte];

            // Check output set for this state
            var iter = self.output[state].iterator(.{});
            while (iter.next()) |pat_id| {
                if (match_count < out_matches.len) {
                    out_matches[match_count] = @intCast(pat_id);
                    match_count += 1;
                }
            }
        }

        return match_count;
    }

    fn deinit(self: *AhoCorasick) void {
        self.allocator.free(self.goto_fn);
        self.allocator.free(self.failure);
        self.allocator.free(self.terminal_pattern);
        for (self.output[0..self.state_count]) |*bs| {
            bs.deinit();
        }
        self.allocator.free(self.output);
    }
};

// ─── Packet Batch Buffer ───
pub const PacketBatch = struct {
    metas: []AegisPktMeta,
    payloads: [][MAX_PAYLOAD_SIZE]u8,
    payload_lens: []u32,
    count: usize,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !PacketBatch {
        return .{
            .metas = try allocator.alloc(AegisPktMeta, CAPTURE_BATCH_SIZE),
            .payloads = try allocator.alloc([MAX_PAYLOAD_SIZE]u8, CAPTURE_BATCH_SIZE),
            .payload_lens = try allocator.alloc(u32, CAPTURE_BATCH_SIZE),
            .count = 0,
            .allocator = allocator,
        };
    }

    fn reset(self: *PacketBatch) void {
        self.count = 0;
    }

    fn deinit(self: *PacketBatch) void {
        self.allocator.free(self.metas);
        self.allocator.free(self.payloads);
        self.allocator.free(self.payload_lens);
    }
};

// ─── Detection Alert ───
pub const Alert = struct {
    timestamp: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
    pattern_ids: [MAX_PATTERN_MATCHES]u32,
    pattern_count: u32,
    severity: u8, // 0=info, 1=low, 2=medium, 3=high, 4=critical
};

// ─── Capture Engine ───
pub const CaptureEngine = struct {
    allocator: std.mem.Allocator,
    ac: AhoCorasick,
    batch: PacketBatch,
    alert_count: u64,
    packet_count: u64,
    running: bool,


    fn init(allocator: std.mem.Allocator, patterns: []const []const u8) !CaptureEngine {
        var ac = try AhoCorasick.init(allocator);
        for (patterns) |pat| {
            _ = try ac.addPattern(pat);
        }
        try ac.build();

        return .{
            .allocator = allocator,
            .ac = ac,
            .batch = try PacketBatch.init(allocator),
            .alert_count = 0,
            .packet_count = 0,
            .running = false,
        };
    }

    /// readBatch - Read up to CAPTURE_BATCH_SIZE packets from IPC bridge.
    fn readBatch(self: *CaptureEngine) u32 {
        self.batch.reset();
        var read_count: u32 = 0;

        while (read_count < CAPTURE_BATCH_SIZE) {
            var buf_size: u32 = MAX_PAYLOAD_SIZE;
            const rc = ipc_read_packet(
                &self.batch.metas[read_count],
                &self.batch.payloads[read_count],
                &buf_size,
            );
            if (rc <= 0) break; // 0 = empty, -1 = error
            self.batch.payload_lens[read_count] = buf_size;
            read_count += 1;
        }

        self.batch.count = @intCast(read_count);
        self.packet_count += read_count;
        return read_count;
    }

    /// processBatch - Run Aho-Corasick on each packet in the batch.
    /// Matched packets are:
    ///   1. Evaluated by the Rust Semi-NIDS engine for adaptive decision
    ///   2. Forwarded to Rust shield for forensic hashing
    ///   3. Decision is stored back in meta for WFP kernel to consume
    fn processBatch(self: *CaptureEngine) !void {
        var pattern_ids: [MAX_PATTERN_MATCHES]u32 = undefined;

        for (0..self.batch.count) |i| {
            const meta = &self.batch.metas[i];
            const payload = self.batch.payloads[i][0..self.batch.payload_lens[i]];

            // Fast Aho-Corasick scan
            const match_count = self.ac.scan(payload, &pattern_ids);

            if (match_count > 0) {
                self.alert_count += 1;

                // ── Step 1: Compute threat score from pattern matches ──
                // Each pattern match contributes to the score. Simple heuristic:
                // score = min(100, match_count * 15 + sum_severity * 5)
                var base_score: f64 = @floatFromInt(match_count * 15);
                if (base_score > 100.0) base_score = 100.0;

                // ── Step 2: Determine confidence from match count ──
                // 1 match = Low, 2-3 = Medium, 4+ = High, known exploit sig = Critical
                const confidence: u8 = if (match_count >= 4) 3 // High
                                      else if (match_count >= 2) 2 // Medium
                                      else 1; // Low

                // ── Step 3: Build risk_flags from pattern IDs ──
                var risk_flags: u32 = 0;
                for (pattern_ids[0..match_count]) |pid| {
                    risk_flags |= @as(u32, 1) << @intCast(pid % 32);
                }

                // ── Step 4: Ask Rust Semi-NIDS engine for adaptive decision ──
                // This implements Property 1 (threshold-based dropping) and
                // Property 2 (fail-open graceful degradation)
                const decision_raw = semi_nids_evaluate(
                    meta.src_ip,
                    meta.dst_ip,
                    meta.src_port,
                    meta.dst_port,
                    @as(u8, @intCast(meta.ip_proto)),
                    base_score,
                    confidence,
                    risk_flags,
                    meta.process_id,
                );

                // ── Step 5: Store decision back in AegisPktMeta ──
                // WFP kernel driver reads these fields for enforcement
                meta.threat_score = @intFromFloat(base_score * 10.0); // x10 fixed-point
                meta.confidence = confidence;
                meta.risk_flags = risk_flags;

                // ── Step 6: Forward to Rust shield for forensic hashing ──
                _ = shield_submit_packet(
                    meta,
                    &self.batch.payloads[i],
                    self.batch.payload_lens[i],
                    &pattern_ids,
                    match_count,
                );

                // ── Step 7: Log decision for monitoring ──
                const decision_name = switch (decision_raw) {
                    0 => "PASS",
                    1 => "ALERT_ONLY",
                    2 => "RATE_LIMIT",
                    3 => "BLOCK",
                    4 => "BLOCK_PRESERVE",
                    5 => "PENDING_HUMAN",
                    else => "UNKNOWN",
                };
                std.log.debug("Semi-NIDS: {s} → {d} (score={d:.0}, conf={d}, flags=0x{x})", .{
                    decision_name, meta.src_ip, base_score, confidence, risk_flags,
                }
                    );
            }
        }
    }

    /// run - Main capture loop. Reads batches and processes until stopped.
    fn run(self: *CaptureEngine) !void {
        self.running = true;
        std.log.info("AEGIS Capture: Starting main loop", .{});

        while (self.running) {
            const count = self.readBatch();
            if (count > 0) {
                try self.processBatch();
            } else {
                // No packets — brief sleep to avoid busy-wait
                std.time.sleep(1_000); // 1 μs
            }
        }

        std.log.info("AEGIS Capture: Stopped — {d} packets, {d} alerts", .{
            self.packet_count, self.alert_count,
        }
            );
    }

    fn stop(self: *CaptureEngine) void {
        self.running = false;
    }

    fn deinit(self: *CaptureEngine) void {
        self.batch.deinit();
        self.ac.deinit();
    }
};

// ─── Global Engine Instance ───
var g_engine: ?CaptureEngine = null;

// ─── Public API ───
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8) !void {
    loadDlls();
    // Initialize IPC bridge
    const ipc_rc = ipc_init();
    if (ipc_rc != 0) std.log.warn("IPC bridge init failed (rc={d}), running without IPC", .{ipc_rc});

    // Initialize Rust Semi-NIDS engine (adaptive drop + fail-open + human-in-loop)
    const semi_rc = semi_nids_init();
    if (semi_rc != 0) std.log.warn("Semi-NIDS init failed (rc={d}), running in fail-open mode", .{semi_rc});

    // Initialize Rust Correlation engine (cross-vector scoring)
    const corr_rc = correlation_init();
    if (corr_rc != 0) std.log.warn("Correlation init failed (rc={d}), running without correlation", .{corr_rc});

    g_engine = try CaptureEngine.init(allocator, patterns);
}

pub fn run() !void {
    if (g_engine) |*eng| {
        try eng.run();
    } else {
        return error.NotInitialized;
    }
}

pub fn stop() void {
    if (g_engine) |*eng| {
        eng.stop();
    }
}

pub fn deinit() void {
    if (g_engine) |*eng| {
        eng.deinit();
    }
    semi_nids_shutdown();
    ipc_shutdown();
    g_engine = null;
}

pub fn getStats() struct { packets: u64, alerts: u64, blocked: u64, pending: u64, fail_open: u64 } {
    var total: u64 = 0;
    var blocked: u64 = 0;
    var alerts: u64 = 0;
    var pending: u64 = 0;
    var fail_open: u64 = 0;
    _ = semi_nids_get_stats(&total, &blocked, &alerts, &pending, &fail_open);

    if (g_engine) |eng| {
        return .{ .packets = eng.packet_count, .alerts = eng.alert_count, .blocked = blocked, .pending = pending, .fail_open = fail_open };
    }
    return .{ .packets = 0, .alerts = 0, .blocked = blocked, .pending = pending, .fail_open = fail_open };
}

// ─── Tests ───
test "AhoCorasick basic matching" {
    const testing = std.testing;
    var ac = try AhoCorasick.init(testing.allocator);
    defer ac.deinit();

    _ = try ac.addPattern("he");
    _ = try ac.addPattern("she");
    _ = try ac.addPattern("his");
    _ = try ac.addPattern("hers");
    try ac.build();

    var matches: [64]u32 = undefined;
    const count = ac.scan("ushers", &matches);
    try testing.expect(count >= 2); // Should match "she" and "he" and "hers"
}
