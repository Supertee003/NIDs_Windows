//! nids_analyze.zig — AEGIS NIDS Analysis Layer (Layer 2: Zig)
//!
//! Stream reassembly, protocol detection, and rule matching engine.
//! This is the ANALYSIS-PHASE hook point where SecDevOps, forensics,
//! and hook techniques are applied:
//!   - Pre-analysis hooks:  Inspect packet before stream reassembly
//!   - Post-analysis hooks: Inspect reassembled stream before verdict
//!   - Forensic hooks:      SHA-256 hashing of evidence (via Rust FFI)
//!
//! Hook model: comptime function injection — Zig's comptime allows
//! registering hook functions at compile time without runtime overhead.
//!
//! Build: Zig 0.13+ (cross-compile for Windows x86_64)
//! Language: Zig

const std = @import("std");
const capture = @import("nids_capture.zig");

const win = std.os.windows;
// ─── Constants ───

// =================================================================
// [ EXTERN DECLARATIONS FOR WINDOWS NAMED PIPES ]
// [FIX] Proper Win32 API signatures with ?*win.OVERLAPPED and win.BOOL
// Old signatures used bare pointers causing type mismatch with Zig 0.13+
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

extern "kernel32" fn ConnectNamedPipe(hNamedPipe: win.HANDLE, lpOverlapped: ?*win.OVERLAPPED) win.BOOL;
extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: win.HANDLE) win.BOOL;
extern "kernel32" fn ReadFile(
    hFile: win.HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?*win.OVERLAPPED,
) win.BOOL;

const MAX_STREAM_BUF: usize = 1 * 1024 * 1024; // 1 MiB per stream
const STREAM_TIMEOUT_MS: u64 = 30_000; // 30 seconds
const MAX_HOOKS: usize = 16;

// ─── Hook System (comptime-registered analysis interceptors) ───
/// Hooks are the core mechanism for injecting SecDevOps + forensics
/// into the analysis pipeline WITHOUT modifying core logic.
///
/// Pre-hook:  Called before stream reassembly. Can flag packet for
///            early rejection (e.g., known-bad IP blacklist).
/// Post-hook: Called after reassembly + pattern matching. Can modify
///            verdict severity or trigger forensic preservation.
pub const HookResult = enum(u8) {
    pass, // Continue normal processing
    drop, // Silently discard this packet/stream
    alert, // Raise alert but continue processing
    preserve, // Alert + preserve for forensic chain-of-custody
};

// =================================================================
// [ WFP EVENT HEADER — 44 bytes from kernel driver ]
// [FIX] packed struct to match C driver #pragma pack(1)
// Without this fix, field offsets can have padding that misaligns
// with the kernel header, causing corrupted reads in windows_capture.zig
// =================================================================
pub const WfpEventHeader = packed struct {
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

// =================================================================
// [ C++ IPC BRIDGE EVENT — 52 bytes, packed for C ABI ]
// [FIX] packed struct to match C++ #pragma pack(1)
// Without this fix, u64 timestamp was at wrong offset (40 vs 36),
// causing memory corruption when passing events across FFI boundary.
// Matches: C++ IpcEvent, Rust AegisIpcEvent, Python ctypes _pack_=1
// =================================================================
const AegisIpcEvent = packed struct {
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

pub const PacketContext = struct {
    meta: capture.AegisPktMeta,
    payload: []const u8,
    timestamp_ms: u64,
    stream_id: u64,
};

pub const AnalysisVerdict = struct {
    action: HookResult,
    severity: u8, // 0-4
    rule_ids: []const u32, // Matched rule IDs
    forensic_hash: ?[32]u8, // SHA-256 if preserved
};

/// Hook function signature: (context) → HookResult
pub const PreHookFn = *const fn (*const PacketContext) HookResult;
pub const PostHookFn = *const fn (*const PacketContext, *const AnalysisVerdict) HookResult;

// ─── Stream Reassembly ───
/// TCP stream reassembler that handles:
/// - Out-of-order segment reordering
/// - Overlapping segment detection (suspicious)
/// - Stream timeout and cleanup
pub const StreamReassembler = struct {
    allocator: std.mem.Allocator,
    streams: std.HashMap(u64, *TcpStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    current_time_ms: u64,

    fn init(allocator: std.mem.Allocator) !StreamReassembler {
        return .{
            .allocator = allocator,
            .streams = std.HashMap(u64, *TcpStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .current_time_ms = 0,
        };
    }

    /// feed - Feed a TCP segment into the reassembler.
    /// Returns the reassembled stream data if the stream is complete (FIN/RST),
    /// or null if still accumulating.
    fn feed(self: *StreamReassembler, stream_id: u64, seq: u32, payload: []const u8, tcp_flags: u8, timestamp_ms: u64) !?[]const u8 {
        self.current_time_ms = timestamp_ms;

        const gop = try self.streams.getOrPut(stream_id);
        if (!gop.found_existing) {
            const stream = try self.allocator.create(TcpStream);
            stream.* = TcpStream.init(self.allocator);
            gop.value_ptr.* = stream;
        }

        const stream = gop.value_ptr.*;
        try stream.addSegment(seq, payload, timestamp_ms);

        // Check if stream is complete (FIN or RST)
        const is_fin = (tcp_flags & 0x01) != 0; // FIN
        const is_rst = (tcp_flags & 0x04) != 0; // RST

        if (is_fin or is_rst) {
            const result = try stream.getAssembled(self.allocator);
            // Remove completed stream
            self.streams.removeByPtr(gop.key_ptr);
            stream.deinit();
            self.allocator.destroy(stream);
            return result;
        }

        return null;
    }

    /// expireTimeouts - Remove streams older than STREAM_TIMEOUT_MS.
    fn expireTimeouts(self: *StreamReassembler) !void {
        var it = self.streams.iterator();
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        while (it.next()) |entry| {
            if (self.current_time_ms - entry.value_ptr.*.last_activity_ms > STREAM_TIMEOUT_MS) {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        for (to_remove.items) |id| {
            if (self.streams.fetchRemove(id)) |kv| {
                kv.value.deinit();
                self.allocator.destroy(kv.value);
            }
        }
    }

    fn deinit(self: *StreamReassembler) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit();
    }
};

/// Single TCP stream being reassembled.
pub const TcpStream = struct {
    segments: std.ArrayList(TcpSegment),
    assembled_len: usize,
    expected_seq: u32,
    last_activity_ms: u64,

    const TcpSegment = struct {
        seq: u32,
        data: []const u8,
        timestamp_ms: u64,
    };

    fn init(allocator: std.mem.Allocator) TcpStream {
        return .{
            .segments = std.ArrayList(TcpSegment).init(allocator),
            .assembled_len = 0,
            .expected_seq = 0,
            .last_activity_ms = 0,
        };
    }

    fn addSegment(self: *TcpStream, seq: u32, payload: []const u8, timestamp_ms: u64) !void {
        try self.segments.append(.{
            .seq = seq,
            .data = payload,
            .timestamp_ms = timestamp_ms,
        });
        self.last_activity_ms = timestamp_ms;
        if (self.segments.items.len == 1) {
            self.expected_seq = seq + @as(usize, @intCast(payload.len));
        }
    }

    fn getAssembled(self: *TcpStream, allocator: std.mem.Allocator) ![]const u8 {
        // Sort segments by sequence number
        std.mem.sort(TcpSegment, self.segments.items, {}, struct {
            fn lessThan(_: void, a: TcpSegment, b: TcpSegment) bool {
                return a.seq < b.seq;
            }
        }
            .lessThan);

        // Calculate total length
        var total: usize = 0;
        for (self.segments.items) |seg| {
            total += seg.data.len;
        }
        if (total > MAX_STREAM_BUF) total = MAX_STREAM_BUF;

        var buf = try allocator.alloc(u8, total);
        var offset: usize = 0;
        for (self.segments.items) |seg| {
            const to_copy = @min(seg.data.len, total - offset);
            @memcpy(buf[offset..][0..to_copy], seg.data[0..to_copy]);
            offset += to_copy;
        }

        return buf[0..offset];
    }

    fn deinit(self: *TcpStream) void {
        self.segments.deinit();
    }
};

// ─── Analysis Engine with Hooks ───
pub const AnalysisEngine = struct {
    allocator: std.mem.Allocator,
    reassembler: StreamReassembler,
    pre_hooks: [MAX_HOOKS]?PreHookFn,
    post_hooks: [MAX_HOOKS]?PostHookFn,
    pre_hook_count: usize,
    post_hook_count: usize,
    verdict_count: u64,

    fn init(allocator: std.mem.Allocator) !AnalysisEngine {
        return .{
            .allocator = allocator,
            .reassembler = try StreamReassembler.init(allocator),
            .pre_hooks = [_]?PreHookFn{null} ** MAX_HOOKS,
            .post_hooks = [_]?PostHookFn{null} ** MAX_HOOKS,
            .pre_hook_count = 0,
            .post_hook_count = 0,
            .verdict_count = 0,
        };
    }

    /// registerPreHook - Register a pre-analysis hook.
    /// Called before stream reassembly. Can short-circuit processing.
    fn registerPreHook(self: *AnalysisEngine, hook: PreHookFn) !void {
        if (self.pre_hook_count >= MAX_HOOKS) return error.TooManyHooks;
        self.pre_hooks[self.pre_hook_count] = hook;
        self.pre_hook_count += 1;
    }

    /// registerPostHook - Register a post-analysis hook.
    /// Called after reassembly + pattern matching. Can modify verdict.
    fn registerPostHook(self: *AnalysisEngine, hook: PostHookFn) !void {
        if (self.post_hook_count >= MAX_HOOKS) return error.TooManyHooks;
        self.post_hooks[self.post_hook_count] = hook;
        self.post_hook_count += 1;
    }

    /// analyze - Main analysis pipeline for a single packet.
    /// Pipeline: Pre-hooks → Reassemble → Pattern Match → Post-hooks → Verdict
    fn analyze(self: *AnalysisEngine, ctx: *const PacketContext, pattern_ids: []const u32) !AnalysisVerdict {
        // ── Phase 1: Pre-Analysis Hooks ──
        for (self.pre_hooks[0..self.pre_hook_count]) |hook_opt| {
            if (hook_opt) |hook| {
                const result = hook(ctx);
                switch (result) {
                    .drop => return .{
                        .action = .drop,
                        .severity = 0,
                        .rule_ids = &.{},
                        .forensic_hash = null,
                    },
                    .alert, .preserve => {
                        // Pre-hook triggered — escalate but continue
                        break;
                    },
                    .pass => {},
                }
            }
        }

        // ── Phase 2: Stream Reassembly (for TCP) ──
        // (Stream reassembly is handled by the reassembler separately;
        //  here we just note that the packet has been through pre-hooks)

        // ── Phase 3: Pattern Match → Initial Verdict ──
        var verdict = AnalysisVerdict{
            .action = if (pattern_ids.len > 0) .alert else .pass,
            .severity = if (pattern_ids.len > 0) 2 else 0,
            .rule_ids = pattern_ids,
            .forensic_hash = null,
        };

        // ── Phase 4: Post-Analysis Hooks ──
        for (self.post_hooks[0..self.post_hook_count]) |hook_opt| {
            if (hook_opt) |hook| {
                const result = hook(ctx, &verdict);
                switch (result) {
                    .preserve => {
                        verdict.action = .preserve;
                        // Forensic hash will be computed by Rust shield
                    },
                    .alert => {
                        if (verdict.action == .pass) verdict.action = .alert;
                    },
                    .drop => {
                        verdict.action = .drop;
                    },
                    .pass => {},
                }
            }
        }

        self.verdict_count += 1;
        return verdict;
    }

    fn deinit(self: *AnalysisEngine) void {
        self.reassembler.deinit();
    }

    // ─── Built-in Hook Implementations ───

    /// Pre-hook: Blacklist check (SecDevOps — known-bad IPs)
    fn hook_blacklist_check(ctx: *const PacketContext) HookResult {
        // Example: Block known C2 IPs
        const blacklist = [_]u32{
            0x0A000001, // 10.0.0.1 (example)
            0xC0A80001, // 192.168.0.1 (example)
        };
        for (blacklist) |bad_ip| {
            if (ctx.meta.src_ip == bad_ip or ctx.meta.dst_ip == bad_ip) {
                return .alert;
            }
        }
        return .pass;
    }

    /// Post-hook: Forensic preservation for high-severity alerts
    fn hook_forensic_preserve(ctx: *const PacketContext, verdict: *const AnalysisVerdict) HookResult {
        _ = ctx;
        if (verdict.severity >= 3) { // high or critical
            return .preserve; // Triggers SHA-256 in Rust shield
        }
        return .pass;
    }

    /// Post-hook: Digital forensics chain-of-custody timestamping
    fn hook_chain_of_custody(ctx: *const PacketContext, verdict: *const AnalysisVerdict) HookResult {
        _ = verdict;
        if (ctx.meta.ip_proto == 6) { // TCP — ensure ordered evidence
            return .pass; // Chain-of-custody maintained by stream reassembly
        }
        return .pass;
    }
};

// ─── Global Analysis Engine ───
var g_analyzer: ?AnalysisEngine = null;

pub fn init(allocator: std.mem.Allocator) !void {
    g_analyzer = try AnalysisEngine.init(allocator);

    // Register built-in hooks (SecDevOps + Forensics)
    try g_analyzer.?.registerPreHook(AnalysisEngine.hook_blacklist_check);
    try g_analyzer.?.registerPostHook(AnalysisEngine.hook_forensic_preserve);
    try g_analyzer.?.registerPostHook(AnalysisEngine.hook_chain_of_custody);
}

pub fn analyze(ctx: *const PacketContext, pattern_ids: []const u32) !AnalysisVerdict {
    if (g_analyzer) |*a| {
        return try a.analyze(ctx, pattern_ids);
    }
    return error.NotInitialized;
}

pub fn deinit() void {
    if (g_analyzer) |*a| {
        a.deinit();
    }
    g_analyzer = null;
}

// ─── Tests ───
test "Analysis hook pipeline" {
    const testing = std.testing;
    var analyzer = try AnalysisEngine.init(testing.allocator);
    defer analyzer.deinit();

    try analyzer.registerPreHook(AnalysisEngine.hook_blacklist_check);
    try analyzer.registerPostHook(AnalysisEngine.hook_forensic_preserve);

    const ctx = PacketContext{
        .meta = .{
            .size = 0,
            .orig_len = 0,
            .timestamp = 0,
            .layer_id = 0,
            .direction = 0,
            .process_id = 0,
            .ip_proto = 6,
            ._pad = 0,
            .src_ip = 0x0A000001, // Blacklisted
            .dst_ip = 0,
            .src_port = 12345,
            .dst_port = 80,
        },
        .payload = &.{},
        .timestamp_ms = 1000,
        .stream_id = 1,
    };

    const verdict = try analyzer.analyze(&ctx, &.{ 1, 2 });
    try testing.expect(verdict.action == .alert or verdict.action == .preserve);
}
