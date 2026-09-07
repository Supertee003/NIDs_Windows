// II01 - ETW Real-time Source (Zig side)
// AEGIS NIDS v5.0+ â€” Real-time Event Tracing for Windows consumer
//
// Wraps the native C helper (etw_native.c) which calls StartTraceW/ProcessTrace.
// This Zig module provides the high-level session API and event decoding.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

// ============================================================================
// ETW provider GUIDs (well-known)
// ============================================================================
pub const PROVIDER_KERNEL_PROCESS = [16]u8{ 0x22, 0xFB, 0x2D, 0xF6, 0xA0, 0x1B, 0x10, 0x40, 0xB3, 0x20, 0x29, 0x33, 0x33, 0x8D, 0xDE, 0x6C };
pub const PROVIDER_KERNEL_FILE = [16]u8{ 0xED, 0xD0, 0x89, 0x2E, 0x80, 0xB5, 0x10, 0x40, 0x99, 0xF6, 0x49, 0x9A, 0x86, 0xA9, 0x3A, 0x05 };
pub const PROVIDER_KERNEL_REGISTRY = [16]u8{ 0xAE, 0x53, 0x7C, 0x9E, 0xB2, 0xF5, 0x10, 0x40, 0x9D, 0x2D, 0x53, 0xA0, 0xC7, 0xA1, 0xA0, 0x9C };
pub const PROVIDER_KERNEL_IMAGE = [16]u8{ 0x73, 0xCA, 0x9B, 0x9C, 0x3B, 0x0B, 0x10, 0x40, 0x95, 0x6F, 0x54, 0x7E, 0x9B, 0x55, 0xC4, 0x4B };

// ============================================================================
// ETW Event Record (simplified, matches native ETW EVENT_RECORD struct)
// ============================================================================
pub const EtwEventRecord = extern struct {
    event_id: u32,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
    timestamp_ns: i64,
    process_id: u32,
    thread_id: u32,
    image_base: u64,
    image_size: u32,
    // Extended data (image filename, registry path, etc.)
    ext_data_len: u16,
    ext_data_offset: u32, // offset into shared buffer
};

// ============================================================================
// EtwCallback â€” invoked per ETW event
// ============================================================================
pub const EtwCallback = *const fn (ctx: *anyopaque, rec: *const EtwEventRecord, ext_data: []const u8) void;

// ============================================================================
// Native FFI (etw_native.c)
// ============================================================================
extern "aegis_etw_helper" fn aegis_etw_start(session_name: [*]const u8, providers: [*]const [16]u8, provider_count: usize) c_int;
extern "aegis_etw_helper" fn aegis_etw_stop(session_name: [*]const u8) c_int;
extern "aegis_etw_helper" fn aegis_etw_set_callback(cb: *const fn (ctx: *anyopaque, rec: *const EtwEventRecord, ext_data: [*]const u8, ext_len: usize) callconv(.C) void, ctx: *anyopaque) c_int;

// ============================================================================
// EtwSource â€” high-level Zig wrapper
// ============================================================================
pub const EtwSource = struct {
    session_name: [64]u8 = [_]u8{0} ** 64,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    events_received: u64 = 0,
    events_dropped: u64 = 0,
    callback: ?EtwCallback = null,
    callback_ctx: ?*anyopaque = null,

    pub fn init() EtwSource {
        var s = EtwSource{};
        @memcpy(s.session_name[0..11], "AEGIS_NIDS\x00");
        return s;
    }

    pub fn start(self: *EtwSource, providers: []const [16]u8) !void {
        if (@import("builtin").os.tag != .windows) return error.UnsupportedPlatform;
        if (providers.len == 0) return error.NoProviders;
        const name_z = std.mem.sliceTo(&self.session_name, 0);
        const rc = aegis_etw_start(name_z.ptr, providers.ptr, providers.len);
        if (rc != 0) {
            diag.err("aegis_etw_start failed: rc={d}", .{rc});
            return error.EtwStartFailed;
        }
        self.running.store(true, .release);
        diag.info("ETW session {s} started with {d} providers", .{ name_z, providers.len });
    }

    pub fn stop(self: *EtwSource) void {
        if (!self.running.load(.acquire)) return;
        const name_z = std.mem.sliceTo(&self.session_name, 0);
        _ = aegis_etw_stop(name_z.ptr);
        self.running.store(false, .release);
        diag.info("ETW session {s} stopped", .{name_z});
    }

    pub fn setCallback(self: *EtwSource, ctx: *anyopaque, cb: EtwCallback) !void {
        self.callback_ctx = ctx;
        self.callback = cb;
        const wrapper = struct {
            fn wrap(c: *anyopaque, rec: *const EtwEventRecord, ext_data: [*]const u8, ext_len: usize) callconv(.C) void {
                const outer: *EtwSource = @ptrCast(@alignCast(c));
                if (outer.callback) |cb_fn| cb_fn(outer.callback_ctx.?, rec, ext_data[0..ext_len]);
                outer.events_received += 1;
            }
        };
        const rc = aegis_etw_set_callback(wrapper.wrap, @ptrCast(self));
        if (rc != 0) return error.EtwSetCallbackFailed;
    }
};

// ============================================================================
// Tests (Linux stubs)
// ============================================================================
test "EtwSource init produces a session name" {
    const s = EtwSource.init();
    const name = std.mem.sliceTo(&s.session_name, 0);
    try std.testing.expectEqualStrings("AEGIS_NIDS", name);
}

test "EtwSource start with no providers fails" {
    var s = EtwSource.init();
    try std.testing.expectError(error.NoProviders, s.start(&[_][16]u8{}));
}

test "EtwSource start on non-Windows fails" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var s = EtwSource.init();
    const providers = [_][16]u8{PROVIDER_KERNEL_PROCESS};
    try std.testing.expectError(error.UnsupportedPlatform, s.start(&providers));
}
