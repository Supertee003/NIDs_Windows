// cpp_adapter.zig Î“Ã‡Ã¶ Zig Î“Ã¥Ã† C++ Adapter Framework ABI bridge (T2, Step 12)
//
// Imports the extern "C" functions exported by bridge/aegis_adapter.hpp/.cpp
// and wraps them in idiomatic Zig types.
//
// The C++ adapter framework owns all direct Win32 API contact for host
// sources (ETW, FIM, Registry, Process).  Once this bridge is wired,
// Zig MUST NOT call Win32 APIs directly for these sources.
//
// Usage:
//   const reg = CppAdapter.Registry.create();
//   const proc = reg.start(.process) catch return error.AdapterFailed;
//   var frames: [8][109]u8 = undefined;
//   const n = proc.poll(&frames);
//   proc.health(); // -> AdapterHealth
//   proc.stop();
//   reg.destroy();
//
// Build: requires linking against libaegis_adapter (g++ / CMake target).

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");

// ============================================================
// C++ Adapter ABI Î“Ã‡Ã¶ extern "C" declarations (from aegis_adapter.hpp)
// ============================================================

const adapter_kind_network: u8 = 5;
const adapter_kind_process: u8 = 4;
const adapter_kind_fim: u8 = 2;
const adapter_kind_registry: u8 = 3;
const adapter_kind_etw: u8 = 1;

const adapter_state_created: u8 = 0;
const adapter_state_started: u8 = 1;
const adapter_state_stopped: u8 = 2;
const adapter_state_error: u8 = 3;

const WIRE_PAYLOAD_SIZE: u32 = 109;

// Opaque handle types (C++ vtable pointers).
const AdapterRegistryHandle = ?*anyopaque;
const AdapterHandle = ?*anyopaque;

// ---- extern "C" function imports ----

extern "aegis_adapter" fn aegis_adapter_registry_create() callconv(.C) AdapterRegistryHandle;
extern "aegis_adapter" fn aegis_adapter_registry_destroy(reg: AdapterRegistryHandle) callconv(.C) void;
extern "aegis_adapter" fn aegis_adapter_start(reg: AdapterRegistryHandle, kind: u8) callconv(.C) AdapterHandle;
extern "aegis_adapter" fn aegis_adapter_stop(handle: AdapterHandle) callconv(.C) i32;
extern "aegis_adapter" fn aegis_adapter_poll(
    handle: AdapterHandle,
    out_set: [*]u8,
    max_out: u32,
    canonical_buf: [*]u8,
    canonical_cap: u32,
    bytes_per_event: *u32,
) callconv(.C) i32;
extern "aegis_adapter" fn aegis_adapter_health(
    handle: AdapterHandle,
    out_state: *u8,
    out_last_error: *u32,
    out_events_produced: *u64,
) callconv(.C) void;
extern "aegis_adapter" fn aegis_adapter_selftest() callconv(.C) i32;

// ============================================================
// Zig-Friendly Wrappers
// ============================================================

pub const AdapterKind = enum(u8) {
    network = adapter_kind_network,
    process = adapter_kind_process,
    fim = adapter_kind_fim,
    registry = adapter_kind_registry,
    etw = adapter_kind_etw,
};

pub const AdapterState = enum(u8) {
    created = adapter_state_created,
    started = adapter_state_started,
    stopped = adapter_state_stopped,
    @"error" = adapter_state_error,
};

pub const AdapterHealth = struct {
    state: AdapterState,
    last_error: u32,
    events_produced: u64,
};

pub const PollOutcome = struct {
    events_emitted: i32,
    per_event_wire_size: u32,
};

// ============================================================
// CppAdapter namespace
// ============================================================

pub const CppAdapter = struct {
    // ---- Handle (wraps a single C++ Adapter* vtable pointer) ----

    pub const Handle = struct {
        inner: AdapterHandle,

        pub fn stop(self: Handle) !void {
            if (self.inner == null) return error.NullHandle;
            const rc = aegis_adapter_stop(self.inner);
            if (rc != 0) return error.StopFailed;
        }

        /// Poll the adapter for events.  Returns up to `max_frames` canonical
        /// frames (109 bytes each) into `wire_buf` (which must be Î“Ã«Ã‘ 109*max_frames).
        /// The `out_set` slice marks which entries were filled (1 = valid, 0 = empty).
        pub fn poll(self: Handle, out_set: []u8, wire_buf: []u8) !PollOutcome {
            if (self.inner == null) return error.NullHandle;
            if (wire_buf.len < out_set.len * WIRE_PAYLOAD_SIZE) return error.BufferTooSmall;
            var bytes_per_event: u32 = 0;
            const n = aegis_adapter_poll(
                self.inner,
                out_set.ptr,
                @intCast(out_set.len),
                wire_buf.ptr,
                @intCast(wire_buf.len),
                &bytes_per_event,
            );
            if (n < 0) return error.PollFailed;
            return .{
                .events_emitted = n,
                .per_event_wire_size = bytes_per_event,
            };
        }

        pub fn health(self: Handle) AdapterHealth {
            if (self.inner == null) return .{ .state = .created, .last_error = 0, .events_produced = 0 };
            var state: u8 = adapter_state_created;
            var last_error: u32 = 0;
            var produced: u64 = 0;
            aegis_adapter_health(self.inner, &state, &last_error, &produced);
            return .{
                .state = @enumFromInt(state),
                .last_error = last_error,
                .events_produced = produced,
            };
        }
    };

    // ---- Registry (wraps AdapterRegistry*) ----

    pub const Registry = struct {
        inner: AdapterRegistryHandle,

        pub fn create() !Registry {
            const h = aegis_adapter_registry_create();
            if (h == null) return error.RegistryCreateFailed;
            return .{ .inner = h };
        }

        pub fn start(self: Registry, kind: AdapterKind) !Handle {
            if (self.inner == null) return error.NullRegistry;
            const h = aegis_adapter_start(self.inner, @intFromEnum(kind));
            if (h == null) return error.AdapterStartFailed;
            return .{ .inner = h };
        }

        pub fn destroy(self: Registry) void {
            if (self.inner) |h| {
                aegis_adapter_registry_destroy(h);
            }
        }
    };

    // ---- Standalone self-test (calls C++ self-test) ----

    pub fn selfTest() !void {
        const rc = aegis_adapter_selftest();
        if (rc != 0) return error.SelfTestFailed;
    }
};

// ============================================================
// Fabric Integration Helper
//
// Polls a handle and feeds all produced canonical events into the
// Zig fabric (nose_contract.submitEvent).  Acquisition only Î“Ã‡Ã¶
// no policy / detection.
// ============================================================

pub fn feedFabric(handle: CppAdapter.Handle, max_frames: usize) !struct { accepted: u64, rejected: u64 } {
    const nose_contract = @import("../capture/nose_contract.zig");
    var set_buf: [64]u8 = undefined;
    var wire_buf: [64 * 109]u8 = undefined;
    const actual_max: usize = @min(max_frames, 64);
    var accepted: u64 = 0;
    var rejected: u64 = 0;

    const out_set = set_buf[0..actual_max];
    const out_wire = wire_buf[0 .. actual_max * 109];
    const result = try handle.poll(out_set, out_wire);

    for (0..@intCast(@max(result.events_emitted, 0))) |i| {
        if (out_set[i] == 0) continue;
        const base = i * WIRE_PAYLOAD_SIZE;
        const frame = out_wire[base .. base + WIRE_PAYLOAD_SIZE];
        const event = canonical.deserializeFromBytes(frame) orelse {
            rejected += 1;
            continue;
        };
        switch (nose_contract.submitEvent(event)) {
            .accepted => accepted += 1,
            else => rejected += 1,
        }
    }
    return .{ .accepted = accepted, .rejected = rejected };
}

// ============================================================
// Tests (link stubs required: compile with aegis_adapter.cpp)
// ============================================================

test "AdapterKind enum values match C ABI" {
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(AdapterKind.network));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(AdapterKind.process));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(AdapterKind.fim));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(AdapterKind.registry));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(AdapterKind.etw));
}

test "AdapterState enum values match C ABI" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(AdapterState.created));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(AdapterState.started));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(AdapterState.stopped));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(AdapterState.@"error"));
}

test "Wire payload size matches canonical" {
    try std.testing.expectEqual(@as(u32, 109), WIRE_PAYLOAD_SIZE);
}