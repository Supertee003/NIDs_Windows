//! Phase 3 ABI manifest: explicit boundaries between wire and internal events.
const std = @import("std");
const canonical = @import("canonical_event.zig");
const internal = @import("event.zig");

pub const CONTRACT_VERSION: u16 = 1;
pub const CANONICAL_EVENT_WIRE_BYTES: usize = canonical.WIRE_PAYLOAD_SIZE;
pub const INTERNAL_IPC_EVENT_BYTES: usize = internal.EVENT_SIZE;
pub const CONTROL_PROTOCOL_VERSION: u16 = 2;

pub const Boundary = struct {
    name: []const u8,
    version: u16,
    bytes: usize,
    encoding: []const u8,
};

pub const boundaries = [_]Boundary{
    .{ .name = "canonical_event_v1", .version = 1, .bytes = CANONICAL_EVENT_WIRE_BYTES, .encoding = "little-endian-explicit-fields" },
    .{ .name = "ipc_event_v5_internal", .version = internal.EVENT_VERSION, .bytes = INTERNAL_IPC_EVENT_BYTES, .encoding = "zig-extern-struct" },
};

test "ABI manifest keeps wire and internal boundaries distinct" {
    try std.testing.expectEqual(@as(usize, 109), CANONICAL_EVENT_WIRE_BYTES);
    try std.testing.expectEqual(@as(usize, 96), INTERNAL_IPC_EVENT_BYTES);
    try std.testing.expect(CANONICAL_EVENT_WIRE_BYTES != INTERNAL_IPC_EVENT_BYTES);
    try std.testing.expectEqual(@as(usize, 2), boundaries.len);
}

test "ABI manifest versions are explicit" {
    try std.testing.expectEqual(@as(u16, 1), boundaries[0].version);
    try std.testing.expectEqual(internal.EVENT_VERSION, boundaries[1].version);
    try std.testing.expectEqual(@as(u16, 2), CONTROL_PROTOCOL_VERSION);
}
