// PATCH-38 - Python/Cython Integration Contracts
// AEGIS NIDS v5.0+ -- Python ctypes bridge contracts
//
// Integration layers:
//   1. Python Brain → C++ IPC Bridge: ctypes (aegis_ipc.dll)
//   2. Python Brain → Canonical Event: ctypes mirror
//   3. Cython hot loops: measured performance paths

const std = @import("std");

// ============================================================================
// Contract 1: Python → C++ IPC Bridge (ctypes)
// ============================================================================

/// Python loads aegis_ipc.dll via ctypes.CDLL() and calls C ABI functions.
/// This module defines the Zig-side view of those contracts.

/// IPC Event (C++ bridge format, consumed by Python via ctypes).
pub const IpcEvent = extern struct {
    kind: u8,
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    severity: u8,
    rule_id: u32,
    timestamp_ms: u64,
};

/// IPC Command (C++ bridge format, consumed by Python via ctypes).
pub const IpcCommand = extern struct {
    cmd_type: u8,
    payload: [23]u8,
};

/// IPC command types (must match Python AegisIpcCommand).
pub const IpcCmdType = enum(u8) {
    ping = 0,
    shutdown = 1,
    block_ip = 2,
    unblock_ip = 3,
    get_defcon = 4,
};

/// Bridge function signatures (Python calls these via ctypes).
pub extern "aegis_ipc" fn aegis_bridge_init() callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_shutdown() callconv(.C) void;
pub extern "aegis_ipc" fn aegis_bridge_push_event(event: *const IpcEvent) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_pop_event(event: *IpcEvent) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_get_defcon() callconv(.C) u32;
pub extern "aegis_ipc" fn aegis_bridge_block_ip(ip: u32) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_unblock_ip(ip: u32) callconv(.C) i32;

// ============================================================================
// Contract 2: Python → Canonical Event (ctypes mirror)
// ============================================================================

/// Python Brain uses ctypes to mirror the canonical event structure.
/// This module defines the Zig-side view of that contract.

/// Canonical Event (Python ctypes mirror, 109 bytes wire format).
pub const CanonicalEvent = extern struct {
    magic: u32,
    version: u16,
    struct_size: u16,
    event_id: u64,
    timestamp_ms: u64,
    monotonic_ns: u64,
    source: u8,
    source_ip: u32,
    source_port: u16,
    dest_ip: u32,
    dest_port: u16,
    session_id: u64,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    is_pipe: u8,
    event_type: u32,
    severity: u8,
    rule_id: u32,
    ruleset_version: u64,
    payload_length: u32,
    payload_hash: u64,
    policy_action: u8,
    enforcement_status: u8,
    defcon_impact: u8,
    context_flags: u32,
    reserved: [16]u8,
};

pub const EVENT_MAGIC: u32 = 0x41454731; // "AEG1"
pub const EVENT_VERSION: u16 = 1;

/// Verify canonical event header (Python must produce this).
pub fn verifyCanonicalEventHeader(event: *const CanonicalEvent) bool {
    if (event.magic != EVENT_MAGIC) return false;
    if (event.version != EVENT_VERSION) return false;
    return true;
}

// ============================================================================
// Contract 3: Cython Hot Loop Interfaces
// ============================================================================

/// Cython modules accelerate hot loops in the Python Brain.
/// These are the Zig-side interfaces that Cython modules call.

/// Packet hash computation (Cython-accelerated).
pub fn computePacketHash(data: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(data);
    return hasher.final();
}

/// Event deduplication check (Cython-accelerated).
pub fn isDuplicateEvent(hash1: u64, hash2: u64) bool {
    return hash1 == hash2;
}

/// Alert aggregation key (Cython-accelerated).
pub fn computeAggregationKey(src_ip: u32, dst_ip: u32, rule_id: u32) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(std.mem.asBytes(&src_ip));
    hasher.update(std.mem.asBytes(&dst_ip));
    hasher.update(std.mem.asBytes(&rule_id));
    return hasher.final();
}

// ============================================================================
// Tests
// ============================================================================

test "Python→C++: IPC command type enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(IpcCmdType.ping));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(IpcCmdType.shutdown));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(IpcCmdType.block_ip));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(IpcCmdType.unblock_ip));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(IpcCmdType.get_defcon));
}

test "Python→C++: IPC Event/Command sizes are reasonable" {
    try std.testing.expect(@sizeOf(IpcEvent) > 0);
    try std.testing.expect(@sizeOf(IpcEvent) <= 128);
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(IpcCommand));
}

test "Python→Canonical: Event header verification" {
    var event: CanonicalEvent = std.mem.zeroes(CanonicalEvent);
    event.magic = EVENT_MAGIC;
    event.version = EVENT_VERSION;
    try std.testing.expect(verifyCanonicalEventHeader(&event));
}

test "Python→Canonical: Invalid magic rejected" {
    var event: CanonicalEvent = std.mem.zeroes(CanonicalEvent);
    event.magic = 0xDEADBEEF;
    event.version = EVENT_VERSION;
    try std.testing.expect(!verifyCanonicalEventHeader(&event));
}

test "Python→Canonical: Invalid version rejected" {
    var event: CanonicalEvent = std.mem.zeroes(CanonicalEvent);
    event.magic = EVENT_MAGIC;
    event.version = 999;
    try std.testing.expect(!verifyCanonicalEventHeader(&event));
}

test "Cython: Packet hash is deterministic" {
    const data = "test packet data";
    const h1 = computePacketHash(data);
    const h2 = computePacketHash(data);
    try std.testing.expectEqual(h1, h2);
}

test "Cython: Different data produces different hashes" {
    const h1 = computePacketHash("data_a");
    const h2 = computePacketHash("data_b");
    try std.testing.expect(h1 != h2);
}

test "Cython: Duplicate event detection" {
    try std.testing.expect(isDuplicateEvent(42, 42));
    try std.testing.expect(!isDuplicateEvent(42, 43));
}

test "Cython: Aggregation key is deterministic" {
    const k1 = computeAggregationKey(0xC0A80101, 0xC0A80102, 42);
    const k2 = computeAggregationKey(0xC0A80101, 0xC0A80102, 42);
    try std.testing.expectEqual(k1, k2);
}

test "Cython: Different IPs produce different aggregation keys" {
    const k1 = computeAggregationKey(0xC0A80101, 0xC0A80102, 42);
    const k2 = computeAggregationKey(0xC0A80103, 0xC0A80104, 42);
    try std.testing.expect(k1 != k2);
}
