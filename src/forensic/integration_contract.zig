// PATCH-37 - Go/C++ ↔ Zig Integration Contracts
// AEGIS NIDS v5.0+ -- Language boundary contracts for Go, C++, and Zig
//
// Integration layers:
//   1. Go Nose → Zig Core: Named pipe IPC (109-byte canonical wire)
//   2. Zig Core → C++ Adapter: FFI (opaque handles, canonical wire frames)
//   3. Zig Core → C++ IPC Bridge: FFI (IpcEvent push/pop)
//   4. Zig Core → Rust PEP: FFI (PepRequest/PepResponse)

const std = @import("std");

// ============================================================================
// Contract 1: Go Nose → Zig Core (Named Pipe IPC)
// ============================================================================

/// Named pipe path for Go Nose → Zig Core communication.
pub const NOSE_PIPE_PATH = "\\\\.\\pipe\\aegis_nose";

/// Go Nose sends 125-byte wire frames (16-byte header + 109-byte payload).
/// Zig Core reads from the named pipe and deserializes.
pub const NoseWireFrame = extern struct {
    header: NoseWireHeader,
    payload: [109]u8,
};

pub const NoseWireHeader = extern struct {
    magic: u32, // 0x57455631 ("WEV1")
    version: u16, // 1
    payload_type: u16, // 0=event
    payload_length: u32, // 109
    crc32: u32, // CRC32 of payload
};

pub const NOSE_WIRE_MAGIC: u32 = 0x57455631; // "WEV1"

/// Verify Go Nose wire frame header.
pub fn verifyNoseFrame(frame: *const NoseWireFrame) bool {
    if (frame.header.magic != NOSE_WIRE_MAGIC) return false;
    if (frame.header.version != 1) return false;
    if (frame.header.payload_type != 0) return false;
    if (frame.header.payload_length != 109) return false;
    return true;
}

// ============================================================================
// Contract 2: Zig Core → C++ Adapter (FFI)
// ============================================================================

/// Opaque handle types for C++ adapter FFI.
pub const AdapterRegistryHandle = ?*anyopaque;
pub const AdapterHandle = ?*anyopaque;

/// Adapter event set (output from poll).
pub const AdapterEventSet = extern struct {
    events: [64]AdapterEvent,
    count: u32,
};

pub const AdapterEvent = extern struct {
    timestamp_ns: u64,
    data: [109]u8, // Canonical event wire bytes
    data_len: u32,
};

/// Adapter kind enum.
pub const AdapterKind = enum(u32) {
    etw = 0,
    fim = 1,
    registry = 2,
    process = 3,
};

/// Adapter health state.
pub const AdapterHealth = extern struct {
    state: u32, // 0=healthy, 1=degraded, 2=failed
    last_error: u32, // Windows error code
    events_produced: u64,
};

/// Zig → C++ adapter FFI function signatures.
/// These are declared as extern and resolved at link time.
pub extern "aegis_adapter" fn aegis_adapter_registry_create() callconv(.C) AdapterRegistryHandle;
pub extern "aegis_adapter" fn aegis_adapter_registry_destroy(reg: AdapterRegistryHandle) callconv(.C) void;
pub extern "aegis_adapter" fn aegis_adapter_start(reg: AdapterRegistryHandle, kind: AdapterKind) callconv(.C) AdapterHandle;
pub extern "aegis_adapter" fn aegis_adapter_stop(handle: AdapterHandle) callconv(.C) void;
pub extern "aegis_adapter" fn aegis_adapter_poll(
    handle: AdapterHandle,
    out_set: *AdapterEventSet,
    max_out: u32,
    canonical_buf: [*]u8,
    canonical_cap: u32,
    bytes_per_event: u32,
) callconv(.C) i32;
pub extern "aegis_adapter" fn aegis_adapter_health(
    handle: AdapterHandle,
    out_state: *AdapterHealth,
) callconv(.C) void;

// ============================================================================
// Contract 3: Zig Core → C++ IPC Bridge (FFI)
// ============================================================================

/// IPC Event (C++ bridge format).
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

/// IPC Command (C++ bridge format).
pub const IpcCommand = extern struct {
    cmd_type: u8,
    payload: [23]u8,
};

/// IPC command types.
pub const IpcCmdType = enum(u8) {
    ping = 0,
    shutdown = 1,
    block_ip = 2,
    unblock_ip = 3,
    get_defcon = 4,
};

/// Zig → C++ IPC bridge FFI function signatures.
pub extern "aegis_ipc" fn aegis_bridge_init() callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_shutdown() callconv(.C) void;
pub extern "aegis_ipc" fn aegis_bridge_push_event(event: *const IpcEvent) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_pop_event(event: *IpcEvent) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_get_defcon() callconv(.C) u32;
pub extern "aegis_ipc" fn aegis_bridge_block_ip(ip: u32) callconv(.C) i32;
pub extern "aegis_ipc" fn aegis_bridge_unblock_ip(ip: u32) callconv(.C) i32;

// ============================================================================
// Contract 4: Zig Core → Rust PEP (FFI)
// ============================================================================

/// PEP Request (Zig → Rust).
pub const PepRequest = extern struct {
    decision_kind: u8,
    flow_id: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    policy_id: u32,
    severity: u8,
    caller_pid: u32,
    caller_capability_mask: u32,
    request_id: u64,
    reserved: u32,
};

/// PEP Response (Rust → Zig).
pub const PepResponse = extern struct {
    decision: u8, // 0=allow, 1=block, 2=rate_limit, 3=quarantine
    reason: u32,
    quota_remaining: u32,
    signed_by: u32,
};

/// PEP decision values.
pub const PepDecision = enum(u8) {
    allow = 0,
    block = 1,
    rate_limit = 2,
    quarantine = 3,
};

/// Zig → Rust PEP FFI function signatures.
pub extern "aegis_pep" fn aegis_pep_init() callconv(.C) i32;
pub extern "aegis_pep" fn aegis_pep_shutdown() callconv(.C) void;
pub extern "aegis_pep" fn aegis_pep_enforce(
    req: *const PepRequest,
    resp: *PepResponse,
) callconv(.C) i32;
pub extern "aegis_pep" fn aegis_pep_quota_remaining() callconv(.C) u32;

// ============================================================================
// Tests
// ============================================================================

test "Go→Zig: Nose pipe path is correct" {
    try std.testing.expectEqualStrings("\\\\.\\pipe\\aegis_nose", NOSE_PIPE_PATH);
}

test "Go→Zig: Wire frame header size is 16 bytes" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(NoseWireHeader));
}

test "Go→Zig: Wire frame verification" {
    var frame: NoseWireFrame = std.mem.zeroes(NoseWireFrame);
    frame.header.magic = NOSE_WIRE_MAGIC;
    frame.header.version = 1;
    frame.header.payload_type = 0;
    frame.header.payload_length = 109;
    try std.testing.expect(verifyNoseFrame(&frame));
}

test "Go→Zig: Invalid magic rejected" {
    var frame: NoseWireFrame = std.mem.zeroes(NoseWireFrame);
    frame.header.magic = 0xDEADBEEF;
    frame.header.version = 1;
    frame.header.payload_type = 0;
    frame.header.payload_length = 109;
    try std.testing.expect(!verifyNoseFrame(&frame));
}

test "C++→Zig: Adapter kind enum values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(AdapterKind.etw));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(AdapterKind.fim));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(AdapterKind.registry));
    try std.testing.expectEqual(@as(u32, 3), @intFromEnum(AdapterKind.process));
}

test "C++→Zig: IPC command type enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(IpcCmdType.ping));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(IpcCmdType.shutdown));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(IpcCmdType.block_ip));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(IpcCmdType.unblock_ip));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(IpcCmdType.get_defcon));
}

test "Rust→Zig: PEP decision enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(PepDecision.allow));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PepDecision.block));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(PepDecision.rate_limit));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(PepDecision.quarantine));
}

test "Rust→Zig: PEP Request/Response sizes are reasonable" {
    try std.testing.expect(@sizeOf(PepRequest) > 0);
    try std.testing.expect(@sizeOf(PepRequest) <= 256);
    try std.testing.expect(@sizeOf(PepResponse) > 0);
    try std.testing.expect(@sizeOf(PepResponse) <= 64);
}

test "C++→Zig: IPC Event/Command sizes are reasonable" {
    try std.testing.expect(@sizeOf(IpcEvent) > 0);
    try std.testing.expect(@sizeOf(IpcEvent) <= 128);
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(IpcCommand));
}
