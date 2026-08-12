/**
 * aegis_bindings.zig — Zig FFI Bindings for C++ IPC Bridge
 * ============================================================
 * Provides Zig-side type definitions and function bindings for
 * communicating with the C++ IPC Bridge (aegis_ipc.dll).
 *
 * CRITICAL: All structs use `packed` layout to match C++ #pragma pack(1).
 * Mismatched alignment causes field offset errors and memory corruption
 * across the FFI boundary.
 *
 * Cross-language contract:
 *   C++   : #pragma pack(1) struct IpcEvent { ... }
 *   Zig   : const AegisIpcEvent = packed struct { ... }
 *   Rust  : #[repr(C, packed)] struct AegisIpcEvent { ... }
 *   Python: class AegisIpcEvent(ctypes.Structure): _pack_ = 1
 *   Cython: cdef packed struct C_AegisIpcEvent { ... }
 */

const std = @import("std");
const win = std.os.windows;

// =================================================================
// [ IPC EVENT STRUCT — 52 bytes, packed for C ABI ]
// [FIX] packed struct to match C++ #pragma pack(1)
// Without this fix, u64 timestamp was at wrong offset (40 vs 36),
// causing memory corruption when passing events across FFI boundary.
// =================================================================
const AegisIpcEvent = packed struct {
    event_type: u32,        // 0-3:   event classification
    source_ip: u32,         // 4-7:   source IPv4
    dest_ip: u32,           // 8-11:  destination IPv4
    source_port: u16,       // 12-13: source port
    dest_port: u16,         // 14-15: destination port
    protocol: u8,           // 16:    IP protocol number
    direction: u8,          // 17:    0=inbound, 1=outbound
    layer_id: u8,           // 18:    which layer generated this event
    tier_result: u8,        // 19:    tier decision (0=pass, 1=match, 2=block)
    payload_length: u32,    // 20-23: payload size in bytes
    rule_id: u32,           // 24-27: matched rule CRC32
    severity: u32,          // 28-31: severity level (0=info, 1=medium, 2=high, 3=critical)
    reserved: u32,          // 32-35: reserved for future use
    timestamp: u64,         // 36-43: millisecond timestamp
    source_pid: u32,        // 44-47: PID of source process
    defcon_impact: u32,     // 48-51: DEFCON impact assessment (1-5)
};

// =================================================================
// [ BRIDGE FUNCTION SIGNATURES — extern declarations ]
// These are resolved at runtime via std.DynLib in nids_analyze.zig,
// but declared here for type checking and documentation.
// =================================================================

// Bridge lifecycle
extern fn aegis_bridge_init() i32;
extern fn aegis_bridge_shutdown() i32;

// Event queue operations
extern fn aegis_bridge_push_event(event: *const AegisIpcEvent) i32;
extern fn aegis_bridge_pop_event(event: *AegisIpcEvent) i32;

// Query functions
extern fn aegis_bridge_get_defcon() u8;
extern fn aegis_bridge_get_event_count() u32;

// Packet parsing
extern fn aegis_parse_packet(
    data: [*]const u8,
    data_len: u32,
    out_event: *AegisIpcEvent,
) i32;

// =================================================================
// [ HELPER: PUSH TIER-1 MATCH RESULT ]
// Convenience function to construct and push an event.
// =================================================================
pub fn pushMatchEvent(
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
    timestamp: u64,
    source_pid: u32,
    defcon_impact: u32,
) i32 {
    var event: AegisIpcEvent = .{
        .event_type = event_type,
        .source_ip = source_ip,
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .protocol = protocol,
        .direction = direction,
        .layer_id = layer_id,
        .tier_result = tier_result,
        .payload_length = payload_length,
        .rule_id = rule_id,
        .severity = severity,
        .reserved = 0,
        .timestamp = timestamp,
        .source_pid = source_pid,
        .defcon_impact = defcon_impact,
    };
    return aegis_bridge_push_event(&event);
}
