/**
 * aegis_bindings.zig — Zig FFI Bindings for C++ IPC Bridge
 *
 * Zig @cImport-style declarations for calling the C++ IPC Bridge functions.
 * These extern declarations match the extern "C" ABI in aegis_ipc.hpp and
 * aegis_packet_parser.hpp, allowing Zig Core (Tier-1) to push events
 * into the C++ Bridge and receive DEFCON state.
 *
 * Architecture: Zig Core → C++ Bridge (via these externs) → Python Brain
 *
 * ⚠️ NOTE: This file uses link-time extern declarations (requires aegis_ipc.dll
 * at link time). For runtime-loaded DLL (no link dependency), see nids_analyze.zig
 * which uses std.DynLib instead. This file is kept for reference / optional use.
 */

const std = @import("std");

// ====== IPC Event Structure (matches C++ IpcEvent — 48 bytes) ======
const AegisIpcEvent = extern struct {
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

// ====== IPC Command Structure ======
const AegisIpcCommand = extern struct {
    command_id: u32,
    target_subsystem: u32,
    payload_size: u32,
    response_expected: u32,
    timestamp: u64,
};

// ====== IPC Bridge Functions (extern "C" ABI) ======
extern fn aegis_bridge_init() i32;
extern fn aegis_bridge_shutdown() i32;
extern fn aegis_bridge_push_event(event: *const AegisIpcEvent) i32;
extern fn aegis_bridge_pop_event(event: *AegisIpcEvent) i32;
extern fn aegis_bridge_get_defcon() u8;
extern fn aegis_bridge_update_defcon(critical: u32, blocked: u32, kernel: u32, total: u32) void;
extern fn aegis_bridge_block_ip(ip: u32) i32;
extern fn aegis_bridge_unblock_ip(ip: u32) i32;
extern fn aegis_bridge_get_event_count() u32;
extern fn aegis_bridge_get_dropped_count() u32;
extern fn aegis_bridge_get_defcon_label() [*:0]const u8;
extern fn aegis_bridge_get_defcon_description() [*:0]const u8;

// ====== Packet Parser Functions (extern "C" ABI) ======
extern fn aegis_parse_packet(data: [*]const u8, data_len: u32, out_event: *AegisIpcEvent) i32;
extern fn aegis_check_nop_sled(payload: [*]const u8, len: u32, min_seq: u32) i32;
extern fn aegis_check_malformed(data: [*]const u8, data_len: u32) i32;

// ====== Helper: Push Aho-Corasick match result to C++ Bridge ======
// After Tier-1 (Zig) fast pattern matching, push the result to the Bridge
// for Tier-2 (Python) deep inspection.
pub fn pushTier1Match(
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    rule_id: u32,
    payload_ptr: [*]const u8,
    payload_len: u32,
) i32 {
    var event: AegisIpcEvent = .{
        .event_type = 0,         // NETWORK event
        .source_ip = source_ip,
        .dest_ip = dest_ip,
        .source_port = source_port,
        .dest_port = dest_port,
        .protocol = protocol,
        .direction = 0,          // inbound
        .layer_id = 0,           // NETWORK layer
        .tier_result = 1,        // Tier-1 fast match
        .payload_length = payload_len,
        .rule_id = rule_id,
        .severity = 1,           // Medium (will be upgraded by Tier-2/3)
        .reserved = 0,
        .timestamp = 0,          // TODO: get timestamp
        .source_pid = 0,
        .defcon_impact = 4,      // ELEVATED (will be recalculated)
    };
    return aegis_bridge_push_event(&event);
}

// ====== Helper: Get DEFCON level ======
pub fn getDefconLevel() u8 {
    return aegis_bridge_get_defcon();
}

// ====== Helper: Get DEFCON label as Zig string ======
pub fn getDefconLabel() [:0]const u8 {
    const ptr = aegis_bridge_get_defcon_label();
    return std.mem.sliceTo(ptr, 0);
}
