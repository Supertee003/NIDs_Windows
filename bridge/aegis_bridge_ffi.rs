/**
 * aegis_bridge_ffi.rs — Rust FFI Bindings for C++ IPC Bridge
 *
 * Rust Mouth (Tier-3) uses these FFI declarations to communicate with
 * the C++ IPC Bridge. The extern "C" ABI matches aegis_ipc.hpp exactly,
 * allowing Rust to push behavioral validation results and receive DEFCON state.
 *
 * Architecture: Rust Mouth → C++ Bridge (via these externs) → Go Nose
 */

// ====== IPC Event Structure (matches C++ IpcEvent — packed, 48 bytes) ======
// NOTE: C++ uses #pragma pack(push, 1) so we must match with repr(C, packed)
// field sizes match C++ exactly: u16 for ports, u8 for protocol/direction/etc.
use std::os::raw::{c_int, c_uint, c_ulong, c_char, c_uchar, c_ushort};

#[repr(C, packed)]
pub struct AegisIpcEvent {
    pub event_type:      c_uint,     // 4B — EventType enum
    pub source_ip:       c_uint,     // 4B — IPv4 source
    pub dest_ip:         c_uint,     // 4B — IPv4 dest
    pub source_port:     c_ushort,   // 2B — u16 (matches C++ exactly)
    pub dest_port:       c_ushort,   // 2B — u16 (matches C++ exactly)
    pub protocol:        c_uchar,    // 1B — u8 (matches C++ exactly)
    pub direction:       c_uchar,    // 1B — u8
    pub layer_id:        c_uchar,    // 1B — u8
    pub tier_result:     c_uchar,    // 1B — u8 — TierResult enum
    pub payload_length:  c_uint,     // 4B
    pub rule_id:         c_uint,     // 4B
    pub severity:        c_uint,     // 4B
    pub reserved:        c_uint,     // 4B
    pub timestamp:       c_ulong,    // 8B — u64
    pub source_pid:      c_uint,     // 4B
    pub defcon_impact:   c_uint,     // 4B
}   // Total: 4+4+4+2+2+1+1+1+1+4+4+4+4+8+4+4 = 48 bytes ✓

// ====== Compile-time struct size verification (Enhancement) ======
// ถ้า struct size เปลี่ยน → compile error ทันที
// ป้องกัน ABI breakage จาก padding/alignment เปลี่ยน


// Use std.compile_error for const assert (no std.assert in const context)


// ====== IPC Command Structure ======
#[repr(C, packed)]
pub struct AegisIpcCommand {
    pub command_id:        c_uint,
    pub target_subsystem:  c_uint,
    pub payload_size:      c_uint,
    pub response_expected: c_uint,
    pub timestamp:         c_ulong,
}

// ====== Compile-time struct size verification ======
const fn assert(cond: bool) -> () {
    if !cond { panic!("ABI struct size mismatch!"); }
    ()
}

const _: () = assert(std::mem::size_of::<AegisIpcEvent>() == 48);
const _: () = assert(std::mem::size_of::<AegisIpcCommand>() == 24);

// ====== IPC Bridge FFI Functions ======
extern "C" {
    pub fn aegis_bridge_init() -> c_int;
    pub fn aegis_bridge_shutdown() -> c_int;
    pub fn aegis_bridge_push_event(event: *const AegisIpcEvent) -> c_int;
    pub fn aegis_bridge_pop_event(event: *mut AegisIpcEvent) -> c_int;
    pub fn aegis_bridge_get_defcon() -> c_uint;
    pub fn aegis_bridge_update_defcon(critical: c_uint, blocked: c_uint,
                                      kernel: c_uint, total: c_uint);
    pub fn aegis_bridge_block_ip(ip: c_uint) -> c_int;
    pub fn aegis_bridge_unblock_ip(ip: c_uint) -> c_int;
    pub fn aegis_bridge_get_event_count() -> c_uint;
    pub fn aegis_bridge_get_dropped_count() -> c_uint;
    pub fn aegis_bridge_get_defcon_label() -> *const c_char;
    pub fn aegis_bridge_get_defcon_description() -> *const c_char;
}

// ====== Packet Parser FFI Functions ======
extern "C" {
    pub fn aegis_parse_packet(data: *const u8, data_len: c_uint,
                              out_event: *mut AegisIpcEvent) -> c_int;
    pub fn aegis_check_nop_sled(payload: *const u8, len: c_uint,
                                min_seq: c_uint) -> c_int;
    pub fn aegis_check_malformed(data: *const u8, data_len: c_uint) -> c_int;
}

// ====== Helper: Push Tier-3 behavioral result to C++ Bridge ======
// After Rust Mouth (Tier-3) validates a packet, push the result to Bridge
// for DEFCON aggregation and Dashboard display.
pub fn push_tier3_result(
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    rule_id: u32,
    severity: u32,
) -> i32 {
    let event = AegisIpcEvent {
        event_type:      0,       // NETWORK
        source_ip:       source_ip as c_uint,
        dest_ip:         dest_ip as c_uint,
        source_port:     source_port as c_ushort,
        dest_port:       dest_port as c_ushort,
        protocol:        protocol as c_uchar,
        direction:       0 as c_uchar, // inbound
        layer_id:        0 as c_uchar, // NETWORK layer
        tier_result:     3 as c_uchar, // Tier-3 behavioral match
        payload_length:  0,
        rule_id:         rule_id as c_uint,
        severity:        severity as c_uint,
        reserved:        0,
        timestamp:       0,       // TODO: SystemTime
        source_pid:      0,
        defcon_impact:   if severity >= 3 { 1 } else if severity >= 2 { 2 } else { 4 },
    };
    unsafe { aegis_bridge_push_event(&event) }
}

// ====== Helper: Get DEFCON level ======
pub fn get_defcon_level() -> u8 {
    unsafe { aegis_bridge_get_defcon() as u8 }
}

// ====== Helper: Get DEFCON label as Rust String ======
pub fn get_defcon_label() -> String {
    unsafe {
        let ptr = aegis_bridge_get_defcon_label();
        let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ====== DEFCON Level Constants ======
pub const DEFCON_1_MAXIMUM: u8 = 1;
pub const DEFCON_2_SEVERE:  u8 = 2;
pub const DEFCON_3_HIGH:    u8 = 3;
pub const DEFCON_4_ELEVATED: u8 = 4;
pub const DEFCON_5_SAFE:    u8 = 5;
