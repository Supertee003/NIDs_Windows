/**
 * aegis_bridge_ffi.rs — Rust FFI Bindings for C++ IPC Bridge
 *
 * Rust Mouth (Tier-3) uses these FFI declarations to communicate with
 * the C++ IPC Bridge. The extern "C" ABI matches aegis_ipc.hpp exactly,
 * allowing Rust to push behavioral validation results and receive DEFCON state.
 *
 * Architecture: Rust Mouth → C++ Bridge (via these externs) → Go Nose
 */

use std::os::raw::{c_int, c_uint, c_ulong, c_char, c_ushort, c_uchar};

// ====== IPC Event Structure (matches C++ IpcEvent exactly — see aegis_ipc.hpp) ======
#[repr(C, packed)]
pub struct AegisIpcEvent {
    pub event_type:      c_uint,      // 0=NETWORK, 1=KERNEL_FILE, 2=KERNEL_PROCESS, 3=L2_PIPE
    pub source_ip:       c_uint,      // IPv4: u32
    pub dest_ip:         c_uint,      // IPv4: u32
    pub source_port:     c_ushort,    // uint16_t
    pub dest_port:       c_ushort,    // uint16_t
    pub protocol:        c_uchar,     // uint8_t (6=TCP, 17=UDP)
    pub direction:       c_uchar,     // uint8_t (0=in, 1=out)
    pub layer_id:        c_uchar,     // uint8_t
    pub tier_result:     c_uchar,     // uint8_t
    pub payload_length:  c_uint,      // u32
    pub rule_id:         c_uint,      // u32
    pub severity:        c_uint,      // u32
    pub reserved:        c_uint,      // u32
    pub timestamp:       c_ulong,     // u64
    pub source_pid:      c_uint,      // u32
    pub defcon_impact:   c_uint,      // u32
}

// ====== IPC Command Structure ======
#[repr(C, packed)]
pub struct AegisIpcCommand {
    pub command_id:        c_uint,
    pub target_subsystem:  c_uint,
    pub payload_size:      c_uint,
    pub response_expected: c_uint,
    pub timestamp:         c_ulong,
}

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
        source_port:     source_port as c_uint,
        dest_port:       dest_port as c_uint,
        protocol:        protocol as c_uint,
        direction:       0,       // inbound
        layer_id:        0,       // NETWORK layer
        tier_result:     3,       // Tier-3 behavioral match
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
