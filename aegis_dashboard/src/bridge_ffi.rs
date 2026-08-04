/**
 * aegis_dashboard/src/bridge_ffi.rs — Bridge FFI bindings for egui Dashboard
 *
 * Pure Rust calls to C++ Bridge via extern "C" ABI.
 * Zero HTTP, Zero API — direct memory-level IPC.
 *
 * When Bridge DLL is not available, gracefully degrades to
 * reading from SQLite database + Rules.json file.
 */

use std::os::raw::{c_int, c_uint, c_ulong, c_char};
use std::sync::atomic::{AtomicBool, Ordering};

static BRIDGE_AVAILABLE: AtomicBool = AtomicBool::new(false);

// ====== IPC Event (matches C++ IpcEvent — 48 bytes) ======
#[repr(C, packed)]
pub struct IpcEvent {
    pub event_type:      c_uint,
    pub source_ip:       c_uint,
    pub dest_ip:         c_uint,
    pub source_port:     c_uint,
    pub dest_port:       c_uint,
    pub protocol:        c_uint,
    pub direction:       c_uint,
    pub layer_id:        c_uint,
    pub tier_result:     c_uint,
    pub payload_length:  c_uint,
    pub rule_id:         c_uint,
    pub severity:        c_uint,
    pub reserved:        c_uint,
    pub timestamp:       c_ulong,
    pub source_pid:      c_uint,
    pub defcon_impact:   c_uint,
}

// ====== Bridge FFI Declarations ======
extern "C" {
    fn aegis_bridge_init() -> c_int;
    fn aegis_bridge_shutdown() -> c_int;
    fn aegis_bridge_push_event(event: *const IpcEvent) -> c_int;
    fn aegis_bridge_pop_event(event: *mut IpcEvent) -> c_int;
    fn aegis_bridge_get_defcon() -> c_uint;
    fn aegis_bridge_update_defcon(critical: c_uint, blocked: c_uint,
                                  kernel: c_uint, total: c_uint);
    fn aegis_bridge_block_ip(ip: c_uint) -> c_int;
    fn aegis_bridge_unblock_ip(ip: c_uint) -> c_int;
    fn aegis_bridge_get_event_count() -> c_uint;
    fn aegis_bridge_get_dropped_count() -> c_uint;
    fn aegis_bridge_get_defcon_label() -> *const c_char;
    fn aegis_bridge_get_defcon_description() -> *const c_char;
}

// ====== Safe Rust API ======

/// Initialize Bridge connection. Returns true if Bridge DLL is available.
pub fn init() -> bool {
    // Try to load and initialize Bridge
    let result = unsafe { aegis_bridge_init() };
    let available = result == 0;
    BRIDGE_AVAILABLE.store(available, Ordering::SeqCst);
    available
}

/// Shutdown Bridge connection
pub fn shutdown() {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_shutdown(); }
    }
}

/// Check if Bridge is connected
pub fn is_available() -> bool {
    BRIDGE_AVAILABLE.load(Ordering::SeqCst)
}

/// Get DEFCON level (1-5). Returns 5 (SAFE) if Bridge unavailable.
pub fn get_defcon_level() -> u8 {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_get_defcon() as u8 }
    } else {
        5 // SAFE when disconnected
    }
}

/// Get DEFCON label string
pub fn get_defcon_label() -> String {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe {
            let ptr = aegis_bridge_get_defcon_label();
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    } else {
        "SAFE (Bridge offline)".to_string()
    }
}

/// Get DEFCON description string
pub fn get_defcon_description() -> String {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe {
            let ptr = aegis_bridge_get_defcon_description();
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    } else {
        "Bridge is not connected. Displaying cached data.".to_string()
    }
}

/// Block an IP address via Bridge (WFP + netsh)
pub fn block_ip(ip: u32) -> bool {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_block_ip(ip as c_uint) == 0 }
    } else {
        tracing::warn!("Bridge offline — cannot block IP {}", ip_to_string(ip));
        false
    }
}

/// Unblock an IP address
pub fn unblock_ip(ip: u32) -> bool {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_unblock_ip(ip as c_uint) == 0 }
    } else {
        false
    }
}

/// Pop next event from Bridge ring buffer. Returns None if empty.
pub fn pop_event() -> Option<IpcEvent> {
    if !BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        return None;
    }
    let mut event = unsafe { std::mem::zeroed::<IpcEvent>() };
    let result = unsafe { aegis_bridge_pop_event(&mut event) };
    if result == 0 { Some(event) } else { None }
}

/// Get total event count from Bridge
pub fn get_event_count() -> u32 {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_get_event_count() as u32 }
    } else {
        0
    }
}

/// Get dropped event count from Bridge
pub fn get_dropped_count() -> u32 {
    if BRIDGE_AVAILABLE.load(Ordering::SeqCst) {
        unsafe { aegis_bridge_get_dropped_count() as u32 }
    } else {
        0
    }
}

/// Convert u32 IP to dotted-decimal string
pub fn ip_to_string(ip: u32) -> String {
    format!("{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Parse dotted-decimal IP to u32
pub fn string_to_ip(s: &str) -> Option<u32> {
    let parts: Vec<u8> = s.split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    if parts.len() == 4 {
        Some(((parts[0] as u32) << 24) |
             ((parts[1] as u32) << 16) |
             ((parts[2] as u32) << 8) |
              (parts[3] as u32))
    } else {
        None
    }
}

/// Get DEFCON color for egui rendering
pub fn defcon_color(level: u8) -> egui::Color32 {
    match level {
        1 => egui::Color32::from_rgb(220, 38, 38),   // RED — MAXIMUM
        2 => egui::Color32::from_rgb(249, 115, 22),   // ORANGE — SEVERE
        3 => egui::Color32::from_rgb(234, 179, 8),    // YELLOW — HIGH
        4 => egui::Color32::from_rgb(59, 130, 246),   // BLUE — ELEVATED
        _ => egui::Color32::from_rgb(34, 197, 94),    // GREEN — SAFE
    }
}

/// Protocol number to name
pub fn protocol_name(proto: u32) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        58 => "ICMPv6",
        _ => "OTHER",
    }
}

/// Event type to name
pub fn event_type_name(et: u32) -> &'static str {
    match et {
        0 => "NETWORK",
        1 => "KERNEL_FILE",
        2 => "KERNEL_PROCESS",
        3 => "L2_PIPE",
        _ => "UNKNOWN",
    }
}
