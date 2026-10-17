#![deny(unsafe_op_in_unsafe_fn)]

//! Shield is an advisory Tier-3 screening component (SUPPORT). It never
//! authorizes privileged actions and never calls the WFP enforcement
//! boundary. PEP-001 (2026-10-17) removed the former duplicate PEP/WFP
//! surface; the sole enforcement authority is the Rust PEP (rust-src/lib.rs).
//!
//! The crate exports exactly ONE C symbol:
//!   aegis_shield_screen(ptr: *const u8, len: usize) -> i32
//!     0 = clean/advisory-allow, >0 = suspicious (escalate to the canonical
//!     policy path, never enforce), <0 = rejected (null/oversize input).
//! The Zig core loads it DynLib-only via src/policy/shield_screen.zig.

mod screen;

#[no_mangle]
pub extern "C" fn aegis_shield_screen(ptr: *const u8, len: usize) -> i32 {
    const MAX_PAYLOAD_SIZE: usize = 4096;
    if ptr.is_null() || len > MAX_PAYLOAD_SIZE {
        return -1;
    }
    // SAFETY: the C caller supplies a valid read-only buffer of `len` bytes;
    // null and oversized inputs are rejected before constructing the slice.
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    screen::screen_payload(input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn null_pointer_is_rejected() {
        assert_eq!(crate::aegis_shield_screen(std::ptr::null(), 0), -1);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let byte = 0u8;
        assert_eq!(crate::aegis_shield_screen(&byte, 4097), -1);
    }

    #[test]
    fn ffi_benign_payload_is_advisory_allow() {
        let payload = b"benign";
        assert_eq!(crate::aegis_shield_screen(payload.as_ptr(), payload.len()), 0);
    }

    #[test]
    fn ffi_suspicious_payload_escalates_without_enforcing() {
        let payload = b"prefix DROP! suffix";
        assert_eq!(crate::aegis_shield_screen(payload.as_ptr(), payload.len()), 1);
    }

    #[test]
    fn benign_payload_is_advisory_allow() {
        assert_eq!(crate::screen::screen_payload(b"benign"), 0);
    }
}
