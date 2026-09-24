#![deny(unsafe_op_in_unsafe_fn)]

//! Shield is an advisory Tier-3 screening component. It never authorizes
//! privileged actions and never calls the WFP enforcement boundary.

mod pep;

use std::ffi::CStr;

/// Checked string boundary for callers that provide metadata to Shield.
/// Invalid or null pointers are rejected before any screening work.
pub fn checked_label(ptr: *const std::ffi::c_char) -> Option<String> {
    if ptr.is_null() { return None; }
    let value = unsafe { CStr::from_ptr(ptr) };
    value.to_str().ok().map(str::to_owned)
}

#[no_mangle]
pub extern "C" fn aegis_shield_screen(ptr: *const u8, len: usize) -> i32 {
    const MAX_PAYLOAD_SIZE: usize = 4096;
    if ptr.is_null() || len > MAX_PAYLOAD_SIZE { return -1; }
    // SAFETY: the C caller supplies a valid read-only buffer of `len` bytes;
    // null and oversized inputs are rejected before constructing the slice.
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    pep::screen_payload(input)
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
    fn benign_payload_is_advisory_allow() {
        assert_eq!(crate::pep::screen_payload(b"benign"), 0);
    }
}
