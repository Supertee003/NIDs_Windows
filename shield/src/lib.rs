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
    let Some(input) = (unsafe { ptr.as_ref() }) else { return -1 };
    if input.len() < len { return -1; }
    pep::screen_payload(&input[..len])
}

#[cfg(test)]
mod tests {
    #[test]
    fn benign_payload_is_advisory_allow() {
        assert_eq!(crate::pep::screen_payload(b"benign"), 0);
    }
}
