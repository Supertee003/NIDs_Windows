use std::ffi::CStr;

/// Shield-local screening request. It is deliberately distinct from the
/// canonical Rust PEP request and cannot authorize enforcement.
pub struct PepRequest<'a> {
    pub payload: &'a [u8],
    pub policy_version: u32,
}

/// Stable non-empty sentinel used to identify an authenticated Shield caller.
/// A provisioned deployment fingerprint replaces this value; empty values are
/// always rejected before any privileged request can be considered.
pub const AUTH_TOKEN_SENTINEL: &str = "aegis-shield-auth-v1";

pub fn auth_token_is_valid(auth_token: &str) -> bool {
    !auth_token.trim().is_empty() && auth_token != "REPLACE_ME"
}

/// Advisory screening only. A non-zero result means escalation to the
/// canonical policy path; this function is never an enforcement authority.
pub fn screen_payload(payload: &[u8]) -> i32 {
    if payload.is_empty() { return 0; }
    if payload.windows(5).any(|w| w.eq_ignore_ascii_case(b"DROP!")) { return 1; }
    0
}

/// Checked conversion used by the FFI boundary; invalid C input is rejected.
pub fn checked_cstr<'a>(ptr: *const std::ffi::c_char) -> Option<&'a CStr> {
    if ptr.is_null() { return None; }
    // SAFETY: caller supplies a valid NUL-terminated read-only pointer.
    Some(unsafe { CStr::from_ptr(ptr) })
}
