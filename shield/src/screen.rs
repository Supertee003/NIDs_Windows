//! Shield screening predicate — the ONLY logic behind the Tier-3 provider.
//!
//! This module was `pep.rs` until the PEP-001 migration slice. The former
//! second-PEP request/quota/auth surface (PepRequest, AUTH_TOKEN_SENTINEL,
//! auth_token_is_valid, checked_cstr) was dead code with no caller anywhere
//! in the tree and is removed. What remains is the advisory screening
//! predicate the Zig core actually calls through `aegis_shield_screen`
//! (loaded DynLib-only by src/policy/shield_screen.zig).
//!
//! This function never authorizes enforcement and never touches WFP
//! mutation. The sole enforcement authority is the Rust PEP (rust-src/lib.rs).

/// Advisory screening only. A non-zero result means escalation to the
/// canonical policy path; this predicate is never an enforcement authority.
pub fn screen_payload(payload: &[u8]) -> i32 {
    if payload.is_empty() {
        return 0;
    }
    if payload.windows(5).any(|w| w.eq_ignore_ascii_case(b"DROP!")) {
        return 1;
    }
    0
}
