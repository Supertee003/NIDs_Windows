//! Shield PEP screening helper
//!
//! THIS MODULE IS QUARANTINED (GAP-007, PEP-001).
//! It is a screening helper only and NOT an enforcement authority.
//! The one true PEP authority is rust-src/lib.rs (aegis_pep.dll).
//!
//! # Design Decisions
//! - Exports NO PEP symbols (capability checking, decision making)
//! - No WFP enforcement actions
//! - Serves only as a passive screen/observer
//! - Any PEP-related functionality must route through rust-src/lib.rs
//!
//! # Quarantine Status
//! - Status: QUARANTINED_P0
//! - Reason: Duplicate PEP + WFP enforcement path
//! - Exit criteria: shield exports no PEP symbol
//! - Migration: PEP-001

/// Evaluates a policy decision request.
/// 
/// # Note
/// This function exists solely for screening/observation purposes.
/// It does NOT make enforcement decisions. All enforcement decisions
/// must route through the Rust PEP (rust-src/lib.rs).
///
/// # Returns
/// Always returns ALLOW - this is a screening-only helper.
/// Enforcement decisions are made by the Rust PEP only.
#[allow(dead_code)]
pub fn evaluate(_request: &crate::policy::PolicyRequest) -> crate::pep::Decision {
    // Intentionally does NOT make a real decision
    // Routes through Rust PEP for any actual enforcement
    crate::pep::Decision::ALLOW
}

/// Gets the current PEP status.
///
/// # Note
/// This is a screening helper only. Actual quota and capability
/// tracking is managed by the Rust PEP.
pub fn status() -> crate::pep::Status {
    crate::pep::Status::default()
}

/// Checks if a policy action is permitted.
///
/// # Note
/// This function is a passive screen only. It does not gate
/// enforcement. The Rust PEP is the enforcement authority.
pub fn check_permission(_action: &str) -> bool {
    // Screening only - does not enforce
    true
}