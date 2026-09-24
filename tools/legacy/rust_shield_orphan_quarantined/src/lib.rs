//! Aegis Shield - Rust shield library
//! 
//! THIS LIBRARY IS QUARANTINED (GAP-007, PEP-001).
//! It serves as a screening helper only and NOT an enforcement authority.
//! The one true PEP authority is rust-src/lib.rs (aegis_pep.dll).
//!
//! # Screening Only
//! - No PEP capability checking
//! - No WFP enforcement
//! - No quota tracking
//! - All decisions route through the Rust PEP
//!
//! # Quarantine Status
//! - Classification: SUPPORT (not CANONICAL)
//! - Reason: Duplicate PEP + WFP enforcement path
//! - Exit criteria: shield exports no PEP symbol

// Removed: PEP evaluation functionality
// Per PEP-001, all PEP enforcement must go through rust-src/lib.rs

/// Default PEP status - screening helper only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Status {
    /// Quota remaining (screening only, not enforced)
    pub quota_remaining: u32,
    /// Whether two-person rule is active (screening only)
    pub two_person_active: bool,
    /// DEFCON level from screening (informational only)
    pub defcon_level: u8,
}

impl Default for Status {
    fn default() -> Self {
        Status {
            quota_remaining: 0,
            two_person_active: false,
            defcon_level: 0,
        }
    }
}

/// Policy request type for screening
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    /// Rule ID being evaluated
    pub rule_id: String,
    /// Action being requested
    pub action: String,
    /// Source identifier
    pub source: String,
}

impl PolicyRequest {
    /// Create a new policy request (screening only)
    pub fn new(rule_id: String, action: String, source: String) -> Self {
        PolicyRequest {
            rule_id,
            action,
            source,
        }
    }
}

// Removed WFP enforcement functions per quarantine
// - aegis_pep_evaluate (dormant Zig extern removed)
// - WFP filter auth actions
// - Quota enforcement actions

// All enforcement MUST route through rust-src/lib.rs / aegis_pep.dll