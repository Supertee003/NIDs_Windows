//! Aegis Shield binary
//! 
//! Screening helper only - not an enforcement authority.
//! Built externally via: cargo build --release --manifest-path shield/Cargo.toml
//!
//! # Purpose
//! Passive screening and observation only.
//! All enforcement decisions route through the Rust PEP (aegis_pep.dll).
//!
//! # Quarantine Notice
//! This binary is QUARANTINED_P0 (GAP-007, PEP-001).
//! It does NOT expose any PEP enforcement symbols.
//! Negative control: fails if PEP surface reappears in shield.

use aegis_shield::{PolicyRequest, Status};

fn main() {
    println!("Aegis Shield - Screening Helper");
    println!("==================================");
    println!("Status: QUARANTINED_P0 (GAP-007, PEP-001)");
    println!("Role: Screening helper only, NOT enforcement authority");
    println!("One true PEP authority: rust-src/lib.rs (aegis_pep.dll)");
    println!();
    
    // Demonstrate screening-only behavior
    let req = PolicyRequest::new("rule_001".to_string(), "block_ip".to_string(), "nids-engine".to_string());
    let decision = "OBSERVE_ONLY";
    let st = Status::default();

    println!("Screening evaluation: {} for rule {}", decision, req.rule_id);
    println!("Shield status: {{ quota: {}, two_person: {}, defcon: {} }}", 
        st.quota_remaining, st.two_person_active, st.defcon_level);
    println!();
    println!("IMPORTANT: All enforcement decisions must route through");
    println!("the Rust PEP (rust-src/lib.rs). This shield binary");
    println!("exports no PEP symbols and serves screening only.");
}
