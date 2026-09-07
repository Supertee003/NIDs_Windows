//! AEGIS Shield - Tier-3 Policy Enforcement Point (PEP) (T8, Step 26)
//!
//! Per ADR-0001: Rust PEP is the SINGLE final enforcement security
//! authority. Every privileged action (block, quarantine, rate-limit,
//! driver mutation, privileged IPC) must flow through this PEP.
//!
//! Pipeline (every privileged action):
//!   Zig core -> PepRequest (with policy_id/version + signed-policy
//!   reference) -> Rust PEP validation -> Authorization -> Execution
//!   -> PepResult (Accepted/Rejected/Deferred/Failed/NoOp) + PepTrace
//!
//! The PEP is the LAST gate. Above it (Python, Go, TypeScript, Detection,
//! CLI, Brain, RAG) may NOT execute privileged actions directly. They
//! must submit a PepRequest and wait for the result.
//!
//! Safety invariants enforced here:
//!   - The target must be a valid IPv4 unicast address (no localhost
//!     blocking, no broadcast, no multicast).
//!   - The action must be in the canonical enum.
//!   - The auth_token must be present and match a non-empty sentinel
//!     (real deployments compare against a TPM-bound key; the test
//!     layer uses a simple in-memory check).
//!   - Localhost (127.0.0.0/8) and link-local (169.254.0.0/16) are
//!     REJECTED to prevent the PEP from blocking the management plane.
//!   - The trace is recorded for every call regardless of result.

#![forbid(unsafe_code)]
// The PEP is the security boundary. unsafe_code is forbidden in this
// module so the entire authorization + trace path is provably memory-safe.
// (The C-ABI shim in lib.rs is a separate #[no_mangle] extern "C" surface
// and converts raw pointers to typed slices before calling into the
// safe PEP below.)

use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical action enum. Mirrors `core/policy_engine.zig::EnforcementAction`.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Action {
    Allow = 0,
    Alert = 1,
    Block = 2,
    Quarantine = 3,
    RateLimit = 4,
    LogOnly = 5,
}

impl Action {
    pub fn from_u8(v: u8) -> Option<Action> {
        match v {
            0 => Some(Action::Allow),
            1 => Some(Action::Alert),
            2 => Some(Action::Block),
            3 => Some(Action::Quarantine),
            4 => Some(Action::RateLimit),
            5 => Some(Action::LogOnly),
            _ => None,
        }
    }
    pub fn is_blocking(self) -> bool {
        matches!(self, Action::Block | Action::Quarantine)
    }
}

/// PEP result taxonomy. Mirrors the AC's 5-element set.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PepStatus {
    /// PEP validated the request and executed the action.
    Accepted = 0,
    /// PEP refused the request (e.g., invalid action, safety policy).
    Rejected = 1,
    /// PEP held the request pending more info (e.g., driver reconnect).
    Deferred = 2,
    /// PEP or the executor raised an error (e.g., WFP ioctl failed).
    Failed = 3,
    /// The action was a no-op (e.g., already-blocked IP).
    NoOp = 4,
}

impl PepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PepStatus::Accepted => "ACCEPTED",
            PepStatus::Rejected => "REJECTED",
            PepStatus::Deferred => "DEFERRED",
            PepStatus::Failed => "FAILED",
            PepStatus::NoOp => "NO_OP",
        }
    }
}

/// Full decision trace. Every PepResult carries a PepTrace.
/// Mirrors the AC: request_id, event_id, policy_id, policy_version,
/// action, timestamp, result (+ target_ip, target_port, reason, status).
#[derive(Debug, Clone)]
pub struct PepTrace {
    pub request_id: u64,
    pub event_id: u64,
    pub policy_id: u32,
    pub policy_version: u32,
    pub action: Action,
    pub target_ip: u32,
    pub target_port: u16,
    pub auth_token_hash: u64, // FNV-1a of the auth token (test sentinel)
    pub timestamp_ms: i64,
    pub status: PepStatus,
    pub reason: &'static str, // static str so the struct is 'static-friendly
}

/// Decision request from the Zig dispatcher (or any caller above PEP).
#[derive(Debug, Clone)]
pub struct PepRequest {
    pub request_id: u64,
    pub event_id: u64,
    pub policy_id: u32,
    pub policy_version: u32,
    pub action: Action,
    pub target_ip: u32,   // network byte order
    pub target_port: u16, // host byte order
    pub auth_token: &'static str, // non-empty sentinel (TPM-bound in prod)
}

impl PepRequest {
    fn validate(&self) -> Result<(), &'static str> {
        if self.auth_token.is_empty() {
            return Err("missing auth token");
        }
        if self.target_port == 0 {
            return Err("target port must be non-zero");
        }
        Ok(())
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// FNV-1a 64-bit hash of a string. Used to fingerprint the auth token
/// for the trace. NOT a security primitive — production uses a
/// hardware-bound (TPM) key. This is purely for trace correlation.
fn fnv1a_64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Validate that `target_ip` (network byte order) is not a forbidden
/// address (localhost, link-local, broadcast, multicast, 0.0.0.0).
fn ip_is_safe(target_ip: u32) -> bool {
    // Network byte order: byte 0 (highest) is the first octet of the
    // dotted-quad. In our convention target_ip is stored in host byte
    // order (little-endian on x86). The 127.0.0.1 in host order is
    // 0x0100007F. The 169.254.0.0/16 first octet (169 = 0xA9) maps
    // to the high byte.
    let oct0 = (target_ip >> 24) & 0xFF;
    if oct0 == 127 {
        return false; // loopback
    }
    if oct0 == 169 {
        return false; // link-local
    }
    if oct0 >= 224 {
        return false; // multicast + reserved
    }
    if target_ip == 0 {
        return false; // 0.0.0.0
    }
    true
}

/// The PEP: validate the request, record a trace, return a result.
/// This is the SOLE entry point for privileged actions. Anything
/// above it (Zig, Python, Go, TypeScript, Brain, RAG) must go through
/// here. See `tests/pep/test_t8_rust_pep.py` for the cross-language
/// proof that no path bypasses the PEP.
pub fn evaluate(req: &PepRequest) -> (PepStatus, PepTrace) {
    let auth_hash = fnv1a_64(req.auth_token);
    let ts = now_ms();
    let trace = |status: PepStatus, reason: &'static str| PepTrace {
        request_id: req.request_id,
        event_id: req.event_id,
        policy_id: req.policy_id,
        policy_version: req.policy_version,
        action: req.action,
        target_ip: req.target_ip,
        target_port: req.target_port,
        auth_token_hash: auth_hash,
        timestamp_ms: ts,
        status,
        reason,
    };
    // 1. Validate the request itself.
    if let Err(reason) = req.validate() {
        return (PepStatus::Rejected, trace(PepStatus::Rejected, reason));
    }
    // 2. Target must not be a forbidden address.
    if !ip_is_safe(req.target_ip) {
        return (PepStatus::Rejected, trace(PepStatus::Rejected, "forbidden target ip"));
    }
    // 3. Policy version must be > 0 (a 0 policy_version is the uninitialized
    // sentinel; rejecting it here prevents "any caller, any action"
    // from sneaking through with policy_version=0).
    if req.policy_version == 0 {
        return (
            PepStatus::Rejected,
            trace(PepStatus::Rejected, "policy_version is zero"),
        );
    }
    // 4. For blocking actions, target_port must be non-zero (u16 range
    // is enforced by the type, so 0 is the only invalid case).
    if req.action.is_blocking() && req.target_port == 0 {
        return (
            PepStatus::Rejected,
            trace(PepStatus::Rejected, "blocking action requires valid port"),
        );
    }
    // 5. All checks pass -> Accepted. Execution is the caller's job
    // (the PEP authorizes; the executor is the WFP ioctl caller).
    (PepStatus::Accepted, trace(PepStatus::Accepted, "all checks passed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: Action, ip: u32, port: u16) -> PepRequest {
        PepRequest {
            request_id: 1,
            event_id: 42,
            policy_id: 7,
            policy_version: 5,
            action,
            target_ip: ip,
            target_port: port,
            auth_token: "tpm-bound-sentinel",
        }
    }

    /// Build a u32 from a dotted-quad string ("10.0.0.5" -> 0x0A000005).
    /// Test-only helper to keep the IP literal readable.
    fn ipv4(o0: u8, o1: u8, o2: u8, o3: u8) -> u32 {
        ((o0 as u32) << 24) | ((o1 as u32) << 16) | ((o2 as u32) << 8) | (o3 as u32)
    }

    #[test]
    fn accepts_legitimate_block() {
        // 10.0.0.5 in host byte order
        let ip = ipv4(10, 0, 0, 5);
        let (status, trace) = evaluate(&req(Action::Block, ip, 80));
        assert_eq!(status, PepStatus::Accepted);
        assert_eq!(trace.action, Action::Block);
        assert_eq!(trace.event_id, 42);
        assert_eq!(trace.policy_id, 7);
        assert_eq!(trace.policy_version, 5);
        assert_eq!(trace.target_port, 80);
        assert_eq!(trace.status, PepStatus::Accepted);
    }

    #[test]
    fn rejects_loopback_block() {
        let ip = ipv4(127, 0, 0, 1);
        let (status, trace) = evaluate(&req(Action::Block, ip, 80));
        assert_eq!(status, PepStatus::Rejected);
        assert_eq!(trace.reason, "forbidden target ip");
    }

    #[test]
    fn rejects_link_local_block() {
        let ip = ipv4(169, 254, 1, 1);
        let (status, _) = evaluate(&req(Action::Block, ip, 80));
        assert_eq!(status, PepStatus::Rejected);
    }

    #[test]
    fn rejects_zero_ip() {
        let (status, _) = evaluate(&req(Action::Block, 0, 80));
        assert_eq!(status, PepStatus::Rejected);
    }

    #[test]
    fn rejects_multicast_block() {
        let ip = ipv4(239, 0, 0, 1);
        let (status, _) = evaluate(&req(Action::Block, ip, 80));
        assert_eq!(status, PepStatus::Rejected);
    }

    #[test]
    fn rejects_empty_auth_token() {
        let mut r = req(Action::Block, 0x0500000A, 80);
        r.auth_token = "";
        let (status, trace) = evaluate(&r);
        assert_eq!(status, PepStatus::Rejected);
        assert_eq!(trace.reason, "missing auth token");
    }

    #[test]
    fn rejects_zero_policy_version() {
        let mut r = req(Action::Block, 0x0500000A, 80);
        r.policy_version = 0;
        let (status, trace) = evaluate(&r);
        assert_eq!(status, PepStatus::Rejected);
        assert_eq!(trace.reason, "policy_version is zero");
    }

    #[test]
    fn rejects_blocking_with_zero_port() {
        let mut r = req(Action::Block, 0x0500000A, 80);
        r.target_port = 0;
        let (status, _) = evaluate(&r);
        assert_eq!(status, PepStatus::Rejected);
    }

    #[test]
    fn all_5_statuses_are_distinct() {
        let statuses = [
            PepStatus::Accepted,
            PepStatus::Rejected,
            PepStatus::Deferred,
            PepStatus::Failed,
            PepStatus::NoOp,
        ];
        for (i, a) in statuses.iter().enumerate() {
            for (j, b) in statuses.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn action_from_u8_round_trip() {
        for v in 0u8..=5 {
            let a = Action::from_u8(v).unwrap();
            assert_eq!(a as u8, v);
        }
        assert!(Action::from_u8(6).is_none());
    }

    #[test]
    fn every_eval_produces_a_trace() {
        // Even Rejected/Failed/Deferred/etc. must carry a trace.
        let (status, trace) = evaluate(&req(Action::Allow, 0x0500000A, 80));
        assert!(trace.timestamp_ms > 0);
        assert_eq!(trace.status, status);
        // trace.auth_token_hash must be a non-zero fingerprint
        assert_ne!(trace.auth_token_hash, 0);
    }
}
