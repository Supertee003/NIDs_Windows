//! AEGIS Shield - Tier-3 FFI Layer
//! Provides C-compatible interface for the AEGIS NIDS scoring and validation engine.

pub mod windows_enforce;
pub mod pep;

use std::os::raw::{c_int, c_char};
use std::ffi::CStr;

/// Default threat threshold (Medium severity at full confidence)
pub const DEFAULT_THRESHOLD: f64 = 50.0;

/// Opaque handle for the AEGIS scoring engine
pub struct AegisEngine {
    initialized: bool,
    threshold: f64,
}

/// Map severity string to numeric score aligned with Rules.json:
///   Critical=100, High=75, Medium=50, Low=25
fn severity_to_numeric(severity: &str) -> f64 {
    match severity.to_lowercase().as_str() {
        "critical" => 100.0,
        "high" => 75.0,
        "medium" => 50.0,
        "low" => 25.0,
        _ => 0.0,
    }
}

/// FFI: Create a new AEGIS scoring engine instance
#[no_mangle]
pub extern "C" fn aegis_engine_create(threshold: f64) -> *mut AegisEngine {
    let engine = Box::new(AegisEngine {
        initialized: true,
        threshold: if threshold > 0.0 { threshold } else { DEFAULT_THRESHOLD },
    });
    Box::into_raw(engine)
}

/// FFI: Destroy an AEGIS scoring engine instance
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_destroy(engine: *mut AegisEngine) {
    if !engine.is_null() {
        let _ = Box::from_raw(engine);
    }
}

/// FFI: Score a threat event by numeric severity, returns score (0-100) or -1 on error
/// severity: 0=Low(25), 1=Medium(50), 2=High(75), 3=Critical(100)
/// confidence: must be in [0.0, 1.0], will be clamped
#[no_mangle]
pub unsafe extern "C" fn aegis_score_event(
    engine: *const AegisEngine,
    severity: c_int,
    confidence: f64,
) -> c_int {
    if engine.is_null() {
        return -1;
    }
    let eng = &*engine;
    if !eng.initialized {
        return -1;
    }

    // Map severity enum (0-3) to Rules.json numeric scale
    let severity_score: f64 = match severity {
        3 => 100.0, // Critical
        2 => 75.0,  // High
        1 => 50.0,  // Medium
        0 => 25.0,  // Low
        _ => 0.0,
    };

    // Clamp confidence to valid range
    let confidence = confidence.clamp(0.0, 1.0);

    // Final score: severity_weight * confidence
    let score = severity_score * confidence;
    score as c_int
}

/// FFI: Score a threat event by severity string, returns score (0-100) or -1 on error
/// severity_str: "Critical", "High", "Medium", or "Low"
/// confidence: must be in [0.0, 1.0], will be clamped
#[no_mangle]
pub unsafe extern "C" fn aegis_score_event_str(
    engine: *const AegisEngine,
    severity_str: *const c_char,
    confidence: f64,
) -> c_int {
    if engine.is_null() || severity_str.is_null() {
        return -1;
    }
    let eng = &*engine;
    if !eng.initialized {
        return -1;
    }

    let severity_cstr = match CStr::from_ptr(severity_str).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let severity_score = severity_to_numeric(severity_cstr);
    let confidence = confidence.clamp(0.0, 1.0);

    let score = severity_score * confidence;
    score as c_int
}

/// FFI: Check if score exceeds threshold
#[no_mangle]
pub unsafe extern "C" fn aegis_is_threat(
    engine: *const AegisEngine,
    score: c_int,
) -> c_int {
    if engine.is_null() {
        return 0;
    }
    let eng = &*engine;
    if (score as f64) >= eng.threshold {
        1
    } else {
        0
    }
}

/// FFI: Get current threshold
#[no_mangle]
pub unsafe extern "C" fn aegis_get_threshold(engine: *const AegisEngine) -> f64 {
    if engine.is_null() {
        return DEFAULT_THRESHOLD;
    }
    let eng = &*engine;
    eng.threshold
}

/// FFI: Set threshold, returns 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn aegis_set_threshold(engine: *mut AegisEngine, threshold: f64) -> c_int {
    if engine.is_null() {
        return -1;
    }
    let eng = &mut *engine;
    eng.threshold = if threshold > 0.0 { threshold } else { DEFAULT_THRESHOLD };
    0
}

// =====================================================================
// Tier-3 Payload Safety Validation (4 checks)
// =====================================================================
//
// Entry point `validate_payload_safety` is loaded in-process by the Zig
// core (core/bridge_init.zig, FnValidatePayloadSafety) via the symbol of
// the same name in `sec_monitor.dll`. It is fail-CLOSED: any invalid or
// unrecognized input is rejected as unsafe.
//
// The four checks mirror the gate defined in tests/aegis_mouth_test.py:
//   1. check_suspicious_size          - empty or oversized buffers
//   2. check_nop_sled                 - long runs of 0x90
//   3. check_buffer_overflow_pattern  - heap spray / int3 / zero fill / A-run
//   4. check_malformed_headers        - known exploit framing markers

const MAX_PAYLOAD_BYTES: usize = 65535;
const NOP_SLED_MIN_RUN: usize = 8;
const UNIFORM_FILL_MIN_RUN: usize = 8;
const ASCII_OVERFLOW_MIN_RUN: usize = 32;

/// Check 1: reject empty or oversized payload buffers.
fn check_suspicious_size(len: usize) -> bool {
    len > 0 && len <= MAX_PAYLOAD_BYTES
}

/// Check 2: reject NOP sleds (runs of 0x90).
fn check_nop_sled(data: &[u8]) -> bool {
    let mut run: usize = 0;
    for &b in data {
        if b == 0x90 {
            run += 1;
            if run >= NOP_SLED_MIN_RUN {
                return false;
            }
        } else {
            run = 0;
        }
    }
    true
}

fn is_uniform_fill(data: &[u8], byte: u8) -> bool {
    data.len() >= UNIFORM_FILL_MIN_RUN && data.iter().all(|&b| b == byte)
}

/// Check 3: reject exploit-typed buffer fills (heap spray 0x0c, int3
/// padding 0xcc, all-zero) and long ASCII overflow runs.
fn check_buffer_overflow_pattern(data: &[u8]) -> bool {
    if is_uniform_fill(data, 0x00) || is_uniform_fill(data, 0x0c) || is_uniform_fill(data, 0xcc) {
        return false;
    }
    let mut run: usize = 0;
    let mut max_run: usize = 0;
    for &b in data {
        if b == b'A' {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 0;
        }
    }
    max_run < ASCII_OVERFLOW_MIN_RUN
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Check 4: reject known exploit framing markers.
fn check_malformed_headers(data: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[
        b"meterpreter",
        b"wscript",
        b"powershell -enc",
        b"cmd.exe /c",
    ];
    !MARKERS.iter().any(|m| contains_ascii_case_insensitive(data, m))
}

/// C-ABI entry point: returns true when `data` passes all Tier-3 checks.
#[no_mangle]
pub unsafe extern "C" fn validate_payload_safety(data: *const u8, len: usize) -> bool {
    if data.is_null() || !check_suspicious_size(len) {
        return false;
    }
    let bytes = std::slice::from_raw_parts(data, len);
    check_nop_sled(bytes)
        && check_buffer_overflow_pattern(bytes)
        && check_malformed_headers(bytes)
}

/// Number of Tier-3 checks (reported to the Zig core for status).
#[no_mangle]
pub extern "C" fn tier3_check_count() -> u32 {
    4
}

/// Tier-3 shield version string.
#[no_mangle]
pub extern "C" fn tier3_version() -> *const c_char {
    b"aegis-shield 0.1.0\0".as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(data: *const u8, len: usize) -> bool {
        unsafe { validate_payload_safety(data, len) }
    }

    #[test]
    fn safe_http_payload_accepted() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(v(payload.as_ptr(), payload.len()));
    }

    #[test]
    fn null_pointer_rejected() {
        assert!(!v(std::ptr::null(), 0));
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(!v(b"".as_ptr(), 0));
    }

    #[test]
    fn oversized_payload_rejected() {
        let big = vec![b'A'; 70_000];
        assert!(!v(big.as_ptr(), big.len()));
    }

    #[test]
    fn nop_sled_rejected() {
        let sled = vec![0x90; 100];
        assert!(!v(sled.as_ptr(), sled.len()));
    }

    #[test]
    fn all_zero_payload_rejected() {
        let zeros = vec![0x00; 16];
        assert!(!v(zeros.as_ptr(), zeros.len()));
    }

    #[test]
    fn heap_spray_rejected() {
        let spray = vec![0x0c; 250];
        assert!(!v(spray.as_ptr(), spray.len()));
    }

    #[test]
    fn meterpreter_marker_rejected() {
        let meter = b"POST /meterpreter HTTP/1.1\r\n";
        assert!(!v(meter.as_ptr(), meter.len()));
    }

    #[test]
    fn tier3_check_count_returns_four() {
        assert_eq!(tier3_check_count(), 4);
    }

    #[test]
    fn tier3_version_returns_nonempty_cstr() {
        let p = tier3_version();
        assert!(!p.is_null());
        let cstr = unsafe { std::ffi::CStr::from_ptr(p) };
        assert!(!cstr.to_bytes().is_empty());
    }
}

// ============================================================
// T8: Rust PEP C-ABI shim (Step 26)
// ============================================================
//
// The PEP is exposed to Zig (and any FFI caller) via a stable C-ABI.
// The shim converts raw C inputs into the safe Rust `PepRequest`,
// invokes the safe `pep::evaluate`, and writes the result into a
// caller-provided out-parameter. This is the ONLY exposed C entry
// point for privileged action authorization.

/// C-ABI input (caller-allocated, caller-owned).
#[repr(C)]
pub struct PepRequestC {
    pub request_id: u64,
    pub event_id: u64,
    pub policy_id: u32,
    pub policy_version: u32,
    /// Must be a valid `Action` byte (0..=5). Otherwise the PEP
    /// returns REJECTED with reason "unknown action".
    pub action: u8,
    /// Target IPv4 in host byte order.
    pub target_ip: u32,
    pub target_port: u16,
    /// Null-terminated UTF-8 auth token. May not be null. Empty
    /// string is REJECTED.
    pub auth_token: *const c_char,
}

/// C-ABI output (caller-allocated; 32 bytes).
///
/// Layout (must match `shield/include/shield.h::pep_result_t` if/when
/// that header is generated; for now both sides agree on the same
/// field order):
///   [0]   status  (u8)
///   [1]   action  (u8)
///   [2..10]  request_id (u64 LE)
///   [10..14] policy_id  (u32 LE)
///   [14..22] timestamp_ms (i64 LE)
///   [22..26] auth_token_hash (u64 LE -- but only first 4 bytes used to fit)
///   [26..30] reserved
///   [30..32] reason_len (u16 LE) -- the reason string is in a separate
///           caller buffer; this field is the byte count copied there.
#[repr(C)]
pub struct PepResultC {
    pub status: u8,
    pub action: u8,
    pub request_id: u64,
    pub policy_id: u32,
    pub policy_version: u32,
    pub timestamp_ms: i64,
    pub auth_token_hash: u64,
    pub reason_len: u16,
}

/// Reason string table — fixed so the C side doesn't need to allocate.
/// Indexed by `PepStatus` value. (Status values 0..=4 -> reasons 0..=4.)
const REASONS: [&str; 5] = [
    "all checks passed",
    "rejected by policy",
    "deferred",
    "executor failed",
    "no-op (already in target state)",
];

/// C entry point: evaluate a PepRequest and write the result.
///
/// `result_out` must be a valid pointer to a `PepResultC` allocated by
/// the caller. `reason_out` must point to at least 64 bytes; the
/// reason string is truncated to 63 bytes + NUL.
///
/// Returns 0 on success, -1 if any required pointer is null.
#[no_mangle]
pub unsafe extern "C" fn aegis_pep_evaluate(
    req: *const PepRequestC,
    result_out: *mut PepResultC,
    reason_out: *mut c_char,
    reason_out_len: usize,
) -> c_int {
    if req.is_null() || result_out.is_null() || reason_out.is_null() {
        return -1;
    }
    let r = &*req;
    // Convert the auth_token C string to &'static str (the PEP signature
    // requires 'static; this is fine for the C-ABI lifetime which is
    // bounded by the call).
    let auth_token: &str = if r.auth_token.is_null() {
        ""
    } else {
        match CStr::from_ptr(r.auth_token).to_str() {
            Ok(s) => s,
            Err(_) => "",
        }
    };
    let action = match pep::Action::from_u8(r.action) {
        Some(a) => a,
        None => {
            // Unknown action -> Rejected. Build a minimal trace + write.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            (*result_out) = PepResultC {
                status: pep::PepStatus::Rejected as u8,
                action: r.action,
                request_id: r.request_id,
                policy_id: r.policy_id,
                policy_version: r.policy_version,
                timestamp_ms: now,
                auth_token_hash: 0,
                reason_len: 0,
            };
    let reason = REASONS[pep::PepStatus::Rejected as usize];
            let bytes = reason.as_bytes();
            let n = bytes.len().min(reason_out_len.saturating_sub(1));
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, reason_out, n);
            *reason_out.add(n) = 0;
            (*result_out).reason_len = n as u16;
            return 0;
        }
    };
    let pep_req = pep::PepRequest {
        request_id: r.request_id,
        event_id: r.event_id,
        policy_id: r.policy_id,
        policy_version: r.policy_version,
        action,
        target_ip: r.target_ip,
        target_port: r.target_port,
        auth_token: unsafe {
            // SAFETY: the lifetime is bounded by this call. The caller
            // (Zig core or a test) must keep the auth token buffer alive
            // for the duration of `aegis_pep_evaluate`. We transmute to
            // &'static str to satisfy the `PepRequest` signature.
            std::mem::transmute::<&str, &'static str>(auth_token)
        },
    };
    let (status, trace) = pep::evaluate(&pep_req);
    (*result_out) = PepResultC {
        status: status as u8,
        action: trace.action as u8,
        request_id: trace.request_id,
        policy_id: trace.policy_id,
        policy_version: trace.policy_version,
        timestamp_ms: trace.timestamp_ms,
        auth_token_hash: trace.auth_token_hash,
        reason_len: 0,
    };
    let reason = REASONS[status as usize];
    let bytes = reason.as_bytes();
    let n = bytes.len().min(reason_out_len.saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, reason_out, n);
    *reason_out.add(n) = 0;
    (*result_out).reason_len = n as u16;
    0
}

/// Number of PEP statuses (for the Zig side to know the reason table).
#[no_mangle]
pub extern "C" fn aegis_pep_status_count() -> u32 {
    5
}

/// PEP version string.
#[no_mangle]
pub extern "C" fn aegis_pep_version() -> *const c_char {
    b"aegis-pep 1.0.0\0".as_ptr() as *const c_char
}

#[cfg(test)]
mod pep_abi_tests {
    use super::*;
    use std::ffi::CString;

    fn make_c_request_with_auth() -> (PepRequestC, CString) {
        let auth = CString::new("tpm-sentinel").unwrap();
        // 10.0.0.5 = 0x0A << 24 | 0 << 16 | 0 << 8 | 5
        let target_ip: u32 = (10u32 << 24) | 5;
        let req = PepRequestC {
            request_id: 100,
            event_id: 42,
            policy_id: 7,
            policy_version: 5,
            action: pep::Action::Block as u8,
            target_ip,
            target_port: 80,
            auth_token: auth.as_ptr(),
        };
        (req, auth) // caller must keep auth alive for the duration of the call
    }

    #[test]
    fn abi_accepts_legitimate_block() {
        let (req, _auth) = make_c_request_with_auth();
        let mut result = unsafe { std::mem::zeroed::<PepResultC>() };
        let mut reason = [0u8; 64];
        let rc = unsafe { aegis_pep_evaluate(&req, &mut result, reason.as_mut_ptr() as *mut c_char, reason.len()) };
        assert_eq!(rc, 0, "rc was {}; reason={:?}", rc, std::str::from_utf8(&reason[..result.reason_len as usize]).unwrap_or("<bad utf8>"));
        assert_eq!(result.status, pep::PepStatus::Accepted as u8);
        assert_eq!(result.request_id, 100);
        assert_eq!(result.policy_id, 7);
        assert!(result.reason_len > 0);
    }

    #[test]
    fn abi_rejects_null_inputs() {
        let mut result = unsafe { std::mem::zeroed::<PepResultC>() };
        let mut reason = [0u8; 64];
        let rc = unsafe {
            aegis_pep_evaluate(
                std::ptr::null(),
                &mut result,
                reason.as_mut_ptr() as *mut c_char,
                reason.len(),
            )
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn abi_status_count_is_5() {
        assert_eq!(aegis_pep_status_count(), 5);
    }

    #[test]
    fn abi_version_is_nonempty() {
        let p = aegis_pep_version();
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) };
        assert!(!s.to_bytes().is_empty());
    }
}
