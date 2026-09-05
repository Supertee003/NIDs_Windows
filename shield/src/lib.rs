//! AEGIS Shield - Tier-3 FFI Layer
//! Provides C-compatible interface for the AEGIS NIDS scoring and validation engine.

pub mod windows_enforce;

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
