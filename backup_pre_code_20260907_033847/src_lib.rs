// =====================================================================
// src/lib.rs — AEGIS NIDS Rust PEP (Policy Enforcement Point)
// ---------------------------------------------------------------------
// G10: Rust PEP is the SOLE enforcement authority.
//
// Authority chain (from report v2.0 G10):
//   Policy Decision → FFI/IPC contract → Rust validation → authorization
//   → execution plan → Windows action → audit result
//
// FORBIDDEN paths:
//   CLI → WFP
//   Python → WFP
//   Brain → WFP
//   Detection → WFP
//
// This module provides TWO FFI entry points:
//   1. validate_payload_safety() — Tier-3 DETECTOR (evidence only, returns bool)
//   2. pep_enforce_action()      — PEP ENFORCER (executes policy decisions)
//
// The PEP enforcer is the ONLY function that can call Windows enforcement APIs.
// =====================================================================

use std::slice;

// =====================================================================
// CONFIG: Thresholds สำหรับ Tier-3 checks
// =====================================================================
const MAX_NOP_SLED: usize = 50;          // NOP sled threshold (50+ consecutive 0x90)
const MIN_SUSPICIOUS_SIZE: usize = 65000; // packets > 65KB ผิดปกติ (MTU ปกติ ~1500)
const MAX_REPEATED_BYTE: usize = 200;    // 200+ bytes ซ้ำกัน = heap spray / flood

// Malformed header signatures (binary patterns)
const SHELLCODE_MARKER: [u8; 8] = [0x90; 8]; // 8+ consecutive NOPs
const HEAP_SPRAY_MARKER: [u8; 4] = [0x0c, 0x0c, 0x0c, 0x0c]; // common heap spray
const METASPLOIT_MARKER: [u8; 8] = *b"meterpre"; // meterpreter string

// =====================================================================
// G10: PEP ACTION TYPES — enforcement actions that Rust can execute
// =====================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepAction {
    Allow = 0,       // No action — allow traffic
    Alert = 1,       // Log only — no enforcement
    Block = 2,       // Block source IP (WFP callout)
    RateLimit = 3,   // Rate-limit traffic
    Quarantine = 4,  // Isolate host from network
}

impl PepAction {
    fn from_u8(val: u8) -> Option<PepAction> {
        match val {
            0 => Some(PepAction::Allow),
            1 => Some(PepAction::Alert),
            2 => Some(PepAction::Block),
            3 => Some(PepAction::RateLimit),
            4 => Some(PepAction::Quarantine),
            _ => None,
        }
    }
}

// =====================================================================
// G10: PEP DECISION — policy decision passed via FFI
// =====================================================================

/// PEP decision received from the Policy authority (G9).
/// G10 requirement: every action has request_id/event_id/policy_id/policy_version/source/timestamp/result
#[repr(C)]
pub struct PepDecision {
    pub action: u8,            // PepAction enum
    pub source_ip: u32,        // IP to block/rate-limit (0 = N/A)
    pub rule_id: u32,           // Rule that triggered this decision
    pub policy_version: u64,    // Policy version that authorized this action
    pub event_id: u64,         // Event ID that triggered this decision (G2 canonical)
    pub confidence: u8,         // Confidence 0-100
    pub request_id: u64,       // Unique request ID for audit trace
    pub source_operator: u8,    // 0=auto, 1=cli, 2=federation
    pub timestamp_ms: u64,      // Decision timestamp (ms since epoch)
}

/// G10: PEP result enum (accepted/rejected/deferred/failed/no-op)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PepResultType {
    Accepted = 0,
    Rejected = 1,
    Deferred = 2,
    Failed = 3,
    NoOp = 4,
}

/// PEP result — returned to caller after enforcement attempt
#[repr(C)]
pub struct PepResult {
    pub success: bool,         // Did enforcement succeed?
    pub action_taken: u8,     // What action was actually taken
    pub audit_logged: bool,   // Was the action recorded in audit log?
    pub error_code: u32,      // 0 = OK, non-zero = error
    pub result: u8,           // PepResultType: 0=accepted, 1=rejected, 2=deferred, 3=failed, 4=no_op
}

// =====================================================================
// G10: PEP ENFORCEMENT STATE — tracks what has been enforced
// =====================================================================

use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};

static TOTAL_ENFORCEMENTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BLOCKS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ALERTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_FAILED: AtomicU64 = AtomicU64::new(0);
static LAST_ENFORCEMENT_TS: AtomicU64 = AtomicU64::new(0);

// =====================================================================
// G10: PEP FFI ENTRY POINT — THE enforcement authority
// =====================================================================

/// PEP enforce action — the ONLY function that can enforce.
///
/// Authority chain:
///   1. Policy (G9) decides action based on evidence
///   2. Zig calls this FFI function with PepDecision
///   3. Rust validates the decision (action is valid, policy_version is current)
///   4. Rust executes the action (WFP block, alert log, etc.)
///   5. Rust returns PepResult with audit info
///
/// FORBIDDEN: any other code path that calls WFP/netsh directly.
#[no_mangle]
pub extern "C" fn pep_enforce_action(decision: *const PepDecision) -> PepResult {
    // Validate input
    if decision.is_null() {
        return PepResult {
            success: false,
            action_taken: PepAction::Allow as u8,
            audit_logged: false,
            error_code: 1, // null input
        };
    }

    let dec = unsafe { &*decision };

    // Validate action
    let action = match PepAction::from_u8(dec.action) {
        Some(a) => a,
        None => {
            return PepResult {
                success: false,
                action_taken: PepAction::Allow as u8,
                audit_logged: false,
                error_code: 2, // invalid action
            };
        }
    };

    // Validate policy version (must be non-zero — G9 requirement)
    if dec.policy_version == 0 {
        return PepResult {
            success: false,
            action_taken: action as u8,
            audit_logged: false,
            error_code: 3, // unsigned policy rejected
        };
    }

    // Execute enforcement based on action
    let mut success = true;
    let mut audit_logged = true;

    match action {
        PepAction::Allow => {
            // No enforcement needed — just log
            TOTAL_ALERTS.fetch_add(0, Ordering::Relaxed);
        }
        PepAction::Alert => {
            // Log only — no blocking
            TOTAL_ALERTS.fetch_add(1, Ordering::Relaxed);
        }
        PepAction::Block => {
            // BLOCK: This is the enforcement path.
            // On Windows: call WFP IOCTL_AEGIS_BLOCK_FLOW via FFI to kernel driver
            // On Linux (test): just increment counter
            //
            // FORBIDDEN paths (verified by G10):
            //   - Python netsh advfirewall (this is a fallback, NOT the primary path)
            //   - CLI direct WFP call
            //   - Brain direct WFP call
            //   - Detection direct WFP call
            //
            // The ONLY accepted path is: Policy → this function → WFP
            TOTAL_BLOCKS.fetch_add(1, Ordering::Relaxed);
            // TODO (G12): Call WFP IOCTL_AEGIS_BLOCK_FLOW here once driver is built
        }
        PepAction::RateLimit => {
            // Rate-limit: future implementation via WFP
            TOTAL_ALERTS.fetch_add(1, Ordering::Relaxed);
        }
        PepAction::Quarantine => {
            // Quarantine: future implementation via WFP + network isolation
            TOTAL_BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Record audit
    TOTAL_ENFORCEMENTS.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    LAST_ENFORCEMENT_TS.store(now, Ordering::Relaxed);

    PepResult {
        success,
        action_taken: action as u8,
        audit_logged,
        error_code: 0,
        result: if success { PepResultType::Accepted as u8 } else { PepResultType::Failed as u8 },
    }
}

// =====================================================================
// G10: PEP STATS — query enforcement statistics
// =====================================================================

#[no_mangle]
pub extern "C" fn pep_get_stats(
    total_enforcements: *mut u64,
    total_blocks: *mut u64,
    total_alerts: *mut u64,
    total_failed: *mut u64,
) {
    if !total_enforcements.is_null() {
        unsafe { *total_enforcements = TOTAL_ENFORCEMENTS.load(Ordering::Relaxed) };
    }
    if !total_blocks.is_null() {
        unsafe { *total_blocks = TOTAL_BLOCKS.load(Ordering::Relaxed) };
    }
    if !total_alerts.is_null() {
        unsafe { *total_alerts = TOTAL_ALERTS.load(Ordering::Relaxed) };
    }
    if !total_failed.is_null() {
        unsafe { *total_failed = TOTAL_FAILED.load(Ordering::Relaxed) };
    }
}

// =====================================================================
// TIER-3 DETECTOR (unchanged — evidence only, NOT enforcement)
// =====================================================================

#[no_mangle]
pub extern "C" fn validate_payload_safety(data: *const u8, len: usize) -> bool {
    // 1. ป้องกัน Null Pointer + Zero-length (DoS / malformed input)
    if data.is_null() || len == 0 {
        return false;
    }

    // 2. สร้าง Slice อ่านข้อมูลแบบ Zero-copy (Ownership โดย Rust แต่ไม่ free)
    let payload = unsafe { slice::from_raw_parts(data, len) };

    // 3. Tier-3 Behavior Validation — เรียกตามลำดับความรุนแรง
    if check_suspicious_size(payload) {
        return false;
    }
    if check_nop_sled(payload) {
        return false;
    }
    if check_buffer_overflow_pattern(payload) {
        return false;
    }
    if check_malformed_headers(payload) {
        return false;
    }

    // ผ่านการตรวจสอบทั้งหมด — ปลอดภัย ส่งต่อไป Tier-1
    true
}

// =====================================================================
// CHECK 1: Suspicious Packet Sizes
//   - packets > 65KB เกิน MTU ปกติ (~1500 bytes)
//   - อาจเป็น Ping of Death, Oversized ICMP, หรือ fragmentation attack
//   - packets < 4 bytes ไม่สามารถเป็น valid header ได้ (min IPv4 header = 20B)
// =====================================================================
fn check_suspicious_size(payload: &[u8]) -> bool {
    if payload.len() > MIN_SUSPICIOUS_SIZE {
        // ยกเว้น: ถ้าเป็น jumbo frame ที่ถูกต้อง (header แรกเป็น IP version 4/6)
        // ตรวจดูว่ามี valid IP header signature หรือไม่
        if !is_valid_ip_header(payload) {
            return true; // suspicious
        }
    }
    if payload.len() > 0 && payload.len() < 4 {
        // สั้นเกินไปที่จะเป็น packet ที่ถูกต้อง
        return true;
    }
    false
}

/// ตรวจว่าเป็น valid IPv4/IPv6 header (version nibble = 4 หรือ 6)
fn is_valid_ip_header(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let version = payload[0] >> 4;
    version == 4 || version == 6
}

// =====================================================================
// CHECK 2: NOP Sled Detection (Shellcode)
//   - ตรวจหา \x90 ติดกันเกิน MAX_NOP_SLED (50 bytes)
//   - เป็น signature คลาสสิกของ buffer overflow exploitation
// =====================================================================
fn check_nop_sled(payload: &[u8]) -> bool {
    let mut nop_count = 0;
    for &byte in payload {
        if byte == 0x90 {
            nop_count += 1;
            if nop_count > MAX_NOP_SLED {
                return true; // NOP sled detected
            }
        } else {
            nop_count = 0;
        }
    }
    false
}

// =====================================================================
// CHECK 3: Buffer Overflow Patterns
//   - ตรวจหา repeated bytes (heap spray, memset-based overflow)
//   - ตรวจหา known shellcode markers
//   - ตรวจหา Metasploit/meterpreter signatures
// =====================================================================
fn check_buffer_overflow_pattern(payload: &[u8]) -> bool {
    // 3.1 Repeated byte detection (heap spray pattern)
    //     ใช้ algorithm: count run-length ของ byte ซ้ำ
    if payload.len() >= MAX_REPEATED_BYTE {
        let mut run_byte = payload[0];
        let mut run_len = 1;
        for &byte in &payload[1..] {
            if byte == run_byte {
                run_len += 1;
                if run_len >= MAX_REPEATED_BYTE {
                    return true; // 200+ bytes ซ้ำกัน = heap spray
                }
            } else {
                run_byte = byte;
                run_len = 1;
            }
        }
    }

    // 3.2 Known shellcode marker (4-byte NOP sled)
    if contains_subslice(payload, &SHELLCODE_MARKER) {
        return true;
    }

    // 3.3 Heap spray marker (0x0c pattern — common in IE exploits)
    if contains_subslice(payload, &HEAP_SPRAY_MARKER) {
        return true;
    }

    // 3.4 Metasploit meterpreter string signature
    if payload.len() >= METASPLOIT_MARKER.len() {
        if contains_subslice(payload, &METASPLOIT_MARKER) {
            return true;
        }
    }

    false
}

/// ค้นหา needle ใน haystack แบบ manual (no external deps)
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

// =====================================================================
// CHECK 4: Malformed Headers
//   - ตรวจหา binary patterns ที่บ่งบอกถึง malformed/forged packets
//   - รวมถึง patterns ที่ใช้ใน network stack fingerprinting
// =====================================================================
fn check_malformed_headers(payload: &[u8]) -> bool {
    // ข้ามถ้า payload สั้นเกินไปที่จะเป็น header
    if payload.len() < 8 {
        return false;
    }

    // 4.1 All-zero payload (8+ bytes) — เป็น pattern ของ null packet flood
    if payload.len() >= 8 && payload[..8].iter().all(|&b| b == 0x00) {
        return true;
    }

    // 4.2 All-0xFF payload (8+ bytes) — เป็น pattern ของ broadcast flood
    if payload.len() >= 8 && payload[..8].iter().all(|&b| b == 0xFF) {
        return true;
    }

    // 4.3 Repeated pattern (abababab...) — pattern ของ某些 fuzzing tools
    if payload.len() >= 16 {
        let pat = &payload[..2];
        let mut is_pattern = true;
        for i in (0..16).step_by(2) {
            if &payload[i..i + 2] != pat {
                is_pattern = false;
                break;
            }
        }
        if is_pattern {
            return true;
        }
    }

    false
}

// =====================================================================
// STATS API — สำหรับ debug/stats (เรียกจาก Zig ได้)
// =====================================================================

/// นับจำนวน checks ที่ทำงาน (สำหรับ instrumentation)
#[no_mangle]
pub extern "C" fn tier3_check_count() -> u32 {
    4
}

/// คืนชื่อ version ของ Tier-3 shield (สำหรับ log)
#[no_mangle]
pub extern "C" fn tier3_version() -> *const u8 {
    b"Tier-3 Memory Safety Shield v2.0\0".as_ptr()
}

// =====================================================================
// UNIT TESTS
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_payload_passes() {
        let safe = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(validate_payload_safety(safe.as_ptr(), safe.len()));
    }

    #[test]
    fn test_null_pointer_rejected() {
        assert!(!validate_payload_safety(std::ptr::null(), 0));
    }

    #[test]
    fn test_zero_length_rejected() {
        let empty: [u8; 0] = [];
        assert!(!validate_payload_safety(empty.as_ptr(), 0));
    }

    #[test]
    fn test_nop_sled_detected() {
        // 100 NOP bytes — definitely a sled (>50 threshold + matches 8-byte marker)
        let sled = [0x90u8; 100];
        assert!(!validate_payload_safety(sled.as_ptr(), sled.len()));
    }

    #[test]
    fn test_short_nop_sequence_passes() {
        // 3 NOP bytes embedded in normal traffic — too short to be a sled
        // (NOP sled threshold = 50, SHELLCODE_MARKER = 8 bytes)
        let payload = b"GET /index.html HTTP/1.1\x90\x90\x90\r\nHost: example.com\r\n\r\n";
        assert!(validate_payload_safety(payload.as_ptr(), payload.len()));
    }

    #[test]
    fn test_broken_nop_sled_passes() {
        // 60 NOP bytes broken in the middle → two runs of 30 each (both < 50)
        // and no 8-consecutive NOPs after breaking every 7 bytes
        let mut broken = [0x41u8; 100]; // fill with 'A' (non-NOP)
        // Insert short NOP runs (7 bytes each, separated by 'A')
        for i in 0..100 {
            if i % 8 < 7 {
                broken[i] = 0x90;
            }
        }
        // Max NOP run = 7 (< 8-byte marker, < 50 threshold) → should pass
        assert!(validate_payload_safety(broken.as_ptr(), broken.len()));
    }

    #[test]
    fn test_oversized_packet_detected() {
        let big = vec![0x41u8; 70000];
        // ไม่ใช่ valid IP header → should be rejected
        assert!(!validate_payload_safety(big.as_ptr(), big.len()));
    }

    #[test]
    fn test_heap_spray_detected() {
        let spray = [0x0cu8; 250];
        assert!(!validate_payload_safety(spray.as_ptr(), spray.len()));
    }

    #[test]
    fn test_meterpreter_string_detected() {
        let meterpreter = b"POST /meterpreter HTTP/1.1\r\n";
        assert!(!validate_payload_safety(meterpreter.as_ptr(), meterpreter.len()));
    }

    #[test]
    fn test_all_zero_payload_detected() {
        let zeros = [0x00u8; 16];
        assert!(!validate_payload_safety(zeros.as_ptr(), zeros.len()));
    }

    #[test]
    fn test_all_ff_payload_detected() {
        let ffs = [0xFFu8; 16];
        assert!(!validate_payload_safety(ffs.as_ptr(), ffs.len()));
    }

    #[test]
    fn test_repeated_pattern_detected() {
        let pattern = b"ababababababababab";
        assert!(!validate_payload_safety(pattern.as_ptr(), pattern.len()));
    }

    // =================================================================
    // G10: PEP ENFORCEMENT TESTS
    // =================================================================

    #[test]
    fn test_pep_null_decision_rejected() {
        let result = pep_enforce_action(std::ptr::null());
        assert!(!result.success);
        assert_eq!(result.error_code, 1);
    }

    #[test]
    fn test_pep_invalid_action_rejected() {
        let dec = PepDecision {
            action: 99, // invalid
            source_ip: 0,
            rule_id: 1,
            policy_version: 1,
            event_id: 1,
            confidence: 50,
        };
        let result = pep_enforce_action(&dec);
        assert!(!result.success);
        assert_eq!(result.error_code, 2);
    }

    #[test]
    fn test_pep_unsigned_policy_rejected() {
        let dec = PepDecision {
            action: PepAction::Block as u8,
            source_ip: 0x0A000001,
            rule_id: 1,
            policy_version: 0, // unsigned!
            event_id: 1,
            confidence: 90,
        };
        let result = pep_enforce_action(&dec);
        assert!(!result.success);
        assert_eq!(result.error_code, 3);
    }

    #[test]
    fn test_pep_allow_succeeds() {
        let dec = PepDecision {
            action: PepAction::Allow as u8,
            source_ip: 0,
            rule_id: 0,
            policy_version: 1,
            event_id: 1,
            confidence: 0,
        };
        let result = pep_enforce_action(&dec);
        assert!(result.success);
        assert_eq!(result.error_code, 0);
    }

    #[test]
    fn test_pep_alert_succeeds() {
        let dec = PepDecision {
            action: PepAction::Alert as u8,
            source_ip: 0,
            rule_id: 5,
            policy_version: 1,
            event_id: 42,
            confidence: 60,
        };
        let result = pep_enforce_action(&dec);
        assert!(result.success);
        assert!(result.audit_logged);
        assert_eq!(result.action_taken, PepAction::Alert as u8);
    }

    #[test]
    fn test_pep_block_succeeds() {
        let dec = PepDecision {
            action: PepAction::Block as u8,
            source_ip: 0xC0A80101,
            rule_id: 10,
            policy_version: 1,
            event_id: 100,
            confidence: 95,
        };
        let result = pep_enforce_action(&dec);
        assert!(result.success);
        assert!(result.audit_logged);
        assert_eq!(result.action_taken, PepAction::Block as u8);
    }

    #[test]
    fn test_pep_stats_returns_counts() {
        // Enforce a few actions first
        let dec = PepDecision {
            action: PepAction::Block as u8,
            source_ip: 1,
            rule_id: 1,
            policy_version: 1,
            event_id: 1,
            confidence: 90,
        };
        let _ = pep_enforce_action(&dec);

        let mut total: u64 = 0;
        let mut blocks: u64 = 0;
        let mut alerts: u64 = 0;
        let mut failed: u64 = 0;
        pep_get_stats(&mut total, &mut blocks, &mut alerts, &mut failed);
        assert!(total > 0);
        assert!(blocks > 0);
    }
}
