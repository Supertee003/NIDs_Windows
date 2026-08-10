// =====================================================================
// src/lib.rs — AEGIS NIDS Tier-3 Memory Safety Shield (Rust FFI)
// ---------------------------------------------------------------------
// หน้าที่: เป็นด่านหน้า (Pre-screen) ที่ถูกเรียกโดย Zig ผ่าน C-ABI
//          ก่อนส่ง payload เข้า Tier-1 Aho-Corasick engine
//
// ตรวจสอบ 4 ประเภทของภัยคุกคามที่มุ่งเป้าไปที่ตัว NIDS เอง:
//   1. Null/Zero-length payload (DoS prevention)
//   2. NOP sled / Buffer Overflow pattern (Shellcode detection)
//   3. Suspicious packet sizes (size-based anomalies)
//   4. Malformed headers (binary pattern checks)
//
// คืนค่า: true = ปลอดภัย (ส่งต่อไป Tier-1), false = อันตราย (Drop ทันที)
//
// ออกแบบตามหลัก Cyber Hygiene: Ownership + Zero-copy slice
//   ไม่มี allocation เพิ่ม, ไม่มี hidden GC, ไม่มี runtime overhead
// =====================================================================

use std::slice;
// ====== Metric Counters for Health State Changes (Enhancement) ======
// ใช้สำหรับ monitoring: ถ้า reject_count พุ่ง → อาจมี attack
// ถ้า panic_count > 0 → FFI มีปัญหา ต้อง investigate
// ถ้า accept_count ต่ำ → อาจมี false positive
// All counters are mutable statics (safe in single-writer FFI context)
static mut ACCEPT_COUNT: u64 = 0;
static mut REJECT_COUNT: u64 = 0;
static mut REJECT_SUSPICIOUS_SIZE: u64 = 0;
static mut REJECT_NOP_SLED: u64 = 0;
static mut REJECT_OVERFLOW: u64 = 0;
static mut REJECT_MALFORMED: u64 = 0;
static mut PANIC_COUNT: u64 = 0;

// =====================================================================
// CONFIG: Thresholds สำหรับ Tier-3 checks
// =====================================================================
const MAX_NOP_SLED: usize = 50;          // NOP sled threshold (50+ consecutive 0x90)
const MIN_SUSPICIOUS_SIZE: usize = 65000; // packets > 65KB ผิดปกติ (MTU ปกติ ~1500)
const MAX_REPEATED_BYTE: usize = 200;    // 200+ bytes ซ้ำกัน = heap spray / flood

// Malformed header signatures (binary patterns)
// ใช้ 8 bytes สำหรับ NOP marker เพราะ 4 bytes สั้นเกินไป (อาจเป็น legit padding)
const SHELLCODE_MARKER: [u8; 8] = [0x90; 8]; // 8+ consecutive NOPs
const HEAP_SPRAY_MARKER: [u8; 4] = [0x0c, 0x0c, 0x0c, 0x0c]; // common heap spray
const METASPLOIT_MARKER: [u8; 8] = *b"meterpre"; // meterpreter string

// =====================================================================
// MAIN FFI ENTRY POINT
// =====================================================================
// IMPORTANT: Return u8 (not bool) for C ABI compatibility!
// C bool size varies by platform (1 byte on MSVC, 4 bytes on some GCC)
// Using u8 eliminates ABI mismatch: 0 = unsafe, 1 = safe
//
// CRITICAL: Rust panic MUST NOT cross FFI boundary!
// If any check panics, catch_unwind returns 0 (unsafe) instead of UB.
// This is a fundamental safety rule: FFI functions must be panic-safe.
#[no_mangle]
pub extern "C" fn validate_payload_safety(data: *const u8, len: usize) -> u8 {
    // ====== Catch Unwind: prevent panic from crossing FFI boundary ======
    // If the inner function panics, we return 0 (unsafe) instead of UB.
    // This is MANDATORY for extern "C" functions per Rust RFC.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate_payload_safety_inner(data, len)
    })) {
        Ok(result) => result,
        Err(_) => {
            // Panic caught! Increment metric, return unsafe
            unsafe { PANIC_COUNT += 1; }
            0 // Treat as unsafe — conservative default
        }
    }
}

/// Inner implementation — may panic (caught by outer wrapper)
/// Uses Borrow/Slice (zero-copy) instead of ownership transfer:
///   - payload: &[u8] is a borrowed slice — no allocation, no ownership move
///   - The caller (Zig) owns the data; Rust only borrows it for inspection
///   - This follows Rust's ownership rules: borrow, don't move
fn validate_payload_safety_inner(data: *const u8, len: usize) -> u8 {
    // 1. ป้องกัน Null Pointer + Zero-length (DoS / malformed input)
    if data.is_null() || len == 0 {
        unsafe { REJECT_COUNT += 1; }
        return 0; // unsafe
    }

    // 2. สร้าง Slice อ่านข้อมูลแบบ Zero-copy (Borrow — ไม่ move ownership)
    //    Ownership: Zig เป็นเจ้าของ data, Rust เพียง borrow เพื่ออ่าน
    let payload = unsafe { slice::from_raw_parts(data, len) };

    // 3. Tier-3 Behavior Validation — เรียกตามลำดับความรุนแรง
    if check_suspicious_size(payload) {
        unsafe { REJECT_COUNT += 1; REJECT_SUSPICIOUS_SIZE += 1; }
        return 0; // unsafe
    }
    if check_nop_sled(payload) {
        unsafe { REJECT_COUNT += 1; REJECT_NOP_SLED += 1; }
        return 0; // unsafe
    }
    if check_buffer_overflow_pattern(payload) {
        unsafe { REJECT_COUNT += 1; REJECT_OVERFLOW += 1; }
        return 0; // unsafe
    }
    if check_malformed_headers(payload) {
        unsafe { REJECT_COUNT += 1; REJECT_MALFORMED += 1; }
        return 0; // unsafe
    }

    // ผ่านการตรวจสอบทั้งหมด — ปลอดภัย ส่งต่อไป Tier-1
    unsafe { ACCEPT_COUNT += 1; }
    1 // safe
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
    b"Tier-3 Memory Safety Shield v3.0 (u8-ABI)\0".as_ptr()
}

// =====================================================================
// SELF-TEST — เรียกจาก Zig หลัง load DLL เพื่อ verify ว่า FFI ทำงาน
// =====================================================================

/// FFI Self-Test: return 0xA5A5A5A5 if the Shield works correctly
/// Zig calls this after loading sec_monitor.dll to verify:
///   1. Symbol lookup succeeded
///   2. Calling convention matches
///   3. Return value size is correct (u32)
#[no_mangle]
pub extern "C" fn tier3_self_test() -> u32 {
    // Test 1: Validate a safe payload should return 1 (safe)
    let safe = b"GET / HTTP/1.1\r\n";
    let safe_result = validate_payload_safety(safe.as_ptr(), safe.len());

    // Test 2: Validate null should return 0 (unsafe)
    let null_result = validate_payload_safety(std::ptr::null(), 0);

    // If both tests pass, return magic value
    if safe_result == 1 && null_result == 0 {
        0xA5A5A5A5  // Magic: Shield works!
    } else {
        0xDEADDEAD  // Shield is broken!
    }
}

/// FFI Ping: Simple function that returns input + 1
/// Used to verify basic FFI call mechanism
#[no_mangle]
pub extern "C" fn tier3_ping(val: u32) -> u32 {
    val.wrapping_add(1)
}

// =====================================================================
// METRIC API — สำหรับ monitoring health state changes via FFI
// =====================================================================

/// Get all Tier-3 metrics as packed u64 values
/// Returns [accept_count, reject_count, panic_count] via output pointers
#[no_mangle]
pub extern "C" fn tier3_get_metrics(
    out_accept: *mut u64,
    out_reject: *mut u64,
    out_panic: *mut u64,
) {
    unsafe {
        if !out_accept.is_null() { *out_accept = ACCEPT_COUNT; }
        if !out_reject.is_null() { *out_reject = REJECT_COUNT; }
        if !out_panic.is_null() { *out_panic = PANIC_COUNT; }
    }
}

/// Get per-category reject counts
#[no_mangle]
pub extern "C" fn tier3_get_reject_detail(
    out_suspicious_size: *mut u64,
    out_nop_sled: *mut u64,
    out_overflow: *mut u64,
    out_malformed: *mut u64,
) {
    unsafe {
        if !out_suspicious_size.is_null() { *out_suspicious_size = REJECT_SUSPICIOUS_SIZE; }
        if !out_nop_sled.is_null() { *out_nop_sled = REJECT_NOP_SLED; }
        if !out_overflow.is_null() { *out_overflow = REJECT_OVERFLOW; }
        if !out_malformed.is_null() { *out_malformed = REJECT_MALFORMED; }
    }
}

// =====================================================================
// QSBR (Quiescent State-Based RCU) — สำหรับ Rust side shared data access
// =====================================================================
// QSBR เป็น variant ของ RCU ที่เหมาะกับ Rust:
//   - Thread ประกาศ "quiescent state" เมื่อไม่ได้อ่าน shared data
//   - Reclamation เกิดขึ้นเมื่อทุก thread ผ่าน quiescent state
//   - ไม่ต้องมี epoch counter (เบากว่า EBR)
//
// ใน AEGIS: Zig ใช้ EBR, Rust ใช้ QSBR เมื่อต้อง access shared state
//           ผ่าน C++ Bridge (เช่น DEFCON counters)

pub mod qsbr {
    use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

    const MAX_QSBR_THREADS: usize = 64;

    #[allow(dead_code)]
    static GLOBAL_EPOCH: AtomicUsize = AtomicUsize::new(1);
    static THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);
    static QUIESCENT: [AtomicBool; MAX_QSBR_THREADS] = {
        const FALSE: AtomicBool = AtomicBool::new(true); // Start as quiescent
        [FALSE; MAX_QSBR_THREADS]
    };

    /// Register current thread for QSBR — returns slot index
    pub fn register() -> usize {
        let slot = THREAD_COUNT.fetch_add(1, Ordering::Relaxed);
        if slot < MAX_QSBR_THREADS {
            QUIESCENT[slot].store(true, Ordering::Release);
        }
        slot
    }

    /// Unregister thread from QSBR
    pub fn unregister(slot: usize) {
        if slot < MAX_QSBR_THREADS {
            QUIESCENT[slot].store(false, Ordering::Release);
        }
        THREAD_COUNT.fetch_sub(1, Ordering::Relaxed);
    }

    /// Enter read-side critical section
    pub fn read_lock(slot: usize) {
        if slot < MAX_QSBR_THREADS {
            QUIESCENT[slot].store(false, Ordering::Release);
        }
    }

    /// Leave read-side critical section (announce quiescent state)
    pub fn read_unlock(slot: usize) {
        if slot < MAX_QSBR_THREADS {
            QUIESCENT[slot].store(true, Ordering::Release);
        }
    }

    /// Check if all threads are in quiescent state (safe to reclaim)
    /// Memory Barrier: Uses Acquire/Release ordering to ensure
    /// all prior reads from shared data are visible before reclaim
    pub fn all_quiescent() -> bool {
        // Full memory barrier before checking — ensures all prior
        // reads from shared data are complete and visible
        std::sync::atomic::fence(Ordering::SeqCst);
        let count = THREAD_COUNT.load(Ordering::Acquire);
        for i in 0..count.min(MAX_QSBR_THREADS) {
            if !QUIESCENT[i].load(Ordering::Acquire) {
                return false;
            }
        }
        true
    }

    /// Bounded deferred queue with backpressure (Enhancement)
    /// ถ้า pending reclaims เกิน MAX_PENDING → force reclaim
    const MAX_PENDING_RECLAIMS: usize = 128;
    static PENDING_COUNT: AtomicUsize = AtomicUsize::new(0);

    pub fn defer_reclaim() -> bool {
        let count = PENDING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if count > MAX_PENDING_RECLAIMS {
            // Backpressure: too many pending — force reclaim
            PENDING_COUNT.store(0, Ordering::Release);
            false // Caller should reclaim now
        } else {
            true // OK to defer
        }
    }

    pub fn complete_reclaim() {
        PENDING_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
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
        assert_eq!(validate_payload_safety(safe.as_ptr(), safe.len()), 1);
    }

    #[test]
    fn test_null_pointer_rejected() {
        assert_eq!(validate_payload_safety(std::ptr::null(), 0), 0);
    }

    #[test]
    fn test_zero_length_rejected() {
        let empty: [u8; 0] = [];
        assert_eq!(validate_payload_safety(empty.as_ptr(), 0), 0);
    }

    #[test]
    fn test_nop_sled_detected() {
        let sled = [0x90u8; 100];
        assert_eq!(validate_payload_safety(sled.as_ptr(), sled.len()), 0);
    }

    #[test]
    fn test_short_nop_sequence_passes() {
        let payload = b"GET /index.html HTTP/1.1\x90\x90\x90\r\nHost: example.com\r\n\r\n";
        assert_eq!(validate_payload_safety(payload.as_ptr(), payload.len()), 1);
    }

    #[test]
    fn test_broken_nop_sled_passes() {
        let mut broken = [0x41u8; 100];
        for i in 0..100 {
            if i % 8 < 7 {
                broken[i] = 0x90;
            }
        }
        assert_eq!(validate_payload_safety(broken.as_ptr(), broken.len()), 1);
    }

    #[test]
    fn test_oversized_packet_detected() {
        let big = vec![0x41u8; 70000];
        assert_eq!(validate_payload_safety(big.as_ptr(), big.len()), 0);
    }

    #[test]
    fn test_heap_spray_detected() {
        let spray = [0x0cu8; 250];
        assert_eq!(validate_payload_safety(spray.as_ptr(), spray.len()), 0);
    }

    #[test]
    fn test_meterpreter_string_detected() {
        let meterpreter = b"POST /meterpreter HTTP/1.1\r\n";
        assert_eq!(validate_payload_safety(meterpreter.as_ptr(), meterpreter.len()), 0);
    }

    #[test]
    fn test_all_zero_payload_detected() {
        let zeros = [0x00u8; 16];
        assert_eq!(validate_payload_safety(zeros.as_ptr(), zeros.len()), 0);
    }

    #[test]
    fn test_all_ff_payload_detected() {
        let ffs = [0xFFu8; 16];
        assert_eq!(validate_payload_safety(ffs.as_ptr(), ffs.len()), 0);
    }

    #[test]
    fn test_repeated_pattern_detected() {
        let pattern = b"ababababababababab";
        assert_eq!(validate_payload_safety(pattern.as_ptr(), pattern.len()), 0);
    }

    #[test]
    fn test_self_test_returns_magic() {
        assert_eq!(tier3_self_test(), 0xA5A5A5A5);
    }

    #[test]
    fn test_ping_returns_increment() {
        assert_eq!(tier3_ping(41), 42);
        assert_eq!(tier3_ping(0), 1);
    }
}
