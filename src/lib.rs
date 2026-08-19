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
}
