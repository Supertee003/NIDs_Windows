use std::slice;

/// ฟังก์ชันถูกเรียกโดย Zig ผ่าน C-ABI
/// คืนค่า true = ปลอดภัย, false = อันตราย (สั่ง Drop)
#[no_mangle]
pub extern "C" fn validate_payload_safety(data: *const u8, len: usize) -> bool {
    // 1. ป้องกัน Null Pointer
    if data.is_null() || len == 0 {
        return false; 
    }

    // 2. สร้าง Slice อ่านข้อมูลจาก Memory ที่ Zig จองไว้แบบ Zero-copy
    let payload = unsafe { slice::from_raw_parts(data, len) };

    // 3. กฎ Anti-Exploit พื้นฐาน: ป้องกัน Buffer Overflow / NOP Sled ที่ยิงเข้า NIDS
    let mut nop_count = 0;
    for &byte in payload {
        if byte == 0x90 {
            nop_count += 1;
            // ถ้าเจอ \x90 ติดกันเกิน 50 ตัว ให้ตีว่าเป็น Shellcode Slide
            if nop_count > 50 {
                return false; 
            }
        } else {
            nop_count = 0;
        }
    }

    // ผ่านการตรวจสอบเบื้องต้น ปลอดภัยให้วิเคราะห์ต่อได้
    true 
}