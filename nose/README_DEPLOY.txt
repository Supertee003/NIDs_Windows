# AEGIS NOSE v5.0 + MOUTH v3.0 — Deploy Guide

## ไฟล์ที่ต้องวาง

### NOSE (Go) v5.0 → `D:\NIds_Windows\nose\`
| ไฟล์ | วางที่ | หมายเหตุ |
|---|---|---|
| `main.go` | `nose\main.go` | Entry point |
| `model.go` | `nose\model.go` | bubbletea Model + 5 panels |
| `collectors.go` | `nose\collectors.go` | Data structs + 3 collectors |
| `styles.go` | `nose\styles.go` | Cool-tone lipgloss styles |
| `go.mod` | `nose\go.mod` | Dependencies (bubbletea+lipgloss) |

### MOUTH (Rust) v3.0 → `D:\NIds_Windows\mouth\`
| ไฟล์ | วางที่ | หมายเหตุ |
|---|---|---|
| `windows_sec_monitor.rs` | `mouth\windows_sec_monitor.rs` | DEFCON enforcer v3.0 |
| `aegis_mouth_tui.rs` | `mouth\aegis_mouth_tui.rs` | สำเนาเหมือนกัน |

### Utility → `D:\NIds_Windows\`
| ไฟล์ | หมายเหตุ |
|---|---|
| `cleanup_nose_mouth.bat` | ลบไฟล์เก่า + go mod tidy + build test |
| `scan_nose_folder.py` | สแกนโฟลเดอร์ ตรวจสอบไฟล์ |

## ขั้นตอนบน Windows

1. ลบไฟล์เก่าใน `nose\` ถ้ามี:
   - `windows_perf.go`, `windows_perf_test.go`, `go.sum` เก่า

2. วางไฟล์ v5.0 ใน `nose\` (เขียนทับ)

3. วางไฟล์ v3.0 ใน `mouth\` (เขียนทับ)

4. รัน `cleanup_nose_mouth.bat` — จะทำ:
   - ลบไฟล์เก่าที่เหลือ
   - ตรวจสอบไฟล์ครบ
   - `go mod tidy`
   - build test

5. Build MOUTH:
   ```
   rustc -O mouth\windows_sec_monitor.rs -o dist\windows_sec_monitor.exe
   ```

## การแยกบทบาท

- 🔍 **NOSE v5.0** = "จมูกดมกลิ่นหาความผิดปกติ" → System Health, Network Traffic + sparklines, Top Talkers, Protocol Distribution, Raw Packet Stream
- 🛡️ **MOUTH v3.0** = "ยามรักษาความปลอดภัย + กระบอกเสียง" → DEFCON focal point, Active Mitigations, Alert Feed, DEFCON-aware border
