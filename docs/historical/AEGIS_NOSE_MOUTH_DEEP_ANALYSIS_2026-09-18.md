# AEGIS Nose–Mouth Deep Analysis

วันที่วิเคราะห์: 2026-09-18  
ขอบเขต: Nose ingress, Zig runtime, Rust PEP/Mouth, wire ABI, health/readiness, enforcement และ forensic feedback

## ข้อสรุป

AEGIS ต้องพัฒนา **Nose และ Mouth ควบคู่กัน** แต่ทั้งสองส่วนมีบทบาทต่างกันอย่างเคร่งครัด Nose เป็น acquisition component ที่อ่าน packet และส่ง `CanonicalEvent` เข้า Zig ผ่าน named pipe `\\.\pipe\aegis_nose` ส่วน Mouth ควรเป็น operator and mitigation consumer ที่แสดงสถานะและผล enforcement จาก Rust PEP ไม่ควรตัดสิน policy หรือเรียก WFP โดยตรง

ปัจจุบัน control plane ของ Zig ทำงานจริงแล้ว แต่ Golden Path ยังไม่สมบูรณ์ เพราะ `aegis-nose.exe` ยังไม่ได้เชื่อมต่อ consumer pipe ใน runtime acceptance ที่ผ่านมา จึงมี `nose_connected=false`, `nose_frames_read=0`, `nose_frames_submitted=0` และ `last_event_id=0` แม้ health จะรายงาน `nose_ready=true` ความหมายของ readiness จึงยังคลุมเครือและต้องแยก listener readiness ออกจาก connection readiness

## 1. Runtime topology ที่พบ

ลำดับ production path ที่ควรเป็น:

```text
Npcap
  -> Go Nose capture
  -> CanonicalEvent 109-byte wire frame
  -> length-prefixed named pipe \\.\pipe\aegis_nose
  -> Zig Nose reader
  -> MPMC queue
  -> detection
  -> policy
  -> Rust PEP
  -> WFP / host adapter
  -> EnforcementReceipt
  -> forensic ring/hash chain
  -> Mouth/operator surfaces
```

Zig เป็น runtime owner และ control-plane owner ขณะที่ Rust PEP เป็น enforcement authority การมี Mouth เป็น process แยกได้ แต่ต้องไม่สร้าง authority ที่สอง

## 2. Nose: สิ่งที่ทำงานถูกต้อง

`nose/capture.go` มีขอบเขตที่เหมาะสม คืออ่าน Npcap, แปลง packet เป็น canonical event และไม่ทำ policy decision เอง `nose/pipe_writer.go` ส่ง frame ด้วยรูปแบบ `u32 little-endian length` ตามด้วย payload 109 bytes และมี short-write protection ผ่าน `writeAll`

การแยก `-capture`, `-capture-self-test` และ TUI mode เป็นการออกแบบที่ถูกต้อง อย่างไรก็ตาม daemon ไม่ได้เริ่ม Nose capture ให้เองใน flow ที่ตรวจสอบ จึงต้องเริ่ม `aegis-nose.exe -capture` แยก หรือเพิ่ม lifecycle supervisor ที่ชัดเจน

## 3. Nose: จุดเสี่ยงที่ต้องแก้ก่อน Golden Path

### 3.1 Readiness รายงานเกินจริง

Health payload ปัจจุบันมี `nose_ready=true` แต่ยังมี `nose_connected=false` และ counters เป็นศูนย์ สถานะควรแยกเป็น:

```json
{
  "nose_listener_ready": true,
  "nose_connected": false,
  "nose_first_frame_seen": false,
  "nose_frames_read": 0,
  "nose_frames_submitted": 0
}
```

เมื่อ listener พร้อมแต่ไม่มี producer ให้รายงาน `WAITING_FOR_INGRESS` หรือ `DEGRADED` ตาม readiness policy ไม่ควรรวมเป็น `nose_ready=true` โดยไม่มีความหมายเพิ่มเติม

### 3.2 ความเสี่ยงของ Golden Vector decoder

`nose/canonical.go` มี `Serialize` ที่เขียน header 8 bytes แล้ววาง `EventID` ที่ offset 8 ซึ่งสอดคล้องกับ wire contract แต่ `nose/golden_path_ffi.go` ฟังก์ชัน `Deserialize` อ่าน `EventID` จาก `b[0:8]` ทำให้ตีความ magic/schema/size เป็น event ID หากฟังก์ชันนี้ถูกใช้ใน production หรือ acceptance path จะทำให้ผลตรวจข้ามภาษาไม่ถูกต้อง

ต้องใช้ decoder เดียวที่ยึด offset เดียวกัน และเพิ่ม test ที่ตรวจ magic, schema, struct-size marker, event ID และขนาด 109 bytes ก่อนอนุญาตให้ Golden Path ผ่าน

### 3.3 Event type alias ไม่สอดคล้อง

ใน `canonical.go` enum หลักกำหนด `EventBlock = 0`, `EventForward = 1`, `EventAlert = 2` แต่ alias `TypeForward = 2` ทำให้ event ที่ capture path สร้างด้วย `TypeForward` ถูกตีความเป็น `EventAlert` ตาม enum หลัก ต้องเลือก vocabulary เดียวและกำหนดค่าใน ABI manifest เพียงแห่งเดียว

### 3.4 Policy action alias ไม่สอดคล้อง

`PolicyAllow`, `PolicyBlock`, `PolicyFailed` อยู่ที่ 0, 1, 2 แต่ `ActionLogOnly = 5` ถูกใช้ใน capture path การใช้ค่า 5 ต้องถูกประกาศเป็น enum wire ที่ถูกต้อง หรือเปลี่ยน capture event ให้ใช้ action ที่ canonical contract รองรับ ห้ามปล่อยให้ decoder แต่ละภาษาตีความต่างกัน

## 4. Zig runtime และ control plane

จาก health response control plane ผ่านจริง ได้แก่ named control pipe, runtime state `RUNNING`, Tier-3 `READY`, PEP availability และ ETW/FIM/WFP readiness จุดที่ยังไม่พิสูจน์คือการรับ frame จาก Nose และการส่งผ่าน detection, policy, PEP และ forensic

`runtime.stop` และ `runtime.restart` ยังปฏิเสธอย่างถูกต้องเพราะ daemon supervisor ยังไม่มี verified worker join transaction ส่วน `daemon.shutdown` เปลี่ยน state และส่ง stop request แต่ต้องทดสอบว่ามีลำดับ Stop ingress, join producers, drain queue, flush forensics และ teardown ครบจริง ไม่ควรถือว่า JSON `{"shutdown":true}` เป็นหลักฐานของ graceful shutdown

## 5. Mouth: บทบาทที่ควรเป็น

Mouth ใน `mouth/windows_sec_monitor.rs` ปัจจุบันทำหน้าที่ tail log, คำนวณ DEFCON, แสดง alert/mitigation feed, เขียน `enforced.json` และเปิด health pipe `\\.\pipe\aegis-mouth-health` หน้าที่เหล่านี้เหมาะกับ operator surface และ feedback consumer แต่ยังไม่ใช่ enforcement implementation ที่พิสูจน์ได้

จุดสำคัญคือชื่อและ UI เช่น `DEFCON ENFORCER`, `READY TO ENFORCE` และ `Active Mitigations` อาจทำให้เข้าใจว่า Mouth เป็นผู้บังคับใช้จริง ทั้งที่โค้ดหลักอ่าน log แล้วสร้างสถานะของตนเอง ยังไม่พบหลักฐานในส่วนที่อ่านว่ามีการส่งคำสั่ง WFP หรือรับ `EnforcementReceipt` จาก Rust PEP โดยตรง

ดังนั้น Mouth ต้องไม่:

1. คำนวณ policy decision แทน Rust PEP
2. เขียน block/quarantine state ที่เป็น source of truth แยกจาก PEP
3. เรียก WFP โดยตรงโดยไม่มี receipt และ authority check
4. เปลี่ยน alert จาก log ให้กลายเป็นหลักฐาน enforcement โดยอัตโนมัติ

Mouth ควรทำสิ่งต่อไปนี้:

1. รับ `DetectionResult`, `PolicyDecision` และ `EnforcementReceipt` ที่มี trace ID เดียวกัน
2. แยก `decision`, `requested`, `host_effect` และ `verified` ใน UI
3. แสดง `BLOCK_REQUESTED`, `BLOCK_APPLIED`, `BLOCK_FAILED` ต่างกันอย่างชัดเจน
4. ใช้ health pipe สำหรับ health เท่านั้น
5. ส่ง operator acknowledgement หรือ recovery request กลับผ่าน Zig control plane ไม่ส่งตรงไป WFP

## 6. Authority model ที่ต้องล็อก

```text
Nose        = observation and ingress
Zig         = lifecycle, queue, detection orchestration, forensic orchestration
Policy      = policy evaluation and signed policy metadata
Rust PEP    = sole enforcement authority
WFP adapter = host effect only, called by PEP
Mouth       = display, acknowledgement, receipt consumer, operator feedback
```

ถ้า Mouth ต้องมี mitigation command ให้ส่งผ่าน Zig control plane ไปยัง Rust PEP เท่านั้น และต้องรอ receipt ที่ตรวจสอบ trace ID, policy version, decision hash และ adapter effect

## 7. แผนพัฒนาที่แนะนำ

### Stage A: ABI correctness

แก้ decoder offset ใน `golden_path_ffi.go`, รวม enum definitions, ตรวจ 109-byte length prefix และเพิ่ม cross-language round-trip test สำหรับ Go, Zig และ Rust ก่อนเริ่ม live capture

### Stage B: Nose live ingress

สร้าง acceptance runner ที่เริ่ม Zig daemon, รอ `nose_listener_ready`, เริ่ม `aegis-nose.exe -capture`, รอ `nose_connected` และตรวจ `frames_read > 0`, `frames_submitted > 0`, `last_event_id > 0` จาก control health

### Stage C: Golden Path

ส่ง benign event ก่อน แล้วตรวจ queue, processed, detection, policy match, PEP decision, receipt และ forensic record โดยใช้ trace ID เดียวตลอดเส้นทาง

### Stage D: Mouth read-only integration

ให้ Mouth อ่าน receipt/health จาก canonical runtime interface ไม่ใช่สรุป enforcement จากข้อความ log ให้เพิ่ม schema validation และแสดงสถานะที่แยก decision กับ host effect

### Stage E: Enforcement proof

ใช้ controlled block event ที่ไม่กระทบระบบจริงก่อน ตรวจว่า Rust PEP เป็นผู้เรียก adapter, WFP ตอบผล, receipt ระบุผล host effect และ Mouth แสดงผลเดียวกัน จากนั้นทดสอบ failure injection และ fail-closed behavior

### Stage F: Lifecycle and recovery

ทดสอบ shutdown และ restart แบบมีหลักฐาน: ingress stopped, producers joined, queue drained, forensic flushed, Mouth health transitions, PEP teardown และ no orphan processes

## 8. Acceptance criteria

| ด้าน | เกณฑ์ผ่าน |
|---|---|
| Nose connection | `nose_connected=true` หลังเริ่ม capture จริง |
| Wire ABI | ทุก frame มี 109-byte payload และ header ถูกต้อง |
| Exactly once | event IDs monotonic และ duplicate counter เป็นศูนย์ |
| Detection | processed และ detections เพิ่มตาม fixture |
| Policy | policy version และ decision hash ตรวจสอบได้ |
| PEP | มี receipt จาก Rust PEP ไม่ใช่จาก Mouth |
| Host effect | WFP result แยกจาก decision และ verify ได้ |
| Forensics | record hash chain verify ผ่าน |
| Mouth | แสดง receipt state โดยไม่สร้าง decision เอง |
| Shutdown | ไม่มี producer หรือ process orphan หลัง stop |

## ข้อสรุปสุดท้าย

ต้องพัฒนา Nose และ Mouth ควบคู่กันจริง แต่ลำดับที่ปลอดภัยคือ **แก้ ABI และ ingress ก่อน จากนั้นเชื่อม PEP receipt แล้วจึงยกระดับ Mouth เป็น operator surface ที่เชื่อถือได้** ไม่ควรเริ่มจากการเพิ่มปุ่ม block หรือ logic enforcement ใน Mouth เพราะจะสร้าง authority ซ้ำและทำให้การพิสูจน์ Golden Path ยากขึ้น

## References

[1]: `nose/capture.go` "AEGIS Go Nose capture and CanonicalEvent ingress"

[2]: `nose/pipe_writer.go` "AEGIS Nose named-pipe frame writer"

[3]: `nose/canonical.go` "AEGIS canonical 109-byte wire format"

[4]: `nose/golden_path_ffi.go` "AEGIS Go golden-vector validation"

[5]: `src/control/handler_registry.zig` "AEGIS Zig control handlers and enforcement status"

[6]: `mouth/windows_sec_monitor.rs` "AEGIS Mouth Rust dashboard and health pipe"
