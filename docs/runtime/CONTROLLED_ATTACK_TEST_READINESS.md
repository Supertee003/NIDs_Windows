# AEGIS NIDS — Controlled Attack-Test Readiness

## Purpose

เอกสารนี้กำหนดเกณฑ์ก่อนนำ AEGIS NIDS ไปทดสอบเหตุการณ์โจมตีใน Windows lab ที่ได้รับอนุญาตเท่านั้น การทดสอบระยะแรกต้องใช้ synthetic events, replay traffic หรือ benign fixtures ก่อน ห้ามเริ่มจาก payload ที่ทำลายระบบหรือการทดสอบกับเครื่อง production

## Readiness gates

| Gate | สิ่งที่ต้องพิสูจน์ | เกณฑ์ผ่าน |
|---|---|---|
| R1 | Process lifecycle | core, brain และ aggregator health ผ่าน; ไม่มี stale process |
| R2 | Sensor transport | `aegis_sensor_pipe` รับ event และตอบ `1 sent, 0 failed` |
| R3 | Canonical queue | log มี `Canonical event queued`; `events_processed` เพิ่ม |
| R4 | Detection | synthetic fixture ทำให้ rule ที่กำหนด match หรือมี explicit unmatched result |
| R5 | Policy/PEP | policy decision มี trace และ PEP เป็นผู้ตัดสิน enforcement เพียงจุดเดียว |
| R6 | Forensics | forensic record มี event/trace/audit identity และ replay อ่านได้ |
| R7 | Safety | WFP/minifilter เป็น lab-only, rollback พร้อม, ไม่มี external destination |
| R8 | Evidence | เก็บ build hash, config hash, logs, counters และผลตรวจทุก gate |

## Required invariants

ทุก event ที่ทดสอบต้องคง identity เดียวกันตลอดเส้นทาง:

```text
event_id -> trace_id -> audit_id -> policy/request id -> forensic id
```

หาก event transport ผ่านแต่ `events_processed` หรือ forensic record ไม่เพิ่ม ให้ถือว่า **ไม่พร้อม** และหยุดการทดสอบระยะถัดไป

## Benign validation sequence

```powershell
cd D:\NIDs_Windows

python tools\aegisctl.py status
python tools\aegisctl.py health

python scripts\aegis_event_gen.py `
  --pipe `
  --count 1 `
  --rule-id GATE-C-TRACE `
  --attack GATE-C-END-TO-END `
  --severity High

python tools\aegisctl.py metrics
python tools\aegisctl.py events stats
python tools\aegisctl.py forensic search --field rule_id --value GATE-C-TRACE
```

Expected evidence after the rebuilt core is running:

```text
Summary: 1 sent, 0 failed
[PIPE SENSOR] Canonical event queued
 events_processed > 0
 last_event_ms > 0
 forensic_records > 0
```

## Stop conditions

หยุดทันทีเมื่อพบอย่างใดอย่างหนึ่งต่อไปนี้:

- endpoint ไม่ตรงกับ owner ที่ประกาศไว้
- event ถูกนับว่า sent แต่ไม่มี canonical queue evidence
- counters ลดลงหรือ reset ระหว่างการทดสอบ
- มี duplicate หรือ non-monotonic event identity
- policy/PEP decision ไม่มี trace ที่ตรวจสอบย้อนกลับได้
- WFP หรือ driver เปลี่ยนสถานะโดยไม่มี operator record
- มี network destination นอก lab หรือไม่มี rollback

## Test scope

ระยะ controlled attack testing ควรแบ่งเป็นสามระดับ:

1. **Synthetic/replay:** ใช้ JSON fixtures และ packet captures ที่ไม่ก่ออันตราย เพื่อพิสูจน์ detection, policy, forensic และ replay
2. **Isolated lab traffic:** ใช้เครื่องทดสอบที่แยกเครือข่ายและมี snapshot เพื่อพิสูจน์ sensor/driver behavior
3. **Approved adversarial scenarios:** ทำเฉพาะ scenario ที่ได้รับอนุมัติ มี rollback และกำหนด success/failure criteria ล่วงหน้า

ระบบยังไม่ควรเข้าสู่ระดับที่ 2 หรือ 3 จนกว่า R1–R6 จะผ่านจาก binary ที่ rebuild ล่าสุด และผลลัพธ์ถูกเก็บไว้เป็นหลักฐาน
