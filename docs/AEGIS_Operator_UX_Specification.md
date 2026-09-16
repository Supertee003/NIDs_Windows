# AEGIS Operator UX Specification

## เป้าหมาย

AEGIS ควรให้ผู้ปฏิบัติงานตอบคำถามสำคัญได้ภายในเวลาไม่กี่วินาทีว่า ระบบพร้อมหรือไม่ มีเหตุการณ์อะไรเกิดขึ้น เหตุการณ์นั้นมาจากที่ใด rule ใดตัดสินใจ policy อย่างไร หลักฐานถูกบันทึกครบหรือไม่ และควรทำ action ใดต่อไป

หน้าจอทุกแบบต้องใช้คำศัพท์และลำดับข้อมูลเดียวกัน แต่ไม่จำเป็นต้องแสดงรายละเอียดเท่ากันทุกช่องทาง

## Information hierarchy

ทุกหน้าจอควรเรียงข้อมูลดังนี้:

1. **Runtime readiness** แสดงจาก `aegisctl health` และต้องแยก `RUNNING`, `DEGRADED`, `FAILED` ให้ชัด
2. **Data plane** แสดง event ingress, processed, dropped, duplicate และ non-monotonic counters
3. **Detection and policy** แสดง detections, severity, rule, action และ enforcement result
4. **Forensic integrity** แสดง record count, chain verification และ last evidence timestamp
5. **Operator actions** แสดงคำสั่งที่ทำได้ พร้อมผลลัพธ์และข้อควรระวัง

ห้ามใช้สีหรือข้อความ `OK` แทน readiness ที่ยังไม่ได้ตรวจจาก Control Center และห้าม dashboard ที่อ่าน log โดยตรงรายงานว่า runtime `RUNNING`

## ช่องทางการใช้งาน

| ช่องทาง | งานหลัก | Source of truth |
|---|---|---|
| Unified CLI | operator command และ automation | Control Center pipe |
| TUI | terminal monitoring และ quick triage | CLI/control payload |
| Desktop dashboard | overview, evidence และ investigation | health snapshot + canonical event log |
| Threat graph | relationship analysis | canonical event log |
| Prometheus endpoint | monitoring integration | runtime/control adapter |

## Unified CLI contract

```text
aegis health
aegis doctor
aegis metrics
aegis rules validate
aegis rules reload
aegis events stats
aegis forensic verify
aegis tui
aegis web
aegis graph
```

คำสั่งควรใช้ exit code ดังนี้:

| Code | ความหมาย |
|---|---|
| 0 | operation สำเร็จและ postcondition ผ่าน |
| 1 | operation ทำงานแต่ผลไม่ผ่าน หรือ runtime degraded |
| 2 | command/argument ไม่ถูกต้อง |
| 3 | Control Center unavailable |
| 4 | evidence หรือ integrity validation ล้มเหลว |

## TUI layout

TUI ควรแบ่งเป็น 4 แถว:

- Header: runtime state, degraded flag, PID, version และ uptime
- Readiness strip: Zig, Go, C++ bridge, PEP, Tier-3, ETW, FIM, Registry และ Control
- Counter strip: events in/out, detections, blocks, drops, errors และ forensic records
- Event stream: timestamp, source, rule, severity, policy และ result

TUI รุ่นปัจจุบันเรียก `get_health_payload()`, `metrics.snapshot` และ `forensics.verify` จาก Control Center เมื่อ daemon พร้อมใช้งาน จึงแสดง runtime state, worker readiness, data-plane counters, duplicate counters และ forensic integrity จาก contract เดียวกัน หาก Control Center ใช้งานไม่ได้จึงค่อยแสดง process scan เป็น `fallback process scan` และห้ามตีความ fallback นี้ว่าเป็น authoritative health

เมื่อผู้ใช้กดดูรายละเอียด ให้แสดง correlation ID, event ID, source/destination, protocol, decision trace และ forensic record ID ในหน้ารายละเอียด ไม่ควรยัดข้อมูลทั้งหมดไว้ในตารางหลัก

## Dashboard layout

Dashboard ใช้ dark neutral theme และใช้สีเฉพาะความหมาย:

- Green: ready/verified
- Amber: degraded/warning
- Red: failed/blocked/critical
- Blue: informational/evidence
- Gray: unavailable or not measured

หน้าแรกควรมี:

1. Runtime status card
2. Worker readiness matrix
3. Data-plane counters
4. Detection/policy summary
5. Forensic integrity card
6. Latest evidence table
7. Action bar ที่ลิงก์ไปยัง CLI command ที่เกี่ยวข้อง

Dashboard ที่อ่านไฟล์ evidence โดยตรงต้องติดป้าย `EVIDENCE VIEW` และต้องบอก operator ให้ใช้ `aegis health` สำหรับ runtime authority

## Threat graph

Graph ใช้ความสัมพันธ์:

```text
Source IP → Rule → AEGIS NIDS
```

Edge label ต้องแสดง policy/action และ node tooltip ต้องมี rule, attack/event type และจำนวนครั้ง Graph ไม่ควรสร้างชื่อ attacker จาก attack type เพียงอย่างเดียว เพราะทำให้ source identity สูญหาย

## Operator workflows

### Start-of-shift check

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensic verify
```

### Rule change

```powershell
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 rules reload
.\scripts\aegis.ps1 metrics
```

### Triage

```powershell
.\scripts\aegis.ps1 events stats
.\scripts\aegis.ps1 forensic list
.\scripts\aegis.ps1 graph
```

### Failure response

หาก health เป็น `DEGRADED` หรือ integrity verify ไม่ผ่าน ให้หยุด enforcement test, เก็บ `doctor` output และไม่ใช้ TUI ที่อ่าน process list เป็นหลักฐานแทน Control Center

## สิ่งที่ไม่ควรทำ

- ไม่ให้ UI แต่ละตัวคำนวณ health ด้วยกฎของตนเอง
- ไม่แก้ Rules ผ่านไฟล์โดยไม่สั่ง `rules validate` และ `rules reload`
- ไม่ใช้ log เก่าคนละ schema ใน dashboard เดียวกัน
- ไม่แสดง `ALLOW` เป็น enforcement success เมื่อ PEP/WFP unavailable
- ไม่วาง destructive action ไว้ติดกับปุ่ม refresh โดยไม่มี confirmation และ audit
