# AEGIS Windows-Native NIDS/IPS — Manus AI Account Handoff

**วันที่:** 24 กันยายน 2026  
**ผู้จัดทำ:** Manus AI  
**โครงการ:** NIDs / AEGIS Windows-native NIDS/IPS  
**สถานะโดยรวม:** Partially Ready — controlled observe-only qualification  
**Prevention Gate:** **CLOSED**  
**ห้ามประกาศระบบเป็น Production IPS จนกว่าจะผ่าน host-effect proof และ rollback proof ครบถ้วน

---

## 1. บทสรุปสำหรับการส่งต่องาน

AEGIS เป็นระบบตรวจจับและป้องกันการบุกรุกบน Windows ที่ใช้หลายภาษา ได้แก่ Zig, Rust, C/WDK, Go และ Python ระบบมี event pipeline, Aho–Corasick signature detection, WFP kernel integration, ETW/FIM/Registry telemetry, named-pipe sensors, forensic ring, control plane และ Rust Policy Enforcement Point หรือ PEP

งานพัฒนาที่ทำแล้วทำให้ระบบผ่านระดับ **synthetic qualification** และ **observe-only runtime qualification** หลายส่วนแล้ว โดยเฉพาะ receipt-aware enforcement boundary, ETW/FIM ABI foundation, Rule 22 synthetic canary, L2 named-pipe adapter, L7 payload classification และ native runtime readiness

อย่างไรก็ตาม ระบบยังไม่ควรเปิด prevention gate เพราะหลักฐาน exact attribution ของ native named-pipe sensor ยังไม่ผ่าน และยังไม่มีหลักฐาน production-grade ของการ block จริงบน Windows, provider-backed postcondition, benign probe ที่ถูก block, exact rollback และ post-cleanup absence ครบชุด

จุดล่าสุดที่พบคือ active daemon ใช้ `src/main.zig -> src/daemon.zig` ไม่ใช่ legacy `src/core/nids_main.zig` เดิมจึงไม่มี `pipe_monitor` ใน active runtime ต่อมาได้เพิ่ม T5 pipe monitor เข้า `src/daemon.zig` แล้ว แต่ผลทดสอบล่าสุดยังไม่พบ record ที่ตรงกับ fixture pipe แบบ exact ดังนี้:

```text
runtime_state       = RUNNING
runtime_degraded    = false
events_processed     = 6
forensic_records     = 6
forensic_verified    = true
source_only records  = 0
payload_only records = 0
exact records        = 0
blocks               = 0
errors               = 0
PEP called           = false
WFP block called     = false
prevention gate      = closed
```

ดังนั้นงานถัดไปต้องมุ่งที่ **การพิสูจน์ว่า active Thread 5 enumerate native pipe จริงและส่ง event เข้า forensic ring** ก่อนที่จะเริ่ม attack testing หรือ enforcement proof

---

## 2. กติกาความปลอดภัยที่ต้องรักษา

ห้ามแก้ `prevention_gate` ให้เปิดเพียงเพราะ provider รายงาน `READY` หรือ `host_effect_capable=true` ค่าเหล่านี้หมายถึง dependency พร้อม ไม่ใช่หลักฐานว่า host effect ถูกพิสูจน์แล้ว

ทุกผลลัพธ์ที่มีคำว่า `BLOCKED`, `ENFORCED`, `ROLLED_BACK` หรือ `CLEANED` ต้องอ้างอิง provider-backed receipt และ read-back เท่านั้น Local intent, log line, filter ID, static fixture, metrics หรือ exit code 0 ไม่ถือเป็น host-effect evidence

งานปัจจุบันต้องอยู่ในโหมด observe-only เท่านั้น การสร้าง fixture ในเครื่อง, การสร้าง named pipe ชั่วคราว, การอ่าน forensic record และการตรวจ health เป็นการทดสอบที่ยอมรับได้ การติดตั้ง WFP filter, การส่ง attack traffic ที่มีผลจริง, การ block host, การเปลี่ยน firewall state หรือการลบข้อมูล production ต้องแยกเป็น controlled proof และต้องมี approval ตาม workflow ที่เหมาะสม

---

## 3. สถาปัตยกรรมปัจจุบัน

เส้นทาง active runtime ที่ใช้งานจริงคือ:

```text
src/main.zig
    -> src/daemon.zig
        -> RuntimeSupervisor
            -> legacy named-pipe sensor
            -> Go Nose pipe reader
            -> event_processor.pipelineLoop
            -> ETW thread
            -> FIM thread
            -> Registry thread
            -> active named-pipe monitor [เพิ่มล่าสุด]
            -> Windows control pipe
```

เส้นทาง event หลักคือ:

```text
Sensor
  -> canonical/internal event adapter
  -> event_queue.pushEvent()
  -> event_processor.processEvent()
  -> flow lookup
  -> Aho-Corasick signature matching
  -> anomaly detection
  -> threat tracker
  -> policy evaluation
  -> Rust PEP authorization
  -> action dispatcher
  -> forensic ring append
```

เส้นทาง enforcement ที่ได้รับอนุญาตเพียงเส้นทางเดียวคือ:

```text
control request or pipeline decision
  -> Rust PEP
  -> C/user bridge
  -> WFP driver/provider
  -> complete EnforcementReceipt
  -> exact provider read-back
  -> benign host-effect probe
  -> cleanup by receipt.filter_id
  -> exact post-delete query
  -> ROLLED_BACK
```

---

## 4. สิ่งที่ทำเสร็จและหลักฐานที่ผ่านแล้ว

### 4.1 Enforcement และ receipt boundary

`enforcement.block` ถูกออกแบบให้ต้องมี `event_id` และ `trace_id` และต้องตรวจ provider read-back ก่อนรายงาน host effect ส่วน `unblock` ต้องตรวจสถานะ absent หลังลบ ไม่ควรรายงาน rollback จากผลลัพธ์ของ delete call เพียงอย่างเดียว

สถานะนี้ถือว่า **source implementation มีทิศทางถูกต้อง** แต่ต้อง compile และ execute บน Windows พร้อม provider จริงอีกครั้งก่อนจัดเป็น production evidence

### 4.2 ETW/FIM sensor foundation

มีการแก้ C/Rust/Zig ABI mismatch ของ ETW และเพิ่ม TDH property decoding สำหรับ `ImageName`, `CommandLine` และ `ParentId` มี monotonic AEGIS event ID และ bounded payload hashing แล้ว

Synthetic/runtime probe ที่เกี่ยวข้องผ่านตาม handoff เดิม แต่ต้องเติม real sensor IDs ใน Rule 22 evidence matrix

### 4.3 Rule 22 synthetic validation

Synthetic canary ของ pipe rules R3001–R3005 ผ่านทั้ง sensor matcher และ regex matcher:

| Rule | Positive fixture | Sensor positive | Sensor negative | Regex positive | Regex negative |
|---|---|---:|---:|---:|---:|
| R3001 | `MSSE-1234` | true | true | true | true |
| R3002 | `psexec-svc` | true | true | true | true |
| R3003 | `anonymous-channel` | true | true | true | true |
| R3004 | `meterpreter-ctrl` | true | true | true | true |
| R3005 | `atsvc-job-1` | true | true | true | true |

ผลนี้พิสูจน์ matcher แต่ยังไม่พิสูจน์ native Windows enumeration และ forensic attribution ของแต่ละ rule

### 4.4 L7/WFP mapping

WFP capture มี payload bytes อยู่แล้ว แต่เดิมส่ง event เป็น `forward` โดยไม่บันทึก application-layer classification ได้เพิ่ม `src/capture/l7_classifier.zig` และต่อเข้ากับ `src/capture/windows_capture.zig` โดยใช้ `CanonicalEvent.context_flags` bits 8–13 ซึ่งไม่เปลี่ยน frozen v1 ABI

Classifier ปัจจุบันตรวจ signature แบบ bounded สำหรับ DNS, HTTP, TLS, SMB, RDP และ Kerberos marker แบบจำกัด ค่า unknown จะไม่ถูกยกระดับเป็น protocol identity

### 4.5 L2 pipe adapter และ forensic path

`pipe_monitor.zig` มี local `PipeObservation` contract เพื่อให้ direct Zig test ไม่ import sibling module นอก module path จากนั้น production adapter แปลง observation เป็น `IpcEvent` และส่งเข้า `event_queue.pushEvent()`

มีการเพิ่ม `event.nextEventId()` ใน `src/contract/event.zig` และกำหนด `trace_id = event_id` สำหรับ pipe events ในทั้ง legacy adapter และ active daemon adapter

Forensic `RecordHeader.reserved[6]` ใช้เก็บ `EventSource` เพื่อให้ exact sensor attribution ตรวจได้ในภายหลัง

### 4.6 Native runtime readiness

ผล runtime proof ที่ผ่านก่อนหน้าแสดงว่า runtime พร้อมจริงในระดับ qualification:

```text
state             = RUNNING
degraded          = false
nose_ready        = true
pipeline_ready    = true
etw_ready         = true
fim_ready         = true
registry_ready    = true
rust_shield       = READY
pep_ready         = true
provider_ready    = true
forensic_verified = true
blocks            = 0
errors            = 0
```

มี native named-pipe aggregate proof ผ่านในรอบก่อนหน้า โดย events และ forensic records เพิ่มขึ้นพร้อมกัน แต่ exact record attribution ยังไม่ผ่าน จึงจัดเป็น observe-only pipeline proof เท่านั้น

---

## 5. ไฟล์สำคัญที่ต้องอ่านต่อ

| ไฟล์ | หน้าที่ | สถานะ |
|---|---|---|
| `src/daemon.zig` | Active runtime owner และ worker supervision | แก้ล่าสุด เพิ่ม active pipe monitor |
| `src/core/nids_main.zig` | Legacy/alternate runtime path | มี pipe wiring แต่ไม่ใช่ `zig build run` entrypoint |
| `src/capture/pipe_monitor.zig` | Native `FindFirstFileW(\\.\\pipe\\*)` sensor | ต้องพิสูจน์ runtime attribution |
| `src/pipeline/event_processor.zig` | Detection, policy, PEP, forensic append | active pipeline |
| `src/pipeline/event_queue.zig` | Queue boundary และ payload copy | active pipeline |
| `src/forensic/forensic_pipeline.zig` | Hash-chained forensic ring | เพิ่ม source metadata ล่าสุด |
| `src/control/handler_registry.zig` | Control handlers | เพิ่ม forensic source/payload filtered lookup |
| `src/contract/event.zig` | Frozen `IpcEvent` contract และ event ID | เพิ่ม monotonic ID generator |
| `src/policy/pep_bindings.zig` | Rust PEP FFI, receipt verification | ห้าม bypass |
| `src/capture/l7_classifier.zig` | Bounded L7 metadata classifier | observe-only |
| `scripts/run_pipe_native_runtime_observe_only_proof.ps1` | Native pipe runtime proof | ล่าสุดเปลี่ยนเป็น Win32 `CreateNamedPipeW` fixture |
| `analysis/AEGIS_DEEP_CODE_ANALYSIS_20260923.md` | Original deep audit | อ่านเพื่อ P0/P1 blockers |
| `analysis/L2_PIPE_FORENSIC_CHAIN_20260924.md` | Source-level L2 chain audit | ผ่านระดับ source |
| `analysis/L2_NATIVE_PIPE_RUNTIME_PROOF_20260924.md` | Aggregate native runtime proof | PASS แต่ exact attribution pending |
| `analysis/L7_WFP_MAPPING_20260924.md` | L7 mapping report | observe-only |

---

## 6. จุดค้างปัจจุบันที่ต้องแก้ตามลำดับ

### P0 — ทำให้ native pipe exact attribution ผ่าน

ปัญหาปัจจุบันไม่ใช่ control query เพราะ `source_only_query`, `payload_only_query` และ `exact_query` เป็นศูนย์พร้อมกัน หมายถึงยังไม่มี forensic record จาก active pipe monitor ที่ตรงกับ fixture

ต้องตรวจตามลำดับนี้:

1. ยืนยันว่า runtime log มีข้อความ `named-pipe monitor started` และ `[PM] Thread 5 started`
2. เพิ่ม sensor-level counters เช่น `scan_count`, `suspicious_found`, `last_suspicious_name` และ `last_published_hash` ใน `runtime_state`
3. แสดง counters เหล่านี้ผ่าน `health` หรือ `metrics.snapshot`
4. รัน fixture ด้วย Win32 `CreateNamedPipeW` ซึ่งทำแล้วใน runner ล่าสุด
5. ตรวจว่า `scan_count` เพิ่มขึ้นระหว่าง 20 วินาที
6. ตรวจว่า `suspicious_found` เพิ่มขึ้น
7. ตรวจว่า `last_suspicious_name` ตรงกับ unique pipe name
8. ถ้า sensor พบแต่ forensic ไม่เพิ่ม ให้ debug callback/queue
9. ถ้า sensor ไม่พบ ให้ debug `FindFirstFileW` path, privilege, pipe name encoding และ scan timing
10. เมื่อ record พบแล้วตรวจ source ordinal 5, payload prefix, nonzero event ID และ rule ID

ไม่ควรเพิ่ม event เข้า queue จาก runner เพื่อแก้ผลทดสอบ เพราะจะทำลายความหมายของ native sensor proof

### P0 — ทำให้ forensic query robust

Filtered lookup ที่เพิ่มใน `forensics.list` เป็น minimal diagnostic implementation และต้องทดสอบบน Zig 0.13/Windows จริง โดยเฉพาะ:

- `RecordHeader.reserved[6]` ไม่ชนกับ existing metadata
- `readRecord()` index semantics ถูกต้องเมื่อ ring wrap
- payload length ไม่เกิน record boundary
- allocator lifetime ของ JSON response ถูกต้อง
- query ไม่ส่งคืน record ที่ hash/CRC invalid
- query สามารถคืน `event_id`, `rule_id`, `source`, `payload_len`, `record_seq` ได้

ควรเพิ่ม test fixture ใน Zig สำหรับ source filter และ payload prefix filter

### P1 — เติม Rule 22 real evidence matrix

Synthetic PASS ต้องถูกแยกจาก real host evidence อย่างชัดเจน แต่ละ rule ต้องมีอย่างน้อย:

```text
rule_id
sensor_id
source
fixture identity
observed event_id
trace_id
payload hash
forensic record sequence
rule match result
host effect
cleanup result
```

### P0 — Isolated reversible enforcement proof

ทำได้ต่อเมื่อ exact observe-only attribution และ provider-backed receipt compile/runtime verification ผ่านก่อนเท่านั้น ขอบเขตที่ปลอดภัยคือ remote lab target ที่ควบคุมได้, tuple เฉพาะ, time-bounded filter, benign probe, read-back, rollback และ read-back absent

ห้ามใช้ attack traffic เพื่อพิสูจน์ block ก่อน provider proof ผ่าน

### P1 — Authorization และ ownership

ต้องยืนยันว่า device ACL, caller authentication, filter ownership, restart reconciliation และ dynamic/persistent WFP semantics ถูกพิสูจน์บน Windows ไม่ใช่แค่ source intent

---

## 7. แผน Backend จนถึง Production

### 7.1 Event and sensor layer

ให้เลือก canonical acquisition authority เพียงหนึ่งเส้นทางต่อ data source ปัจจุบัน Go Nose เป็น canonical network ingress ขณะที่ named-pipe monitor เป็น host sensor ที่ส่งเข้า shared queue ห้ามเปิด legacy direct path ซ้ำโดยไม่ได้ตรวจ event duplication

ทุก sensor ต้องมี source ID, monotonic event ID, timestamp, payload length, payload hash และ readiness counter ของตัวเอง Event ที่สร้างจาก sensor ต้องไม่ประกาศ host effect

### 7.2 Detection and policy layer

Aho–Corasick, regex และ anomaly detector ต้องมี rule identity ที่ผูกกับ event ID เดียวกัน การเปลี่ยน severity หรือ policy decision ต้องไม่ลบ detection identity เดิม

Policy intent ต้องแยกจาก enforcement result เสมอ ตัวอย่างเช่น `policy_action=block` หมายถึงคำขอเชิงนโยบาย ส่วน `enforcement_status=enforced` ต้องเกิดหลัง receipt/read-back เท่านั้น

### 7.3 PEP and WFP layer

Rust PEP ต้องเป็น privileged mutation authority เพียงจุดเดียว FFI ต้อง validate ABI bounds, decision ordinal, filter ID และ caller capability

Receipt v1 ควรประกอบด้วยอย่างน้อย `event_id`, `trace_id`, `policy_id`, `filter_id`, requested tuple, provider status, decision, audit ID, timestamp และ verification state

Provider query ต้องแยกผลลัพธ์อย่างน้อยสามแบบ:

```text
PRESENT_EXACT
ABSENT_EXACT
QUERY_ERROR
```

ห้าม map ทั้ง `ABSENT_EXACT` และ `QUERY_ERROR` เป็น null เดียวกัน เพราะจะพิสูจน์ rollback ไม่ได้

### 7.4 Forensic layer

Forensic ring ต้องบันทึก event identity, source, rule, payload hash, policy ID, PEP decision, audit ID และ hash chain state ทุก record ต้องผ่าน CRC และ per-record hash verification ก่อน query/export

ควรเพิ่ม `forensics.show` และ `forensics.export` ที่คืน verified records โดยไม่ให้ CLI อ่าน local intent หรือไฟล์ปลอมแทน active ring

### 7.5 Control plane

คำสั่ง read-only เช่น health, metrics, forensic verify และ forensic filtered search ควรคืน JSON schema ที่ stable พร้อม availability state

คำสั่ง mutation ต้องคืน structured failure เมื่อ provider unavailable, receipt invalid, query error หรือ gate closed และต้องไม่คืน exit code 0 จาก intent ที่ยังไม่พิสูจน์

### 7.6 Reliability

ต้องมี bounded startup readiness, worker failure reasons, graceful shutdown, join ownership, queue backpressure metrics, event drop metrics, exactly-once counters และ restart reconciliation

---

## 8. แผน Frontend/Operator Console จนใช้งานง่าย

ปัจจุบันหลักฐานใน repository เน้น backend และ CLI/control plane มากกว่า frontend production การพัฒนา frontend ควรเริ่มหลัง JSON contracts ของ backend ถูก freeze

Frontend ที่เหมาะสมควรมีหน้าหลักดังนี้:

### Dashboard

แสดง runtime state, degraded state, worker readiness, sensor counters, queue depth, drops, forensic verification และ prevention gate แบบเด่นชัด

ต้องแสดงคำเตือนแยกกันระหว่าง:

```text
Detection available
Provider ready
Enforcement gate closed
Host effect proven
```

ห้ามใช้สีหรือคำว่า `Blocked` เมื่อมีเพียง policy intent

### Events

แสดง event ID, trace ID, source, timestamp, protocol, L7 classification, rule ID, severity, payload hash และ processing fate ผู้ใช้ต้องกรองตาม sensor, rule, event ID และ time range ได้

### Forensics

แสดง record sequence, event ID, source, rule ID, payload hash, audit ID, policy ID, PEP decision, CRC state และ hash-chain verification ต้องมีปุ่ม export เฉพาะ verified records

### Rules

แสดง Rule 22 matrix โดยแยก `Synthetic`, `Observe-only real`, `Provider proof` และ `Production approved` อย่างชัดเจน

### Enforcement

หน้านี้ต้อง default เป็น read-only และแสดง gate state, provider state, receipt state และ rollback state ก่อนให้ operator ทำ action ใด ๆ หาก workflow ยังไม่ approved ต้อง disable mutation controls

### Health and diagnostics

แสดง startup failure reason, missing worker, binary versions, provider readiness, driver readiness, last event time, event ID monotonicity และ forensic chain status

### Backend API contract สำหรับ frontend

ควรใช้ JSON schema versioned เช่น:

```json
{
  "schema_version": 1,
  "runtime": {
    "state": "RUNNING",
    "degraded": false,
    "prevention_gate": "CLOSED"
  },
  "capabilities": {
    "detection": true,
    "forensics": true,
    "provider_ready": true,
    "host_effect_capable": false
  },
  "evidence": {
    "forensic_verified": true,
    "last_event_id": 123,
    "duplicate_event_ids": 0,
    "non_monotonic_event_ids": 0
  }
}
```

`host_effect_capable=true` ต้องไม่เปลี่ยน `prevention_gate` เป็น OPEN โดยอัตโนมัติ

---

## 9. Test plan ที่ต้องทำต่อ

### Stage A — Compile and unit tests

รันบน Windows ด้วย Zig 0.13:

```powershell
Set-Location D:\NIDs_Windows
zig test src\capture\pipe_monitor.zig -O Debug
zig test src\capture\l7_classifier.zig -O Debug
zig build test -Doptimize=Debug
```

จากนั้น build native helpers และ full runtime ตาม script ที่ repository ใช้อยู่:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_and_check.ps1
```

### Stage B — Runtime readiness

```powershell
python tools\aegisctl.py health --json
python tools\aegisctl.py readiness --pretty
python tools\aegisctl.py forensics verify --json
```

ต้องตรวจว่า `state=RUNNING`, workers ที่ต้องการพร้อม, forensic verified และ gate ยัง closed

### Stage C — Native pipe attribution

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\run_pipe_native_runtime_observe_only_proof.ps1 `
  -WaitSeconds 30 `
  -EvidencePath "$PWD\analysis\L2_NATIVE_PIPE_EXACT_PROOF_20260924.json"
```

ก่อนตัดสิน PASS ต้องดู sensor-level counters ไม่ใช่ดู aggregate metrics เท่านั้น

### Stage D — ETW/FIM runtime proof

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\run_etw_runtime_observe_only_proof.ps1

powershell -ExecutionPolicy Bypass `
  -File .\scripts\run_fim_runtime_observe_only_proof.ps1
```

### Stage E — L7 benign proof

ใช้ benign traffic ใน isolated host เท่านั้น แล้วตรวจ L7 context flags, event ID, payload hash และ forensic record โดยไม่เปิด enforcement

### Stage F — Controlled enforcement proof

เริ่มได้เมื่อ Stage A–E ผ่านและมี approval สำหรับ reversible host-effect test เท่านั้น ต้องใช้ tuple เฉพาะ target, receipt-aware block, benign connectivity probe, provider read-back, unblock และ post-delete query

---

## 10. สิ่งที่ห้ามสรุปจากผลปัจจุบัน

ห้ามสรุปว่า `provider_ready=true` หมายถึงระบบ block ได้อย่างถูกต้อง

ห้ามสรุปว่า `events_processed > 0` หมายถึง pipe sensor พบ fixture

ห้ามสรุปว่า `forensic_records` เพิ่มขึ้นหมายถึง record ของ pipe นั้นถูกบันทึก

ห้ามสรุปว่า `blocks=0` เป็น rollback proof เพราะรอบล่าสุดไม่มี block request ตั้งแต่ต้น

ห้ามสรุปว่า synthetic canary เป็น real host attack validation

ห้ามเปิด prevention gate จากผล runtime health เพียงอย่างเดียว

---

## 11. Prompt สำหรับเริ่มงานใน Manus AI บัญชีอื่น

คัดลอกข้อความต่อไปนี้ไปเปิดงานใหม่:

> ผมกำลังพัฒนาโครงการ AEGIS Windows-native NIDS/IPS ใน `D:\NIDs_Windows` โปรดอ่านไฟล์ `analysis/AEGIS_MANUS_ACCOUNT_HANDOFF_20260924.md` ก่อนเริ่มงาน และรักษา `prevention_gate = CLOSED` ตลอดช่วง qualification
>
> ระบบใช้ Zig 0.13, Rust PEP, C/WDK WFP, Go Nose, Python control plane และ Windows ETW/FIM/Registry
>
> สถานะล่าสุดคือ runtime `RUNNING`, degraded=false, PEP/provider พร้อม, forensic chain verified และ observe-only pipeline ทำงาน แต่ native pipe exact attribution ยังไม่ผ่าน
>
> ผลล่าสุด:
>
> ```text
> events_processed   = 6
> forensic_records   = 6
> source_only        = 0
> payload_only       = 0
> exact_query        = 0
> blocks             = 0
> errors             = 0
> ```
>
> Active entrypoint คือ `src/main.zig -> src/daemon.zig` และได้เพิ่ม `pipe_monitor` เข้า `RuntimeSupervisor` ใน `src/daemon.zig` แล้ว ต้องตรวจให้เห็น log `named-pipe monitor started` และ `[PM] Thread 5 started`
>
> งานถัดไปที่ต้องทำคือเพิ่ม sensor-level counters และ diagnostic output ใน `pipe_monitor.zig`/`runtime_state.zig` เพื่อพิสูจน์ว่า `FindFirstFileW(\\.\\pipe\\*)` เห็น fixture หรือไม่ จากนั้นจึงแก้ queue/forensic attribution หาก sensor พบแต่ record ไม่เข้า
>
> ห้ามแก้ gate ให้เปิด ห้ามสร้าง attack traffic ที่มีผลจริง ห้ามเรียก PEP/WFP mutation ในขั้นนี้ และห้ามรายงาน `ENFORCED` จาก local metrics หรือ log
>
> หลัง exact native attribution ผ่าน ให้เติม Rule 22 real evidence matrix, ตรวจ ETW/FIM real sensor IDs, แล้วจึงออกแบบ isolated reversible provider-backed block/rollback proof

---

## 12. คำตัดสินสุดท้าย

AEGIS อยู่ในสถานะ **Partially Ready for Controlled Observe-only Testing** ระบบมีพื้นฐานเพียงพอสำหรับพัฒนาต่อใน Windows host จริง และมี control/data/forensic boundaries ที่ชัดเจนขึ้นมากแล้ว

งานที่เร่งด่วนที่สุดไม่ใช่การเปิด IPS แต่คือการพิสูจน์ active sensor path ให้ครบหนึ่ง record ตั้งแต่ native enumeration จนถึง forensic record exact attribution จากนั้นจึงค่อยปิดช่องว่าง provider-backed enforcement และ rollback

Production approval ต้องมีหลักฐานอย่างน้อยดังนี้:

```text
22 rules real sensor matrix
native event attribution
stable event/trace identity
forensic verified records
authenticated PEP authority
complete EnforcementReceipt v1
provider-backed PRESENT_EXACT
benign host-effect proof
exact cleanup
provider-backed ABSENT_EXACT
safe restart/ownership reconciliation
frontend truthfulness review
```

จนกว่าจะครบรายการนี้ สถานะที่ถูกต้องคือ:

```text
DETECTION_ONLY / OBSERVE_ONLY
PROVIDER_READY_BUT_GATE_CLOSED
NOT PRODUCTION IPS
```

## References

[1]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew "Microsoft Learn FindFirstFileW"

[2]: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes "Microsoft Learn Named Pipes"

[3]: https://learn.microsoft.com/en-us/windows/win32/fwp/writing-callout-drivers "Microsoft Learn Writing Callout Drivers"

[4]: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing "Microsoft Learn Event Tracing"
