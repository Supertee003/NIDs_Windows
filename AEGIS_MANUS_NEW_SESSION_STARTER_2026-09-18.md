# AEGIS Manus New Session Starter and Technical Handoff

**วันที่จัดทำ:** 2026-09-18  
**โครงการ:** NIDs / AEGIS Windows-native Network Intrusion Detection and Response  
**วัตถุประสงค์:** ใช้เป็นเอกสารเริ่มต้นสำหรับ Manus session ใหม่ เมื่อ session เดิมสิ้นสุดหรือเครดิตหมด โดยให้ agent ใหม่เข้าใจระบบ วิเคราะห์ต่อจากหลักฐานปัจจุบัน และไม่เริ่มตรวจระบบซ้ำแบบไร้ทิศทาง

---

## 1. ข้อความเริ่มต้นที่ให้คัดลอกไปยัง Manus session ใหม่

ให้คัดลอกข้อความใน block นี้ไปเป็นข้อความแรกของ session ใหม่ได้ทันที

> คุณกำลังพัฒนาต่อโครงการ **AEGIS** ซึ่งเป็น Windows-native Network Intrusion Detection and Response system ใน repository `D:\NIDs_Windows` ผู้ใช้ต้องการให้พัฒนาต่อจากสถานะจริงในเอกสารนี้ ห้ามเริ่มจากสมมติฐานว่าโครงสร้างทั้งหมด production-ready แล้ว
>
> ก่อนแก้ source ให้ทำตามลำดับนี้:
>
> 1. อ่านไฟล์ `AEGIS_MANUS_NEW_SESSION_STARTER_2026-09-18.md` ทั้งฉบับ
> 2. อ่าน `AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md`
> 3. อ่าน `AEGIS_SYSTEM_WIDE_RUNTIME_FLOW_2026-09-18.md`
> 4. ตรวจ `git rev-parse HEAD`, working tree และไฟล์ source ที่ระบุในเอกสาร
> 5. ตรวจว่า machine maps และ inventory ตรงกับ current HEAD ก่อนเชื่อผล
> 6. รัน targeted tests ก่อนแก้ source
> 7. แก้เป็น vertical slice โดยรักษา invariants และ authority boundaries
> 8. รัน test และบันทึกผลหลังทุก patch
>
> สถาปัตยกรรม authority ที่ต้องรักษาคือ:
>
> ```text
> Nose = network observation and ingress only
> Zig = runtime owner, lifecycle owner, queue and orchestration owner
> Rust PEP = sole privileged enforcement authority
> WFP = host effect provider
> Forensic = evidence and integrity record
> Mouth = operator/read-only receipt presentation
> ```
>
> Golden Path ที่พิสูจน์แล้วใน Windows คือ:
>
> ```text
> Go Nose
>   -> 109-byte CanonicalEvent
>   -> \\.\pipe\aegis_nose
>   -> Zig canonical reader
>   -> event queue
>   -> pipeline processing
>   -> forensic append
>   -> verified hash chain
> ```
>
> ผล Controlled Canonical Ingress Proof ล่าสุดผ่านแล้ว:
>
> ```text
> proof = canonical_observe_only
> passed = true
> requested = 1
> packets_captured delta = 1
> events_processed delta = 1
> forensic_records delta = 1
> blocks delta = 0
> errors delta = 0
> forensic integrity = ok
> forensic verified = true
> ```
>
> แต่ยังห้ามประกาศว่า Detection -> Policy -> Rust PEP -> WFP host effect -> EnforcementReceipt -> Mouth ผ่านแล้ว เพราะ fixture ล่าสุดเป็น `forward`, `RuleID=0`, `log_only` และพิสูจน์เฉพาะ canonical ingress ถึง forensic
>
> งานถัดไปตามลำดับคือ:
>
> 1. ตรวจและทำให้ DetectionResult deterministic
> 2. สร้าง alert-only fixture ที่พิสูจน์ detection และ policy match โดยไม่สร้าง WFP block
> 3. ทำให้ Rust PEP คืน EnforcementReceipt ที่ตรวจ postcondition ได้จริง
> 4. แยก PEP decision ออกจาก WFP host effect
> 5. เชื่อม receipt เข้า forensic และ Mouth
> 6. ทำ graceful shutdown แบบ stop ingress -> join producers -> drain queue -> flush forensic -> teardown -> STOPPED
> 7. ทำ truth rebuild และ full Windows acceptance
>
> ห้ามใช้ผลจาก `aegisctl simulate`, `policy simulate` หรือ `enforcement simulate` เป็น production proof เพราะบาง handler เป็น fixture หรือ intentionally unavailable ให้พิสูจน์ผ่าน actual control path และ actual canonical pipe เท่านั้น

---

## 2. ภาพรวมโครงการ

AEGIS เป็นระบบตรวจจับและตอบสนองภัยคุกคามบน Windows ที่มีหลายภาษาและหลาย boundary การทำงานไม่ได้จบที่การรับ packet หรือการแสดงคำว่า `BLOCKED` ใน log ระบบต้องพิสูจน์ความต่อเนื่องของข้อมูลและอำนาจตั้งแต่ ingress ถึงผลกระทบบน host

ภาพรวมที่ถูกต้องคือ:

```text
Npcap / ETW / FIM / Registry / other sensors
        |
        v
Acquisition adapters
        |
        v
Canonical event contract
        |
        v
Ingress validation and identity authority
        |
        v
Bounded event queue
        |
        v
DetectionResult
        |
        v
PolicyDecision
        |
        v
Rust PEP authorization
        |
        v
WFP / native host adapter
        |
        v
EnforcementReceipt
        |
        +--------------------+
        v                    v
Forensic evidence       Mouth/operator display
```

### บทบาทของแต่ละภาษา

| ส่วนประกอบ | ภาษา | บทบาทปัจจุบัน | ขอบเขตอำนาจที่ต้องรักษา |
|---|---|---|---|
| Runtime Hub | Zig | daemon, lifecycle, control pipe, queue, detection/policy orchestration, forensic coordination | เป็น runtime owner แต่ไม่สร้าง enforcement authority ซ้ำกับ Rust |
| Nose | Go | Npcap acquisition และ canonical network ingress | รับและส่งข้อมูลเท่านั้น ไม่ block, quarantine หรือเรียก WFP |
| Native adapters | C/C++ | WFP, ETW, FIM และ Windows boundary | รายงาน adapter/host result กลับมา ไม่ตัดสิน policy เอง |
| PEP | Rust | policy enforcement point และ privileged authorization | เป็นผู้เดียวที่อนุญาต privileged host action |
| Policy authoring | TypeScript | สร้าง validate sign/seal policy | ไม่บังคับใช้ policy |
| Intelligence | Python/Cython | analytics, enrichment, context และ operator tools | ไม่ข้าม PEP ไปบังคับใช้ |
| Mouth | Rust | dashboard, health, DEFCON และ receipt presentation | แสดงผล ไม่สร้าง enforcement decision เอง |

---

## 3. สถานะที่ยืนยันแล้ว

### 3.1 Runtime acceptance ล่าสุด

ผล runtime ที่ผู้ใช้ส่งล่าสุดมีสาระสำคัญดังนี้:

```text
State: RUNNING
Degraded: False
runtime_available: true
overall_gate: true
worker_gate: true
```

Workers ที่ผ่าน readiness:

```text
pipeline_ready: READY
sensor_ready: READY
nose_ready: READY
etw_ready: READY
fim_ready: READY
registry_ready: READY
failed: NO
failure_reason: none
```

Data-plane ล่าสุดก่อน Controlled Proof:

```text
nose_connected: true
nose_frames_read: 19775
nose_frames_rejected: 0
nose_frames_submitted: 19775
nose_frames_dropped: 0
nose_pipe_errors: 0
nose_last_event_id: 19775
nose_duplicate_event_ids: 0
nose_non_monotonic_event_ids: 0
```

Metrics โดยรวม:

```text
anomalies: 0
errors: 0
detections: 0
blocks: 0
forensic_records: 20056
packets_captured: 19775
rules_loaded: 22
```

Forensic verification:

```text
integrity: ok
verified: true
```

PEP status:

```text
Enabled: True
Mode: FAIL_CLOSED
```

### 3.2 Controlled Canonical Ingress Proof ล่าสุด

คำสั่งที่ใช้คือ:

```powershell
Set-Location D:\NIDs_Windows
.\scripts\run_controlled_proof.ps1 -Count 1
```

ผลที่ผ่าน:

```text
[NOSE PIPE] connected to \\.\pipe\aegis_nose
[NOSE PIPE] first canonical frame sent: 113 bytes event_id=1
[NOSE INJECT] observe-only sent=1 dropped=0 count=1
```

ผล proof:

```json
{
  "proof": "canonical_observe_only",
  "passed": true,
  "requested": 1,
  "deltas": {
    "packets_captured": 1,
    "events_processed": 1,
    "forensic_records": 1,
    "blocks": 0,
    "errors": 0
  },
  "forensic": {
    "integrity": "ok",
    "records": 35,
    "verified": true
  }
}
```

ผลนี้เป็นหลักฐานจริงของ:

```text
Go canonical serializer
-> FrameWriter
-> named pipe aegis_nose
-> Zig reader
-> queue/pipeline processing
-> forensic append
-> retained hash-chain verification
```

ผลนี้ยังไม่ใช่หลักฐานของ:

```text
signature detection
policy match
Rust PEP decision
WFP host effect
EnforcementReceipt
Mouth receipt consumption
```

สาเหตุคือ fixture มีค่า:

```text
EventType = forward
RuleID = 0
PolicyAction = log_only
```

### 3.3 Authority invariant

คำสั่ง `aegisctl authority` แสดง:

```text
Authority invariant: HELD
```

ความหมายคือ invariant ด้าน authority boundary ยังถืออยู่ ระบบไม่พบหลักฐานว่า component อื่นแย่ง privileged enforcement authority จาก Rust PEP

`HELD` ไม่ได้หมายความว่า WFP host effect เกิดขึ้นจริง และไม่ใช่ substitute ของ EnforcementReceipt

---

## 4. แผนผังไฟล์สำคัญ

### Zig runtime

```text
src/main.zig
src/daemon.zig
src/control/state_machine.zig
src/control/handler_registry.zig
src/capture/nose_pipe_reader.zig
src/contract/canonical_event.zig
src/contract/event.zig
src/pipeline/event_queue.zig
src/pipeline/event_processor.zig
src/pipeline/runtime_state.zig
src/policy/policy_ir.zig
src/policy/policy_engine.zig
src/policy/pep_bindings.zig
src/policy/action_dispatcher.zig
src/forensic/forensic_pipeline.zig
src/forensic/decision_trace.zig
```

### Go Nose

```text
nose/main.go
nose/capture.go
nose/canonical.go
nose/pipe_writer.go
nose/golden_path_ffi.go
nose/inject.go
```

### Operator and control

```text
tools/aegisctl.py
tools/aegisctl/api/control_api.py
scripts/aegis_event_gen.py
scripts/run_controlled_proof.ps1
```

### Configurations

```text
configs/Rules.json
configs/policies.json
```

### Mouth and native integration

```text
mouth/windows_sec_monitor.rs
mouth/aegis_mouth_tui.rs
```

### Project documents

```text
AEGIS_COMPLETE_PHASE_PLAN_2026-09-17.md
AEGIS_END_TO_END_DEVELOPMENT_PLAN.md
AEGIS_SYSTEM_ANALYSIS_BASELINE_2026-09-17.md
AEGIS_SYSTEM_WIDE_RUNTIME_FLOW_2026-09-18.md
AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md
AEGIS_MANUS_NEW_SESSION_STARTER_2026-09-18.md
```

---

## 5. Nose data path แบบละเอียด

Nose เป็น front door ของ **network data plane** ไม่ใช่ front door ของทุก sensor ในระบบ เพราะ ETW, FIM และ Registry มี ingress ของตัวเอง

Live capture flow:

```text
Npcap packet
  -> gopacket decode
  -> eventFromPacket
  -> CanonicalEvent
  -> Serialize()
  -> 109-byte wire payload
  -> 4-byte little-endian length prefix
  -> 113-byte pipe frame
  -> \\.\pipe\aegis_nose
  -> Zig readExact
  -> canonical validation/deserialization
  -> pushCanonicalEvent
  -> event queue
```

หน้าที่ของ Nose:

- เลือก Npcap adapter
- เปิด passive capture
- ใช้ BPF `ip or ip6`
- สร้าง source/destination IP, ports และ protocol
- สร้าง event identity ของ producer
- serialize canonical frame
- reconnect pipe ตาม implementation
- นับ sent และ dropped frame

สิ่งที่ Nose ห้ามทำ:

- ตัดสินใจ block หรือ quarantine
- เรียก WFP โดยตรง
- อ้างว่า host effect สำเร็จ
- เป็น source of truth ของ policy
- สร้าง receipt แทน PEP

### ความหมายของ frame size

```text
4-byte length prefix + 109-byte payload = 113 bytes
```

เมื่อเห็นข้อความ:

```text
first canonical frame sent: 113 bytes
```

ให้ตีความว่าการส่งระดับ transport สำเร็จเท่านั้น ต้องตรวจ metrics และ forensic ต่อจึงจะยืนยัน pipeline ได้

---

## 6. Canonical ABI ที่ต้องระวัง

Canonical wire payload มี 109 bytes และ header 8 bytes:

```text
0..3      magic
4..5      schema version
6..7      struct-size marker
8..15     event_id
16..23    timestamp_ms
24..31    monotonic_ns
32        source
33..36    source_ip
37..38    source_port
39..42    dest_ip
43..44    dest_port
45..52    session_id
53        protocol
54        direction
55        layer_id
56        is_pipe
57..60    event_type
61        severity
62..65    rule_id
66..73    ruleset_version
74..77    payload_length
78..85    payload_hash
86        policy_action
87        enforcement_status
88        defcon_impact
89..92    context_flags
93..108   reserved extension area
```

Internal `IpcEvent` เป็น 96 bytes และไม่ใช่ wire payload เดียวกัน ห้ามรวมสอง layout ให้กลายเป็น contract เดียวแบบไม่มี version

จุดที่ต้องตรวจต่อก่อน enforcement:

- Go และ Zig event-type ordinals ต้องตรงกัน
- Go และ Zig policy-action ordinals ต้องตรงกัน
- struct-size marker ต้องเป็นค่าที่ทุกภาษาเข้าใจเหมือนกัน
- comment เรื่อง hash ต้องตรงกับ implementation จริง
- timestamp ต้องแยก wall-clock จาก monotonic clock
- IPv6 representation ต้องมี contract ที่ชัดเจน
- invalid source, event type, policy action และ confidence ต้องถูก reject ทุกภาษาเหมือนกัน

---

## 7. Event identity และ exactly-once

ปัญหาเดิมคือ Go Nose มี process-local counter:

```go
var eventSequence uint64
```

เมื่อ Nose restart counter เริ่มจาก 1 อีกครั้ง ขณะที่ Zig ยังถือ event ID จาก generation เดิม จึงเกิด non-monotonic event ID แม้ไม่ใช่ duplicate ภายใน process เดียว

หลักการแก้ที่ถูกต้อง:

```text
หนึ่ง identity authority
หนึ่ง namespace ที่ระบุ producer generation
duplicate แยกจาก collision
non-monotonic แยกจาก retry
```

ตัวเลือกที่ต้องประเมิน:

```text
identity = node_id + runtime_generation + producer_epoch + producer_event_id
```

หรือให้ Zig ingress เป็นผู้จัดสรร global sequence แล้ว Nose ส่ง producer-local ID เป็น metadata

ห้ามแก้โดยการ reset Zig counter หรือซ่อน non-monotonic metric เพราะจะทำให้ health ดูดีแต่สูญเสียหลักฐาน identity

Retry ต้องออกแบบพร้อม idempotency ก่อนเปิดใช้ เพราะการ resend frame ที่ไม่มี deduplication อาจสร้าง forensic หรือ enforcement side effect ซ้ำ

---

## 8. Detection และ Policy: จุดที่ต้องพัฒนาต่อ

Pipeline ปัจจุบันใน `src/pipeline/event_processor.zig` มีลำดับโดยประมาณ:

```text
flow lookup
-> signature matching
-> anomaly detection
-> threat tracking
-> forensic trace preparation
-> policy evaluation
-> PEP call
-> action dispatch
-> forensic append
```

`pushCanonicalEvent` ใน `event_queue.zig` แปลง CanonicalEvent เป็น IpcEvent โดยคง event ID, severity, rule ID และ metadata แต่ปัจจุบัน payload bytes ไม่ได้ถูกส่งเข้า queue ใน canonical path แม้ payload length และ hash จะถูกคงไว้

ผลกระทบคือ payload-based signature detection อาจเห็น metadata แต่ไม่เห็น raw payload จริง

ข้อสังเกตสำคัญ:

- Canonical event ที่มี `event_type = match_` และ `rule_id != 0` สามารถทำให้ pipeline นับ detection จาก metadata ได้
- Canonical event ที่เป็น `forward` และไม่มี rule ID เป็น ingress/observation proof ไม่ใช่ detection proof
- Policy `block_signature_match` หากถูกใช้กับ rule ID ที่ไม่เป็นศูนย์อาจนำไปสู่ block action จึงห้ามใช้เป็น fixture แรก
- การพิสูจน์ detection ควรใช้ fixture alert-only ที่ไม่มี WFP block side effect
- `policySimulate` และ `enforcementSimulate` ใน handler ปัจจุบันเป็น structural response ไม่ใช่ proof ของ actual pipeline

### Severity mapping ที่แก้แล้ว

พบ mapping ระหว่าง canonical severity และ internal EventSeverity:

```text
Canonical 0 -> internal info=2
Canonical 1 -> internal warning=4
Canonical 2 -> internal critical=6
Canonical 3 -> internal alert=7
```

Policy `alert_high_severity` เดิมใช้ `severity == 5` ซึ่งคือ internal `error` และไม่ match High ที่ map เป็น warning จึงแก้ใน:

```text
configs/policies.json
```

จาก:

```json
{"field":"severity","op":"eq","value_int":5}
```

เป็น:

```json
{"field":"severity","op":"eq","value_int":4}
```

Critical policy `severity >= 6` ยังไม่ได้เปลี่ยน

ก่อนใช้ policy ใหม่ ต้อง reload policy หรือ restart daemon จาก project root และตรวจว่า runtime โหลด config จริง

---

## 9. PEP, WFP และ EnforcementReceipt

Rust PEP ต้องเป็น sole authority ของ privileged action โดยรับ request จาก Zig และตรวจอย่างน้อย:

```text
policy signature
policy version
policy hash
TTL/expiry
caller capability
request freshness
nonce/replay protection
request identity
WFP availability
host effect result
```

สิ่งที่ห้ามสับสน:

```text
decision = สิ่งที่ PEP อนุญาตหรือปฏิเสธ
submission = request ถูกส่งไป provider แล้ว
host effect = Windows/WFP ทำผลจริงแล้ว
receipt = หลักฐานที่ผูกทุกขั้นตอนเข้าด้วยกัน
```

`BLOCKED` ใน log หรือ `pep_decision=block` ไม่ใช่หลักฐานว่า WFP filter ถูกติดตั้งและมีผลจริง

Production EnforcementReceipt ควรมีอย่างน้อย:

```text
request_id
event_id
trace_id
audit_id
policy_id
policy_version
policy_hash
requested_action
pep_decision
status
provider
filter_id
host_effect_confirmed
timestamp
failure_reason
```

สถานะต้องแยกอย่างน้อย:

```text
AUTHORIZED
SUBMITTED
ENFORCED
UNAVAILABLE
FAILED
DEFERRED
ESCALATED
```

งานถัดไปควรเริ่มจาก `alert-only` หรือ `log-only` receipt ที่ตรวจได้ โดยยังไม่เรียก WFP block หลังจากนั้นจึงเพิ่ม controlled WFP fixture ใน isolated lab พร้อม cleanup proof

---

## 10. Forensic evidence

Forensic ring ปัจจุบันพิสูจน์ hash-chain integrity ของ retained records ได้ แต่เป็น bounded in-memory storage ไม่ใช่ durable complete history

ต้องแยก metrics ต่อไปนี้:

```text
accepted
retained
exported
overwritten
lost_before_accept
lost_after_accept
append_failed
duplicate_suppressed
```

ทุก accepted event ควรมี forensic identity เดียว และ append ต้อง idempotent โดยใช้ event identity หรือ evidence id ไม่ใช่ record sequence อย่างเดียว

Record ที่สมบูรณ์ควรผูก:

```text
event_id
trace_id
audit_id
detection_result
policy_decision
pep_request_id
enforcement_id
host_effect result
```

ผล:

```json
{"integrity":"ok","verified":true}
```

หมายความว่า records ที่ยังอยู่ใน ring มี chain integrity ไม่ได้หมายความว่าไม่มี record ถูก overwrite หรือไม่มี event สูญหายก่อน append

---

## 11. Mouth

Mouth เป็น operator surface ไม่ใช่ enforcement authority

Mouth ควรอ่าน canonical health และ receipt stream จาก runtime แล้วแสดงสถานะแยกกัน:

```text
DECISION_REQUESTED
DECISION_ALLOW
DECISION_BLOCK
ENFORCEMENT_SUBMITTED
HOST_EFFECT_CONFIRMED
ENFORCEMENT_FAILED
ENFORCEMENT_DEFERRED
```

Mouth ไม่ควรสรุปว่า host ถูก block จากการค้นข้อความ `BLOCKED` ใน log เพียงอย่างเดียว

จุดที่ต้องตรวจต่อ:

- health ต้องมาจาก core จริง ไม่ hard-code `RUNNING/OK`
- version ของ Mouth ต้องตรงกับ runtime contract
- counters ต้อง update จริง
- parser ต้องใช้ JSON schema ไม่ใช้ substring เป็นหลัก
- input/output path ต้องไม่ชนกัน
- log rotation ต้องไม่ทำให้ receipt หาย
- health thread ต้อง join ตอน shutdown
- PID และ source IP ต้องไม่ใช้ field เดียวกัน

---

## 12. Lifecycle และ graceful shutdown

Zig daemon เป็น owner ของ worker handles, stop signal, join order และ readiness

Startup:

```text
STOPPED
  -> STARTING
  -> initialize adapters/workers
  -> readiness barrier
  -> READY/RUNNING/DEGRADED
```

Shutdown ที่ถูกต้อง:

```text
RUNNING/DEGRADED
  -> STOPPING
  -> stop acquisition
  -> reject new ingress
  -> wait producers
  -> drain accepted queue
  -> complete detection/policy/PEP
  -> flush forensic/audit
  -> teardown WFP/bridges
  -> join workers
  -> verify postconditions
  -> STOPPED
```

ห้ามตอบ `STOPPED` หลังเพียง set enum หาก workers ยังไม่ join หรือ forensic ยังไม่ flush

`daemon.shutdown` และ `runtime.stop` ต้องตรวจให้เห็น postconditions จริง หากยังทำไม่ได้ให้คืน unavailable แทนการอ้างว่าสำเร็จ

---

## 13. ขั้นตอนทำงานของ Manus session ใหม่

### ขั้นที่ 1: ตรวจความจริงของ repository

```powershell
Set-Location D:\NIDs_Windows
git rev-parse HEAD
git status --short
```

ตรวจว่ามีไฟล์ต่อไปนี้:

```powershell
Test-Path .\AEGIS_MANUS_NEW_SESSION_STARTER_2026-09-18.md
Test-Path .\AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md
Test-Path .\scripts\run_controlled_proof.ps1
Test-Path .\nose\inject.go
```

ห้ามเชื่อรายงานเก่าหาก SHA หรือ source ไม่ตรง current working tree

### ขั้นที่ 2: รัน targeted tests

```powershell
Set-Location D:\NIDs_Windows
zig build test
```

```powershell
Set-Location D:\NIDs_Windows\nose
gofmt -w inject.go main.go
go test ./... -timeout 30s
```

หาก Go test timeout ให้ใช้:

```powershell
go test ./... -timeout 30s -v
```

และบันทึกชื่อ test ที่ค้าง ห้ามประกาศ pass จาก timeout

### ขั้นที่ 3: ตรวจ runtime

เริ่ม daemon จาก project root:

```powershell
Set-Location D:\NIDs_Windows
zig build run
```

จาก PowerShell อีกหน้าต่างหนึ่ง:

```powershell
Set-Location D:\NIDs_Windows
python tools\aegisctl.py health --json
python tools\aegisctl.py readiness
python tools\aegisctl.py metrics
python tools\aegisctl.py forensics verify --json
python tools\aegisctl.py authority
```

### ขั้นที่ 4: Build Nose

```powershell
Set-Location D:\NIDs_Windows\nose
gofmt -w inject.go main.go
go test ./... -timeout 30s
go build -o ..\dist\aegis-nose.exe .
```

ตรวจ flag:

```powershell
Set-Location D:\NIDs_Windows
.\dist\aegis-nose.exe -h
```

ต้องเห็น:

```text
-inject-observe
-inject-count
```

### ขั้นที่ 5: รัน canonical ingress proof

```powershell
Set-Location D:\NIDs_Windows
.\scripts\run_controlled_proof.ps1 -Count 1
```

ผ่านเมื่อ:

```text
passed = true
events_processed delta >= requested
forensic_records delta >= requested
forensic.verified = true
blocks delta = 0
errors delta = 0
```

### ขั้นที่ 6: พัฒนา vertical slice ถัดไป

อย่าเริ่ม WFP block ทันที ให้พัฒนาในลำดับ:

```text
alert-only DetectionResult
  -> alert-only PolicyDecision
  -> PEP authorization
  -> EnforcementReceipt with no-host-effect status
  -> forensic linkage
  -> Mouth display
```

จากนั้นค่อยทำ:

```text
isolated WFP effect
  -> filter ID capture
  -> host_effect_confirmed
  -> cleanup proof
  -> receipt verification
```

---

## 14. Roadmap ต่อจากสถานะปัจจุบัน

### Phase A — Truth synchronization

สร้าง inventory, reference map และ manifest จาก current HEAD ใหม่ หลัง source patch สำคัญทุกครั้งต้องตรวจว่า maps ไม่ stale

### Phase B — ABI convergence

รวม magic, version, size, offsets, enum และ validation ให้เป็น authoritative contract เดียว พร้อม golden vectors ทุกภาษา

### Phase C — Identity convergence

กำหนด runtime generation และ producer epoch เพิ่ม duplicate/collision/replay semantics และทำให้ forensic identity durable

### Phase D — Ingress convergence

ให้ Nose, ETW, FIM, Registry และ legacy sensor ผ่าน ingress authority/facade เดียวกัน พร้อม counter conservation:

```text
submitted = accepted + rejected + capacity_dropped + lifecycle_dropped
```

### Phase E — Detection and policy

สร้าง deterministic `DetectionResult` และ `PolicyDecision` ที่มี trace ID เดียวและระบุ source/version/rule identity ชัดเจน

### Phase F — PEP and WFP

ทำ PEP ABI ให้ตรง เพิ่ม signature/freshness/nonce/replay/capability checks สร้าง receipt และตรวจ host effect จาก WFP จริง

### Phase G — Forensic

ทำ idempotent append, durable export, evidence completeness และ shutdown flush

### Phase H — Mouth

เปลี่ยนเป็น canonical receipt consumer แยก decision จาก host effect และรายงาน degraded state จริง

### Phase I — Lifecycle

ทำ stop, reject ingress, join producers, drain queue, flush evidence, teardown adapters, join workers และ restart generation

### Phase J — Release

รัน full test suite, Windows host E2E, controlled lab cleanup, truth rebuild และ release artifact verification

---

## 15. Stop-the-line conditions

หยุด feature development และแก้ correctness ก่อนเมื่อพบเหตุการณ์ต่อไปนี้:

- ABI mismatch
- enum semantic mismatch
- event identity collision
- silent event loss
- accepted queue event หาย
- duplicate PEP side effect
- enforcement bypass
- WFP success ที่ไม่มี host proof
- unauthorized control-pipe access
- runtime state ไม่ตรง process/worker จริง
- stale inventory/reference map
- mock หรือ fixture ถูกอ้างเป็น production proof
- `verified=true` ถูกตีความว่า durable evidence ทั้งหมด
- `Authority invariant: HELD` ถูกตีความว่า WFP host effect สำเร็จ

---

## 16. หลักการรายงานผล

ทุกครั้งที่ทำงานต่อ ให้รายงานตามรูปแบบนี้:

```text
1. Scope ที่ทำ
2. Source files ที่แก้
3. Invariant ที่ต้องรักษา
4. Test command
5. Runtime command
6. ผลที่สังเกตได้จริง
7. สิ่งที่พิสูจน์ได้
8. สิ่งที่ยังพิสูจน์ไม่ได้
9. ความเสี่ยงที่เหลือ
10. ขั้นถัดไป
```

ห้ามใช้คำว่า “production-ready” จนกว่าจะผ่านอย่างน้อย:

```text
ABI byte-level validation
identity continuity
ingress reconciliation
deterministic detection/policy
Rust PEP-only enforcement
verified WFP host effect
EnforcementReceipt linkage
forensic completeness/durability
Mouth receipt integration
graceful shutdown
truth-valid release artifacts
```

---

## 17. เอกสารอ้างอิงภายในโครงการ

[1]: ./AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md "AEGIS Development Handoff"
[2]: ./AEGIS_SYSTEM_WIDE_RUNTIME_FLOW_2026-09-18.md "AEGIS System-Wide Runtime Flow"
[3]: ./AEGIS_COMPLETE_PHASE_PLAN_2026-09-17.md "AEGIS Complete Phase Plan"
[4]: ./AEGIS_END_TO_END_DEVELOPMENT_PLAN.md "AEGIS End-to-End Development Plan"
[5]: ./src/contract/canonical_event.zig "Zig Canonical Event Contract"
[6]: ./src/pipeline/event_queue.zig "Zig Event Queue and Canonical Ingress Adapter"
[7]: ./src/pipeline/event_processor.zig "Zig Detection Pipeline Event Processor"
[8]: ./nose/canonical.go "Go Canonical Event Serializer"
[9]: ./nose/pipe_writer.go "Go Nose Canonical Pipe Writer"
[10]: ./nose/inject.go "Go Observe-Only Canonical Injector"
[11]: ./scripts/run_controlled_proof.ps1 "Controlled Canonical Proof Runner"

เอกสารนี้ควรถูกอ่านร่วมกับ source ปัจจุบันเสมอ โดย source และผล runtime ที่ตรวจซ้ำได้มีอำนาจเหนือข้อความรายงานเก่า [1] [2]

---

## 18. สรุปสั้นสำหรับ agent ใหม่

```text
AEGIS ไม่ได้จบที่ Nose ต่อ pipe ได้

สิ่งที่ผ่านแล้ว:
Nose -> canonical wire -> aegis_nose -> Zig -> queue -> pipeline -> forensic verified

สิ่งที่ยังต้องทำ:
detection -> policy -> Rust PEP -> WFP host effect -> receipt -> Mouth -> graceful shutdown

กฎสำคัญ:
Nose observe only
Zig owns runtime
Rust PEP owns enforcement
WFP proves host effect
Forensic proves evidence
Mouth displays receipts

เริ่มงานใหม่โดยอ่านเอกสารนี้ก่อน
ตรวจ current HEAD ก่อนเชื่อ report
รัน targeted tests ก่อนแก้
ทำ alert-only receipt proof ก่อน block
ห้ามใช้ mock เป็น production proof
```
