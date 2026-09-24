# AEGIS Development Handoff

## วัตถุประสงค์ของเอกสาร

เอกสารนี้เป็น **คู่มือส่งต่องานพัฒนา AEGIS** สำหรับใช้เริ่มงานต่อใน session ใหม่หรือโดย developer/agent อื่น โดยไม่ต้องพึ่งพาบริบทการสนทนาเดิมทั้งหมด เอกสารอธิบายว่า AEGIS ประกอบด้วยอะไร เส้นทางข้อมูลจริงอยู่ที่ไหน อำนาจของแต่ละส่วนอยู่ตรงใด หลักฐานใดผ่านแล้ว จุดใดยังไม่ผ่าน และควรพัฒนาต่ออย่างไรโดยไม่สร้าง authority ซ้ำ

เอกสารนี้ต้องอ่านคู่กับ source ปัจจุบันและผล runtime ล่าสุดเสมอ เพราะ **runtime behavior และ current source มีอำนาจสูงกว่า report เก่าและ machine maps ที่ยังไม่ได้ rebuild**

## 1. สรุปสถานะปัจจุบัน

AEGIS เป็น Windows-native NIDS/NIDR ที่แบ่งบทบาทตามภาษา:

| ส่วน | ภาษา | บทบาท |
|---|---|---|
| Runtime Hub | Zig | lifecycle, control, queue, detection orchestration, policy orchestration, forensic coordination |
| Nose | Go | Npcap packet acquisition และ canonical network ingress |
| Native adapters | C/C++ | WFP/ETW/FIM และ Windows adapter boundary |
| PEP | Rust | privileged authorization และ final enforcement authority |
| Policy authoring | TypeScript | สร้าง/validate/seal policy โดยไม่บังคับใช้เอง |
| Intelligence | Python/Cython | analytics, enrichment และ context |
| Mouth | Rust | operator dashboard, DEFCON feedback, health และ receipt presentation |

หลักการที่ต้องรักษา:

```text
Nose = observation/ingress
Zig = runtime owner
Rust PEP = sole enforcement authority
WFP = host effect
Forensics = evidence
Mouth = operator feedback
```

### หลักฐานที่ผ่านแล้ว

การทดสอบบน Windows ล่าสุดพิสูจน์เส้นทางต่อไปนี้ได้จริง:

```text
Go Nose -> \\.\pipe\aegis_nose -> Zig reader -> event processing -> forensic ring
```

ค่าหลักฐานล่าสุด:

```text
State: RUNNING
Degraded: False
nose_frames_read: 3194
nose_frames_submitted: 3194
nose_frames_rejected: 0
nose_frames_dropped: 0
nose_pipe_errors: 0
errors: 0
dropped: 0
rules_loaded: 22
events_processed: 3784
forensic_records: 3784+
forensics integrity: verified=true
Authority invariant: HELD
```

นี่พิสูจน์ **ingress, processing และ retained forensic integrity** แต่ยังไม่พิสูจน์ครบว่า detection, policy decision, Rust PEP, WFP host effect และ EnforcementReceipt ทำงานจริงใน Windows production path

### จุดที่ต้องแก้ต่อ

1. Event identity ของ Go Nose เป็น process-local และ reset เมื่อ Nose restart ทำให้ non-monotonic counter เพิ่ม
2. มี event model/identity หลายชุด: CanonicalEvent 109-byte, IpcEvent 96-byte และ legacy ingress
3. Go Nose pipe path ยัง bypass Event Fabric facade ในบางจุด
4. Policy/enum/PEP ABI มีความเสี่ยง schema drift ข้ามภาษา
5. PEP response ยังไม่เท่ากับ EnforcementReceipt ที่ยืนยัน host effect
6. Forensic ring เป็น bounded in-memory evidence ไม่ใช่ durable complete history
7. Shutdown ยังต้องพิสูจน์ stop ingress, drain queue, flush forensic และ join ครบ
8. Mouth ยังอ่าน log และคำนวณ DEFCON เอง ควรย้ายไปเป็น receipt consumer
9. Machine maps อาจ stale ต้อง rebuild หลัง commit ที่สำคัญ

## 2. ความเข้าใจที่ถูกต้องเกี่ยวกับ Nose

Nose เป็น **front door ของ network data plane** ไม่ใช่ front door ของทุก sensor ทั้งระบบ เพราะ ETW, FIM, Registry และ adapter อื่นยังมี ingress ของตนเอง

Nose capture flow:

```text
Npcap packet
  -> gopacket decode
  -> eventFromPacket
  -> CanonicalEvent
  -> Serialize 109 bytes
  -> u32 LE length prefix + payload
  -> \\.\pipe\aegis_nose
  -> Zig readExact
```

ขนาด frame บน pipe:

```text
4-byte length prefix + 109-byte payload = 113 bytes
```

Nose ทำสิ่งต่อไปนี้:

- เลือก physical Npcap adapter
- เปิด capture แบบ passive
- ใช้ BPF `ip or ip6`
- แปลง IP/port/protocol เป็น canonical metadata
- โหลด signature rules เพื่อจัดประเภท event
- ส่ง frame ไป Zig
- นับ packets, canonical events และ dropped frames

Nose ห้ามทำสิ่งต่อไปนี้:

- ตัดสินใจ block/quarantine
- เรียก WFP โดยตรง
- ประกาศ host effect สำเร็จ
- เป็น source of truth ของ policy

### ความหมายของ `nose_connected`

`nose_connected` เป็น **สถานะ connection ปัจจุบัน** ไม่ใช่สถานะว่าเคยเชื่อมต่อหรือไม่

ดังนั้นลำดับนี้ถูกต้อง:

```text
Nose กำลังทำงานและ pipe connected -> nose_connected=true
Nose ถูกหยุด/กลับมาที่ PowerShell -> nose_connected=false
แต่ frames_read/submitted ยังคงเก็บสถิติที่ผ่านมา
```

ก่อนหน้านี้มีการตีความ `nose_connected=false` ผิดว่าเป็น health bug ทั้งที่หลังหยุด Nose แล้วค่านี้ถูกต้อง สิ่งที่ควรเพิ่มคือ field แยก เช่น:

```json
{
  "nose_connected": false,
  "nose_first_frame_seen": true,
  "nose_last_disconnect_ms": 123,
  "nose_frames_read": 3194
}
```

ห้ามเปลี่ยน `nose_connected` ให้ค้างเป็น true หลัง client disconnect เพราะจะทำให้ health โกหก

## 3. Event identity และ exactly-once

ปัญหา event ID ล่าสุดเกิดจาก Go Nose มี:

```go
var eventSequence uint64
```

เมื่อ process เริ่มใหม่ sequence กลับไป 1 ขณะที่ Zig daemon ยังมี `g_last_event_id` จากรอบก่อน จึงได้:

```text
previous event_id = 693
new Nose event_id = 1
non_monotonic_event_ids += 1
```

นี่ไม่ใช่ duplicate ภายใน process เดียว แต่เป็น identity continuity failure ข้าม process generation

แนวทางที่ต้องทำต่อ:

1. เลือก identity authority เพียงจุดเดียว
2. ห้ามให้ Go, legacy Zig และ canonical Zig mint ID ใน namespace เดียวกันโดยอิสระ
3. ใช้ runtime generation/producer epoch หรือ durable compound identity
4. ตรวจ collision โดยดูทั้ง identity และ payload hash
5. แยก duplicate, collision และ non-monotonic เป็นคนละ metric
6. กำหนด retry semantics ก่อนเพิ่ม ACK/retry เพราะ retry โดยไม่มี idempotency จะสร้าง side effect ซ้ำ

แบบที่แนะนำ:

```text
identity = node_id + runtime_generation + producer_epoch + event_id
```

หรือให้ Zig ingress authority เป็นผู้จัดสรร global sequence แล้ว Nose ส่ง producer-local sequence เป็น metadata เท่านั้น

## 4. ABI และ patch ที่ทำแล้ว

ไฟล์ที่แก้ในรอบนี้:

```text
nose/golden_path_ffi.go
```

การแก้ไขคือ `Deserialize` เดิมอ่าน `EventID` จาก `b[0:8]` ซึ่งเป็น header ของ wire frame การแก้ไขใหม่ตรวจ:

- magic ที่ offset 0..3
- schema version ที่ offset 4..5
- struct-size marker ที่ offset 6..7
- event ID จาก offset 8..15

การแก้ไขนี้เป็น correctness patch ที่ไม่เปลี่ยน production wire layout

ต้องรันบน Windows:

```powershell
Set-Location D:\NIDs_Windows\nose
go test ./...
```

และต้องเพิ่ม/ตรวจ golden vectors ให้ครอบคลุม:

- benign forward
- match/alert
- IPv4
- IPv6
- bad magic
- bad schema
- bad struct size
- invalid source
- invalid event type
- invalid policy action
- confidence > 100
- truncated frame

## 5. Canonical event contract

Zig canonical contract ระบุ:

```text
EVENT_MAGIC       = 0x41454731
EVENT_VERSION     = 1
WIRE_PAYLOAD_SIZE = 109
```

Layout สำคัญ:

```text
0..3      magic
4..5      version
6..7      struct_size
8..15     event_id
16..23    timestamp_ms
24..31    monotonic_ns
32        source
33..36    source_ip
37..38    source_port
39..42    dest_ip
43..44    dest_port
45..52    session_id
53..56    protocol/direction/layer/is_pipe
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

ต้องตรวจความขัดแย้งต่อไปนี้ก่อน enforcement:

- Go `TypeForward` และ Zig `EventType.forward`
- Go `ActionLogOnly=5` กับ PolicyAction table
- Go `DefaultDevStructSize=128` กับ Zig `EVENT_SCHEMA_SIZE`
- Go comment ที่อ้าง SHA-256 แต่ implementation ใช้ FNV-1a
- `monotonic_ns` ที่บาง path ใช้ wall-clock nano timestamp
- IPv6 ที่เก็บเพียง 4 bytes แรก

ห้ามแก้ enum แบบเฉพาะไฟล์เดียว ต้องแก้ authoritative contract และ regenerate/test ทุกภาษา

## 6. Zig runtime และ lifecycle

Zig daemon เป็น runtime owner ต้องเป็นผู้เดียวที่ถือ:

- worker handles
- stop signal
- join order
- readiness
- restart generation
- control authority

Startup ที่ถูกต้อง:

```text
STOPPED
  -> STARTING
  -> worker initialization
  -> readiness barrier
  -> READY/RUNNING/DEGRADED
```

Shutdown ที่ต้องบังคับ:

```text
RUNNING/DEGRADED
  -> STOPPING
  -> stop acquisition
  -> reject new ingress
  -> wait producers
  -> drain accepted queue
  -> finish processing
  -> flush forensic/audit
  -> teardown adapters
  -> join workers
  -> STOPPED
```

ห้ามตอบ `STOPPED` ก่อน worker join และ postconditions สำเร็จ

จุดที่ source ต้องแก้ต่อ:

- `transition()` ต้อง enforce `canTransition`
- `daemon.shutdown` ต้องเป็น transaction ไม่ใช่ set state แล้วตอบทันที
- queue ต้องมี close/drain semantics
- `g_stop_requested` ต้อง reset ตาม generation ถ้ามี restart ใน process เดียว
- counters ที่ข้าม thread ต้องเป็น atomic หรือ consistent snapshot
- health/status ต้อง copy snapshot ก่อนปล่อย mutex

## 7. Queue และ processing

Queue เป็น bounded queue ที่ copy event เข้า storage ซึ่งดีด้าน ownership แต่ต้องมี conservation invariant:

```text
submitted = accepted + rejected + capacity_dropped + lifecycle_dropped
```

เมื่อ event accepted แล้ว ต้องมี terminal outcome อย่างใดอย่างหนึ่ง:

```text
processed
or
explicitly dropped with reason
```

ไม่ควรมี accepted event ที่หายเงียบตอน shutdown

การแปลง CanonicalEvent เป็น IpcEvent ต้องตรวจว่ามี raw payload bytes เพียงพอสำหรับ detection หรือไม่ ปัจจุบันบาง path เก็บเพียง `payload_length` และ `payload_hash` ทำให้ payload-based detection อาจทำงานไม่ได้ตามที่ operator คาด

## 8. Detection, policy และ PEP

ลำดับบังคับ:

```text
DetectionResult
  -> PolicyDecision
  -> PepRequest
  -> Rust PEP
  -> WFP adapter
  -> EnforcementReceipt
```

Rust PEP เป็นผู้เดียวที่อนุญาต privileged action ต้องตรวจ:

- action enum
- policy signature
- policy version/hash
- expiry/TTL
- caller capability
- request freshness
- nonce/replay
- two-person rule เมื่อจำเป็น
- WFP availability
- host effect result

`ALLOW` หรือ `BLOCK decision` ไม่ใช่ host effect proof

Receipt ที่ต้องมี:

```text
request_id
trace_id
event_id
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
audit_id
```

สถานะต้องแยก:

```text
AUTHORIZED
SUBMITTED
ENFORCED
UNAVAILABLE
FAILED
DEFERRED
ESCALATED
```

## 9. Forensic

Forensic ring ให้ integrity ของ retained records แต่ยังเป็น bounded in-memory storage

ต้องแยก metric:

```text
retained
exported
overwritten
lost_before_accept
lost_after_accept
append_failed
```

ทุก accepted event ต้องมี forensic identity เดียว และ append ต้อง idempotent ด้วย event identity ไม่ใช่เพียง record sequence

ต้องผูก:

```text
event_id
trace_id
audit_id
policy_id/version/hash
pep_request_id
enforcement_id
host_effect result
```

## 10. Mouth

Mouth เป็น operator surface ไม่ใช่ enforcement authority

Mouth ควรอ่าน health/receipt จาก canonical runtime interface และแสดง:

```text
RUNNING
DEGRADED
WAITING_FOR_INGRESS
DECISION_ONLY
ENFORCED
FAILED
```

ต้องไม่ตีความ raw log `BLOCKED` เป็น host effect โดยไม่มี receipt

สิ่งที่ต้องแก้ใน Mouth:

- version 1.0.0/3.0.0 ให้ตรงกัน
- health counters ต้อง update จริง
- ตรวจ core dependency จริง
- JSON parser ต้องไม่ใช้ substring parsing เป็นหลัก
- รองรับ log rotation
- input/output path ต้องไม่ชนกัน
- graceful shutdown และ health thread join
- sanitize ANSI/control characters
- แยก PID กับ source IP ใน mitigation display

## 11. คำสั่งตรวจ runtime บน Windows

เปิด PowerShell ใหม่และรันจาก project root:

```powershell
Set-Location D:\NIDs_Windows
python tools\aegisctl.py health
python tools\aegisctl.py metrics
python tools\aegisctl.py authority
python tools\aegisctl.py forensics verify
python tools\aegisctl.py readiness
```

ตรวจ Go Nose:

```powershell
Set-Location D:\NIDs_Windows\nose
go test ./...
..\dist\aegis-nose.exe -capture-self-test
..\dist\aegis-nose.exe -list-devices
```

เริ่ม live capture จาก root เพื่อให้ Rules path ถูกต้อง:

```powershell
Set-Location D:\NIDs_Windows
.\dist\aegis-nose.exe -capture -pipe \\.\pipe\aegis_nose
```

หลักฐานที่ต้องดู:

```text
[NOSE RULES] loaded=22
[NOSE PIPE] connected
first canonical frame sent: 113 bytes
```

แล้วตรวจ health ขณะ Nose ยังทำงานอยู่ จากอีกหน้าต่างหนึ่ง:

```powershell
python tools\aegisctl.py health
python tools\aegisctl.py metrics
```

คาดหวัง:

```text
nose_connected = true
nose_frames_read > 0
nose_frames_submitted > 0
nose_frames_rejected = 0
nose_frames_dropped = 0
nose_pipe_errors = 0
```

เมื่อกด `Ctrl+C` ที่ Nose แล้ว `nose_connected=false` เป็นค่าที่ถูกต้อง แต่ counters ต้องคงค่าที่เคยรับไว้

## 12. ลำดับ phase หลังจากนี้

### Phase A — Truth

Rebuild inventory/reference/maps จาก current HEAD แล้วได้ `TRUTH_VALID`

### Phase B — ABI

แก้ canonical decoder, enum, struct-size, hash, timestamp และ cross-language vectors

### Phase C — Identity

กำหนด global identity/epoch และ duplicate/collision policy

### Phase D — Ingress convergence

ให้ Nose และ sensor paths ผ่าน ingress authority เดียว พร้อม counters conservation

### Phase E — Detection/policy

ทำ DetectionResult และ PolicyDecision deterministic พร้อม trace linkage

### Phase F — PEP/WFP

ทำ ABI ปัจจุบันให้ตรง, signature/freshness/replay checks, receipt และ host effect proof

### Phase G — Forensic

ทำ idempotent append, durable export, evidence completeness และ shutdown flush

### Phase H — Mouth

เชื่อม receipt/health จริง และลบ enforcement semantics ที่สรุปจาก log เพียงอย่างเดียว

### Phase I — Lifecycle

ทำ stop/drain/flush/join/restart generation และ Windows service acceptance

### Phase J — Release

รัน full test suite, Windows host E2E, truth rebuild และ release artifact verification

## 13. Stop-the-line conditions

หยุดการพัฒนา feature ใหม่ทันทีเมื่อพบ:

- ABI mismatch
- enum semantic mismatch
- event identity collision
- silent event loss
- queue accepted event หาย
- duplicate PEP side effect
- enforcement bypass
- WFP success ที่ไม่มี host proof
- unauthorized control pipe access
- state RUNNING/STOPPED ที่ไม่ตรง runtime
- stale truth maps
- mock หรือ fixture ถูกนำเสนอเป็น production proof

## 14. สถานะเอกสารและไฟล์สำคัญ

เอกสาร system-wide:

```text
AEGIS_SYSTEM_WIDE_RUNTIME_FLOW_2026-09-18.md
```

เอกสาร handoff นี้:

```text
AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md
```

ไฟล์ source สำคัญ:

```text
src/daemon.zig
src/control/state_machine.zig
src/control/handler_registry.zig
src/capture/nose_pipe_reader.zig
src/contract/canonical_event.zig
src/pipeline/event_queue.zig
src/pipeline/event_processor.zig
src/pipeline/runtime_state.zig
nose/main.go
nose/capture.go
nose/pipe_writer.go
nose/canonical.go
nose/golden_path_ffi.go
rust-src/lib.rs
mouth/windows_sec_monitor.rs
tools/aegisctl.py
tools/aegisctl/api/control_api.py
```

## 15. คำสั่งเริ่มงานใน session ใหม่

เมื่อเริ่ม session ใหม่ ให้ทำตามลำดับ:

1. อ่านเอกสารนี้ทั้งฉบับ
2. อ่าน `AEGIS_SYSTEM_WIDE_RUNTIME_FLOW_2026-09-18.md`
3. ตรวจ `git rev-parse HEAD`
4. ตรวจ source files ที่ระบุในหัวข้อ 14
5. ห้ามเชื่อ machine maps หาก SHA ไม่ตรง current HEAD
6. รัน targeted tests ก่อนแก้ source
7. แก้ทีละ vertical slice
8. รัน test หลังทุก patch
9. เก็บ command, output, commit และ evidence ID ลง report
10. ห้ามประกาศ production-ready จน PEP/WFP host effect และ graceful shutdown ผ่าน

## สถานะ handoff ล่าสุด

รอบนี้ได้แก้ `nose/golden_path_ffi.go` ให้ตรวจ header และอ่าน EventID จาก offset 8 อย่างถูกต้อง โดยยังไม่เปลี่ยน wire format และยังไม่ได้ประกาศ enforcement สำเร็จ

งานถัดไปที่ควรเริ่มคือ:

```text
1. รัน go test ./... บน Windows
2. เพิ่ม/ยืนยัน negative golden vectors
3. ออกแบบ event identity epoch
4. แก้ ingress accounting
5. ทำ controlled detection fixture
6. ทำ PEP receipt proof
7. เชื่อม Mouth แบบ read-only receipt consumer
```

> เป้าหมายของการพัฒนาต่อไม่ใช่เพิ่ม component ให้มากขึ้น แต่คือทำให้มี **event authority เดียว, runtime owner เดียว, enforcement authority เดียว และ evidence path ที่ตรวจสอบซ้ำได้**


## Addendum: แพตช์ event identity ล่าสุด

รอบถัดมาพบว่า `nose_non_monotonic_event_ids=3` เกิดหลัง Nose ถูกเริ่มใหม่หลายครั้ง ขณะที่ `nose_last_event_id` ของ Zig ยังเป็นค่าจาก process รุ่นก่อน Go Nose จึงเริ่ม sequence ใหม่จาก 1 แล้วถูกนำไปเปรียบเทียบกับ sequence รุ่นเก่า

แพตช์ล่าสุดแก้ที่:

```text
src/capture/nose_pipe_reader.zig
```

การเปลี่ยนแปลงคือ:

- เริ่ม `previous_connection_event_id` ใหม่เมื่อมี client connection ใหม่
- ตรวจ duplicate ภายใน connection เดียว
- ตรวจ non-monotonic ภายใน connection เดียว
- คง `g_last_event_id` เป็นค่า latest runtime observation สำหรับ health/forensic
- ไม่ลบหรือ reset counters สะสม
- ระบุชัดว่า cross-generation identity continuity ยังต้องแก้ด้วย epoch หรือ durable identity contract

เหตุผลเชิง semantics:

```text
same Nose connection + event ID regression = real ordering defect
new Nose connection + sequence restart = generation boundary, not proof of same-stream regression
```

แพตช์นี้ไม่อ้างว่า exactly-once ข้าม process สำเร็จแล้ว เพราะยังไม่มี producer epoch, durable counter หรือ collision ledger ดังนั้น acceptance gate ที่เหลือคือการเพิ่ม identity contract ข้าม generation และตรวจ duplicate/collision หลัง reconnect อย่างเป็นทางการ

ต้องทดสอบบน Windows หลัง rebuild daemon:

```powershell
Set-Location D:\NIDs_Windows
zig build
```

จากนั้นเริ่ม daemon รุ่นใหม่และทำ Nose capture เพียงหนึ่ง connection ต่อรอบ:

```powershell
.\dist\aegis-nose.exe -capture -pipe \\.\pipe\aegis_nose
```

ตรวจขณะ Nose ยังทำงาน:

```powershell
python tools\aegisctl.py health
python tools\aegisctl.py metrics
```

เกณฑ์รอบนี้:

```text
nose_connected=true ขณะ Nose ทำงาน
nose_connected=false หลังหยุด Nose
nose_frames_read > 0
nose_frames_rejected=0
nose_frames_dropped=0
nose_pipe_errors=0
non_monotonic ไม่เพิ่มจาก reconnect เพียงอย่างเดียว
```

หากต้องการพิสูจน์ identity ข้าม restart ต้องทำ test เฉพาะที่ส่ง sequence เดิม/ชนกันจาก producer epoch ต่างกัน และตรวจ collision policy ไม่ใช่ใช้ counter อย่างเดียว


## Addendum: ABI boundary hardening ล่าสุด

แพตช์ถัดมาแก้ที่:

```text
src/contract/canonical_event.zig
```

ก่อน `@enumFromInt` ใน `deserializeFromBytes` มีการตรวจค่าจาก wire frame ซึ่งเป็น untrusted input:

- EventSource ต้องอยู่ในค่าที่ประกาศ 0..16 หรือ 255
- EventType ต้องอยู่ในค่าที่ประกาศ 0..9 หรือ custom `0xFFFFFFFF`
- PolicyAction ต้องอยู่ในค่าที่ประกาศ 0..5
- confidence ต้องไม่เกิน 100

เพิ่ม negative tests สำหรับ unknown source, event type, policy action และ confidence >100 เพื่อให้ malformed frame ถูก reject ก่อนสร้าง semantic event

แพตช์นี้ยังไม่เปลี่ยน wire layout และยังไม่ตัดสิน policy/enforcement เป็นเพียง boundary validation

ต้องรันหลัง rebuild:

```powershell
Set-Location D:\NIDs_Windows
zig build test
```

หาก build.zig ของ environment ไม่รองรับ subcommand นี้ ให้ใช้คำสั่ง test ที่ repository กำหนดไว้ใน `zig build -h` หรือรันชุด unit test เดิมของโครงการ แล้วเก็บ stderr/stdout เป็น evidence


## Addendum: ผลทดสอบ ABI hardening บน Windows

ผลจากไฟล์แนบล่าสุด:

```text
zig build test             ผ่าน
Go test ./...              ผ่าน (cached)
Nose capture self-test     ผ่าน: 109 bytes, magic 0x41454731
```

คำสั่ง `zig build` ล้มเหลวเฉพาะขั้น install:

```text
AccessDenied: unable to update ... zig-out\\bin\\aegis_nids.exe
```

สาเหตุคือ executable รุ่นเก่ายังถูก daemon PID 16648 เปิดใช้งานอยู่ ทำให้ Windows ล็อกไฟล์ ไม่ใช่ compile error และไม่ใช่ ABI test failure

ขั้นตอน rebuild ที่ถูกต้อง:

1. หยุด Nose ถ้ายังทำงานอยู่ด้วย `Ctrl+C`
2. หยุด daemon จาก console owner เดิมด้วยวิธี graceful shutdown ที่ project ใช้ หรือปิด process owner อย่างปกติ
3. ตรวจว่า `aegis_nids.exe` ไม่ถูกใช้งานแล้ว
4. รัน:

```powershell
Set-Location D:\NIDs_Windows
zig build
```

5. เริ่ม daemon binary รุ่นใหม่
6. รัน health/metrics และ Nose capture ใหม่

ไม่ควรใช้ `taskkill /F` เป็นขั้นตอนปกติ เพราะจะข้าม shutdown transaction และอาจทำให้ queue/forensic flush ไม่ครบ ใช้ force termination เฉพาะกรณี process ค้างและบันทึกเป็น recovery evidence


## Addendum: หลัง build ใหม่สำเร็จ

`zig build` ผ่านแล้ว หลังหยุด process รุ่นเก่าที่ล็อก executable ไว้

ผล `aegisctl` ทันทีหลัง build:

```text
State: DEGRADED
component: control_api
runtime_available: false
availability_error: control daemon unavailable; subsystem data is diagnostic only
```

ผลนี้เป็น **diagnostic-unavailable state ที่ถูกต้อง** ไม่ใช่ daemon degradation เพราะ daemon รุ่นใหม่ยังไม่ได้เริ่มทำงาน คำสั่ง `metrics.snapshot` และ `forensics.verify` จึง query control pipe ไม่ได้ตามที่ควรเป็น

ขั้นถัดไปคือเริ่ม daemon รุ่นใหม่ด้วย `zig build run` หรือ executable ที่ build.zig กำหนด จาก console แยก แล้วตรวจ health ขณะ process ยังทำงานอยู่


## Addendum: policy severity alignment

ตรวจพบว่า policy ใช้ internal `event.EventSeverity` ไม่ใช่ค่า canonical 0..3 โดย mapping ใน `pushCanonicalEvent` คือ:

```text
Canonical 0 -> internal info=2
Canonical 1 -> internal warning=4
Canonical 2 -> internal critical=6
Canonical 3 -> internal alert=7
```

policy `alert_high_severity` เดิมใช้ `severity == 5` ซึ่งคือ internal `error` และไม่ตรงกับ High ที่ถูก map เป็น `warning=4` จึงแก้:

```text
configs/policies.json
severity eq 5 -> severity eq 4
```

policy Critical `severity >= 6` ไม่ได้เปลี่ยน และยังไม่เพิ่ม rule ที่ทำให้เกิด WFP block ใหม่

ข้อควรระวังสำหรับ Controlled Detection Proof:

- `aegisctl simulate` intentionally returns unavailable และไม่ควรถูกใช้เป็น proof
- `scripts/aegis_event_gen.py --pipe` ส่งเข้า legacy `aegis_sensor_pipe` ไม่ใช่ canonical `aegis_nose`
- canonical Nose path ส่ง 109-byte event และ `pushCanonicalEvent` คง `rule_id`, `event_type`, severity และ event identity แต่ยังไม่ส่ง raw payload bytes เข้า queue
- ดังนั้น controlled fixture ที่พิสูจน์ canonical path ต้องสร้างผ่าน Go Nose `FrameWriter` หรือ live packet capture และต้องบันทึก transport อย่างชัดเจน
- policy/enforcement simulation handlers ที่คืน JSON คงที่เป็น structural fixture ไม่ใช่ host-level proof


## Addendum: Go injector test session

เพิ่มไฟล์ canonical observe-only injector:

```text
nose/inject.go
```

ใช้ `FrameWriter` เดียวกับ live Nose และส่ง event ที่:

```text
EventType = forward
Severity = canonical 1
RuleID = 0
PolicyAction = log_only
```

จึงเป็น fixture สำหรับ alert-only/observe-only path ไม่ใช่ block fixture

การรัน `gofmt -w inject.go && go test ./...` รอบแรกไม่มี outputนานและถูกหยุดหลัง timeout เพื่อป้องกัน process ค้าง การรันซ้ำทำไม่ได้จาก agent เพราะ Windows terminal pipe ถูกปิดแล้ว

ให้รันใน PowerShell ใหม่ด้วย timeout ของ Go:

```powershell
Set-Location D:\NIDs_Windows\nose
gofmt -w inject.go
go test ./... -timeout 30s
```

หาก test timeout ให้เก็บ stack trace จาก Go แล้วแยกว่าเป็น test เดิมที่ค้างหรือ compile error ของ injector ห้ามใช้ผล timeout เป็น test pass


### CLI entrypoint ของ observe-only injector

เพิ่ม flag ใน `nose/main.go`:

```text
-inject-observe
-inject-count N
```

คำสั่งนี้ใช้ `FrameWriter` เดียวกับ `-capture` และส่งไปยัง default canonical pipe `\\.\\pipe\\aegis_nose` จึงไม่ใช้ legacy sensor pipe

ตัวอย่าง:

```powershell
Set-Location D:\NIDs_Windows\nose
.\aegis-nose.exe -inject-observe -inject-count 1 -pipe \\.\pipe\aegis_nose
```

หรือจาก project root:

```powershell
.\dist\aegis-nose.exe -inject-observe -inject-count 1 -pipe \\.\pipe\aegis_nose
```

คาดหวัง:

```text
[NOSE PIPE] connected to \\.\pipe\aegis_nose
[NOSE PIPE] first canonical frame sent: 113 bytes event_id=...
[NOSE INJECT] observe-only sent=1 dropped=0 count=1
```

หลังส่ง event ให้ตรวจ metrics/forensic โดยเปรียบเทียบค่าก่อนและหลัง:

```text
packets_captured เพิ่ม 1
 events_processed เพิ่ม 1
forensic_records เพิ่ม 1
errors ไม่เพิ่ม
blocks ไม่เพิ่มจาก fixture นี้
```

จากนั้นตรวจ `logs/aegis_core.ndjson` ด้วย `aegisctl events tail --count 20 --json` เพื่อหา `event_id` เดียวกันตั้งแต่ audit ถึง forensic หาก runtime ไม่เพิ่ม detection/policy matched ให้บันทึกเป็น defect ของ internal mapping ไม่ใช่ประกาศ Golden Path ผ่าน


## Addendum: automated controlled proof runner

เพิ่มสคริปต์:

```text
scripts/run_controlled_proof.ps1
```

หน้าที่ของสคริปต์:

1. ตรวจ health และ worker readiness ก่อนเริ่ม
2. ตรวจ forensic hash chain ก่อนส่ง event
3. เรียก `dist\\aegis-nose.exe -inject-observe` ผ่าน canonical `aegis_nose` pipe
4. ตรวจ metrics และ forensic หลังส่ง
5. คำนวณ delta และคืน exit code 1 หาก event ไม่ถูก process/forensic หรือมี block/error เพิ่ม

สคริปต์เป็น fail-closed และไม่สามารถรายงาน pass เมื่อ control daemon unavailable

คำสั่งหลัก:

```powershell
Set-Location D:\NIDs_Windows
.\scripts\run_controlled_proof.ps1 -Count 1
```

Acceptance:

```text
events_processed delta >= requested
forensic_records delta >= requested
forensic.verified = true
blocks delta = 0
errors delta = 0
```


## Addendum: proof runner PowerShell argument bug

ผลรัน `run_controlled_proof.ps1` ครั้งแรกหยุดที่ขั้น health และแสดง `aegisctl` help ด้วย exit code 2

Root cause:

```powershell
function Invoke-AegisJson([string[]]$Args)
```

ชื่อ `$Args` ชนกับ automatic variable ของ PowerShell ทำให้ splatting `@Args` ไม่ส่ง CLI arguments ตามที่ตั้งใจ

แก้เป็น:

```powershell
function Invoke-AegisJson([string[]]$CliArgs)
$raw = & python tools\\aegisctl.py @CliArgs 2>&1
```

ผลครั้งแรกจึงยังไม่ใช่ daemon failure และยังไม่ได้เริ่ม canonical injection


## Acceptance Record: Controlled Canonical Ingress Proof passed

วันที่รัน: 2026-09-18

ผลจาก `scripts\\run_controlled_proof.ps1 -Count 1`:

```text
[NOSE PIPE] connected to \\.\\pipe\\aegis_nose
[NOSE PIPE] first canonical frame sent: 113 bytes event_id=1
[NOSE INJECT] observe-only sent=1 dropped=0 count=1
```

Proof result:

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

ความหมาย: canonical Go Nose serializer/FrameWriter, `aegis_nose` named pipe, Zig reader, queue/pipeline processing และ forensic append/hash-chain verification ผ่านในรอบนี้ โดยไม่มี block หรือ error เพิ่ม

ขอบเขตที่ยังไม่ถูกพิสูจน์ด้วย fixture นี้: fixture เป็น `forward`, `RuleID=0`, `log_only`; จึงไม่ได้พิสูจน์ signature detection, policy match, Rust PEP decision/receipt หรือ WFP host effect. ขั้นต่อไปต้องใช้แยก fixture สำหรับ detection+alert policy และห้ามใช้ block fixture จนกว่าจะมี observe-only enforcement receipt ที่ตรวจ postcondition ได้
