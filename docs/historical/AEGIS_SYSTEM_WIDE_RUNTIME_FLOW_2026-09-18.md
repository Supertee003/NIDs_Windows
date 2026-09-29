# AEGIS System-Wide Runtime Flow

วันที่วิเคราะห์: 2026-09-18  
ขอบเขต: Nose, Zig runtime, event queue, detection, policy, Rust PEP, WFP, forensic และ Mouth

## บทสรุป

ใช่ครับ **Nose ถูกออกแบบให้เป็น front door ของ data plane** หรือด่านหน้าที่รับข้อมูลจาก network และส่งต่อเป็น `CanonicalEvent` ไปยัง Zig runtime Nose ไม่ควรเป็นผู้ตัดสิน policy ไม่ควรเรียก WFP และไม่ควรประกาศว่า enforcement สำเร็จ

ภาพที่ถูกต้องของระบบคือ:

```text
Npcap / sensors
    -> Nose acquisition
    -> CanonicalEvent wire frame
    -> named pipe
    -> Zig ingress reader
    -> bounded event queue
    -> detection
    -> policy evaluation
    -> Rust PEP
    -> WFP host effect
    -> EnforcementReceipt
    -> forensic evidence
    -> Mouth/operator feedback
```

อย่างไรก็ตาม source ปัจจุบันยังมีหลาย path ที่ต้องทำให้เป็นหนึ่งเดียว ได้แก่ event identity หลายตัว, `CanonicalEvent` 109 bytes กับ `IpcEvent` 96 bytes, Go Nose pipe ที่ bypass Event Fabric, forensic append ที่มีความเสี่ยงซ้ำ และ Mouth ที่อ่าน log แล้วสรุป DEFCON แทนการรับ receipt โดยตรง

## 1. บทบาทของแต่ละส่วน

| ส่วนประกอบ | บทบาทที่ถูกต้อง | สิ่งที่ไม่ควรทำ |
|---|---|---|
| Nose | รับ packet, สร้าง canonical event, ส่ง ingress frame | ตัดสิน policy หรือบังคับใช้ |
| Zig runtime | เป็น runtime owner, รับเข้า queue, จัด lifecycle, ประสาน detection/policy/forensic | เปิด authority enforcement ซ้ำ |
| Event queue | เก็บ event แบบ bounded และกำหนด drop accounting | ซ่อน event loss |
| Detection | วิเคราะห์ event และสร้าง detection result | เรียก WFP โดยตรง |
| Policy | ประเมิน rule/policy และสร้าง decision request | เปลี่ยน host state เอง |
| Rust PEP | เป็น final enforcement authority | ให้ caller ข้าม signature/freshness/receipt |
| WFP adapter | ทำ host effect และคืนผลจาก driver | ประกาศ success จาก intent |
| Forensic | เก็บ evidence, trace, hash chain และผลลัพธ์ | อ้าง ring memory ว่าเป็น history ถาวร |
| Mouth | แสดงสถานะ, receipt, alert และ operator feedback | สร้าง decision หรือบังคับใช้เอง |

## 2. การทำงานของ Nose

Nose มีโหมด capture ที่อ่าน packet จาก Npcap ด้วย `pcap.OpenLive` แบบ passive และ filter `ip or ip6` จากนั้น `eventFromPacket` แปลงข้อมูลเป็น `CanonicalEvent` ซึ่งมี event ID, timestamp, source, IP, ports, protocol, payload length และ payload hash

`FrameWriter` serialize payload เป็น 109 bytes แล้วเติม length prefix แบบ little-endian 4 bytes ดังนั้น frame ที่ส่งจริงมี 113 bytes:

```text
4-byte payload length + 109-byte CanonicalEvent
```

Nose มีหน้าที่ด้าน acquisition เท่านั้น การที่ Nose โหลด rules เพื่อจำแนก packet เป็น event type หรือ severity ยังต้องไม่ถูกตีความว่าเป็น policy enforcement

### จุดแข็งที่พิสูจน์ได้

จาก runtime acceptance ที่ผ่านมา Nose สามารถ:

- เชื่อม `\\.\pipe\aegis_nose` ได้
- ส่ง frame มากกว่า 3,000 frames
- ส่งโดยไม่มี pipe error, drop หรือ reject
- โหลด Rules.json ได้เมื่อเริ่มจาก project root
- ผ่าน self-test ของ 109-byte wire format

### จุดเสี่ยงของ Nose

ปัจจุบัน `eventSequence` เป็น process-local counter และ reset เมื่อ Nose restart ดังนั้น event ID อาจย้อนจาก 693 กลับไป 1 ทำให้ `non_monotonic_event_ids` เพิ่มขึ้น แม้ duplicate counter ยังเป็นศูนย์

นอกจากนี้ ABI ยังมีความเสี่ยงจาก enum และ parser ที่ไม่ตรงกัน เช่น `TypeForward` กับ `EventForward` ใช้ค่าไม่สอดคล้องกัน และ `ActionLogOnly=5` อยู่นอก enum หลักที่ประกาศไว้ ต้องมี authoritative table เดียวสำหรับทุกภาษา

การ serialize ยังมีข้อจำกัดด้าน IPv6 เพราะเก็บเพียง 4 bytes แรกของ address และใช้ FNV-1a ใน `quickHash` ขณะที่ comment อ้าง SHA-256 prefix ต้องกำหนดสัญญาให้ตรงกัน

## 3. Zig ingress และ event queue

Zig reader รับ length-prefixed frame, ตรวจขนาด, deserialize และส่งเข้า bounded queue ปัจจุบัน runtime รับข้อมูลจริงได้แล้ว เพราะ health แสดง `nose_frames_read` และ `nose_frames_submitted` เพิ่มขึ้นโดยไม่มี reject หรือ pipe error

อย่างไรก็ตาม canonical Nose path ยัง bypass Event Fabric facade และส่งเข้า queue โดยตรง ส่วน queue แปลง 109-byte `CanonicalEvent` เป็น `IpcEvent` 96 bytes ขณะเดียวกันระบบยังมี ingress อื่น เช่น ETW, FIM, Registry และ legacy sensor ที่มี event identity counter ของตนเอง

นี่ทำให้ระบบมีปัญหาเชิงสถาปัตยกรรม:

```text
หลาย ingress
หลาย event model
หลาย identity issuer
หลาย counter
```

แม้ data path จะทำงาน แต่ยังไม่ใช่ single authoritative event fabric

Queue เป็น bounded queue และ copy event เข้า storage ของตนเอง ซึ่งดีต่อ ownership แต่เมื่อเต็มจะ drop event และเมื่อ shutdown จะหยุดโดยไม่ drain queue อย่างเป็นทางการ ต้องแยกให้ชัดว่า event ใด accepted, rejected, capacity-dropped และ lifecycle-dropped

## 4. Detection และ policy

หลัง queue consumer จะทำ flow lookup, detection, threat tracking และ policy evaluation จากนั้นสร้าง decision trace และส่ง request ต่อไปยัง Rust PEP

ลำดับที่ควรเป็น:

```text
CanonicalEvent
    -> DetectionResult
    -> PolicyDecision
    -> PepRequest
```

แต่ source ปัจจุบันมีข้อจำกัดสำคัญ: `pushCanonicalEvent` คง payload length และ hash แต่ไม่ได้ส่ง raw payload bytes เข้า queue ดังนั้น detection ที่ต้องตรวจ payload จริงอาจเห็นเพียง metadata ไม่ใช่เนื้อหา packet

นอกจากนี้ policy schema ยังมี drift ระหว่าง TypeScript, Zig, Rust และเอกสาร เช่น ordinal ของ `BLOCK` ไม่ตรงกัน ต้องหยุดการทดสอบ enforcement จนกว่าจะรวม schema และ enum เป็นชุดเดียว

## 5. Rust PEP และ WFP

Rust PEP ควรเป็น authority เดียวสำหรับ privileged enforcement โดยตรวจ:

- policy signature
- policy version และ expiry
- caller capability
- request freshness และ nonce
- replay protection
- decision taxonomy
- WFP adapter availability
- host effect result

ปัจจุบัน source มีแนวคิด fail-closed และ capability checks บางส่วน แต่ยังมีช่องว่างที่ต้องแก้ก่อน production ได้แก่ PEP ยังไม่ผูก signature verification, TTL และ replay protection เข้ากับทุก enforcement request อย่างชัดเจน และ `PepResponse` ยังไม่ใช่ `EnforcementReceipt` ที่พิสูจน์ host effect ได้ครบ

Receipt ที่ production ต้องมีอย่างน้อย:

```text
request_id
trace_id / event_id
policy_id / policy_version / policy_hash
requested_action
pep_decision
status
provider
filter_id
host_effect_confirmed
timestamp
failure or deferred reason
audit_id
```

คำว่า `BLOCKED` ใน log หรือ decision ไม่เท่ากับ host effect สำเร็จ ต้องมี filter ID หรือผลยืนยันจาก WFP driver

## 6. Forensic evidence

Forensic ring มีข้อดีด้าน CRC, SHA-256 hash chain, mutex และ snapshot copy แต่เป็น bounded in-memory ring จึงพิสูจน์ integrity ได้เฉพาะ records ที่ยังคงอยู่ ไม่ใช่ complete durable history

ปัจจุบันยังต้องแก้:

- event identity ไม่ durable ข้าม process restart
- `record_seq` เริ่มใหม่เมื่อ daemon restart
- ring overwrite ทำให้ evidence เก่าหาย
- shutdown ยังไม่ drain queue และ flush/export evidence ให้ครบ
- processor และ ActionDispatcher อาจมี output path ที่ทำให้ record ซ้ำ
- SecurityDecisionTrace ยังไม่ได้ผูกเข้า forensic record อย่างครบถ้วน

ดังนั้นผล `verified=true` หมายถึง hash chain ของข้อมูลที่ retained ถูกต้อง ไม่ได้หมายความว่าไม่มี event สูญหายหรือไม่มี record ซ้ำ

## 7. Mouth และ operator feedback

Mouth ปัจจุบันอ่าน log แบบ tail, สะสม alert, คำนวณ DEFCON, แสดง dashboard และเขียน `enforced.json` เมื่อระดับเปลี่ยน มี health pipe แยกชื่อ `\\.\pipe\aegis-mouth-health`

บทบาทนี้เหมาะกับ operator surface แต่ยังไม่ควรถือเป็น enforcement implementation เพราะ Mouth ไม่ควรสรุป host effect จากข้อความ log เอง

Mouth ควรรับข้อมูลจาก canonical runtime หรือ receipt stream และแสดงสถานะแยกกัน:

```text
DECISION_REQUESTED
DECISION_ALLOW / BLOCK / QUARANTINE
ENFORCEMENT_SUBMITTED
HOST_EFFECT_CONFIRMED
ENFORCEMENT_FAILED
ENFORCEMENT_DEFERRED
```

จุดเสี่ยงของ Mouth ที่ต้องแก้ ได้แก่ health response ที่ hard-code `RUNNING/OK`, counters ที่ไม่ถูก update, log rotation ที่ไม่ถูกตรวจ, parser แบบ substring, output path ที่อาจชนกับ input log และไม่มี graceful shutdown

## 8. เหตุผลของค่าที่พบใน runtime

### `nose_connected=false` ทั้งที่รับ frame ได้

นี่เป็น health semantics bug ไม่ใช่ pipe failure เพราะ `nose_frames_read` และ `nose_frames_submitted` เพิ่มขึ้นจริง ควรแยก:

```json
{
  "nose_listener_ready": true,
  "nose_connected": true,
  "nose_first_frame_seen": true
}
```

### `nose_non_monotonic_event_ids` เพิ่มขึ้น

เกิดจาก Nose restart แล้ว process-local `eventSequence` เริ่มใหม่จาก 1 ขณะที่ Zig ยังจำ event ID จากรอบก่อน วิธีแก้ที่ถูกต้องคือใช้ runtime-issued identity หรือ compound identity ที่มี `producer_epoch`/`runtime_generation` ไม่ใช่ซ่อน counter

### `events_processed` มากกว่า `nose_frames_read`

เป็นไปได้เพราะ events processed รวม ETW/FIM/Registry หรือ ingress อื่น จึงต้องเพิ่ม per-source counters เพื่อยืนยัน Nose-only Golden Path

## 9. Canonical runtime flow ที่ควรบังคับ

```text
[1] Npcap / sensor
    - packet acquisition only

[2] Nose
    - validate packet
    - create CanonicalEvent
    - preserve producer metadata

[3] Ingress authority
    - validate ABI/header/enum
    - assign or validate global identity
    - deduplicate/collision-check
    - account accepted/rejected/dropped

[4] Queue
    - bounded copy
    - explicit backpressure and drop reason

[5] Detection
    - create deterministic DetectionResult

[6] Policy
    - verify policy version/signature
    - create PolicyDecision

[7] Rust PEP
    - authorize privileged action
    - call WFP adapter
    - produce EnforcementReceipt

[8] Forensics
    - append one idempotent evidence record
    - link event, trace, policy, PEP and host effect

[9] Mouth
    - display receipt and health
    - send operator request through Zig control plane
```

## 10. ลำดับแก้ไขที่ปลอดภัย

### Gate 1: ABI และ identity

รวม enum, magic, schema version, struct size และ offsets ให้เป็น authoritative contract เดียว แก้ event identity ให้ไม่ reset และเพิ่ม duplicate/collision policy

### Gate 2: Ingress accounting

ให้ Nose path ผ่าน ingress facade เดียว เพิ่ม counters ที่ reconcile ได้:

```text
frames_read
frames_validated
frames_rejected
frames_accepted
frames_dropped
duplicates
collisions
```

### Gate 3: Detection/policy

ส่ง payload ตาม contract ที่ detection ต้องใช้ และสร้าง DetectionResult กับ PolicyDecision ที่ deterministic พร้อม trace ID เดียว

### Gate 4: PEP receipt

ทำให้ Rust PEP ตรวจ signature, freshness, nonce, capability และคืน EnforcementReceipt ที่ผูก WFP filter/host effect ได้จริง

### Gate 5: Forensic durability

เพิ่ม idempotency key, durable export, queue drain และ shutdown flush ไม่เรียก in-memory ring ว่า complete evidence

### Gate 6: Mouth integration

เปลี่ยน Mouth จาก log-derived enforcement display เป็น receipt consumer แยก decision กับ host effect และรายงาน DEGRADED เมื่อ input หรือ output ไม่พร้อม

### Gate 7: Lifecycle

แก้ shutdown เป็น transaction:

```text
stop acquisition
-> reject new ingress
-> wait producers
-> drain accepted queue
-> finish detection/policy/PEP
-> flush forensic/audit
-> teardown WFP/bridges
-> join workers
-> publish STOPPED
```

ห้าม publish `STOPPED` ก่อน postconditions เหล่านี้สำเร็จ

## 11. Acceptance gates

ระบบจะถือว่า Golden Path ผ่านเมื่อ:

- event identity เดิมอยู่ครบตั้งแต่ Nose ถึง forensic
- frame ABI ผ่าน byte-for-byte validation
- accepted event ไม่ถูก process ซ้ำ
- dropped/rejected event ไม่มี PEP side effect
- detection และ policy มี trace ที่ตรวจสอบได้
- privileged action ผ่าน Rust PEP เท่านั้น
- EnforcementReceipt ยืนยัน host effect ได้
- forensic record มี event, trace, policy, PEP และ receipt linkage
- Mouth แสดง receipt เดียวกับ runtime ไม่สร้าง decision เอง
- shutdown drain/flush/join ครบและไม่มี orphan process

## ข้อสรุป

คำตอบคือ **ใช่ครับ Nose เป็นด่านหน้าของระบบตามการออกแบบ** แต่ระบบไม่ได้มีเพียง Nose ตัวเดียว เพราะยังมี ETW, FIM, Registry, legacy pipe และ WFP-related paths ที่อาจสร้าง event ได้ ดังนั้นสิ่งที่ต้องพัฒนาต่อไม่ใช่เพียง “ทำให้ Nose ต่อ pipe ได้” แต่ต้องทำให้ทุก ingress ผ่าน identity, ABI, queue และ accounting authority เดียวกัน

ผล runtime ล่าสุดพิสูจน์แล้วว่าเส้นทาง:

```text
Nose -> named pipe -> Zig -> processing -> forensic
```

ทำงานจริง แต่ยังไม่พิสูจน์:

```text
Detection -> Policy -> Rust PEP -> WFP host effect -> EnforcementReceipt -> Mouth
```

จึงควรพัฒนาต่อโดยล็อก **single event authority, single enforcement authority และ verified evidence path** ก่อนประกาศ production-ready
