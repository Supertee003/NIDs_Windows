# AEGIS Kernel-Mode Detection and Semi-IPS Architecture Report

**วันที่:** 21 กันยายน 2026  
**โครงการ:** AEGIS Windows-native NIDS/IPS  
**วัตถุประสงค์:** ออกแบบการเพิ่ม detection ใน kernel mode ให้ทำงานร่วมกับ Nose, Zig, Rust PEP, WFP และ Mouth โดยรักษา separation of concerns, fail-closed behavior และ production safety

---

## 1. Executive recommendation

AEGIS ควรพัฒนาเป็น **user-mode NIDS ที่มี kernel-mode sensor และ kernel-mode WFP enforcement** ไม่ควรย้าย detection engine ทั้งหมดไปไว้ใน kernel

รูปแบบที่เหมาะสมที่สุดคือ:

```text
Nose                  = front-door packet/event sensor
Kernel sensor         = low-level host/network telemetry and early classification
Zig runtime           = event fabric, lifecycle, correlation, health
Python/Cython         = deep inspection, signatures, enrichment, analytics
TypeScript            = policy authoring, validation, signing, packaging
Rust PEP              = sole enforcement authority
WFP driver            = kernel host-effect provider
Mouth                 = receipt-driven operator/output layer
```

ระบบจะมีลักษณะเป็น:

> **Full-spectrum IDS with semi-IPS behavior:** ตรวจจับได้ทั้ง network path และ host/kernel path แต่การป้องกันจะทำงานเฉพาะเมื่อ Rust PEP อนุมัติและ WFP สร้าง host effect ที่ตรวจสอบได้

คำว่า **semi-IPS** ควรหมายถึงระบบสามารถ block, quarantine หรือ rate-limit เฉพาะ flow ที่ผ่าน policy, capability, receipt และ postcondition ครบ ไม่ใช่การให้ kernel driver ตัดสินใจ block เอง

---

## 2. ตำแหน่งที่เหมาะสมของแต่ละส่วน

### 2.1 Nose: ด้านหน้าและ network ingress

Nose ควรอยู่ด้านหน้าเหมือนเดิม เพราะเหมาะกับงานที่ต้องรับ packet จำนวนมากและทำ normalization:

```text
Npcap / capture source
    -> Go Nose
    -> CanonicalEvent
    -> named pipe
    -> Zig Event Fabric
```

Nose ควรรับผิดชอบ:

- packet capture
- link/network/transport decoding
- flow metadata
- event identity
- canonical serialization
- bounded reconnect/retry
- source interface metadata

Nose ไม่ควรรับผิดชอบ:

- kernel policy mutation
- WFP filter creation
- final block decision
- privileged enforcement
- UI status

### 2.2 Kernel sensor: ขนานกับ Nose ไม่ใช่แทน Nose

Kernel sensor ควรวางเป็น **parallel sensor plane** ไม่ควรวางเป็นขั้นตอนหลัง Nose เพราะ event บางประเภทไม่ผ่าน Npcap หรือไม่ควรรอ user-mode parsing

```text
                     +--> Go Nose --> canonical network events --+
Network/Host activity +                                           |
                     +--> Kernel sensor --> kernel telemetry -----+--> Zig Event Fabric
```

Kernel sensor เหมาะกับ:

- WFP classify metadata
- flow lifecycle
- process identity ของ socket/flow
- PID, application path, package identity
- interface and compartment metadata
- connection allow/block observation
- TCP state transitions
- high-confidence low-cost signatures
- driver/provider health events
- tamper and policy integrity signals

### 2.3 Zig: จุดรวม event และ runtime authority

Zig ไม่ควรตรวจ payload เชิงลึกใน kernel แทน แต่ควรเป็นจุดรวม:

```text
Nose event
Kernel event
ETW event
FIM event
Registry event
    -> validation
    -> deduplication
    -> correlation
    -> queue
    -> detection pipeline
    -> policy input
```

Zig ควรเป็นผู้กำหนด runtime generation, event sequencing, worker lifecycle, backpressure และ health state

### 2.4 Python/Cython: deep detection และ analytics

Python/Cython เหมาะกับงานที่มีความซับซ้อนและเปลี่ยนแปลงบ่อย:

- protocol-aware inspection
- regex and rule matching
- ML/heuristics
- enrichment
- threat intelligence
- multi-event correlation
- forensic context
- explainable detection

Kernel sensor ควรส่ง metadata หรือ bounded evidence ให้ Python/Cython ไม่ควรส่ง memory pointer หรือโครงสร้าง kernel ภายในโดยตรง

### 2.5 Rust PEP: enforcement authority เดียว

Rust PEP ต้องคงตำแหน่งเดิมและห้ามลด authority ของมันเพียงเพราะเพิ่ม detection ใน kernel:

```text
Kernel detection signal
    -> user-mode event
    -> Zig/Python correlation
    -> signed policy decision
    -> Rust PEP authorization
    -> WFP mutation
    -> host postcondition
    -> EnforcementReceipt
```

Kernel sensor สามารถส่ง `DETECTION_CANDIDATE`, `FLOW_OBSERVATION` หรือ `HIGH_CONFIDENCE_SIGNAL` ได้ แต่ไม่ควรส่งคำสั่ง `BLOCK_NOW` ที่ driver ปฏิบัติตามเอง

### 2.6 WFP driver: provider ไม่ใช่ brain

WFP driver ควรทำงานใน kernel เป็น:

- callout registration
- flow classification
- metadata extraction
- bounded telemetry
- filter add/delete ตาม request ที่ผ่าน PEP
- exact filter identity management
- fail-safe behavior เมื่อ provider state ไม่สมบูรณ์

Driver ไม่ควรทำ:

- parse HTTP/DNS/TLS เต็มรูปแบบ
- โหลด policy file
- verify policy signature แทน PEP
- ติดต่อ Python หรือ TypeScript
- เขียนไฟล์ forensic โดยตรง
- ประกาศ `BLOCKED_CONFIRMED` เอง

### 2.7 Mouth: ด้านประกาศผลและ operational output

Mouth ควรอยู่ปลายทางหลัง enforcement และ evidence pipeline:

```text
Raw events
  -> detection
  -> policy decision
  -> PEP receipt
  -> forensic linkage
  -> Mouth
```

Mouth มีหน้าที่:

- แสดง detection
- แสดง confidence และ severity
- แสดง enforcement state
- แสดง provider state
- แสดง receipt/filter identity ที่เหมาะสม
- แสดง rollback/cleanup result
- ส่ง alert หรือ report ให้ operator

Mouth ห้าม infer ว่า block สำเร็จจาก:

- log line
- policy action
- PEP request
- WFP API return code เพียงอย่างเดียว

Mouth ต้องใช้ `EnforcementReceipt` ที่ validate แล้วเท่านั้น

---

## 3. เป้าหมายสถาปัตยกรรมที่แนะนำ

```text
+----------------------+       +----------------------+
| External network     |       | Host activity        |
+----------+-----------+       +----------+-----------+
           |                              |
           v                              v
+----------------------+       +----------------------+
| Go Nose / Npcap      |       | Kernel sensor        |
| packet ingress       |       | WFP/ETW/flow signals |
+----------+-----------+       +----------+-----------+
           |                              |
           +---------------+--------------+
                           v
                 +----------------------+
                 | Zig Event Fabric     |
                 | validation, queue,   |
                 | correlation, health  |
                 +----------+-----------+
                            v
                 +----------------------+
                 | Python/Cython        |
                 | deep detection       |
                 +----------+-----------+
                            v
                 +----------------------+
                 | Policy engine        |
                 | TypeScript/Python    |
                 | signed policy        |
                 +----------+-----------+
                            v
                 +----------------------+
                 | Rust PEP             |
                 | authority/capability |
                 +----------+-----------+
                            v
                 +----------------------+
                 | WFP user bridge     |
                 +----------+-----------+
                            v
                 +----------------------+
                 | aegis_wfp.sys       |
                 | kernel enforcement  |
                 +----------+-----------+
                            v
                 +----------------------+
                 | Host postcondition  |
                 | receipt + forensics |
                 +----------+-----------+
                            v
                 +----------------------+
                 | Mouth / operator UI |
                 +----------------------+
```

หลักสำคัญคือ **kernel sensor และ WFP enforcement อยู่ใน kernel แต่ authority และ deep reasoning ยังคงอยู่ใน user mode**

---

## 4. สิ่งที่ควรทำใน kernel และสิ่งที่ไม่ควรทำ

### 4.1 งานที่เหมาะกับ kernel

งานใน kernel ต้องมีขอบเขตเล็ก, deterministic และ bounded:

1. **Flow metadata extraction** เช่น source/destination address, port, protocol, direction, interface, compartment
2. **Process attribution** เช่น PID, app identity หรือ process path ที่ระบบ Windows เปิดเผยผ่าน layer ที่ใช้
3. **Connection lifecycle** เช่น flow established, teardown, retransmission metadata และ state transitions
4. **Low-cost structural checks** เช่น malformed header, impossible length, invalid flag combination และ rate anomaly
5. **Early high-confidence indicators** ที่ใช้ข้อมูลไม่มากและมี false positive ต่ำ
6. **Provider telemetry** เช่น filter match, classify latency, provider error, dropped event และ device state
7. **Tamper signals** เช่น unexpected unload, policy epoch mismatch, invalid request sequence และ replayed request
8. **Host-effect observation** เช่น filter match counters หรือ flow postcondition signal

### 4.2 งานที่ไม่ควรอยู่ใน kernel

ไม่ควรวางงานต่อไปนี้ใน driver เว้นแต่มีเหตุผลด้าน safety และ review ระดับสูง:

- full HTTP parser
- TLS decryption
- arbitrary regex engine
- Python/Cython runtime
- TypeScript/JavaScript runtime
- dynamic policy file loading
- network calls to threat intelligence
- complex machine learning
- unbounded memory allocation
- blocking I/O
- logging ลง disk
- JSON parsingขนาดใหญ่
- policy signing and key management
- final enforcement authorization

เหตุผลคือ kernel crash, deadlock, memory corruption หรือ performance regression จะกระทบทั้ง host ไม่ใช่แค่ AEGIS process

---

## 5. Kernel detection event contract

ต้องเพิ่ม contract ใหม่แยกจาก `CanonicalEvent` เดิม โดยไม่ยัด kernel-private fields ลงใน packet event โดยตรง

ตัวอย่างแนวคิด:

```c
#pragma pack(push, 1)
typedef struct AEGIS_KERNEL_DETECTION_EVENT {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint64_t event_id;
    uint64_t runtime_generation;
    uint64_t timestamp_100ns;
    uint32_t event_kind;
    uint32_t confidence;
    uint32_t severity;
    uint32_t pid;
    uint32_t process_hash;
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t direction;
    uint16_t flags;
    uint64_t flow_id;
    uint64_t provider_epoch;
    uint64_t evidence_hash;
    uint32_t reserved;
} AEGIS_KERNEL_DETECTION_EVENT;
#pragma pack(pop)
```

รายละเอียดจริงต้องกำหนดร่วมกันใน shared header และตรวจด้วย compile-time/static assertions ของ C, Zig และ Rust

### 5.1 Contract requirements

ทุก kernel event ต้องมี:

- magic และ version
- struct size
- event ID
- runtime generation
- timestamp source
- event kind
- severity/confidence
- flow identity
- provider epoch
- bounded evidence hash
- reserved extension space

ห้ามส่ง:

- kernel pointer
- raw address ที่ user mode นำไป dereference
- unbounded string
- arbitrary user-supplied buffer
- internal WFP object pointer

### 5.2 Transport

แนะนำลำดับการ transport:

```text
Kernel driver
  -> bounded non-paged ring / queue
  -> overlapped IOCTL read
  -> Rust or Zig user-mode bridge
  -> canonical user-mode event
  -> Zig Event Fabric
```

ไม่ควรให้ driver เปิด named pipe เอง เพราะ named pipe เป็น user-mode control/data-plane concern

หากใช้ IOCTL ต้องมี:

- `METHOD_OUT_DIRECT` หรือ contract ที่เหมาะสมกับขนาดข้อมูล
- strict input/output length validation
- IOCTL access mask
- caller authorization
- sequence number
- ring overflow counter
- bounded queue
- cancel-safe IRP handling
- unload-safe cleanup

---

## 6. Detection semantics และ state machine

ต้องไม่ให้ kernel event ถูกตีความเป็น block โดยอัตโนมัติ

แนะนำสถานะ:

```text
KERNEL_OBSERVED
  -> CANDIDATE
  -> CORRELATED
  -> POLICY_EVALUATED
  -> PEP_AUTHORIZED
  -> WFP_REQUESTED
  -> HOST_EFFECT_CONFIRMED
  -> ROLLED_BACK
```

Failure states:

```text
DROPPED_KERNEL_EVENT
INVALID_KERNEL_EVENT
CORRELATION_TIMEOUT
POLICY_REJECTED
PEP_REJECTED
PROVIDER_UNAVAILABLE
WFP_FAILED
POSTCONDITION_FAILED
CLEANUP_FAILED
```

Kernel driver อาจหยุดหรือชะลอ traffic ได้เฉพาะในกรณี emergency fail-safe ที่ออกแบบและอนุมัติแยกต่างหาก แต่ไม่ควรนำ behavior นี้มาใช้ใน production baseline ก่อนมี safety review และ rollback proof

---

## 7. Detection tiers ที่เหมาะสม

### Tier 0 — Kernel telemetry

ส่ง metadata และ lifecycle signals เท่านั้น ไม่มี block decision

ตัวอย่าง:

- new flow
- socket attribution
- filter match
- malformed packet indicator
- provider error

### Tier 1 — Kernel early classification

ทำ structural checks ที่ deterministic:

- invalid packet length
- impossible TCP flags
- suspicious scan rate
- protocol mismatch
- excessive connection churn

ผลลัพธ์เป็น `DetectionCandidate` ไม่ใช่ `EnforcementReceipt`

### Tier 2 — User-mode deep detection

ใช้ Python/Cython/Go/Zig สำหรับ:

- signatures
- regex
- protocol parsing
- threat intelligence
- event correlation
- anomaly scoring

### Tier 3 — PEP-authorized prevention

Rust PEP ตรวจ policy, capability, trust, severity, quota และ provider readiness ก่อนส่ง WFP request

### Tier 4 — Host-proofed IPS

WFP driver สร้าง filter, คืน filter identity, ระบบตรวจ traffic จริงและสร้าง receipt

---

## 8. แผนพัฒนาแบบเป็นระยะ

### Phase K0 — Threat model และ scope freeze

ต้องจัดทำ:

- kernel attack surface
- IOCTL threat model
- user/kernel trust boundary
- driver unload behavior
- ring overflow behavior
- malformed event behavior
- fail-open/fail-closed decision
- rollback plan

Deliverables:

- `KERNEL_DETECTION_THREAT_MODEL.md`
- updated authority invariants
- driver security checklist

### Phase K1 — Shared ABI contract

สร้าง:

- `drivers/wfp_callout/aegis_detection.h`
- `src/windows/kernel_detection.zig`
- `rust-src/kernel_detection.rs`
- golden binary fixtures

ทดสอบ:

- size
- offsets
- packing
- endian
- enum ordinals
- round-trip serialization

### Phase K2 — Kernel telemetry only

เพิ่ม event production โดยยังไม่ทำ detection และไม่ block

เกณฑ์ผ่าน:

- driver load/unload stable
- no memory leak
- no crash under sustained flow churn
- queue overflow observable
- event drop explicit
- service stop completes

### Phase K3 — User-mode bridge

ทำ bridge อ่าน event จาก driver ด้วย overlapped I/O และส่งเข้า Zig

เกณฑ์ผ่าน:

- cancel-safe read
- reconnect
- generation mismatch rejection
- malformed event rejection
- bounded memory
- backpressure metrics

### Phase K4 — Kernel early classifiers

เพิ่ม classifier แบบเล็กและ deterministic โดยคืน candidate เท่านั้น

ตัวอย่าง:

```text
TCP_SYN_SCAN_CANDIDATE
MALFORMED_HEADER_CANDIDATE
FLOW_RATE_ANOMALY_CANDIDATE
PROVIDER_TAMPER_CANDIDATE
```

ต้องทดสอบ false positive และ false negative แยกจาก host enforcement

### Phase K5 — Correlation กับ Nose

สร้าง correlation key:

```text
runtime_generation + producer_id + flow_id + event_id
```

ตรวจ duplicate และ non-monotonic events โดยไม่ทำให้ event จาก kernel และ Nose ถูกนับซ้ำ

### Phase K6 — Policy integration

Kernel candidate ต้องไหลเข้ากระบวนการเดียวกับ Nose:

```text
candidate -> DetectionResult -> PolicyDecision -> PEP
```

อย่าสร้าง kernel-specific enforcement shortcut

### Phase K7 — Controlled enforcement

ใช้เฉพาะ disposable VM และ target port ที่ยืนยันแล้ว

ต้องพิสูจน์:

- baseline reachable
- block receipt
- actual traffic blocked
- forensic linkage
- exact cleanup
- traffic restored

### Phase K8 — Production hardening

ตรวจ:

- signing and attestation
- installer rollback
- driver upgrade compatibility
- crash dump policy
- ETW diagnostics
- performance budget
- security review
- recovery after BSOD/reboot

---

## 9. Performance budget

Kernel detection ต้องมี budget ที่วัดได้ ไม่ใช่เพียง “ทำงานได้”

ควรกำหนดและวัด:

| Metric | เป้าหมายเริ่มต้น |
|---|---:|
| classify path CPU overhead | < 2% บน baseline workload |
| kernel event size | fixed-size หรือ bounded |
| queue memory | fixed upper bound |
| event delivery latency | p99 < 10 ms ใน lab |
| dropped event rate | 0 ภายใต้ acceptance workload |
| driver unload time | bounded และไม่มี stuck IRP |
| malformed input handling | ไม่ crash และไม่ leak |
| sustained flow test | อย่างน้อย 30–60 นาที |

ตัวเลขต้องปรับตาม hardware จริง แต่ต้องถูกบันทึกใน acceptance report

---

## 10. Security requirements

### 10.1 IOCTL security

ทุก IOCTL ต้องตรวจ:

- access mask
- caller mode
- input/output length
- integer overflow
- pointer validation
- request sequence
- request freshness
- capability
- provider epoch
- shutdown state

### 10.2 Replay protection

ทุก privileged request ต้องมี:

- monotonic request ID
- runtime generation
- nonce หรือ freshness window
- policy version
- caller capability
- exact action scope

Driver ต้อง reject request ที่:

- generation เก่า
- sequence ซ้ำ
- filter identity ไม่ถูกต้อง
- destination fields เปลี่ยนจาก receipt
- cleanup request ไม่มี receipt context

### 10.3 Fail-closed rules

เมื่อเกิดเหตุการณ์ต่อไปนี้:

- Rust PEP unavailable
- provider unavailable
- malformed request
- queue overflow
- policy signature invalid
- runtime generation mismatch
- driver unload in progress

ระบบต้องไม่ประกาศ `ENFORCED` และต้องแสดงสถานะที่ตรงจริง เช่น `DEGRADED`, `REJECTED`, `UNAVAILABLE` หรือ `POSTCONDITION_FAILED`

### 10.4 Kernel crash safety

ต้องตรวจด้วย:

- Driver Verifier
- Special Pool
- I/O Verification
- Pool Tracking
- Force IRQL Checking
- deadlock detection
- DMA checks หากเกี่ยวข้อง

Driver Verifier ต้องรันใน disposable test VM ไม่ใช่เครื่อง production

---

## 11. Test strategy

### 11.1 Unit and ABI tests

ทดสอบ C, Zig และ Rust ให้ตรวจ struct layout เดียวกัน

```text
sizeof
offsetof
alignment
packing
enum values
serialization
malformed input
```

### 11.2 Driver tests

ทดสอบ:

- load
- start
- stop
- unload
- duplicate load
- missing provider
- malformed IOCTL
- short buffer
- oversized buffer
- stale request
- replayed request
- invalid filter ID
- exact cleanup

### 11.3 Fuzzing

Fuzz:

- IOCTL input
- event header
- lengths
- protocol/port fields
- sequence values
- event correlation

เกณฑ์คือไม่มี crash, bugcheck, memory leak หรือ uncontrolled allocation

### 11.4 Integration tests

ทดสอบ flow ต่อไปนี้:

```text
Nose event -> Zig -> detection -> policy -> PEP -> no-op
Kernel event -> Zig -> detection -> policy -> PEP -> no-op
Kernel candidate + Nose event -> deduplicated correlation
PEP reject -> no WFP filter
WFP provider fail -> no ENFORCED receipt
WFP success -> receipt with filter_id
cleanup by filter_id -> filter removed
```

### 11.5 Host-effect proof

ใช้ VMware lab:

```text
Attacker Kali: 192.168.126.10
Target Windows: 192.168.126.20
Target service: TCP/8080
```

ลำดับ:

1. ตรวจ target listener
2. ตรวจ attacker baseline HTTP 200
3. ตรวจ health และ provider readiness
4. ส่ง `enforcement.block` ผ่าน Rust PEP path
5. บันทึก receipt
6. ตรวจ traffic blocked จาก attacker
7. ตรวจ WFP filter identity
8. ตรวจ forensic linkage
9. ส่ง `enforcement.unblock` ด้วย `filter_id`
10. ตรวจ traffic กลับมา HTTP 200
11. ตรวจ orphan filters
12. รัน lifecycle recovery

### 11.6 Attack tests หลัง production baseline

ควรทดสอบใน isolated lab:

- SYN scan
- port scan
- malformed TCP flags
- fragmented traffic
- oversized payload
- DNS anomaly
- HTTP signature test
- repeated connection churn
- process attribution mismatch
- driver tamper attempt
- stale receipt replay
- unauthorized IOCTL
- kernel event flood
- queue overflow
- daemon restartระหว่างมี filter

ทุก attack test ต้องมี expected result และ evidence ไม่ใช่เพียงดู log

---

## 12. Metrics ที่ต้องเพิ่ม

Health และ Mouth ควรแสดง metrics แยกกัน:

```text
kernel_events_received
kernel_events_accepted
kernel_events_rejected
kernel_events_dropped
kernel_queue_depth
kernel_queue_high_watermark
kernel_classifier_candidates
kernel_classifier_false_positive_review
kernel_ioctls_received
kernel_ioctls_rejected
kernel_ioctls_replayed
kernel_filter_matches
kernel_classify_latency_p50
kernel_classify_latency_p99
kernel_provider_errors
kernel_driver_generation
kernel_driver_epoch
```

ห้ามรวม `kernel_events_dropped` กับ `Nose frames_dropped` เพราะเป็นคนละ data plane และมีความหมายด้าน evidence ต่างกัน

---

## 13. การปรับ health contract

เพิ่มสถานะเหล่านี้แยกจากกัน:

```json
{
  "kernel_sensor": {
    "available": true,
    "driver_loaded": true,
    "device_ready": true,
    "telemetry_ready": true,
    "classifier_ready": true,
    "queue_depth": 0,
    "events_dropped": 0,
    "provider_epoch": 4
  },
  "rust_shield": {
    "pep_ready": true,
    "policy_authority": true,
    "provider_ready": true,
    "host_effect_capable": true
  },
  "enforcement": {
    "mode": "semi_ips",
    "receipt_required": true,
    "host_effect_proven": false
  }
}
```

`kernel_sensor.available=true` ไม่ได้แปลว่า prevention active และ `provider_ready=true` ไม่ได้แปลว่ามี block เกิดขึ้นแล้ว

---

## 14. Release and installer implications

เมื่อเพิ่ม kernel sensor ต้องปรับ installer ให้ติดตั้งและตรวจ version ของ:

- kernel driver
- user-mode WFP bridge
- PEP DLL
- Zig daemon
- shared ABI manifest
- symbol/provenance manifest
- test certificate สำหรับ lab เท่านั้น

Installer ต้องมี rollback ที่ลบ:

- driver service
- device state
- WFP provider registration
- filters ที่ AEGIS สร้าง
- user-mode bridge
- stale runtime handles

ห้าม uninstall แล้วปล่อย orphan filters หรือ service deletion-pending โดยไม่มี recovery instruction

---

## 15. คำแนะนำเฉพาะสำหรับ AEGIS ปัจจุบัน

### สิ่งที่ควรรักษาไว้

- Rust PEP เป็น sole enforcement authority
- WFP exact filter identity
- Nose 10/10 ingress proof
- Zig daemon เป็น runtime owner
- Mouth ใช้ receipt-driven state
- forensic ring และ hash verification
- explicit health distinction ระหว่าง PEP, provider และ host effect

### สิ่งที่ควรเพิ่ม

1. สร้าง `kernel_detection` contract แยกจาก `CanonicalEvent`
2. เพิ่ม kernel telemetry reader แบบ overlapped IOCTL
3. เพิ่ม kernel event queue metrics ใน Zig health
4. เพิ่ม `KernelDetectionCandidate` ใน detection contract
5. เพิ่ม correlation ระหว่าง Nose flow และ kernel flow
6. เพิ่ม Driver Verifier lab scripts
7. เพิ่ม malformed IOCTL/fuzz tests
8. เพิ่ม boot/reboot/recovery proof
9. เพิ่ม filter orphan scan ใน cleanup gate
10. เพิ่ม Mouth views สำหรับ `KERNEL_OBSERVED`, `CANDIDATE`, `ENFORCED`, `POSTCONDITION_FAILED`

### สิ่งที่ไม่ควรเพิ่ม

- Python runtime ใน driver
- TypeScript runtime ใน driver
- full IDS parser ใน kernel
- direct block shortcut จาก classifier
- UI state ที่อ่านจาก driver log โดยตรง
- WFP mutation ที่ไม่ผ่าน PEP

---

## 16. Definition of Done สำหรับ Full IDS / Semi-IPS

ระบบจะถือว่าพร้อมในระดับนี้เมื่อผ่านทุกข้อ:

### Detection

- Nose ตรวจ network traffic ได้
- Kernel sensor ตรวจ host/flow metadata ได้
- User-mode deep engine ตรวจ payload และ correlate ได้
- event identity ข้าม source ไม่ซ้ำและตรวจสอบได้
- dropped event มี metric และ evidence

### Prevention

- ทุก block ผ่าน Rust PEP
- WFP filter ระบุ IP/port/protocol ได้
- receipt มี filter identity
- host traffic postcondition พิสูจน์ได้
- cleanup ใช้ exact filter ID
- rollback ผ่านและ traffic กลับมาได้

### Security

- driver IOCTL authorization ผ่าน
- replay/stale generation ถูก reject
- Driver Verifier ผ่าน
- malformed input ไม่ทำให้ crash
- no direct bypass จาก Nose, Python, Zig, CLI หรือ Mouth

### Operations

- daemon singleton
- lifecycle recovery ผ่าน
- installer rollback ผ่าน
- reboot recovery ผ่าน
- health แยก detection readiness และ enforcement readiness
- Mouth แสดงสถานะจาก evidence จริง

---

## 17. Final conclusion

ตำแหน่งที่เหมาะสมที่สุดคือ:

```text
Nose       = ด้านหน้า network ingress
Kernel     = parallel low-level sensor และ WFP enforcement provider
Zig        = event fabric, lifecycle, correlation, health
Python     = deep detection และ analytics
TypeScript = policy authoring/signing
Rust PEP   = sole enforcement authority
Mouth      = ปลายทางสำหรับประกาศผลจาก receipt และ forensic evidence
```

แนวทางนี้ทำให้ AEGIS มีความสามารถใกล้เคียง **full IDS** โดยมีทั้ง network detection, host/kernel telemetry, deep user-mode analysis และ forensic correlation ขณะเดียวกันยังคงเป็น **semi-IPS ที่ปลอดภัย** เพราะ kernel ไม่สามารถตัดสินใจ block เอง และการป้องกันทุกครั้งต้องผ่าน Rust PEP, WFP filter, host postcondition และ EnforcementReceipt

หลักการสำคัญที่สุดคือ:

> **Kernel ควรทำสิ่งที่ต้องเร็วและใกล้ host; user mode ควรทำสิ่งที่ต้องฉลาดและเปลี่ยนแปลงบ่อย; Rust PEP ต้องเป็นจุดเดียวที่อนุญาตการป้องกัน; Mouth ต้องประกาศเฉพาะสิ่งที่ evidence ยืนยันแล้ว**

## References

[1]: ./AEGIS_MANUS_PRODUCTION_HANDOFF_2026-09-21.md "AEGIS production handoff report"
[2]: ./PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md "AEGIS production completion runbook"
[3]: ./PHASE_10_VMWARE_ISOLATED_LAB_PLAN_2026-09-19.md "VMware isolated lab plan"
[4]: ./drivers/wfp_callout/aegis_wfp.h "AEGIS WFP driver contract"
[5]: ./drivers/wfp_callout/aegis_wfp.c "AEGIS WFP kernel implementation"
[6]: ./rust-src/lib.rs "Rust PEP and WFP adapter"
[7]: ./src/policy/pep_bindings.zig "Zig to Rust PEP bindings"
[8]: ./src/control/protocol.zig "AEGIS control protocol"
[9]: ./src/control/handler_registry.zig "AEGIS control handler registry"
[10]: ./src/capture/nose_pipe_reader.zig "Zig Nose pipe reader"
[11]: ./nose/pipe_writer.go "Go Nose pipe writer"
[12]: ./tools/aegisctl/api/control_api.py "AEGIS Python control API"
