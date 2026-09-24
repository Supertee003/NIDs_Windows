# AEGIS Execution Phase Plan

**วันที่:** 18 กันยายน 2026  
**Repository HEAD baseline:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**เป้าหมาย:** พัฒนาและพิสูจน์ AEGIS แบบเป็นลำดับ โดยรักษา ABI, identity, authority boundary และ fail-closed semantics

## หลักการดำเนินงาน

AEGIS จะพัฒนาเป็นหลาย track แบบขนาน แต่แต่ละ Phase จะจบด้วย checkpoint ที่พิสูจน์ boundary เดียวให้ชัดเจน การมี source file, type หรือ binary ไม่ถือเป็น runtime proof และการมี PEP decision ไม่ถือเป็นหลักฐานว่า WFP host effect สำเร็จ

Authority model ที่ต้องรักษาคือ:

```text
Nose = network observation and ingress only
Python/Cython = detection intelligence only
Zig = runtime, lifecycle, queue and orchestration owner
Policy = decision construction, not privileged enforcement
Rust PEP = sole privileged enforcement authority
C++/native bridge = provider and ABI adapter
WFP = host effect provider
Forensic = evidence and integrity record
Mouth = read-only receipt and health presentation
```

## Phase 0 — Truth Synchronization

### Steps

1. ยืนยัน current HEAD, working tree และรายการไฟล์ที่แก้หรือเพิ่ม โดยไม่ reset หรือ discard งานเดิม
2. ตรวจ `inventory.json`, `reference_map.json`, `runtime_manifest.json` และ `PHASE_0_TRUTH_REBUILD_REPORT.*`
3. แยก source, generated artifact, build output และ runtime artifact ออกจากกัน
4. ระบุ artifact discovery roots ที่ถูกต้อง เช่น `zig-out/bin`, `target/release`, `dist`, `mouth/target/release` และ `release`
5. เพิ่ม provenance ให้ทุก manifest โดยอ้าง current HEAD และ generator เดียวกัน
6. รัน `git diff --check`, Zig tests, Go tests และ Python contract tests ก่อน patch ใหม่

### Exit criteria

- Current HEAD และ working tree ถูกบันทึก
- ไม่มีการอ้าง generated artifact ที่ stale โดยไม่ระบุ provenance
- Unresolved truth artifacts ถูกระบุชื่อและสาเหตุ
- Baseline test result ถูกบันทึก แม้บาง test จะ fail

## Phase 1 — Contract and ABI Convergence

### Steps

1. ตรึง CanonicalEvent v1: magic, version, size marker, offsets, endian และ enum ordinals
2. ตรึง Internal IpcEvent v5 แยกจาก wire v1
3. สร้าง golden vectors ที่ Go และ Zig serialize/deserialize ได้ byte-identical
4. ตรวจ invalid source, event type, policy action, confidence และ size marker
5. ตรวจ PEP FFI structs ระหว่าง Zig และ Rust ด้วย field offsets และ sizes
6. กำหนด version ของ DetectionResult, PolicyDecision, EnforcementReceipt และ Mouth receipt input
7. ห้ามเพิ่ม raw payload เข้า wire v1 โดยไม่สร้าง versioned protocol ใหม่

### Exit criteria

- ABI byte-level tests ผ่านในทุกภาษาที่มี implementation
- Wire v1 และ internal event ไม่ถูกปะปน
- Invalid input ถูก reject แบบ deterministic
- Golden vector และ schema มี provenance

## Phase 2 — Identity and Ingress Conservation

### Steps

1. กำหนด identity authority และ producer generation
2. แยก duplicate, collision, retry, replay และ non-monotonic semantics
3. เลิกพึ่ง process-local event counter เพียงอย่างเดียวเมื่อข้าม restart
4. ทำ ingress counters ให้ตรวจ conservation:

```text
submitted = accepted + rejected + capacity_dropped + lifecycle_dropped
```

5. ให้ Nose และ Zig รายงาน source, epoch และ sequence ที่ตรวจย้อนกลับได้
6. ทำ retry/idempotency contract ก่อนเปิด reconnect resend
7. ทดสอบ queue full, reconnect, restart และ duplicate frame

### Exit criteria

- Event identity ต่อเนื่องข้าม producer restart ตาม contract
- ไม่มี silent loss
- Queue accepted event ถูกนับและตรวจย้อนกลับได้
- Retry ไม่สร้าง duplicate forensic หรือ enforcement side effect

## Phase 3 — Nose Network Ingress

### Steps

1. ตรวจ Npcap capture และ BPF `ip or ip6`
2. ตรวจ Go canonical serializer และ named pipe writer
3. คง Nose เป็น observe-only
4. ตรวจ source/destination, port, protocol, direction และ timestamp
5. ทำ controlled observe fixture ที่ใช้ actual canonical pipe
6. แยก metadata-only wire v1 กับ raw payload path
7. หากต้องใช้ payload detection ให้เลือก side-channel หรือ versioned wire v2 อย่างชัดเจน
8. ตรวจ Nose counters และ reconnect behavior

### Exit criteria

- Nose ส่ง canonical frame จริงผ่าน `\\.\pipe\aegis_nose`
- Zig รับและ validate frame จริง
- Queue และ forensic รับ event ได้ตามจำนวน
- ไม่มี block, WFP call หรือ receipt ที่สร้างจาก Nose

## Phase 4 — Python/Cython Detection

### Steps

1. กำหนด DetectionResult schema ที่ผูก `event_id`, detector, version, rule, severity, reason และ confidence
2. ทำให้ Python regex และ Cython regex คืน shape และ semantics เดียวกัน
3. ใช้ Python fallback เป็น correctness oracle ของ Cython
4. ตรวจ rule ordering, invalid regex, malformed payload, payload size และ encoding
5. ระบุว่า Cython ไม่มี path ไป policy, PEP, C++, WFP หรือ subprocess
6. เชื่อมผลเข้า Zig ผ่าน versioned adapter หรือ validated IPC
7. สร้าง alert-only fixture ที่ตรวจ detection โดยไม่สร้าง host effect

### Exit criteria

- Cython/Python parity tests ผ่าน
- DetectionResult deterministic และ explainable
- Detection proof มี event identity เดียวกับ ingress
- ไม่มี enforcement side effect จาก Brain

## Phase 5 — Zig Pipeline and PolicyDecision

### Steps

1. ตรวจ payload preservation ระหว่าง ingress และ detector
2. แปลง DetectionResult เป็น PolicyDecision ที่ deterministic
3. แยก matched detection, matched policy และ requested action
4. ตรวจ severity mapping และ policy version/hash
5. ทำ policy alert-only และ log-only ก่อน block
6. ตรวจ trace ID เดียวตั้งแต่ event ถึง policy
7. ปฏิเสธ policy ที่ stale, invalid หรือไม่มี provenance

### Exit criteria

- DetectionResult เดิมให้ PolicyDecision เดิม
- Alert-only policy ไม่เรียก WFP block
- Policy match มี rule/policy identity และ trace ID
- Simulation handler ไม่ถูกใช้เป็น production proof

## Phase 6 — Rust PEP and C++ Native Bridge

### Steps

1. ตรวจ Rust PEP request validation: signature, version, hash, TTL, capability, freshness, nonce และ replay
2. ตรวจ caller identity และ request identity
3. แยก PEP decision จาก provider submission
4. ตรวจ C ABI และ C++ bridge field layout
5. ให้ C++ bridge ทำหน้าที่ adapter/provider ไม่ตัดสิน policy เอง
6. คืน provider result ที่มี filter ID หรือ failure reason
7. ทำ alert-only/no-host-effect PEP receipt ก่อน WFP block
8. ทดสอบ unavailable PEP, invalid capability, stale request และ duplicate request

### Exit criteria

- Privileged action มี Rust PEP gate เดียว
- C++ bridge ไม่มี bypass path
- PEP unavailable ไม่กลายเป็น allow
- Alert-only receipt ตรวจ postcondition ได้

## Phase 7 — EnforcementReceipt and Forensic Evidence

### Steps

1. ขยาย receipt ให้มี request ID, event ID, trace ID, audit ID, policy identity, provider และ timestamp
2. แยก `AUTHORIZED`, `SUBMITTED`, `ENFORCED`, `FAILED`, `UNAVAILABLE`, `DEFERRED` และ `ESCALATED`
3. ผูก provider result กับ host-effect confirmation
4. ทำ forensic append แบบ idempotent ด้วย evidence identity
5. แยก accepted, retained, exported, overwritten, lost และ append_failed metrics
6. ตรวจ hash-chain และ completeness แยกจากกัน
7. สร้าง alert-only receipt proof ที่ไม่มี WFP side effect

### Exit criteria

- Receipt ไม่อ้าง `ENFORCED` หากไม่มี host proof
- Forensic record ผูก event, detection, policy, PEP และ receipt ได้
- Duplicate receipt ไม่ทำให้ evidence ซ้ำหรือ side effect ซ้ำ
- Integrity ไม่ถูกตีความว่า durable completeness

## Phase 8 — WFP and Tier-3 Host Effect

### Steps

1. ทำ artifact discovery ของ `sec_monitor.dll`, PEP DLL, user adapter และ WFP driver
2. ตรวจ dependencies, signing, architecture และ runtime search path
3. ตรวจ Tier-3 health pipe และ dependency readiness
4. ตรวจ WFP provider availability
5. ทำ isolated block fixture เท่านั้น
6. เก็บ filter ID และ provider response
7. ยืนยัน host effect ด้วย postcondition บน Windows
8. ทำ cleanup proof และ rollback proof
9. ให้ failure/unavailable/deferred ถูกส่งกลับเป็น receipt ที่ตรงสถานะ

### Exit criteria

- `overall_gate=true` เฉพาะเมื่อ Tier-3 และ worker readiness ผ่านจริง
- WFP host effect มีหลักฐาน postcondition
- Cleanup สำเร็จและตรวจซ้ำได้
- ไม่มี `BLOCKED` จาก log เพียงอย่างเดียว

## Phase 9 — Mouth Receipt-Driven Operator Surface

### Steps

1. แยก health pipe ออกจาก receipt stream
2. ให้ Mouth อ่าน canonical health จาก Core/Tier-3 ไม่ hard-code `RUNNING/OK`
3. ให้ Mouth อ่าน EnforcementReceipt ที่มี schema version
4. เปลี่ยน Active Mitigations จาก log-derived เป็น receipt-derived
5. แยก `DECISION_BLOCK` จาก `HOST_EFFECT_CONFIRMED`
6. แสดง `ENFORCEMENT_PENDING`, `FAILED`, `DEFERRED` และ `UNAVAILABLE`
7. ห้าม Mouth เรียก PEP, WFP, netsh หรือ C++ bridge เพื่อสร้าง enforcement
8. ทดสอบ malformed receipt, stale receipt และ missing host proof

### Exit criteria

- Mouth เป็น read-only consumer
- `BLOCKED` แสดงได้เฉพาะ receipt ที่ `ENFORCED` และ `host_effect_confirmed=true`
- Health และ counters มาจาก runtime จริง
- Mouth shutdown และ health thread join ได้

## Phase 10 — Lifecycle and Graceful Shutdown

### Steps

1. หยุด acquisition
2. reject ingress ใหม่
3. join producers
4. drain accepted queue
5. ทำ detection/policy/PEP ให้จบ
6. flush forensic และ audit
7. teardown WFP/bridge
8. join workers และ Mouth health thread
9. ตรวจ postconditions
10. ตั้ง `STOPPED` หลังทุกขั้นผ่านเท่านั้น

### Exit criteria

- ไม่มี accepted event หายระหว่าง shutdown
- ไม่มี PEP side effect ค้างโดยไม่มี receipt
- Evidence flush เสร็จ
- Restart สร้าง generation ใหม่และไม่ชน identity เดิม

## Phase 11 — Full Acceptance and Release Truth

### Steps

1. รัน unit, contract, integration และ Windows host tests
2. รัน Nose observe proof
3. รัน Python/Cython parity proof
4. รัน alert-only Detection → Policy → Receipt proof
5. รัน C++/PEP ABI proof
6. รัน isolated WFP host-effect proof
7. รัน Mouth receipt-consumption proof
8. รัน graceful shutdown/restart proof
9. regenerate inventory, reference map, runtime manifest และ build manifest
10. ตรวจ artifact SHA และ release package

### Exit criteria

ห้ามใช้คำว่า production-ready จนกว่าจะผ่านทั้งหมด:

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

## Execution order ที่เริ่มทันที

ลำดับการลงมือใน working tree คือ:

1. แก้และทดสอบ health/Tier-3 mapping ให้ผ่าน contract tests
2. สร้าง source inventory ของ Python/Cython และ C++ bridge พร้อม authority audit
3. สร้าง DetectionResult adapter ที่ใช้ Python fallback เป็น oracle
4. เพิ่ม deterministic PolicyDecision/alert-only fixture
5. ขยาย EnforcementReceipt ให้รองรับ no-host-effect status
6. เชื่อม forensic linkage
7. ปรับ Mouth ให้ receipt-driven โดยยังไม่เรียก WFP
8. ทำ Nose payload/identity integration โดยไม่ทำลาย wire v1
9. ตรวจ artifact discovery และ Tier-3 readiness
10. ทำ isolated WFP proof และ cleanup เป็นลำดับสุดท้าย

## Reporting format หลังแต่ละ Step

ทุก patch ต้องรายงาน:

1. Scope
2. Source files changed
3. Invariants preserved
4. Test commands
5. Runtime commands
6. Observed results
7. Proven claims
8. Unproven claims
9. Residual risks
10. Next step
