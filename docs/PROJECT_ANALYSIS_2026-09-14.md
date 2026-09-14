# AEGIS NIDS Windows — รายงานวิเคราะห์โครงสร้างและทิศทางพัฒนาต่อ

**วันที่วิเคราะห์:** 2026-09-14  
**ขอบเขต:** repository ปัจจุบันใน `NIDs_Windows` โดยยึด source code, build graph, runtime imports, contracts และ tests ที่มีอยู่จริง  
**ผลกระทบต่อโค้ด:** รายงานฉบับนี้ไม่แก้ implementation ใด ๆ

## 1. บทสรุปสำหรับการตัดสินใจ

โปรเจกต์นี้ไม่ได้ไม่มีโครงสร้าง แต่กำลังอยู่ในช่วง **migration และ consolidation ที่ยังไม่เสร็จ** โดยมีสองสถาปัตยกรรมซ้อนกันอยู่พร้อมกัน ชุดแรกคือ runtime ที่ถูก refactor มาอยู่ใต้ `src/` และใช้ `src/main.zig` เป็น entrypoint ส่วนชุดที่สองคือสถาปัตยกรรมแบบ multi-language golden path ที่เอกสารระบุว่า Go Nose ต้องส่ง `CanonicalEvent` เข้า Zig ผ่าน pipe แล้วไหลต่อไปยัง policy และ Rust PEP

**สิ่งที่ทำงานจริงในปัจจุบัน** คือ Zig daemon ที่รับ event จาก Npcap, ETW/FIM/Registry และ named pipe เก่า จากนั้นประมวลผลด้วย `event.IpcEvent` ผ่าน `src/pipeline/event_processor.zig` แล้วเรียก Zig policy IR และ Rust PEP ในบางกรณี [1] [2] [3] ขณะที่ Go Nose และ `src/capture/nose_pipe_reader.zig` ซึ่งควรเป็นเส้นทาง Canonical Event ยังไม่ได้ถูกผูกเข้ากับ runtime path ของ daemon อย่างชัดเจน [6] [7]

ดังนั้นสถานะที่เหมาะสมในการเรียกโปรเจกต์ตอนนี้คือ:

> **Security-oriented NIDS prototype ที่มี runtime spine ใช้งานได้บางส่วน และมี proof/documentation จำนวนมาก แต่ยังไม่ใช่ production architecture ที่ contract และ golden path สอดคล้องกันทั้งระบบ**

ผมไม่แนะนำให้เพิ่ม detector, dashboard, federation feature หรือ enforcement feature ใหม่ในทันที จุดคอขวดคือการทำให้ **event contract, policy contract, ingestion path และ enforcement semantics เหลืออย่างละหนึ่งความจริง** ก่อน

## 2. ภาพรวมสิ่งที่โปรเจกต์มีอยู่แล้ว

โครงสร้างโดยเจตนาของระบบมีชั้นสำคัญครบเกือบทั้งหมด ได้แก่การรับข้อมูล, normalization, event queue, flow state, detection, threat tracking, policy, Rust PEP, forensic trace, control plane และ operational tooling โค้ดชุดนี้มีความพยายามด้าน security architecture สูง เช่นการแยก PEP ออกจาก detection, การมี decision trace, การมี health state และการมี policy signing module

ตารางต่อไปนี้แยก **ความสามารถที่มีโค้ด** ออกจาก **ความสามารถที่เป็น runtime truth**:

| พื้นที่ | สิ่งที่มีใน repository | สถานะจากการตรวจ | ความหมาย |
|---|---|---|---|
| Runtime entrypoint | `src/main.zig` → `win32_service` → `daemon.runDaemon()` | **ใช้งานจริง** | เป็นจุดเริ่ม process ปัจจุบัน [1] [2] |
| Packet ingestion | Npcap ผ่าน `src/pipeline/packet_callback.zig` | **ใช้งานจริงใน daemon** | แปลง packet เป็น `IpcEvent` และ push เข้า queue [2] |
| Host telemetry | ETW, FIM, Registry threads | **ถูก spawn ใน daemon** | เป็น worker ที่ runtime พยายามเริ่ม [2] |
| Legacy named-pipe sensor | `\\.\pipe\aegis_sensor_pipe` ใน `src/core/nids_capture.zig` | **ถูก spawn ใน daemon บน Windows** | มีเส้นทาง submit เข้า fabric และมี direct analysis ซ้ำ [2] [8] |
| Go Nose capture | `nose/main.go`, `nose/pipe_writer.go` | **มี implementation แต่ไม่ใช่ daemon golden path ปัจจุบัน** | default pipe คือ `\\.\pipe\aegis_nose` [7] |
| Nose reader | `src/capture/nose_pipe_reader.zig` | **ยังไม่ถูกผูกเข้ากับ main build** | เอกสารในไฟล์ระบุเองว่า deferred และไม่อยู่ใน `build.zig` main target [6] |
| Internal pipeline | `event_queue` → `event_processor` | **ใช้งานจริง** | ใช้ `event.IpcEvent` เป็น event หลัก [3] [4] |
| Policy loading | `configs/policies.json` → `policy.PolicySet` | **ใช้งานจริง** | daemon parse policy แบบ simplified [2] |
| TypeScript policy | `ts_policy` compiler/types/seal | **authoring/support** | ยังไม่เห็น runtime handoff ที่ daemon ใช้เป็น source ของ policy [10] [11] |
| Rust PEP | `rust-src/lib.rs` + `pep_bindings.zig` | **เป็น enforcement boundary ที่ถูกเรียก** | FFI ถูกเรียกจาก event processor [3] [13] [14] |
| Forensics | `ForensicRing`, decision trace, forensic pipeline | **ถูกเรียกใน active pipeline** | มีการ append หลังการตัดสินใจ [3] |
| Control plane | Windows named pipe + `tools/aegisctl.py` | **มี runtime/control implementation** | เป็น management path แยกจาก event path [1] [2] |
| Federation TLS | Rust module | **ยังมีลักษณะ stub** | code สร้าง config ด้วย empty roots และ no client auth [14] |
| Documentation truth | manifest, architecture docs, phase docs | **ไม่ตรงกันหลายจุด** | มี SHA และ path ที่เก่ากว่า source ปัจจุบัน [16] |

## 3. Runtime path ที่เกิดขึ้นจริงในปัจจุบัน

เส้นทางที่ควรใช้เป็น baseline ในการจัดระเบียบคือเส้นทางนี้:

```text
src/main.zig
  -> platform/win32_service.zig
  -> daemon.runDaemon()
       -> load configs/Rules.json
       -> load configs/policies.json into policy.PolicySet
       -> initialize PepEnforcer
       -> initialize ActionDispatcher
       -> Windows only:
            bridge_init.initAll()
            spawn src/core/nids_capture.zig
            spawn pipelineLoop()
            spawn Npcap captureThread()
            spawn ETW thread
            spawn FIM thread
            spawn Registry thread
            serve control pipe

Npcap / ETW / FIM / Registry / legacy sensor pipe
  -> pipeline/event_queue.zig
  -> pipeline/event_processor.zig
       -> FlowTable
       -> Aho-Corasick signature matching
       -> AnomalyDetector
       -> ThreatTracker
       -> policy.PolicySet.evaluate()
       -> pep.PepEnforcer.enforce()
       -> ActionDispatcher.dispatch()
       -> ForensicRing.append()
```

หลักฐานสำคัญคือ `daemon.zig` import `policy_ir`, `pep_bindings`, `forensic_pipeline`, `action_dispatcher`, `pipeline/event_processor` และ `core/nids_capture` โดยตรง [2] ส่วน `event_processor.zig` รับ `queue.QueuedEvent` ซึ่งภายในมี `event.IpcEvent` และเรียกทุก stage ใน active path [3]

### สิ่งที่ไม่ได้อยู่ใน path นี้

`src/capture/nose_pipe_reader.zig` ไม่ได้ถูก import โดย daemon และไฟล์ระบุว่าไม่อยู่ใน main target ของ `build.zig` [6] ขณะเดียวกัน Go Nose เขียนไปที่ `\\.\pipe\aegis_nose` [7] แต่ daemon เปิด `\\.\pipe\aegis_sensor_pipe` ผ่าน legacy sensor [8] จึงสรุปได้ว่า **Go Nose canonical acquisition path ยังเป็น intended path ไม่ใช่ current production path**

นี่เป็นข้อค้นพบที่สำคัญที่สุดของรายงาน เพราะเอกสารหลายไฟล์ประกาศว่า Go Nose เป็น canonical acquisition authority แต่ runtime ปัจจุบันยังรับข้อมูลผ่าน Npcap/legacy sensor โดยตรง

## 4. จุดที่ทำให้รู้สึกว่าโปรเจกต์ “ทำมั่ว”

อาการดังกล่าวเกิดจากการสะสมของงานหลาย phase ไม่ใช่จากการไม่มีการออกแบบ สาเหตุหลักมี 5 ประการ

### 4.1 มี event model สองชั้น แต่ชื่อทำให้เข้าใจว่าเป็นสิ่งเดียวกัน

ระบบมี `event.IpcEvent` ใน `src/contract/event.zig` ซึ่งเป็น internal runtime event ขนาด 96 bytes และมี `CanonicalEvent` ใน `src/contract/canonical_event.zig` ซึ่งเป็น cross-language model แบบ logical struct ขนาด 128 bytes พร้อม explicit wire payload 109 bytes [4] [5]

การมี internal representation กับ wire representation แยกกันไม่ใช่ปัญหาโดยตัวมันเอง แต่ปัญหาในปัจจุบันคือเอกสารเรียกทั้งสองแบบว่า canonical และหลาย module ใช้คำว่า `CanonicalEvent` ทั้งที่ active pipeline ใช้ `IpcEvent` อยู่จริง จึงไม่ชัดว่า field ไหนเป็น authority และ event ถูกแปลงตรงจุดใด

นอกจากนี้ `event.zig` ยังมี comment และ test ที่ไม่สอดคล้องกันเอง: constant บังคับขนาด 96 bytes แต่ test ท้ายไฟล์คาดหวัง 80 bytes [4] นี่เป็นสัญญาณว่ามี schema revision ค้างอยู่ในไฟล์เดียวกัน

### 4.2 Go Nose มีอยู่ แต่ยังไม่ได้เชื่อมกับ runtime ที่ start จริง

Go Nose มี serializer สำหรับ wire event 109 bytes และ writer ที่ส่ง frame แบบ `u32 length + payload` ไปยัง `aegis_nose` [7] Zig reader ก็รองรับ frame รูปแบบนี้ [6] แต่ daemon ไม่ได้ start reader ดังกล่าว และ `build.zig` ไม่ได้เพิ่ม reader เป็น active runtime target [6] [15]

ผลคือมี contract ที่ดูสมบูรณ์ในระดับไฟล์ แต่ยังไม่มีหลักฐานว่า event จาก Go Nose เดินทางถึง `event_processor` ของ daemon จริงใน path ปัจจุบัน

### 4.3 Legacy sensor มีสองพฤติกรรมใน request เดียว

`src/core/nids_capture.zig` รับ payload แล้วทำสองอย่างต่อเนื่อง:

1. สร้าง event และ submit เข้า event fabric ผ่าน `nose_int.submit()`
2. เรียก `nids_analyze.inspect_packet()` โดยตรงอีกครั้ง

นั่นหมายถึง sensor เดียวมีโอกาสทำให้เกิดทั้ง fabric submission และ direct analysis ใน request เดียว [8] แม้ `nids_analyze.zig` จะถูกอธิบายในเอกสารว่าเป็น migration wrapper แล้ว แต่การเรียก direct analysis ยังทำให้เส้นทางประมวลผลไม่เป็น single path ที่พิสูจน์ได้

ยิ่งไปกว่านั้น หาก analysis เกิด error โค้ดนี้แสดงผลว่า event “allowed (fail-open)” [8] พฤติกรรมนี้ควรเป็น policy ที่ตัดสินใจอย่างชัดเจน ไม่ควรซ่อนอยู่ใน sensor adapter เพราะทำให้ความหมายของ failure ต่างกันตาม source

### 4.4 Policy contract มีอย่างน้อยสามชุด

ปัจจุบันมี policy representation ที่ทับซ้อนกันดังนี้:

| ชุด | ไฟล์หลัก | ลักษณะ |
|---|---|---|
| Runtime policy | `src/policy/policy_ir.zig` | `PolicySet`, `Predicate`, `Condition`, `Action`; daemon ใช้โหลด `configs/policies.json` [2] [9] |
| Authoring/compiler model | `ts_policy/src/types.ts`, `compiler.ts`, `seal.ts` | TypeScript สร้างและ seal policy [10] [11] |
| Rewrite/signing model | `src/policy/policy_plane.zig`, `policy_signing.zig` | มี `PolicyIR`, Ed25519 signing และ verification [12] |

`src/policy/policy_contract.zig` ยังบันทึก mismatch โดยตรง เช่น TypeScript ใช้ magic `POL1` แต่ Zig contract ใช้ `POLI` และชุด condition type ของ TypeScript กับ Zig ไม่ตรงกัน [12]

นอกจากนี้ TypeScript `seal.ts` ระบุว่าใช้ HMAC เป็น temporary seal และ Ed25519 เป็นงาน follow-up [11] แต่ Zig `policy_signing.zig` มี Ed25519 signing แล้ว [12] จึงยังไม่มี policy lifecycle เดียวที่ตอบได้ว่า policy ใดถูก author, compile, sign, load และ verify ใน production

### 4.5 เอกสาร truth ไม่ได้ผูกกับ revision ปัจจุบัน

`runtime_manifest.json` ระบุ `head_sha` เป็น `688ab566...` ขณะที่ revision ที่ตรวจได้จาก repository คือ `c9ebc16...` นอกจากนี้ `ARCHITECTURE_CANONICAL.md`, `COMPONENT_MATRIX.md`, `runtime-path.md` และ baseline ต่างช่วงเวลากัน และบางไฟล์ยังอ้าง `core/`, `nids_main.zig`, bridge/brain/aggregator process model ที่ไม่ตรงกับ daemon ปัจจุบัน [16] [17] [18]

ผลคือการอ่านเอกสารอย่างเดียวทำให้เห็นระบบที่ดูเสร็จมากกว่าที่ runtime ทำจริง ขณะที่การอ่าน source อย่างเดียวก็ทำให้ไม่เห็นเป้าหมาย migration เดิม จึงต้องมี “runtime truth” ฉบับเดียวที่อ้างอิง revision ปัจจุบันเสมอ

## 5. ประเด็นความเสี่ยงที่ควรแก้ก่อนเพิ่ม feature

| ระดับ | ประเด็น | หลักฐาน | ผลกระทบ |
|---|---|---|---|
| **P0** | Ingestion path ไม่เป็นเส้นเดียว | daemon start `aegis_sensor_pipe` และ Npcap แต่ Go Nose/reader ใช้ `aegis_nose` และไม่ถูกผูกเข้า daemon [2] [6] [7] [8] | event อาจเข้าไม่ถึง path ที่เอกสารอ้าง และการทดสอบ golden path อาจทดสอบคนละระบบ |
| **P0** | PEP ไม่ได้รับ requested policy action โดยตรง | `event_processor` ส่ง event + policy เข้า `PepEnforcer`, แต่ `PepRequest` ไม่มี action field และ Rust ตัดสินจาก capability, severity และ quota [3] [13] [14] | policy `block` อาจไม่ block ตาม action และ policy ที่ไม่ได้ขอ block อาจถูก block เมื่อ severity สูง |
| **P0** | caller identity ถูกแทนด้วยค่าคงที่ | `event_processor` ส่ง `caller_pid=0` และ `caller_caps=0xFFFFFFFF` [3] | capability control กลายเป็นการให้สิทธิ์เต็มแก่ทุก event และไม่สามารถ audit ผู้เรียกจริงได้ |
| **P0** | มี direct analysis และ fail-open ใน legacy sensor | `nids_capture.zig` submit เข้า fabric แล้วเรียก `inspect_packet()` อีกครั้ง และ error ถูก map เป็น allowed [8] | duplicate decision, accounting ผิด, และ failure ของ security analysis อาจกลายเป็น allow |
| **P1** | Event contract ซ้อนกันและมี stale size assertion | `IpcEvent` 96 bytes กับ `CanonicalEvent` 128/109 bytes; test `IpcEvent` คาด 80 bytes [4] [5] | field mapping และ cross-language compatibility ตรวจยากมาก |
| **P1** | Policy contract ข้ามภาษาไม่ตรงกัน | magic, condition ordinals และ signing semantics แตกต่างกัน [10] [11] [12] | policy ที่ compile ได้ใน TypeScript อาจไม่ตีความเหมือนใน Zig |
| **P1** | Federation TLS ยังเป็น stub | Rust ใช้ empty root store และ `with_no_client_auth()` [14] | ไม่ควรอ้างว่า federation production ใช้ mTLS จนกว่าจะมี implementation และ test จริง |
| **P1** | Static tests ถูกใช้แทน runtime proof | golden path test ระบุว่า static tests ผ่านได้โดยไม่มี component ทำงาน และ live tests skip ได้ [19] | CI อาจเขียวทั้งที่ pipe endpoint และ process wiring ใช้งานจริงไม่ได้ |
| **P2** | Pipe framing ยังไม่ robust ต่อ partial read | reader เรียก `ReadFile` ครั้งเดียวต่อ header/payload และถือว่าอ่านไม่ครบคือ drop [6] | frame อาจถูกทิ้งเมื่อ Windows pipe คืนข้อมูลไม่ครบใน read เดียว |
| **P2** | เอกสารอ้าง TCP fallback แต่ writer ไม่มี socket implementation | `pipe_writer.go` มี `useSocket` field แต่ `dialPipe()` ใช้ `os.OpenFile` อย่างเดียว [7] | non-Windows test path ที่เอกสารสัญญาไว้อาจไม่ทำงานจริง |
| **P2** | Build graph ยังรวม proof/tool path หลายชุด | `build.zig` compile main, all tests, fuzz และ core tools พร้อม optional import libraries [15] | ขอบเขต “production”, “proof” และ “operator tool” ยังแยกไม่ชัด |

## 6. โครงสร้างเป้าหมายที่แนะนำ

ผมแนะนำให้จัดระบบโดย **ไม่รื้อทุกอย่างพร้อมกัน** และยอมรับว่ามี internal event representation กับ wire representation ได้ แต่ต้องตั้งชื่อและ authority ให้ชัด

### 6.1 Runtime spine เดียว

```text
[Ingress adapters]
  Npcap / ETW / FIM / Registry / Go Nose (เลือกและประกาศให้ชัด)
        |
        v
[Canonical ingress adapter]
  validate + assign event_id + provenance + schema version
        |
        v
[RuntimeEvent]
  internal Zig representation used by queue and pipeline
        |
        v
[One event_processor]
  flow -> detection -> tracking -> policy decision -> PEP -> forensic
        |
        v
[ActionResult]
  executed / denied / deferred / failed / not_applicable
        |
        v
[Forensic trace + metrics + operator output]
```

ข้อเสนอเชิงชื่อคือให้ `CanonicalEvent v1` หมายถึง **cross-process wire contract เท่านั้น** และเปลี่ยนชื่อ `IpcEvent` เป็น `RuntimeEvent` หรือ `InternalEvent` เพื่อไม่ให้ทั้งสองชนิดแย่งความหมายของคำว่า canonical

### 6.2 Policy authority เดียว

กำหนด lifecycle เดียว:

```text
TypeScript authoring
  -> canonical JSON/IR
  -> Zig structural validation + deterministic policy evaluation
  -> Rust Ed25519 verification + rollback/expiry check
  -> Rust PEP receives explicit requested_action
  -> ActionResult
```

`policy_plane.zig` และ `policy_signing.zig` ควรเป็น contract implementation เดียวที่เลือกใช้ หรือถูกยุบให้เหลือ module เดียว ส่วน `policy_ir.zig` ควรเป็น runtime evaluator ที่รับ IR เดียวกัน ไม่ควรมี JSON policy format ที่มี semantics อีกชุดแยกต่างหาก

### 6.3 PEP request ต้องมีข้อมูลที่เพียงพอ

`PepRequest` ควรมีอย่างน้อย:

| Field | เหตุผล |
|---|---|
| `requested_action` | ทำให้ Rust PEP ตัดสินจาก policy action จริง ไม่ใช่เดาจาก severity |
| `policy_id` | เชื่อม decision กับ policy |
| `policy_version` | ตรวจ rollback และ audit version |
| `caller_pid` หรือ authenticated caller identity | ตรวจผู้ร้องขอจริง |
| `capability_mask` ที่ derive จาก caller | ไม่ให้ event pipeline ให้สิทธิ์เต็มเอง |
| `request_id` | idempotency, approval และ trace |
| `event_id` | เชื่อมกับหลักฐานต้นทาง |

Rust PEP ควรเป็นผู้ตัดสินว่าจะ execute, deny, defer หรือ fail และควรส่ง `ActionResult` กลับมาให้ Zig บันทึกโดยไม่ตีความว่า “เรียก function สำเร็จ” เท่ากับ “enforcement สำเร็จ”

## 7. แผนจัดระเบียบแบบทีละระยะ

### ระยะ 0 — Freeze และทำ runtime inventory

**เป้าหมาย:** หยุดการขยายความสับสนก่อนแก้โครงสร้าง

1. กำหนด `src/main.zig` + `src/daemon.zig` เป็น current runtime baseline
2. ทำตาราง file classification ใหม่เป็น `ACTIVE`, `ADAPTER`, `PROOF`, `TEST`, `LEGACY`, `OPTIONAL`
3. บันทึก import graph ของ daemon และ build graph ของ `build.zig`
4. แยกเอกสารที่อธิบาย current state ออกจากเอกสาร target state
5. ห้ามลบไฟล์จนกว่าจะพิสูจน์ว่าไม่มี runtime, build, test หรือ deployment dependency

**ผลลัพธ์ที่ควรได้:** `docs/architecture/RUNTIME_TRUTH.md` ที่มี revision, entrypoint, spawned workers, endpoints และ active contracts ครบถ้วน

### ระยะ 1 — Freeze event contract

**เป้าหมาย:** ให้ทุกคนรู้ว่า event แบบใดเป็น internal และแบบใดเป็น wire

1. ตัดสินใจใช้ `CanonicalEvent` เป็น cross-process contract
2. เปลี่ยนชื่อหรือทำเอกสารชัดเจนให้ `IpcEvent` เป็น internal runtime type
3. เพิ่ม adapter เดียวจาก Go wire event ไป runtime event
4. สร้าง golden vectors ชุดเดียวที่ตรวจ magic, version, size, endian, enum และ field offsets ใน Zig, Go, Rust และ C
5. แก้ test ที่คาด 80 bytes ให้ตรงกับ contract ที่เลือก หรือยกเลิก test ถ้าเป็น stale contract

**เกณฑ์ผ่าน:** event เดียวที่ส่งจาก source ใด source หนึ่งเข้า runtime ได้ครบหนึ่งครั้ง และมี byte-level test ข้ามภาษา

### ระยะ 2 — เลือก ingestion path เดียว

มีสองทางเลือกที่ถูกต้อง แต่ไม่ควรคงไว้พร้อมกัน:

| ทางเลือก | เมื่อควรเลือก | งานที่ต้องทำ |
|---|---|---|
| **A: ใช้ Npcap/host adapters เป็น ingress หลักก่อน** | ต้องการให้ runtime ปัจจุบันเสถียรเร็ว | mark Go Nose/reader เป็น optional, หยุดอ้างว่าเป็น golden path, ลบ direct legacy analysis และรวม sensor submit ให้เข้า queue เดียว |
| **B: ใช้ Go Nose เป็น ingress หลัก** | ต้องการให้ multi-process acquisition เป็นสถาปัตยกรรมหลัก | wire `nose_pipe_reader` เข้า daemon, ใช้ endpoint เดียว, เพิ่ม process supervision และ live Windows E2E |

สำหรับการจัดระเบียบครั้งแรก ผมแนะนำ **A เป็น short-term stabilization** แล้วค่อยทำ B เป็น migration slice แยกต่างหาก เพราะ A ใช้ active path ที่มีอยู่จริงและลดจำนวน moving parts ก่อน

ไม่ว่าจะเลือกทางใด ต้องลบหรือปิด direct call `nids_analyze.inspect_packet()` จาก sensor path เพื่อให้ event มีเจ้าของการประมวลผลเพียงหนึ่งจุด

### ระยะ 3 — ทำ policy และ PEP semantics ให้ตรงกัน

1. เพิ่ม `requested_action` ใน PEP ABI
2. หยุดส่ง `caller_caps=0xFFFFFFFF` จาก event pipeline
3. กำหนด source ของ caller identity และ capability อย่างชัดเจน
4. ทำให้ Rust ใช้ policy action ที่ verify แล้ว ไม่ใช่ใช้ severity เป็น action โดย implicit
5. แยก `Decision`, `Authorization`, `Execution` และ `ActionResult`
6. เพิ่ม tests ที่พิสูจน์อย่างน้อย `allow`, `alert`, `block`, `rate_limit`, `quarantine`, `denied`, `deferred`, `WFP unavailable`

### ระยะ 4 — ทำ documentation และ CI ให้สะท้อนความจริง

1. regenerate `runtime_manifest.json` จาก current revision ไม่เขียน SHA ด้วยมือ
2. แยก static contract tests ออกจาก live Windows tests ให้เห็นผลคนละหมวด
3. เพิ่ม test ที่ fail เมื่อ endpoint ใน writer, reader และ daemon ไม่ตรงกัน
4. เพิ่ม Windows elevated build/test job สำหรับ Npcap, WFP และ PEP DLL
5. เปลี่ยนคำว่า “REAL”, “production”, “golden path” ให้ใช้ได้เมื่อมี runtime evidence ไม่ใช่แค่ module test
6. mark federation TLS เป็น `PROOF/STUB` จนกว่าจะมี certificate validation และ mTLS integration test จริง

### ระยะ 5 — ค่อยพัฒนาฟีเจอร์ต่อ

หลังระยะ 0–4 ผ่านแล้วจึงค่อยเพิ่ม detector, RAG, dashboard, federation และ advanced enforcement โดยทุก feature ต้องระบุให้ครบว่า:

- รับ input จาก contract ใด
- อยู่ stage ใด
- มี authority หรือเป็น advisory
- มี failure behavior อย่างไร
- เขียน forensic record ตรงไหน
- มี unit, contract และ live integration test แบบใด

## 8. ลำดับ commit ที่แนะนำ

เพื่อป้องกันการแก้ใหญ่จนย้อนกลับไม่ได้ ให้แบ่งงานเป็น commit เล็กที่แต่ละ commit มี proof ของตัวเอง:

| ลำดับ | Engineering idea | หลักฐานที่ต้องเพิ่ม |
|---:|---|---|
| 1 | บันทึก current runtime truth | import/build inventory และ runtime diagram |
| 2 | แยก `RuntimeEvent` ออกจาก `CanonicalEvent` เชิงความหมาย | contract document + size/offset tests |
| 3 | ทำ ingestion ให้เหลือ queue entry เดียว | duplicate-path test และ event-count invariant |
| 4 | ทำ PEP action explicit | ABI test ข้าม Zig/Rust + action matrix |
| 5 | แก้ caller identity/capability | authorization tests ที่ไม่ใช้ all-capability shortcut |
| 6 | รวม policy lifecycle | TS→IR→Zig→Rust golden vector |
| 7 | อัปเดต manifest/docs จาก revision ปัจจุบัน | generated truth check ใน CI |
| 8 | เพิ่ม Windows live E2E | start → send event → observe → decide → forensic |

## 9. Definition of Done ก่อนเริ่ม feature ใหม่

ถือว่าระบบพร้อมกลับไปพัฒนาฟีเจอร์เมื่อผ่านเงื่อนไขต่อไปนี้:

- มี entrypoint production เพียงหนึ่งชุดที่ระบุในเอกสารและตรงกับ `build.zig`
- มี ingress path ที่ประกาศชัดเจนและ event ไม่ถูก process ซ้ำ
- มี cross-process event contract เพียงหนึ่งชุด พร้อม golden vectors ข้ามภาษา
- internal runtime event ไม่ถูกเรียกว่า canonical จนทำให้สับสนกับ wire contract
- policy action ที่ผู้เขียนระบุเดินทางถึง Rust PEP แบบ explicit
- caller identity และ capability ไม่ถูก hard-code เป็นสิทธิ์เต็ม
- PEP แยก `decision` ออกจาก `execution result` และ forensic บันทึกผลจริง
- TypeScript, Zig และ Rust ใช้ magic/version/enum/signing semantics เดียวกัน
- static tests และ live Windows tests แยกผลชัดเจน
- manifest และ architecture truth อ้างอิง revision ปัจจุบันโดยอัตโนมัติ
- มี Windows elevated E2E ที่พิสูจน์เส้นทางจริงอย่างน้อยหนึ่งเหตุการณ์ตั้งแต่ ingress ถึง forensic

## 10. คำตอบตรง ๆ ว่าควรพัฒนาต่อไปทางไหน

ทิศทางที่เหมาะสมไม่ใช่การเพิ่มความสามารถให้ทุก module ที่มีอยู่ แต่คือการทำให้โปรเจกต์กลายเป็น **single-spine, contract-first NIDS** ตามลำดับนี้:

1. ยืนยัน `src/daemon.zig` และ `src/pipeline/event_processor.zig` เป็น runtime ปัจจุบัน
2. ทำให้ event model มีสองชั้นอย่างตั้งใจและมี adapter เดียว
3. เลือก Npcap หรือ Go Nose เป็น ingress หลักในแต่ละช่วง และหยุดการมีสองเส้นทางพร้อมกัน
4. รวม policy model ให้ TypeScript เป็น authoring, Zig เป็น decision orchestration และ Rust เป็น verification/enforcement
5. แก้ PEP ABI ให้ action, identity, policy version และ execution result ครบ
6. ทำ live Windows evidence ให้มาก่อนการอ้างว่าเป็น production หรือ golden path
7. จากนั้นจึงค่อยขยาย detection, dashboard, federation และ automation

ถ้าทำตามลำดับนี้ โค้ดที่มีอยู่จำนวนมากจะไม่สูญเปล่า เพราะส่วนที่เป็น detection, flow, forensic, control และ PEP สามารถเก็บไว้ได้ เพียงแต่ต้องย้ายจากสถานะ “หลาย implementation ที่ดูเหมือน active” ไปเป็น “หนึ่ง implementation ที่มี authority ชัดเจน”

## References

[1]: ../src/main.zig "AEGIS Zig process entrypoint"
[2]: ../src/daemon.zig "AEGIS daemon startup orchestration"
[3]: ../src/pipeline/event_processor.zig "Active event processing pipeline"
[4]: ../src/contract/event.zig "Internal IpcEvent contract"
[5]: ../src/contract/canonical_event.zig "Cross-language CanonicalEvent contract"
[6]: ../src/capture/nose_pipe_reader.zig "Go Nose pipe reader and deferred runtime wiring"
[7]: ../nose/pipe_writer.go "Go Nose canonical event pipe writer"
[8]: ../src/core/nids_capture.zig "Legacy named-pipe sensor path"
[9]: ../src/policy/policy_ir.zig "Runtime Zig policy IR and evaluator"
[10]: ../ts_policy/src/types.ts "TypeScript policy authoring types"
[11]: ../ts_policy/src/seal.ts "TypeScript policy sealing implementation"
[12]: ../src/policy/policy_signing.zig "Zig policy signing and verification"
[13]: ../src/policy/pep_bindings.zig "Zig-to-Rust PEP FFI bindings"
[14]: ../rust-src/lib.rs "Rust PEP implementation and federation TLS module"
[15]: ../build.zig "Master Zig build graph"
[16]: ../runtime_manifest.json "Declared runtime manifest and authority map"
[17]: architecture/ARCHITECTURE_CANONICAL.md "Declared canonical architecture"
[18]: runtime/COMPONENT_MATRIX.md "Declared component and endpoint matrix"
[19]: ../tests/runtime/test_golden_path.py "Static and live golden-path tests"
