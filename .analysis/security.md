# AEGIS NIDS Windows — PEP และ Enforcement Security Review

**ขอบเขตการตรวจ:** `rust-src`, `src/policy`, `src/core/rust_pep.zig`, `src/windows/aegis_wfp.c`, `src/windows/wfp_ioctl.c`, WFP driver/callout, Shield, policy/rules configuration และ privileged action ทุกจุดที่พบใน source tree

**Revision ที่ใช้ตรวจ:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` (current `HEAD`)

**Revision ที่ไม่ใช้เป็นหลักฐาน:** `688ab56` และ machine maps ที่ชี้ไป revision นี้ถือเป็น stale ตามโจทย์

**สถานะหลักฐาน:** รายงานนี้เป็น **static source review** เป็นหลัก ยังไม่มี runtime proof บน Windows จริง ไม่มีหลักฐานว่าผล WFP filter ถูกติดตั้งและมีผลกับ traffic ใน host เป้าหมาย และไม่มีหลักฐานว่า artifact ที่ deploy ตรงกับ source revision นี้

---

## 1. บทสรุปผู้บริหาร

AEGIS มีแนวคิดให้ Rust PEP เป็น authority เดียวของ privileged enforcement และมี fail-closed บางชั้นที่เขียนไว้ชัดเจน แต่เส้นทางที่ตรวจพบยัง **ไม่ควรประกาศเป็น production prevention system**. จุดที่สำคัญที่สุดมีสามกลุ่ม

1. **Policy authenticity ยังไม่อยู่ใน active load path.** `daemon.runDaemon()` โหลด `configs/Rules.json` และ `configs/policies.json` เป็น JSON ธรรมดา แล้วสร้าง `PolicySet` โดยไม่เรียก `verifyPolicy()` หรือ `verifyPolicyWithStore()`. โมดูล Ed25519 ใน `src/policy/policy_signing.zig` มี implementation และ tests แต่ยังไม่ถูกผูกเข้ากับ startup, reload หรือ PEP request. `PolicyCompiler` ยังเก็บ SHA-256 fingerprint 64 บิตลง field ชื่อ `signature` และมีคอมเมนต์ยอมรับว่าไม่ใช่ Ed25519. ดังนั้น static evidence มีเพียง “มี verifier” ไม่ใช่ “ทุก policy ที่ enforce ผ่าน verifier”.

2. **PEP FFI บางส่วน fail-closed ต่อ WFP failure แต่ยังเชื่อ caller-supplied authority.** Zig สร้าง `caller_pid` และ `caller_capability_mask` แล้วส่งเข้า Rust; Rust เชื่อ capability bit `0x01` โดยไม่ได้ bind PID กับ Windows token/SID/integrity level. `request_id`, `policy_version`, policy signature และ nonce ไม่ได้ถูกใช้เป็น freshness/replay/authentication gate ใน `aegis_pep_enforce()`. ค่า capability ถูกตั้งเป็น `0x01` ใน daemon เอง. หากมี caller อื่นเข้าถึง DLL หรือ device ได้ ขอบเขตนี้ไม่ใช่ OS-enforced authority.

3. **WFP มีหลาย path และมี ABI/semantic mismatch.** Active-looking Rust PEP path โหลด `aegis_wfp_user.dll` แล้วเรียก mutating IOCTL. ขณะเดียวกัน `src/windows/aegis_wfp.c` ซึ่งถูก compile รวมใน DLL เดียวกันมี direct user-mode WFP API อีกชุดหนึ่ง และ `src/windows/wfp_ioctl.c` เปิด device ด้วย `GENERIC_READ | GENERIC_WRITE`. Kernel device code ไม่มี SDDL/caller authorization ที่เห็นใน source. ส่วน WFP event/stat structs ระหว่าง Zig และ C ไม่ตรงกัน: Zig `WfpEventHeader`/`WfpRingStats` เป็น natural-aligned และขนาด 48/16 bytes ตามลำดับโดย static expectation ใน source ขณะที่ C/driver ใช้ packed 40/24 bytes. นี่เป็น ABI defect ที่ทำให้ telemetry และ readiness ไม่ใช่หลักฐานของ enforcement.

**ข้อสรุปด้านความปลอดภัย:** ระบบควรคงอยู่ใน **detection-only/degraded mode** จนกว่าจะพิสูจน์และปิด direct device access, caller identity binding, mandatory policy signature, replay semantics, ABI contract, WFP filter effect และ final-result audit. ห้ามตีความ `ALLOW`, `PepDecision.block`, `ActionDispatcher` log หรือ unit-test success ว่าเป็นหลักฐานว่า traffic ถูก block จริง

---

## 2. เส้นทางที่ตรวจพบจาก actual call graph

### 2.1 Active daemon path ที่มีหลักฐานจาก source

เส้นทาง production entry ที่ตรวจได้จาก current source คือ

```text
src/main.zig
  -> platform/win32_service.mainEntry()
  -> daemon.runDaemon()
       -> SecurityCheck
       -> load configs/Rules.json into Aho-Corasick
       -> load configs/policies.json into PolicySet
       -> pep.PepEnforcer.init()                 [aegis_pep.dll FFI]
       -> spawn pipeline/event_processor.pipelineLoop()
       -> Go Nose / sensor / ETW / FIM / registry workers
       -> event_processor.processEvent()
            -> detection and threat tracking
            -> PolicySet.evaluate()
            -> pep.PepEnforcer.enforce()
                 -> aegis_pep_enforce()
                 -> Rust WFP adapter
                 -> aegis_wfp_ioctl_block_ip()
                 -> DeviceIoControl(IOCTL_AEGIS_BLOCK_FLOW)
                 -> kernel AegisWfpBlockFlow()
                 -> FwpmFilterAdd0()
            -> ActionDispatcher.dispatch()       [logging/federation/forensics; not WFP]
            -> ForensicRing.append()
```

หลักฐานสำคัญคือ `src/main.zig:20-35`, `src/daemon.zig:85-119`, `src/daemon.zig:179-298`, `src/daemon.zig:308-329`, `src/daemon.zig:383-425`, `src/pipeline/event_processor.zig:152-173` และ `rust-src/lib.rs:339-426`.

`src/policy/dispatcher.zig` และ `src/policy/dispatcher_phase_b.zig` เป็น dispatcher อีกชุดหนึ่งที่มี pipeline `Event Fabric -> ... -> Rust PEP -> Forensics` ตามคอมเมนต์ แต่ README ระบุเองว่ายังมี runtime spine/dispatcher ซ้อนกันและห้ามอ้างว่าเป็น production golden path จนกว่าจะมี call graph จาก entrypoint. ใน active daemon ที่ตรวจได้ `event_processor.pipelineLoop()` เป็น owner ที่เห็นการถูกเรียกจาก `daemon.runDaemon()`; จึงต้องแยก alternate dispatcher นี้ออกจาก runtime proof.

### 2.2 Active PEP path กับ alternate simulation path

มีอย่างน้อยสาม implementation ที่ชื่อหรือบทบาทคล้าย PEP

| Path | สิ่งที่ source แสดง | สถานะหลักฐาน |
|---|---|---|
| `src/policy/pep_bindings.zig` -> `aegis_pep.dll` | FFI boundary ที่ active daemon ส่ง request เข้า Rust | เป็น active-looking path; ยังต้อง Windows build/runtime proof |
| `src/core/rust_pep.zig` (`RustPep`) | Zig model มี in-memory `AutoHashMap` และบอกว่าของจริงจะเรียก WFP | simulation/compatibility path; ไม่ใช่หลักฐาน WFP effect |
| `src/policy/policy_contract.zig` (`PEP`) | contract model; block เรียก `rust_pep.block_ip`, rate-limit ทำสำเร็จโดยไม่เรียก adapter, quarantine not implemented | alternate contract/test path; มี false-success semantics |

`src/tests/integration/rust_pep_integration.zig` เป็น facade ของ `RustPep` และ unit test คาดหวัง `.executed`/in-memory blocked map. มันไม่ได้พิสูจน์ `aegis_pep.dll`, `aegis_wfp_user.dll`, driver หรือ `FwpmFilterAdd0` บน Windows.

### 2.3 WFP telemetry path กับ WFP mutation path

`src/policy/wfp_ioctl.zig` ระบุว่าตนเป็น read-only telemetry และเปิด device ด้วย `GENERIC_READ`; path นี้มี `IOCTL_AEGIS_READ_EVENTS` และ `IOCTL_AEGIS_GET_STATS`. อย่างไรก็ตาม Rust PEP โหลด C DLL และเรียก `aegis_wfp_ioctl_block_ip`/`aegis_wfp_ioctl_unblock_ip` ซึ่งอยู่ใน `src/windows/wfp_ioctl.c` และเปิด device ด้วย `GENERIC_READ | GENERIC_WRITE`. ดังนั้นมี mutating path จริงแยกจาก read-only Zig wrapper.

นอกจากนี้ CMake root compile `src/windows/aegis_wfp.c` และ `src/windows/wfp_ioctl.c` รวมกันเป็น `aegis_wfp_user`. `aegis_wfp.c` มี direct user-mode `FwpmEngineOpen0`/`FwpmFilterAdd0` API และ exported `aegis_wfp_add_block`, `aegis_wfp_remove_filter`, `aegis_wfp_install`, `aegis_wfp_uninstall`. แม้ไม่พบ active Zig call site ที่เรียก direct exports เหล่านี้ แต่ DLL export surface เป็น alternate privileged authority และต้องถือเป็น attack surface จนกว่าจะลบหรือ gate ที่ OS boundary.

---

## 3. Policy และ rule configuration

### 3.1 `configs/Rules.json` เป็น detection input ไม่ใช่ authenticated policy artifact

`configs/Rules.json` มี `schema_version: "2.0"`, rule IDs เช่น `R0056`, severity และ action เช่น `Drop`, `Block`, `Alert`. `src/pipeline/rule_loader.zig:83-98` ใช้เฉพาะ `rule_id` และ `match_pattern` เพื่อสร้าง Aho-Corasick. ฟิลด์ action, severity, target ports และ target protocols จาก Rules.json ไม่ถูกใช้ใน loader นี้เพื่อ authorize WFP action. Rule ID ถูกแปลงเป็น FNV-1a 32 บิต (`rule_loader.zig:11-19`).

การโหลดครั้งแรกใน daemon (`src/daemon.zig:155-176`) และ hot reload (`rule_loader.zig:22-129`) ไม่ตรวจ Ed25519, policy version, expiry, trust store หรือ digest. การ reload เป็นเพียงการ parse และ swap automaton. ในกรณี parse/load failure ระบบเก็บ ruleset เก่า หรือเริ่มด้วยศูนย์ rule ตาม path ที่เกี่ยวข้อง; นี่เป็น fail-soft สำหรับ detection และไม่ใช่ mandatory security-policy gate.

### 3.2 `configs/policies.json` ถูกนำมาใช้เป็น active policy input แต่ไม่มี signature

`configs/policies.json` มีหก policy หลัก เช่น `block_critical_threats`, `block_signature_match`, `rate_limit_anomaly`, `log_etw_events` และ `alert_injection_detected`. Daemon parse เป็น `policy.Policy` ที่ `src/policy/policy_ir.zig` กำหนด และส่ง `PolicySet` เข้า `event_processor`.

ข้อจำกัดเชิง semantics ที่ตรวจได้จาก source มีดังนี้

* `PolicySet.evaluate()` คืน **policy แรก**ที่ match (`policy_ir.zig:104-109`) ไม่มี priority/specificity arbitration.
* parser ใน daemon สร้างเพียงหนึ่ง predicate ในหนึ่ง clause และอ่านเฉพาะ first clause/first predicate (`daemon.zig:240-280`). Multi-clause/multi-predicate ที่ผู้เขียน policy อาจตั้งใจไม่ได้ถูก enforce ตาม representation เต็ม.
* `gte` ถูกแปลงเป็น `gt` (`daemon.zig:262-264`). ดังนั้น policy `severity >= 6` ใน config จะไม่ match ค่า severity 6 ที่เป็น `critical`; จะ match เฉพาะค่ามากกว่า 6 เช่น `alert`/`emergency`.
* `PolicyCondition.in` ใน `policy_plane.zig:95-103` และ `policy_ir.zig:153-161` ถูกลดรูปเป็น equality; range/set semantics ไม่สมบูรณ์.
* `ttl_sec` ถูก parse และเก็บ แต่ `PolicySet.evaluate()` ไม่ใช้ TTL. ไม่พบ expiry enforcement ของ policy rule ใน active pipeline.
* ถ้า policy file หาย/parse ไม่ได้ daemon แค่ log warning แล้ว `PolicySet` ว่าง (`daemon.zig:184-214`). ไม่มี stop-the-line หรือ fail-closed prevention state จาก policy absence.
* action string ที่ไม่รู้จักถูกแปลงเป็น `.pass` (`daemon.zig:228-230`) โดยไม่มี error/deny. นี่เป็น silent downgrade ของ privileged intent.
* ไม่มี policy digest/version/signature ถูกส่งเข้า `PepRequest`; `PepContext.policy_version` default เป็นศูนย์ (`pep_bindings.zig:26-31, 86-97`).

### 3.3 Policy engine รุ่นอื่นมี default allow และไม่เชื่อมกับ signed IR

`src/policy/policy_engine.zig` เป็น planner อีกตัวที่ตัดสินจาก aggregated verdict, brain, threat intel และ correlation. มันมี priority hard-coded และ default `.allow` สำหรับ `unknown`/policy absent. `src/tests/integration/policy_integration.zig:45-71` ก็ return `allow` เมื่อไม่ initialized. นี่เป็น safety containment ได้ในมุม “ไม่บล็อกโดยไม่มี planner” แต่ไม่ใช่ fail-closed prevention; หาก deployment ต้องการ block guarantee จะเกิด false negative.

`src/policy/policy_plane.zig:224-291` มี compiler ที่คำนวณ SHA-256 ของ rule array แต่เก็บเพียง 64 บิตใน `ir.hash` และทำ `ir.signature = hash`; คอมเมนต์ระบุชัดว่า Ed25519 ยังไม่ถูกเพิ่ม. ขณะที่ `src/policy/policy_signing.zig` มี Ed25519 จริง, expiry และ rollback check. จาก source ที่ตรวจไม่พบ call จาก `daemon.runDaemon()` หรือ `rule_loader` ไปยัง `signPolicy`, `verifyPolicy` หรือ `verifyPolicyWithStore`.

---

## 4. PEP authority, authorization และ ABI

### 4.1 สิ่งที่ PEP ป้องกันได้ใน source

`src/policy/pep_bindings.zig:79-105` มี containment ที่ถูกต้องบางส่วน

* PEP ไม่พร้อม -> คืน `.escalate`, ไม่คืน `.allow`.
* FFI return code ไม่เป็นศูนย์ -> คืน `.escalate`.
* `unblockIp()` คืน false เมื่อ PEP ไม่พร้อมหรือ FFI error.
* มี tests ยืนยัน unavailable/failure ไม่ถูก map เป็น allow.

`rust-src/lib.rs:350-420` ก็ตั้งใจ default ไม่ให้ action privileged สำเร็จจนกว่าการ authorize และ WFP adapter จะสำเร็จ. สำหรับ `ACTION_BLOCK`, Rust จะเปลี่ยนผลเป็น `DECISION_ESCALATE` ถ้า `Adapter::load()` หรือ `adapter.block()` ล้มเหลว. นี่เป็น static evidence ของ fail-closed เฉพาะ block path นี้.

### 4.2 Authority ที่ยังเป็น caller-supplied

ใน daemon (`src/daemon.zig:121-125`) runtime ตั้ง

```text
state.g_runtime_pid = GetCurrentProcessId()
state.g_runtime_capability_mask = 0x01
```

แล้ว `event_processor` ส่งค่าดังกล่าวเข้า `PepEnforcer.enforce()` (`event_processor.zig:155-164`). Rust ตรวจเพียง `(caller_capability_mask & 0x01) != 0` สำหรับ action ที่ constrain/mutate traffic (`rust-src/lib.rs:361-369`). ไม่พบการเรียก Windows `OpenProcessToken`, SID/ACL check, integrity-level check, signer check หรือ binding ของ PID กับ process handle ใน Rust PEP. `caller_pid` ถูกเก็บใน request แต่ไม่ถูกตรวจใน `aegis_pep_enforce`; `aegis_pep_unblock_ip` ทิ้งทั้ง `caller_pid` และ `request_id` (`rust-src/lib.rs:430-450`).

ดังนั้น capability bit เป็น **input ที่ caller ส่งมาเอง** ไม่ใช่ proof ของ authority. หาก DLL ถูกเรียกจาก process อื่นที่มี ABI access หรือ device เปิดได้ การตั้ง bit `0x01` อาจเพียงพอสำหรับ block/unblock. ต้องถือเป็น P0/P1 boundary defect จนกว่าจะมี OS-backed identity binding.

### 4.3 Replay, two-person rule และ quota ยังไม่ใช่ enforcement จริง

Rust `PepState` มี `quotas`, `two_person_rule` และ `pending_approvals` แต่ `two_person_rule` เริ่มเป็น `false` และไม่พบ exported control/config API ที่เปิดใช้. `pending_approvals` ถูกอ่านเฉพาะเมื่อ flag นี้เปิด; ไม่พบ path เติม approval. `aegis_pep_enforce()` ตั้ง `quota_remaining = QUOTA_DEFAULT` คงที่และไม่ increment quota count. `aegis_pep_quota_remaining()` อ่าน map ได้ แต่ map ไม่ถูกเติมใน enforcement path ที่ตรวจ.

`request_id` จึงไม่ใช่ one-time nonce ใน Rust PEP. มันใช้เป็น key สำหรับ pending approval เท่านั้น และไม่มี replay cache, monotonic floor, expiry หรือ persistence. `policy_version` ใน request ไม่ถูกใช้. ผลคือ request เดิมที่มี capability bit สามารถถูกส่งซ้ำได้ในระดับ PEP โดย source ไม่แสดงการปฏิเสธซ้ำ.

### 4.4 Control IPC มี authorization model แต่ยังไม่ผูกกับ PEP path และมีช่องว่าง replay

`src/policy/control_ipc.zig` ออกแบบ role `READ < OPERATE < PRIVILEGED`, ACL explicit, freshness, `(request_id, nonce)` replay check และ audit. นี่เป็น static design evidence ที่ดี แต่ไม่ใช่ runtime proof ว่า Windows named-pipe boundary ใช้ authorizer นี้ก่อน privileged command ทุกครั้ง. README ยังระบุ control contract และ runtime command surfaces ไม่สอดคล้องกัน.

ข้อจำกัดเชิง implementation ที่พบ

* `caller_hash` เป็น FNV-1a ของ identity string; ไม่ใช่ authenticated Windows SID/token. `role`, `caller_hash`, `request_id` และ `nonce` อยู่ใน request ที่ caller ส่ง.
* `seen` มีเพียง 64 entries. เมื่อเต็ม `recordSeen()` ไม่ evict และไม่บันทึก entry ใหม่ (`control_ipc.zig:293-298`). หลังเต็ม request ใหม่จะไม่ถูกจำ replay ใน process อายุยาว.
* `rollKey()` XOR hash ของ request ID กับ nonce (`control_ipc.zig:280-283`) ทำให้ pair ที่ต่างกันอาจชน key ได้; collision ทำให้ legitimate request ถูกปฏิเสธหรือ replay หลุดขึ้นกับรูปแบบ collision.
* `isExpired()` ตรวจเฉพาะ `now_ms > issued_at_ms + timeout_ms`; ไม่ปฏิเสธ request ที่ `issued_at_ms` อยู่ในอนาคต และ addition overflow ไม่ถูกตรวจ.
* audit เป็น ring 1024 entries จึงไม่ใช่ durable audit. ไม่มี cryptographic chain และไม่มีการผูก PEP/WFP adapter result.
* `ControlCommand.fromInt()` ทำ normalization ของค่าที่อยู่นอกช่วงแบบกว้าง ซึ่งต้องตรวจ parser/boundary จริงว่า invalid command ไม่ถูกลดรูปเป็น `status`.

---

## 5. FFI และ ABI findings

### 5.1 Rust PEP request/response layout

จาก source อย่างเดียว layout ที่ประกาศใน Zig และ Rust โดยเจตนาตรงกัน

| Type | Zig expectation | Rust `#[repr(C)]` | Static conclusion |
|---|---:|---:|---|
| `PepContext` | 24 bytes; offsets 0,4,8,16 | fields `u32,u32,u64,u32`; expected 24 bytes | น่าจะตรงบน x64; ต้อง compile-time/assert ข้ามภาษา |
| `PepRequest` | 64 bytes; `flow_id` offset 8, `ctx` offset 40 | same fields/order | น่าจะตรงบน x64; ยังไม่มี generated ABI artifact |
| `PepResponse` | 16 bytes; offsets 0,4,8,12 | `u8,u32,u32,u32` | น่าจะตรงบน x64 |
| decision ordinals | 0..5 | constants 0..5 | ตรงตาม source |

แต่มี static compile inconsistency ใน Rust tests: struct field คือ `PepContext.policy_version` (`rust-src/lib.rs:156-162`) ขณะที่ tests สร้าง field `.reserved` (`rust-src/lib.rs:559-563`). หากไฟล์นี้ถูก compile ตาม current HEAD tests จะไม่ผ่านจนกว่าจะยืนยันว่า source/artifact คนละ revisionหรือแก้ให้ตรงกัน. นี่เป็นหลักฐานว่า “ABI tests มีอยู่” ไม่เท่ากับ “Rust crate current HEAD build ผ่าน”.

`pep_bindings.zig` tests ตรวจขนาด/offset ฝั่ง Zig (`pep_bindings.zig:164-223`) แต่ไม่มี Rust `size_of`/offset export ที่ generated จาก compiler และไม่มี Windows link/runtime proof.

### 5.2 WFP telemetry ABI mismatch: high confidence

`src/windows/wfp_ioctl.c` และ `drivers/kernel/wfp_callout/aegis_wfp.h` ใช้ packed structs

* `AEGIS_WFP_EVENT_HEADER`: `#pragma pack(1)`, 40 bytes.
* `AEGIS_WFP_RING_STATS`: packed six `uint32_t`, 24 bytes.

แต่ `src/policy/wfp_ioctl.zig` ประกาศ `extern struct` ที่ไม่ได้ pack

* `WfpEventHeader` มี fields เดียวกันแต่ `u64 timestamp` ถูก align ตาม ABI; บน x64 คาดว่าจะมี 48 bytes ไม่ใช่ 40.
* `WfpRingStats` มีเพียงสี่ `u32` รวม 16 bytes และ field meaning ไม่ตรงกับ C/driver หก `u32`.

`wfp_ioctl.zig:get_stats()` ส่ง output buffer ขนาด `@sizeOf(WfpRingStats)` และต้องการ bytes อย่างน้อย 16 (`wfp_ioctl.zig:205-225`), ขณะที่ kernel `AegisWfpGetStats()` ปฏิเสธ output ที่เล็กกว่า 24 (`drivers/kernel/wfp_callout/aegis_wfp.c:298-304`). ผล static ที่คาดได้คือ stats อาจ fail ทุกครั้งหรือข้อมูลถูกตีความผิด. `read_events()` คืน raw bytes จึงต้องมี parser ที่ใช้ 40-byte packed contract; source ที่ตรวจไม่พบ proof ว่า consumer ใช้ขนาดเดียวกัน.

นี่กระทบทั้ง ABI correctness, WFP health/readiness, forensic evidence และการตัดสินว่า adapter พร้อมหรือไม่. ไม่ควรใช้ `wfpIsConnected()` หรือ log “device opened” เป็น proof ว่า event/stat contract ใช้งานได้.

### 5.3 Rust dynamic loader ABI/path

Rust PEP `wfp_adapter::Adapter::load()` ใช้ `LoadLibraryW` กับชื่อ relative ได้แก่ `aegis_wfp_user.dll` และ `build\\Release\\aegis_wfp_user.dll`, แล้ว `GetProcAddress` หา `aegis_wfp_ioctl_open`, `aegis_wfp_ioctl_block_ip`, `aegis_wfp_ioctl_unblock_ip` (`rust-src/lib.rs:228-268`).

ข้อสังเกต

* CMake root output ของ native helpers คือ `dist` (`CMakeLists.txt:28-36`), แต่ loader ไม่ค้น `dist` โดย explicit path.
* Relative/system DLL lookup ขัดกับ requirement ใน README ที่ต้องใช้ trusted absolute path, signature/hash verification และ ACL-protected directory.
* ไม่ตรวจ module signature, file hash, ABI version, export version หรือ DLL identity ก่อนโหลด.
* Function pointers ใช้ `extern "system"`; C exports ถูกประกาศเป็น C functions และ CMake target ไม่ได้แสดง ABI version. บน x64 calling convention มักรวมกัน แต่ยังต้องยืนยันด้วย header/generated ABI; ห้ามถือ unit compile เป็น proof ทุก target.

---

## 6. WFP effect, kernel boundary และ false success

### 6.1 `src/windows/aegis_wfp.c` direct helper

`aegis_wfp_open()` เปิด BFE session แล้วพยายามเพิ่ม provider/sub-layer แต่ไม่ตรวจ return code ของ `FwpmProviderAdd0()` และ `FwpmSubLayerAdd0()` (`aegis_wfp.c:32-51`). จึงสามารถคืน 0 หลัง engine เปิดได้แม้ provider/sub-layer registration ล้มเหลว. `aegis_wfp_add_block()` ตรวจ `FwpmFilterAdd0()` และคืน negative error เมื่อ fail แต่มีข้อจำกัด

* filter layer คือ `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, จึงครอบคลุม outbound connect มากกว่า inbound transport และไม่ใช่ generic “block IP ทุก traffic”.
* source/destination conditions ถูก map เป็น local/remote address; ต้องยืนยัน byte order และ direction กับ caller.
* filter key ใช้ `AEGIS_WFP_FILTER_KEY_BASE.Data1 ^= g_next_filter_id`; counter เป็น process-local ไม่ atomic และอาจเกิด key collision หลัง restart/parallel calls.
* `g_next_filter_id` increment หลัง add สำเร็จเท่านั้น; ไม่มี persistent ownership map.
* `aegis_wfp_remove_filter()` คืน 0 แม้ enum fail, filter ไม่พบ หรือ `FwpmFilterDeleteById0()` ล้มเหลว เพราะผล delete ไม่ถูกตรวจ (`aegis_wfp.c:134-155`). เป็น false success โดยตรง.
* `aegis_wfp_uninstall()` แค่ close engine; ไม่ลบ filters ทั้งหมด. ถ้า filters ไม่อยู่ใน dynamic session หรือถูกเพิ่มโดย session อื่น อาจค้างใน BFE.

ไม่พบ active call จาก `event_processor` ไป direct `aegis_wfp_add_block`, แต่ DLL export ทำให้เป็น privileged bypass surface และต้องถูก disable/remove หรือบังคับให้มี authenticated broker เดียว.

### 6.2 IOCTL driver path

`src/windows/wfp_ioctl.c` เปิด `\\.\\AegisWfpDevice` ด้วย `GENERIC_READ | GENERIC_WRITE` และ exposes block/unblock functions. `drivers/kernel/wfp_callout/aegis_wfp.c` dispatches `IOCTL_AEGIS_BLOCK_FLOW` และ `IOCTL_AEGIS_UNBLOCK_FLOW` without source-level caller authorization. `DriverEntry()` ใช้ `IoCreateDevice()` และ `IoCreateSymbolicLink()` (`drivers/kernel/wfp_callout/aegis_wfp.c:58-80`); ไม่พบ `IoCreateDeviceSecure`, SDDL assignment หรือ token/SID check ใน device-control path.

`AegisWfpBlockFlow()` ตรวจเพียง input length >= 4 แล้วอ่าน IP จาก `SystemBuffer`, เปิด WFP และเพิ่ม filter (`drivers/kernel/wfp_callout/aegis_wfp.c:214-297`). ยังต้องตรวจ Windows kernel API contract เพราะ code สร้าง `FWPM_FILTER0` โดยไม่มี `layerKey` และใช้ filter ที่ตั้ง `FWPM_FILTER_FLAG_PERSISTENT` ภายใน dynamic session. ต่อให้ API ยอมรับ filter ผลที่ได้ก็เป็น filter เดียวที่เก็บไว้ใน global `g_FilterId/g_BlockedIp`; source ไม่รองรับ ownership ต่อหลาย request/หลาย IP อย่างชัดเจน.

`AegisWfpUnblockFlow()` ป้องกันเฉพาะ IP ที่เท่ากับ global active IP และ filter ID ปัจจุบัน (`aegis_wfp.c:376-431`). นี่ไม่ใช่ general blocklist reconciliation และไม่ bind unblock ให้กับ request/policy/caller เดิม.

### 6.3 WFP callout เป็น fail-open telemetry ไม่ใช่ prevention

`drivers/kernel/wfp_callout/aegis_wfp_callout.c:18-114` register callout ที่ `FWPM_LAYER_INBOUND_TRANSPORT_V4`, เขียน 5-tuple ลง ring แล้วตั้ง

```text
classifyOut->actionType = FWP_ACTION_PERMIT;
classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
```

คอมเมนต์ระบุ `FAIL-OPEN`. Filter ที่ register ใน `aegis_wfp_callout.c:202-215` ไม่มี conditions และ action เป็น `FWP_ACTION_PERMIT`. จึงมี static evidence ว่า driver callout นี้ **ไม่ block packet**; มีหน้าที่ capture/telemetry เท่านั้น. การมี callout/filter/register success หรือ event ring data ไม่ใช่หลักฐานว่า prevention effect เกิดขึ้น.

### 6.4 False-success cases ที่ต้องถือเป็น stop-the-line

* `src/policy/action_dispatcher.zig:69-83` เขียน “PEP validated block; WFP enforcement executed by Rust PEP” และ “PEP validated rate_limit; WFP enforcement executed by Rust PEP”. Dispatcher ไม่ได้รับ adapter receipt; เป็นเพียง log/forensic/federation router.
* `PepDecision.rate_limit` ใน Rust PEP ถูกคืนเป็น decision แต่ไม่มี adapter call ที่ apply rate limit. `ActionDispatcher` ก็ไม่มี WFP call.
* `PepDecision.quarantine` ถูกคืนพร้อม reason “adapter execution is downstream”; dispatcher เพียงแจ้ง federation และ forensic ไม่มี local isolation.
* `src/policy/policy_contract.zig:232-235` นับ `rate_limit` เป็น success โดยไม่เรียก WFP/rate limiter.
* `policy_contract.PEP` บล็อก host event ที่ `source_ip == 0` แล้ว return success และตั้ง `enforcement_status = 1` (`policy_contract.zig:211-230`) แม้ไม่มี target ที่จะ block.
* `src/core/rust_pep.zig:189-228` ใส่ IP ลง in-memory map แล้ว return executed; คอมเมนต์ระบุเองว่าเป็น authorized decision model และ Rust PEP production เป็นเจ้าของ side effect. Unit test นี้พิสูจน์แค่ map insertion.
* `rust_pep_integration.execute()` return `.no_op` เมื่อไม่ initialized และ alternate `policy_integration` return allow when engine absent. ข้อมูลเหล่านี้ต้องถูกบันทึกเป็น degraded/non-enforcing result ไม่ใช่ success.
* `aegis_wfp_remove_filter()` return 0 แม้ไม่พบ/delete fail ดังกล่าวข้างต้น.
* `PepResponse.signed_by` ถูกตั้ง 0 เสมอ (`rust-src/lib.rs:353-356, 422-425`), ดังนั้น response ไม่ใช่ signed enforcement receipt.
* Forensic record ใน active event processor เก็บ `pep_decision` ordinal และ event/policy IDs (`event_processor.zig:198-200`) แต่ไม่ได้เก็บ `PepResponse.reason`, `quota_remaining`, `signed_by`, OS caller identity, WFP filter ID หรือ `FwpmFilterAdd0` result. จึงไม่สามารถ reconstruct final effect จาก forensic record ได้.

---

## 7. Shield Rust

Shield ถูกประกาศให้เป็น screening-only และไม่ใช่ PEP authority. ทั้ง `rust-src/shield/src/lib.rs` และ root `shield/src/lib.rs` ไม่มี WFP mutation; root exports `aegis_shield_screen` ซึ่งคืนผล screening. `rust-src/shield/src/pep.rs` ยังมี `auth_token_is_valid()` และ `screen_payload()` แต่คอมเมนต์ระบุว่า non-zero เป็นเพียง escalation เข้า canonical path และไม่มี enforcement.

อย่างไรก็ตามมี duplicate crate/source roots และ artifact expectations ต่างกัน

* README ระบุ authority source เป็น `rust-src/shield/src/lib.rs` และ artifact เป็น `shield/target/release/sec_monitor.dll`.
* root `shield/Cargo.toml` สร้าง crate `aegis-shield`, library name `sec_monitor`, `cdylib`/`rlib`.
* ไม่มีหลักฐานใน `daemon.runDaemon()` ว่า Shield screening DLL ถูกโหลดเพื่อ authorize PEP. `bridge_init.zig` เองระบุ `SHIELD_VERSION = "REMOVED"` และ active bridge state ไม่รวม Shield.

ดังนั้น Shield ไม่ควรถูกนับเป็น signature/trust/authority proof. จุดที่ควรปิดคือ retire duplicate source ให้เหลือ advisory ABI เดียว, ระบุ artifact ที่ build จาก HEAD เดียวกัน และแสดง health แยกจาก PEP/WFP.

---

## 8. Static evidence กับ runtime proof

### 8.1 Static evidence ที่ยืนยันได้จาก current HEAD

* Active-looking daemon call graph โหลด policy JSON, สร้าง `PepEnforcer`, และส่ง matched policy เข้า PEP FFI.
* PEP FFI มี enum/struct declarations และ Zig-side size/offset tests.
* Rust PEP มี null-pointer check, capability-bit check และเปลี่ยน block เป็น escalate หาก WFP adapter load/call fail.
* WFP driverมี read/event IOCTL และ mutating block/unblock IOCTL.
* WFP callout classify เป็น permit/fail-open.
* Policy signing module มี Ed25519 verification, expiry, rollback taxonomy และ TrustStore model.
* Control IPC มี intended ACL/role/freshness/replay/audit design.

### 8.2 สิ่งที่ยังไม่มี runtime proof

ยังไม่มีหลักฐานจาก Windows host ว่า

* `aegis_pep.dll` ถูก build จาก `46b93dc...` และถูกโหลดโดย daemon.
* `aegis_wfp_user.dll` ที่ถูกโหลดเป็น DLL ที่ถูก sign/trusted และเป็น version เดียวกับ Zig/Rust ABI.
* driver ถูกติดตั้ง, signed, loaded และ device ACL จำกัดเฉพาะ intended service SID.
* `IOCTL_AEGIS_BLOCK_FLOW` ถูกปฏิเสธจาก standard user/low-integrity/foreign process.
* block request สร้าง WFP filter ที่ถูกต้องบน intended layer และ filter มี packet effect.
* filter effect ครอบคลุม source/destination/direction/protocol ที่ policy ระบุ.
* rate-limit/quarantine มี side effect จริง; source ปัจจุบันไม่แสดง adapter สำหรับสอง action นี้.
* policy file ผ่าน mandatory Ed25519/trust-store/rollback/expiry gate ก่อนมีผล.
* control named pipe ใช้ `Authorizer` ทุก privileged operation และผูก identity จาก OS token.
* replay request เดิมถูกปฏิเสธหลัง restart และข้าม process.
* forensic record มี final adapter result และ WFP filter ownership.

### 8.3 Test source ไม่ใช่ runtime proof

Unit tests ใน `pep_bindings.zig`, `policy_signing.zig`, `control_ipc.zig`, `policy_contract.zig` และ Rust `lib.rs` ตรวจ branches/in-memory models. หลาย test ใช้ `std.testing`, target ที่ไม่ใช่ Windows หรือ mock/in-memory map. Rust PEP tests ยอมรับทั้ง `DECISION_BLOCK` และ `DECISION_ALLOW reason=4` ในบาง branch (`rust-src/lib.rs:547-577`), ซึ่งไม่ใช่ assertion ว่า WFP effect เกิด. ต้องจัดทำ host integration test ที่อ่าน BFE filter state และส่ง actual traffic เพื่อยืนยัน effect.

---

## 9. Risk register

| ID | ระดับ | ความเสี่ยง | หลักฐาน | ผลกระทบ |
|---|---|---|---|---|
| P0-PEP-01 | P0 | Device mutating IOCTL ไม่มีหลักฐาน restrictive SDDL/OS caller check | `drivers/wfp_callout/aegis_wfp.c:58-80,151-177,214-297`; `src/windows/wfp_ioctl.c:69-103` | process อื่นอาจ block/unblock WFP โดย bypass PEP |
| P0-PEP-02 | P0 | Capability/PID เป็น caller-supplied และไม่ bind OS identity | `daemon.zig:121-125`; `rust-src/lib.rs:361-369,430-450` | ปลอม authority/capability และ replay privileged request |
| P0-PEP-03 | P0 | Policy signature/TrustStore ไม่ mandatory ใน active load path | `daemon.zig:179-298`; `policy_signing.zig`; `policy_plane.zig:267-286` | attacker ที่แก้ JSON อาจเปลี่ยน detection/policy action |
| P0-PEP-04 | P0 | Zig/C/driver WFP ABI stats/header mismatch | `wfp_ioctl.zig:37-60,205-225`; `wfp_ioctl.c:28-55`; driver header | health/telemetry/parse ผิด และยืนยัน effect ไม่ได้ |
| P1-PEP-05 | P1 | Rust PEP ไม่ทำ replay/quota/two-person enforcement จริง | `rust-src/lib.rs:300-315,350-426` | duplicate/repeated block ไม่ถูกจำกัด; high severity ไม่ได้ two-person |
| P1-PEP-06 | P1 | Relative DLL loading/no signature or hash verification | `rust-src/lib.rs:228-268`; `build.zig:59-70`; `README.md:205-216` | DLL planting/โหลด artifact ผิด revision |
| P1-PEP-07 | P1 | Direct WFP helper exported alongside canonical PEP | `CMakeLists.txt:22-36`; `aegis_wfp.c:32-165` | alternate privileged authority และ filter ownership drift |
| P1-PEP-08 | P1 | WFP callout permit/fail-open | `aegis_wfp_callout.c:8-9,111-114,202-215` | telemetry path ไม่ป้องกัน traffic แม้ deployment คาด prevention |
| P1-PEP-09 | P1 | rate-limit/quarantine มี decision/log แต่ไม่มี enforcement receipt/side effect | `rust-src/lib.rs:376-381`; `action_dispatcher.zig:74-89`; `policy_contract.zig:232-241` | false success/false prevention claim |
| P1-PEP-10 | P1 | Direct helper remove/uninstall ละเลย error/filter ownership | `aegis_wfp.c:134-165` | filter ค้างหรือ audit บอก success ทั้งที่ delete fail |
| P1-PEP-11 | P1 | Control replay cache จำกัด 64 และ key XOR collision | `control_ipc.zig:280-298,337-354` | replay protection เสื่อมใน long-lived daemon |
| P1-PEP-12 | P1 | Current Rust source test field mismatch `reserved` vs `policy_version` | `rust-src/lib.rs:156-162,559-563` | build/test artifact อาจไม่ตรง HEAD |
| P2-PEP-13 | P2 | Policy parser ลด multi-condition และ `gte` เป็น `gt` | `daemon.zig:240-280` | false negative/incorrect enforcement |
| P2-PEP-14 | P2 | Default allow/empty policy/dependency degradation ไม่แสดง final enforcement state ทุก path | `policy_integration.zig:45-71`; `daemon.zig:184-187` | detection-only ถูกเข้าใจเป็น prevention/allow |
| P2-PEP-15 | P2 | Forensics เก็บ intent/ordinal ไม่ใช่ final adapter/WFP receipt | `event_processor.zig:175-200` | incident reconstruction และ replay audit ไม่ครบ |
| P2-PEP-16 | P2 | Rust PEP crate manifest/artifact provenance ไม่ชัด; `rust-src/Cargo.toml` ไม่อยู่ใน tree | `build.zig:59-70`; `rust-src/lib.rs` | ไม่สามารถพิสูจน์ว่าผลิต DLL จาก current HEAD |

---

## 10. Gaps ที่ต้องปิดก่อนเปิด privileged production

1. **Canonical authority gap:** กำหนดให้มี PEP broker เดียว, ลบ/ซ่อน direct `aegis_wfp_*` exports ที่ไม่ใช่ broker และให้ทุก mutating IOCTL ผ่าน signed/authenticated request.
2. **OS identity gap:** เปลี่ยนจาก capability bit ที่ caller ส่งเป็น service SID/token validation ที่ boundary. ตรวจ PID ด้วย kernel/OS primitive ไม่เชื่อ `caller_pid` จาก frame.
3. **Device ACL gap:** สร้าง device ด้วย restrictive SDDL/secure device object; ทดสอบ standard user, low integrity, unrelated service และ malicious same-user process.
4. **Policy authenticity gap:** กำหนด signed artifact เดียว เช่น `SignedPolicy` ที่ครอบคลุม canonical policy bytes, version, expiry, signer และ digest. Reject unsigned JSON; bind `policy_version`/digest/signer เข้า PEP request และ forensic record.
5. **Policy semantics gap:** เลิก parse เฉพาะ first clause/predicate; ทำ canonical compiler/parser ที่ตรงกับ simulator และ policy evaluator. ระบุ default behavior เมื่อ policy missing เป็น explicit `ENFORCEMENT_UNAVAILABLE`, ไม่ใช่ implicit allow.
6. **Replay gap:** ใช้ authenticated request envelope, monotonic persistent counter/nonce store, bounded eviction ที่ปลอดภัย, atomic consume และ restart persistence. ไม่ใช้ XOR-combined hash เป็น replay identity.
7. **Quota/two-person gap:** ทำ quota decrement/commit ก่อน side effect, transaction/recovery หลัง adapter result, และเปิด two-person rule จาก trusted configuration พร้อม approval identity ที่ตรวจได้.
8. **ABI gap:** สร้าง generated C/Rust/Zig header หรือ compile-time ABI manifest; pack event/stats ให้ตรงกัน. แก้ `WfpEventHeader` 40 bytes และ `WfpRingStats` 24 bytes ให้ตรง driver หรือเปลี่ยน driver contract ทั้งชุด.
9. **WFP effect gap:** แยก telemetry callout (permit) ออกจาก prevention filter อย่างชัดเจน. Prevention adapter ต้องระบุ layer, direction, address semantics, protocol, ownership, idempotency และ filter ID ใน receipt.
10. **False-success gap:** เปลี่ยน API เป็น explicit `authorized`, `submitted`, `applied`, `verified`, `rejected`, `unavailable`, `failed`. ห้าม `ActionDispatcher` log ว่า executed หากไม่มี adapter receipt/verification.
11. **Quarantine/rate-limit gap:** implement actual Windows adapter หรือ mark unsupported and return non-enforcing escalation. ห้าม return success/validated จาก log-only route.
12. **Artifact provenance gap:** เพิ่ม Cargo manifest/workspace สำหรับ `rust-src/lib.rs` authority, pin dependency versions, produce hash/signature manifest และตรวจว่า `aegis_pep.dll`, `aegis_wfp_user.dll`, driver และ Zig executable มาจาก HEAD เดียวกัน.
13. **WFP cleanup gap:** เก็บ map ของ policy/request -> filter ID/key; ตรวจทุก return code; cleanup ผ่าน owner เดียว; ทดสอบ restart, crash, duplicate block, stale filter และ concurrent add/remove.
14. **Runtime proof gap:** ทำ Windows E2E matrix ที่พิสูจน์ actual BFE state และ traffic effect รวม missing DLL/driver, wrong ABI, unsigned policy, expired/rollback policy, replay, low-privilege caller และ adapter failure.
15. **Forensics gap:** บันทึก policy digest/version/signer, caller SID/PID binding, request/nonce, PEP reason/quota/signed_by, adapter receipt, WFP filter ID, final verification result และ explicit non-enforcing state.

---

## 11. แผนทดสอบถัดไปที่ควรใช้เป็น exit gate

### Gate A — build and ABI

ให้ build Rust PEP จาก current HEAD บน Windows และแก้/ยืนยัน `policy_version` field mismatch. ให้ Zig/C/Rust export `sizeof`, `alignof`, field offsets และ enum ordinals ลง artifact เดียว แล้ว compare ใน CI. ตรวจ `WfpEventHeader=40`, `WfpRingStats=24` และ bytes returned จาก `DeviceIoControl`.

### Gate B — policy security

สร้าง unsigned/tampered/unknown-key/expired/rollback policy แล้วพิสูจน์ว่า daemon ไม่เริ่ม prevention และไม่ reload policy. ตรวจว่าการเปลี่ยนหนึ่ง byte ใน rule, expiry, version, signer หรือ action ถูก reject ก่อน `PolicySet` ถูกสร้าง. ตรวจว่า `configs/policies.json` plain JSON ไม่สามารถ bypass signed artifact path.

### Gate C — authorization and replay

เรียก PEP และ device จาก standard user, low-integrity process, unrelated PID, duplicated request, reused nonce, future-issued request และ request หลัง restart. ทุกกรณีที่ไม่ได้ authenticate ต้องได้ explicit deny/unavailable และไม่เพิ่ม WFP filter.

### Gate D — WFP effect

ส่ง traffic inbound/outbound ที่ตรง/ไม่ตรง 5-tuple และตรวจ BFE filter enumeration, layer, conditions, weight, filter owner และ packet result. ทดสอบ block หลาย IPพร้อมกัน, unblock ผิด IP, daemon crash/restart และ stale filters. แยกผล callout permit telemetry จาก prevention filter.

### Gate E — final-result evidence

ให้ forensic record ของแต่ละ request มีสถานะลำดับ `authorized -> submitted -> applied -> verified` หรือสถานะ failure ที่ชัดเจน. ห้ามใช้ `PepDecision.block` เป็น final result หากไม่มี filter/traffic verification. ตรวจ replay และ rollback evidence ข้าม restart.

---

## 12. ข้อสรุปสุดท้าย

จาก current HEAD `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` มี source intent ที่ดีเรื่อง PEP เดียวและ fail-closed เมื่อ Rust PEP/WFP adapter หาย โดยเฉพาะ `pep_bindings.zig` และ Rust block path. แต่ implementation ยังมี authority ที่ caller ปลอมได้, policy signature ที่ไม่ mandatory, replay/quota/two-person ที่ไม่ active, direct mutating device path ที่ไม่มีหลักฐาน ACL, duplicate WFP exports, ABI mismatch ของ WFP telemetry และ false-success models หลายชุด.

ดังนั้นผล review คือ **ไม่ผ่านสำหรับ privileged prevention production**. ให้เปิดได้เฉพาะ detection-only หรือ degraded mode ที่ health/audit ระบุชัดว่าไม่มี enforcement guarantee จนกว่า P0 ทั้งหมดและ Gate A–E จะผ่านบน Windows host ด้วย artifact ที่ผูกกับ current HEAD. `688ab56` และ machine maps ที่อ้าง revision ดังกล่าวไม่ควรใช้เป็นหลักฐานปิดความเสี่ยง.

---

## References

[1]: ../src/main.zig "AEGIS Windows main entrypoint"
[2]: ../src/daemon.zig "AEGIS daemon startup, policy loading and PEP initialization"
[3]: ../src/pipeline/event_processor.zig "Active detection, policy, PEP and forensic pipeline"
[4]: ../src/policy/pep_bindings.zig "Zig/Rust PEP FFI contract"
[5]: ../rust-src/lib.rs "Rust PEP FFI implementation and WFP adapter"
[6]: ../src/core/rust_pep.zig "Zig Rust-PEP model and WFP gate wrapper"
[7]: ../src/policy/policy_ir.zig "Policy DSL, PolicySet and action ordinals"
[8]: ../src/policy/policy_plane.zig "Policy IR compiler and simulator"
[9]: ../src/policy/policy_signing.zig "Ed25519 policy verifier and TrustStore model"
[10]: ../src/policy/control_ipc.zig "Control-plane roles, replay and audit authorizer"
[11]: ../src/policy/action_dispatcher.zig "Action routing and enforcement-result logging"
[12]: ../src/policy/policy_contract.zig "Alternate policy/PEP contract model"
[13]: ../src/windows/aegis_wfp.c "User-mode direct WFP helper"
[14]: ../src/windows/wfp_ioctl.c "User-mode WFP device IOCTL bridge"
[15]: ../drivers/wfp_callout/aegis_wfp.h "Kernel WFP device and packed ABI header"
[16]: ../drivers/wfp_callout/aegis_wfp.c "Kernel WFP driver and mutating IOCTL handlers"
[17]: ../drivers/wfp_callout/aegis_wfp_callout.c "Kernel WFP telemetry callout"
[18]: ../src/policy/wfp_ioctl.zig "Zig read-only WFP telemetry wrapper"
[19]: ../src/pipeline/rule_loader.zig "Rules.json loading and hot reload"
[20]: ../configs/policies.json "Active JSON policy configuration"
[21]: ../configs/Rules.json "Detection rule configuration"
[22]: ../README.md "Repository architecture, authority and safety status"
[23]: ../CMakeLists.txt "Native build graph for WFP user DLL and helpers"
[24]: ../build.zig "Zig build graph and Rust PEP import-library expectation"
[25]: ../rust-src/shield/src/lib.rs "Quarantined Shield screening library"
[26]: ../shield/src/lib.rs "Root Shield advisory library"
[27]: ../src/tests/integration/rust_pep_integration.zig "In-memory RustPep integration facade"
[28]: ../src/tests/integration/policy_integration.zig "Policy planner integration facade"
[29]: ../src/policy/tier3_state.zig "Tier-3 state and fail-open override"
[30]: ../src/contract/event.zig "Canonical 96-byte event contract"
