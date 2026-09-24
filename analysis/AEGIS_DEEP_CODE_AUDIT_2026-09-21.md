# AEGIS Windows NIDS/IPS — Deep Code Audit

**วันที่ตรวจ:** 21 กันยายน 2026  
**Source of truth:** `D:\NIDs_Windows`  
**สถานะ:** **NOT ACCEPTED / ยังไม่ Production-ready**  
**ผู้จัดทำ:** Manus AI

## 1. ข้อสรุปสำหรับผู้พัฒนา

AEGIS มีแนวคิดสถาปัตยกรรมที่ถูกต้องในระดับสูง ได้แก่ การให้ Zig เป็น runtime owner, ให้ Go Nose เป็น canonical ingress, ให้ Rust PEP เป็น privileged policy enforcement point และให้ WFP เป็น host-effect provider อย่างไรก็ตาม code audit จาก source จริงพบว่า **เส้นทางสำคัญยังมี contract drift และ critical defects ที่ทำให้ไม่สามารถยืนยันการ block จริงได้**

ข้อค้นพบที่สำคัญที่สุดคือเส้นทาง WFP port-specific enforcement ยังไม่ผ่าน correctness proof: `src/policy/pep_bindings.zig` ส่งค่า action ordinal ที่ไม่ตรงกับ Rust (`PepDecision.block = 1` ขณะที่ Rust กำหนด `ACTION_BLOCK = 4`) จึงมีความเสี่ยงสูงที่คำสั่ง block จะถูกตีความเป็น log หรือ allow แทนการเรียก WFP นอกจากนี้ kernel response path ไม่ตั้ง `IoStatus.Information` ตามขนาด response ที่ user bridge คาดหวัง และ filter ไม่กำหนด layer อย่างชัดเจนตามที่ WFP contract ต้องการ

ปัญหานี้เกิดร่วมกับช่องว่างอีกหลายชั้น ได้แก่ named pipe ของ Nose ยังไม่มี producer authentication ที่พิสูจน์ได้, transport ระหว่าง Go กับ Zig ไม่ตรงกับ WEV1 ที่เอกสารประกาศ, policy path มี fail-open เมื่อ policy หรือ PEP ไม่พร้อม, control API ยัง retry mutation ได้โดยไม่มี idempotency, dashboard เปิด bind แบบกว้างโดยไม่มี authentication, installer และ build graph มีหลายชุดที่ไม่ตรงกัน และ evidence maps อ้างอิง HEAD เก่า

ดังนั้นผลตัดสินคือ **Runtime readiness ที่ Handoff รายงานไว้ไม่เท่ากับ production acceptance** การพัฒนาควรเริ่มจากการปิด P0 blockers และสร้าง canonical contract เดียวก่อนทำ controlled TCP/8080 proof อีกครั้ง

## 2. ขอบเขตและหลักฐาน

การตรวจครอบคลุม source, scripts, configuration, tests, manifests และ runbooks ที่ถูกติดตามใน repository รวมถึงรายงานตรวจย่อย 7 ด้าน ได้แก่ runtime Zig, Rust/WFP enforcement, Go Nose ingress, detection/policy/forensics, Python control plane, Windows build/install และ tests/evidence. Inventory ของ Git มี 827 paths ใน snapshot ที่ตรวจ และรายงานย่อยระบุไฟล์จริงของแต่ละโมดูลไว้โดยละเอียด

Static scan ถูกเก็บไว้ที่ [static inventory](deep_audit/static_inventory.md) และรายการ tracked files อยู่ที่ [tracked files](deep_audit/tracked_files.txt) รายงานย่อยมีดังนี้:

| พื้นที่ | รายงาน |
|---|---|
| Zig runtime/control plane | [01-runtime-zig](deep_audit/01-runtime-zig.md) |
| Rust PEP/WFP/ABI | [02-enforcement](deep_audit/02-enforcement.md) |
| Go Nose/ingress | [03-ingress](deep_audit/03-ingress.md) |
| Detection/policy/forensics | [04-brain-policy](deep_audit/04-brain-policy.md) |
| Python control/CLI/dashboard | [05-control-cli](deep_audit/05-control-cli.md) |
| Windows scripts/installer/release | [06-windows-scripts](deep_audit/06-windows-scripts.md) |
| Tests/manifests/evidence | [07-tests-docs](deep_audit/07-tests-docs.md) |

การตรวจใน sandbox ไม่ได้อ้างว่า Windows host proof ผ่าน เนื่องจาก environment นี้ไม่มี `zig`, `cargo`, `go` และ `pytest` ที่จำเป็นสำหรับการ build/test หลายส่วน การตรวจจึงแยกชัดเจนระหว่าง **static finding**, **local test result** และ **Windows lab evidence**

## 3. ภาพรวมการทำงานของระบบ

เส้นทางที่ออกแบบไว้คือ:

```text
Npcap / Go Nose
  -> CanonicalEvent
  -> named pipe
  -> Zig reader and event queue
  -> flow/detection/correlation/policy
  -> Rust PEP through FFI
  -> WFP user bridge and IOCTL
  -> WFP kernel filter
  -> receipt with filter_id
  -> traffic postcondition
  -> forensic/audit linkage
```

Zig daemon เริ่ม runtime, สร้าง worker set, เปิด control pipe และรวม health. Go Nose จับ packet และส่ง canonical frame. Python/Cython และ TypeScript ควรทำ detection หรือ policy preparation เท่านั้น. Rust PEP ควรเป็นผู้อนุญาต privileged action. User-mode bridge ส่งคำสั่งไป kernel driver และ driver สร้าง exact flow filter. Cleanup ต้องรับ `filter_id` จาก receipt เดิมเท่านั้น

ใน source ปัจจุบันมี implementation ที่ทำหน้าที่เดียวกันหลายชุด เช่น health implementation มากกว่าหนึ่งแบบ, dispatcher หลาย path, Npcap/parser หลายชุด, installer หลายแบบ, WFP implementation/legacy implementation ซ้ำ และ policy sources หลายแห่ง ความเสี่ยงหลักจึงไม่ใช่เพียง bug รายจุด แต่คือ **runtime graph ที่ใช้งานจริงไม่ตรงกับ graph ที่ tests และ manifests อ้างถึง**

## 4. Critical findings ที่ต้องแก้ก่อนการพิสูจน์ block

### 4.1 WFP enforcement action ordinal ผิด

**หลักฐาน:** `src/policy/pep_bindings.zig`, `rust-src/lib.rs`

Zig สร้าง requested action จาก enum ของตนเอง โดยใช้ค่าที่เท่ากับ 1 สำหรับ block แต่ Rust กำหนด action 1 เป็น log และ action 4 เป็น block. ผลคือ request ที่ชื่อ block อาจไม่เข้าสู่ WFP path เลย

**ผลกระทบ:** receipt `ENFORCED` ไม่สามารถเชื่อถือได้ และ controlled proof อาจกลายเป็น false positive หากตรวจเพียง response หรือ state ภายใน

**การแก้:** สร้าง shared/generated enum contract เดียว พร้อม compile-time assertions และ golden vector ที่ทดสอบ Zig → Rust → C → kernel โดยตรง ห้ามใช้ enum ordinal ที่ประกาศซ้ำเองในแต่ละภาษา

### 4.2 Kernel response ABI ไม่สมบูรณ์

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.c`, `src/windows/wfp_ioctl.c`

Kernel dispatch ไม่ตั้ง `Irp->IoStatus.Information` เป็นขนาด `AEGIS_WFP_FLOW_RESPONSE` ใน path ที่คืน filter ID ขณะที่ user bridge รับผลเฉพาะเมื่อ `out_len` ตรงกับ response size และ `filter_id != 0`

**ผลกระทบ:** block อาจสร้าง filter แต่ user bridge ถือว่าล้มเหลว หรือ receipt ไม่มี identity ที่ใช้ cleanup

**การแก้:** กำหนด IOCTL request/response เป็น generated header เดียว ระบุ `sizeof`, `offsetof`, packing และ success semantics ในทุก boundary พร้อม negative tests สำหรับ short response และ zero filter ID

### 4.3 Filter layer และ ownership ยังพิสูจน์ไม่ได้

**หลักฐาน:** `drivers/wfp_callout/aegis_wfp.c`, `drivers/wfp_callout/aegis_wfp.h`

Filter ถูกสร้างโดยไม่กำหนด layer ที่ชัดเจนใน filter structure ตาม contract. อีกทั้งมี global filter ID เดียวที่ใช้ทั้ง capture และ enforcement โดยไม่มี lock หรือ per-receipt store

**ผลกระทบ:** concurrent blocks, restart, unload หรือ crash อาจทำให้ลบผิด filter หรือมี orphan filter ค้างอยู่ ซึ่งขัดกับกฎ exact cleanup

**การแก้:** ใช้ lock-protected receipt registry ที่เก็บ filter ID, owner GUID, request ID, runtime generation และ flow identity; อนุญาต cleanup เฉพาะ receipt เดิมและ filter ที่พิสูจน์ว่าเป็นของ AEGIS

### 4.4 Provider readiness ยังเป็นเพียง device-open probe

**หลักฐาน:** `rust-src/lib.rs`, `src/windows/aegis_wfp.c`

สถานะ provider พร้อมใช้งานเมื่อ DLL โหลดและเปิด device/export ได้ แต่ยังไม่ตรวจ image hash, signature/trust mode, architecture, provider GUID, sublayer identity, filter ownership หรือ provider ABI version

**ผลกระทบ:** binary ผิดรุ่นหรือ DLL ที่ถูกแทนที่อาจถูกประกาศว่า ready และรับ privileged request ได้

**การแก้:** เพิ่ม attestation ที่ตรวจ path ที่อนุญาต, SHA-256, Authenticode policy, export version, device identity, provider/sublayer GUID และ build provenance ก่อนเปิด `host_effect_capable=true`

### 4.5 Ingress pipe ไม่มี authentication และ bounded cancellation เพียงพอ

**หลักฐาน:** `src/capture/nose_pipe_reader.zig`, `nose/pipe_writer.go`

Nose reader สร้าง named pipe โดยไม่มี ACL/SID หรือ producer handshake ที่พิสูจน์ได้. Length prefix มาจาก peer และ path อ่านแบบ blocking โดยไม่มีเพดาน discard/deadline/cancel ที่ชัดเจน

**ผลกระทบ:** local process อาจ inject forged events, ทำให้ reader ค้างด้วย frame ขนาดใหญ่หรือ partial frame และทำลาย shutdown/reconnect

**การแก้:** ใช้ explicit pipe security descriptor, service SID/token binding, producer handshake ที่ผูก generation และ identity, maximum frame/discard limits และ overlapped I/O ที่ cancel ได้

### 4.6 Active transport ไม่ตรงกับ canonical WEV1 contract

**หลักฐาน:** `nose/pipe_writer.go`, `src/capture/nose_pipe_reader.zig`, `shared/protocol/protocol.md`, `src/contract/wire_event.zig`

Live path ใช้ 4-byte little-endian length + 109-byte payload รวม 113 bytes ขณะที่เอกสาร WEV1 ระบุ header และ CRC ที่ทำให้มีรูปแบบต่างกัน. Live path ยังไม่มี integrity check และ mapping ไป `IpcEvent` ทิ้ง source, session, direction และ provenance บางส่วน

**ผลกระทบ:** decoder หลายตัวอาจยอมรับข้อมูลคนละ semantics และ forensic correlation สูญหาย

**การแก้:** เลือก WEV1 เป็น transport เดียว หรือประกาศ 113-byte transport เป็น protocol version ที่เป็นทางการ พร้อม CRC/MAC, version gate, cross-language vectors และ field round-trip test

### 4.7 Policy path มี fail-open เมื่อ dependency ไม่พร้อม

**หลักฐาน:** `src/policy/dispatcher.zig`, `src/policy/dispatcher_phase_b.zig`, `src/policy/policy_engine.zig`, `src/core/rust_pep.zig`

เมื่อ policy หรือ PEP ไม่ initialized มี path ที่เลือก allow/default allow หรือ no-op และยังนับ event เป็น processed. Policy engine active path ยังไม่ผูกกับ signed PolicyIR และ TrustStore อย่างชัดเจน

**ผลกระทบ:** ระบบอาจตรวจพบภัยคุกคามแต่ไม่ปฏิเสธ privileged action หรือรายงานผล processed ทั้งที่ enforcement ไม่พร้อม

**การแก้:** เปลี่ยน unavailable/error เป็น `REJECTED`, `DEFERRED` หรือ `DEGRADED` แบบ explicit. ห้ามแปลง provider unavailable เป็น allow และต้องให้ signed policy verification เป็น gate ก่อน policy activation

### 4.8 Control API retry mutation ได้และ request identity ไม่ถึง daemon

**หลักฐาน:** `tools/aegisctl/api/control_api.py`, `tools/aegisctl/client.py`, `shared/protocol/control_protocol.md`

Python สร้าง role/request ID/nonce ในบางชั้น แต่ request ที่ส่ง daemon ไม่ได้บังคับ envelope เดียวกัน. Retry ที่ควรใช้กับ read-only ถูกใช้กับ enforcement block/unblock ซึ่งอาจสร้าง duplicate filter หลัง response สูญหาย

**ผลกระทบ:** ไม่สามารถแยก “คำสั่งยังไม่ทำ” จาก “ทำแล้วแต่ response หาย” ได้ และอาจเกิด filter ซ้ำ

**การแก้:** แยก read-only retry ออกจาก mutation. Mutation ต้องมี idempotency key, server-side outcome cache และ query สำหรับ resolve ผลเดิม. Daemon ต้อง validate protocol version, nonce, issued time, caller binding และ replay atomically

### 4.9 Dashboard และ backup มี operational security defects

**หลักฐาน:** `tools/aegisctl/web_dashboard/app.py`, `tools/backup_recovery.py`, `tools/legacy/backup_recovery.py`

Dashboard bind `0.0.0.0` โดยไม่มี authentication และมี health path ที่อาจรายงาน RUNNING แบบคงที่แม้ daemon unavailable. Restore รับ manifest path โดยยังไม่มี canonical containment, absolute path/traversal/symlink rejection และ atomic staging

**ผลกระทบ:** เปิด operational data ให้ network และเสี่ยง arbitrary file write จาก backup input

**การแก้:** bind loopback เป็นค่าเริ่มต้น, ใช้ authenticated operator boundary, escape event data, health ต้องมาจาก daemon. Restore ต้อง canonicalize path, allowlist root, ปฏิเสธ traversal/symlink, stage แล้ว atomic promote และ verify manifest/signature

### 4.10 Build/evidence provenance ไม่เป็น current-head proof

**หลักฐาน:** `SYSTEM_MAP.json`, `FLOW_MAP.json`, `EVIDENCE_INDEX.json`, `runtime_manifest.json`, `build_manifest.json`, release scripts

Truth maps อ้าง head SHA เก่าเมื่อเทียบกับ repository HEAD. Build/install/package มีหลาย graph และหลาย version identity. บาง source ที่ `all_tests` import ไม่อยู่ใน tracked clean checkout. CI coverage เป็น job-presence gate ไม่ใช่ code coverage และ host tests skip ได้เมื่อไม่มี Windows prerequisites

**ผลกระทบ:** รายงาน PASS อาจอ้าง artifact หรือ source คนละรุ่นกับ runtime ที่กำลังใช้งาน

**การแก้:** regenerate maps จาก locked HEAD เดียว, require strict verification, ทำ clean-checkout build, pin toolchains, ใช้ manifest เป็น authority เดียว และเปลี่ยน required Windows job จาก skip เป็น fail เมื่อ prerequisite หาย

## 5. Findings สำคัญระดับ P1/P2

1. Shared counters, audit IDs, PEP IDs และ health snapshots มี plain mutable state ข้าม pipeline/control threads โดยไม่มี atomic หรือ lock snapshot ที่พิสูจน์ได้
2. Bridge spool thread ถูกสร้างแต่ไม่ได้เก็บ handle เพื่อ join; shutdown ปิด socket และ queue ได้ขณะ worker ยังทำงาน
3. Runtime lifecycle ที่ถูกทดสอบใน `src/reliability/lifecycle.zig` ไม่ใช่ lifecycle ที่ `src/daemon.zig` ใช้จริง
4. Health schema มี implementation มากกว่าหนึ่งแบบ และ Python tests ต้องการ field ที่ active daemon ไม่ได้ส่ง
5. Rule reload เก็บ automaton เก่าตลอดอายุ daemon ทำให้ memory โตไม่จำกัด และรายงาน reload สำเร็จแม้ rules_loaded เป็นศูนย์
6. Policy loader แปลง operator หรือ severity ที่ไม่รองรับเป็นค่า default แทนการ reject
7. Forensic ring และ replay มีปัญหา stale index หลัง wrap, pointer lifetime, lack of durable anchor และแยก `unavailable` จาก `no_diff` ไม่ชัด
8. Policy signing ระหว่าง TypeScript, Zig และ Python ใช้ canonical bytes คนละแบบ; การ hash raw Zig struct ที่มี pointer ไม่ใช่ canonical policy serialization
9. Aho–Corasick signature path ไม่รวม failure-state outputs ครบ จึงเสี่ยงพลาด suffix/overlap matches
10. Go event sequence reset ต่อ connection และ metadata หลาย field เป็นศูนย์; duplicate/non-monotonic events ถูกนับและส่งต่อแทนการ reject ตาม policy
11. Installer หลายชุดใช้คนละ service/artifact topology, test signing, global `taskkill`, `Everyone:F` และ rollback ที่ไม่เป็น transaction
12. WFP device path ยังไม่มีหลักฐาน explicit SDDL หรือ caller authorization ที่ผูกกับ token/capability; hard-coded `caller_caps=1` ไม่ใช่ authorization proof
13. FIM native helper มีความเสี่ยง data race, event reuse และ use-after-free ใน stop timeout
14. Test suites จำนวนมากเป็น import-only, source-text, manifest หรือ in-memory proofs ไม่ใช่ Windows host behavior และหลาย suite skip ได้

## 6. สถานะตาม production gates

| Gate | สถานะจาก code audit | เหตุผล |
|---|---:|---|
| Source inventory | PARTIAL | มี tracked inventory แต่มี working-tree-only dependency และหลาย duplicate graph |
| Build reproducibility | FAIL / UNPROVEN | toolchain ไม่พร้อมใน audit environment และ clean checkout imports ไม่ครบ |
| Static authority audit | FAIL | พบ fail-open, hard-coded capability, legacy paths และ duplicated WFP implementations |
| Zig runtime | UNPROVEN | มี lifecycle/health/concurrency drift และยังไม่ได้ build ใน environment นี้ |
| Go ingress | FAIL | pipe ACL, framing contract, replay/identity และ bounded read ยังไม่พอ |
| Rust PEP/ABI | FAIL | action ordinal mismatch, response ABI defect และ provider attestation ไม่ครบ |
| Driver installation | NOT ACCEPTED | test signing, multiple installer graphs, hash/service proof ยังไม่ current-head verified |
| Baseline traffic | NOT RUN | ต้องใช้ disposable VMware lab ตาม Handoff |
| TCP/8080 block | NOT RUN / MUST NOT RUN YET | ห้ามเริ่มจนแก้ P0, build/install hash และ singleton daemon ครบ |
| Receipt/forensics linkage | FAIL | receipt ยังไม่มี request/trace/audit/event/generation/provider/postcondition/cleanup ครบ |
| Exact cleanup | UNPROVEN | global filter ID และ orphan/restart handling ไม่พอ |
| Recovery | UNPROVEN | active lifecycle กับ tested lifecycle ไม่ใช่ path เดียว |
| Production acceptance | **NOT ACCEPTED** | หลาย P0 gates fail หรือไม่มี evidence |

## 7. แผนพัฒนาที่แนะนำ

### P0 — ทำให้ contract ถูกต้องและปิด bypass

1. Freeze canonical runtime graph และ canonical build graph. ปิดหรือ quarantine legacy WFP, IP-only, TCP และ bookkeeping paths.
2. แก้ action ordinal, kernel response length, filter layer และ shared ABI ก่อนทำ integration test.
3. สร้าง generated contract สำหรับ enum, packed structs, IOCTL sizes, offsets, endianness และ golden vectors.
4. สร้าง authenticated pipe protocol พร้อม ACL/SID, producer handshake, generation, nonce, freshness, replay cache และ bounded cancellation.
5. เปลี่ยน PEP/policy unavailable เป็น explicit reject/degraded และบังคับ signed policy activation.
6. ทำ per-receipt filter registry ที่ lock-protected และ exact cleanup ด้วย filter ID เดิมเท่านั้น.
7. ขยาย receipt ให้มี `request_id`, `trace_id`, `audit_id`, `event_id`, `policy_id`, `runtime_generation`, provider status, host postcondition และ cleanup result.
8. รวม health schema เดียวและแยก control liveness, data readiness, provider readiness, host-effect capability และ verified enforcement.
9. ทำ clean checkout build ให้ผ่านโดย track/remove missing imports และ pin toolchains.

### P1 — ทำให้ runtime ปลอดภัยภายใต้ concurrency และ failure

1. เปลี่ยน counters/IDs/state เป็น atomic หรือ immutable snapshot ที่ lock ชัดเจน.
2. เก็บและ join ทุก worker รวม bridge spool; ใช้ overlapped I/O cancellation และ join deadlines.
3. ทำ policy reload แบบ generation/RCU หรือ stop-the-world พร้อม bounded reclamation.
4. รวม parser/Npcap owner และกำหนด semantics ของ payload, truncation, hash และ provenance.
5. แก้ forensic wrap/replay, durable anchor, stale index และ unavailable/no-diff distinction.
6. ทำ dashboard authentication/loopback default และ backup restore containment/atomicity.
7. รวม installer เป็น transaction เดียวที่ตรวจ signature, hash, service, driver, health และ rollback postconditions.

### P2 — ขยายหลักฐานและความสามารถในการดูแล

1. เพิ่ม Windows VM CI แบบ non-skippable สำหรับ named pipe, token/ACL, WFP IOCTL, driver lifecycle, installer และ recovery.
2. เพิ่ม concurrency, fuzz, mutation, disk-full, crash-after-mutation, driver-unload และ blocked-shutdown tests.
3. เพิ่ม code coverage จริงต่อ Zig/Rust/Go/Python/TypeScript แทน job-presence claims.
4. รวม config/rules เป็น signed, versioned, schema-validated source เดียว.
5. ลด PII/payload retention ด้วย redaction, encryption, ACL, quotas และ bounded streaming.

## 8. ลำดับ validation ที่ปลอดภัย

ให้รันตามลำดับนี้เท่านั้น และเก็บ output เป็น evidence ที่ผูกกับ commit, environment และ SHA-256:

1. ตรวจ `git status`, HEAD, tracked imports และ regenerate truth artifacts.
2. รัน Python compile/tests และ contract tests ที่ไม่ทำ host mutation.
3. รัน root `cargo test` จาก `Cargo.toml` ที่มีอยู่จริง ไม่ใช้ `rust-src\Cargo.toml` โดยเดา.
4. รัน `zig build` และ Zig tests ด้วย toolchain ที่ pin version.
5. รัน Go tests และ cross-language frame vectors.
6. build user bridge และ driver จาก canonical script เดียว.
7. ตรวจ signature, build hash กับ installed hash และ service `binPath` ให้ตรง.
8. หยุด daemon ทุกตัวและ start เพียงหนึ่ง process; verify authoritative health จาก control pipe.
9. รัน observe-only 10-frame proof.
10. ทดสอบ malformed block request ต้อง reject และไม่สร้าง filter.
11. ใน disposable VMware lab เท่านั้น ตรวจ baseline HTTP 200 ของ `192.168.126.20:8080`.
12. หลัง P0 ผ่านแล้วจึงทำ block request ผ่าน Control Pipe → Zig → Rust PEP → WFP และตรวจ traffic postcondition.
13. ตรวจ receipt และ forensic linkage ครบทุก ID ก่อนประกาศ block.
14. ส่ง unblock ด้วย `filter_id` จาก receipt เดิม ตรวจ HTTP 200 และไม่มี orphan filter.
15. รัน lifecycle recovery proof และตรวจ generation, singleton, stale handle และ forensic chain.

ห้ามใช้ `netsh`, Windows Firewall API, legacy `block_ip`, in-memory blocked map, process existence, log-only decision หรือ bookkeeping เป็นหลักฐาน host block

## 9. เกณฑ์ Production Acceptance ที่ปรับปรุงแล้ว

การรับรองต้องมีหลักฐาน machine-verifiable ของทุกข้อ: clean checkout build; canonical ABI vectors; signed/provider-attested driver; build hash เท่ากับ installed hash; exactly one daemon; authoritative health; 10/10 ingress; malformed request fail-closed; baseline 200; receipt `ENFORCED` พร้อม non-zero filter ID; actual TCP failure; full forensic linkage; exact filter-ID cleanup; restored HTTP 200; no orphan filter; restart/recovery; deterministic package/SBOM; และ current-head evidence maps

หากข้อใดไม่มีหลักฐานหรือมีเพียง static/in-memory proof ให้ผลเป็น **NOT ACCEPTED** ไม่ใช่ `PRODUCTION_ATTESTED`

## References

[1]: ../AEGISWindowsNIDS_IPS—ProductionHandoffReport.md "AEGIS Windows NIDS/IPS Production Handoff Report"
[2]: ../src/policy/pep_bindings.zig "Zig to Rust PEP bindings"
[3]: ../rust-src/lib.rs "Rust PEP and WFP adapter"
[4]: ../drivers/wfp_callout/aegis_wfp.c "WFP kernel driver implementation"
[5]: ../drivers/wfp_callout/aegis_wfp.h "WFP shared IOCTL contract"
[6]: ../src/windows/wfp_ioctl.c "WFP user-mode bridge"
[7]: ../src/capture/nose_pipe_reader.zig "Zig Nose named-pipe reader"
[8]: ../nose/pipe_writer.go "Go Nose frame writer"
[9]: ../src/policy/dispatcher.zig "Active policy dispatcher"
[10]: ../tools/aegisctl/api/control_api.py "Python control-plane API"
[11]: ../tools/aegisctl/web_dashboard/app.py "Operational dashboard"
[12]: ../tools/backup_recovery.py "Backup and restore operations"
[13]: ../SYSTEM_MAP.json "Runtime system map"
[14]: ../FLOW_MAP.json "Runtime flow map"
[15]: ../EVIDENCE_INDEX.json "Evidence index"
[16]: ../runtime_manifest.json "Runtime manifest"
[17]: ../build_manifest.json "Build provenance manifest"
[18]: ../tests/wfp/test_t11_windows_host.py "Windows WFP host test"
[19]: ../PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md "Production completion runbook"
