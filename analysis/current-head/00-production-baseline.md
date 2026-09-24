# AEGIS Production Baseline และแผนลงมือทำแบบ Production-safe

**Repository:** `NIDs_Windows`  
**Review baseline:** `HEAD 46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**สถานะตัดสิน:** **NOT PRODUCTION-READY; prevention ต้องปิดอยู่**  
**โหมดที่อนุญาตในระหว่าง convergence:** `detection-only` หรือ `degraded` เท่านั้น

> รายงานนี้สังเคราะห์ผล review ของ build/inventory, ABI/contract, runtime/lifecycle, data plane/detection, brain/policy, PEP/WFP/native, forensics/security และ operator/release เข้าด้วยกัน โดยยึด source และ active call graph เป็นหลัก ไม่ยกระดับผลจากไฟล์ที่มีอยู่, log, UI state, PEP decision, DLL/SYS presence หรือ static test ให้เป็นหลักฐาน host enforcement

## 1. Executive decision

AEGIS มี implementation จำนวนมากและมีทิศทาง architecture ที่ถูกต้อง แต่ยังไม่มีเส้นทาง Production เดียวที่พิสูจน์ครบตั้งแต่ ingress ไปจนถึง host effect และ cleanup เส้นทาง executable ที่ review พบคือ `build.zig -> src/main.zig -> src/platform/win32_service.zig -> src/daemon.zig -> RuntimeSupervisor -> event_processor` โดยมี Go Nose เป็น external producer ผ่าน named pipe พร้อมกับ legacy sensor, ETW, FIM และ Registry paths อื่นที่ยัง active อยู่ เส้นทางนี้ยังไม่ใช่ golden path ที่พิสูจน์ end-to-end บน Windows current head

ข้อสรุปสำคัญมีห้าประการ

1. **Prevention ต้องปิด** เพราะ `RustPep.execute` ยังมี in-memory/simulation behavior, dispatcher สามารถ log การ execute จาก PEP decision, และ active PEP response ยังไม่มี provider/filter identity, host-effect postcondition หรือ `EnforcementReceipt` ที่ตรวจสอบได้ การตอบ `accepted`, `executed`, `SUCCESS` หรือการมี DLL/SYS ไม่ใช่หลักฐานว่า traffic ถูก block
2. **Security boundary ยังไม่ปลอดภัยพอสำหรับ privileged operation** control pipe ใช้ `lpSecurityDescriptor=null` และ derive role จาก token ของ daemon แทนการ impersonate client; Rust PEP รับ `caller_pid`/`caller_capability_mask` จาก request; WFP device/IOCTL ยังไม่มี restrictive SDDL และ caller validation ที่พิสูจน์แล้ว
3. **Contract ยังแยกเป็นหลายชุด** active Nose ใช้ raw frame `4 + 109 = 113` bytes แต่ support WEV1 ใช้ `16 + 109 = 125` bytes; Go เขียน `struct_size=128` ขณะที่ fixtures/metadata ระบุ 109 และ Zig อ้าง `@sizeOf`; Nose reader push เข้า `event_queue` แต่ dispatcher drain `event_fabric`; policy action ordinals ระหว่าง Zig, TypeScript และ canonical path ไม่ตรงกัน
4. **Policy loader ยังไม่เป็น signed canonical loader** daemon โหลด `configs/policies.json` โดยตรง ใช้ parser แบบ ad hoc, unknown action map เป็น `pass`, TTL ไม่ถูกบังคับ, unknown operator/field ถูก normalize และ active loader ไม่เรียก Ed25519 verification ทำให้ policy artifact ที่ผิดหรืออ่อนกว่าสามารถลดระดับการบังคับใช้ได้
5. **Evidence, lifecycle และ release ยังไม่ปิด gate** forensic ring เป็น process-local/volatile และยังไม่ผูก event, policy digest, PEP request, provider/filter, receipt, trace, audit, runtime generation และ cleanup ครบถ้วน; export/replay บาง handler เป็น success-shaped placeholder; package/build/signing/driver/installer paths ขัดแย้งกัน และ truth artifacts หลายชุด stale

Handoff ระบุว่ามี observe-only data-plane evidence และ lifecycle recovery evidence ในอดีต แต่ evidence ดังกล่าวไม่ใช่ current-head Windows host-effect proof และไม่ปิดข้อบกพร่องของ receipt, authorization, provider postcondition, cleanup, package หรือ rollback ในรายงานนี้ [1] [2]

## 2. หลักการตัดสินและข้อจำกัดของหลักฐาน

### 2.1 ลำดับความน่าเชื่อถือ

ให้ใช้ลำดับต่อไปนี้เสมอ: runtime ที่สังเกตได้จริง, source ณ HEAD ที่ระบุ, build/link graph, generated truth ที่ verify แล้ว, test/evidence ที่ผูกกับ HEAD และเอกสารเก่าเป็นลำดับท้าย รายงาน review ทั้งหมดเป็น source-level review ที่ HEAD ตามที่ระบุ จึงไม่อนุญาตให้ตีความผลเป็น Windows execution result

Repository มี working-tree modifications ขณะจัดทำ baseline เช่น `build.zig`, `src/daemon.zig`, `rust-src/lib.rs`, `src/capture/nose_pipe_reader.zig`, `src/platform/win32_pipe.zig`, policy/forensic files, `inventory.json`, `reference_map.json` และ `runtime_manifest.json` ดังนั้นผลการเปลี่ยนแปลงเหล่านี้ต้องแยกจาก commit `46b93dc...` และห้ามเรียกว่า current-head proof จนกว่าจะกำหนด commit ใหม่และ regenerate artifacts ใหม่

### 2.2 Evidence language

- **E0/E1:** source review, architecture review, static inspection หรือยังไม่มี execution proof
- **E2:** unit/module test
- **E3:** deterministic component integration
- **E4:** Windows component integration
- **E5:** end-to-end system simulation
- **E6:** clean-room production simulation
- **E7:** independent release verification

รายงานนี้ถือ Windows Zig/Rust/CMake/MSVC/WDK/Go/Node execution, elevated token, Npcap live capture, actual DLL loading, WFP effect, VMware VMnet1 isolation, service/device identity, install/upgrade/rollback/uninstall และ signing เป็น **UNVERIFIED** เว้นแต่มี evidence artifact ที่ระบุ commit, binary digest, host, command, pre/postcondition และ cleanup ครบถ้วน

## 3. Invariants ที่ห้ามถูกละเมิด

### I-1: One runtime owner

`Zig daemon` เป็น owner เดียวของ start, stop, restart, readiness, worker handles, health, queue coordination และ control protocol CLI, dashboard, installer และ legacy scripts เป็น client/support เท่านั้น ห้ามเป็น supervisor ที่สอง ห้ามใช้ PID scan หรือ `taskkill` เป็น operational truth

### I-2: One ingress authority

ทุก producer ต้องส่งผ่าน ingress authority และ queue/fabric เดียวที่มี bounded backpressure, reason-coded drop ledger และ event identity เดียวกัน ห้ามมี active dual path ระหว่าง legacy sensor กับ Go Nose โดยไม่ประกาศ compatibility boundary และพิสูจน์การรวม identity

### I-3: Detection ไม่ใช่ enforcement

`DetectionResult != PolicyDecision != PEP authorization != WFP host effect != verified postcondition` ตัวตรวจจับ, Python/Cython, TypeScript, Go Nose และ Zig orchestration ขอ action ได้ แต่ห้าม mutate WFP หรือสร้าง final `BLOCKED`

### I-4: Rust PEP เป็น privileged authority เดียว

มีเพียง authenticated Rust PEP/provider boundary ที่ authorize และ mutate privileged filtering state ได้ direct C/C++ WFP exports, bridge, Shield, scripts และ caller-supplied capability ต้องถูกลบ, quarantine หรือทำให้ unreachable จาก production image

### I-5: Receipt-driven truth

เฉพาะ receipt ที่ผ่านเงื่อนไขต่อไปนี้เท่านั้นจึงเรียกว่า `BLOCKED_CONFIRMED` หรือ `ENFORCED`:

```text
receipt.version == supported
receipt.status == ENFORCED
receipt.host_effect_confirmed == true
receipt.request_id != 0
receipt.event_id != 0
receipt.trace_id != 0
receipt.audit_id != 0
receipt.filter_id != 0
provider identity และ policy digest/version ตรวจสอบได้
postcondition และ cleanup result ตรวจสอบได้
```

PEP decision, provider return code, dispatcher log, forensic intent, Mouth counter หรือ dashboard state ที่ไม่มี receipt ไม่ใช่ host block

### I-6: Fail closed

PEP/WFP/driver/DLL/policy/evidence unavailable, ambiguous provider response, zero filter ID, failed postcondition, stale request, malformed response หรือ cleanup failure ต้องเป็น `ENFORCEMENT_UNAVAILABLE`, `ENFORCEMENT_FAILED`, `POSTCONDITION_FAILED`, `AUTHORIZATION_DENIED` หรือสถานะที่ไม่ใช่ `ALLOW`/`ENFORCED` ตามกรณี ห้ามลด error เป็น allow และห้ามเปิด prevention ระหว่าง proof ไม่ครบ

### I-7: Evidence ต้อง finalized และ durable ตาม claim

Finalized record ต้อง link `event_id -> detection/incident -> policy id/version/digest/signer -> PEP request -> provider/filter -> receipt -> trace/audit -> runtime generation -> cleanup/rollback` และต้องบันทึก source commit, dirty-tree state, binary/dependency/toolchain digest และ host identity

## 4. Stop-the-line register แบ่งตามความรุนแรง

### P0 — Security / Safety

**P0-S1: ไม่มี authoritative EnforcementReceipt และ host-effect proof** — `PepResponse` ปัจจุบันมีเพียง decision/reason/quota/signed_by; `ActionDispatcher` และ forensic path สามารถรับรอง WFP จาก decision/log โดยไม่มี provider, filter ID, host postcondition, receipt version และ linkage ครบถ้วน `RustPep.execute` ยังแทรก IP เข้า in-memory map แล้วคืน `executed` ได้ จึงห้ามเปิด prevention

**P0-S2: Privileged control boundary ไม่ bind กับ client identity** — control named pipe ใช้ null security descriptor; authorization ใช้ `GetCurrentProcess()` ของ daemon ไม่ใช่ impersonated connecting client และ token-query failure ลดสิทธิ์เป็น `operate` แทน deny ต้องแก้ SDDL, impersonation, SID/integrity และ deny-on-ambiguity

**P0-S3: WFP device/IOCTL boundary ยังรับ caller ที่ spoof ได้** — driver/device ไม่แสดง restrictive SDDL และ mutating IOCTL ไม่ตรวจ OS token/SID/integrity อย่างเพียงพอ Rust ใช้ capability/PID ที่ caller ส่งมาเอง และ unblock discard `caller_pid/request_id`

**P0-S4: Policy input สามารถ fail-open ทาง semantic** — active daemon อ่าน unsigned JSON, unknown action map เป็น `pass`, unknown field/operator normalize, `gte` semantics ผิด, อ่านเพียง clause แรก, TTL/expiry ไม่ถูกบังคับ และ active loader ไม่ verify Ed25519 จึงห้าม policy block ใด ๆ ถูกถือว่า trusted

**P0-S5: มี duplicate/direct mutation authority** — `src/windows/aegis_wfp.c` export direct `FwpmFilterAdd0/FwpmFilterDeleteById0`; C helper/driver/Rust adapter เป็นหลาย transport; Shield/direct helper และ legacy scripts เป็น risk ของ second authority ต้องมี static authority lint และ production-image negative proof

**P0-S6: Replay/export ที่ success-shaped อาจทำให้ mutation หรือ false evidence ผ่าน** — replay มี enforce mode/protocol mutation semantics และ export/replay handlers คืน success โดยยังไม่มี verified deterministic, observe-only implementation ห้ามใช้เป็น evidence หรือ enforcement path

### P1 — Correctness / Contract

**P1-C1: Wire framing และ size semantics ขัดแย้ง** — active Go raw frame คือ 113 bytes (`u32 length + 109 payload`), support WEV1 คือ 125 bytes (`16 header + 109 payload`), Go marker คือ 128 ขณะที่ fixtures/metadata ระบุ 109 และ Zig อ้าง in-memory `@sizeOf` 128 บางจุด ต้องแยก `WIRE_PAYLOAD_SIZE=109` จาก `ABI_MEMORY_SIZE=128` หากนั่นคือข้อสรุปที่ canonical contract เลือก และต้องไม่ส่ง natural-aligned struct ข้ามภาษา

**P1-C2: Queue authority ขาดการเชื่อมต่อที่พิสูจน์ได้** — `nose_pipe_reader.zig` push เข้า `event_queue` แต่ dispatcher drain `event_fabric`; active path ไม่พิสูจน์ว่าผู้บริโภคเดียวกันถึง detection และ forensics ได้ และ active legacy sensor เพิ่ม producer อีกชุด

**P1-C3: Policy enum/status/digest ไม่ตรงกัน** — action ordinals ของ `src/policy/policy_ir.zig` ไม่ตรงกับ TypeScript/canonical; raw action ถูกส่งเข้า Rust; TypeScript, Zig policy plane, policy IR และ seal ใช้ representation/digest คนละแบบ; error/status/decision ถูกปะปน

**P1-C4: Payload และ event identity สูญหาย** — Go canonical ingress ส่ง metadata แต่ Zig conversion ส่ง payload ว่างให้ detector; IpcEvent conversion drop identity/evidence fields และลด payload hash เป็น u32; event ID เป็น process-local และ reset เมื่อ Nose/runtime restart จึงยังไม่มี dedup/idempotency ข้าม generation

**P1-C5: Runtime shutdown/readiness ยังไม่ bounded** — synchronous `ConnectNamedPipe`, `ReadFile`, `FlushFileBuffers` และ Go writer อาจ block; supervisor ตั้ง stop flag ก่อน join แต่ไม่มี deadline/postcondition; daemon รายงาน STOPPED ก่อน worker/pipe release; heartbeat reducer ไม่ครบและ `RUNNING` อาจค้างหลัง worker ตาย

**P1-C6: Multi-producer queue/counters ยังไม่พิสูจน์** — producer head publication ไม่มี CAS/producer lock ที่พิสูจน์กับหลาย producer; push result ถูกละเลย; ETW metrics อาจเพิ่มแม้ queue insertion fail; 64-bit counter ถูก cast เป็น u32; Event Fabric drop ledger ถูก bypass

**P1-C7: PEP/native/build graph ไม่ converge** — root CMake default ไม่ build driver และอ้าง `kernel/wfp_callout` ขณะที่ source อยู่ `drivers/wfp_callout`; driver dispatch สองชุดตีความ UNBLOCK ต่างกัน; ownership/filter cleanup จำกัด/ไม่ครบ; device/service/DOS link/provider identity ยังไม่พิสูจน์

**P1-C8: Forensic record ไม่สมบูรณ์และไม่ durable** — ring เป็น process-local/volatile ไม่มี policy digest, request/receipt/provider/filter, trace/audit, generation, cleanup; invalid ring sizes อาจ panic; forensic write/export/error propagation ยังไม่ครบ

### P2 — Hardening / Operational resilience

**P2-H1:** ต้อง bound malformed frame length ก่อน discard รวม `0xFFFFFFFF`, reject/close connection และทดสอบ partial read/write, truncated payload, reconnect, EOF และ shutdown cancellation

**P2-H2:** ต้องมี ABI conformance harness กับ DLL จริง ครอบคลุม size/offset, calling convention, symbol/version handshake, ownership/lifetime, malformed response, unknown decision ordinal และ struct-size compatibility

**P2-H3:** ต้องใช้ trusted absolute DLL/driver paths, restricted DLL search, Authenticode/pinned digest, ABI handshake และ ACL-protected install directory

**P2-H4:** ต้องสร้าง producer identity + runtime generation + producer epoch + sequence หรือ global ingress ID พร้อม duplicate/replay/idempotency semantics และ counters ที่แยก collision, duplicate, non-monotonic, rejected, capacity-dropped และ lifecycle-dropped

**P2-H5:** ต้อง preserve binary payload แบบ length-aware รวม embedded NUL, invalid UTF-8, IPv6, oversized/truncated input และทำ Cython/Python parity กับ active module จริง ห้าม `str(payload)` เป็น detector semantics

**P2-H6:** ต้องมี durable audit/hash-chain checkpoint, safe payload ACL/redaction, bounded exporter retries, format escaping, partial-write handling และ deterministic observe-only replay จาก historical event/policy/context/build identity

**P2-H7:** ต้องมี heartbeat/watchdog ของ worker ทุกตัว, bounded join, stop acknowledgement, pipe handle cancellation/close, stale-generation rejection และ fail-safe recovery หลัง enforcement

### P3 — UX / Release / Provenance

**P3-R1:** Mouth และ dashboard ใช้ log/event strings คำนวณ blocked/DEFCON/total blocked ได้ ต้องเปลี่ยนเป็น validated receipt stream และแยก `OBSERVED`, `ALERTED`, `POLICY_BLOCK_REQUESTED`, `AUTHORIZATION_DENIED`, `ENFORCEMENT_UNAVAILABLE`, `ENFORCEMENT_FAILED`, `BLOCKED_CONFIRMED`, `ROLLED_BACK`

**P3-R2:** legacy `run_aegis.bat`, `stop_aegis.bat`, `aegis_status.py` อาจเป็น second supervisor, global `taskkill`, PID/process heuristic และ status false-positive ต้อง quarantine หรือ hard-fail ใน package ปกติ

**P3-R3:** package/installer/release paths ขัดแย้งกัน: CI ส่ง arguments ที่ `installer.py` ไม่รองรับ; versions และ directories ต่างกัน; kernel driver ถูก omit; clean install/upgrade/interrupted upgrade/rollback/uninstall ยังไม่พิสูจน์

**P3-R4:** signing เป็น development/test-signing มี hard-coded PFX password และ optional testsigning; `signatures.json` เป็น claim file ไม่ใช่ cryptographic signature; SBOM ใช้ Python `hash()` ที่ไม่ deterministic และ omit binary/dependency trees

**P3-R5:** generated truth/build provenance stale หรือขัดแย้ง และ release bundle เป็น version 6.0.0 ที่ไม่มี current-head provenance ขณะที่ metadata อื่นระบุ 5.0.0 หรือ commit เก่า จึงห้าม release

## 5. Contradictions และ source-of-truth decisions ที่ต้องปิด

| เรื่อง | หลักฐานที่ขัดแย้ง | การตัดสินใจที่ต้องทำก่อน implementation | ห้ามอ้างจนกว่าจะปิด |
|---|---|---|---|
| Event frame | raw Nose 113 bytes กับ WEV1 125 bytes | เลือกและตั้งชื่อ contract เดียว เช่น `NoseRawEventFrameV1` หรือ `WEV1`; quarantine อีก path; สร้าง vectors ทุกภาษา | Go↔Zig compatibility |
| Struct size | Go marker 128, fixture/metadata 109, Zig `@sizeOf` | นิยาม wire payload size กับ memory ABI size แยกกัน หรือเลือก semantics เดียวอย่างชัดเจน | positive fixture ผ่าน |
| Ingress queue | reader push `event_queue`, dispatcher drain `event_fabric` | เลือก Event Fabric หรือ `event_queue` เป็น authority เดียวและ route ทุก producer ผ่าน adapter เดียว | event reached dispatcher |
| Event identity | process-local counters หลายชุดและ reset ข้าม restart | global ingress ID หรือ producer/generation/epoch/sequence พร้อม idempotency | exactly-once/replay-safe |
| Policy authority | TypeScript, Zig policy plane, `policy_ir`, seal และ JSON loader | generate Policy IR, action/error/operator maps และ canonical bytes จาก source เดียว | digest/action equivalence |
| Policy loading | active unsigned ad hoc `policies.json` กับ additive Ed25519 helper | signed canonical envelope, trust store, expiry, version, rollback floor และ reject unknown | policy trusted |
| Enforcement state | PEP decision, in-memory `executed`, direct C WFP, Rust adapter, driver | Rust PEP/provider เป็น mutation authority เดียว; all other paths request/support only | blocked/confirmed |
| PEP result | 16-byte decision-only response กับ required receipt | versioned receipt API or receipt-returning side channel with complete identity | provider success |
| Driver graph | root CMake points wrong path/default OFF กับ `drivers/wfp_callout` source | select one driver/source/service/IOCTL/SDDL mapping and build it as required artifact | driver ready |
| Auth identity | control uses daemon token; PEP trusts caller fields; device ACL unproven | impersonated OS token at each boundary; deny on ambiguity | privileged client acceptance |
| Lifecycle | handoff records source-level readiness/supervisor patches; reviews find blocking I/O and optimistic STOPPED | rerun bounded Windows tests against exact resulting commit | orderly shutdown/restart |
| Evidence | prior observe-only/lifecycle evidence in handoff vs volatile/incomplete current forensic implementation | classify old evidence as historical and regenerate current-head evidence with digest/generation | current production claim |
| Release | bundle 6.0.0, metadata 5.0.0, old commit/provenance and unsupported CI args | one manifest-driven package graph with current HEAD, signing, SBOM and clean-room proof | release acceptance |

## 6. Vertical slice execution order

แต่ละ slice ต่อไปนี้เป็นงานที่สามารถทำและตรวจได้เป็นลำดับ โดยห้ามข้าม exit gate ไปทำ slice ถัดไปในลักษณะที่ทำให้ prevention ดูเหมือนพร้อม

### Slice V0 — Current-head truth, safety containment และ change-control freeze

**วัตถุประสงค์:** ทำให้ทุกคนรู้ว่าอะไรเป็น source ปัจจุบัน อะไรเป็น generated artifact และปิดช่องทางที่อาจทำให้ review อ้างสถานะเกินจริง

**Invariant:** prevention remains closed; no direct WFP mutation outside the selected authority; every artifact and test result carries exact commit, dirty-tree state and toolchain identity; stale maps never act as truth

**Files/symbols:** `tools/truth.py`; `SYSTEM_MAP.json`; `FLOW_MAP.json`; `AUTHORITY_MAP.json`; `CONTRACT_MAP.json`; `EVIDENCE_INDEX.json`; `build_truth.json`; `build_manifest.json`; `AI_CONTEXT.md`; `inventory.json`; `reference_map.json`; `runtime_manifest.json`; `build.zig`; root/bridge CMake; `Cargo.toml`; release manifests; `AGENTS.md`

**Tests ก่อนแก้:** บันทึก `git rev-parse HEAD`, branch, status, log, `git ls-files`; รัน `python tools/truth.py verify` และเก็บผล `TRUTH_INVALID`; ตรวจ source/build scope และเก็บ list of stale/missing/mismatched artifacts แยกจาก working tree

**Tests หลังแก้:** generator ทุกตัวรันจาก clean checkout; strict verify ต้อง fail เมื่อ source, commit, path, SHA, build graph หรือ package scope ไม่ตรง; verify ต้องผ่านเมื่อ regenerated จาก exact HEAD; static authority lint ต้อง fail หากพบ direct mutation หรือ second supervisor

**Windows-only proof:** ไม่มีสิทธิ์สรุปจาก sandbox ต้องรัน clean Windows checkout ด้วย build/test matrix และเก็บ `git commit`, source-tree digest, binary digest, toolchain versions และ preflight output ก่อนพิจารณา gate ต่อไป

**Rollback:** revert generated artifacts หรือ restore prior known-good snapshot แต่คง prevention gate ปิด; ห้าม rollback ไปยัง stale map แล้วใช้เป็น current truth; แยกงานจาก dirty tree ด้วย clean worktree/commit ใหม่

**Exit gate:** ไม่มี stale/contradictory truth artifact; inventory-to-git scope reconciliation ผ่าน; exact HEAD/dirty state ถูกบันทึก; direct authority lint ผ่าน; release และ host-enforcement claims ยังเป็น closed

### Slice V1 — Privileged boundary containment และ one-authority fence

**วัตถุประสงค์:** ทำให้ unauthorized/malformed/unavailable path ไม่สามารถ mutate host และทำให้ direct paths compile/run ไม่ได้ใน production surface

**Invariant:** only authenticated Rust PEP may request privileged mutation; caller identity derives from Windows token at boundary; missing/ambiguous identity, capability spoof, provider unavailable และ zero filter ID fail closed; no UI/evidence reports confirmed block without receipt

**Files/symbols:** `src/platform/win32_pipe.zig` pipe creation/handler; `src/control/authorization.zig`; `src/control/protocol.zig`; `src/core/rust_pep.zig` (`RustPep.execute`, `block_ip`, `unblock_ip`); `src/policy/pep_bindings.zig`; `rust-src/lib.rs` (`aegis_pep_enforce`); `src/windows/aegis_wfp.c`; `src/windows/wfp_ioctl.c`; `drivers/wfp_callout/*`; root/bridge CMake; `shield/` and `rust-src/shield/`; `scripts/run_aegis.bat`, `scripts/stop_aegis.bat`, `tools/aegis_status.py`

**Tests ก่อนแก้:** static grep/authority graph ของ direct `Fwpm*`, IOCTL mutation, caller-supplied capability/PID และ legacy supervisors; unit tests malformed PEP response, missing DLL/driver, zero filter, provider error และ no-receipt behavior; เรียกดูว่า `RustPep.execute` อาจคืน executed จาก in-memory map

**Tests หลังแก้:** standard user, low-integrity, wrong SID, spoofed PID/capability, malformed decision ordinal, missing provider, duplicate request, expired request และ invalid policy ต้องถูกปฏิเสธหรือ `UNAVAILABLE/FAILED`; direct C bridge and legacy script must be unreachable/negative-tested in production build; receiptless dispatcher/forensic/UI path must never emit `BLOCKED_CONFIRMED`

**Windows-only proof:** Administrator, standard user, separate local account และ low-integrity process ทดสอบ control pipe SDDL + client impersonation; เปิด device ด้วย expected path; ส่ง mutating IOCTL ที่ถูกต้องและ spoofed; ตรวจ service/device/DOS link/provider ownership; ทดสอบ missing DLL/driver และ wrong endpoint บน Windows x64

**Rollback:** keep `host_effect_capable=false` and prevention disabled; if auth or authority lint fails, remove mutation artifacts from package and return `NOT_IMPLEMENTED/UNAVAILABLE`; never restore direct mutation merely to make a demo pass

**Exit gate:** one privileged authority in build and runtime graph; restrictive SDDL and token binding proven on Windows; no caller-controlled capability/PID; all failure paths fail closed; no confirmed block without valid receipt

### Slice V2 — Canonical contract and ABI freeze

**วัตถุประสงค์:** freeze event, IPC, policy, status/error และ receipt ABI ก่อนแก้หลายภาษาพร้อมกัน

**Invariant:** Go, Zig, Rust, C/C++, Python และ TypeScript agree on explicit wire layout, offsets, byte order, enums, ownership, length, version, malformed-input behavior and error mapping; memory layout is never silently used as wire layout

**Files/symbols:** `src/contract/canonical_event.zig`; `src/contract/event.zig`; `src/contract/wire_event.zig`; `shared/event/`; `shared/wire/`; `contracts/fixtures/`; `nose/canonical.go`; `nose/pipe_writer.go`; `src/capture/nose_pipe_reader.zig`; `nose/golden_path_ffi.go`; `src/policy/policy_ir.zig`; `ts_policy/src/compiler.ts`; `ts_policy/src/seal.ts`; `src/policy/pep_bindings.zig`; `rust-src/lib.rs`

**Tests ก่อนแก้:** เก็บ failing vectors ของ 109/113/125, struct 109/128, all enum ordinals, `EventID` offset bug ใน `golden_path_ffi.go`, unknown response ordinal, partial frame และ reserved bytes

**Tests หลังแก้:** generated offsets/size manifests; cross-language positive and negative golden vectors; round-trip Go↔Zig↔Rust/C++/Python; vectors for magic/version/length/CRC if chosen, embedded NUL, IPv4/IPv6, malformed length, truncated payload, unknown action/error/decision; ABI harness against actual built DLL, not only mock/unit library

**Windows-only proof:** build and execute x86_64 Windows ABI harness against exact `aegis_pep.dll`, `aegis_wfp_user.dll`, driver/device endpoint and Go/Zig binaries; record calling convention, struct offsets, symbol/version handshake and malformed input results

**Rollback:** quarantine new schema behind explicit version; keep active prevention closed and retain old decoder only as observe-only compatibility input with telemetry; do not silently accept both semantic meanings of `struct_size`

**Exit gate:** one named wire contract, one Policy IR/status map, one receipt ABI, generated vectors pass in every selected language, and any unsupported legacy path is explicitly marked support/legacy in manifest

### Slice V3 — Canonical observe-only data plane

**วัตถุประสงค์:** พิสูจน์ Go Nose → authenticated ingress → queue/fabric → detector → finalized detection forensic record โดยไม่ mutate WFP

**Invariant:** one ingress authority; one event identity remains unchanged to forensics; payload/evidence reference is preserved; every accepted/rejected/capacity/lifecycle drop has reason and counter; no detection result can block

**Files/symbols:** `nose/main.go`; `nose/capture.go`; `nose/canonical.go`; `nose/pipe_writer.go`; `src/capture/nose_pipe_reader.zig`; `src/pipeline/event_queue.zig`; `src/contract/event_fabric.zig`; `src/pipeline/dispatcher.zig`; `src/pipeline/event_processor.zig`; `src/detection/`; `src/forensic/forensic_pipeline.zig`; legacy `src/core/nids_capture.zig`

**Tests ก่อนแก้:** send all five golden vectors; verify active reader behavior; trace `event_queue` vs `event_fabric`; test concurrent Go Nose, legacy sensor, ETW/FIM/Registry producers; observe payload loss, duplicate local IDs, ignored push results, unbounded length discard and queue saturation

**Tests หลังแก้:** one end-to-end synthetic event with same identity at source, queue, detector, policy input and forensic record; reconnect/EOF/partial I/O; restart with producer generation and dedup; flood/backpressure conservation; binary/NUL/invalid encoding/oversized payload; assert detector cannot invoke WFP; compare sent/accepted/rejected/dropped/processed/forensic counters

**Windows-only proof:** run exact Go Nose and Zig daemon on Windows with Npcap adapter selection and BPF; use benign traffic on isolated lab profile; verify named-pipe ACL, live capture, event counts and forensic record. Direct Zig Npcap path must either be proven out-of-scope or removed from production graph

**Rollback:** disable legacy producer and revert to observe-only synthetic ingress; if conservation or identity fails, set runtime degraded and block enforcement; retain raw evidence for diagnosis, never retry side effects blindly

**Exit gate:** E4/E5 observe-only evidence shows one event identity end-to-end, no payload semantic loss, bounded shutdown, no unexplained drops, and no WFP mutation; only then can detection/policy slice consume this path

### Slice V4 — Signed canonical policy and detection semantics

**วัตถุประสงค์:** replace direct unsigned JSON with one signed Policy IR and make action/condition/expiry/version semantics identical across languages

**Invariant:** unsigned, bad signature, unknown key, revoked key, expired/not-yet-valid, rollback, malformed action/operator/field, unsupported schema and digest mismatch are rejected; no unknown value maps to `pass`; active policy has immutable ID/revision/digest/signer/expiry/schema

**Files/symbols:** `src/daemon.zig` policy loading around `Rules.json`/`policies.json`; `src/policy/policy_ir.zig`; `src/policy/policy_contract.zig`; `src/policy/policy_signing.zig`; `src/pipeline/rule_loader.zig`; `configs/policies.json`; `ts_policy/src/compiler.ts`; `ts_policy/src/seal.ts`; `ts_policy/tests/`; `contracts/fixtures/pep/`; `src/pipeline/event_processor.zig`; Python/Cython `brain/` and `src/detection/`

**Tests ก่อนแก้:** unsigned/bad signature/unknown key/expiry/rollback vectors; unknown action mapping to pass; TTL no-op; unknown fields/operators; first-clause-only behavior; TypeScript vs Zig digest mismatch; Cython/Python binary payload parity gap

**Tests หลังแก้:** canonical byte/digest/signature equivalence; action map tests for `BLOCK`, `RATE_LIMIT`, `LOG_ONLY`, `ALERT`, `ESCALATE`; expiry and clock-skew; persistent rollback floor; atomic reload with last-known-good retention and generation/digest propagation; arbitrary bytes, NUL, invalid UTF-8, max payload and timeout parity for active detector implementations

**Windows-only proof:** load signed/invalid policy through actual daemon and verify health/audit/forensic states; verify policy reload, reject and rollback with runtime generation; no WFP action is allowed merely because policy says block

**Rollback:** retain last-known-good signed policy only if its rollback floor and signature remain valid; otherwise enter degraded/no-prevention; never fallback to unsigned `policies.json` or map parse errors to allow

**Exit gate:** active loader calls mandatory verification, semantic vectors pass across Zig/Rust/TypeScript, policy digest/version appears in all decisions and evidence, and invalid policies fail closed

### Slice V5 — Authenticated control, lifecycle และ truthful health

**วัตถุประสงค์:** make runtime lifecycle real, cancellable และ client-authenticated พร้อม health reducer ที่ไม่หลอกว่า RUNNING

**Invariant:** each transition has one owner, deadline, acknowledgement and postcondition; `STOPPED` only after worker joins/pipe release/evidence flush; `RUNNING` requires required dependencies and fresh worker heartbeats; fallback process scan is diagnostic only

**Files/symbols:** `src/control/protocol.zig`; `src/control/authorization.zig`; `src/control/state_machine.zig`; `src/control/handler_registry.zig`; `src/control/audit.zig`; `src/platform/win32_pipe.zig`; `src/daemon.zig` `RuntimeSupervisor`; `src/pipeline/event_processor.zig`; `src/pipeline/runtime_state.zig`; `src/reliability/`; `tools/aegisctl.py`; `tools/aegisctl/api/control_api.py`; `scripts/aegis_daemon.py`; legacy stop/status scripts

**Tests ก่อนแก้:** held `ConnectNamedPipe`/`ReadFile`, partial Nose frame, slow/full writer, stop race, missing nonce/version/deadline, replay request, PID reuse and worker stall; inspect optimistic STOPPED and static heartbeat fields

**Tests หลังแก้:** overlapped/cancellable I/O or proven handle cancellation; protocol version, request ID, nonce, issued-at/deadline, replay cache, authenticated identity and runtime generation; bounded joins; STOPPING→STOPPED evidence; worker heartbeat/reducer and failure mask; standard-user denial; PID fallback never promotes health; all handler placeholders return audited `NOT_IMPLEMENTED/UNAVAILABLE`

**Windows-only proof:** elevated and non-elevated client matrix; held pipe cancellation; stop/restart with new runtime generation, old process exit, pipe release, worker acknowledgements and health transitions; inject worker failure and verify `DEGRADED/FAILED`, not `RUNNING`

**Rollback:** emergency force-stop is a separately audited break-glass path; normal UI/CLI cannot use it; if cancellation or join deadline fails, stay `STOPPING/DEGRADED` and keep prevention closed

**Exit gate:** one lifecycle owner, no unbounded blocking call, correct auth/replay/deadline behavior, truthful health and postcondition-backed mutations

### Slice V6 — Durable forensic evidence และ observe-only replay

**วัตถุประสงค์:** finalize evidence เป็น first-class contract ก่อน host effect และทำ replay ให้ deterministic/observe-only

**Invariant:** every finalized event/decision has complete linkage and integrity; evidence write failure is visible; replay cannot call PEP/WFP; export does not claim success without source-range, redaction, escaping and write verification

**Files/symbols:** `src/forensic/forensic_pipeline.zig`; `shared/runtime/`; `src/control/audit.zig`; export/replay handlers in `src/control/handler_registry.zig`; `tests/forensics/`; fuzz targets; `mouth/windows_sec_monitor.rs`; dashboard evidence adapters

**Tests ก่อนแก้:** restart/crash persistence, incomplete links, invalid ring size, prefix-match replay, caller-supplied replay outcome, enforce-mode path, partial export/write, SIEM escaping/retry, payload ACL and raw evidence bounds

**Tests หลังแก้:** append/finalize/verify chain with event, policy, PEP request, provider/filter, receipt, trace/audit, generation and cleanup; crash recovery/checkpoint/retention; exact replay from frozen historical event/rules/policy/context/build identity with zero mutation calls; export verification and redaction negative tests

**Windows-only proof:** run active daemon, capture evidence before/after restart and verify generation-qualified integrity; invoke replay while provider is available and assert no WFP/PEP mutation; verify export file ACL and complete write

**Rollback:** disable export/replay and return audited `NOT_IMPLEMENTED/UNAVAILABLE`; retain raw protected evidence for diagnosis; never enable replay enforcement as fallback

**Exit gate:** durable or explicitly bounded evidence matches its claim, replay is observe-only and deterministic, and incomplete receipt/evidence cannot reach confirmed-block UI

### Slice V7 — Versioned EnforcementReceipt through Rust PEP/provider

**วัตถุประสงค์:** implement the first real enforcement vertical slice only after V1–V6 gates pass

**Invariant:** request is authenticated, fresh, non-replayed and bound to signed policy/event; provider response is independently observed; success requires nonzero provider/filter identity, host postcondition, receipt version, complete linkage and cleanup ownership; every ambiguous result fails closed

**Files/symbols:** `rust-src/lib.rs`; `src/policy/pep_bindings.zig`; `src/core/rust_pep.zig`; `src/policy/dispatcher.zig`; `src/forensic/forensic_pipeline.zig`; `src/windows/aegis_wfp.c`; `src/windows/wfp_ioctl.c`; selected `drivers/wfp_callout/*`; CMake/WDK/INF/service files; policy request/receipt fixtures

**Tests ก่อนแก้:** malformed/untrusted Rust response; zero/missing filter; wrong provider; false provider success with no effect; duplicate request ID; stale policy digest; missing DLL/driver; provider error; cleanup failure; restart while active filter; direct C helper bypass

**Tests หลังแก้:** PEP ABI conformance; auth token and policy signature linkage; nonce/deadline/replay-generation tests; provider returns filter identity; independently query filter/provider/traffic postcondition; create receipt only after observation; cleanup/rollback receipt; forensic append failure blocks confirmed state; direct adapters not callable from production graph

**Windows-only proof:** build exact Rust DLL/native helper/driver from selected current source; elevated Administrator matrix and unauthorized standard/low-integrity negatives; service/device/DOS-link/IOCTL/provider/sublayer/filter ownership; only an isolated target is allowed; record `request_id`, `event_id`, `trace_id`, `audit_id`, `policy_digest`, `provider`, `filter_id`, host observation and cleanup

**Rollback:** default `host_effect_capable=false`; any provider ambiguity, postcondition failure or cleanup failure sets `ENFORCEMENT_FAILED/POSTCONDITION_FAILED` and removes/isolates filter if safely possible; if cleanup cannot be proven, stop further enforcement and quarantine host state

**Exit gate:** receipt validation passes and is consumed by forensic/UI; no PEP response or dispatcher log alone can yield `BLOCKED_CONFIRMED`; exact provider/driver ownership and cleanup are proven

### Slice V8 — Isolated VMware VMnet1 host-effect, recovery และ lifecycle acceptance

**วัตถุประสงค์:** prove reversible real host effect in a controlled lab, not on Wi-Fi/NAT/production network

**Invariant:** target is explicit and disposable; baseline reachability is proven; block is observable from independent target; unblock restores reachability; no stale filter/device/runtime ownership remains; all evidence is tied to current commit and binaries

**Files/symbols:** `scripts/run_host_production_preflight.ps1`; `scripts/wfp_service.ps1`; Windows service/driver/INF/package scripts; `tools/aegisctl.py`; `mouth/`; dashboard; selected lab runbook and evidence schema

**Tests ก่อนแก้:** read-only preflight; VMnet1 topology confirmation; target service reachability; capture path and provider readiness; verify `VMnet8`, Wi-Fi, localhost, production gateway and unconfirmed private addresses are excluded

**Tests หลังแก้ / Windows-only proof:** on isolated topology only, `Windows AEGIS host 192.168.126.1`, `Kali 192.168.126.10`, disposable Windows target `192.168.126.20` subject to guest/VMware confirmation: reachability before → signed request → provider/filter create → independent block observation → receipt and forensic linkage → remove filter → reachability after → enumerate provider/filter/device to prove no stale state → restart daemon and repeat generation/recovery. Any timeout is failed proof, not readiness

**Rollback:** pre-registered emergency cleanup removes only owned provider/filter state; if ownership is ambiguous, stop test, isolate host, preserve evidence and do not continue; restore detection-only and `host_effect_capable=false`

**Exit gate:** E4/E5/E6 evidence has independent reachability before/during/after, valid receipt, forensic linkage, cleanup, restart recovery, no stale filter and exact binary/source provenance. This gate cannot be closed by unit/static tests

### Slice V9 — Operator, Mouth, dashboard และ CLI truth convergence

**วัตถุประสงค์:** make operator surfaces consume the same structured health, status, receipt and forensic truth

**Invariant:** UI displays confirmation only from validated receipt; process/PID/log data is diagnostic; degraded/unavailable/failed/denied/pending/enforced/rolled-back are distinct; mutating buttons show request and postcondition

**Files/symbols:** `mouth/windows_sec_monitor.rs`; `aegis_dashboard/src/main.rs`; `tools/aegisctl.py`; `tools/aegisctl/client.py`; `scripts/aegis_console*.py`; `scripts/aegis_status.py`; health/control schema decoders

**Tests ก่อนแก้:** forged log/event tests; stale receipt; policy intent without provider effect; PEP-ready/provider-not-ready; daemon unavailable; PID reuse; blocked counter from string-only input

**Tests หลังแก้:** receipt identity/version/filter/postcondition required for blocked count/DEFCON; health fallback explicitly `runtime_available=false`; all statuses render consistently; operator control requires versioned request, auth, audit and postcondition; no global process kill in normal path

**Windows-only proof:** run UI/CLI against actual daemon in degraded, denied, unavailable, failed, enforced, rolled-back and stale-runtime states; compare UI fields with health/receipt/forensic artifacts on disk

**Rollback:** revert UI to conservative `UNVERIFIED/DEGRADED` labels and disable mutation buttons; never restore log-derived blocked counters

**Exit gate:** Mouth, dashboard, CLI and reports agree exactly; no UI claims confirmed block without receipt; legacy supervisor/status paths are removed or explicitly diagnostic-only

### Slice V10 — Build, package, signing, clean-room และ release acceptance

**วัตถุประสงค์:** turn the verified source graph into one reproducible Windows package with provenance and rollback

**Invariant:** package file list, hashes, signatures, INF/catalog, service/device names, DLL dependencies, SBOM and install layout derive from one manifest and exact source HEAD; installer never ships an unverified driver or stale config

**Files/symbols:** root `build.zig`; root/bridge `CMakeLists.txt`; `Cargo.toml`; `rust-src/`; `nose/`; `ts_policy/`; `installer/`, `installer.nsi`; `release/`; `release_engineering.py`; `installer.py`; `package_release.ps1`; `release_package.ps1`; `upgrade_rollback.py`; `scripts/wfp_service.ps1`; SBOM/signing/provenance generators; CI workflows

**Tests ก่อนแก้:** clean checkout build matrix; detect unsupported installer arguments; compare package versions/layouts; verify signing/manifest claims; enumerate binaries omitted by source-only SBOM; clean install/uninstall/upgrade/rollback gaps

**Tests หลังแก้:** `zig build`, `zig build test`; root Rust build/test; Shield separately labelled; CMake/MSVC/WDK driver build; Go tests/build; TypeScript typecheck/tests; Python tests; ABI harness; deterministic SBOM; real Authenticode/catalog/signature verification; package hash and source/binary provenance; interrupted upgrade, rollback, uninstall/reinstall and residual state checks

**Windows-only proof:** clean Windows VM install with elevation, service/device start, exact health/preflight, isolated lab proof, clean uninstall, upgrade, interrupted-upgrade, rollback and reinstall; verify no residual service/device/provider/filter/firewall/ACL state; standard user cannot mutate

**Rollback:** signed prior package with tested downgrade path; retain filter/service ownership ledger; if package or rollback proof fails, do not publish and leave host in detection-only state

**Exit gate:** E6/E7 independent release review approves exact package contents, signatures/catalog, SBOM, current-head provenance, install/upgrade/rollback/uninstall and isolated host-effect evidence. Only then may project separately decide whether to enable prevention in production

## 7. Test matrix ที่ต้องส่งมอบตาม slice

| Layer | Required result | หลักฐานขั้นต่ำ |
|---|---|---|
| Contract | size/offset/enum/version/error/receipt vectors pass | generated vector manifest + per-language output |
| Static authority | no direct WFP/second supervisor/unknown-to-pass path | source/build lint report tied to commit |
| Component | Zig, Rust, C/C++, Go, Python/Cython, TypeScript tests | command, exit code, toolchain and artifact digest |
| Runtime | bounded startup, worker heartbeat, cancellation, join, health | health snapshots before/after + shutdown trace |
| Ingress | conservation, payload, identity, duplicate/drop semantics | event ledger and forensic IDs |
| Policy | signature, expiry, rollback, unknown input rejection | signed/invalid fixture results |
| PEP | auth, ABI, freshness, provider/filter, receipt | receipt + provider query + negative matrix |
| Forensics | durable linkage, chain, replay observe-only | verification/replay/export artifacts |
| Windows host | service/device/ACL/driver/provider/WFP | elevated and unauthorized client logs |
| VMware | reachable → blocked → reachable, no stale filter | independent target observations + cleanup |
| Release | clean build/install/upgrade/rollback/uninstall | package manifest, hashes, signatures, VM report |

ทุก test artifact ต้องบันทึก `test_id`, exact commit, source/package digest, OS/architecture, runtime generation, command line, profile, health before/after, event/policy/PEP/provider/receipt IDs, filter identity, forensic identity, cleanup/rollback result และ final gate state หากสิ่งใดไม่ทราบให้เขียน `UNVERIFIED` ไม่เขียนเป็น success

## 8. Current blockers ที่ต้องเปิดไว้ใน tracking system

1. `P0-S1` ไม่มี provider-backed `EnforcementReceipt` และ host postcondition
2. `P0-S2` control pipe SDDL/client impersonation/authorization ไม่ผ่าน proof
3. `P0-S3` WFP device/IOCTL SDDL และ OS-token authorization ไม่ผ่าน proof
4. `P0-S4` active policy unsigned, unknown-to-pass, expiry/operator/rollback semantics ไม่ปลอดภัย
5. `P0-S5` direct WFP and duplicate mutation surfaces ยังอยู่ใน graph
6. `P0-S6` replay/export success-shaped และ replay mutation semantics ยังไม่ปิด
7. `P1-C1` event framing/struct-size contradiction
8. `P1-C2` event_queue/event_fabric disconnected authority
9. `P1-C3` policy action/status/digest divergence
10. `P1-C4` payload loss and cross-restart identity/idempotency gap
11. `P1-C5/P1-C6` synchronous I/O, queue correctness, metrics, heartbeat และ shutdown postcondition
12. `P1-C7` driver source/build/service/device/IOCTL/provider graph ไม่ converge
13. `P1-C8` forensic durability/linkage/verification gap
14. `P2-H*` bounds, ABI harness, trusted loading, replay, payload, audit and lifecycle hardening
15. `P3-R1/P3-R2` UI/log truth and second-supervisor scripts
16. `P3-R3/P3-R4` package, signing, SBOM, installer, driver and rollback graph
17. `P3-R5` current-head truth/provenance artifacts stale or contradictory
18. Windows x64 clean build/test matrix ยังไม่ถูก execute ใน review environment
19. Elevated standard-user/low-integrity/VMware VMnet1 WFP proof ยังไม่ถูก execute
20. Working tree มี modifications ที่ยังไม่ถูกแยกเป็น reviewed commit และ current-head attestation

## 9. Stale artifacts และ regeneration plan

`tools/truth.py verify` ถูก review รายงานว่า invalid สำหรับ `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `build_manifest.json` และ `AI_CONTEXT.md`; มีเพียง `runtime_manifest.json` ที่ report ระบุว่า match HEAD ในขณะ review อย่างไรก็ตาม working tree ปัจจุบันแสดง modifications ใน `inventory.json`, `reference_map.json` และ `runtime_manifest.json` ด้วย จึงต้องตรวจใหม่หลัง clean checkout ไม่ใช้คำว่า current truth จากผลเก่า

`build_truth.json` ยังขัดแย้งภายในตัวเอง: top-level `head_sha` เป็น `688ab566...` แต่ note ระบุ synchronization กับ `48eb2a7...` และไม่มีค่าใดตรงกับ review HEAD `46b93dc...` รายงาน release ยังพบ bundle version `6.0.0`, package metadata/version `5.0.0`, source commit เก่า `0a7418b` และ binary payload ที่ ignored/untracked

Regeneration ต้องเป็น transaction เดียว: clean checkout → record HEAD/dirty state → run canonical generators → reconcile every referenced path against `git ls-files` and build graph → verify SHA/commit/version/toolchain/dependency digests → static authority check → commit generated artifacts หรือ mark them as ephemeral → rerun `tools/truth.py verify` → archive report. ห้ามแก้ SHA หรือ manifest ด้วยมือ และห้ามใช้ generated artifact ที่ไม่ผ่าน verify เป็น authority

## 10. Recommended patch order แบบสั้น

1. **Containment now:** keep prevention closed, remove/quarantine direct mutation, turn all unavailable/failure/placeholder claims into explicit non-enforcing status, and freeze current-head provenance
2. **Freeze contracts:** canonical event/frame/size, ingress identity, Policy IR/action/error map, PEP ABI และ EnforcementReceipt
3. **Prove observe-only path:** one ingress/queue, one event identity, payload preservation, bounded runtime and finalized detection evidence
4. **Secure policy and control:** mandatory signed policy, strict parser/reload/rollback, control SDDL/token binding, nonce/deadline/replay and truthful health
5. **Make evidence real:** durable linked forensic records and observe-only deterministic replay
6. **Implement provider-backed PEP:** one driver/native graph, provider/filter/postcondition, receipt and cleanup ownership
7. **Run Windows/VMware gates:** elevated/negative auth, service/device/driver, isolated block/unblock/cleanup/recovery
8. **Converge UI and release:** receipt-driven operator surfaces, one package graph, signatures/SBOM/provenance, clean-room install/upgrade/rollback/uninstall and independent release verification

## 11. Final acceptance statement

จนกว่าจะผ่าน V0–V10 ตาม exit gates นี้ คำที่ยอมรับได้คือ **source implementation**, **observe-only**, **degraded**, **PEP decision**, **enforcement requested**, **enforcement unavailable**, **enforcement failed** หรือ **UNVERIFIED** ตาม evidence ที่มีเท่านั้น คำว่า **BLOCKED_CONFIRMED**, **host enforcement**, **production-ready prevention**, **clean install**, **rollback passed**, **driver ready**, **WFP ready** และ **release accepted** ต้องสงวนไว้สำหรับหลักฐาน Windows/VMware และ clean-room ที่ตรงกับ current release เท่านั้น

การทำให้ demo แสดง `BLOCK`, การมี DLL/SYS, การมี filter API, self-hashing release manifest, UI counter, historical evidence หรือ unit/static test ไม่สามารถชดเชย receipt, host-effect observation, cleanup, identity authorization, lifecycle และ package proof ที่ยังขาดได้

## References

[1]: file:///home/ubuntu/upload/AEGISComprehensiveDevelopmentAnalysisandProductionHandoff.md "AEGIS Comprehensive Development Analysis and Production Handoff"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/README.md "AEGIS NIDS Windows README and current safety status"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/01-build-inventory.md "AEGIS current-head build and inventory review"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/02-contracts-abi.md "AEGIS contracts and ABI review"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/03-runtime-lifecycle.md "AEGIS runtime and lifecycle review"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/04-data-plane-detection.md "AEGIS data-plane and detection review"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/05-brain-policy.md "AEGIS policy and brain review"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/06-pep-wfp-native.md "AEGIS PEP, WFP and native review"
[9]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/07-forensics-security.md "AEGIS forensics and security review"
[10]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/current-head/08-operator-release.md "AEGIS operator and release review"

<!-- end of report -->
