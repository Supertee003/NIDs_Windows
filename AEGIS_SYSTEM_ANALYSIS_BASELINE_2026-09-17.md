# AEGIS NIDS Windows — System Analysis Baseline

**วันที่ตรวจ:** 17 กันยายน 2026  
**วัตถุประสงค์:** วิเคราะห์โครงสร้าง การไหลของข้อมูล อำนาจการควบคุม สัญญาข้ามภาษา และความเสี่ยงของ repository ก่อนเริ่มการพัฒนารอบถัดไป  
**ขอบเขต:** source tree, repository instructions, machine-readable maps, runtime/control paths, acquisition, policy, Rust PEP, forensics, tests และ skills ที่ติดตั้งใน `.agents/skills/`

## บทสรุปผู้บริหาร

AEGIS เป็นระบบ Windows-native Network Intrusion Detection and Response ที่แบ่งงานตามภาษาและ plane โดยมี **Zig เป็น runtime hub**, **Go Nose เป็น packet-acquisition adapter**, **C/C++ เป็น Windows-native adapters**, **Rust PEP เป็น security enforcement authority**, **Python เป็น analytics**, และ **TypeScript เป็น policy authoring** สถาปัตยกรรมนี้มีแนวคิดที่ถูกต้องในระดับการแบ่งอำนาจ แต่ repository ยังไม่อยู่ในสภาวะที่สามารถใช้เอกสาร truth เป็น authority ได้ทันที

จุดที่ยืนยันได้จาก repository ปัจจุบันคือ branch `main` ชี้ไปที่ `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` ขณะที่ `AGENTS.md` อ้าง `48eb2a72265a15c1b780a6bfa76d4f4dae2fc7f2` และ `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json` อ้าง `688ab566d477105df5f868cee1571fbec77eedfd` ดังนั้น machine maps ทั้งหมดต้องถือว่า **stale จนกว่าจะ regenerate และ verify** ตามกฎของ repository เอง

รายงานแนบเสนอให้เริ่มจาก truth synchronization ซึ่งสอดคล้องกับผลตรวจจริง อย่างไรก็ตาม รายงานแนบมีข้อสังเกตบางส่วนที่เป็น historical snapshot เช่น การระบุว่า root tree ไม่แสดง `shield/`; ใน repository ที่ตรวจปัจจุบันมี `shield/` อยู่จริง และ machine maps ปัจจุบันก็จัด `shield/` เป็น support payload-screening crate ดังนั้นข้อสรุปที่เชื่อถือได้ต้องยึด current source และ runtime call graph มากกว่ารายงานเก่า

**ข้อสรุปเชิงปฏิบัติ:** ยังไม่ควรเพิ่ม UI, federation, XDR, Brain หรือ detector feature ใหม่ ควรทำตามลำดับนี้ก่อน: (1) synchronize truth, (2) ทำ runtime/control authority ให้เป็นหนึ่งเดียว, (3) freeze contract และ ABI ด้วย golden vectors, (4) พิสูจน์ synthetic event end-to-end, (5) พิสูจน์ Windows WFP host effect และ rollback, แล้วจึง productize UI และ intelligence

## 1. Repository และกติกาการทำงาน

Repository มี source และ artifact ในหลายภาษา โดยจำนวนไฟล์เชิงโครงสร้างที่ตรวจได้คร่าว ๆ คือ `src` 267 ไฟล์, `tools` 73, `bridge` 178, `brain` 33, `go` 9, `nose` 16, `mouth` 6, `rust-src` 6, `shield` 4, `shared` 21, `tests` 116 และ `scripts` 68 ไฟล์ ตัวเลขนี้ใช้เพื่อบอก scale เท่านั้น ไม่ใช่หลักฐานว่าไฟล์ทั้งหมดอยู่ใน production path

`.agents/skills/` มี skills จำนวนมาก เช่น `codebase-design`, `diagnosing-bugs`, `code-review`, `implement`, `tdd`, `to-spec`, `to-tickets`, `improve-codebase-architecture` และ skills สำหรับ handoff/research/review การพัฒนาต่อควรเลือก skill ตาม phase แทนการใช้ทุก skill พร้อมกัน เพราะ repository กำหนดให้หน่วยคิดคือ **system flow**, หน่วยแก้คือ **vertical slice**, และหน่วยพิสูจน์คือ **evidence**

`AGENTS.md` กำหนด source-of-truth hierarchy ดังนี้: runtime behavior, current source, build configuration, current-head manifests, AGENTS/ADR, evidence, reports และ README ตามลำดับ นอกจากนี้ยังกำหนด stop-the-line triggers ได้แก่ ABI mismatch, memory corruption, race/deadlock, silent event loss, policy/PEP bypass, unauthorized enforcement, privileged IPC exposure, duplicate runtime/authority, production mock, build/runtime mismatch และ stale evidence กฎเหล่านี้มีผลโดยตรงต่อแผนพัฒนารอบต่อไป

## 2. ภาพรวมสถาปัตยกรรมที่ตั้งใจ

ระบบแบ่งเป็นห้า plane:

| Plane | เจ้าของหลัก | หน้าที่ | สิ่งที่ห้ามเป็นเจ้าของ |
|---|---|---|---|
| Acquisition | Go และ C/C++ | packet capture, ETW, FIM, Registry และ native adapter | policy, detection authority, enforcement |
| Runtime | Zig | event fabric, flow, detection orchestration, correlation, action dispatch, control, forensics | privileged enforcement และ cryptographic trust |
| Intelligence | Python/Cython | analytics, threat context, RAG และ measured hot loops | runtime orchestration, privileged OS calls, enforcement |
| Security | Rust PEP | signature/trust, authorization และ WFP enforcement | detection และ event fabric |
| Control | Python CLI, TypeScript policy authoring | operator commands, policy authoring, simulation และ presentation | authoritative runtime state และ enforcement |

หลักการสำคัญคือ **Zig เป็น hub ไม่ใช่ทุกภาษาเชื่อมต่อกันเป็น mesh** การเชื่อมต่อควรผ่าน C ABI, PEP ABI, Control Protocol หรือ Analytics Contract ที่มี version และ layout ที่ตรึงไว้แล้ว

## 3. Production call graph ที่ตรวจพบ

เส้นทาง entrypoint ปัจจุบันคือ Windows service/console entrypoint → `src/main.zig` → `platform/win32_service.mainEntry` → `daemon.runDaemon()` ใน `src/daemon.zig` โดย daemon ทำงานตามลำดับใหญ่ดังนี้:

1. ติดตั้ง diagnostics และตรวจ security self-check
2. สร้าง runtime state, arena, forensic ring, watchdog, performance tracker และ fault injector
3. โหลด rules จาก `configs/Rules.json`
4. โหลด policy จาก `configs/policies.json`
5. initialize PEP และ ActionDispatcher
6. initialize bridge, native adapters, Shield screening path และ legacy sensor-related code
7. สร้าง worker handles ผ่าน `RuntimeSupervisor`
8. เปิด control pipe
9. รอ shutdown และ join worker ใน reverse startup order

`RuntimeSupervisor` เป็นการปรับปรุงที่สำคัญ เพราะถือ handles ของ pipeline, sensor, Nose reader, ETW, FIM และ Registry รวมถึงเป็นเจ้าของ stop signal และ join อย่างเป็นลำดับ การมีโครงสร้างนี้สนับสนุนเป้าหมาย “one runtime owner” แต่ต้องตรวจ runtime behavior บน Windows อีกครั้ง ไม่ควรสรุปจากการมี struct ใน source เพียงอย่างเดียว

## 4. Data plane: acquisition ถึง forensics

เส้นทางเป้าหมายคือ:

```text
Npcap / Windows telemetry
  -> Go Nose หรือ native adapter
  -> Canonical Event
  -> Zig reader / event queue
  -> flow table
  -> detection
  -> correlation / threat tracking
  -> Policy IR
  -> Rust PEP authorization
  -> WFP effect หรือ explicit unavailable/failed
  -> audit
  -> forensic record / replay
```

รายงาน deep audit ใน repository ยืนยันว่าก่อนหน้านี้มี acquisition concepts ซ้อนกัน ได้แก่ direct Zig Npcap, legacy sensor pipe และ Go Nose canonical pipe รวมถึง ETW/FIM/Registry paths จุดนี้สำคัญมาก เพราะ process ที่ทำงานหรือ Npcap handle ที่เปิดได้ไม่ได้พิสูจน์ว่า event เดียวเดินทางครบ pipeline

รายงานดังกล่าวยังระบุหลักฐานที่ดีขึ้นแล้วว่า Go Nose → `aegis_nose` named pipe → Zig deserializer → `event_queue` สามารถส่ง synthetic/live event ได้ และมีการปิด direct Zig Npcap ใน production เพื่อให้ Go Nose เป็น canonical network ingress อย่างไรก็ตาม ต้องยืนยันจาก current source และ Windows host run ว่าไม่มี duplicate path กลับมาอีก และต้องใช้ event ID เดียวกันตรวจตั้งแต่ ingress ถึง forensic append

Health ต้องแยกอย่างน้อยสี่ชั้น: process liveness, adapter readiness, frame reception และ event processing โดย counter ที่ต้องรักษาไว้ ได้แก่ `nose_process_connected`, `nose_frames_received`, `nose_frames_rejected`, `nose_frames_submitted`, `pipeline_events_processed`, `capture_packets`, `capture_errors`, `last_event_ms`, duplicate event IDs และ non-monotonic event IDs การรายงานเพียง `RUNNING` ของ worker ไม่เพียงพอ

## 5. Canonical contracts และ ABI

`CONTRACT_MAP.json` ประกาศ contract หลักห้าชุด:

| Contract | รูปแบบ | เจ้าของ/ผู้ใช้ | ความเสี่ยงที่ต้องพิสูจน์ |
|---|---|---|---|
| Canonical Event | 109-byte fixed-width extern struct | Go, C, Rust, Python, Zig | enum ordinal, offsets, endianness, event identity |
| PEP ABI | C ABI + `repr(C)` structs | Zig ↔ Rust | size/alignment, null handling, decision semantics |
| Runtime ABI | lifecycle and worker stages | Zig runtime | state transitions, readiness, stop/join |
| Control Protocol | JSON over `\\.\pipe\aegis_control` | CLI/TS ↔ Zig | auth, freshness, nonce/replay, postcondition |
| Policy IR | versioned AST | TypeScript → Zig/Rust | semantic parity, signing, evaluation |

จุดเสี่ยงหลักไม่ใช่เพียง field size แต่เป็น **semantic parity** รายงาน deep audit ระบุว่า Go และ Zig เคยมี event type/policy action ordinal ไม่ตรงกัน แม้ frame จะผ่าน magic/version/size validation ได้ ดังนั้น golden vectors ต้องตรวจค่าทุก field ไม่ใช่เพียง round-trip length

PEP structs ใน Rust ใช้ `#[repr(C)]` และมี `PepContext`, `PepRequest`, `PepResponse` แต่ควรเพิ่มหรือยืนยัน layout tests ที่เปรียบเทียบกับ Zig โดยตรง ได้แก่ `sizeOf`, alignment, offset ทุก field, enum values และ reserved/version fields การคอมไพล์สำเร็จไม่ใช่หลักฐาน ABI conformance

## 6. Security and enforcement authority

`rust-src/lib.rs` เป็น final enforcement authority ตาม map และ implementation มีแนวคิด fail-closed ที่สำคัญ: เมื่อ capability ไม่พอ หรือ WFP adapter unavailable/failed จะเปลี่ยนผลเป็น escalation แทนการรายงาน enforcement สำเร็จ การทดสอบที่จำเป็นต้องแยกเป็นสอง postconditions:

1. **Decision proof:** Rust PEP อนุญาต ปฏิเสธ หรือ escalate ตาม capability, policy action, severity และ approval rule ได้ถูกต้อง
2. **Enforcement proof:** WFP adapter ถูกโหลดจริง, filter ถูกสร้างจริง, traffic effect สังเกตได้, และ unblock/rollback ทำให้ traffic กลับคืนได้

`ActionDispatcher` ระบุชัดว่าไม่แตะ WFP โดยตรง ซึ่งถูกต้องตาม authority model แต่ dispatcher ยังเป็นเพียง routing/audit layer ที่รับ PEP decision แล้ว หากการเรียก PEP เกิดที่อื่นหรือ action result ไม่ถูกเชื่อมกลับเข้า forensic trace จะยังไม่ถือว่า golden path สมบูรณ์

`shield/` มีอยู่จริงใน current tree และถูกจัดเป็น support Tier-3 payload screening ไม่ใช่ final enforcement authority แต่ machine map ระบุว่ามีไฟล์ที่เคยเป็น duplicate PEP/WFP path และถูก quarantine ไว้ การตรวจ exit gate ต้องเป็น negative test: shield ต้องไม่ export หรือถูก bind ให้เป็น PEP/WFP authority อีกครั้ง

## 7. Control plane และ lifecycle

Control flow ที่ประกาศคือ operator → Python/TypeScript client → named pipe → Zig authorization → handler → real mutation → postcondition → audit → structured result ซึ่งเป็นแบบที่ถูกต้อง

แต่ `tools/aegisctl/api/control_api.py` ยังมีความเสี่ยงเชิง authority เพราะ:

- `SUBSYSTEMS` ยังมี `rust_shield`
- หาก daemon query ไม่ได้ `get_all_status()` fallback ไปอ่าน PID/process
- health adapter สังเคราะห์ Tier-3 เป็น `READY/STOPPED` จาก process/file presence และมีการตรวจ `sec_monitor.dll`
- control API จึงอาจรายงานสถานะที่ไม่ใช่ state machine ของ daemon

`tools/aegisctl/commands/lifecycle.py` ยัง start executable ด้วย `subprocess.Popen`, stop ด้วย `psutil` หรือ `taskkill`, และ watchdog ตรวจ PID แล้ว restart เอง นี่เป็น second operational authority นอก Zig daemon แม้ `stop` จะพยายามส่ง `daemon.shutdown` ก่อนก็ตาม ควรแยก `--force` เป็น emergency recovery ที่ audit ได้ และไม่ให้ normal `start/stop/restart/watchdog` mutate process โดยตรงหลัง runtime supervisor เป็น authority ที่พร้อมใช้งาน

## 8. Command truthfulness และ false success

`handler_registry.zig` มีโครงสร้างที่ดีขึ้น ได้แก่ structured error envelope, handler failure fields, audit record และ `NOT_IMPLEMENTED` เมื่อไม่มี handler แต่ต้องตรวจ implementation ของ handlers ทุกตัวว่าผลลัพธ์มี postcondition จริง ไม่ใช่เพียงการ serialize JSON สำเร็จ

คำสั่งที่ต้องมีหลักฐานจริงก่อนคืน success ได้แก่ `policy.verify`, `policy.simulate`, `forensics.show`, `forensics.export`, `forensics.replay`, `enforcement.verify`, `runtime.start`, `runtime.stop` และ `runtime.restart` สำหรับ export ต้องตรวจไฟล์/hash/record count สำหรับ replay ต้องเป็น observe-only และใช้ historical build identity, policy, context และ event สำหรับ enforcement ต้องรายงานแยก `ALLOW`, `DENY`, `ENFORCEMENT_UNAVAILABLE`, `ENFORCEMENT_FAILED`, `AUTHORIZATION_DENIED`, `POSTCONDITION_FAILED` และ `NOT_IMPLEMENTED`

## 9. Priority findings

### P0 — Truth graph ไม่ตรง current HEAD

นี่เป็น blocker ที่ยืนยันได้ทันทีจาก `.git/refs/heads/main`, `AGENTS.md` และ machine maps ทุกการอ่าน map ก่อน regenerate มีโอกาสนำไปสู่การแก้ผิด tree หรืออ้าง evidence ผิด commit

**Exit gate:** ทุก map มี current `head_sha`, ทุก path มีอยู่จริง, ไม่มี stale shield/build references และ `python tools/truth.py verify` ให้ `TRUTH_VALID`

### P0 — Runtime health อาจยังผสม daemon truth กับ Python synthesis

Zig มี state machine และ worker readiness แต่ Python control API ยังมี fallback PID/process probing และ Tier-3 synthesis เมื่อ daemon query ล้มเหลว

**Exit gate:** system status/health จาก daemon เป็น authority เดียว; fallback มีสถานะ diagnostic ที่แยกชัดและไม่ถูกใช้เป็น operational truth

### P0 — Lifecycle มี second control authority

CLI ยัง launch/terminate/watchdog process โดยตรง

**Exit gate:** normal lifecycle command ส่ง versioned command envelope ไป daemon, ตรวจ postcondition จาก state machine และ audit ทุก mutation; `--force` เท่านั้นที่เป็น emergency path

### P0 — ห้าม positive result ที่ไม่มี proof

Command handlers และ adapters ต้องไม่ตอบ success เพียงเพราะสร้าง payload ได้

**Exit gate:** negative tests ตรวจว่า dependency หาย, WFP unavailable, invalid signature, corrupt evidence และ missing record ให้ผล explicit failure/unavailable

### P1 — Canonical ingress และ event semantics ต้องพิสูจน์ครบ

ต้องยืนยัน Go Nose เป็น network ingress เดียวใน production และ enum/value/offset ตรงกันทุกภาษา

**Exit gate:** synthetic event หนึ่งตัวมี event ID เดียวผ่าน named pipe, queue, detection, policy, PEP, audit และ forensic record โดย duplicate/non-monotonic counters เป็นศูนย์

### P1 — PEP decision ยังไม่เท่ากับ WFP host proof

Static test และ source contract ยังไม่แทนการติดตั้ง DLL/driver และสังเกต traffic effect บน Windows host

**Exit gate:** E5 evidence มี request ID, PEP decision, filter ID/result, traffic observation, audit linkage และ rollback observation

### P1 — Config path และ runtime working directory

`daemon.zig` โหลด `configs/Rules.json` และ `configs/policies.json` จาก current working directory ขณะที่ roadmap ระบุ working-directory เป็นสาเหตุที่ต้องตรวจบน Windows service/console

**Exit gate:** resolved executable/config directory ถูกกำหนดตาม deployment profile และ startup diagnostics แสดง path ที่ใช้จริงโดยไม่เปิดเผย secret

## 10. แผนพัฒนาที่แนะนำ

### Slice 0: Truth synchronization

หยุดการเปลี่ยน behavior ก่อน regenerate maps จาก current HEAD ตรวจทุก `file`, `artifact`, `source_root`, build command และ evidence reference แล้วลบ stale references หรือระบุ quarantine อย่างเป็นทางการ

### Slice 1: Runtime health convergence

กำหนด state machine เป็น authority เดียวและแยก lifecycle state จาก data-plane state เพิ่ม dependency, queue pressure, last-event, counters, PEP/WFP state, audit persistence และ worker failure reasons ลง schema ที่ versioned

### Slice 2: Control/lifecycle convergence

ให้ CLI/TUI/Web เป็น thin client ผ่าน control protocol เท่านั้น ย้าย start/stop/restart/watchdog ownership ไป daemon และเก็บ `--force` เป็น emergency operation ที่ audit ได้

### Slice 3: Contract freeze

สร้าง fixtures/golden vectors สำหรับ event, PEP, health, policy และ forensic record แล้วทำ cross-language round-trip และ ABI layout tests ใน CI

### Slice 4: Golden synthetic event

เริ่มจาก synthetic Go Canonical Event ไม่พึ่ง Npcap ก่อน พิสูจน์ frame → reader → queue → detection metadata → policy → PEP → action result → audit → forensic append → verify/replay

### Slice 5: Windows host enforcement

ติดตั้งและโหลด DLL/driver จริง ทดสอบ block/unblock หรือ quarantine ตาม scope ที่ปลอดภัย ตรวจ traffic effect และ rollback ด้วย evidence ระดับ E5

### Slice 6: Reliability and evidence

ทำ fault injection สำหรับ queue saturation, worker init failure, PEP unavailable, WFP unavailable, disk failure, corrupt policy/evidence, cancellation และ restart budget แล้วบังคับ fail-closed/degraded state ที่สังเกตได้

### Slice 7: Intelligence และ UI

หลัง golden path ผ่านเท่านั้น จึงเชื่อม Brain ผ่าน Analytics Contract และทำ UI เป็น projection ของ backend truth โดยไม่ให้มี state หรือ authority ซ้ำ

## 11. Definition of done สำหรับ vertical slice ถัดไป

ทุก patch ต้องประกาศ PATCH-ID, FLOW-ID, target HEAD, target files/symbols, scope, contract/ABI/authority/state/test/evidence impact และหลัง patch ต้องรายงาน final HEAD, changed files, old/new flow, invariant, build/test/Windows result, evidence level, rollback, remaining risk และ open blockers

Slice จะถือว่าเสร็จก็ต่อเมื่อ implementation ถูกเรียกใช้ใน production path, มี owner ชัด, contract สอดคล้อง, ทดสอบที่ seam จริง, มี evidence ที่ผูกกับ commit และ artifact digest, fail-safe เมื่อ dependency ไม่พร้อม, audit ได้ และ rollback ได้

## 12. ข้อจำกัดของการตรวจครั้งนี้

การตรวจครั้งนี้เป็น source-level baseline และ static architecture review ยังไม่ได้อ้างว่า Windows host runtime, WFP driver effect, clean install หรือ release signing ผ่านแล้ว การอ่านบางไฟล์ถูกจำกัดด้วยขนาด output ของเครื่องมือ จึงใช้ machine maps และ targeted source inspection เป็นแกน และไม่ควรถือ baseline นี้แทน `TRUTH_VALID` หรือ E5/E7 evidence

## References

[1]: AGENTS.md "Repository agent instructions and source-of-truth hierarchy"
[2]: README.md "AEGIS NIDS Windows current implementation and target architecture"
[3]: AEGIS_Deep_Development_Report_Current_HEAD.md "Deep development report supplied for the current project"
[4]: AEGIS_Development_Roadmap_To_Final.md "Roadmap from current state to final system"
[5]: SYSTEM_MAP.json "Machine-readable system component map"
[6]: FLOW_MAP.json "Machine-readable runtime and control flow map"
[7]: AUTHORITY_MAP.json "Machine-readable authority and security ownership map"
[8]: CONTRACT_MAP.json "Machine-readable cross-language contract map"
[9]: docs/DEEP_AUDIT_RUNTIME_CONVERGENCE_2026-09-15.md "Deep audit of runtime convergence and canonical ingress"
[10]: tools/aegisctl/api/control_api.py "Python control API and health adapter"
[11]: tools/aegisctl/commands/lifecycle.py "CLI lifecycle and watchdog implementation"
[12]: src/policy/action_dispatcher.zig "Zig action dispatcher and PEP enforcement boundary"
[13]: src/control/handler_registry.zig "Zig control command registry and handlers"
[14]: src/daemon.zig "Zig daemon entrypoint and runtime supervisor"
[15]: rust-src/lib.rs "Rust PEP ABI, authorization and WFP adapter"
[16]: .agents/skills/codebase-design/SKILL.md "Deep-module and seam design guidance"
[17]: .agents/skills/diagnosing-bugs/SKILL.md "Feedback-loop and evidence-driven diagnosis guidance"
[18]: .agents/skills/code-review/SKILL.md "Two-axis standards and specification review guidance"
