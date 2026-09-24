# AEGIS NIDS Windows — แผนพัฒนาจาก Baseline ถึง Production Acceptance

**ฉบับ:** 1.0  
**วันที่:** 17 กันยายน 2026  
**Target architecture:** Zig runtime hub, Go/C acquisition, Rust PEP security authority, Python/Cython intelligence, TypeScript policy authoring  
**เป้าหมาย:** ทำให้ AEGIS เป็น Windows security appliance ที่ติดตั้งได้จริง ใช้ runtime owner เดียว มี enforcement authority เดียว มี contract เดียว มี health ที่เชื่อถือได้ และมีหลักฐานตรวจสอบซ้ำได้

## บทสรุปการตัดสินใจ

AEGIS ไม่ควรพัฒนาต่อด้วยการเพิ่ม detector, UI หรือ federation ก่อนแก้ runtime/control blockers เพราะระบบมีความเสี่ยงจาก authority ซ้ำและจากหลักฐานที่ยังแยกระหว่าง source-level กับ Windows host-level ไม่ชัดเจน แผนนี้จึงใช้ลำดับแบบ **convergence ก่อน expansion** โดยเริ่มจาก truth, runtime lifecycle, control authority และ contracts แล้วค่อยพิสูจน์ data plane, enforcement, portability, forensics, operator workflow และ release

จุดที่ต้องแก้ก่อนเป็นอันดับแรกคือ core live lifecycle, control/lifecycle authority, stale truth artifacts, canonical event/PEP/health contracts และ false-success behavior เมื่อ PEP หรือ WFP ไม่พร้อม จากนั้นจึงทำ golden path เดียวตั้งแต่ input ไปถึง forensic evidence และ rollback

> **Production-complete** หมายถึงระบบติดตั้งบน Windows เครื่องใหม่ เลือก LAN หรือ Wi-Fi ผ่าน profile ได้ เริ่ม runtime ได้ เห็น health ที่เป็นจริง ตรวจจับ event ได้ ตัดสิน policy ผ่าน Rust PEP ได้ enforce ผ่าน WFP หรือรายงาน unavailable อย่างชัดเจน ส่งออก evidence ได้ และ update/rollback ได้โดยไม่แก้ source code

## 1. เป้าหมายสุดท้ายและ invariants

### 1.1 Runtime authority เดียว

`src/main.zig` และ `daemon.runDaemon()` ต้องเป็น production entrypoint เดียว `RuntimeSupervisor` ต้องเป็นเจ้าของ worker handles, stop signal, join order, restart semantics และ readiness state การ start/stop/restart ปกติจาก CLI, watchdog หรือ UI ต้องผ่าน control protocol ไม่สร้างหรือฆ่า process โดยตรง

### 1.2 Enforcement authority เดียว

Rust PEP เป็นผู้อนุญาตหรือปฏิเสธ privileged action และ WFP adapter ที่ PEP ควบคุมเป็นผู้ทำ host effect ไม่มี C++, Python, TypeScript, CLI หรือ `shield` path ใดเรียก firewall mutation โดยตรง เมื่อ PEP/WFP ไม่พร้อม ระบบต้องคืน `UNAVAILABLE`, `FAILED` หรือ `ESCALATE` ไม่ใช่ `SUCCESS` หรือ `BLOCKED` ปลอม

### 1.3 Contract เดียว

Canonical Event, Policy IR, PEP ABI, health response, control IPC, forensic trace และ rules schema ต้องมี version, owner, fixture และ cross-language tests เดียวกัน ทุก implementation ที่ไม่ตรง contract ต้องหยุดที่ boundary พร้อม error ที่ audit ได้

### 1.4 Health ที่เป็นจริง

เฉพาะ Zig daemon ที่ยืนยัน runtime state, worker readiness, counters, PEP readiness และ data-plane progress ได้ เมื่อ daemon ติดต่อไม่ได้ control API แสดง `DEGRADED`, `source=diagnostic`, `runtime_available=false` และห้ามใช้ PID/process fallback เป็น operational truth

### 1.5 Evidence ที่ตรวจซ้ำได้

ทุก run ที่สำคัญต้องผูก test ID, commit, artifact digest, environment, command, health ก่อน/หลัง, event ID, policy ID/version, request ID, PEP decision, enforcement result, forensic ID และ rollback result เข้าด้วยกัน

## 2. สถานะเริ่มต้นที่ยืนยันแล้ว

| พื้นที่ | สถานะปัจจุบัน | ความหมาย |
|---|---|---|
| Architecture analysis | มี baseline แล้ว | ใช้เป็น context แต่ต้อง rebaseline หลังทุก patch |
| Inventory/reference map | regenerate แล้ว | สร้างจาก 724 ไฟล์ปัจจุบัน |
| Machine maps | stale กับ current HEAD | ห้ามใช้เป็น current authority จน rebuild |
| Health authority patch | แก้แล้ว | daemon unavailable ถูกระบุเป็น diagnostic/degraded |
| Targeted health/aegisctl tests | ผ่าน 37 tests | เป็น E2-level evidence ของ patch นี้ |
| Full runtime suite | 246 tests, 36 failures, 9 skipped | failures อยู่ใน daemon/Windows integration และ Gate E/F; ยังไม่ใช่ production proof |
| Core live lifecycle | blocker | ต้องยืนยัน control pipe และ truthful health บน Windows |
| WFP host enforcement | ยังไม่ยืนยัน | ต้องใช้ Windows host ที่มี driver/PEP จริง |
| Git status บน FUSE mount | ช้า | ไม่ใช่ product defect; ใช้ targeted diff/Windows terminal แทน |

## 3. ลำดับ phase และจุดที่ต้องแก้

## Phase 0 — Truth and change control

**เป้าหมาย:** ทำให้เอกสาร truth ตรงกับ source ก่อนอ้างอิงหรือพัฒนา feature ใหม่

**จุดที่ต้องแก้/สร้าง:** `AI_CONTEXT.md`, `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `runtime_manifest.json`, `build_manifest.json`, `tools/truth.py` และ generator ที่เกี่ยวข้อง

**งานหลัก:** regenerate maps จาก current HEAD; ตรวจทุก path ให้มีอยู่จริง; แยก canonical, support, optional และ legacy; แก้ build manifest provenance; ให้ evidence index ระบุ historical evidence เมื่อ commit ไม่ตรง; เพิ่มคำสั่งหรือ script เดียวสำหรับ rebuild-and-verify

**Exit gate:** `python tools/truth.py verify` ได้ `TRUTH_VALID`; maps parse ได้; ไม่มี stale SHA; ไม่มี map อ้าง path ที่หาย; build manifest verify ได้โดยไม่รายงาน source commit เก่า

**หลักฐาน:** truth verification output, map digest manifest, current HEAD record

## Phase 1 — Core live lifecycle

**เป้าหมาย:** core ต้องเริ่มได้และเปิด health/control pipe เสมอ แม้ dependency จะ degraded

**จุดที่ต้องตรวจ/แก้:** `src/main.zig`, `src/daemon.zig`, `src/platform/win32_service.zig`, `src/control/*`, `src/runtime/*`, `tests/runtime/test_harness_integration.py`, build output และ deployment working directory

**ลำดับวินิจฉัย:** ตรวจ process exit code; stderr; resolved executable/config/DLL directories; PEP load state; bridge load state; security self-check; pipe creation error; pipe ACL/name; worker initialization และ shutdown order

**การปรับที่ต้องทำ:** สร้าง control pipe ก่อนเริ่ม worker ที่อาจ fail; expose startup phase และ failure mask; ใช้ absolute deployment/profile paths; ส่ง structured health แม้ state เป็น `DEGRADED` หรือ `FAILED`; แยก service dispatcher fallback จาก normal console behavior; เพิ่ม startup diagnostics ที่ไม่เปิดเผย secret

**Exit gate:** core lifecycle integration test ผ่าน; health pipe ตอบภายใน timeout; `RUNNING` เมื่อ dependencies พร้อม และ `DEGRADED` พร้อม reason เมื่อ PEP/WFP ไม่พร้อม; ไม่มี silent exit

**หลักฐาน:** Windows process log, health-before/after, pipe probe output, failure reason, binary digest

## Phase 2 — Control and lifecycle convergence

**เป้าหมาย:** ให้ Zig daemon เป็น operational authority เดียว

**จุดที่ต้องแก้:** `tools/aegisctl/commands/lifecycle.py`, `tools/aegisctl/api/control_api.py`, `tools/aegisctl/client.py`, `src/control/handler_registry.zig`, control protocol schema และ watchdog implementation

**การปรับที่ต้องทำ:** ให้ `start`, `stop`, `restart`, `watchdog` ส่ง versioned command envelope ไป daemon; ให้ daemon คืน postcondition และ audit record; ย้าย process launch/terminate ปกติออกจาก CLI; เก็บ `--force` เป็น emergency recovery เท่านั้น; ลบหรือแยก `rust_shield` จาก canonical operational subsystem registry; ใช้ PID/process scan เฉพาะ diagnostic command

**Exit gate:** normal lifecycle ไม่มี `Popen`, `taskkill` หรือ process kill path; ทุก mutation มี request ID, authorization, state transition, postcondition และ audit; daemon unavailable คืน `EXIT_RUNTIME_UNAVAILABLE`; force path มี explicit warning และ audit

## Phase 3 — Contract and ABI freeze

**เป้าหมาย:** ปิดความเสี่ยง cross-language semantic mismatch

**จุดที่ต้องแก้/สร้าง:** `shared/event/canonical_event.md`, `shared/schema/canonical_event_v1.h`, `src/contract/canonical_event.zig`, Go Nose canonical serializer, Rust PEP structs, Zig bindings, Policy IR, health schema และ forensic schema

**การปรับที่ต้องทำ:** สร้าง fixtures ใน `contracts/fixtures/event`, `contracts/fixtures/pep`, `contracts/fixtures/health`, `contracts/fixtures/forensic`; ตรวจ field offsets, size, alignment, enum ordinals, endianness, reserved fields, version และ null behavior; ตรวจ Go/Zig/Rust/Python round trip; เพิ่ม negative vectors สำหรับ truncated frame, bad magic, wrong version, duplicate ID และ non-monotonic ID

**Exit gate:** golden vectors ผ่านทุกภาษา; ABI layout tests ผ่านบน x86_64 Windows release build; semantic values ตรงกัน; malformed input ถูก reject โดยไม่ crash หรือ silently drop

## Phase 4 — Canonical acquisition and data plane

**เป้าหมาย:** มี ingress เดียวและพิสูจน์ event เดียวผ่าน pipeline ครบ

**จุดที่ต้องแก้/ตรวจ:** `nose/`, `src/capture/`, named pipe reader, event queue, flow table, detection, correlation, threat tracking และ forensic append

**การปรับที่ต้องทำ:** ให้ Go Nose เป็น canonical network ingress; quarantine direct/legacy duplicate ingress; เพิ่ม counters `frames_read`, `frames_rejected`, `frames_submitted`, `events_processed`, duplicate IDs, non-monotonic IDs และ last event; ใช้ synthetic event ID เดียวตามตั้งแต่ ingress ถึง forensic record; จำกัด queue behavior และประกาศ drop reason

**Exit gate:** synthetic event golden test ผ่านตั้งแต่ Nose → pipe → Zig reader → queue → flow → detection → correlation → policy input → audit → forensic append; duplicate และ non-monotonic counters เป็นศูนย์; backpressure มีผลที่สังเกตได้

## Phase 5 — Rules and policy productization

**เป้าหมาย:** rules/policy ใช้ใน production ได้โดยไม่ bypass validation, signature หรือ audit

**จุดที่ต้องแก้:** `configs/Rules.json`, `configs/policies.json`, schema validator, TypeScript policy compiler, Zig Policy IR, trust store, control handlers และ policy reload path

**การปรับที่ต้องทำ:** ปิด vocabulary ของ severity/action; บังคับ unique rule ID; เพิ่ม scope, revision, author, expiry และ change reason; compile dry-run ให้ Zig และ Tier-2 ให้ผลสอดคล้อง; ใช้ atomic policy swap; ตรวจ signature ก่อน enable; ให้ reload ผ่าน control IPC; rollback ruleset ได้; ทุก CRUD มี audit

**Exit gate:** invalid schema, duplicate ID, bad regex, expired signature และ unsigned production policy ถูกปฏิเสธ; reload ไม่ทำให้ runtime ใช้ policy ครึ่งชุด; policy version/digest อยู่ในทุก decision trace

## Phase 6 — Enforcement and fail-closed behavior

**เป้าหมาย:** ทุก privileged decision มี authorization และ host effect ที่พิสูจน์ได้

**จุดที่ต้องแก้/ตรวจ:** `rust-src/lib.rs`, `src/policy/pep_bindings.zig`, `src/policy/action_dispatcher.zig`, `src/windows/aegis_wfp.c`, bridge boundary, audit และ host tests

**การปรับที่ต้องทำ:** ให้ ActionDispatcher เรียก PEP ผ่าน ABI เดียว; ตรวจ capability, quota, signature, expiry, replay, two-person rule และ request freshness; แยก decision จาก enforcement result; ห้าม positive success เมื่อ WFP unavailable/failed; ผูก filter ID และ host result กับ request ID; รองรับ unblock/quarantine expiry และ rollback

**Decision matrix:**

| PEP | WFP | ผลที่อนุญาต |
|---|---|---|
| ready | ready | execute และบันทึก host effect |
| ready | unavailable | `ENFORCEMENT_UNAVAILABLE` หรือ `ESCALATE` |
| ready | failed | `ENFORCEMENT_FAILED` |
| unavailable | ready | `AUTHORIZATION_UNAVAILABLE`; ห้าม execute |
| denied | any | `AUTHORIZATION_DENIED`; ห้าม execute |

**Exit gate:** static authority checks ผ่าน; simulation negative tests ผ่าน; approved Windows host block/unblock/quarantine ผ่าน; rollback คืน traffic/state ได้

## Phase 7 — Portable deployment and adapter selection

**เป้าหมาย:** รองรับ Windows host ที่มี LAN, Wi-Fi, VPN หรือ virtual adapter โดยไม่แก้ source

**จุดที่ต้องแก้:** `config/deployment_profile.example.json`, adapter inventory/selector, Npcap, ETW, FIM, Registry, WFP setup และ startup health

**การปรับที่ต้องทำ:** รองรับ auto และ explicit selection ด้วย description, MAC หรือ index; exclude loopback/virtual ตาม profile; แสดง provider readiness และ reason; replay mode ต้องทำงานได้โดยไม่มี live NIC; unavailable provider ต้อง degraded อย่างชัดเจนและไม่เปลี่ยน enforcement เป็น allow

**Exit gate:** mock adapter tests ผ่าน; Wi-Fi และ Ethernet สร้าง Canonical Event schema เดียวกัน; replay mode ผ่าน; deployment profile validate ผ่าน

## Phase 8 — WSL2 controlled attack laboratory

**เป้าหมาย:** พิสูจน์ระบบด้วย traffic ที่ควบคุม scope, rate และ cleanup ได้

**ขอบเขต:** ใช้ benign HTTP service และ markers สำหรับ SQL injection, command injection, XSS, path traversal, bounded reconnaissance, harmless file/process events และ canary block ที่มี expiry ห้ามใช้ malware จริง, credential theft, ransomware หรือ uncontrolled flood

**จุดที่ต้องสร้าง:** lab topology, scenario runner, cleanup, rate limit, scenario manifest, expected decision matrix และ evidence bundle

**Exit gate:** ทุก scenario มี matched rule, severity/action, event/request IDs, PEP decision, WFP result หรือ explicit unavailable, forensic export และ rollback result

## Phase 9 — Forensics, replay and evidence

**เป้าหมาย:** evidence เป็น release artifact ที่ตรวจซ้ำได้ ไม่ใช่ log ที่อ่านด้วยมือเท่านั้น

**จุดที่ต้องแก้/สร้าง:** forensic pipeline, replay engine, export commands, evidence index, run bundle tooling และ audit schema

**การปรับที่ต้องทำ:** ใช้ append-only hash chain; รักษา ordered decision trace; บันทึก policy/context/binary provenance; replay ต้องเป็น observe-only และห้าม enforce; export JSON/CSV; แสดง atom ที่แตกต่างเมื่อ replay ต่างจาก historical result

**Evidence bundle:**

```text
evidence/<run-id>/
  environment.json
  command.txt
  test-output.txt
  health-before.json
  health-after.json
  decision-trace.ndjson
  forensic-export.json
  artifact-digests.json
  result.json
```

**Exit gate:** event → decision → policy → PEP → action → host result → audit → forensic chain verify ได้; replay ไม่ mutate host; export digest และ record count ตรวจซ้ำได้

## Phase 10 — Operator product and safe lifecycle

**เป้าหมาย:** operator ใช้งานระบบได้โดยไม่ต้องรู้รายละเอียดทั้งเจ็ดภาษา

**คำสั่งหลัก:** `preflight`, `install`, `profile validate`, `start`, `status`, `health`, `events`, `forensic export`, `rules`, `policy`, `canary`, `stop`, `snapshot`, `rollback`

**จุดที่ต้องแก้:** CLI/TUI/Web projections, error taxonomy, runbooks, installer และ control protocol presentation

**Error ที่ต้องเป็น actionable:** `CORE_NOT_RUNNING`, `PEP_UNAVAILABLE`, `WFP_DRIVER_MISSING`, `ADAPTER_NOT_FOUND`, `RULESET_INVALID`, `CONTROL_PIPE_UNAVAILABLE` แต่ละ error ต้องระบุสาเหตุ ผลกระทบ คำสั่งตรวจสอบ และวิธี recovery โดยไม่สื่อว่า enforcement สำเร็จ

**Exit gate:** operator ทำ workflow ตั้งแต่ install ถึง rollback ได้จาก clean host โดยไม่แก้ source; UI ทุกส่วนอ่าน backend truth เดียวกัน; ไม่มี duplicate state หรือ authority

## Phase 11 — Release, installer and update safety

**เป้าหมาย:** สร้าง release ที่ติดตั้ง ตรวจสอบ อัปเดต และย้อนกลับได้

**จุดที่ต้องแก้/ตรวจ:** `tools/release_engineering.py`, `build_manifest.json`, `build_truth.json`, installer, signing, SBOM, packaging, upgrade/rollback scripts และ CI workflows

**Release gate:** clean checkout build; toolchain pinned; required artifacts ครบ; digests ตรง; authority scan ผ่าน; unit/integration tests ผ่าน; Windows lifecycle ผ่าน; WFP host test ผ่าน; install/uninstall/upgrade/rollback ผ่าน; evidence bundle ครบ

## Phase 12 — Final production acceptance

ระบบจะประกาศเสร็จเมื่อเงื่อนไขทั้งหมดผ่านพร้อมกัน:

1. Truth artifacts ตรง current HEAD
2. Core health pipe ตอบเสมอและ lifecycle ผ่าน
3. Runtime owner มีเพียง Zig daemon/supervisor
4. Enforcement authority มีเพียง Rust PEP/WFP boundary
5. Canonical contracts และ ABI vectors ผ่านทุกภาษา
6. Synthetic event golden path ผ่านตั้งแต่ ingress ถึง forensic
7. LAN/Wi-Fi profile selection ผ่านโดยไม่แก้ source
8. WSL2 scenarios ผ่านพร้อม cleanup และ rollback
9. Replay ไม่ enforce
10. Installer, update และ rollback ผ่านบน clean Windows host
11. Full test matrix มีเพียง expected skips
12. Release manifest, SBOM, signatures และ evidence bundle verify ได้

## 4. ลำดับ patch ที่ควรทำจริง

### Patch 1 — เสร็จแล้ว

`HEALTH-001-DIAGNOSTIC-BOUNDARY` แยก daemon truth ออกจาก diagnostic PID fallback และเพิ่ม regression tests

### Patch 2 — ต่อไป

`LIFECYCLE-001-DAEMON-AUTHORITY` แก้ `lifecycle.py` ให้ normal start/stop/restart/watchdog ส่ง command ไป daemon และกำหนด `--force` เป็น emergency-only path พร้อม postcondition tests

### Patch 3

`TRUTH-002-CURRENT-HEAD-REBUILD` สร้าง/แก้ generator ให้ rebuild maps ทั้งชุดจาก current HEAD และทำ `TRUTH_VALID` ให้ผ่านโดยไม่แก้ SHA แบบตรง ๆ

### Patch 4

`CORE-001-HEALTH-PIPE-FIRST` แก้ startup ordering และ diagnostics ของ core บน Windows จน health pipe ตอบแม้ worker dependency fail

### Patch 5

`CONTRACT-001-GOLDEN-VECTORS` เพิ่ม event, PEP, health และ forensic fixtures พร้อม ABI layout checks

### Patch 6

`DATA-001-SYNTHETIC-END-TO-END` พิสูจน์ event ID เดียวผ่าน acquisition, detection, policy, PEP, audit และ forensic

### Patch 7

`PEP-001-WFP-HOST-PROOF` พิสูจน์ decision/host effect/rollback บน approved Windows host

### Patch 8

`ADAPTER-001-PORTABLE-PROFILE` ทำ adapter selection สำหรับ LAN/Wi-Fi/Npcap/ETW/FIM/Registry และ replay mode

### Patch 9

`EVIDENCE-001-REPLAY-BUNDLE` ทำ evidence bundle, replay observe-only และ export verification

### Patch 10

`RELEASE-001-CLEAN-INSTALL-ROLLBACK` ทำ installer, signing, update, rollback และ final acceptance

## 5. วิธีทำงานในแต่ละ patch

ทุก patch ต้องประกาศ PATCH-ID, FLOW-ID, target HEAD, target files/symbols, scope, contract/ABI/authority/state/test/evidence impact ก่อนแก้

หลังแก้ต้องบันทึก final HEAD, files changed, old flow → new flow, invariant, build result, test result, Windows resultถ้ามี, evidence level, artifacts, rollback, remaining risk, open blockers และ completion gate

หลังจบ patch ต้อง rebuild machine maps ที่เกี่ยวข้องและ update evidence index ห้ามใช้ map ก่อน patch เป็น current truth ต่อเนื่อง

## 6. สิ่งที่ห้ามทำในระหว่างพัฒนา

ห้ามเพิ่ม UI, federation หรือ detector ใหม่ก่อน core lifecycle และ authority convergence ผ่าน ห้ามแก้เฉพาะ SHA เพื่อหลอก verifier ห้ามทำให้ PEP คืน success เมื่อ WFP ไม่พร้อม ห้ามให้ Shield เป็น enforcement authority ห้ามให้ CLI kill process ใน normal lifecycle ห้ามใช้ PID fallback เป็น health truth ห้ามอ้าง E5 จาก unit test และห้ามใช้ WSL2 scenario ที่ไม่มี rate limit, expiry และ cleanup

## 7. Immediate next action

เริ่ม Patch 2 `LIFECYCLE-001-DAEMON-AUTHORITY` โดยตรวจ control command ที่ daemon รองรับจริงก่อน แล้วทำ vertical slice ครบเส้นทาง:

```text
CLI lifecycle request
  -> explicit transport
  -> Zig command handler
  -> RuntimeSupervisor state transition
  -> postcondition query
  -> audit record
  -> structured CLI result
```

หาก daemon ยังไม่รองรับ command บางตัว ให้เพิ่ม handler ที่ `NOT_IMPLEMENTED` อย่างชัดเจนก่อน ห้ามให้ CLI แอบใช้ process mutation เป็น fallback โดยไม่ประกาศ

## References

[1]: AGENTS.md "AEGIS repository vertical-slice, authority and evidence requirements"

[2]: AEGIS_Development_Roadmap_To_Final.md "Existing AEGIS roadmap from current state to final system"

[3]: AEGIS_SYSTEM_ANALYSIS_BASELINE_2026-09-17.md "Current source-level architecture and risk baseline"

[4]: tools/aegisctl/api/control_api.py "Control health authority and diagnostic boundary"

[5]: tools/aegisctl/commands/lifecycle.py "Current lifecycle and watchdog implementation"

[6]: tests/runtime/test_health.py "Health contract and regression tests"

[7]: tools/truth.py "Truth artifact verifier"

[8]: tools/generate_truth_artifacts.py "Inventory and reference-map generator"

[9]: tools/release_engineering.py "Build manifest, digest and release tooling"
