# AEGIS NIDS Windows — แผนเร่งรัดสู่ระบบสมบูรณ์

**ฉบับ:** 1.1  
**วันที่:** 16 กันยายน 2026  
**จุดเริ่มต้น:** Source-level convergence ใกล้เสร็จ แต่ยังไม่ production-complete

## 1. หลักการเริ่มต้น

เส้นทางที่เร็วที่สุดไม่ใช่การเพิ่มฟีเจอร์จำนวนมาก แต่คือการปิด **vertical slice** เดียวให้ผ่านตั้งแต่ build, start, health, event, detection, policy, PEP, WFP, forensic evidence จนถึง stop และ rollback จากนั้นจึงขยายความสามารถอื่น

```text
install/build
  -> bridge
  -> core/supervisor
  -> truthful health
  -> canonical event
  -> detection/correlation
  -> policy decision
  -> Rust PEP
  -> WFP หรือ explicit unavailable
  -> forensic evidence
  -> operator export
  -> stop/update/rollback
```

ห้ามทำให้ test ผ่านด้วยการลดความเข้ม ห้ามรายงาน `BLOCK` เมื่อ PEP/WFP ไม่พร้อม และห้ามประกาศ production-complete จากจำนวนไฟล์หรือจำนวน test เพียงอย่างเดียว

## 2. สถานะจริงปัจจุบัน

ส่วนที่มีหลักฐานระดับ contract หรือ source แล้ว ได้แก่ Rules CRUD, ruleset 22 rules, policy lifecycle, enforcement command contract, security hardening, artifact digest verification, PEP static invariants และ forensic/replay contract บางส่วน

Blocker ที่ต้องทำก่อนคือ:

1. **Core live lifecycle บน Windows ยังไม่ผ่าน** เพราะ `\\.\pipe\aegis_control` ไม่ตอบ health ภายใน 5 วินาที
2. **WFP host enforcement ยังไม่ผ่านการยืนยันบนเครื่องจริง** ที่มี PEP DLL และ WFP driver
3. Adapter selection, golden-path evidence, WSL2 laboratory และ clean-install rollback ยังต้องพิสูจน์แบบ end-to-end

## 3. ลำดับการพัฒนา

### Phase 0 — Windows reference host และ baseline

**ทำที่ไหน:** Windows x86_64 reference host ใน project root

ตรวจ toolchain, สิทธิ์ administrator, Npcap SDK, WFP state, adapter inventory และ DLL dependencies จากนั้นเก็บ commit, OS build, tool versions, environment variables และ adapter inventory ลง evidence baseline

```bat
cd /d D:\NIDs_Windows
zig version
rustc --version
cargo --version
go version
python --version
cmake --version
scripts\build_all.bat
```

**ผ่านเมื่อ:** clean build ให้ผลชัดเจน และมี baseline ที่ทำซ้ำได้

### Phase 1 — Core live lifecycle

**ไฟล์หลัก:** `src/daemon.zig`, `src/platform/win32_service.zig`, `src/platform/win32_pipe.zig`, `tests/runtime/conftest.py`, `tests/runtime/test_harness_integration.py`

วินิจฉัยตามลำดับนี้:

1. process exit code และ lifetime
2. stdout/stderr และ missing DLL
3. resolved working directory และ config paths
4. PEP load state และ bridge load state
5. security self-check category ที่ล้มเหลว
6. `CreateNamedPipeW` และ `ConnectNamedPipe` Win32 error
7. pipe name, ACL และ response envelope

กฎการแก้คือ core ต้องเปิด health pipe แม้อยู่ใน `DEGRADED` และต้องบอก failure reason จริง

```bat
zig build
python -m pytest tests/runtime/test_harness_integration.py -v
```

**Exit criteria:** lifecycle test ได้ `4 passed` หรือ expected skips เท่านั้น และ health มี `component`, `state`, `deps`, `workers.pipeline_ready` และ `failure_reasons`

### Phase 2 — Freeze canonical contracts

สร้าง versioned fixtures ใน `contracts/fixtures/` สำหรับ event, health, policy, PEP ABI และ forensic trace ให้ Zig, Rust, Python, Go และ TypeScript ใช้ fixture เดียวกัน

ต้องตรวจ field order, required fields, bounds, digest, version, severity/action vocabulary, ABI size/alignment และ backward compatibility

**Exit criteria:** cross-language round-trip และ x86_64 Windows ABI layout test ผ่าน

### Phase 3 — Runtime portability และ adapter selection

ใช้ `config/deployment_profile.example.json` เป็นฐาน ไม่ใช้ host assumption แบบ hard-coded

ต้องรองรับ:

- auto selection
- Ethernet และ Wi-Fi ด้วย description, MAC หรือ index
- exclude loopback/virtual adapters
- Npcap, WFP, ETW และ replay provider
- fallback reason ใน health
- provider failure ที่ไม่เปลี่ยน privileged decision เป็น allow

ทดสอบ mock inventory, auto selection, explicit MAC selection, unavailable provider, replay mode และ live LAN/Wi-Fi โดยต้องสร้าง canonical event schema เดียวกัน

### Phase 4 — Rules และ policy productization

เชื่อม CLI เข้ากับ control IPC เท่านั้น ห้าม CLI mutate enforcement state โดยตรง

ต้องเพิ่ม JSON schema, duplicate-ID rejection, regex validation, scope, severity, action vocabulary, revision, expiry, change reason, dry-run compilation, atomic policy swap, rollback, audit record และ signature verification ก่อน enable production policy

**Exit criteria:** `rules validate`, CRUD, `policy reload`, enable/disable และ rollback ทำงานผ่าน control IPC พร้อม audit ที่ตรวจสอบได้

### Phase 5 — Golden path detection และ enforcement

พิสูจน์ input เดียวตั้งแต่ WSL2/LAN/Wi-Fi ถึง evidence:

```text
input -> Go Nose/adapter -> canonical event -> Zig detection
-> correlation -> policy -> Rust PEP -> WFP -> response -> forensic trace
```

ทุก decision ต้องรักษา `event_id`, `incident_id`, `policy_id`, `policy_version`, `request_id`, `pep_decision`, `enforcement_result` และ `forensic_id`

| PEP | WFP | ผลที่ยอมรับได้ |
|---|---|---|
| ready | ready | block/quarantine + evidence |
| ready | unavailable | unavailable/escalate; ห้าม false success |
| unavailable | ready | reject/escalate; fail closed |
| unavailable | unavailable | detection/audit เท่านั้น |

### Phase 6 — WSL2 controlled laboratory

ใช้ WSL2 เป็น controlled attacker เท่านั้น ห้าม malware จริง, credential theft, ransomware หรือ uncontrolled flood

ลำดับ scenario คือ connectivity, disposable HTTP, SQLi marker, command-injection marker, XSS marker, path-traversal marker, bounded reconnaissance, harmless file/process marker, replay comparison และ canary block ที่มี expiry/rollback

ทุก scenario ต้องบันทึก expected rule/action, identifiers, PEP decision, WFP result หรือ explicit unavailable, forensic export และ cleanup

### Phase 7 — Forensics, replay และ evidence

ทำ append-only hash chain, ordered decision trace, provenance ของ event/policy/context/binary, historical replay ที่ไม่ enforce และ difference reason

ต่อหนึ่ง run ต้องมี:

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

### Phase 8 — Operator workflow

รวมคำสั่งให้ operator ใช้ได้จาก surface เดียว:

```text
preflight
install/build
profile validate
start
status
health
events
forensic export
rules/policy management
canary run
stop
snapshot
rollback
```

ข้อผิดพลาดต้องมี code, cause, impact, diagnostic command และ recovery เช่น `CORE_NOT_RUNNING`, `PEP_UNAVAILABLE`, `WFP_DRIVER_MISSING`, `ADAPTER_NOT_FOUND`, `RULESET_INVALID` และ `CONTROL_PIPE_UNAVAILABLE`

### Phase 9 — Release, installer และ rollback

สร้าง Windows binaries, DLLs, Go/Python/Cython/TypeScript artifacts, profile template, signed policy package, SBOM, manifest, digest file, installer และ rollback snapshot

ทดสอบ clean install, start, upgrade, failed-upgrade recovery, rollback, uninstall และการรักษา config/evidence

### Phase 10 — Final acceptance

ต้องผ่าน full pytest โดยไม่มี unexpected failure, Zig/Rust/Shield/C++/Go/TypeScript tests, Windows lifecycle, WFP host block/unblock, WSL2 lab และ release verification

ผู้ตรวจต้องติดตั้งบน clean Windows host, เลือก LAN หรือ Wi-Fi, start, ดู health, เปลี่ยน rule, สร้าง bounded event จาก WSL2, เห็น decision, export evidence, stop และ rollback ได้โดยไม่แก้ source

## 4. แผนเร่งรัด 10 วันทำการ

| วัน | ผลลัพธ์ |
|---|---|
| 1 | reference host, toolchain baseline, clean build |
| 2 | core diagnostics และ root-cause classification |
| 3 | core lifecycle ผ่านบน Windows |
| 4 | canonical fixtures และ ABI/round-trip tests |
| 5 | adapter selection และ replay mode |
| 6 | policy reload, atomic swap และ rollback |
| 7 | event-to-PEP-to-WFP/evidence golden path |
| 8 | WSL2 bounded scenarios และ cleanup |
| 9 | evidence bundle, replay และ actionable CLI errors |
| 10 | clean install, upgrade, rollback และ release candidate gate |

ถ้า Phase 1 ใช้เวลานาน ให้หยุด feature work และแก้ process lifetime, DLL/config path, self-check, pipe creation และ health response ก่อน เพราะทุก phase หลังจากนั้นพึ่งพา core lifecycle

## 5. Definition of Done

ประกาศ production-complete ได้เมื่อเงื่อนไขทั้งหมดต่อไปนี้ผ่านพร้อมหลักฐาน:

1. runtime owner เดียวและ worker start/stop/join มี postcondition จริง
2. core health pipe ตอบเสมอเมื่อ process ยังทำงาน
3. privileged decision ทั้งหมดผ่าน Rust PEP และ WFP authority เดียว
4. canonical contracts มี version และ cross-language tests ผ่าน
5. Wi-Fi และ Ethernet เลือกผ่าน profile โดยไม่แก้ source
6. rules/policy ผ่าน validation, audit, signature และ rollback
7. identifiers ครบตั้งแต่ event ถึง forensic evidence
8. replay ไม่สามารถ enforce
9. WSL2 lab มี scope, rate limit, expiry และ cleanup
10. installer, upgrade, rollback และ uninstall ผ่านบน clean host
11. artifact digest ตรง manifest และ evidence bundle ตรวจซ้ำได้
12. full acceptance และ operational demonstration ผ่าน

## 6. สิ่งที่ต้องทำทันที

เริ่มที่ Phase 0 และ Phase 1 เท่านั้น:

1. รัน `scripts\build_all.bat` บน Windows reference host
2. รัน `python -m pytest tests/runtime/test_harness_integration.py -v`
3. เก็บ exit code, stdout, stderr, cwd, DLL state และ Win32 pipe error
4. แก้ root cause จริงโดยไม่ลดความเข้มของ test
5. รันซ้ำจน core lifecycle ผ่าน
6. เก็บ evidence และ freeze Phase 1
7. จึงเริ่ม Phase 2 และ Phase 3

ทุก work session ต้องส่งรายการไฟล์ที่แก้, commands ที่รัน, environment, ผล test, expected skips, blocker และ evidence path

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"

[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"

[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"

[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"

[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

---

**สรุป:** เริ่มจากทำให้ core รันและตอบ health จริงบน Windows ก่อน จากนั้น freeze contracts, ทำ adapter portability, เชื่อม policy/enforcement, พิสูจน์ WSL2 golden path, สร้าง evidence และปิด installer/rollback gates ตามลำดับนี้เท่านั้น จึงจะเรียกได้ว่าระบบสมบูรณ์ตาม code ที่พัฒนาขึ้น

## 7. บันทึกการดำเนินงาน

ผู้พัฒนาอนุมัติให้ใช้แผนนี้เป็นลำดับงานหลักของโครงการ การอนุมัติหมายถึงการอนุมัติ workflow ไม่ใช่การยืนยันว่า production-complete แล้ว งานรอบแรกที่ทำแล้วคือการเพิ่ม startup diagnostics ใน core lifecycle; งานถัดไปคือ rebuild และทดสอบบน Windows reference host

## 8. สถานะ phase

| Phase | สถานะ |
|---|---|
| 0 Reference host | เริ่มแล้ว; ต้องเก็บ baseline บน Windows |
| 1 Core lifecycle | กำลังปิด; ต้อง rebuild และรัน live test |
| 2 Contracts | รอ Phase 1 |
| 3 Adapters | รอ Phase 2 |
| 4 Policy productization | contract ผ่านบางส่วน; ต้องเชื่อม production path |
| 5 Golden path | ยังไม่ยืนยัน live |
| 6 WSL2 lab | วางแบบแล้ว |
| 7 Evidence/replay | contract ผ่านบางส่วน |
| 8 Operator workflow | มีบางส่วน; ต้องรวมเป็น one-command workflow |
| 9 Release safety | artifact verification บางส่วนผ่าน |
| 10 Acceptance | ยังไม่ผ่าน |

หากงานใดไม่ช่วยปิด gate, เพิ่ม evidence หรือแก้ security/build dependency ให้เลื่อนไปก่อน

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

---

**ข้อสรุป:** ความสมบูรณ์ของ AEGIS จะตัดสินจาก runtime behavior บน Windows, enforcement behavior บน approved host, evidence bundle และ clean-install demonstration ไม่ใช่จาก source code ที่ดูครบเพียงอย่างเดียว

## 9. การรับรองแผนปฏิบัติการ

คำสั่งของผู้พัฒนาคือให้ดำเนินการตามแผนนี้ จึงกำหนดให้ Phase 0 และ Phase 1 เป็นงานแรก และให้ใช้ exit criteria กับ evidence เป็นเงื่อนไขบังคับของทุกการพัฒนาถัดไป

## 10. รูปแบบรายงานเมื่อจบรอบงาน

ทุก work session ต้องรายงานไฟล์ที่แก้ เหตุผล คำสั่งที่รัน environment ผล test expected skips failure reason และ phase ที่ผ่านหรือยังเป็น blocker การเปลี่ยนแปลงใดที่ไม่มีหลักฐานทำซ้ำได้ให้ถือว่ายังไม่เสร็จ

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

---

**ข้อสรุป:** แผนนี้ทำให้การพัฒนาเร็วขึ้นด้วยการลดงานที่ไม่ช่วยปิด blocker และทำให้คำว่า “ระบบสมบูรณ์” เป็นผลตรวจรับที่วัดได้และตรวจซ้ำได้

## 11. เอกสารอ้างอิงภายในโครงการ

โปรดใช้ roadmap, README, local runbook, lifecycle integration test และ build manifest เป็น source of truth ของงานแต่ละ phase และบันทึกความขัดแย้งระหว่างเอกสารกับ runtime ตามลำดับความน่าเชื่อถือที่กำหนดใน README

## 12. ขั้นตอนถัดไปที่ต้องดำเนินการ

เมื่อมี Windows reference host พร้อม ให้ดำเนินการ Phase 0 และ Phase 1 ทันทีตามหัวข้อ 6 ก่อน แล้วส่งผล test และ diagnostics กลับมาเพื่อเลือก root-cause fix รอบถัดไป

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

---

**สิ้นสุดแผน**

## 13. Implementation status

Source changes from the previous work session have already added core startup diagnostics, lifecycle process diagnostics, working-directory/config diagnostics, console startup error propagation, and Win32 named-pipe error reporting. These changes remain subject to Windows rebuild and runtime verification.

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

## 14. Final operating rule

Do not mark the project complete until the final acceptance criteria and operational demonstration in this document have been executed on the approved Windows host.

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

## 15. Owner decision

The project owner has directed that development proceed according to this plan. Work shall begin with the reference-host baseline and core live lifecycle, and later phases shall not be treated as complete without their stated exit criteria and evidence.

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

## 16. Completion note

This document is the execution plan, not proof of completion. Proof must come from the commands, tests, runtime observations, host enforcement checks, evidence bundles and clean-install demonstration described above.

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"

---

End of execution plan.


## 17. โหมดการพัฒนาแบบเป็นระบบและประหยัด Credits

แผนนี้ไม่กำหนดให้รีบส่งมอบภายในเวลาสั้น แต่กำหนดให้ลดงานซ้ำและแก้เฉพาะ blocker ที่มีผลต่อระบบจริง โดยใช้หลักการต่อไปนี้:

1. อ่านและวิเคราะห์ไฟล์ครั้งเดียว แล้วบันทึกผลไว้ในเอกสารหรือ evidence เพื่อไม่ต้องวิเคราะห์ซ้ำในรอบถัดไป
2. ทำงานทีละ phase และทีละ blocker ห้ามเริ่ม phase ใหม่ก่อน exit criteria ของ phase ปัจจุบันผ่าน
3. ก่อนแก้ source ต้องมี failing test หรือ runtime evidence ที่ระบุปัญหาได้
4. หลังแก้ต้องรันเฉพาะ targeted test ก่อน แล้วจึงรัน full suite เมื่อ phase มีแนวโน้มผ่าน
5. งานที่เป็นเอกสารหรือ contract ให้ทำครั้งเดียวและให้ทุกภาษานำไปใช้ร่วมกัน
6. ไม่สร้าง feature ใหม่ในส่วนที่ยังไม่มี runtime owner หรือยังไม่มี canonical contract
7. ทุก session ต้องส่งต่อเพียงสี่ข้อมูล: สิ่งที่พบ, สิ่งที่แก้, ผลทดสอบ, blocker ถัดไป
8. หากต้องใช้ Windows host หรือ driver จริง ให้หยุดที่จุดนั้นและขอผล test จาก host แทนการเดาหรือรันการวิเคราะห์ซ้ำใน sandbox

### รอบการทำงานมาตรฐานหนึ่งรอบ

```text
ตรวจ blocker เดียว
  -> แก้ source ที่เกี่ยวข้องเท่านั้น
  -> รัน targeted test
  -> เก็บ evidence
  -> อัปเดตสถานะ phase
  -> เลือก blocker ถัดไป
```

### งานที่เริ่มทันที

งานปัจจุบันคือ Phase 1: Core live lifecycle โดยผู้พัฒนาต้องรันบน Windows reference host:

```bat
cd /d D:\NIDs_Windows
zig build
python -m pytest tests/runtime/test_harness_integration.py -v
```

ถ้า test ผ่าน ให้ส่งผลลัพธ์มาเพื่อเริ่ม Phase 2 โดยไม่ต้องวิเคราะห์ source tree ใหม่ ถ้ายังไม่ผ่าน ให้ส่งเฉพาะ output ของ core test, exit code, stdout/stderr และ Win32 error เพื่อแก้ root cause ต่อจุดนั้น

หากไม่มี Windows toolchain ในขณะนี้ ให้ถือว่า Phase 1 อยู่สถานะ `blocked-by-environment` และไม่ควรใช้ Credits ทำ static analysis ซ้ำจนกว่าจะมีผล runtime ใหม่

## References

[1]: `AEGISNIDSWindows—Roadmapจากสถานะปัจจุบันสู่ระบบสมบูรณ์.md` "AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์"
[2]: `README.md` "AEGIS NIDS Windows — Architecture and current truth status"
[3]: `docs/runtime/LOCAL_RUNBOOK.md` "AEGIS NIDS — Local Runbook"
[4]: `tests/runtime/test_harness_integration.py` "Windows component lifecycle integration tests"
[5]: `build_manifest.json` "AEGIS release build manifest and artifact digests"
