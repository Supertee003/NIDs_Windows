# AEGIS Master Target Alignment

**วันที่:** 2026-09-14  
**Target authority:** `AEGIS_Development_Master_Report_From_Start_To_Final.md`  
**Repository baseline:** `c9ebc16` ตามรายงานแนบและการตรวจ source ปัจจุบัน

## 1. ข้อสรุป

Master Report ที่แนบมาไม่ใช่แค่เอกสารอธิบายระบบ แต่เป็น **target architecture, development order และ definition of done** ของ AEGIS ทั้งระบบ จึงควรใช้เป็นเอกสารนำทางหลักต่อจากนี้

เป้าหมายสุดท้ายคือ:

```text
Operator CLI / TUI / Web
          |
   One Control Protocol
          |
      Zig Runtime Spine
          |
Canonical Event 109-byte
          |
Go Nose / C / C++ acquisition
          |
Detection -> Correlation -> Incident
          |
Policy IR
          |
Rust PEP — sole privileged authority
          |
Windows WFP / ETW / FIM
          |
Audit -> Forensics -> Hash Chain -> Replay -> Verification
```

ดังนั้นข้อเสนอเดิมที่ให้ใช้ Npcap/host adapters เป็น ingress หลักในระยะสั้นยังใช้ได้เฉพาะ **temporary stabilization** เท่านั้น ไม่ใช่ target สุดท้าย เป้าหมายตาม Master Report ต้องทำให้ `Npcap -> Go Nose -> Canonical Event -> Zig Fabric` เป็น golden path ที่พิสูจน์ได้จริง

## 1.1 Implementation progress — foundation slice

เริ่ม implementation บน branch `fix/foundation-truth-pep-health` จาก `c9ebc16` แล้ว โดยแก้เฉพาะ foundation/control path ดังนี้:

| รายการ | การเปลี่ยนแปลง | หลักฐาน |
|---|---|---|
| Health payload | เพิ่ม `version`, process uptime แบบ monotonic, `subsystems`, `tier3` และ dependency state ที่สร้างจากสถานะจริง | `tools/aegisctl/api/control_api.py` |
| Health tests | เพิ่ม tests ตรวจ subsystem state, PID, tier3 และ counters | `tests/runtime/test_health.py` |
| Runtime health model | แก้ subsystem IDs ที่ซ้ำกัน, ทำ initialization เป็น 6 ช่อง และไม่ assume capture พร้อม, เพิ่ม `recovering` serialization | `src/control/health/runtime_health.zig` |
| PEP authority | ลบ dormant `extern "sec_monitor"` PEP declarations ออกจาก forensic contract; structures เหลือเพื่อ screening/test compatibility | `src/forensic/policy_contract.zig` |
| Control CLI | `status` แสดง state/version/uptime และเพิ่ม `diagnose` ตาม golden-path contract | `tools/aegisctl.py` |
| Encoding defect | แก้ `tools/aegisctl/api/__init__.py` จาก UTF-16 ที่ทำให้ Python import ล้มเหลวเป็น UTF-8 package initializer | `tools/aegisctl/api/__init__.py` |

ผลการตรวจ:

```text
python3 -m unittest tests.runtime.test_health tests.runtime.test_golden_path
38 tests passed, 1 skipped

python3 -m py_compile
control API, CLI และ health tests ผ่าน
```

ข้อจำกัดที่ยังไม่ปิด: Zig toolchain ไม่พร้อมใช้งานใน sandbox นี้ และ Windows host build ยังต้องรันบนเครื่องเป้าหมายก่อนประกาศว่า Slice นี้ผ่านครบทุกภาษา

## 1.2 Implementation progress — explicit PEP action and identity

ปรับ security path ต่อใน source แล้ว:

- เพิ่ม `requested_action` ใน Zig/Rust `PepRequest` ABI โดยรักษา layout ที่เหลือให้เข้ากัน
- Rust PEP ตัดสินจาก policy action ที่ส่งมาโดยตรง (`pass`, `log`, `alert`, `rate_limit`, `block`, `quarantine`, `escalate`)
- severity ใช้ประกอบ two-person rule ของ block เท่านั้น ไม่ถูกใช้แทน policy action
- advisory actions ไม่ต้องใช้ privileged capability
- privileged actions ต้องมี capability bit ที่ PEP ตรวจสอบ
- pipeline ใช้ `state.g_runtime_pid` และ `state.g_runtime_capability_mask` แทน `caller_pid=0` และ `0xFFFFFFFF`
- daemon กำหนด PID จริงหลัง security self-check ผ่าน และให้ capability เฉพาะที่ประกาศไว้
- เพิ่ม Rust regression test สำหรับ advisory action ที่ไม่มี capability

ข้อจำกัดการ verify รอบนี้:

```text
Python runtime/golden-path tests: PASS (38 passed, 1 skipped)
Python compile checks: PASS
Rust cargo test: NOT RUN — cargo ไม่ติดตั้งใน sandbox
Zig build/test: NOT RUN — zig ไม่ติดตั้งใน sandbox
Windows WFP/PEP live test: PENDING บนเครื่อง Windows เป้าหมาย
```

## 1.3 Implementation progress — Canonical Event Golden Path

เริ่ม wiring เส้นทางรับ event จาก Go Nose เข้าสู่ Zig runtime แล้ว:

- Go `FrameWriter` ใช้ `writeAll` เพื่อป้องกัน short write ทำให้ length prefix และ payload ถูกเขียนครบเป็น frame เดียว
- Zig `nose_pipe_reader` ใช้ `readExact` ทั้ง header, payload และ malformed-frame discard เพื่อไม่ตีความ partial read เป็น event ใหม่
- Go Nose ใช้ atomic monotonic event sequence แทน timestamp เป็น event ID เพื่อลด collision และรองรับการติดตาม exactly-once ในชั้นถัดไป
- daemon spawn named-pipe reader ที่ใช้ `g_stop_requested` ร่วมกับ lifecycle ของ daemon; reader ส่งเข้า `pipeline/event_queue.zig` โดยตรง
- reader ยังคง validate magic/version/size ก่อน submit; policy และ enforcement ไม่อยู่ใน acquisition path
- `pipeline/event_queue.zig` มี `pushCanonicalEvent()` เป็น adapter เดียวจาก canonical wire model เข้า detector queue และรักษา `event_id` เดิม

ผลการตรวจรอบนี้:

```text
Python runtime/golden-path tests: PASS (38 passed, 1 skipped)
Go test ./nose: NOT RUN — go ไม่ติดตั้งใน sandbox
Zig build/test: NOT RUN — zig ไม่ติดตั้งใน sandbox
Windows named-pipe E2E: PENDING บนเครื่อง Windows เป้าหมาย
```

หมายเหตุทางสถาปัตยกรรม: ตอนนี้ runtime path ใช้ `pipeline/event_queue.zig` เป็น queue เดียวสำหรับ Nose-to-detector แล้ว ส่วน `nose_contract.zig` เหลือเป็น compatibility API ที่ไม่ถูก initialize ใน daemon path; ยังไม่ควรประกาศ exactly-once ข้ามทั้งระบบจนกว่าจะมี Windows E2E test และ duplicate-event assertion

## 1.4 Windows verification progress

ผลจาก Windows host ล่าสุด:

```text
Rust cargo test: PASS (18 passed, 0 failed)
Go test: package setup failure fixed in source
```

Go Nose มี package declaration ปะปนกันระหว่าง `main` และ `nose` ใน `canonical.go` กับ `golden_path_ffi.go` จึงปรับให้ทั้ง executable และ golden-vector helper ใช้ `package main` เดียวกัน นอกจากนี้แก้ helper ที่อ้าง `json.Object` ซึ่งไม่มีใน `encoding/json` และแก้การเรียก `String()` บน `EnforcementStatus` ที่เป็น byte field

หลังเปิดเผย package เดิม พบ source constants ถูกประกาศซ้ำสองชุดใน `canonical.go` จึงลบชุดซ้ำและคง frozen wire ordinals ไว้เพียงชุดเดียว

รอบถัดมาปรับ compatibility aliases ให้เป็น untyped constants เพื่อใช้กับ `byte`/`uint32` fields ได้โดยตรง, เปลี่ยนชื่อ golden helper ที่ชนกับ test function, และแก้ JSON expected-field handling ใน `golden_path_ffi.go`

ล่าสุดปรับ source constants ของ Go ให้เป็น untyped frozen ordinals ที่ตรงกับ Zig canonical schema พร้อมเติม `registry`, `go_aggregator`, `npcap` และ short alias `cluster_fed` เพื่อให้ capture และ cross-language tests ใช้ชุดค่าเดียวกัน

เพิ่ม `classifyGo()` ให้ map source ordinals ไปยัง SourceKind เดียวกับ Zig (`network`, `host`, `process`, `file`, `registry`, `ml`, `federation`, `replay`, `core`, `external`)

Golden vector พบ reserved-area mismatch ที่ `confidence`: `node_id` ยังคง offset 11 ตาม Zig contract และแก้ `confidence` เป็น offset 15 เพื่อไม่เขียนทับ byte ที่สองของ node ID

Windows `zig build test` เปิดเผย stale assertion ใน `src/contract/event.zig`: `IpcEvent` layout ปัจจุบันมีขนาด 96 bytes ตาม `EVENT_SIZE` และ field layout จริง ไม่ใช่ 80 bytes ตาม comment/test เก่า จึงแก้ comment, compile assertion และ test ให้ยืนยัน 96 bytes โดยไม่ตัด field หรือเปลี่ยน ABI

การ build executable เปิดเผย Zig 0.13 syntax issue ใน optional Nose reader spawn; แก้ `catch` block ให้คืน `null` ด้วย labeled block (`break :blk null`) อย่างถูกต้อง

Runtime smoke test พบ daemon เริ่ม `RUNNING`, Tier-3/PEP เป็น `READY` แล้ว segfault ใน `SetEntriesInAclW` ระหว่างสร้าง control-pipe ACL (`win32_pipe.zig:181`). ปิด custom ACL FFI จาก startup path ชั่วคราวและใช้ default security descriptor เพื่อหยุด crash; ก่อน production ต้องแทนที่ด้วย ACL/SDDL implementation ที่ทดสอบบน Windows จริงและยืนยันว่า `aegisctl` ordinary user เข้าถึงได้ตาม policy

หลัง daemon ทำงานต่อได้ พบว่า `aegisctl` ยังรายงานสถานะจำลองจาก pid files เพราะ `--transport=pipe` ไม่ได้ถูกใช้งานจริง จึงเพิ่ม Python Windows named-pipe client ใน `tools/aegisctl/api/control_api.py` สำหรับ `system.status` และ `system.health`; CLI จะใช้ daemon response เป็น authoritative source และ fallback เฉพาะเมื่อ pipe unavailable

การทดสอบภาคสนามยังได้ fallback เดิม จึงเปลี่ยน client จาก Python file I/O เป็น Win32 `CreateFileW`/`WriteFile`/`ReadFile`/`CloseHandle` โดยตรง เพื่อรองรับ byte-mode named pipe ที่ไม่มี EOF ระหว่าง response และแยก transport failure จาก daemon health อย่างชัดเจน

Probe บน Windows เปิด pipe และเขียน request ได้ 40 bytes แต่ `ReadFile` ได้ `ERROR_PIPE_NOT_CONNECTED (233)`. เพิ่ม `FlushFileBuffers` ฝั่ง Zig หลังเขียน response และก่อน disconnect; ต้อง rebuild daemon แล้ว probe ซ้ำเพื่อยืนยัน response delivery

หลัง rebuild แล้วยังได้ error 233 จึงเพิ่ม diagnostics ใน control-pipe server เพื่อบันทึกจำนวน request bytes ที่อ่าน, `ReadFile` error และผล `FlushFileBuffers`; ขั้นต่อไปคือแยกว่า server ไม่อ่าน request, handler ไม่เขียน response หรือ client ถูกตัดก่อน response

Probe สำเร็จและได้ response 1524 bytes แต่พบ JSON malformed ที่ `healthJson`: serializer เขียน `"subsystems":[]` แล้วเติม object ต่อโดยไม่เปิด array ใหม่ ทำให้ Python JSON decode ล้มเหลวและ fallback. แก้ทั้งสองจุดให้เขียน `"subsystems":[` ก่อนวนรายการ

เพื่อป้องกัน stale writer/buffer behavior เพิ่มเติม ลบการเขียน health JSON รอบแรกและ `clearRetainingCapacity()` ออก เหลือการสร้าง response เพียงครั้งเดียวก่อนเขียน subsystem objects

WFP service `AegisWfp` ยัง STOPPED และ `\\.\AegisWfpDevice` ไม่มีอยู่จริง จึงอธิบายเฉพาะการขาด kernel enforcement device; ไม่ใช่สาเหตุของ control-pipe JSON หรือ CLI transport. Probe ยืนยัน daemon health response ถูกต้องแล้ว จึงเพิ่ม control-client debug flag `AEGIS_DEBUG_CONTROL=1` และให้ status ใช้ health response เป็น fallback ระหว่างตรวจ Python transport

ผลล่าสุด: `aegisctl status` และ `diagnose` อ่าน daemon จริงสำเร็จ (`7/7`, PID ตรง, Tier3 READY) แต่ `health` ยัง fallback เป็นบางครั้งจาก single-instance pipe timing จึงเพิ่ม retry 3 ครั้งสำหรับ read-only `system.status`/`system.health` queries

Verification ล่าสุดผ่านต่อเนื่อง 3 ครั้ง: `aegisctl health` ได้ `component=core`, PID daemon จริง, uptime เพิ่มขึ้น, `state=RUNNING`, `tier3.ready=true` และ subsystem payload จาก Zig ครบ 7 รายการ. ขั้นถัดไปต้องแก้ state truthfulness เพราะ log ยังบอก WFP/ETW/FIM/Npcap unavailable แต่ health aggregate ยังรายงาน RUNNING ทั้งหมด

ปรับ health contract ให้ส่ง `state` เป็น operational state, `runtime_state` เป็น lifecycle state และ `capabilities` จริง (`wfp`, `cpp_bridge`, `udp_brain`) จาก `bridge_init.status()`. เมื่อ WFP หรือ C++ bridge ไม่พร้อม daemon ยัง `runtime_state=RUNNING` ได้ แต่ `state=DEGRADED` และ `degraded=true`

ผล Windows ล่าสุดยืนยัน WFP device เปิดได้จริง และ `dist/aegis_ipc.dll` โหลดได้ แต่ PE export table ของ DLL ปัจจุบันไม่มี exports ขณะที่ source `bridge/aegis_ipc.cpp` ประกาศ C ABI ครบ จึงต้อง rebuild/copy DLL จาก source เดียวกันก่อนประกาศ C++ bridge พร้อมใช้งาน

เพิ่ม `AEGIS_BRIDGE_API` (`__declspec(dllexport)` บน Windows และ default visibility บน non-Windows) ให้ 5 functions ที่ Zig lookup (`init`, `shutdown`, `push_event`, `get_defcon`, `get_event_count`); ต้อง rebuild DLL แล้วตรวจ PE exports ซ้ำ

Windows bridge build รอบแรกพบ C2375 เพราะ export macro อยู่เฉพาะ definition ไม่ตรง declaration ใน `aegis_ipc.hpp`; ย้าย macro ไปใช้ร่วมกันทั้ง declaration/definition และแก้ `GetTickCount64` ที่ขาด Windows include ใน `aegis_packet_parser.cpp` พร้อม fallback `steady_clock` บน non-Windows

แก้ `src/capture/npcap_adapter.zig` ให้ config device ว่างทำ dynamic enumeration ผ่าน `pcap_findalldevs()` แล้วเลือก canonical Npcap device name ที่มี flag up/running ก่อนเรียก `pcap_create()`. วิธีนี้ป้องกันการส่งชื่อ friendly adapter หรือ path ว่างจนเกิด Windows error 123; Go Nose มี enumeration ของตัวเองอยู่แล้วและไม่ได้เป็นต้นเหตุของ log เดิม

Windows E2E ล่าสุดเชื่อม Go Nose เข้า `\\.\pipe\aegis_nose` ได้แล้ว (`client connected`) แต่ client disconnect ก่อนปรากฏ frame counter จึงเพิ่ม diagnostics ฝั่ง Zig สำหรับ header/payload/length/deserializer/submission และฝั่ง Go สำหรับ pipe connection, first dropped frame และ first sent frame; ต้อง rebuild ทั้ง daemon และ Nose แล้วเก็บ log คู่กันก่อนสรุป protocol failure

รอบถัดมาพบ Go Nose/daemon ไม่แสดง packet หลัง ping แม้ process และ pipe อยู่ จึงปรับ Go `firstUpDevice()` ให้ prefer physical adapter ที่มี address โดยกรอง Hyper-V/VMware/loopback พร้อม log adapter ที่เลือก, packet แรก และ counter ทุก 100 packets; ต้องใช้ explicit Npcap device หรือ build ใหม่เพื่อยืนยันว่า capture source เห็น traffic จริง

## 2. สิ่งที่ตรงกันระหว่าง Master Report กับการตรวจ source

| Master Report ระบุ | หลักฐานใน source ปัจจุบัน | สถานะ |
|---|---|---|
| Zig เป็น runtime spine | `src/main.zig`, `src/daemon.zig`, `src/pipeline/event_processor.zig` | **ตรงและมี active path** |
| Rust PEP เป็น enforcement authority | `rust-src/lib.rs`, `src/policy/pep_bindings.zig` | **มี implementation แต่ต้องปิด residue** |
| Go Nose เป็น canonical acquisition | `nose/main.go`, `nose/pipe_writer.go`, `src/capture/nose_pipe_reader.zig`, `src/pipeline/event_queue.zig` | **reader เข้า detector queue เดียวแล้ว; E2E proof pending** |
| Canonical Event เป็น 109-byte wire contract | Go serializer และ `src/contract/canonical_event.zig` | **มี contract แต่ยังไม่มี E4 runtime proof** |
| Health ต้องมี source เดียว | `src/control/health/runtime_health.zig`, `tools/aegisctl/api/control_api.py` | **foundation payload ปรับแล้ว; Zig/Windows build verification pending** |
| `aegisctl.py` เป็น canonical operator client | `tools/aegisctl.py`, control API และ named pipe | **มี structure แต่ต้องตรวจ postcondition/audit ให้ครบ** |
| Evidence chain เป็นผลลัพธ์สุดท้าย | forensic modules และ decision trace | **มีบางส่วนใน active path แต่ยังไม่ครบ event→action→replay** |
| Brain/RAG เป็น advisory | มี brain/analysis modules | **ควรเลื่อนไปหลัง deterministic path** |
| Web/Federation เป็นงานท้าย | มี components และเอกสารรองรับ | **ยังไม่ควรขยายตอนนี้** |

## 3. สิ่งที่ Master Report เพิ่มความชัดเจนจากรายงานเดิม

### 3.1 ลำดับงานต้องเริ่มจาก foundation ไม่ใช่ feature

ลำดับที่ควรยึดเป็น project sequence คือ:

```text
00 Truth / HEAD convergence
01 PEP authority closure
02 Runtime health contract
03 Control backend
04 CI + evidence chain
05 Canonical event golden path
06 Detection + correlation + incident
07 Policy IR + Rust PEP
08 Windows enforcement
09 Forensic traceability
10 Replay + recovery
11 Brain / RAG
12 CLI
13 TUI
14 Web
15 Federation / XDR
16 Release engineering
17 Final verification
```

จุดนี้สำคัญ: **Web, federation, detector ใหม่ และ language bridge ใหม่ไม่ใช่งานเริ่มต้น**

### 3.2 First development slice ถูกกำหนดไว้แล้ว

Master Report ระบุชัดเจนให้เริ่มด้วย:

```text
TRUTH-001 + PEP-002 + HEALTH-001
```

ขอบเขตคือ:

- resync truth artifacts กับ HEAD ปัจจุบัน
- ลบหรือทำให้ dormant PEP surface เป็น non-authority อย่างชัดเจน
- แก้ health contract และ payload
- เพิ่ม negative controls
- ทำ CI ให้ตรวจ exact HEAD
- บันทึก evidence ใหม่

นี่ควรเป็นชุดแรกที่ลงมือทำ ไม่ควรเริ่มจากการต่อ Go Nose หรือสร้าง Web UI ทันที

## 4. Gap ที่ยืนยันจาก source ปัจจุบัน

### 4.1 Truth artifact ยังไม่ตรง HEAD

`runtime_manifest.json` ยังระบุ:

```text
head_sha = 688ab566d477105df5f868cee1571fbec77eedfd
```

ขณะที่ Master Report ระบุ baseline ล่าสุดเป็น `c9ebc16` ดังนั้น Phase 0 ยังไม่ผ่าน การแก้ควรเป็นการ regenerate current-state artifacts ทั้งชุด ไม่ใช่แก้เฉพาะ `runtime_manifest.json` ด้วยมือ

ชุดที่ต้อง synchronize ได้แก่:

- `AI_CONTEXT.md`
- `SYSTEM_MAP.json`
- `FLOW_MAP.json`
- `AUTHORITY_MAP.json`
- `CONTRACT_MAP.json`
- `EVIDENCE_INDEX.json`
- `build_truth.json`
- `runtime_manifest.json`
- `build_manifest.json`
- `inventory.json`
- `reference_map.json`
- `ci_coverage.json`
- `AGENTS.md`

### 4.2 PEP authority ยังมี semantic residue

`src/forensic/policy_contract.zig` ยังประกาศ `extern "sec_monitor"` หลาย function และมี `aegis_pep_evaluate` ที่ถูกระบุว่า dormant แม้ comment จะบอกว่า Rust PEP เป็น sole authority แล้วก็ตาม

ตาม Master Report สิ่งนี้ยังไม่ถือว่าปิด authority boundary เพราะชื่อ, ABI และ declaration ที่ยังอยู่สามารถถูกเข้าใจว่าเป็น enforcement surface ได้

ต้องทำให้เกิดเงื่อนไขต่อไปนี้:

```text
Rust rust-src/lib.rs = only privileged PEP authority
Shield = screening/compatibility only หรือถูกลบ
ไม่มี dormant PEP declaration ที่ใช้เป็น authority ได้
CI มี negative control เมื่อมี PEP surface ที่สอง
```

### 4.3 Runtime health ยังไม่ตรง contract

จาก `src/control/health/runtime_health.zig` พบ gap ตาม Master Report จริง:

- `SubsystemId.fim` และ `SubsystemId.wfp` ใช้ค่า numeric ซ้ำกัน
- `subsystems` มี 6 ช่อง แต่ `initHealth()` ใส่ค่าเริ่มต้น 5 ค่า
- health payload แสดงเพียง `tier3` ใน `checks`
- payload ไม่ expose subsystem states และ counters ครบ
- `last_event_ms` และ counters อยู่ใน object แต่ไม่ถูกส่งออกครบ
- `capture` ถูกตั้งเป็น `ready` แบบ assumed ตั้งแต่ initialization
- state model ยังไม่มี `recovering` ตาม target transition ที่ระบุใน Master Report
- health ยังต้องเชื่อมกับ liveness จริงของ Npcap, ETW, FIM, WFP, PEP และ control

ดังนั้น health ต้องแก้ก่อน CLI/TUI/Web เพราะทุก interface ควรอ่าน object เดียวกันนี้

### 4.4 Canonical golden path ยังเป็น intended path

Master Report ต้องการ:

```text
Npcap -> Go Nose -> 109-byte Canonical Event -> Named Pipe
      -> Zig Event Fabric -> Flow -> Decoder -> Detection
      -> Correlation -> Incident
```

แต่ source ปัจจุบันยังมีความต่างดังนี้:

- daemon ใช้ Npcap และ internal `IpcEvent` โดยตรง
- Go Nose writer ใช้ `\\.\pipe\aegis_nose`
- legacy sensor ใช้ `\\.\pipe\aegis_sensor_pipe`
- `nose_pipe_reader.zig` ระบุเองว่ายังไม่อยู่ใน main target
- ยังไม่มี live E4 proof ว่า event เดียวจาก Go Nose เดินถึง incident ใน Zig runtime

จึงต้องถือ Phase 5 เป็น migration งานใหญ่ภายหลัง foundation ไม่ใช่ถือว่าเสร็จเพียงเพราะ serializer และ reader compile ได้

### 4.5 Policy/PEP semantics ต้องทำให้ตรงกับ target security invariants

Master Report กำหนด invariants ว่า:

```text
Detector cannot enforce
Brain cannot enforce
CLI cannot enforce
TypeScript cannot enforce
Go cannot enforce
C++ cannot decide policy
Zig cannot bypass PEP
Only Rust PEP authorizes privileged enforcement
```

source ปัจจุบันยังมีจุดที่ต้องแก้ให้สอดคล้อง:

- PEP request ยังไม่มี `requested_action` ที่ชัดเจน
- event processor ส่ง `caller_pid=0`
- event processor ส่ง capability เต็ม `0xFFFFFFFF`
- Rust PEP ใช้ severity/quota เป็นส่วนสำคัญในการตัดสิน action
- Rust enforcement บน non-Windows เปลี่ยน block เป็น allow ซึ่งต้องถูกแยกเป็น test/proof behavior ไม่ใช่ตีความว่า enforcement ผ่าน
- forensic policy contract ยังมีชื่อ Shield PEP ปะปนกับ Rust PEP

## 5. แผนพัฒนาที่ปรับให้ตรง Master Report

### Slice 1 — TRUTH-001 + PEP-002 + HEALTH-001

**ยังไม่แตะ Web, Brain, Federation หรือ detector ใหม่**

งานที่ต้องทำ:

1. เขียน generator/checker กลางให้ current-state artifact ทุกไฟล์อ้าง HEAD เดียวกัน
2. แยก historical evidence ออกจาก current truth
3. ลบ `sec_monitor` PEP declaration ที่ dormant หรือเปลี่ยนให้เป็น non-enforcement screening API ที่ชื่อไม่สับสน
4. เพิ่ม negative static check ห้ามมี second PEP authority
5. แก้ `SubsystemId` และ health subsystem array
6. ทำ health payload ให้มี lifecycle, pid, version, uptime, last event, degraded, tier3, subsystem states และ counters
7. ทำ CLI status/health ให้ใช้ payload เดียวกันและคืน exit code ตาม contract
8. เพิ่ม unit tests ของ health transitions และ payload completeness
9. รัน Zig/Rust/Go/C++/Python/TypeScript checks บน exact HEAD
10. สร้าง evidence index ใหม่พร้อม command, commit, result และ artifact hash

**Definition of done:**

```text
HEAD synchronized
PEP has exactly one authority
Health payload matches contract
CLI reports truthful result
All language checks pass
CI runs against exact HEAD
Evidence is recorded
```

### Slice 2 — Control Backend Truth

ทำ `aegisctl` ให้เป็น client จริง ไม่ใช่ owner ของ state:

```text
CLI -> Command Envelope -> Named Pipe
    -> Zig Handler Registry
    -> Authentication
    -> Authorization
    -> Validation
    -> Mutation
    -> Postcondition Verification
    -> Audit
    -> Structured Result
```

ต้องมี exit code ตาม Master Report และทุกคำสั่ง mutation ต้องพิสูจน์ postcondition ก่อนรายงาน success

### Slice 3 — CI + Evidence Chain

จัด CI เป็นชั้นหลัก:

1. Static topology/authority/contracts
2. Unit tests ทุกภาษา
3. Component integration
4. System integration
5. Windows host verification
6. Production simulation
7. Release verification

การ test ผ่านในระดับ unit ต้องไม่ถูกเลื่อนสถานะเป็น production-ready โดยอัตโนมัติ

### Slice 4 — Canonical Event Golden Path

เมื่อ foundation ผ่านแล้วจึงเชื่อม Go Nose เข้ากับ daemon:

1. เลือก endpoint เดียวสำหรับ production path
2. ผูก `nose_pipe_reader.zig` เข้า main build/runtime
3. เพิ่ม adapter จาก 109-byte `CanonicalEvent` เป็น internal `RuntimeEvent`
4. หยุด direct analysis ซ้ำใน legacy sensor
5. เพิ่ม event-count invariant ว่า event หนึ่งถูก process ครั้งเดียว
6. เพิ่ม Go/Zig/Rust/C++/Python golden vector tests
7. เพิ่ม Windows live E4 test ตั้งแต่ Npcap ถึง Incident

### Slice 5 — Decision → Policy → PEP → WFP

1. เพิ่ม explicit action ใน PEP request
2. เชื่อม policy ID/version/event ID/request ID ครบ
3. derive caller identity/capability จาก authenticated source
4. แยก decision, authorization และ execution result
5. พิสูจน์ WFP state change จริงบน Windows
6. บันทึก `ActionResult` ลง audit และ forensic chain

### Slice 6 — Forensics, Replay, Brain, UX และ Release

ทำตามลำดับใน Master Report เท่านั้น:

```text
Forensics -> Replay/Recovery -> Brain/RAG -> CLI maturity
-> TUI -> Web -> Federation/XDR -> Release Engineering -> E7
```

## 6. ภาพความสำเร็จสุดท้าย

ระบบที่ต้องพัฒนาให้ได้ไม่ใช่ “เจ็ดภาษาเชื่อมกัน” แต่เป็น:

> **หนึ่ง security runtime ที่ใช้หลายภาษาอย่างมีขอบเขต, มี canonical event เดียว, policy model เดียว, enforcement authority เดียว, control protocol เดียว และ evidence chain เดียวที่ตรวจสอบย้อนกลับได้**

คุณภาพระดับ 100% ตาม Master Report ต้องพิสูจน์ครบว่า implemented, used, authoritative, integrated, verified, secure, measured, documented, recoverable, auditable, replayable, Windows verified, real telemetry verified, authorization verified, rollback verified, fail-safe verified และ release verified

## 7. คำแนะนำในการเริ่มงานจริง

อย่าเริ่มจากการเขียน feature ใหม่ ให้เริ่มจาก commit ชุดแรกใน scope นี้:

```text
TRUTH-001 + PEP-002 + HEALTH-001
```

หลังจากชุดนี้ผ่าน ค่อยทำ Control Backend และ CI evidence ก่อนจึงค่อย migrate Go Nose เข้า canonical golden path

การจัดลำดับนี้จะทำให้ implementation ปัจจุบันไม่ต้องถูกทิ้งทั้งหมด แต่จะถูกจัดให้มีบทบาทชัดเจน:

- Zig = runtime spine และ decision orchestration
- Go = acquisition/canonical event production
- Rust = sole privileged enforcement authority
- TypeScript = policy authoring/compiler
- Python = advisory intelligence/RAG
- C/C++ = Windows/native adapters
- CLI/TUI/Web = control clients เท่านั้น

**สถานะปัจจุบัน:** ยังไม่พร้อมสำหรับ feature expansion แต่พร้อมเริ่ม foundation slice แรกตาม Master Report
