# Deep Audit 01 — Zig Runtime, Lifecycle และ Control Plane

## ขอบเขตและข้อสรุป

รายงานนี้ตรวจสอบ source-of-truth ใน repository `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows` โดยใช้ `git ls-files` เป็น inventory หลัก แล้วอ่าน implementation จริงของ `src/main.zig`, `src/daemon.zig`, supervisor, control protocol/dispatch, named pipe, runtime state, pipeline queue/worker, bridge boundary, forensic ring, lifecycle module และ `build.zig` รวมถึงไฟล์ config และ test ที่ tightly coupled เท่านั้น การตรวจนี้ไม่ใช้ `netsh`, Windows Firewall API หรือ `legacy block_ip` เป็นหลักฐานว่า host enforcement สำเร็จ และไม่ได้รัน controlled host block หรือเปลี่ยนระบบภายนอก

**ข้อสรุปโดยรวม:** โค้ดมีเส้นทาง daemon ที่เห็นได้ชัดและมีความพยายามแยก owner ของ worker handle, ใช้ message-mode named pipe และตรวจ token ก่อน dispatch อย่างไรก็ตาม ยังไม่ควรเรียกว่า production-ready เพราะมีปัญหา critical ที่กระทบความน่าเชื่อถือของ build และ health truth รวมถึง data race ของ counters/ID, privileged control protocol ที่นิยาม nonce/version แต่ไม่ตรวจจริง และ background spool thread ที่ไม่มี owner/join ระหว่าง shutdown นอกจากนี้ lifecycle implementation ที่มี fault-injection tests ไม่ใช่ lifecycle ที่ daemon ใช้จริง ขณะที่ test contract ฝั่ง Python ไม่ตรงกับ wire/health payload ของ Zig ที่ active อยู่

## Files reviewed และ inventory gaps

รายการด้านล่างเป็น path ที่มีอยู่จริงและอยู่ใน inventory ที่ตรวจ หรือเป็นไฟล์ tightly coupled ที่ต้องอ่านเพื่อ trace boundary โดยระบุ path ตาม repository root

### Runtime, control, pipeline, platform และ build

| กลุ่ม | ไฟล์ |
|---|---|
| Entry/build | `build.zig`, `src/main.zig`, `src/daemon.zig`, `src/all_tests.zig`, `src/fuzz_entry.zig`, `src/integration_test_main.zig`, `src/perf_bench_main.zig` |
| Control | `src/control.zig`, `src/control/protocol.zig`, `src/control/authorization.zig`, `src/control/audit.zig`, `src/control/handler_registry.zig`, `src/control/state_machine.zig`, `src/control/health/runtime_health.zig` |
| Runtime state/pipeline | `src/pipeline/runtime_state.zig`, `src/pipeline/event_queue.zig`, `src/pipeline/event_processor.zig`, `src/pipeline/rule_loader.zig`, `src/pipeline/telemetry_threads.zig`, `src/pipeline/packet_callback.zig`, `src/pipeline/data_plane_contract.zig` |
| Windows process/service boundary | `src/platform/win32_service.zig`, `src/platform/win32_pipe.zig`, `src/core/bridge_init.zig`, `src/core/nids_capture.zig`, `src/capture/nose_pipe_reader.zig`, `src/capture/nose_contract.zig`, `src/policy/pep_bindings.zig`, `src/policy/action_dispatcher.zig`, `src/windows/etw_realtime.zig`, `src/windows/fim.zig`, `src/windows/registry_monitor.zig` |
| Contract/ABI | `src/contract/canonical_event.zig`, `src/contract/event.zig`, `src/contract/event_fabric.zig`, `src/contract/event_queue.zig`, `src/contract/runtime_manifest.zig`, `src/contract/runtime_spine.zig`, `src/contract/wire_event.zig`, `src/contract/abi_manifest.zig`, `src/policy/enforcement_receipt.zig` |

### Lifecycle, reliability และ tightly coupled forensic implementation

`src/reliability/lifecycle.zig`, `src/reliability/watchdog.zig`, `src/reliability/security_check.zig`, `src/reliability/fault_injection.zig`, `src/reliability/fault_matrix.zig`, `src/reliability/latency_histogram.zig`, `src/reliability/reliability.zig`, `src/reliability/release_engineering.zig`, `src/reliability/release_provenance.zig`, `src/forensic/forensic_pipeline.zig`, `src/forensic/forensic_log.zig`, `src/forensic/forensics_engine.zig`, `src/forensic/evidence_record.zig`, `src/forensic/decision_trace.zig`, `src/forensic/abi_contract.zig`, `src/forensic/integration_contract.zig`, `src/forensic/policy_contract.zig`, `src/forensic/provenance.zig`, `src/forensic/python_contract.zig`, `src/forensic/release_gate.zig`, `src/forensic/release_manifest.zig`, `src/forensic/replay_contract.zig`, `src/forensic/replay_engine.zig`, `src/forensic/replay_integrity.zig`, `src/forensic/replay_verifier.zig`, `src/forensic/replayable_security.zig`, `src/forensic/siem_forwarder.zig` รวมถึง `src/core/nids_main.zig` และ `src/core/rust_pep.zig` ในฐานะ legacy/tightly coupled paths ที่มีผลต่อ ownership และ shutdown

### Config และ tests ที่ใช้เป็นหลักฐาน

`configs/Rules.json`, `configs/policies.json`, `configs/test/host_correlator_config.json`, `configs/test/integration_test_config.json`, `configs/test/perf_benchmark_config.json`, `tests/runtime/test_health.py`, `tests/runtime/test_restart.py`, `tests/runtime/test_states.py`, `tests/runtime/test_timeouts.py`, `tests/runtime/test_wire.py`, `tests/runtime/test_harness_integration.py`, `tests/runtime/README.md`, `tools/aegisctl/api/control_api.py` และ `tools/aegisctl/client.py`

### Exact paths ที่ระบุใน handoff แต่ไม่มีใน tracked inventory

ไม่พบ directory/file ตามชื่อ exact เหล่านี้ใน `git ls-files`: `src/runtime/`, `src/queue/`, `src/health/`, `src/lifecycle/`, `src/forensics/`, `src/analysis/`, `src/ingest/`, `src/telemetry/` และไม่พบ `src/queue.zig`, `src/health.zig`, `src/lifecycle.zig` โดย implementation ที่ใกล้เคียงจริงอยู่ที่ `src/pipeline/runtime_state.zig`, `src/control/health/runtime_health.zig`, `src/reliability/lifecycle.zig` และ `src/forensic/` (เอกพจน์) จึงห้ามสรุปจากชื่อ directory ว่ามี module ตาม handoff

## Architecture และ call/data/control flow

### Startup และ singleton ownership

`src/main.zig:20-34` จัดการ `--version` แล้วเรียก `platform/win32_service.mainEntry()`. บน Windows `mainEntry()` เรียก `StartServiceCtrlDispatcherW`; ถ้า SCM รับ process จะเข้า `serviceMain()` และถ้าไม่ใช่ service จะ fallback เป็น foreground daemon (`src/platform/win32_service.zig:64-126`). Service stop handler ตั้ง `g_stop_requested`, เรียก `bridge_init.requestShutdown()` และเรียก `wakeControlPipe()` เพื่อปลุก accept loop (`src/platform/win32_service.zig:64-72`)

`daemon.runDaemon()` เป็น startup ที่ใช้งานจริง (`src/daemon.zig:88-510`): ติดตั้ง stderr logger, transition state เป็น `STARTING`, register subsystems, run security self-check, กำหนด `g_runtime_pid` และ capability mask, probe capability, จัดสรร arena/forensic ring/watchdog, โหลด Rules และ policies, สร้าง PEP/action dispatcher, initialise Windows/bridge dependencies, แล้วสร้าง worker handles ใน `RuntimeSupervisor` (`src/daemon.zig:51-85, 106-177, 182-343, 367-439`). หลัง readiness wait จะ mark subsystem state, transition เป็น `RUNNING` หรือ `DEGRADED`, ตั้ง service status เป็น running และ serve control pipe บน main thread (`src/daemon.zig:441-501`)

มี singleton เชิง endpoint บางส่วน: control pipe ใช้ `CONTROL_PIPE_MAX_INSTANCES = 1` และ SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (`src/platform/win32_pipe.zig:29-33,63-68,203-212`). แต่ไม่มี process-wide named mutex, owner epoch หรือ PID/instance lease ดังนั้นการป้องกัน duplicate runtime อาศัยการชนกันของ `CreateNamedPipeW` โดยพฤตินัย ไม่ใช่ invariant ที่ตรวจและ audit ได้ หาก process เก่าค้างหรือ endpoint ถูกสร้าง/ปิดในช่วง race จะไม่มี protocol ที่พิสูจน์ว่า client คุยกับ generation ที่ต้องการ

### Input ถึง output ของ data plane

1. **Go Nose process:** `capture/nose_pipe_reader.runPipeReaderLoop()` รับ canonical frames จาก named pipe ของ Go Nose, ตั้ง `g_nose_ready` หลังสร้าง/เตรียม reader แล้วแปลง input เป็น event เข้า `pipeline/event_queue` (`src/capture/nose_pipe_reader.zig:194-309`). นี่เป็น canonical network ingress ตาม comment ใน `src/daemon.zig:406-419`.
2. **Legacy sensor pipe:** daemon ยัง spawn `core/nids_capture.capture_packets` (`src/daemon.zig:389-395`). `aegis_sensor_pipe` ใช้ admin-only SDDL และ overlapped I/O แล้วสร้าง `IpcEvent` ใส่ queue เดียว (`src/core/nids_capture.zig:118-215,239-305`). เส้นทางนี้มีชื่อ “legacy” แต่ยังเป็น worker จริงของ daemon จึงต้องนับเป็น input authority จนกว่าจะถอดออกหรือประกาศ contract ให้ชัดเจน
3. **ETW/FIM/registry:** `pipeline/telemetry_threads.zig` เริ่ม native adapters และ push `IpcEvent` เข้า queue; readiness flags ถูกตั้งเมื่อ adapter เริ่มได้ (`src/pipeline/telemetry_threads.zig:19-52,84-116,118-159`). บน non-Windows worker return โดยไม่ mark failure ทำให้ health เห็น adapter ไม่พร้อมแต่ไม่จำเป็นต้องตีความว่า process ล้ม
4. **Queue:** producers serialise ด้วย `g_queue_producer_mutex`; consumer ใช้ `g_queue_mutex`; queue ขนาด 4096 และ payload ถูกตัดที่ 1500 bytes (`src/pipeline/event_queue.zig:11-51,155-166`). Full queue drop จะนับ `g_queue_drops` แต่ไม่มี backpressure หรือ shutdown drain guarantee
5. **Detection/policy/PEP/forensic:** `pipelineLoop()` ตั้ง pipeline ready แล้ว pop/process จน `g_stop_requested` (`src/pipeline/event_processor.zig:203-251`). `processEvent()` ทำ flow lookup, signature/anomaly/threat tracking, policy evaluation, เรียก Rust PEP พร้อม runtime PID/capability/request ID, dispatch action และ append forensic record (`src/pipeline/event_processor.zig:26-201`). Receipt/host-effect proof ไม่ได้ถูกสร้างโดย handler นี้เป็นหลักฐาน WFP; control `enforcement.status` ยังรายงาน `host_effect_capable:false` (`src/control/handler_registry.zig:487-510`)
6. **Output:** output หลักคือ counters/state ผ่าน control pipe, decision/audit logs และ in-memory forensic ring. Control plane ไม่ได้ส่ง event ต่อไปเป็น wire protocol เดียวกับ Python runtime-contract tests; จึงต้องแยก “JSON ตอบกลับของ named pipe” ออกจาก “NDJSON envelope contract” ที่ tests ฝั่ง Python สร้างขึ้น

### Control plane, privilege และ language/process boundaries

Client เช่น `tools/aegisctl/api/control_api.py:67-126` เปิด `\\.\pipe\aegis_control`, ส่ง JSON `{command,payload}` และอ่าน response โดยรองรับ `ERROR_MORE_DATA`. Zig server ใช้ message-mode named pipe หนึ่ง request/response ต่อ connection (`src/platform/win32_pipe.zig:21-33,224-258`). `handleControlRequest()` ไม่เชื่อ `caller_role` ใน JSON แต่ impersonate client แล้วอ่าน `TokenElevation`; elevated token ได้ `.privileged`, non-elevated token ที่ผ่าน SDDL ได้ `.operate` (`src/platform/win32_pipe.zig:127-172`). จากนั้น handler dispatch ตรวจ role ผ่าน `protocol.contract(cmd)` และ audit ผล (`src/control/handler_registry.zig:139-249`, `src/control/protocol.zig:174-240`)

Boundary สำคัญคือ process/ภาษา: Go Nose และ Python sensor เข้า named pipe; Zig เป็น runtime owner และ pipeline; C++ bridge เป็น DLL ผ่าน `std.DynLib`; Rust PEP เป็น FFI DLL และเป็น authority สำหรับ request; Windows native ETW/FIM/registry ใช้ helper libraries; WFP/host effect ต้องพิสูจน์ด้วย provider-backed receipt ไม่ใช่จาก bookkeeping (`src/core/bridge_init.zig:55-110,226-308,367-424`, `src/policy/pep_bindings.zig`, `src/forensic/forensic_pipeline.zig:123-146`). สิทธิ์ service/process จึงไม่เท่ากับสิทธิ์ของ client: PEP ใช้ `g_runtime_pid` และ mask `0x01` จาก daemon (`src/daemon.zig:124-128`), ขณะที่ control role มาจาก impersonated pipe token

## Critical findings

### C-01 — Build graph ไม่ reproducible จาก tracked repository

`build.zig:123-165` สร้าง test artifact จาก `src/all_tests.zig`; แต่ `src/all_tests.zig:9,25,50,56-59` import paths เช่น `src/contract/abi_manifest.zig`, `src/detection/detection_result.zig`, `src/forensic/replay_contract.zig`, `src/windows/adapter_contract.zig`, `src/operator/recovery_contract.zig`, `src/lab/scenario_contract.zig` และ `src/release/artifact_contract.zig` ที่มีอยู่ใน working tree แต่ไม่ปรากฏใน `git ls-files` ตาม inventory ที่ตรวจ การ clean checkout จาก tracked files จึงมีความเสี่ยงสูงที่จะ compile ไม่ได้ แม้ local execution นี้ไม่มี `zig` จึงไม่ได้แอบอ้างผล build จริง

ผลกระทบคือ test/build gate ไม่ได้พิสูจน์ binary เดียวกับ source ที่ review และ release อาจขึ้นกับ untracked/generated files. นี่เป็น critical supply-chain/reproducibility defect ไม่ใช่เพียง test coverage gap

### C-02 — มี health truth สองชุด และชุดที่ประกาศว่าเป็น single source ไม่ใช่ active source

`src/control/health/runtime_health.zig:1-10,99-161,343-389` ประกาศว่าเป็น single source แต่ไม่ถูก import ใน active daemon/control graph และมี constructs ที่ไม่สอดคล้องกับ Zig syntax/current code เช่น `"true"_" "[1..]`, `temp[10] = 'u8'`, `u8('0' + ...)` และ `@os PID` (`runtime_health.zig:216-221,280-312,346-349`). Active path ใช้ `control/state_machine.zig` และ `RuntimeState.healthJson()` (`src/control/handler_registry.zig:323-350`, `src/control/state_machine.zig:281-357`)

ยิ่งกว่านั้น Python schema tests ต้องการ `counters` และ `deps` (`tests/runtime/test_health.py:75-105`) แต่ active Zig health payload ส่ง `capabilities`, `data_plane`, `deps` และ `workers` โดยไม่มี `counters` แบบ contract เดียวกัน (`src/control/state_machine.zig:320-356`). ดังนั้น “health” ที่ client เห็นอาจถูกต้องตาม implementation ฝั่งหนึ่งแต่ผิดตาม contract/test อีกฝั่ง ทำให้ operator ตัดสินใจจากสถานะที่ไม่ใช่ source of truth เดียว

### C-03 — Shared counters และ identity counters มี data race ระหว่าง pipeline กับ control

ตัวแปรหลายตัวเป็น plain `u64/u32/bool` ใน `src/pipeline/runtime_state.zig:69-110`. Pipeline increment counters และ IDs โดยไม่ lock/atomic (`src/pipeline/event_processor.zig:49-55,82-99,126-177`). ในเวลาเดียวกัน control thread อ่าน counters และ increment `g_pipeline_audit_id` ก่อน dispatch (`src/platform/win32_pipe.zig:139-147`, `src/control/handler_registry.zig:381-410`). ทั้ง pipeline และ control จึงเขียน `g_pipeline_audit_id` พร้อมกันได้ และ `g_pipeline_events_processed`, detections, incident counters, `g_rules_loaded` ถูกอ่านขณะเขียนโดยไม่มี synchronization

ผลที่พิสูจน์ไม่ได้คือ audit/request ID อาจซ้ำหรือหาย, metrics ไม่สอดคล้องกับ forensic audit และ behavior เป็น undefined data race ใน multi-threaded Zig. การใช้ atomic เฉพาะ `g_queue_drops` และ readiness ไม่ครอบคลุม shared state ที่ health/control ใช้เป็น truth

### C-04 — v2 privileged protocol นิยาม nonce/version แต่ active dispatch ไม่ validate และไม่มี replay guard

`src/control/protocol.zig:11-12,247-255` นิยาม `CONTROL_PROTOCOL_VERSION`, `nonce`, `issued_at_ms`, `caller_role` และ request envelope แต่ `handler_registry.dispatch()` อ่านเพียง `command/op` และ `payload` (`src/control/handler_registry.zig:151-179`). ไม่มีการตรวจ `protocol_version`, ไม่มี nonce/replay cache และ request ID จาก envelope ไม่ได้ใช้; server สร้าง `ctx.request_id` จาก global counter (`src/platform/win32_pipe.zig:139-147`). การ auth จาก token ยังดีตรงที่ไม่เชื่อ role ใน JSON แต่ privileged commands (`daemon.shutdown`, `enforcement.block/unblock`, reload/restart contract) ยังสามารถถูกส่งซ้ำโดย process ที่ผ่าน local pipe ACL และ token ได้

นี่เป็น critical control-plane security gap เพราะ protocol ที่ประกาศต่อ caller ไม่ใช่ protocol ที่บังคับใช้จริง และ audit ID ไม่ใช่ request identity จาก caller. ต้องมี version rejection, nonce/request replay semantics และ atomic idempotency policy ก่อนยอมรับ privileged mutation

### C-05 — Bridge spool worker ไม่มี handle ownership/join และ race กับ shutdown

`bridge_init.initAll()` spawn `spoolDrainThread()` แต่เก็บเพียง `g_spool_drain_running: bool` ไม่เก็บ `std.Thread` handle (`src/core/bridge_init.zig:128-145,384-395`). `shutdownAll()` ปิด UDP socketทันที โดยไม่ signal-and-join spool thread (`src/core/bridge_init.zig:417-424`). Worker ยังอ่าน `g_udp_available/g_udp_sock`, ส่ง `sendto`, free message และ requeue ระหว่างที่ shutdown อาจปิด socketแล้ว (`src/core/bridge_init.zig:141-194,333-342`). queued messages ยังไม่ถูก free เมื่อ shutdown และ `g_shutdown` ไม่มี reset สำหรับ generation ใหม่ (`src/core/bridge_init.zig:349-365`)

ผลกระทบคือ data race, lost queued messages, socket use-after-close/undefined native behavior และไม่สามารถพิสูจน์ว่า process shutdown หลัง worker ทั้งหมดหยุดแล้ว แม้ `RuntimeSupervisor` จะ join เฉพาะหก handles ของ daemon (`src/daemon.zig:67-85`)

## Important findings

### I-01 — Lifecycle ที่มี tests ไม่ใช่ lifecycle ที่ daemon ใช้จริง และ runtime commands หลายตัวเป็น NOT_IMPLEMENTED

`src/reliability/lifecycle.zig:131-274` ทำ lifecycle ของ event-fabric/test integration modules และ default profile เป็น `.full` (`lifecycle.zig:62-88`). มัน import `src/tests/integration/*` โดยตรงและไม่ถูกเรียกจาก `src/daemon.zig`; daemon ใช้ local `RuntimeSupervisor` แทน (`src/daemon.zig:51-85`). ใน control handlers `runtime.stop` และ `runtime.restart` จงใจคืน `NOT_IMPLEMENTED` (`src/control/handler_registry.zig:635-651`) ส่วน `runtime.start` เป็นเพียง idempotent assertion ไม่ได้สร้าง worker

ดังนั้น tests ของ lifecycle ไม่ใช่ evidence ของ service lifecycle จริง และคำสั่งที่ protocol contract ประกาศไว้ไม่มี transaction stop/join/start/readiness ใน owner เดียว

### I-02 — RUNNING ถูกเผยแพร่ก่อนยืนยัน worker/data-plane ครบ และ subsystem บางตัวถูก mark running โดยไม่มี proof

Readiness loop รอเพียง pipeline ready, worker failure หรือ timeout 2 วินาที (`src/daemon.zig:441-450`). หลังจากนั้น service status ถูกตั้ง `SERVICE_RUNNING` แม้ Nose/ETW/FIM/registry อาจยังไม่ ready (`src/daemon.zig:456-496`). นอกจากนี้ control และ forensic ถูก `subsystemStarted()` โดยตรงโดยไม่ได้มี readiness probe ของ endpoint/storage (`src/daemon.zig:483-484`). Health operational state ใช้ pipeline เป็นแกนหลัก และรายงาน adapter แยกต่างหาก (`src/control/state_machine.zig:322-350`)

แนวคิด hybrid อาจเป็น policy ที่ตั้งใจ แต่ contract ต้องบอกชัดว่า `RUNNING` หมายถึง control spine เท่านั้น ไม่ใช่ NIDS capture/enforcement readiness. ปัจจุบันชื่อ state และ service SCM state เสี่ยงให้ operator เข้าใจว่า data plane active

### I-03 — Shutdown มี timeout ในเอกสาร แต่ไม่มี bounded join/active-read cancellation ใน daemon

`RuntimeSupervisor.shutdown()` เรียก `join()` ตรง ๆ ทุก worker (`src/daemon.zig:67-85`) โดยไม่มี deadline, escalation หรือ grim-reap. Control server ใช้ blocking `ConnectNamedPipe` และ blocking `ReadFile` (`src/platform/win32_pipe.zig:224-255`). `wakeControlPipe()` ช่วยปลุก connection ที่กำลังรอ accept แต่ไม่รับประกันว่าจะ interrupt `ReadFile` ของ client ที่ต่ออยู่และไม่ส่งข้อมูล (`win32_pipe.zig:260-270`). Tests timeout ฝั่ง Python เป็นเพียง static budget checks (`tests/runtime/test_timeouts.py:20-89`) และไม่ได้วัด join/read cancellation จริง

### I-04 — Rule reload กัน use-after-free ด้วยการ leak automaton ทุก generation และรายงาน success เมื่อโหลดศูนย์

`reloadRules()` swap pointer ภายใต้ mutex แต่ตั้งใจไม่ free `old_ac_ptr` (`src/pipeline/rule_loader.zig:107-126`). จึงปลอดภัยกว่า immediate free แต่ memory โตไม่จำกัดตามจำนวน `rules.reload`. เมื่อ parse/open/build ล้มเหลวหรือได้ศูนย์ จะคง old ruleset แต่คืน `new_count == 0`; handler ตอบ `status:"reloaded"` พร้อมศูนย์ (`src/control/handler_registry.zig:374-379`). นี่ทำให้ caller เข้าใจว่า active rules เป็นศูนย์ทั้งที่ยังใช้ชุดเดิม และไม่มี generation/epoch ใน response

### I-05 — Policy parser เป็น lossy transformation ที่เปลี่ยน semantics ของ config แบบเงียบ

`daemon.zig:246-281` แปลง severity ที่ไม่รู้จักเป็น `.info`, field ที่ไม่รู้จักเป็น `kind`, operator `gte` เป็น `gt` และ parserอ่านเพียง clause/predicate ตัวแรก. Config จริงมี `op:"gte"` และ `op:"in"` (`configs/policies.json:9-20,73-89`) แต่ `in` ไม่ถูก implement ใน branch ดังกล่าว. นี่เปลี่ยน policy behavior โดยไม่ reject malformed/unsupported policy และไม่สอดคล้องกับหลัก fail-closed ของ control plane

### I-06 — Queue ปลอดภัยเชิง reservation แต่ producer ทุกตัวถูก serialize และ drop ไม่มี backpressure/drain contract

`event_queue.zig:26-51` ใช้ producer mutex แก้ปัญหา multi-producer reservation ได้ แต่ throughput ของ ETW/FIM/registry/Nose ถูก serialize ด้วย lock เดียว และ consumer ใช้ mutex อีกตัว (`event_queue.zig:155-166`). Capacity 4096/payload 1500 เป็น fixed limit; full queue เพียง increment drop counter. ไม่มี admission policy ตาม severity/source และ `RuntimeSupervisor` ไม่ drain queue ก่อน join pipeline ดังนั้น shutdown อาจทิ้ง accepted events ขณะ health ยังอ่าน counters ได้ไม่ทัน

### I-07 — Forensic ring มี stale-index semantics ที่อ่าน record ถูก overwrite ได้

`ForensicRing.readRecord()` ตรวจเพียง `index < self.written` แล้วคำนวณ offset modulo storage (`src/forensic/forensic_pipeline.zig:258-268`). หลัง ring wrap ดัชนีเก่าที่ควรถูก reject จะชี้ไป slot ใหม่และคืนสำเนา record อื่นโดยไม่บอกว่า index หมดอายุ. Handler `forensics.show` ยังไม่ implement (`src/control/handler_registry.zig:454-459`) จึงเป็น latent correctness issue แต่ต้องแก้ก่อนเปิด query API

### I-08 — Error path ก่อน control pipe ไม่ publish FAILED/STOPPED ที่สอดคล้องกับ runtime state

ถ้า security self-check fail, `runDaemon()` log แล้ว return `error.SecurityCheckFailed` (`src/daemon.zig:117-123`) ขณะที่ state machine อยู่ `STARTING`; ถ้า resource/config init ล้มเหลวก็ return ผ่าน defer บางส่วนโดยไม่มี transition เป็น `FAILED` หรือ reset subsystem registry (`daemon.zig:137-177,182-313`). Service layer ทำเพียง log และ deferred `SERVICE_STOPPED` (`src/platform/win32_service.zig:77-92`). ผู้ดูแลจึงเห็น process หายไปโดยไม่มี control health endpoint และไม่มี machine-readable startup error ที่ตรงกับ Python error classes

### I-09 — Build configuration ซ่อน missing dependency/config ด้วย `catch ""` และ local verification ทำไม่ได้

`build.zig:116-121` อ่าน test config แล้วแปลงทุก error เป็น empty string; `build.zig:60-75,146-158` ถ้า PEP import/helper ไม่พบเพียงพิมพ์ warning แล้วดำเนิน graph ต่อ. นี่ทำให้ build artifact อาจผ่าน graph แต่ไม่มี dependency ที่ runtime/test ต้องใช้ หรือ fail ช่วง link ช้าเกินไป. ใน execution environment นี้ `zig` ไม่ติดตั้ง จึงไม่มีผล `zig build test` ให้ใช้เป็น evidence และไม่ควรอ้างว่า compile/test ผ่าน

### I-10 — Error JSON ถูกสร้างด้วย string interpolation โดยไม่ escape และมี legacy writer ที่ไม่รองรับ partial write

`handler_registry.errorEnvelope()` ใส่ `code`, `state`, `message` ตรงเข้า JSON (`src/control/handler_registry.zig:67-79`) โดยไม่ใช้ JSON stringifier. ตอนนี้ค่าหลักเป็น controlled literals แต่ future handler หรือ auth reason ที่มาจาก external/native error สามารถทำ response invalid ได้. `platform/win32_pipe.sendResponse()` ก็เขียน `WriteFile` ครั้งเดียวและทิ้ง byte count/error (`src/platform/win32_pipe.zig:119-125`); active dispatch ใช้ `writePipeResponse()` ที่ loop ครบ (`src/control/handler_registry.zig:81-108`) แต่ legacy function ยังคงเป็น compatibility hazard

### I-11 — ไม่มี process mutex/owner epoch แม้ control pipe จำกัดหนึ่ง instance

`CONTROL_PIPE_MAX_INSTANCES=1` ช่วยให้ endpoint ซ้ำชนกัน แต่ไม่ได้บันทึก owner PID, boot generation, binary build marker หรือ lease. `system.health` ส่ง PID ปัจจุบัน แต่ไม่ผูกกับ request/response identity และไม่มี check ว่า client คุยกับ process generation เดิม. ควรเพิ่ม named mutex และ owner record ก่อนรองรับ restart/upgrade ที่มี stale process

## Test และ evidence gaps

1. `zig` ไม่อยู่ใน execution environment (`zig: command not found`) จึงไม่ได้รัน local compile/test. รายงานนี้จงใจไม่เรียก source ว่า buildable หรือ production-ready.
2. `src/all_tests.zig:6-68` เป็น import aggregator และไม่ได้ import active `src/daemon.zig`, `src/control/handler_registry.zig`, `src/platform/win32_pipe.zig`, `src/platform/win32_service.zig`, `src/control/state_machine.zig` หรือ `src/control/health/runtime_health.zig` เป็นชุดทดสอบ runtime/control จริง. การมี test อยู่ในไฟล์ย่อยจึงไม่พิสูจน์ daemon path.
3. `tests/runtime/test_health.py` ตรวจ schema fixture และ mocked `control_api` (`test_health.py:110-260`) แต่ schema ต้องการ `counters`; ไม่มี test ยิง response จริงจาก Zig และไม่มี assertion ว่า payload ของ active `healthJson()` parse ผ่าน schema เดียวกัน.
4. `tests/runtime/test_wire.py` ตรวจ NDJSON envelope `v/kind/src` (`test_wire.py:40-94`) ขณะที่ active named pipe ใช้ `{command,payload}` และ response `{ok,code,state,data,audit_id}`. จึงเป็น protocol contract คนละชุด ไม่ใช่ compatibility evidence ของ `control/protocol.zig`.
5. `tests/runtime/test_states.py` และ `test_timeouts.py` ตรวจตาราง/ค่าคงที่แบบ static (`test_states.py:25-43`, `test_timeouts.py:20-89`) ไม่ได้เรียก `RuntimeState.transition()` หรือ `RuntimeSupervisor.shutdown()` และไม่ได้พิสูจน์ illegal transition, join deadline หรือ pipe wake.
6. Live harness ระบุชัดว่าจะ skip เมื่อไม่ใช่ Windows หรือ binary หาย (`tests/runtime/test_harness_integration.py:45-63`). ไม่พบ evidence artifact ใน repository ที่แสดง successful Windows named-pipe run, token impersonation, shutdown while blocked, duplicate owner หรือ restart generation.
7. ไม่มี test สำหรับ SDDL/ACL และ mapping `TokenElevation -> Role`, malformed/oversized JSON, protocol-version rejection, nonce replay, partial `WriteFile`/`ERROR_MORE_DATA`, multiple clients, handler registry overflow หรือ handler response escaping.
8. ไม่มี concurrent test ครอบคลุม control query พร้อม pipeline mutation, audit ID allocation, rules reload ขณะ match, bridge spool shutdown และ worker failure หลัง readiness. Forensic ring มี concurrent tests บางส่วน (`src/forensic/forensic_pipeline.zig:537-702`) แต่ไม่ครอบคลุม stale index API หรือ daemon shutdown ordering.
9. ไม่มี clean-checkout CI assertion ว่า `git ls-files` ครบทุก import ของ `build.zig`/`all_tests.zig`; untracked source modulesที่พบทำให้ inventory กับ build graph diverge.

## Recommended actions เรียงความสำคัญ

### P0 — ต้องแก้ก่อนยอมรับ production gate

1. **กำหนด canonical runtime owner เพียงชุดเดียว:** ให้ `RuntimeSupervisor` หรือ lifecycle moduleหนึ่งตัวเป็น owner ของ start/stop/restart ทุก worker, bridge spool และ pipe. เพิ่ม process-wide named mutex, owner PID, binary build ID และ generation/epoch. ห้ามให้ `runtime.stop/restart` ตอบ success จน stop, join, cleanup และ readiness ของ generation ใหม่พิสูจน์ได้.
2. **ทำ control protocol v2 ให้ enforce จริง:** parse และ reject version ที่ไม่รองรับ, ใช้ request ID/nonce จาก envelope, เก็บ replay cache แบบ bounded ต่อ privileged command, bind audit กับ caller PID/token/generation และ serialize mutation command. ห้ามเชื่อ `caller_role` จาก JSON; หลักการ token-derived role เดิมให้คงไว้.
3. **แก้ shared state เป็น atomic หรือ snapshot ภายใต้ mutex:** counters, audit/trace/PEP IDs, rules count, incident state และ health fields ต้องมี ownership ชัด. จัดสรร request IDs ด้วย atomic fetch-add เดียว. สร้าง immutable health snapshot เพื่อให้ control อ่าน consistent view.
4. **แก้ shutdown ownership:** เก็บทุก `std.Thread` handle รวม spool thread, signal ทุก flag ที่ worker ใช้, cancel pending overlapped/blocking I/O, join ด้วย deadline, escalate ตาม policy และ free queued messages หลัง worker หยุด. ทำให้ shutdown idempotent และ reset generation state อย่าง explicit.
5. **ซ่อม build provenance:** เพิ่มไฟล์ที่ `all_tests.zig` import ให้ tracked หรือแก้ imports ให้ใช้ tracked paths; เพิ่ม clean-checkout job ที่รัน `git ls-files`, `zig build`, `zig build test` บน Zig version ที่ประกาศ. Missing helper/PEP/config ต้องเป็น hard error สำหรับ production artifact ไม่ใช่ warning/empty fallback.
6. **เลือก health schema เดียว:** ถอด/ย้าย pseudo implementation `control/health/runtime_health.zig` หรือทำให้ compile และเป็น canonical. ทำให้ active `healthJson()` และ Python validator ใช้ schema versionเดียวกัน โดยแยก `control_liveness`, `data_plane_readiness`, `provider_ready`, `host_effect_capable` และ `enforcement_proven` อย่างชัดเจน. `RUNNING` ต้องไม่ถูกอ่านว่า capture/enforcement พร้อมทั้งหมด.

### P1 — แก้ correctness/reliability ต่อเนื่อง

1. เพิ่ม readiness barrier ที่รอ required workers ตาม policy, mark failure เมื่อ worker exit หลัง ready และ publish `FAILED/DEGRADED` พร้อม error code ก่อน service status running.
2. เปลี่ยน `rules.reload` เป็น safe reclamation strategy เช่น stop-the-world สั้น ๆ, epoch/RCU หรือ immutable generations ที่มี bounded retirement; คืนผล `unchanged/failed/activated` พร้อม active generation และไม่รายงาน success เมื่อยังใช้ old rules.
3. ทำ policy parser strict: รองรับทุก operator/clauses ตาม schema หรือ reject policy ทั้งรายการเมื่อ unsupported; ห้าม map unknown/gte/in เป็น semantics อื่นเงียบ ๆ.
4. เพิ่ม bounded read/write timeout และ overlapped/cancelable control server; ใช้ JSON serializer ทุก error/result; ลบหรือแยก legacy writer ที่ไม่ตรวจ partial write.
5. กำหนด queue backpressure/drop policy, drain budget และ counters แบบ atomic. เพิ่ม overload tests ที่วัด latency, drops และ shutdown loss.
6. แก้ forensic ring ให้ตรวจ retained range (`oldest <= index < written`), ส่ง `record_seq`/generation ให้ caller และ reject stale index; เปิด query handler ต่อเมื่อมี authorization และ evidence ครบ.

### P2 — เพิ่มหลักฐานก่อน release

1. เพิ่ม Windows integration tests จริงสำหรับ SDDL/token role, one-instance owner, message framing, `ERROR_MORE_DATA`, partial writes, malformed payload, replay, client disconnect, shutdown ระหว่าง read/connect และ worker join.
2. เพิ่ม stress/race tests สำหรับ control + pipeline + reload และรันด้วย sanitizer/race-capable configuration ที่เหมาะกับ Zig/Windows; ตรวจ duplicate audit/PEP IDs และ monotonicity.
3. เพิ่ม test ที่ build จาก clean clone เท่านั้น และเก็บ artifact manifest ที่มี source commit, Zig version, PEP/helper ABI versions, DLL hashes และ active control protocol version.
4. เพิ่ม evidence report ของ startup-failure, partial-init rollback, bridge unavailable, PEP unavailable, queue full, forensic ring wrap และ service stop โดยไม่ใช้ netsh/legacy bookkeeping เป็น proof ของ enforcement.

## References

[1]: ../src/daemon.zig "Active Zig daemon orchestration and worker supervisor"
[2]: ../src/platform/win32_pipe.zig "Windows control named-pipe server and token boundary"
[3]: ../src/control/handler_registry.zig "Control dispatch, handlers, response serialization and shutdown request"
[4]: ../src/control/protocol.zig "Control protocol v2 command and envelope declarations"
[5]: ../src/control/state_machine.zig "Active runtime state machine and health JSON"
[6]: ../src/pipeline/runtime_state.zig "Shared worker readiness and runtime counters"
[7]: ../src/pipeline/event_queue.zig "Bounded pipeline queue and producer/consumer synchronization"
[8]: ../src/pipeline/event_processor.zig "Detection, policy, PEP and forensic processing loop"
[9]: ../src/core/bridge_init.zig "Cross-language bridge initialization and shutdown"
[10]: ../src/reliability/lifecycle.zig "Separate lifecycle implementation and lifecycle tests"
[11]: ../src/forensic/forensic_pipeline.zig "Forensic ring ownership, integrity and wrap behavior"
[12]: ../build.zig "Zig executable/test build graph and external dependencies"
[13]: ../tests/runtime/test_health.py "Python health schema and mocked control API tests"
[14]: ../tests/runtime/test_wire.py "Python NDJSON runtime-contract wire tests"
[15]: ../tests/runtime/test_harness_integration.py "Platform-gated live runtime harness"
[16]: ../tools/aegisctl/api/control_api.py "Python named-pipe client and control response handling"
[17]: ../configs/policies.json "Runtime policy configuration loaded by daemon"
[18]: ../src/all_tests.zig "Tracked Zig test aggregator and import graph"

**Audit disposition:** Critical findings C-01 through C-05 block a production-readiness claim. Important findings I-01 through I-11 require remediation or explicit documented acceptance with runtime evidence; source comments and static contract tests alone are insufficient evidence.
วิเคราะห์ตาม source จริงและไม่แก้ไข source code
 /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/analysis/deep_audit/01-runtime-zig.md
