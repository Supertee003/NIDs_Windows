# วิเคราะห์ Zig runtime และ lifecycle ของ AEGIS NIDS Windows

**ขอบเขต:** `src/main.zig`, `src/daemon.zig`, `src/control`, `src/platform`, `src/pipeline`, `src/reliability` และเอกสาร runtime/architecture ที่เกี่ยวข้อง  
**Source HEAD ที่ตรวจ:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**หมายเหตุ commit map:** ค่า `688ab...` ถูกถือเป็น stale ตามคำสั่งงาน ไม่ใช้เป็นฐานสรุปผล  
**วิธีอ่านหลักฐาน:** รายงานแยกสิ่งที่พิสูจน์ได้จาก source แบบ static ออกจาก runtime proof ที่ต้องรันบน Windows ซึ่งการวิเคราะห์นี้ยังไม่ได้ทำ

## สรุปผล

Runtime ที่ถูก build จริงมี production entry point เดียวคือ `src/main.zig` ตาม `build.zig` แต่ lifecycle implementation ที่ใช้งานจริงไม่ได้เป็น `src/reliability/lifecycle.zig` ตามเอกสารเดิม หากเป็นเส้นทาง `main -> platform/win32_service.mainEntry -> daemon.runDaemon` แล้ว `daemon` สร้าง worker และให้ main thread serve control pipe การมี `RuntimeSupervisor` ใน `daemon.zig` ทำให้การเก็บ handle และ `join()` ของ worker หลักชัดเจนขึ้นกว่ารุ่นเก่า อย่างไรก็ตาม state machine, readiness, reliability watchdog และ shutdown contract ยังไม่รวมเป็น authority เดียวกัน

Startup มี bounded wait 2 วินาทีและใช้ acquire/release flags ซึ่งเป็นหลักฐาน static ว่ามี handshake ขั้นพื้นฐาน แต่ readiness ไม่ได้ผูกกับ control-pipe bind จริง และระบบตั้ง runtime state เป็น `RUNNING` กับ SCM service status เป็น `SERVICE_RUNNING` ก่อน `CreateNamedPipeW` สำเร็จ การตั้ง `g_runtime.system_state = .stopped` ใน handler ของ `daemon.shutdown` ก็เกิดก่อน supervisor จะหยุดและ join worker จริง จึงมีช่วงที่ status บอกหยุดแล้วแต่ worker ยังทำงานอยู่ นอกจากนี้การหยุดจาก SCM ไม่เปลี่ยน state machine เป็น `STOPPING` หรือ `STOPPED` เลย

ความเสี่ยง concurrency ที่สำคัญที่สุดคือ `event_queue.pushEvent()` มี producer หลาย thread แต่ไม่มี mutex หรือ CAS ตอนจอง `g_queue_head`; mutex มีเฉพาะฝั่ง pop จึงยังพิสูจน์ไม่ได้ว่า queue ปลอด race เมื่อ sensor, Nose, ETW, FIM และ registry ส่งพร้อมกัน อีกประเด็นคือ daemon join producer ทั้งหมดก่อน join pipeline และ pipeline loop ออกจากลูปทันทีเมื่อเห็น stop flag โดยไม่ drain queue ที่ค้างอยู่ ทำให้ shutdown ไม่สอดคล้องกับเอกสารที่กำหนด stop accepting -> drain -> flush

Reliability ส่วนใหญ่เป็น framework ที่ถูกเรียกใช้เพียงบางส่วน: watchdog ลงทะเบียนชื่อ thread แต่มีเฉพาะ pipeline ที่ heartbeat และไม่พบ call site ของ `check()` ในเส้นทาง daemon; `src/reliability/lifecycle.zig` และ aggregate reliability framework ไม่ได้อยู่ใน call graph ของ executable นี้ ขณะที่ `SecurityCheck` ใน source ปัจจุบันเป็น hard-coded pass ทุก check จึงเป็น static framework ไม่ใช่ runtime proof ของ hardening

## Call graph และเส้นทาง runtime จริง

### Build และ process entry

`build.zig:14-21` สร้าง executable `aegis_nids` จาก `src/main.zig` ดังนั้น `src/main.zig` เป็น root ที่ compile จริงของ production executable (`build.zig:57`). `main()` จัดสรร process arguments และจบก่อน startup หากพบ `--version` หรือ `-v` (`src/main.zig:20-30`). เส้นทางปกติคือ `service.mainEntry()` (`src/main.zig:33-35`).

บน Windows `mainEntry()` เรียก `StartServiceCtrlDispatcherW()` พร้อม service table และ `serviceMain()` (`src/platform/win32_service.zig:94-107`). หาก dispatcher สำเร็จ SCM จะเรียก `serviceMain()`, ซึ่ง register handler, ตั้ง `SERVICE_START_PENDING`, เรียก `daemon.runDaemon()` และสุดท้ายตั้ง `SERVICE_STOPPED` ผ่าน `defer` (`src/platform/win32_service.zig:77-92`). หาก dispatcher ไม่ได้เชื่อมต่อกับ SCM โปรแกรม fallback ไป console/foreground mode และ propagate error จาก `runDaemon()` (`src/platform/win32_service.zig:109-126`). นี่คือ static call graph ที่ตรงกับ production entrypoint; ยังไม่มี runtime proof ว่า service table/SCM dispatch ทำงานบน Windows ใน build ปัจจุบัน

### Startup order ใน `runDaemon()`

ลำดับจริงของ `src/daemon.zig` คือ:

1. ติดตั้ง stderr diagnostic sink และ log startup context (`src/daemon.zig:85-101`).
2. เปลี่ยน global runtime state เป็น `STARTING`, register subsystems `zig`, `go`, `cpp`, `rust_pep`, `tier3`, `control`, `forensic` และ mark Zig started (`src/daemon.zig:103-112`).
3. รัน `SecurityCheck.run()`; ถ้าไม่ผ่าน return `error.SecurityCheckFailed` (`src/daemon.zig:114-125`).
4. Probe capability manifest และ publish capability (`src/daemon.zig:127-132`).
5. สร้าง arena, forensic ring, watchdog, performance tracker และ fault injector (`src/daemon.zig:134-146`).
6. สร้าง Aho-Corasick บน heap, load `configs/Rules.json`, expose `state.g_active_ac`, และ load policies จาก `configs/policies.json` (`src/daemon.zig:148-298`).
7. สร้าง anomaly detector, flow table, threat tracker, PEP, Tier-3 state และ action dispatcher (`src/daemon.zig:300-329`).
8. Register watchdog entries สำหรับ pipeline, capture, ETW, FIM และ registry (`src/daemon.zig:331-336`).
9. สร้าง Windows adapter objects และเข้าสู่ Windows branch (`src/daemon.zig:339-353`).
10. `bridge_init.initAll()` เริ่ม WFP/C++/UDP และอาจเริ่ม spool-drain thread (`src/daemon.zig:354-360`, `src/core/bridge_init.zig:367-415`).
11. Reset readiness/failure flags สำหรับ generation นี้ (`src/daemon.zig:363-373`).
12. Spawn worker ตามลำดับ sensor -> pipeline -> Nose reader -> ETW -> FIM -> registry (`src/daemon.zig:375-425`).
13. รอ `g_pipeline_ready` หรือ failure flag สูงสุด 2,000 ms (`src/daemon.zig:427-437`).
14. Publish subsystem states, transition system เป็น `RUNNING` หรือ `DEGRADED`, และตั้ง `SERVICE_RUNNING` (`src/daemon.zig:439-476`).
15. Serve control pipe บน main thread จน shutdown (`src/daemon.zig:478-482`).
16. `RuntimeSupervisor.shutdown()` ทำ stop signal และ join เมื่อ scope จบ (`src/daemon.zig:360-361`, `src/daemon.zig:67-82`).
17. หลัง worker join แล้ว defer อื่น ๆ deinit bridge, ring, AC, policy และ allocator ตามลำดับ LIFO (`src/daemon.zig:135-153`, `src/daemon.zig:357-362`).

Non-Windows branch ไม่สร้าง worker หรือ control pipe แต่เรียก `processor.pipelineLoop()` บน main thread (`src/daemon.zig:483-487`). เนื่องจาก `pipelineLoop()` จะตั้ง readiness และวนรอ queue จน stop flag แต่ไม่มี control path ใน branch นี้ จึงเป็น test mode ที่อาจไม่จบเองโดยไม่มี external state mutation

## Worker creation และ ownership

`RuntimeSupervisor` เป็น owner ของ handles หกตัว ได้แก่ `pipeline`, `sensor`, `nose_reader`, `etw`, `fim`, `registry` (`src/daemon.zig:51-60`). `requestStop()` เขียน `g_stop_requested` ด้วย release และเรียก `bridge_init.requestShutdown()` (`src/daemon.zig:62-65`). `shutdown()` เรียก `requestStop()` ซ้ำได้ แล้ว join reverse startup order และ set handle เป็น null ทุกตัว (`src/daemon.zig:67-82`). จาก static source พบว่า handle ที่ supervisor ถือถูก join ครั้งเดียวใน normal scope และ `defer supervisor.shutdown()` ครอบคลุม return/error path หลังสร้าง supervisor แล้ว

Worker แต่ละตัวมี ownership และ stop semantics ดังนี้:

- **Legacy sensor:** `legacy_capture.capture_packets` ถูก spawn (`src/daemon.zig:375-381`) และ loop ใช้ `bridge_init.g_shutdown` ไม่ใช่ `g_stop_requested` (`src/core/nids_capture.zig:200-203`). `requestStop()` เรียก `bridge_init.requestShutdown()` จึงเชื่อม signal ได้ แต่ source มี dual global shutdown state
- **Pipeline:** `processor.pipelineLoop` ถูก spawn พร้อม pointer ไปยัง `ac`, `ad`, `ft`, `tt`, `ps`, `pep_enf`, `forensic_ring` ซึ่งทั้งหมดเป็น local objects ของ `runDaemon()` และถูก deinit หลัง supervisor join (`src/daemon.zig:383-390`, `src/pipeline/event_processor.zig:205-252`). ownership ระหว่าง run ถูกต้องตาม scope แต่ global queue และ counters ไม่ได้ encapsulate ใน supervisor
- **Nose reader:** `runPipeReaderLoop(&state.g_stop_requested)` สร้าง `\\.\pipe\aegis_nose`, ตั้ง ready หลัง create server และปิด handleด้วย defer (`src/daemon.zig:400-405`, `src/capture/nose_pipe_reader.zig:143-152`)
- **ETW/FIM/registry:** แต่ละตัวตั้ง ready หลัง native initialization สำเร็จและ clear ready ก่อน return (`src/pipeline/telemetry_threads.zig:19-52`, `:85-116`, `:119-159`).
- **Direct Zig Npcap:** ไม่ถูก spawn ใน daemon ปัจจุบัน แม้ `packet_callback.zig` และเอกสาร audit รุ่นก่อนยังมี path นี้อยู่ (`src/daemon.zig:392-398`). เอกสาร `DEEP_AUDIT_RUNTIME_CONVERGENCE_2026-09-15.md` ยืนยันว่าการปิด direct Npcap เป็น remediation ของ HEAD แต่ runtime proof ของ executable ใหม่ยังต้อง build/run จริง
- **Bridge spool thread:** `bridge_init.initAll()` อาจ spawn `spoolDrainThread` แต่ไม่เก็บ `std.Thread` handle ที่ใช้งานได้ใน supervisor (`src/core/bridge_init.zig:384-395`). จึงอยู่นอก ownership/join contract ของ daemon

## Readiness และ state transitions

### Worker flags

`runtime_state.zig` ประกาศ atomic flags `g_pipeline_ready`, `g_sensor_ready`, `g_nose_ready`, `g_etw_ready`, `g_fim_ready`, `g_registry_ready`, รวม `g_worker_failed` และ failure mask (`src/pipeline/runtime_state.zig:15-50`). การใช้ release ตอน publish และ acquire ตอน wait/read เป็นหลักฐาน static ว่าพยายามสร้าง happens-before สำหรับ readiness

อย่างไรก็ดี readiness semantics ไม่เท่ากันทุก worker:

- pipeline ตั้ง ready ทันทีเมื่อเข้าฟังก์ชัน ก่อน process event ใด ๆ (`src/pipeline/event_processor.zig:216-218`)
- Nose ตั้ง ready เมื่อ named pipe server ถูกสร้าง ไม่ใช่เมื่อ Go client เชื่อมต่อหรือมี frame (`src/capture/nose_pipe_reader.zig:143-168`)
- ETW/FIM/registry ตั้ง ready หลัง native adapter start สำเร็จ (`src/pipeline/telemetry_threads.zig:31-45`, `:95-103`, `:137-144`)
- sensor ตั้ง ready หลัง named pipe/security/event setup สำเร็จ (`src/core/nids_capture.zig:137-184`)

ดังนั้น `pipeline_ready=true` หมายถึง loop เริ่มแล้ว ไม่ได้หมายถึง first healthy event ตาม `docs/runtime/LIFECYCLE.md:104-117` และ `docs/runtime/RUNTIME_CONTRACT.md:71-85`. Runtime ปัจจุบันไม่เคยใช้ system state `.ready` เป็น transient stage; daemon transition จาก `.starting` ไป `.running` หรือ `.degraded` โดยตรง (`src/daemon.zig:470-475`).

### Startup timeout และ false readiness

Wait loop หยุดเมื่อ worker ใด ๆ set `g_worker_failed` หรือครบ 2 วินาที (`src/daemon.zig:430-437`). เมื่อครบ timeout โดยไม่มี failure ก็ยังเดินหน้าตั้ง service running; ไม่มีการสร้าง timeout failure kind แยกต่างหาก และไม่มีการยืนยันว่า pipeline ยังมีชีวิตอยู่ หาก pipeline thread เข้าฟังก์ชันแล้ว set ready จากนั้น return ด้วยเหตุอื่น flag จะถูก clear โดย defer แต่ไม่มี `markWorkerFailure()` (`src/pipeline/event_processor.zig:216-245`). Static code จึงยังไม่พิสูจน์ว่า “startup timeout” หรือ “unexpected worker exit” ถูกยกระดับเป็น `FAILED`

### Runtime state machine

`state_machine.zig` นิยาม states `stopped`, `starting`, `ready`, `running`, `degraded`, `recovering`, `stopping` (`src/control/state_machine.zig:19-47`) และ subsystem states รวม `failed/degraded` (`src/control/state_machine.zig:63-85`). แต่ `transition()` รับ state ใดก็ได้โดยไม่มี legal-transition guard (`src/control/state_machine.zig:226-234`). `recomputeHealth()` เปลี่ยน `running -> degraded` หรือ `degraded -> recovering` ได้ แต่ไม่พบการเรียกใน daemon/control path ที่ตรวจ (`src/control/state_machine.zig:236-251`).

State sequence ที่เกิดจริงใน daemon คือ `STOPPED(default) -> STARTING -> RUNNING|DEGRADED`; ไม่มี `.ready`, `.stopping`, `.recovering` หรือ `.failed` system transition ใน path นี้ (`src/daemon.zig:103-112`, `:470-475`). `daemon.shutdown` เขียน `.stopped` โดยตรงใน handler (`src/control/handler_registry.zig:552-570`) ก่อน worker join ส่วน SCM stop ไม่แก้ `g_runtime.system_state` เลย (`src/platform/win32_service.zig:64-72`). จึงมี state authority สองแบบ: control shutdown เปลี่ยน state ก่อน teardown แต่ service stop เปลี่ยนเพียง atomic flags และ SCM status

Subsystem `.control` ถูก mark started ก่อน `serveWindowsPipe()` bind endpoint (`src/daemon.zig:463-464`, `:478-480`) และ `.go` ถูก mark startedจาก `g_nose_ready` ซึ่งหมายถึง pipe server create ไม่ใช่ Go process/client readiness (`src/daemon.zig:443-447`, `src/capture/nose_pipe_reader.zig:150-168`). นี่ทำให้ status อาจประกาศ subsystem running ก่อน dependency/endpoint พร้อมจริง

## Control pipe lifecycle

`serveWindowsPipe()` initialize handler registry, allocates a function-lifetime arena, converts `\\.\pipe\aegis_control` เป็น UTF-16 และเรียก `CreateNamedPipeW` แบบ message mode, single instance, 64 KiB buffers (`src/platform/win32_pipe.zig:150-189`). หลังสร้าง handle แล้ว log ว่า pipe ready และ loop `ConnectNamedPipe` จน `g_stop_requested` เป็น true (`src/platform/win32_pipe.zig:191-224`).

ต่อ connection จะ allocate `conn_arena`, `ReadFile` หนึ่ง message, dispatch ผ่าน `handler_registry.dispatch`, flush response, disconnect และ sleep 20 ms (`src/platform/win32_pipe.zig:202-223`). Protocol dispatch parse envelope, map `command/op`, authorize จาก local role, call handler, audit และ write response (`src/control/handler_registry.zig:138-249`). Local role ถูก hard-code เป็น `.operate` (`src/control/authorization.zig:25-49`), ดังนั้น local caller อ่านและ reload ได้ แต่ shutdown/runtime stop ต้อง privileged ตาม contract (`src/control/protocol.zig:187-190`, `:229-231`). อย่างไรก็ตาม pipe creation ใช้ default OS security descriptor เพราะ `lpSecurityDescriptor=null` (`src/platform/win32_pipe.zig:159-179`); source ไม่ได้พิสูจน์ caller identity จริง จึงไม่เท่ากับ admin-only ACL

`daemon.shutdown` ตอบ success แล้วคืน `.shutdown=true`; control server flush/disconnect ก่อน break และ supervisor ทำ stop/join ต่อ (`src/control/handler_registry.zig:225-248`, `src/platform/win32_pipe.zig:214-224`). เส้นทางนี้มี ordering ที่ดีตรง response ถูกส่งก่อน process exit แต่ state ถูกประกาศ stopped ก่อน postcondition จริง จึงเป็นเพียง protocol acknowledgement ไม่ใช่ verified stop completion

`runtime.start` เป็น idempotent assertion เมื่อ state running/ready แต่ไม่สร้าง worker; ใน state อื่นคืน `RUNTIME_NOT_READY` (`src/control/handler_registry.zig:511-531`). `runtime.stop` และ `runtime.restart` คืน `NOT_IMPLEMENTED` เพราะไม่มี supervisor transaction ที่ handler เรียกได้ (`src/control/handler_registry.zig:534-550`). เอกสาร lifecycle ระบุ start/stop/restart และ restart backoff เป็น contract (`docs/runtime/LIFECYCLE.md:131-154`, `docs/runtime/RUNTIME_CONTRACT.md:171-201`) แต่ control implementation ปัจจุบันไม่ทำตามครบ

### Pipe wake และ SCM stop

SCM handler store `g_stop_requested`, เรียก `bridge_init.requestShutdown()`, ตั้ง `SERVICE_STOP_PENDING` และเรียก `wakeControlPipe()` (`src/platform/win32_service.zig:64-72`). `wakeControlPipe()` เปิด client handle ไปยัง control pipe เพื่อปลุก `ConnectNamedPipe` ที่ block (`src/platform/win32_pipe.zig:227-237`). Static evidence พิสูจน์เฉพาะความตั้งใจและ call path; ไม่พิสูจน์ว่า wake สำเร็จทุก race window โดยเฉพาะกรณี server กำลัง block ที่ `ReadFile` ของ connection อื่น เพราะไม่มี cancellation/overlapped I/O ใน control pipe

## Shutdown และ teardown

### Normal control shutdown

1. Client ส่ง `daemon.shutdown`.
2. Handler ตั้ง global runtime state เป็น `.stopped`, reset uptime, store `g_stop_requested=true`, เรียก `bridge_init.requestShutdown()` (`src/control/handler_registry.zig:552-570`).
3. Dispatch ส่ง response และ serve loop flush/disconnect/break (`src/control/handler_registry.zig:225-248`, `src/platform/win32_pipe.zig:214-224`).
4. `supervisor.requestStop()` ถูกเรียกหลัง serve return และ defer shutdown เรียกซ้ำ (`src/daemon.zig:478-482`, `src/daemon.zig:67-68`).
5. Supervisor join registry -> FIM -> ETW -> Nose -> sensor -> pipeline (`src/daemon.zig:69-81`).
6. หลัง worker join bridge shutdown และ local resources deinit (`src/core/bridge_init.zig:417-424`, `src/daemon.zig:135-153`).

ขั้นตอนนี้ไม่มี queue drain. Pipeline loop condition ตรวจ stop flag ก่อน pop และออกเมื่อ stop เป็น true (`src/pipeline/event_processor.zig:220-245`); supervisor join producers ก่อน pipeline จึงมี event ที่ค้างใน queue แล้วถูกทิ้งเมื่อ pipeline ออก เอกสาร failure model ระบุว่าควร stop accepting, drain queue, flush forensics, close handles (`docs/architecture/failure-model.md:115-128`) แต่ implementation ไม่ทำ drain/flush transaction ดังกล่าว

### SCM stop

SCM stop ไม่ผ่าน `daemon.shutdown` handler; มันตั้ง flags และปลุก pipe แล้ว `serveWindowsPipe()` ออกจาก loop เมื่อเห็น stop (`src/platform/win32_service.zig:64-72`, `src/platform/win32_pipe.zig:191-224`). `runDaemon()` จึง return และ `serviceMain` defer ตั้ง `SERVICE_STOPPED` (`src/platform/win32_service.zig:87-91`). ไม่มี explicit runtime state transition และ service error code ไม่ถูกตั้งเมื่อ `runDaemon()` จบด้วย error เพราะ `serviceMain` catch เพียง log (`src/platform/win32_service.zig:89-91`)

### Ownership gap: bridge spool thread

`spoolDrainThread()` ใช้ `g_shutdown`, `g_udp_available`, `g_udp_sock` และ queue lock; `initAll()` spawn thread แต่ทิ้ง handle (`src/core/bridge_init.zig:138-195`, `:384-395`). `shutdownAll()` ปิด UDP socketทันทีโดยไม่ join spool thread (`src/core/bridge_init.zig:417-424`). แม้ supervisor จะ set shutdown flag ก่อนใน normal daemon path แต่ thread อาจกำลังใช้ socketหรือกำลังตื่นจาก sleep ขณะ `shutdownUdpBrain()` close/null ค่า จึงยังมี TOCTOU/data race และไม่มี guarantee ว่า spool messages ถูก free หรือ drain ก่อน allocator/resource teardown

## Pipeline, queue และ race analysis

### Actual ingress paths

Production daemon ปัจจุบัน spawn legacy sensor และ canonical Go Nose reader พร้อม host telemetry (`src/daemon.zig:375-425`). Direct Zig Npcap ถูกปิดไม่ให้ spawn (`src/daemon.zig:392-398`). Legacy sensor (`aegis_sensor_pipe`) และ Nose (`aegis_nose`) จึงเป็นคนละ pipe และยังเป็น acquisition concepts สองชุด แม้ network canonical authority จะถูกกำหนดให้ Nose ในคอมเมนต์และเอกสาร audit (`docs/DEEP_AUDIT_RUNTIME_CONVERGENCE_2026-09-15.md:16-33`).

### Queue producer race

`event_queue.zig` มี static array 4096 entry และ atomic head/tail (`src/pipeline/event_queue.zig:11-25`). `pushEvent()` โหลด head/tail, ตรวจเต็ม, เขียน slot ที่ `head % size`, แล้ว store head+1 (`src/pipeline/event_queue.zig:27-43`). ไม่มี mutex/CAS รอบการ reserve head. ขณะเดียวกัน producers หลายตัวเรียก `pushEvent()` ได้แก่ Nose (`src/capture/nose_pipe_reader.zig:244-253`), legacy sensor (`src/core/nids_capture.zig:283-298`), ETW/FIM/registry (`src/pipeline/telemetry_threads.zig:75-80`, `:104-112`, `:146-155`) และ diagnostic Npcap path (`src/pipeline/packet_callback.zig:80-83`). `g_queue_mutex` ถูก lock เฉพาะ `popEvent()` (`src/pipeline/event_queue.zig:91-101`). Static evidence จึงชี้ชัดถึง multi-producer reservation race; ยังไม่มี runtime stress proof หรือ TSan-equivalent proof มาหักล้าง

### Shared counters and pointer races

หลาย global counter เป็น plain `u64`, `u32` หรือ `bool` และถูกเขียนจาก worker แล้วอ่านจาก control handler โดยไม่มี atomic/mutex เช่น `g_pipeline_events_processed`, `g_pipeline_detections`, `g_pipeline_policies_matched`, `g_forensic_records_written`, `g_queue_drops`, `g_last_event_ms` (`src/pipeline/runtime_state.zig:69-105`, `src/pipeline/event_processor.zig:49-51`, `:126-129`, `:147-148`, `:175-199`, `src/control/handler_registry.zig:380-406`). บน Windows x64 การอ่าน aligned 64-bit มักไม่ฉีก แต่ Zig memory model ยังไม่ให้ data-race correctness จาก alignment เพียงอย่างเดียว

`g_pipeline_audit_id` ถูก increment จากทั้ง control request context และ pipeline processing (`src/platform/win32_pipe.zig:138-146`, `src/pipeline/event_processor.zig:175-178`) โดยไม่มี synchronization จึงอาจเกิด lost update หรือ duplicate audit IDs. `g_active_ac` ใช้ mutex ตอน swap และ snapshot (`src/pipeline/rule_loader.zig:107-121`, `src/pipeline/event_processor.zig:84-90`); old automata ไม่ถูก destroy เพื่อหลีกเลี่ยง UAF ซึ่งลด lifetime race ได้ แต่แลกกับ intentional leak ตลอด daemon lifetime และไม่มี reclamation protocol

`RuntimeState.statusJson()` และ `healthJson()` lock เพียงตอน copy scalar/slice แล้ว unlock ก่อน iterate shared `subsystems` slice (`src/control/state_machine.zig:264-285`, `:288-337`). ฝั่ง subsystem mutation ใช้ mutex (`src/control/state_machine.zig:148-210`) แต่ JSON serialization อ่าน entries หลัง unlock จึงยังมี unsynchronized concurrent reads/writes ใน status path

## Reliability และ failure semantics

### Watchdog

Daemon ใช้ `src/reliability/watchdog.zig` จริงและสร้าง global watchdog (`src/daemon.zig:141-143`). มัน register indices pipeline, capture, ETW, FIM, registry (`src/daemon.zig:331-336`). แต่ `pipelineLoop()` ได้ `wd_idx=0` และ beat เฉพาะ pipeline (`src/pipeline/event_processor.zig:213-227`). ไม่พบ worker code ที่ใช้ index ของ capture/ETW/FIM/registry และไม่พบ daemon loop ที่เรียก `ReliabilityWatchdog.check()`; ใน watchdog source `check()` สร้าง alert/restarts counter แต่ไม่มี restart action (`src/reliability/watchdog.zig:85-117`). ดังนั้น watchdog เป็น static utility และ pipeline heartbeat มากกว่าระบบ supervision/restart ที่พิสูจน์แล้ว

### Security self-check

`SecurityCheck.run()` ถูกเรียกก่อน capability/worker startup และ fail-closed ใน `runDaemon()` หาก `passed=false` (`src/daemon.zig:114-125`). แต่ checkDep, checkAslr, checkCfg, high entropy ASLR, signed binary และ non-elevated ล้วนตั้ง `.passed=true` โดยตรงหรือมีเพียง comment ว่า real implementation จะทำภายหลัง (`src/reliability/security_check.zig:36-94`). จึงสรุปได้เพียงว่ามี gate call site ไม่ใช่ proof ว่า DEP/ASLR/CFG/signature/elevation ถูกตรวจจริง

### Fault injection และ performance

`state.g_fi` ถูก initialize จาก environment และ pipeline เรียก `maybeDrop()`/`maybeCorrupt()` (`src/daemon.zig:145-146`, `src/pipeline/event_processor.zig:223-235`). นี่เป็น integration จริงระดับหนึ่ง แต่ไม่ใช่ full fault matrix recovery. `g_perf` ถูก observe ใน pipeline (`src/pipeline/event_processor.zig:235-241`) แต่ไม่มี lifecycle impact หรือ threshold-to-degraded path. `src/reliability/fault_matrix.zig` เป็น declarative matrix/drill runner และ `src/reliability/lifecycle.zig` เป็น separate start/run/shutdown framework; ไม่มี evidence ว่าถูกเรียกจาก production `main -> daemon` path

## Static evidence กับ runtime proof

### Static evidence ที่ยืนยันได้จาก HEAD

- Build root คือ `src/main.zig`; service/console dispatch ลง `daemon.runDaemon()`
- `RuntimeSupervisor` ถือและ join worker handles หกตัวใน reverse order
- readiness flags เป็น atomics และ worker หลักตั้ง/clear flag ตาม source ที่ระบุ
- production daemon ปิด direct Zig Npcap spawn และใช้ Go Nose เป็น canonical network ingress ตาม comment/current source
- control protocol dispatch มี authorization, audit, response flush และ `daemon.shutdown` signal path
- `runtime.stop`/`runtime.restart` ยัง `NOT_IMPLEMENTED`
- event queue มี producer หลายตัวแต่ push ไม่มี producer serialization
- watchdog `check()` ไม่มี integration ที่พิสูจน์ได้จาก daemon path และ non-pipeline threads ไม่ heartbeat
- bridge spool thread ไม่มี handle/join ใน `RuntimeSupervisor`
- state transition implementation ไม่ validate legal transitions และ state shutdown ordering ไม่ตรง contract

### Runtime proof ที่ยังไม่มีในการตรวจนี้

การวิเคราะห์นี้ไม่ได้รัน Windows executable, SCM, named pipes, Npcap, ETW/FIM/registry helper, Rust PEP หรือ C++ bridge ดังนั้นยังไม่มีหลักฐาน runtime ว่า:

1. `StartServiceCtrlDispatcherW` เรียก `serviceMain()` ได้จริงด้วย service table ปัจจุบัน
2. `CreateNamedPipeW` control endpoint bind สำเร็จและ `wakeControlPipe()` ปลุก blocking state ได้ในทุกกรณี
3. readiness 2 วินาทีสอดคล้องกับเวลาจริงของ worker/native adapters
4. Nose frame ผ่าน validation -> queue -> pipeline -> forensic ใน executable ที่ build จาก HEAD นี้
5. multi-producer queue race เกิดจริงภายใต้ load หรือไม่ และ loss rate เท่าใด
6. shutdown จาก control และ SCM join worker ครบทุกครั้ง รวม bridge spool thread
7. service status และ health JSON มีค่าตรงกับ process/worker state หลัง failure จริง
8. watchdog alert/restart หรือ fault injection recovery ทำงานจริง

เอกสาร `docs/DEEP_AUDIT_RUNTIME_CONVERGENCE_2026-09-15.md` มี historical claims ว่าเคยพิสูจน์ Go Nose -> Zig submission และพบ duplicate direct Npcap path (`:138-150`) แต่ claim เหล่านี้เป็นเอกสารประกอบ ไม่ใช่ runtime run ที่ทำซ้ำในการวิเคราะห์ HEAD `46b93dc` และไม่ควรยกเป็น proof ใหม่โดยไม่มี binary/log artifact ที่ผูกกับ commit นี้

## Risks ที่จัดลำดับ

| ระดับ | ความเสี่ยง | หลักฐาน static | ผลกระทบ |
|---|---|---|---|
| Critical | Multi-producer queue head race | `src/pipeline/event_queue.zig:27-43`, producers หลายตัวจาก `src/pipeline/telemetry_threads.zig`, `src/capture/nose_pipe_reader.zig`, `src/core/nids_capture.zig` | event overwrite, lost event, corruption หรือ false queue-full state |
| High | Shutdown ไม่ drain queue | `src/pipeline/event_processor.zig:220-245`, supervisor join producers ก่อน pipeline `src/daemon.zig:69-81` | events ที่รับแล้วแต่ค้าง queue หาย; forensic ไม่ครบ |
| High | Bridge spool thread ไม่ถูก join | `src/core/bridge_init.zig:384-395`, `:417-424` | use-after-close/TOCTOU กับ UDP socket, leaked queued messages, nondeterministic exit |
| High | State STOPPED ถูก publish ก่อน join | `src/control/handler_registry.zig:552-570` | operator/health เห็น stopped ขณะ worker ยังประมวลผล |
| High | SCM stop ไม่ update runtime state | `src/platform/win32_service.zig:64-72` | SCM status กับ internal state diverge; recovery/status semantics ไม่น่าเชื่อถือ |
| High | `SERVICE_RUNNING` และ control subsystem marked ก่อน pipe bind | `src/daemon.zig:463-480` | supervisor/CLI race เห็น ready แต่ endpoint ยัง unavailable |
| Medium | Plain shared counters และ audit ID races | `src/pipeline/runtime_state.zig:69-105`, `src/platform/win32_pipe.zig:138-146`, `src/pipeline/event_processor.zig:175-178` | metrics/audit IDs ไม่ deterministic และ data-race undefined behavior |
| Medium | Watchdog ไม่ได้ supervise จริง | `src/reliability/watchdog.zig:85-117`, `src/daemon.zig:331-336`, pipeline only beat `src/pipeline/event_processor.zig:220-222` | stalled worker ไม่ถูก restart/transition ตามเอกสาร |
| Medium | Control ACL ใช้ OS default และ local role เป็น operate | `src/platform/win32_pipe.zig:159-179`, `src/control/authorization.zig:25-49` | local caller boundary ไม่ตรง claim admin-only; mutation exposure กว้างกว่าที่ควร |
| Medium | Control per-connection arena defer อยู่ใน loop | `src/platform/win32_pipe.zig:202-204` | memory ถูกเก็บจน server exit ไม่ใช่ release ต่อ connection; long-lived daemon โตตามจำนวน connection |
| Medium | Lifecycle framework แยกจาก production path | `src/reliability/lifecycle.zig:131-387` เทียบ `src/daemon.zig:85-490` | เอกสาร/contract บอก lifecycle ที่ runtime ไม่ได้ใช้จริง |
| Medium | Security checks เป็น hard-coded pass | `src/reliability/security_check.zig:60-94` | startup gate ให้ความมั่นใจเกินจริงด้าน hardening |

## Gaps ที่ยังต้องปิด

1. ไม่มี authoritative lifecycle owner เดียวที่รวม `RuntimeSupervisor`, `control.state_machine`, `reliability.lifecycle` และ SCM status
2. ไม่มี legal transition validation และไม่มี explicit `STOPPING`/`READY` transaction ใน daemon path
3. ไม่มี proven control-pipe readiness beacon ที่เกิดหลัง bind และก่อน `SERVICE_RUNNING`
4. ไม่มี producer-safe MPMC queue หรือ equivalent serialization contract
5. ไม่มี drain barrier ที่ยืนยัน producers หยุดแล้ว pipeline ประมวลผล queue ที่เหลือภายใน deadline
6. ไม่มี bridge spool thread handle, stop event, join และ allocator/socket teardown order
7. ไม่มี watchdog polling owner, worker index ownership, restart policy หรือ state transition integration
8. ไม่มี atomic snapshot protocol สำหรับ counters/subsystem JSON และ audit ID
9. ไม่มี runtime implementation ของ `runtime.stop`/`runtime.restart`, restart backoff, quarantine หรือ PID adoption ตามเอกสาร
10. ไม่มี Windows runtime evidence package ที่ผูก binary hash, source HEAD, startup logs, health samples, control shutdown response และ join completion
11. ไม่มี proof ว่า default pipe ACL และ caller identity enforce boundary ตาม security requirement
12. `g_stop_requested` และ `bridge_init.g_shutdown` ไม่ถูก resetที่ต้น `runDaemon()`; re-entry/restart ใน process เดียวจึงยังไม่เป็น safe generation

## Next actions ที่แนะนำ

1. ทำ queue correctness เป็น gate แรก: serialize producer reservation ด้วย mutex หรือออกแบบ bounded MPMC queue ที่พิสูจน์แล้ว และเพิ่ม stress test ให้มี Nose + sensor + ETW/FIM/registry producer พร้อมกัน
2. เปลี่ยน shutdown เป็น supervisor-owned transaction: transition `RUNNING/DEGRADED -> STOPPING`, stop producers, close/interrupt ingress, wait producer join, drain pipeline ด้วย deadline, flush forensic, join pipeline, stop bridge spool, แล้วค่อย publish `STOPPED`
3. ย้าย `daemon.shutdown` ให้ส่งคำขอไป supervisor แทนการเขียน `.stopped` โดยตรง; handler ควรตอบ accepted/pending หรือรอ verified postcondition ที่กำหนด timeout
4. กำหนด control readiness หลัง `CreateNamedPipeW` สำเร็จและก่อน `SERVICE_RUNNING`; ถ้า bind fail ต้องไม่ประกาศ service running
5. เพิ่ม `RuntimeSupervisor` ownership ให้ bridge spool thread หรือเปลี่ยน bridge shutdown เป็น stop event + join ก่อนปิด UDP/C++/WFP resources
6. ทำ worker lifecycle table ให้ทุก workerมี start, ready, heartbeat, failure, stop และ join callback; watchdog ต้องมี owner เรียก `check()` และต้องทำให้ failure เปลี่ยน state หรือเริ่ม recovery จริง
7. แก้ shared state โดยใช้ atomic counters/snapshots หรือ mutex ที่ครอบทั้ง update/read; โดยเฉพาะ `g_pipeline_audit_id`, pipeline counters, Nose counters และ subsystem JSON serialization
8. เลือก lifecycle authority เดียว: either ย้าย daemon เข้า `reliability.lifecycle` หรือประกาศ lifecycle module เป็น legacy และปรับเอกสาร/contract ให้ตรงกับ `RuntimeSupervisor`
9. ทดสอบบน Windows จาก clean build ที่ HEAD `46b93dc...`: service start, control health polling, synthetic Nose frame, multiple concurrent producers, `daemon.shutdown`, SCM stop, forced worker failure และ process exit handle audit
10. เก็บ runtime proof artifact ต่อ scenario: executable hash, source HEAD, timestamps, worker readiness snapshot, pipe bind result, queue counters, forensic count, service status transitions และ evidence ว่า thread handle ทุกตัว joined

## References

[1]: ../../build.zig "Production Zig build graph"
[2]: ../../src/main.zig "Production process entrypoint"
[3]: ../../src/daemon.zig "Daemon startup orchestration and RuntimeSupervisor"
[4]: ../../src/platform/win32_service.zig "Windows SCM lifecycle adapter"
[5]: ../../src/platform/win32_pipe.zig "Windows named-pipe control server"
[6]: ../../src/control/state_machine.zig "Runtime and subsystem state machine"
[7]: ../../src/control/handler_registry.zig "Control dispatch and lifecycle handlers"
[8]: ../../src/control/protocol.zig "Control command contracts"
[9]: ../../src/control/authorization.zig "Control authorization policy"
[10]: ../../src/pipeline/runtime_state.zig "Shared readiness, shutdown, and pipeline state"
[11]: ../../src/pipeline/event_processor.zig "Pipeline worker loop"
[12]: ../../src/pipeline/event_queue.zig "Bounded event queue implementation"
[13]: ../../src/pipeline/telemetry_threads.zig "ETW, FIM, and registry workers"
[14]: ../../src/capture/nose_pipe_reader.zig "Canonical Go Nose pipe reader"
[15]: ../../src/core/nids_capture.zig "Legacy sensor-pipe worker"
[16]: ../../src/core/bridge_init.zig "Bridge startup, spool thread, and shutdown"
[17]: ../../src/reliability/watchdog.zig "Active watchdog implementation"
[18]: ../../src/reliability/security_check.zig "Startup security self-check"
[19]: ../../src/reliability/lifecycle.zig "Separate lifecycle framework not used by daemon path"
[20]: ../../docs/runtime/LIFECYCLE.md "Normative lifecycle state machine"
[21]: ../../docs/runtime/RUNTIME_CONTRACT.md "Normative runtime, timeout, health, and restart contract"
[22]: ../../docs/architecture/failure-model.md "Graceful shutdown and failure model"
[23]: ../../docs/DEEP_AUDIT_RUNTIME_CONVERGENCE_2026-09-15.md "Historical runtime convergence audit and prior evidence claims"
[24]: ../../docs/architecture/ADR-RUNTIME-CONVERGENCE.md "Accepted single-runtime architecture decision"
