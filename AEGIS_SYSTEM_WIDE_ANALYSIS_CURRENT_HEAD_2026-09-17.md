# AEGIS NIDS Windows — System-wide Analysis ที่ Current HEAD

**วันที่วิเคราะห์:** 2026-09-17  
**Repository:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`  
**Source HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**บทบาทรายงาน:** Lead-architect synthesis  
**สถานะการแก้ไข:** ไม่ได้แก้ source, configuration, generated map หรือ build artifact ใด ๆ

## 1. ข้อสรุปสำหรับผู้บริหาร

AEGIS ที่ HEAD นี้มี **โครงสร้าง source สำหรับ NIDS แบบหลายภาษา** อยู่จริง แต่ยังไม่มีหลักฐานปัจจุบันที่ยืนยันเส้นทาง `build → deploy → start → acquire → detect → enforce → forensic → stop` ครบหนึ่งรอบบน Windows เครื่องเดียวกันได้ ระบบจึงควรถูกจัดเป็น **detection-only/degraded และยังไม่ควรถูกประกาศเป็น production prevention system** จนกว่าจะปิด blocker ระดับ P0 และสร้างหลักฐาน Windows current-head ใหม่

เส้นทาง runtime ที่เห็นจาก source จริงคือ `src/main.zig` → `src/platform/win32_service.zig` → `src/daemon.zig:runDaemon()` จากนั้น daemon โหลด rules/policies, เตรียม PEP และ bridge, spawn worker หกตัว, เปิด JSON named pipe และรอการควบคุมจาก pipe หรือ SCM [1] [2] โครงสร้าง `RuntimeSupervisor` ถือ handle ของ worker หลักและ join แบบ reverse order เป็น ownership ที่ดีขึ้น แต่ยังไม่ใช่ lifecycle authority เดียว เพราะ state machine, SCM handler, control handler, worker flags, bridge shutdown และ watchdog ต่างถือคนละส่วนของความจริง

ความเสี่ยงเชิงข้อมูลที่รุนแรงที่สุดคือ `src/pipeline/event_queue.zig:pushEvent()` มี producer หลาย thread แต่การจอง `g_queue_head` ไม่มี mutex หรือ CAS การตรวจ queue เต็มและการเขียน slot จึงยังไม่พิสูจน์ว่าเป็น multi-producer queue ที่ปลอดภัย [1] [3] ระหว่าง shutdown supervisor join producer ก่อน pipeline และ pipeline ออกจาก loop เมื่อเห็น stop flag โดยไม่ drain queue ทำให้ event ที่รับเข้ามาแล้วอาจไม่ถูกประมวลผลหรือเขียน forensic

ความเสี่ยงเชิง identity คือ Go Nose สร้าง event sequence แบบ process-local และ reader ตรวจ duplicate/non-monotonic เพียงเพื่อเพิ่ม counter แต่ยัง submit event ที่ผิดลำดับหรือซ้ำ ขณะที่ ETW และ adapter อื่นมี namespace/event semantics ของตนเอง การ restart หรือ reconnect จึงยังไม่มี identity epoch ที่แยกได้อย่างเป็นทางการ [2]

ความเสี่ยงเชิง enforcement คือ source มี PEP FFI และ Rust adapter ที่ตั้งใจ fail-closed เมื่อ PEP unavailable แต่ authority ยังไม่ถูกผูกกับ Windows token/SID/integrity level, capability และ PID เป็นข้อมูลที่ caller ส่ง, policy signature ไม่ได้ถูกบังคับใน active load/reload path, mutating WFP device ไม่มีหลักฐาน SDDL/caller authorization และ WFP callout ที่ตรวจพบเป็น permit/fail-open telemetry ในบาง path [4] ดังนั้นค่า `block`, `ALLOW/ESCALATE`, log หรือ in-memory result ไม่ใช่หลักฐานว่า traffic ถูก block จริง

ความเสี่ยงเชิง operator คือ active control plane เป็น JSON named pipe แต่เอกสารและ map หลายชุดยังอ้าง fixed-header binary protocol คนละชุด Python Brain เรียก syntax `aegisctl block <ip> ...` ที่ parser ปัจจุบันไม่รับ และ top-level block mutation ถูกทำให้ unavailable การเดินทาง Brain → CLI → PEP จึงไปไม่ถึง active daemon [5]

ความเสี่ยงเชิง release คือ truth maps และ evidence หลายชุดอ้าง SHA เก่า `688ab566d477105df5f868cee1571fbec77eedfd`; `build_manifest.json` อ้าง commit อื่นและ digest ตรวจพบ mismatch 7 รายการ; deploy script ใช้ source root ผิด; Go Nose ไม่ถูก spawn/deploy โดย service; installer และ verify-release ต่างคาด layout คนละรุ่น; top-level CMake ปิด kernel-driver build โดย default [6] หลักฐาน runtime ที่มีเป็น run ที่ล้มเหลวหรือเสื่อมสภาพ และ stack/source line ไม่ตรงกับ current source จึงใช้เป็น pass ไม่ได้

**คำตัดสิน:** source implementation หลายส่วนอยู่ระดับ E1 static evidence เท่านั้น ไม่มี current-head E3/E4/E5/E6/E7 proof สำหรับ golden path และไม่มีฐานเพียงพอที่จะยืนยัน privileged prevention, exactly-once acquisition, graceful shutdown หรือ reproducible release

## 2. ขอบเขตและระดับความเชื่อมั่น

รายงานนี้สังเคราะห์ผล static review ของ source, build scripts, tests, documents และ artifacts ที่ผูกกับ repository ข้างต้น โดยถือ `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` เป็น source truth และถือ generated maps ที่อ้าง `688ab...` เป็น stale [1] [6]

ใช้สถานะหลักฐานดังนี้

| สถานะ | ความหมาย | ข้อจำกัด |
|---|---|---|
| **S — Static** | อนุมานจาก source, call graph, declaration หรือ test code | ยืนยันได้ว่ามี implementation/เจตนา ไม่ยืนยันว่า binary ถูก build, loaded หรือทำงานบน Windows |
| **R — Reproduced** | คำสั่งใน sandbox ปัจจุบันทำซ้ำได้ | sandbox เป็น Linux จึงไม่แทน Windows SCM, named pipe, Npcap, WFP หรือ driver |
| **H — Historical/Artifact** | log, evidence index หรือ manifest ที่มาจาก run/commit อื่น หรือ provenance ไม่ครบ | ใช้บอก failure/ความขัดแย้งได้ แต่ห้ามเลื่อนเป็น current-head pass |
| **U — Unresolved** | source หรือหลักฐานขัดกัน/ไม่พอ | ต้องมี targeted Windows test, ABI assertion หรือ artifact digest ก่อนสรุป |

รายงานนี้มีความเชื่อมั่นสูงต่อ call graph และ contract mismatch ที่เห็นตรงจาก source มีความเชื่อมั่นต่ำต่อ behavior ที่ต้องพึ่ง Windows API, compiler layout, DLL/driver provenance, thread scheduling และ WFP host effect เพราะไม่มี current-head Windows execution package ที่ผูก binary hash กับ source ครบ

## 3. ภาพรวมสถาปัตยกรรมปัจจุบัน

### 3.1 Process และ runtime spine

Production executable ถูกสร้างจาก `build.zig` โดยใช้ `src/main.zig` เป็น root `main()` เลือก `--version` หรือเรียก `service.mainEntry()` บน Windows `mainEntry()` พยายามเชื่อม `StartServiceCtrlDispatcherW()` และ fallback เป็น foreground/console เมื่อไม่ได้ถูกเรียกโดย SCM จากนั้น `serviceMain()` หรือ console path เรียก `daemon.runDaemon()` [1] [6]

`daemon.runDaemon()` เป็น startup owner ที่รวมงานต่อไปนี้ไว้ใน process เดียว

1. diagnostics และ startup context
2. runtime state registration และ security self-check
3. capability probe
4. arena, forensic ring, watchdog, performance tracker และ fault injector
5. Aho-Corasick rules จาก `configs/Rules.json`
6. policy set จาก `configs/policies.json`
7. anomaly detector, flow table, threat tracker, PEP และ action dispatcher
8. WFP/C++/UDP bridge initialization
9. worker thread สำหรับ legacy sensor, pipeline, Go Nose reader, ETW, FIM และ Registry
10. control named pipe `\\.\pipe\aegis_control`
11. supervisor shutdown และ resource deinitialization

สถาปัตยกรรมจึงมี **core process หนึ่งตัว** แต่มี acquisition/provider และ bridge หลายแบบ บางแบบ active ใน daemon, บางแบบเป็น alternate หรือ dormant path การมี module อยู่ใน tree ไม่ได้แปลว่าอยู่ใน production call graph

### 3.2 Data plane และ detection plane

Data plane ที่ daemon ตั้งใจใช้ประกอบด้วย

- **Go Nose:** `nose/capture.go` เปิด Npcap, decode packet, serialize Canonical Event แล้วส่ง frame ไป `\\.\pipe\aegis_nose`; `src/capture/nose_pipe_reader.zig` deserialize/validate แล้วส่งเข้า `src/pipeline/event_queue.zig`
- **Legacy sensor/WFP pipe:** `src/core/nids_capture.zig` อ่านเส้นทาง `aegis_sensor_pipe` ผ่าน bridge และส่ง event คนละแนวทางกับ Go canonical path
- **ETW:** `src/pipeline/telemetry_threads.zig` ใช้ native helper `src/windows/etw_native.c` ใน worker path; `src/windows/etw_realtime.zig` เป็น implementation อีกชุดที่ daemon ไม่ได้ instantiate ตามผลวิเคราะห์
- **FIM:** `fim.zig`/`fim_native.c` ใช้ `ReadDirectoryChangesW`; source ปัจจุบันไม่แสดง overflow counter หรือ preservation ของ operation/path ครบใน queue conversion
- **Registry:** worker ใช้ registry notification/poll path แต่แปลงเป็น generic `IpcEvent` ที่ใช้ `dns_query` และไม่รักษา registry kind/path/rule_id ตาม contract ที่ควรเป็น
- **C++ adapter:** มี process snapshot และ synthetic host keepalive แต่ไม่มีหลักฐานว่า daemon เริ่ม `cpp_adapter.feedFabric`; `aegis_adapter.dll` ไม่อยู่ใน active daemon load graph

Detection plane คือ `event_processor.pipelineLoop()` อ่าน event จาก queue แล้วทำ flow lookup, signature matching, anomaly detection, threat tracking, policy evaluation, PEP decision, action dispatch, audit และ forensic append [2] หาก PEP unavailable wrapper จะคืน `.escalate` แทน `.allow` ซึ่งเป็น containment ที่ดีในระดับ source แต่ไม่ได้ยืนยัน side effect บน WFP

### 3.3 Control plane และ operator plane

Active control plane คือ JSON named pipe `\\.\pipe\aegis_control` ที่สร้างใน `src/platform/win32_pipe.zig` แบบ message mode, single instance, buffer 64 KiB หลังรับ request จะ dispatch ไป `src/control/handler_registry.zig` และ map command ผ่าน `src/control/protocol.zig` [5]

Python top-level entrypoint คือ `tools/aegisctl.py` แต่ไม่ใช่ thin client ทุก command: status/health บางส่วน query pipe, rules/policy/events/forensics หลายคำสั่งอ่าน local file, enforcement mutation ถูก mark unavailable และ package command modules เป็น command surface ซ้ำที่ส่วนใหญ่ไม่ได้ register เข้ากับ top-level parser [5]

เส้นทาง control รุ่นเก่าใน `src/policy/control_ipc.zig` และ `shared/protocol/control_protocol.md` อธิบาย fixed-header `CTRL` protocol ที่มี caller identity, role, issued time, timeout และ nonce แต่ไม่ใช่ implementation ที่ active daemon เรียกอยู่ จึงต้องถือเป็น alternate/legacy contract จนกว่าจะมีการเลือก authority เดียว

### 3.4 Enforcement และ privileged boundary

Active-looking enforcement flow คือ pipeline → `src/policy/pep_bindings.zig:PepEnforcer.enforce()` → C ABI `aegis_pep_enforce()` ใน `rust-src/lib.rs` → dynamic load `aegis_wfp_user.dll` → `DeviceIoControl(IOCTL_AEGIS_BLOCK_FLOW)` → kernel WFP handler → `FwpmFilterAdd0()` [4]

พร้อมกันนั้น `src/windows/aegis_wfp.c` มี direct user-mode WFP exports และ `src/windows/wfp_ioctl.c` มี mutating device path อีกชุดหนึ่ง ส่วน Zig `src/policy/wfp_ioctl.zig` ถูกอธิบายเป็น read-only telemetry path การมีหลาย privileged surface ทำให้ Rust PEP ยังไม่ใช่ authority เดียวที่ enforce ได้จริงโดย OS

### 3.5 Reliability และ evidence plane

`RuntimeSupervisor` เป็น owner ของ handle หกตัว ได้แก่ `pipeline`, `sensor`, `nose_reader`, `etw`, `fim`, `registry` และ join reverse startup order [1] แต่ bridge spool thread ที่ `bridge_init.initAll()` อาจ spawn ไม่ถูกเก็บ handle จึงอยู่นอก join contract

Watchdog ถูกสร้างและ register worker หลายตัว แต่ source พบ heartbeat ที่ชัดเจนเฉพาะ pipeline และไม่พบ daemon call site ที่เรียก `ReliabilityWatchdog.check()` หรือทำ restart action การที่มี watchdog object จึงเป็น static framework ไม่ใช่ proof ของ failure recovery

Forensic ring ถูกสร้างใน daemon และ pipeline มีทาง append แต่ shutdown ไม่มี transaction ที่บังคับ drain queue → flush forensic → ปิดทุก producer → join ครบ → publish STOPPED

## 4. Actual end-to-end flows จาก source จริง

### 4.1 Startup จาก SCM หรือ console ถึง service ready

```text
src/main.zig:main
  -> platform/win32_service.mainEntry
     -> StartServiceCtrlDispatcherW / console fallback
        -> daemon.runDaemon
           -> state STARTING
           -> SecurityCheck.run
           -> capability probe
           -> core/detection/PEP/bridge init
           -> spawn sensor, pipeline, Nose, ETW, FIM, Registry
           -> wait readiness สูงสุด 2 วินาที
           -> state RUNNING หรือ DEGRADED
           -> SERVICE_RUNNING
           -> serveWindowsPipe
```

สิ่งที่ source ยืนยันคือมี bounded wait และ atomic readiness flags ข้อจำกัดคือ `pipeline_ready` หมายถึง loop เข้า function, `nose_ready` หมายถึงสร้าง server pipe สำเร็จ, ส่วน ETW/FIM/Registry หมายถึง native start ผ่าน ไม่ได้หมายถึงมี event จริงหรือ downstream detector พร้อม [1]

Daemon mark `.control` และ SERVICE_RUNNING ก่อนที่ `serveWindowsPipe()` จะพิสูจน์ว่า `CreateNamedPipeW()` สำเร็จในเส้นทางเดียวกัน หาก pipe bind ล้ม startup จึงอาจรายงาน running/degraded โดย control endpoint ใช้งานไม่ได้ นี่เป็น static ordering finding; ยังไม่มี current Windows run ยืนยันผลทุก race window

### 4.2 Network packet: Go Nose ถึง detector/forensic

```text
Npcap/pcap.OpenLive + BPF ip/ip6
  -> nose/capture.go:gopacket decode
  -> process-local eventSequence
  -> CanonicalEvent.Serialize (เอกสาร/Go contract 109 bytes)
  -> u32 length + frame ไป \\.\pipe\aegis_nose
  -> nose_pipe_reader.deserialize/validate
  -> duplicate/non-monotonic counters
  -> event_queue.pushCanonicalEvent
  -> event_processor.pipelineLoop
  -> detection -> policy -> PEP -> action/audit/forensic
```

Static source แสดง boundary และการ copy `event_id` ลง `IpcEvent` ไม่มีการ mint ID ใหม่ใน adapter [2] แต่มี defect เชิง identity: sequence เริ่มใหม่ต่อ process, duplicate ที่ reader เพียง warning/counter แล้ว submit ต่อ และไม่มี durable boot/source epoch เมื่อ Nose reconnect/restart

Go `FrameWriter` drop frame เมื่อ Zig reader unavailable หรือ write fail และ retry ใน packet ถัดไป ไม่มี bounded spool ที่พิสูจน์ได้ ดังนั้น consumer outage อาจทำให้ network acquisition ดำเนินต่อพร้อม silent loss นอกเหนือจาก dropped counter/stderr การที่ daemon ไม่ spawn Go Nose ทำให้ deployment ต้องจัดการ process นี้แยกเอง

ยังไม่มี E4/E5 evidence ที่ฉีดหนึ่ง packet ใน current-head Windows run แล้วแสดง `event_id` เดียวกันตั้งแต่ capture, pipe, queue, detector และ forensic record

### 4.3 ETW host event

```text
telemetry.etwThread
  -> native ETW start/callback
  -> map opcode/event record เป็น legacy IpcEvent
  -> event_queue.pushEvent
  -> pipeline
```

`etw_native.c` เป็น helper ที่มี StartTrace/EnableTrace/OpenTrace/ProcessTrace ตาม source แต่ ABI ของ native record กับ Zig `EtwEventRecord` และ provider/GUID definitions ยังต้อง assert บน Windows จริง อีก implementation ใน `src/windows/etw_realtime.zig` ใช้ bounded drop-oldest queue และ `HostEvent` conversion แต่ไม่ใช่ worker ที่ daemon สร้างใน current path

Static finding ที่ต้องแก้คือ callback ใช้ counter `events_emitted` เป็น event ID ก่อน increment ภายใต้หลาย provider และ increment แม้ enqueue ล้มเหลว unknown opcode ถูก map เป็น process_create default ข้อมูล host event จึงอาจผิด identity, semantics และ conservation counter

### 4.4 FIM host event

```text
fimThread
  -> add System32/SysWOW64 rules
  -> FimWatcher.startAll
  -> fim_native.c / ReadDirectoryChangesW
  -> poll raw buffer
  -> capture_fim conversion เป็น IpcEvent
  -> event_queue
  -> pipeline
```

Source มี pending buffer ต่อ session และ poll raw bytes แต่ไม่แสดง overflow/error counter สำหรับ burst เกิน buffer และ telemetry conversion ทำให้ path/operation semantics หายไป ผล runtime artifact ที่มีรายงาน FIM start failure แต่ artifact ไม่ผูก binary SHA กับ current HEAD จึงเป็น H failed observation ไม่ใช่ current proof

### 4.5 Registry event

```text
registryThread
  -> RegOpenKeyExA(HKLM Services/Run)
  -> RegNotifyChangeKeyValue / pollNative
  -> generic IpcEvent
  -> event_queue
  -> pipeline
```

Source ใช้ `event.kind = dns_query` และ payload ว่างใน conversion ที่ตรวจพบ ทำให้ registry event ไม่สามารถระบุ operation, key/path หรือ rule ID ใน downstream policy/forensic ได้ นี่เป็น semantic bug ที่ยืนยันจาก static source ไม่ใช่เพียง runtime uncertainty

### 4.6 Legacy WFP/sensor และ alternate acquisition

Daemon spawn `legacy_capture.capture_packets` และ bridge initialization แต่ runtime log historical ระบุว่า WFP device unavailable จึงไม่มี proof ว่าการอ่าน WFP สำเร็จ การมี `src/capture/windows_capture.zig` เป็น WFP reader อีกตัวที่ใช้ Nose Contract และ analysis/block path ไม่ได้แปลว่า symbol นี้ถูกเลือกโดย `runDaemon()`

C++ `SharedRingBuffer` ใน `bridge/aegis_ipc.hpp` และ `aegis_ipc.cpp` เป็น queue 8192 entries ของ packed event schema อีกแบบหนึ่ง ไม่มี mutex ทั้งที่ documentation อ้าง thread-safe และไม่ได้เชื่อมกับ canonical 109-byte production Nose boundary

### 4.7 Detection → policy → PEP → WFP

```text
event_processor.processEvent
  -> flow/signature/anomaly/threat tracking
  -> PolicySet.evaluate (policy แรกที่ match)
  -> PepEnforcer.enforce
  -> aegis_pep_enforce (Rust C ABI)
  -> WFP user DLL + mutating IOCTL
  -> kernel handler/FwpmFilterAdd0 (ถ้า driver/artifact พร้อม)
  -> ActionDispatcher + audit + forensic
```

Policy parser ใน `daemon.zig` อ่าน first clause/first predicate, map `gte` เป็น `gt`, เก็บ `ttl_sec` แต่ evaluator ไม่ใช้ TTL, action ไม่รู้จักถูก map เป็น `.pass` และ file absence/parse failure ทำให้ policy set ว่างมากกว่าจะหยุด privileged path [4] นี่ทำให้ semantic ที่ดูเหมือน block ใน JSON ไม่ใช่ authorization proof

`PepContext` ใช้ `caller_pid`, `caller_capability_mask`, `request_id`, `policy_version` แต่ source ไม่ได้ bind caller กับ Windows token และ daemon hard-code capability `0x01`; request ID/version/nonce ไม่เป็น replay/freshness gate policy signature ไม่ได้อยู่ใน request อย่างบังคับ

### 4.8 Operator status, rule reload และ block

```text
python tools/aegisctl.py status/health
  -> control_api
  -> system.health/system.status over \\.\pipe\aegis_control
  -> diagnostic PID fallback เมื่อ daemon unavailable
```

Health fallback ระบุ degraded/diagnostic ซึ่งปลอดภัยกว่าการอ้างว่า process มีชีวิตเท่ากับ runtime health อย่างไรก็ดี rule mutation หลายคำสั่งเขียน `config/Rules.json` แต่ daemon reload อ่าน `configs/Rules.json`; การแก้สำเร็จบน disk จึงอาจไม่เปลี่ยน active rules

Brain เรียก subprocess รูปแบบ `block <ip> --rule-id ... --reason ...` แต่ parser จริงต้องมี subcommand `block add --ip ...` และ mutation ยังคืน unavailable ผล probe ของ syntax นี้ได้ argparse exit 2 และ `block add` ได้ unavailable exit 4 ตามรายงาน control [5] ไม่มี request เข้า Zig PEP ในเส้นทางนี้

### 4.9 Normal shutdown และ SCM stop

Normal control shutdown เป็น

```text
daemon.shutdown request
  -> handler sets state STOPPED และ g_stop_requested
  -> bridge_init.requestShutdown
  -> response flush/disconnect
  -> serve pipe return
  -> supervisor requestStop
  -> join registry -> FIM -> ETW -> Nose -> sensor -> pipeline
  -> bridge/resource deinit
```

ปัญหาคือ handler ประกาศ STOPPED ก่อน join และ queue ไม่ถูก drain ขณะที่ pipeline ตรวจ stop flag แล้วออกทันที ส่วน bridge spool thread ไม่ถูก join ก่อน socket/resource deinit [1]

SCM stop ใช้ service handler set flag, `bridge_init.requestShutdown()` และ `wakeControlPipe()` แล้ว serviceMain defer ตั้ง SERVICE_STOPPED ไม่มี explicit runtime state transition เป็น STOPPING/STOPPED และยังไม่มีหลักฐานว่า wake pipe ปลด block ที่ `ReadFile` ได้ครบทุก race window เพราะ pipe ใช้ blocking I/O ไม่มี overlapped cancellation

## 5. Ownership และ authority matrix

| พื้นที่ | Owner ที่ source แสดง | สิ่งที่ owner ทำได้จริง | ช่องว่าง authority |
|---|---|---|---|
| Process/lifecycle | `daemon.runDaemon()` และ `RuntimeSupervisor` | สร้าง worker, signal stop, join 6 handles | state machine/SCM/control handler ยัง publish state แยกกัน; spool thread ไม่อยู่ใน owner |
| System state | `control/state_machine.zig:g_runtime` | register subsystem, transition, health/status JSON | `transition()` ไม่ validate legal transition; daemon ไม่ขับ READY/STOPPING/RECOVERING/FAILED ครบ |
| SCM stop | `win32_service.serviceHandler` | set flag, bridge shutdown, wake pipe, SCM status | ไม่เรียก state machine และไม่พิสูจน์ verified stop |
| Control mutation | `handler_registry` | auth ด้วย local role, handler, audit, response | caller identity/ACL/freshness/nonce ไม่ผูกกับ request; active protocol ไม่ตรง documented binary protocol |
| Event queue | module globals ใน `event_queue.zig` | producer push, pipeline pop | ไม่มี producer reservation owner/serialization และ counters ไม่ atomic |
| Network canonical identity | Go Nose process | mint sequence และ serialize 109-byte frame | sequence ไม่ durable/epoch ไม่ชัด; reader ไม่ reject duplicate |
| Detection/policy | `event_processor` + `PolicySet` | evaluate first matching policy แล้วเรียก PEP | parser ลดรูป semantics, unsigned policy, no TTL/priority proof |
| Enforcement | เจตนาให้ Rust PEP | fail/escalate เมื่อ unavailable; เรียก WFP adapter | direct WFP exports/device path ยังเป็น authority อื่น; OS identity/SDDL/driver effect ไม่พิสูจน์ |
| Bridge | `bridge_init` | WFP/C++/UDP init/shutdown | spool thread handle ถูกทิ้ง; teardown ordering ไม่ปลอดภัย |
| Reliability | watchdog + state flags | register/heartbeat บางส่วน | `check()`/restart integration ไม่อยู่ใน production path |
| Operator config | CLI/local files + daemon reload | อ่าน/เขียนคนละ path ตามคำสั่ง | `config/Rules.json` กับ `configs/Rules.json` split และ local success ไม่เท่ากับ runtime postcondition |
| Release truth | maps/manifests/scripts หลายตัว | ตรวจ/สร้าง metadata บางส่วน | stale SHA, digest mismatch และ packaging authorities หลายรุ่น |

**ข้อเสนอด้าน authority:** ต้องกำหนด lifecycle owner เดียวเป็น transaction coordinator และให้ทุก subsystem report intent/acknowledgement กลับ owner นั้น ส่วน privileged mutation ต้องมี broker เดียวที่ authenticate OS identity, validate signed policy, submit side effect และคืน receipt ที่ตรวจ host effect ได้

## 6. Contracts และ ABI ที่ต้องถือว่าเสี่ยง

### 6.1 Event schemas และ queue planes

Repository มีอย่างน้อยสี่ contract ที่ไม่ควรถือว่า interchangeable

| Contract | ที่มา | ขนาด/ลักษณะที่รายงาน | สถานะ |
|---|---|---|---|
| Canonical Event v1 | `src/contract/canonical_event.zig`, Go Nose | เอกสาร/Go path อ้าง frozen wire 109 bytes | ต้อง assert ขนาดจริงของ target และ generate bindings; Zig `extern` กับ C++/Rust packed อาจจัด alignment ต่างกัน |
| `event.IpcEvent` | `src/contract/event.zig` | 96-byte legacy queue event ตามผลย่อย | ถูกใช้โดย `event_queue` หลัง adapter conversion ไม่ใช่ canonical wire เดียว |
| C++ `IpcEvent` | `bridge/aegis_ipc.hpp` | 72-byte packed schema v2 | SharedRingBuffer แยก queue และ ABI จาก 109-byte contract |
| `wire_v1` framed protocol | `shared/protocol/wire_v1.md` | มี framed form ที่รายงานเป็น 125 bytes | ไม่พบหลักฐานว่าถูกใช้ใน daemon current path |

ความไม่แน่นอนสำคัญคือ compile-time `@sizeOf(CanonicalEvent)` บน target ปัจจุบันยังไม่ได้รันใน Windows และ cross-language serializer ไม่ได้ถูกพิสูจน์ด้วย one generated ABI manifest การอ้าง “109 bytes” จึงเป็น contract claim ที่ต้องยืนยันด้วย `static_assert`, Zig test, Rust/Go/C++ golden bytes และ runtime frame capture

### 6.2 PEP FFI และ WFP ABI

`src/policy/pep_bindings.zig` ประกาศ `PepContext`, `PepRequest`, `PepResponse` เป็น `extern struct` พร้อม tests ที่คาด size 24, 64 และ 16 bytes ตามลำดับ [4] Tests เหล่านี้เป็น static/compile proof ของ Zig-side expectation เท่านั้นจนกว่าจะ link against current Rust DLL และตรวจ `offsetof/sizeof` จาก build เดียวกัน

WFP telemetry structs เป็นอีกปัญหา: ผล security review ระบุว่า Zig `WfpEventHeader`/`WfpRingStats` คาด layout/size ต่างจาก packed C/driver contract โดยรายงาน expected 48/16 เทียบกับ 40/24 การ mismatch นี้ทำให้ event/stats และ readiness ไม่ใช่หลักฐานที่เชื่อถือได้แม้ function จะ return success

ต้องมี **single ABI manifest** ระบุ field order, packing, alignment, size, offset, endianness, version, error codes และ ownership ของ buffer สำหรับ Zig, Rust, C, C++, Go และ driver ห้ามให้ comments/test constants เป็น source of truth แยกกัน

### 6.3 Control protocol

Active protocol จาก `src/control/protocol.zig` มี 30 command enum เช่น `system.status`, `runtime.stop`, `rules.reload`, `policy.verify`, `forensics.export`, `enforcement.verify` และ `daemon.shutdown` โดย metadata กำหนด role และ postcondition [5]

แต่ wire ที่ active client ส่งเป็น JSON `{command,payload}` หรือ `{op,payload}` และ server สร้าง local role `.operate`, local audit ID และ response envelope `{ok,code,state,data,audit_id}` ขณะที่เอกสาร `shared/protocol/control_protocol.md` และ `src/policy/control_ipc.zig` อ้าง fixed-header binary contract ที่มี caller hash, issued time, timeout และ nonce ควรเลือกหนึ่ง protocol แล้วทำ generated command matrix, golden request/response และ compatibility policy

`handler_registry.errorEnvelope()` มีรูปแบบ string ที่ source ดูเหมือนปิด object data แล้วเขียน `audit_id` ต่อก่อนปิด root (`"}},\"audit_id\":...`) จึงต้องมี targeted JSON parse test; อย่าแก้หรือยืนยัน defect นี้จากการอ่านเพียงอย่างเดียวจนกว่าจะรัน test ที่ compile current Zig

### 6.4 Windows named pipe security

`CreateNamedPipeW()` ใน `win32_pipe.zig` ส่ง `lpSecurityDescriptor = null` และ authorizer ใช้ `getLocalRole()` ที่ default เป็น `operate` source ยังไม่พิสูจน์ว่าผู้เรียกเป็น service account/admin หรือ low-integrity/foreign process ถูกปฏิเสธ [1] [5]

การกำหนด `SECURITY_ATTRIBUTES` ใน source จึงเป็น control transport ไม่ใช่ complete RBAC boundary ต้องใช้ restrictive SDDL หรือ equivalent ACL, impersonate client, query token/SID/integrity level, map role จาก policy, log authenticated identity และ test negative cases

## 7. Build, deployment และ provenance

### 7.1 Build graph ที่มีจริง

- Zig `build.zig` สร้าง `aegis_nids`, fuzz, perf และ integration test โดยพยายาม link Rust PEP และ native helper
- top-level Cargo สร้าง `aegis_pep` เป็น `cdylib/rlib`
- top-level CMake สร้าง `aegis_wfp_user`, ETW helper และ FIM helper แต่ `BUILD_KERNEL_DRIVER` default เป็น `OFF`
- `bridge/CMakeLists.txt` เป็น project แยกที่สร้าง `aegis_ipc.dll`, `aegis_bridge.exe`, `aegis_adapter.dll` และ selftests
- `nose/go.mod`/Go source เป็น network acquisition executable ที่ daemon ไม่ได้ spawn
- TypeScript policy layer เป็น authoring/advisory layer ไม่ใช่ enforcement runtime

`Makefile:all` เรียก bridge, shield, nose, core, mouth แต่ไม่ปิด dependency ordering กับ top-level CMake และ output name ของ Nose (`nose_dashboard.exe`) ไม่ตรงกับชื่อที่ manifest/runtime อ้าง (`aegis-nose.exe`) [6]

### 7.2 Build blockers

1. `build.zig` ใช้ `catch ""` กับ test fixtures ทำให้ file หายกลายเป็น empty config แทน configure failure
2. helper existence logic ตรวจค่า `bool` เทียบ `!= null` ซึ่งเป็นเงื่อนไขที่ไม่สะท้อน file existence และอาจเลือก directory ผิด
3. PEP/native helper ที่หายถูกลดเป็น warning แม้ runtime ต้องใช้
4. Zig build ไม่ stage DLL, config, Npcap และ runtime dependency closure ให้ executable โดยอัตโนมัติ
5. workflow native job upload ETW/FIM แต่ไม่ครบ WFP user DLL และ C++ bridge ที่ Zig/runtime ต้องใช้
6. package-release เรียก `tools/installer.py --package --output ...` แต่ script รองรับ `--generate`/`--nsi` ตาม source ที่ตรวจ
7. top-level CMake ไม่ build/sign/install driver จึงไม่มี prevention artifact closure
8. Npcap SDK download ไม่มี checksum/signature pin ที่เป็น hard gate

### 7.3 Deployment blockers

`tools/deploy_windows.py` กำหนด `SOURCE_ROOT = Path(__file__).parent` ซึ่งชี้ไป `tools/` ไม่ใช่ repository root จึงค้น `tools/src`, `tools/build.zig` และ root file ผิด [6] แม้แก้ root แล้วรายการ copy ยังขาด `nose/`, `bridge/`, `brain/`, `ts_policy/`, `scripts/`, `dist/`, target DLL และ driver

`install_service()` ชี้ executable แต่ไม่กำหนด working directory/profile path ทั้งที่ daemon เปิด `configs/Rules.json` และ `configs/policies.json` ด้วย relative path ไม่ stage DLL search path และไม่ start Go Nose ดังนั้น service install สำเร็จไม่ได้แปลว่า runtime พร้อม

มี packaging authority อย่างน้อยสามชุด ได้แก่ `tools/installer.py`, root `installer.nsi` รุ่นเก่า และ `scripts/verify_release.ps1` ที่คาด layout ไม่ตรงกัน installer generator ไม่ได้ใส่ native helper, Go Nose, bridge, driver, service registration และ signing metadata ครบ

### 7.4 Truth และ evidence provenance

`tools/truth.py verify` ถูกสรุปว่า `TRUTH_INVALID`; maps หลัก, evidence index, runtime/build manifests และ `AI_CONTEXT.md` อ้าง revision เก่า `688ab...` [6] `build_manifest.json` อ้าง source commit อื่น และ `release_engineering.py --verify` ตรวจ 339 artifacts แล้วพบ digest mismatch 7 files ได้แก่ `build.zig`, `scripts/aegis_console.py`, `scripts/aegis_event_gen.py`, `scripts/aegis_graph.py`, `shield/Cargo.lock`, `tools/aegisctl.py` และ `tools/aegisctl/api/control_api.py`

SBOM ถูกสร้างก่อน current HEAD และ SPDX ID ที่สร้างจาก Python built-in `hash(path)` ไม่ deterministic ข้าม process แม้ file content เท่ากัน รายงาน runtime `aegis_nids.stderr.log` มี WFP/bridge/ETW/FIM/Npcap/named-pipe failures และ segmentation fault แต่ stack/source line ไม่ตรง current source และไม่มี binary SHA จึงเป็น H failed/stale observation

## 8. Tests และ evidence ที่มีอยู่จริง

Repository นิยามระดับ E0–E7 แต่ current evidence ที่สรุปได้มีเพียง E1 เป็นหลัก

| ระดับ | สถานะที่ current HEAD | สิ่งที่สรุปได้ | สิ่งที่ยังสรุปไม่ได้ |
|---|---|---|---|
| E0 | ไม่มี full release proof | ยังไม่มีหลักฐาน | production readiness |
| E1 | source/build/CI declarations, static tests, call graph | implementation/structure exists | runtime success, side effect, performance |
| E2 | historical/unit-like entries หลายชุด | อาจยืนยัน revision เดิมบางส่วน | ใช้กับ HEAD นี้โดยอัตโนมัติไม่ได้ |
| E3 | ไม่พบ current cross-component artifact | ต้องสร้างใหม่ | component integration |
| E4 | ไม่พบ current full-system run | ต้องสร้างบน Windows | golden path |
| E5 | log Windows ที่ failed/degraded และ provenance ไม่ครบ | เคยมี execution ที่ล้มเหลว | current-head host pass |
| E6 | ไม่พบ current simulation package/result | ไม่มี | operational simulation |
| E7 | ไม่มี clean-room install/rollback current HEAD | ไม่มี | release verified |

`tests/test_golden_path.py` local run ให้ 9 pass/1 fail โดย failure คือหา root `Rules.json` ไม่พบ ขณะที่ daemon ใช้ `configs/Rules.json`; Zig/Cargo/pytest ไม่ได้รันใน sandbox เพราะ toolchain/module ไม่พร้อม และ harness บางส่วนแสดง missing prerequisite เป็น skip/pass-like output [6] ชื่อ test ที่มีคำว่า REAL หรือ host-verified ในบางชุดจึงห้ามนำมาเป็น Windows runtime evidence โดยไม่มี raw output, host identity, binary digest และ current commit binding

CI workflow ประกาศ jobs หลายภาษาและมี `ci-matrix` ตั้งใจถือ required skip/failure เป็น fail แต่ checker ที่รันได้ตรวจเพียง job IDs ใน YAML ไม่ได้อ่าน GitHub execution result จึงเป็น declaration proof เท่านั้น

**Evidence package ที่ขาด:** SHA-256 ของทุก binary/DLL/driver, PDB/build ID, source HEAD, toolchain versions, clean host identity, install transcript, SCM state transitions, health ก่อน/หลัง, one event ID chain, queue counters, PEP request/response, WFP filter ID/effect, forensic/audit hash, stop/join timings และ rollback/uninstall output

## 9. Contradictions และ design decisions ที่ต้องหยุดการตีความผิด

1. **Lifecycle model กับ implementation ไม่ตรงกัน:** docs ระบุ STOPPED → STARTING → READY → RUNNING → DEGRADED → RECOVERING → STOPPING แต่ production call graph เห็น STOPPED → STARTING → RUNNING/DEGRADED; `runtime.stop`/`runtime.restart` เป็น `NOT_IMPLEMENTED`
2. **State owner ซ้ำ:** control shutdown ตั้ง STOPPED ก่อน join; SCM stop ไม่แก้ internal state; service status อาจ STOPPED ขณะ worker ยังทำงาน
3. **Single Event Fabric claim กับสอง queue planes:** production `event_queue` 4096 `IpcEvent` รับ direct จาก Nose/host paths; `nose_contract.PriorityQueue` และ C++ ring เป็นอีก plane พร้อม counter/backpressure คนละชุด
4. **Canonical event claim กับ legacy conversion:** canonical wire 109 bytes ถูกแปลงเป็น 96-byte `IpcEvent`; C++ 72-byte packed และ wire_v1 framed protocol ไม่ได้มี adapter/authority เดียว
5. **Go Nose canonical claim กับ deployment:** daemon ไม่ spawn/deploy Go Nose และ `Makefile`/manifest ใช้ชื่อ artifact ต่างกัน
6. **Control v2 active กับ control_protocol v1 documented:** JSON `{command,payload}` ไม่มี caller/freshness/nonce เทียบกับ fixed header binary contract
7. **CLI contract กับ Brain:** Brain positional block syntax ใช้ไม่ได้; package command ใช้ `block_request`/`enforce_push` ที่ active enum ไม่รับ
8. **Rules path:** daemon reload อ่าน `configs/Rules.json`, CLI mutations เขียน `config/Rules.json`, golden test คาด root `Rules.json`
9. **PEP sole authority claim กับ exports:** Rust PEP, direct `aegis_wfp_*`, mutating IOCTL และ simulation `RustPep` อยู่พร้อมกัน
10. **Fail-closed claim กับ WFP callout:** PEP wrapper escalate เมื่อ unavailable แต่ callout telemetry ตั้ง `FWP_ACTION_PERMIT`; provider/register สำเร็จไม่เท่ากับ block effect
11. **Security check claim กับ implementation:** gate ถูกเรียกแต่ checks หลายตัว hard-coded pass
12. **Historical convergence docs กับ current runtime:** document อ้าง E2/E5 observations แต่ revision, source line และ binary provenance ไม่ตรง HEAD
13. **Health claim กับ readiness:** `nose_ready` หมายถึง pipe server create ไม่ใช่ Go client connected; `pipeline_ready` หมายถึง loop start ไม่ใช่ first healthy event
14. **Build manifest กับ source:** manifest stale, digest mismatch และ artifact collector มองหา `core/`/`config/` แทน `src/`/`configs/`

## 10. Blockers เรียงตามความเสี่ยง

### P0 — ต้องปิดก่อนอ้าง production หรือ privileged prevention

| ลำดับ | Blocker | เหตุผลและผลกระทบ |
|---:|---|---|
| P0-1 | **Event queue multi-producer race** | event อาจ overwrite/corrupt/lost ก่อน detector; กระทบทุก source และ forensic correctness |
| P0-2 | **Enforcement authority และ caller authorization ไม่ปิด** | mutating device/direct WFP surface ไม่มีหลักฐาน SDDL/token binding; untrusted process อาจเรียก privileged path |
| P0-3 | **Policy authenticity ไม่ mandatory** | `configs/policies.json` และ rules โหลด plain JSON; verifier มีแต่ไม่ถูกเรียก; block intent อาจถูกแก้หรือ downgrade |
| P0-4 | **WFP/driver ABI และ host effect ไม่พิสูจน์** | WFP struct size mismatch; driver ไม่อยู่ใน default build; ไม่มี proof filter/traffic effect |
| P0-5 | **Shutdown ไม่เป็น verified transaction** | STOPPED ถูกประกาศก่อน join, queue ไม่ drain, forensic ไม่ flush ตาม deadline, bridge spool ไม่ join |
| P0-6 | **Canonical identity/restart semantics ไม่ปลอดภัย** | process-local sequence, duplicate ยัง submit, ETW ID race; exactly-once และ forensic identity เชื่อถือไม่ได้ |
| P0-7 | **Current-head provenance/release graph invalid** | stale maps, 7 digest mismatch, missing artifacts, deployment root bug; ไม่รู้ว่า binary ที่รันตรง source ใด |
| P0-8 | **Canonical Go Nose ไม่อยู่ใน service deployment closure** | service อาจ healthy แต่ไม่มี network ingress จริง; E2E path ขาด component สำคัญ |
| P0-9 | **Runtime log มี failed/degraded execution และ segfault** | safety baseline ยังไม่ผ่าน และ log ผูก current binary ไม่ได้ |

### P1 — ต้องปิดก่อน operational acceptance

| ลำดับ | Blocker | ผลกระทบ |
|---:|---|---|
| P1-1 | Lifecycle/state authority แยกกันและไม่มี legal transition | health/status/SCM/operator อาจเห็นความจริงคนละแบบ |
| P1-2 | Control pipe ACL/identity และ replay/freshness ไม่ครบ | local pipe ไม่ใช่ authenticated RBAC boundary ตามเอกสาร |
| P1-3 | Active control protocol กับ docs/CLI/Brain ไม่ตรง | automation และ block path ไปไม่ถึง handler หรือได้ false acknowledgement |
| P1-4 | Rules/policy/config paths ซ้ำ | mutation สำเร็จบน file แต่ runtime ไม่ reload artifact เดียวกัน |
| P1-5 | ETW/FIM/Registry semantic fidelity ต่ำ | event type/path/opcode/identity ผิด ทำให้ policy และ forensic ผิด |
| P1-6 | Watchdog ไม่ check/restart และ worker heartbeat ไม่ครบ | worker death อาจไม่ถูกยกระดับเป็น degraded/recovery |
| P1-7 | Shared counters/audit/status snapshots มี data race | metrics และ audit ID อาจ duplicate/lost หรือ JSON อ่าน state ขณะ mutate |
| P1-8 | Go writer ไม่มี bounded spool/loss contract | consumer outage ทำให้ข้อมูลหายโดยไม่แยก intentional loss กับ failure |
| P1-9 | Installer/deploy/release authority หลายชุด | package อาจติดตั้งไม่ครบหรือ verify คนละ layout |

### P2 — ปิดเพื่อความถูกต้องและ maintainability

- ลบหรือ quarantine alternate C++/simulation/legacy paths ออกจาก production claims
- สร้าง generated maps/ABI manifest จาก current HEAD แทนการแก้มือ
- ทำ deterministic SBOM/archive metadata และ pin Npcap/WDK dependencies
- เพิ่ม lifecycle, queue, contract, malformed JSON และ exact command regression tests
- เพิ่ม forensic final-result record ที่ผูก request, identity, policy digest, PEP receipt, WFP filter และ rollback

## 11. Exact files และ symbols ที่ควรเปลี่ยนใน implementation phase

รายการนี้เป็น **change plan เท่านั้น** ไม่ใช่การแก้ในงานนี้

### 11.1 Lifecycle, shutdown และ concurrency

- `src/daemon.zig`: `RuntimeSupervisor`, `requestStop()`, `shutdown()`, `runDaemon()` startup barrier และ state publication ให้เป็น transaction owner เดียว; เพิ่ม bridge spool handle ownership และ verified postconditions
- `src/control/state_machine.zig`: `RuntimeState.transition()`, `recomputeHealth()`, `statusJson()`, `healthJson()`; เพิ่ม legal-transition table, STOPPING/READY/FAILED semantics และ locked snapshot serialization
- `src/control/handler_registry.zig`: `handlers.runtimeStart`, `handlers.runtimeStop`, `handlers.runtimeRestart`, `handlers.daemonShutdown`, `errorEnvelope()`; เปลี่ยนจาก direct state write/NOT_IMPLEMENTED เป็น request-to-supervisor และรอ/รายงาน pending vs verified completion
- `src/platform/win32_service.zig`: SCM service handler, serviceMain error/status path; map SCM stop/start กับ runtime transaction และ report failure code ที่ถูกต้อง
- `src/platform/win32_pipe.zig`: `serveWindowsPipe()`, `wakeControlPipe()`; bind readiness หลัง CreateNamedPipe สำเร็จ, ใช้ cancel/overlapped strategy หรือ explicit bounded wake contract, และตั้ง ACL/impersonation boundary
- `src/core/bridge_init.zig`: `initAll()`, `spoolDrainThread()`, `shutdownAll()`, `requestShutdown()`; เก็บ `std.Thread` handle, stop event, drain/free spool, join ก่อน socket/DLL/WFP teardown
- `src/pipeline/event_queue.zig`: `pushEvent()`, `popEvent()`, queue globals; ใช้ bounded MPMC algorithm ที่มี producer reservation correctness และ explicit close/drain/metrics
- `src/pipeline/runtime_state.zig`, `src/pipeline/event_processor.zig`: shared counters, `g_pipeline_audit_id`, `pipelineLoop()`; ใช้ atomic/locked snapshots, stop accepting → drain deadline → forensic flush และ producer/consumer conservation
- `src/reliability/watchdog.zig`: `check()` และ worker registration; heartbeat ทุก worker, supervisor polling, failure transition และ restart/quarantine policyที่มีหลักฐาน

### 11.2 Acquisition และ canonical identity

- `nose/capture.go`: `eventSequence`/event creation; เพิ่ม source/boot epoch หรือ daemon-issued identity, atomic sequence semantics, reconnect metadata และ counter taxonomy
- `nose/pipe_writer.go`: `FrameWriter`; bounded spool/backpressure/loss receipt และ explicit reconnect contract
- `src/capture/nose_pipe_reader.zig`: frame reader, duplicate/non-monotonic handling; reject/route duplicate ตาม policy และ publish epoch/counters
- `src/contract/canonical_event.zig`: `CanonicalEvent`, `validate()`, `nextEventId()`; freeze generated size/offset manifest and define restart/source identity
- `src/pipeline/telemetry_threads.zig`: `etwThread`, `fimThread`, `registryThread`; source-specific event mapping, heartbeats, success/failure counters, and no event count before enqueue
- `src/windows/etw_native.c`, `src/windows/etw_realtime.zig`: choose one implementation, unify provider GUID/record ABI/callback teardown and validate native layout
- `src/windows/fim_native.c`, `src/windows/fim.zig`: overflow/error propagation, path/operation mapping, bounded buffer policy
- `src/windows/registry_monitor.zig`: preserve registry kind/path/rule_id and use registry source/event type rather than `dns_query`
- `src/capture/windows_capture.zig`, `src/core/nids_capture.zig`: decide one WFP/legacy ingress owner and remove unobservable duplicate paths
- `bridge/aegis_ipc.hpp`, `bridge/aegis_ipc.cpp`, `bridge/aegis_adapter.cpp`, `src/capture/cpp_adapter.zig`: either remove from production claims or wire with canonical adapter, synchronization, identity assignment, real provider semantics and health truth

### 11.3 Policy, PEP และ WFP

- `src/daemon.zig`: policy load block; invoke mandatory `verifyPolicyWithStore()` before `PolicySet` creation/reload, preserve digest/version/signer/expiry/rollback state
- `src/policy/policy_signing.zig`, `src/policy/policy_plane.zig`: make signed canonical IR authoritative; remove hash-as-signature semantics and define TTL/priority/multi-clause behavior
- `src/pipeline/rule_loader.zig`: authenticate and atomically swap one canonical rules path; fail closed or explicitly detection-only when authenticity/parse fails
- `src/policy/pep_bindings.zig`: extend `PepContext/PepRequest` with authenticated identity, policy digest/version, epoch/nonce; return explicit authorized/submitted/applied/verified/failed/unavailable result
- `rust-src/lib.rs`: validate request identity, signature/digest, nonce/replay/quota and adapter receipt; do not trust caller-supplied capability/PID alone
- `src/windows/wfp_ioctl.c`, `src/policy/wfp_ioctl.zig`: converge read-only vs mutating contracts, secure device, unify error codes and ABI
- `src/windows/aegis_wfp.c`, `drivers/wfp_callout/aegis_wfp.c`, `drivers/wfp_callout/aegis_wfp_callout.c`: remove/gate alternate direct exports, fix action semantics, verify filter ownership and actual block behavior
- `rust-src/shield/src/lib.rs`, `src/core/rust_pep.zig`, `src/policy/policy_contract.zig`: label as advisory/test-only or remove duplicate authority and false-success paths

### 11.4 Control/CLI and operator contracts

- `src/control/protocol.zig`: make one command matrix authoritative; define wire fields for identity, request ID, issued time, nonce, timeout and postcondition
- `src/control/authorization.zig`: derive role from authenticated Windows token/SID/integrity level, not default `.operate`
- `src/control/handler_registry.zig`: fix/golden-test success and error envelope, enforce postconditions and use one audit ID source
- `src/platform/win32_pipe.zig`: tested SDDL/ACL and client impersonation
- `tools/aegisctl.py`, `tools/aegisctl/client.py`, `tools/aegisctl/api/control_api.py`, `tools/aegisctl/utils.py`: generate requests from active protocol, unify config path, remove local false-success, fix block syntax
- `brain/windows_brain.py`: call one supported active command and require verified PEP/WFP receipt
- `tools/aegisctl/commands/*.py`: retire or wire explicitly; do not leave a second command authority
- `scripts/aegis_daemon.py`, `scripts/aegis_block.py`, `scripts/aegis_api.py`, `scripts/aegis_event_gen.py`: mark deprecated, guard against alternate owner/enforcement, or migrate to active transport
- `src/policy/control_ipc.zig`, `shared/protocol/control_protocol.md`, `CONTRACT_MAP.json`: regenerate or retire legacy contract claims after decision

### 11.5 Build, deployment และ evidence

- `build.zig`: hard-fail missing fixtures/helpers, correct existence checks, stage all DLL/config/runtime dependencies and declare cross-language dependency order
- `Makefile`, `CMakeLists.txt`, `bridge/CMakeLists.txt`, `Cargo.toml`, `nose/go.mod`: create one orchestrator/artifact closure with names, target triples and hashes
- `tools/deploy_windows.py`: `SOURCE_ROOT`, `deploy()`, `build()`, `run_tests()`, `install_service()`; resolve repository root, include Go/bridge/native/driver/config, set working directory and start dependencies explicitly
- `tools/installer.py`, `installer.nsi`, `scripts/verify_release.ps1`: select one package authority and one layout; generate file directives from manifest and verify exact installed closure
- `.github/workflows/ci.yml`, `tools/ci_coverage.py`: make required toolchain/runtime/prerequisite absence fail, upload every consumed artifact, run Windows E3–E7 gates
- `tools/release_engineering.py`, `build_manifest.json`, `sbom.spdx.json`, `EVIDENCE_INDEX.json`, `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `runtime_manifest.json`, `build_truth.json`, `AI_CONTEXT.md`: regenerate from HEAD with deterministic IDs, commit binding and digest verification; never hand-edit current truth
- `tests/test_golden_path.py`, `tests/runtime/test_harness_integration.py`, `tests/e2e/test_t14_windows_golden_path.py`, `tests/adapters/test_t9_windows_adapters.py`, `tests/release/test_t17_perf_ci_installer.py`: separate static/proxy/live tests and make missing prerequisite a hard failure in required lanes

## 12. Safe development sequence

### Phase 0 — Freeze truth before code changes

1. Verify checkout is exactly `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` and record clean/dirty status.
2. Build a current-head manifest containing source hash, toolchain versions, dependency lock hashes, compiler flags, target, and all expected artifacts.
3. Regenerate maps/evidence index only through deterministic tooling; quarantine stale `688ab...` claims.
4. Do not enable prevention; use detection-only mode while P0 remains open.

### Phase 1 — Freeze contracts and authority

1. Decide whether Canonical Event v1 is the only ingress contract; define exact wire size/offsets and generated bindings.
2. Decide whether active JSON control or fixed-header binary control is authoritative; retire the other from production claims.
3. Decide that one supervisor owns lifecycle and one authenticated PEP broker owns mutation.
4. Publish a command/authority/ABI matrix and make CI reject unknown or duplicate owners.

### Phase 2 — Make data movement correct

1. Replace or formally serialize `event_queue` producer reservation.
2. Add source/boot epoch, duplicate rejection and loss accounting.
3. Unify event conversion; preserve ETW/FIM/Registry semantics and host identity.
4. Add conservation counters: captured, converted, enqueued, rejected, processed, action-requested, action-verified, dropped.
5. Stress all producers concurrently and force queue-full, reconnect and provider-overflow cases.

### Phase 3 — Make lifecycle and shutdown verifiable

1. Implement legal transitions and define READY versus RUNNING versus DEGRADED.
2. Publish control readiness only after bind success and make service running conditional on required gate.
3. Implement supervisor transaction: STOPPING → stop ingress → join producers → drain queue with deadline → flush forensic → join pipeline → join bridges → STOPPED.
4. Own/join spool thread and make SCM/control stop share the same transaction.
5. Integrate heartbeat/check/recovery or explicitly remove restart claims.

### Phase 4 — Secure and verify enforcement

1. Secure WFP device and pipe with OS-enforced caller identity and restrictive ACL.
2. Make signed policy, digest, version, expiry, rollback and replay checks mandatory.
3. Generate and assert Zig/Rust/C/driver ABI.
4. Return receipts with authenticated identity, policy digest, request ID, adapter result, filter ID and host verification.
5. Keep rate-limit/quarantine unsupported unless real adapters and tests exist.

### Phase 5 — Converge operator and packaging paths

1. Fix active CLI/Brain command contract and remove local false-success.
2. Unify rules/policies/forensics source paths and postcondition semantics.
3. Build one orchestrator that builds Zig, Rust, C/native, bridge and Go in dependency order.
4. Package service, configs, DLLs, Go Nose, driver/signatures and verification metadata in one manifest.
5. Set service working directory/profile and explicitly manage Go Nose lifecycle.

### Phase 6 — Evidence gates

Run, on a clean Windows host and one exact current-head bundle, in this order:

1. compile/link/ABI assertions and artifact hashes;
2. install/service registration and dependency closure;
3. control pipe ACL/RBAC negative tests;
4. one synthetic packet through Go Nose to forensic with unchanged event ID;
5. one ETW process event, one FIM change and one Registry change with semantic fields preserved;
6. queue multi-producer stress and conservation equations;
7. policy signature/tamper/expiry/rollback/replay tests;
8. PEP request to WFP filter and actual traffic block/unblock observation;
9. failure injection, crash/restart, SCM stop, control stop, timeout and complete join evidence;
10. clean-room install, upgrade, rollback, uninstall and manifest verification.

No phase should claim the next assurance level merely because source or static tests exist

## 13. Definition of Done

งานแก้ไขจะถือว่าเสร็จเมื่อเงื่อนไขทั้งหมดต่อไปนี้มีหลักฐาน current-head ที่ตรวจย้อนกลับได้

### Authority และ lifecycle

- มี owner เดียวของ lifecycle และทุก state transition ผ่าน legal-transition table
- `READY`, `RUNNING`, `DEGRADED`, `STOPPING`, `STOPPED` มี precondition/postcondition ชัดเจน
- SCM stop, control stop และ failure stop ใช้ supervisor transaction เดียวกัน
- supervisor ถือและ join worker ทุกตัว รวม bridge spool; ไม่มี thread ที่ spawn แล้วสูญ handle
- stop evidence แสดง producer stopped, queue drained/expired ตาม policy, forensic flushed และ join completion ก่อน STOPPED

### Data plane และ correctness

- ทุก ingress ใช้ contract ที่ประกาศเป็น authoritative หรือมี adapter ที่มี version/metrics ชัดเจน
- event ID ไม่ซ้ำข้าม reconnect/restart และ duplicate ถูก reject/record ตาม policy
- multi-producer stress ไม่มี corruption และ conservation equation อธิบายทุก drop/reject
- Go Nose, ETW, FIM และ Registry ส่ง event semantics, path/process identity และ source metadata ถึง detector/forensic ครบ
- queue-full, pipe outage, provider overflow และ restart มี bounded loss policy ที่ operator เห็นได้

### PEP/WFP security

- caller identity มาจาก Windows token/SID/integrity level และ device/pipe ACL ทดสอบกับ standard, low-integrity, foreign PID และ untrusted same-user process
- signed policy เป็น mandatory; tamper, unsigned, expired, rollback และ replay ถูก reject ก่อน mutation
- ABI manifest และ generated/asserted sizes/offsets ตรงกันระหว่าง Zig/Rust/C/C++/driver
- มี receipt ที่แยก authorized, submitted, applied, verified, failed และ unavailable
- block test สังเกต traffic effect และ WFP filter ownership จริง; ไม่ใช้ callout registration หรือ log เป็น proxy
- rate-limit/quarantine มี side effect จริงหรือคืน explicit unsupported/non-enforcing state

### Control/operator

- active protocol มี command matrix เดียวกับ CLI/Brain/docs และ request/response JSON/binary ผ่าน golden tests
- response success/error parse ได้ทุกกรณี รวม authorization denial/unknown command/large payload
- CLI mutation แก้ artifact เดียวกับ daemon reload และรอ verified postcondition
- ไม่มี legacy script/package ที่สร้าง owner หรือ enforcement path ที่ bypass authority หลัก

### Build/deployment/release

- clean host build ได้ด้วย orchestrator เดียวและมี dependency closure ครบ
- artifact ทุกตัวมี SHA-256, source HEAD, compiler/toolchain, signing/provenance และ ABI manifest
- installer มี layout เดียวและรวม executable, Go Nose, DLL, configs, driver/signatures, service metadata และ verifier
- service มี working directory/profile ที่แน่นอน และ start/stop dependency ครบ
- clean-room install/upgrade/rollback/uninstall ผ่าน พร้อม raw transcript และ hash manifest

### Evidence

- ทุก E3–E7 claim ผูกกับ current HEAD, host identity, command, raw output, timestamps และ artifact hashes
- EVIDENCE_INDEX/maps ไม่อ้าง stale revision และ `tools/truth.py verify` ผ่านโดยไม่มี pass-like skip สำหรับ required lane
- มีรายงาน health ก่อน/หลัง, event ID chain, queue counters, PEP request/response, WFP filter/effect, forensic/audit chain และ shutdown/join timing ใน bundle เดียว
- หาก gate ใดไม่ผ่าน ระบบยังถูกติดป้าย detection-only/degraded และไม่มี operator message ที่สื่อว่า prevention สำเร็จ

## 14. Final recommendation

ลำดับการลงทุนที่ปลอดภัยที่สุดคือ **แก้ truth/provenance → freeze canonical contracts/authority → แก้ queue/identity → ทำ lifecycle shutdown ให้ verified → ปิด OS authorization และ signed policy → converge CLI/build/deployment → สร้าง Windows E3–E7 evidence** ห้ามเริ่มจากการเปิด WFP block หรือเพิ่ม policy action ก่อน queue, identity, ABI, authorization และ receipt semantics ปิดครบ

ในสภาพปัจจุบัน ให้ใช้ AEGIS เป็นระบบตรวจจับและแจ้งเตือนแบบ degraded เท่านั้น จัด `PepDecision`, action log, simulation, historical evidence และ service status เป็น **intent/observation** ไม่ใช่หลักฐาน prevention effect จนกว่าจะมี current-head Windows evidence package ตาม Definition of Done

## References

[1]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.analysis/runtime.md "AEGIS runtime และ lifecycle analysis ที่ HEAD 46b93dc"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/daemon.zig "Current daemon orchestration source"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/event_queue.zig "Pipeline event queue source"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.analysis/security.md "PEP และ WFP security review ที่ current HEAD"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.analysis/control.md "CLI, control protocol และ operator path analysis"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.analysis/buildtest.md "Build, deployment, tests และ evidence analysis"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/control/protocol.zig "Active control command and contract source"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/control/handler_registry.zig "Active control dispatch and handler source"
[9]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/platform/win32_pipe.zig "Windows control named-pipe source"
[10]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/canonical_event.zig "Canonical Event v1 contract source"
[11]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/pep_bindings.zig "Zig/Rust PEP FFI binding source"
[12]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/deploy_windows.py "Windows deployment script"
[13]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/control/state_machine.zig "Runtime state machine source"
[14]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/runtime_state.zig "Runtime readiness and counter state source"
[15]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/etw_native.c "Native ETW helper source"
[16]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/fim_native.c "Native FIM helper source"
[17]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/rust-src/lib.rs "Rust PEP C ABI and WFP adapter source"
[18]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/CMakeLists.txt "Native and optional kernel-driver build configuration"
[19]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/capture.go "Go Nose packet capture and event identity source"
[20]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/pipe_writer.go "Go Nose named-pipe writer source"
[21]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/telemetry_threads.zig "ETW/FIM/Registry worker orchestration source"
[22]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/bridge/aegis_ipc.hpp "C++ bridge ring-buffer and IPC contract source"
[23]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/control_protocol.md "Documented legacy control protocol"
[24]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/aegis_nids.stderr.log "Historical/degraded Windows runtime log artifact"
[25]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build.zig "Zig build graph and artifact staging source"
[26]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/installer.py "Installer generator source"
[27]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/release_engineering.py "Release manifest and digest verifier source"
[28]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/test_golden_path.py "Static/golden-path test harness"
[29]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/windows_brain.py "Brain operator/enforcement invocation source"
[30]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/control_ipc.zig "Legacy fixed-header control IPC source"
[31]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/aegis_wfp.c "Direct user-mode WFP export source"
[32]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/drivers/wfp_callout/aegis_wfp.c "Kernel WFP callout source"
[33]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/configs/Rules.json "Runtime rules configuration"
[34]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/configs/policies.json "Runtime policy configuration"
[35]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/EVIDENCE_INDEX.json "Evidence index artifact requiring current-head regeneration"
[36]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build_manifest.json "Build manifest artifact requiring current-head regeneration"
[37]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.github/workflows/ci.yml "Declared CI build and test workflow"
[38]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/aegisctl.py "Active top-level CLI entrypoint"
[39]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/rule_loader.zig "Runtime rules loader and reload path"
[40]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/reliability/watchdog.zig "Reliability watchdog source"
