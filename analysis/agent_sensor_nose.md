# AEGIS Sensor / Nose / Go Source Audit

**ขอบเขต:** `nose/`, `sensor/` และ `adapters/` หากมี, Windows sensor/adapter source ที่เชื่อมกับ runtime, และ Go source ทั้งหมดที่ tracked ใน workspace `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`.

**Baseline ที่อ่านก่อนเริ่ม:** `/home/ubuntu/upload/AEGISProductionHandoff.md` (baseline `46b93dc`, 2026-09-23). งานนี้เป็น read-only audit; ไม่มี production source ถูกแก้ไข.

## Executive summary

Handoff ยืนยันว่า AEGIS อยู่ใน observe-only/qualification mode, prevention gate ต้องปิด และ production IPS blocker ที่ยังไม่ปิดคือ provider-backed `EnforcementReceipt v1`, exact WFP read-back, host postcondition และ exact cleanup proof. ผลตรวจ sensor พบความเสี่ยงเพิ่มเติมที่ทำให้ evidence chain จาก sensor ไป policy/forensic/receipt ยังไม่แข็งแรงพอสำหรับการเปิด gate แม้ผล qualification บางส่วนใน handoff จะผ่านแล้วก็ตาม.

ข้อสรุปสำคัญที่สุดคือ **เส้นทาง ETW ที่ runtime เรียกใช้มี C/Zig ABI ไม่ตรงกันอย่างมีนัยสำคัญ**: `etw_native.c` ส่ง struct ที่เริ่มด้วย `event_id:u32` แต่ `etw_realtime.zig` อ่าน pointer เดียวกันเป็น struct ที่เริ่มด้วย `timestamp_ns:i64` และมี `provider_guid` เป็น field ถัดไป (`src/windows/etw_native.c:20-38,55-89` เทียบ `src/windows/etw_realtime.zig:149-180,896-948`). หาก path นี้ถูกโหลดบน Windows จะตีความ timestamp/PID/provider/path ผิดและอาจอ่าน length/ข้อมูลผิดขอบเขต. นี่เป็น P0 สำหรับการอ้าง ETW เป็น production-grade telemetry หรือใช้ ETW evidence ประกอบ enforcement.

นอกจากนี้ Go Nose ใช้ `UnixNano()` เป็น `MonotonicNS` (`nose/capture.go:184-190`) จึงไม่ใช่ monotonic clock, สร้าง `event_id` แบบ process-local ที่ reset เมื่อ restart (`nose/capture.go:40-42,184-188`), และ writer drop frame เมื่อ pipe ไม่พร้อมหรือ write error โดยไม่ส่ง loss/gap marker (`nose/pipe_writer.go:116-147`). Zig reader รับ duplicate/non-monotonic ID แล้วเพียง log ต่อและยัง submit (`src/capture/nose_pipe_reader.zig:313-333`). ดังนั้น exactly-once ข้าม reconnect/restart ยังพิสูจน์ไม่ได้และใน source ปัจจุบันไม่ถูก enforce.

## วิธีตรวจและสถานะหลักฐาน

| ประเภท | ความหมายในรายงานนี้ |
|---|---|
| **Verified fact** | อ่านจาก source จริงและอ้าง path/line โดยตรง |
| **Inference** | ข้อสรุปเชิงพฤติกรรมจากหลายจุดของ source; ควรยืนยันด้วย Windows integration test |
| **Unknown** | source ไม่พอพิสูจน์ หรือยังไม่มี Windows/WDK runtime evidence |

Go toolchain ไม่มีใน sandbox (`go test ./...` ทั้ง `nose/` และ `go/aggregator/` จึงรันไม่ได้: `go: command not found`). ไม่มีการสรุปว่า tests ผ่านจากการอ่าน source เพียงอย่างเดียว.

## Findings by priority

### P0 — ต้องปิดก่อนอ้าง production IPS / ใช้ evidence เป็นฐาน enforcement

#### P0.1 — ETW C/Zig record ABI ไม่ตรงกัน (active runtime path)

**Verified fact:** C native record คือ `event_id:u32, version:u8, channel:u8, level:u8, opcode:u8, task:u16, keyword:u64, timestamp_ns:i64, process_id:u32, thread_id:u32, ...` (`src/windows/etw_native.c:20-38`). Zig อ่าน record เดียวกันเป็น `timestamp_ns:i64, provider_guid[16], event_id:u16, process_id:u32, ...` (`src/windows/etw_realtime.zig:149-180`). Native callback ส่ง `&out` ให้ callback โดยตรง (`etw_native.c:55-89`), และ Zig `EtwSource` ลงทะเบียน callback ที่รับ `*const EtwEventRecord` (`etw_realtime.zig:896-948`). ไม่มี translation/copy layer หรือ `@cImport` layout assertion ระหว่างสอง struct.

**ผลกระทบ:** timestamp, provider identity, event ID, PID และ variable-length fields ถูกอ่านจาก offset ผิด. `telemetry_threads.zig:55-73` ใช้ `rec.event_id` map process/file/registry kind และ `:59` ใช้ `rec.timestamp_ns`; ทั้งคู่จึงไม่น่าเชื่อถือ. ถ้า length fields ถูกอ่านผิดอาจนำไปสู่ `@memcpy` ที่ขนาดผิดใน downstream conversion. ETW readiness (`telemetry_threads.zig:31-45`) จึงไม่เท่ากับ valid ETW evidence.

**แก้แบบ testable:** ทำ ABI struct เดียวที่ shared ระหว่าง C/Zig หรือเขียน C-to-Zig normalization function; เพิ่ม `sizeof`, `offsetof`, field-value ABI test ที่ compile/run บน Windows; feed native fixture ที่มี known PID/timestamp/provider and assert exact `IpcEvent` fields. ห้ามเปิด IPS gate จาก ETW จน test นี้ผ่าน.

#### P0.2 — Handoff production IPS blocker ยังไม่ถูกแก้ด้วยงาน sensor นี้

**Verified fact from handoff:** `EnforcementReceipt v1` ยัง incomplete, exact WFP read-back ยังไม่ Windows/WDK compiled, host postcondition/cleanup absence proof ยังไม่ executed (`AEGISProductionHandoff.md:125-178,225-236,319-372`). ดังนั้น prevention gate ต้องปิดต่อไป. Sensor audit ไม่พบหลักฐานที่เปลี่ยนสถานะนี้.

**เหตุผลที่ sensor evidence เชื่อมกับ P0:** receipt ต้อง link `event_id`, trace/audit และ forensic evidence. เมื่อ source/provenance ถูกทิ้งที่ canonical-to-pipeline boundary (`src/pipeline/event_queue.zig:90-103`) และ event ID สามารถซ้ำข้าม Nose restart (`nose/capture.go:184-188`, `nose_pipe_reader.zig:257-320`) การอ้าง event chain เป็นหลักฐานอิสระของ host effect ยังไม่ปลอดภัย.

### P1 — ต้องแก้ก่อน production qualification ที่เชื่อถือได้

#### P1.1 — Exactly-once/monotonic ID ไม่ได้ enforce ข้าม restart และ `MonotonicNS` ไม่ monotonic

**Verified facts:** Go global `eventSequence` เริ่มจากศูนย์ต่อ process และ `eventFromPacket` ใช้ `atomic.AddUint64` (`nose/capture.go:40-42,184-188`). `MonotonicNS` ถูกเติมด้วย `time.Now().UnixNano()` (`nose/capture.go:185-190`) ซึ่งเป็น wall-clock epoch time ไม่ใช่ monotonic reading. Zig reader ตรวจ duplicate/regression เฉพาะภายใน connection, log แต่ไม่ reject (`src/capture/nose_pipe_reader.zig:255-320`), จากนั้น submit event เสมอ (`:324-333`). `canonical.submitEvent` ตรวจ magic/version/size เท่านั้น ไม่ตรวจ event ID non-zero, uniqueness หรือ source sequence (`src/capture/nose_contract.zig:123-149`).

**ผลกระทบ:** restart ของ Go Nose มีโอกาสออก ID ซ้ำกับ process รุ่นก่อน; reconnect อาจลดลง; two frames ที่มี ID ซ้ำยังเข้า queue. `MonotonicNS` เปลี่ยนลำดับตาม clock adjustment และ correlator ของ Go aggregator แปลงค่าโดยคูณ `1000` อีก (`go/aggregator/correlator.go:57-65`) ซึ่งไม่สอดคล้องกับ epoch-vs-monotonic semantics และมีโอกาส overflow/เวลาเพี้ยนเมื่อรับค่าระดับ `UnixNano`.

**แก้แบบ testable:** เพิ่ม runtime generation/boot UUID หรือ durable producer epoch + sequence ใน contract; reader ต้อง reject/quarantine duplicate และ regression พร้อม emit explicit gap/degraded record. ใช้ monotonic clock จริง (`time.Since(start)` หรือ platform monotonic API) แยกจาก wall timestamp. เพิ่ม restart/reconnect property test: no accepted duplicate identity, explicit gaps for all drops, sequence continuity per generation.

#### P1.2 — Canonical provenance และ host identity ถูกทิ้งตอนเข้า pipeline

**Verified fact:** `pushCanonicalEventWithPayload` สร้าง `IpcEvent`, คัดลอก event ID, timestamp, network tuple, rule/payload metadata แต่ไม่คัดลอก `ce.source`, `session_id`, `layer_id`, `is_pipe`, PID/PPID/node/confidence หรือ source classification (`src/pipeline/event_queue.zig:70-103`). `IpcEvent.init` จึงปล่อย `source=.system` และ zero context (`src/contract/event.zig:127-152`).

**ผลกระทบ:** เหตุการณ์จาก Go Nose ที่เป็น `npcap_sensor` ไม่ปรากฏ downstream ว่ามาจาก Nose; FIM/Registry/host/process provenance และ cross-tier source identity หาย. Forensic/policy link จึงตอบ “ใครเป็นผู้ผลิต” ไม่ได้ แม้ wire event ก่อนแปลงจะมีข้อมูลนั้น. นี่ขัดกับ handoff five-question/evidence chain (`README.md:183-225`).

**แก้แบบ testable:** กำหนด mapping contract ชัดเจน (`source -> IpcEvent.source`, `session_id -> trace_id/flow_id` หรือเพิ่ม field), preserve `layer/is_pipe/process/node/confidence`, และ test round-trip ทุก source kind ผ่าน `pushCanonicalEventWithPayload` แล้ว assert downstream fields.

#### P1.3 — Pipe backpressure ทำให้ capture block ได้ ทั้งที่ contract บอกว่า non-blocking

**Verified fact:** `FrameWriter.Send` ถือ mutex และเรียก `writeAll` ซึ่งวน write จนหมด frame (`nose/pipe_writer.go:47-67,122-147`). Named-pipe write เป็น synchronous; ไม่มี deadline, bounded queue หรือ context cancellation. หาก reader ช้า pipe buffer เต็ม การจับ packet จะค้างใน `Send`. หากไม่มี consumer/error จะ drop frame และลอง dial ใหม่ในทุก Send (`:125-147`), ไม่มี backoff despite module comment (`:13-15`).

**ผลกระทบ:** capture loss แบบไม่บอก core และ latency/packet loss แบบ unbounded เมื่อ consumer ช้า. `capture.go:158-161` นับ canonical ก่อนรู้ว่า Send สำเร็จ และ ignore return value; `droppedPipe` เป็นเพียง local log metric. ไม่มี degraded state ที่ Zig/control plane เห็น.

**แก้แบบ testable:** แยก bounded producer queue จาก writer; writer มี write deadline/cancel; กำหนดนโยบาย drop ที่ชัดเจนและส่ง loss range/gap event; expose sent/dropped/reconnect/error counters ใน health. Stress ด้วย slow reader, disconnected reader, reconnect และ sustained 10x queue capacity; assert capture loop ไม่ block และ every loss is observable.

#### P1.4 — Reader shutdown hang ได้หลังเปลี่ยนกลับเป็น blocking mode

**Verified fact:** `nose_pipe_reader` สร้าง pipe แบบ `PIPE_NOWAIT`, แต่หลัง connect เรียก `SetNamedPipeHandleState` ให้ byte-mode blocking (`src/capture/nose_pipe_reader.zig:235-249`). `readExact` เรียก blocking `ReadFile` และตรวจ stop flag ได้เฉพาะระหว่าง reads (`:133-157`). Supervisor join เรียก reader join (`src/daemon.zig:67-81`).

**Inference:** เมื่อ Go client ต่ออยู่แต่ไม่มีข้อมูล/ส่ง partial frame, `ReadFile` สามารถ block ไม่มีกำหนดและ `state.g_stop_requested` ไม่ปลุก thread; `supervisor.shutdown()` จึงอาจค้าง. Comment ใน reader ที่อ้าง shutdown pollable ใช้ได้เฉพาะช่วง connect ไม่ใช่ connected read.

**แก้แบบ testable:** ใช้ overlapped I/O + cancellation event หรือ keep NOWAIT/polling พร้อม timeout; add Windows test that connects, sends zero bytes/partial header, requests shutdown, and asserts join < bounded deadline.

#### P1.5 — ETW event loss และ lifecycle ไม่ได้ signal อย่างครบถ้วน

**Verified facts:** `EtwSource.start` เริ่ม native session/thread ก่อน แล้วค่อย `setCallback` (`src/pipeline/telemetry_threads.zig:31-45`, `src/windows/etw_realtime.zig:916-948`); events ก่อน callback registration จะถูกทิ้งโดยไม่มี counter. Native callback ไม่มี running/loss guard (`etw_native.c:55-89`). Native stop รอ consumer สูงสุด 5 วินาทีแล้วปิด handle/free properties (`etw_native.c:182-199`), แต่ไม่รายงาน timeout/degraded state. `EtwEventQueue` (alternate source) ใช้ plain `head/tail/count` ไม่มี mutex/atomics (`etw_realtime.zig:187-231`) ทั้ง callback และ consumer อาจเข้าพร้อมกัน.

**แก้แบบ testable:** register callback before enabling/starting consumption; add native lost-events callback/ETW buffer-loss counter and propagate to runtime health; lock or replace queue with SPSC/MPMC proven algorithm; stop test with blocked ProcessTrace and assert no callback-after-free.

#### P1.6 — FIM overflow/parse loss ถูกกลืน และไม่มี degraded/loss event

**Verified facts:** native FIM has 64 KiB buffer (`fim_native.c:10,35-37`) but Zig polls into 16 KiB (`src/windows/fim.zig:111-117,178-186`). If `bytes > out_len`, `aegis_fim_poll` clears `data_ready` and returns 0, losing the batch (`fim_native.c:111-125`). `ReadDirectoryChangesW` failure exits native thread without a runtime counter/degraded callback (`:35-53`). `parseNotifyRecord` checks `name_bytes` against entire raw buffer rather than the individual record boundary (`src/windows/fim.zig:69-101`), so malformed `next_offset` can make path parsing cross records.

**แก้แบบ testable:** return explicit overflow/error status, retain/rearm data or emit loss marker; make Zig buffer at least native max; validate `12+name_bytes <= record_len`; Windows burst test creates >16 KiB notifications and asserts loss counter/degraded health and no cross-record parse.

#### P1.7 — Registry ingestion is a signal-only watcher, not an attributed change event

**Verified facts:** `RegistryMonitor.startAll` hardcodes two HKLM paths (`src/windows/registry_monitor.zig:143-180`), while the trie may contain other configured paths. `pollNative` emits only `.value_changed` for the watched root (`:192-207`); it cannot identify which value/key changed. `telemetry_threads.registryThread` maps every result to `event.IpcEvent.init(.dns_query)` and sends an empty payload (`src/pipeline/telemetry_threads.zig:169-177`), so registry kind/path/rule ID are absent. Trie matching is case-sensitive (`registry_monitor.zig:64-91`) although Windows registry names are case-insensitive. `drain()` replaces the ArrayList without deinitializing the old allocation (`:232-236`), and `events` has no bounded capacity.

**ผลกระทบ:** persistence/critical-key attribution can be false negative or wrong; queue memory can grow without bound; downstream event type is DNS rather than registry. This is not sufficient evidence for a rule or enforcement decision.

**แก้แบบ testable:** normalize case, carry exact changed key/value and rule ID, map to `.reg_change`, bound queue with drop counter, deinit/drain ownership correctly, and use a Windows test that mutates Run/Services/SAM keys and asserts exact path/rule/event kind.

#### P1.8 — ETW/FIM/Registry `IpcEvent` IDs and metadata are mostly zero/default

**Verified facts:** `telemetry_threads.etwCallback` sets `ev.event_id = diag.metrics.events_emitted.get()` then increments after push (`src/pipeline/telemetry_threads.zig:55-82`), so first event can be zero and IDs are a global metric snapshot, not a producer identity. FIM and Registry construct events with `IpcEvent.init` but never set event_id (`:126-131,172-177`). They also do not fill PID/rule/source-specific context. In the C++ adapter framework, `initFrame` explicitly leaves event ID zero with a comment that a sink assigns it (`bridge/aegis_adapter.cpp:120-134`), but `src/windows/cpp_adapter.zig:190-215` deserializes and calls `nose_contract.submitEvent` without assigning one.

**แก้แบบ testable:** one authoritative identity minting boundary with non-zero IDs, producer/generation fields, and atomic allocation; reject zero at fabric submit; assert all ETW/FIM/Registry/C++ events carry unique IDs and source metadata.

#### P1.9 — Runtime readiness can report RUNNING while canonical Nose capture is absent

**Verified facts:** daemon readiness barrier waits pipeline/ETW/FIM/Registry, not Go producer connection (`src/daemon.zig:441-458`). A successful Zig pipe server sets `g_nose_ready` even when no client is connected (`src/capture/nose_pipe_reader.zig:195-205`), and runtime state gates primary RUNNING only on pipeline failure (`daemon.zig:493-500`). Go headless health hardcodes `RUNNING`, `last_event_ms=0`, all counters zero and core dependency RUNNING (`nose/main.go:155-176`) regardless of Npcap/pipe state.

**ผลกระทบ:** operator can see healthy/ready while no network events are being captured. Handoff explicitly says RUNNING/nose_connected is qualification evidence; source implementation does not make this a durable degraded truth during disconnect/loss.

**แก้แบบ testable:** distinguish `pipe_server_ready`, `producer_connected`, `capture_active`, and `last_event`; promote health only after first successful capture or explicit observe-idle state; demote on disconnect/error and recover on reconnect; add live health assertions.

#### P1.10 — Canonical wire contract has Go enum/schema drift and weak Go validation

**Verified facts:** Zig canonical EventType ordinals are block=0, match=1, forward=2, ip_blocked=3, rejected=4, session_start=5 (`src/contract/canonical_event.zig:246-258`), while Go named constants say `EventForward=1`, `EventAlert=2`, `EventCustom=3`, `EventSessionStart=4` (`nose/canonical.go:99-113`). Go aliases used by capture (`TypeMatch=1`, `TypeForward=2`) happen to match, but the public Go vocabulary is inconsistent. Go policy constants say `PolicyBlock=1`, while Zig policy enum is allow=0, alert=1, block=2, quarantine=3, rate_limit=4, log_only=5 (`canonical.go:124-134`; Zig `:260-267`). Go `Serialize` validates source range and confidence only (`nose/canonical.go:190-235`); `Deserialize` parses fields without checking magic/version/struct size/enums (`:238-276`).

**ผลกระทบ:** future Go callers using named `EventForward`/`PolicyBlock` can emit semantically wrong bytes; Go-side malformed input can be accepted. Current Go canonical golden tests cover selected aliases, not the full enum contract.

**แก้แบบ testable:** generate enums from one contract or add compile-time/golden tests for every ordinal; make Go Deserialize return error and validate magic/version/struct size/source/event/policy/confidence; remove misleading constants.

#### P1.11 — IPv6 identity and payload hash semantics are lossy/inconsistent

**Verified facts:** Go canonical wire has only u32 IPv4 fields; `eventFromPacket` stores only first 4 bytes of each IPv6 address (`nose/capture.go:213-223`). The Zig rich parser also stores full IPv6 only in `PacketInfo`, but `toCanonicalEvent` writes the four-byte canonical fields and does not serialize full v6 identity (`src/capture/npcap_capture.zig:614-665`). Go comments claim canonical payload hash is SHA-256 prefix, but `eventFromPacket` uses `quickHash` FNV-1a 64 (`nose/capture.go:242-260`).

**ผลกระทบ:** IPv6 flows can collide/misattributed by prefix; cross-language dedup/hash equality is not guaranteed. This is especially unsafe for exact-flow evidence.

**แก้แบบ testable:** add v6 extension/sidecar identity or explicitly mark v6 truncated; standardize cryptographic hash algorithm and test Go/Zig/C++ byte vectors for payloads.

### P2 — แก้เพื่อ maintainability/secondary paths and low-cost quality

1. **C++ adapter framework emits synthetic keepalives rather than real telemetry.** `FimAdapter`, `RegistryAdapter`, and `EtwAdapter` emit fabricated periodic frames (`bridge/aegis_adapter.cpp:213-289`), while `windows_adapters.zig` Windows implementations are comments/stubs returning null (`src/windows/windows_adapters.zig:135-170,255-287,377-410`). These paths must be labelled non-production or removed from capability claims; they are not equivalent to the active `telemetry_threads` path.
2. **C++ adapter poll capacity check is incomplete.** `aegis_adapter_poll` checks `canonicalCap < f.size` per iteration but writes at `canonicalBuf + n*f.size` (`bridge/aegis_adapter.cpp:427-448`); a caller with capacity for only one frame can overflow on the second event. Wrapper currently allocates enough, but ABI function itself is unsafe.
3. **C++ IPC bridge is a separate incompatible 72-byte schema and has overlapped-I/O misuse.** `bridge/aegis_ipc.hpp:64-109` defines a packed 72-byte event with schema version 2, unlike Zig 96-byte `IpcEvent` and canonical 109-byte wire. `aegis_ipc.cpp:75-93,134-145,172-229` opens Windows pipes with `FILE_FLAG_OVERLAPPED` but calls Connect/Read/Write with null OVERLAPPED and assumes one complete transfer; no partial I/O/reconnect framing is implemented. This appears legacy/inactive for Go Nose, but must not be presented as the same transport.
4. **Go Nose capture error path exits the whole process from a goroutine.** `nose/main.go:104-117` calls `os.Exit(1)` from the capture goroutine, bypassing coordinated shutdown and making error evidence/flush unreliable. It listens only for `os.Interrupt`, not a context/supervisor-controlled termination path.
5. **Go Nose health/TUI collector goroutines are not stoppable and traffic falls back to simulation.** `nose/collectors.go:111-137,149-211` contains infinite loops; missing real traffic deliberately returns synthetic top talkers/protocol data (`:154-195,207-211`). This must never feed production health/evidence; add explicit `simulated=true` or disable it.
6. **Go IPCReader has no Stop and is not wired to lifecycle.** `nose/ipc_reader.go:36-63` starts an unbounded polling goroutine and no caller shutdown method; file status can remain stale.
7. **Aggregator dedup is not exactly-once and loses distinct events.** Hash is only `rule|src_ip|event` (`go/aggregator/alert.go:49-53`), so same rule/IP/event across sessions, destination, time, and payload is collapsed. Collector does not ingest `event_id` (`go/aggregator/collector.go:21-34`), starts at EOF (`:70-89`), advances offset past an incomplete final line (`:147-188`), and does not handle rotation/rename. The aggregator health hardcodes counters and `last_event_ms=0` (`go/aggregator/main.go:246-273`).
8. **Aggregator has lifecycle/race risks.** `correlateAlerts` and `purgeLoop` run forever with no stop channel (`go/aggregator/main.go:147-177`). `GetAll` returns internal pointers under a read lock then callers use them after unlock (`go/aggregator/alert.go:121-131`); Correlator returns mutable timeline pointers (`go/aggregator/correlator.go:68-100`). `Collector.Stop` is not idempotent (`go/aggregator/collector.go:191-195`). Run `go test -race` after toolchain installation.
9. **Registry drain leaks old ArrayList backing storage.** See `src/windows/registry_monitor.zig:232-236`; retain/deinit ownership must be explicit.
10. **Native ETW/FIM helpers lack complete error/loss counters.** A Windows health payload should expose callback registration drops, provider enable failures, buffer overflow, `ERROR_NOTIFY_ENUM_DIR`, read timeout, reconnect, and shutdown timeout separately; current runtime mostly logs and marks ready/failure only.

## Ingestion and lifecycle matrix

| Path | Actual source inspected | Ordering/ID | Backpressure/loss | Restart/shutdown | Attribution assessment |
|---|---|---|---|---|---|
| Go Npcap -> Go writer -> Zig Nose pipe | `nose/capture.go`, `nose/pipe_writer.go`, `src/capture/nose_pipe_reader.zig` | process-local sequence; no cross-restart epoch; wall clock in monotonic field | synchronous write can block; drops local only; queue-full drops counted but no gap event | reconnect attempts exist but no bounded backoff; reader connected read can hang on stop | network tuple present; v6 truncated; source later discarded by queue mapping |
| ETW native -> Zig callback -> pipeline | `src/windows/etw_native.c`, `src/windows/etw_realtime.zig`, `src/pipeline/telemetry_threads.zig` | no authoritative event ID; first callback ID may be 0 | native/reader loss not surfaced; alternate queue unsynchronized | stop timeout not health-signalled; callback registration race | P0 ABI mismatch; PID/provider/timestamp not trustworthy |
| FIM native -> Zig normalization -> pipeline | `fim_native.c`, `fim.zig`, `telemetry_threads.zig` | no event ID; timestamp generated at parse | 64K native vs 16K Zig, overflow discarded | CancelIoEx/worker stop exists but failures not propagated | path payload only; no root/rule/process in event |
| Registry notify -> Zig monitor -> pipeline | `registry_monitor.zig`, `telemetry_threads.zig` | no event ID; root signal only | unbounded `ArrayList`; append errors ignored in native poll | key/event handles closed; rearm error ignored | wrong `dns_query` kind, no changed value, case-sensitive trie |
| C++ adapter framework -> `cpp_adapter.zig` | `aegis_adapter.cpp/.hpp`, `cpp_adapter.zig` | event ID always 0 unless external sink assigns; sink does not assign | poll ABI capacity bug | stop/destroy ownership exists but handles can stale after registry destroy | synthetic events; C++ Windows timestamp uses uptime (`aegis_adapter.cpp:108-114`) |
| C++ legacy IPC | `aegis_ipc.cpp/.hpp` | separate 72-byte schema, no canonical identity alignment | queue claims ring but no mutex/atomics | overlapped handles used synchronously; no reconnect | do not combine with Nose contract |

## Test coverage: verified and missing

**Present:** Go golden vector and selected synthetic packet/classifier tests (`nose/canonical_test.go:71-272`); Zig canonical golden vectors/validation; pure packet parser tests including VLAN/IPv6/ARP; FIM record parser tests; Registry trie/observe tests; ETW queue/conversion unit fixtures; C++ adapter self-test/unit harness files; aggregator unit tests for dedup/eviction/correlation.

**Missing or insufficient for release:**

- Windows-compiled C/Zig ETW ABI layout/value tests and callback-after-stop tests.
- Real Windows ETW provider enablement and event-ID/provider/PID/timestamp validation.
- FIM overflow (`ERROR_NOTIFY_ENUM_DIR`/large burst), partial/malformed chained records, native stop timeout, and proof-root end-to-end tests.
- Registry case-insensitivity, exact changed value/key, inaccessible key, rearm failure, bounded queue and drain ownership tests.
- Go `FrameWriter` slow-reader/disconnect/reconnect/write-short-write tests; sustained loss and health degradation assertions.
- Go Nose restart/reconnect identity tests proving no duplicate IDs and explicit gaps; monotonic clock tests under wall-clock adjustment.
- Cross-language tests for every enum ordinal, invalid Go deserialization, IPv6 identity, and payload hash algorithm.
- `go test -race` for Nose and aggregator; concurrent producer/consumer Windows queue tests.
- End-to-end event chain test asserting canonical source/session/process/node metadata survives into `IpcEvent`, forensic record, policy decision, and receipt linkage.
- Shutdown test with connected idle/partial Nose pipe and ETW/FIM workers, bounded supervisor join, no leaked process/handle/session.
- Rotation/truncated-line/restart recovery tests for `go/aggregator/collector.go`.

## Low-credit, testable next steps (recommended order)

1. **Do not open prevention gate.** Preserve handoff P0 receipt/read-back/cleanup gate; record this sensor audit as an additional evidence blocker.
2. Add a small Windows-only ABI fixture executable that creates one C `aegis_etw_event_t`, calls the Zig normalization boundary, and asserts every offset/value. This is cheaper and more decisive than a full ETW run.
3. Add a deterministic Go test for two `runCapture` generations: serialize IDs 1..N, restart, serialize again, feed reader validator, and assert rejection/gap behavior after the contract is defined.
4. Add an in-memory `FrameWriter` fake with a blocked/short-write/disconnect script; assert capture never blocks beyond deadline and loss counters/markers are visible.
5. Add a canonical-to-`IpcEvent` mapping test that sets every provenance/identity field and checks no field is silently defaulted.
6. Change FIM polling buffer to the native maximum and add one synthetic chained buffer with `next_offset`/name boundary corruption; assert explicit loss/error, not silent zero.
7. Add registry fixture tests for case variants and rule IDs, and assert emitted kind/path/rule are preserved. Make drain ownership bounded and leak-free.
8. Install Go 1.22+ on the Windows qualification host and run `go test -race ./...` in both `nose/` and `go/aggregator`; then run the handoff Zig/Windows/WDK gates.
9. Only after these observe-path proofs, implement the handoff’s provider-backed receipt, exact tuple read-back, cleanup and post-cleanup absence proof, then rebuild/reverify the RC.

## Unknowns requiring Windows evidence

- Whether the checked-in `aegis_etw_helper` ABI is the exact DLL used by the qualified RC and whether another generated header masks the layout mismatch.
- Whether Go Npcap `time.Now().UnixNano()` is intentionally being treated as an event-time surrogate by downstream consumers; source and contract call it monotonic, so this requires an explicit decision, not assumption.
- Whether the C++ adapter framework and 72-byte bridge are loaded/used by the current release runtime; daemon source visibly uses direct telemetry threads and Go Nose pipe, but bridge initialization is separate.
- Whether Windows named-pipe default ACLs in `nose_pipe_reader.zig` are acceptable for the deployment account; no explicit security descriptor is set for `aegis_nose`.
- Whether the provider GUID arrays used by `EtwSource` (`PROVIDER_KERNEL_*_RT`) are correct for the target Windows ETW session; no live provider enumeration evidence is in this workspace.
- Whether current handoff qualification counters were gathered from the exact baseline source/RC and whether sensor health exposed drops during the run; source health currently underreports them.

## Final disposition

The source contains useful observe-only building blocks and good pure-parser/contract fixtures, but **the sensor fabric is not yet an exactly-once, loss-transparent, restart-safe evidence path**. The most urgent source defect is the active ETW ABI mismatch. The next urgent defects are canonical provenance loss, process-local/restart-unsafe IDs, blocking pipe backpressure and shutdown, silent FIM/Registry loss, and false RUNNING health. These issues do not authorize host mutation; they reinforce the handoff decision that production IPS remains **not approved** until the complete provider-backed receipt and independent WFP postcondition/cleanup proof exists.

## Primary files reviewed

`nose/canonical.go`, `nose/canonical_test.go`, `nose/capture.go`, `nose/collectors.go`, `nose/golden_path_ffi.go`, `nose/ipc_reader.go`, `nose/main.go`, `nose/model.go`, `nose/pipe_writer.go`, `nose/signature_classifier.go`, `nose/styles.go`, `nose/go.mod`, `nose/go.sum`; `go/aggregator/alert.go`, `alert_test.go`, `collector.go`, `correlator.go`, `correlator_test.go`, `main.go`, `go.mod`; `src/contract/canonical_event.zig`, `event.zig`, `event_queue.zig`, `nose_contract.zig`; `src/capture/nose_pipe_reader.zig`, `npcap_adapter.zig`, `npcap_capture.zig`, `packet_decoder.zig`, `windows_capture.zig`; `src/pipeline/event_queue.zig`, `runtime_state.zig`, `packet_callback.zig`, `telemetry_threads.zig`; `src/windows/etw_native.c`, `etw_realtime.zig`, `fim_native.c`, `fim.zig`, `registry_monitor.zig`, `registry_trie.zig`, `windows_adapters.zig`, `cpp_adapter.zig`, `host_telemetry.zig`; `src/core/nids_capture.zig`; `bridge/aegis_adapter.cpp`, `aegis_adapter.hpp`, `aegis_ipc.cpp`, `aegis_ipc.hpp`, `aegis_bridge_main.cpp`, `aegis_adapter_selftest_main.cpp`, `aegis_bridge_test.cpp`; relevant runtime health test `tests/runtime/test_health.py`; repository README and production handoff.

No production source was modified by this audit.
