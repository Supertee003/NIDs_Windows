# Deep Audit 03 — Go Nose และ Zig Packet Ingress

**ขอบเขต:** `nose/**/*`, `go/**/*`, `src/capture/**/*`, canonical event contracts และ tests ที่เกี่ยวข้อง

**Repository ที่ตรวจ:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`

**วิธีตรวจ:** ใช้ `git ls-files` เป็น inventory แล้วอ่าน source จริงใน path ที่ระบุด้านล่าง ไม่แก้ source ไม่รัน controlled host block และไม่ใช้ `netsh`, Windows Firewall API, `legacy block_ip` หรือ bookkeeping เป็นหลักฐาน enforcement

## สรุปผล

ขอบเขตนี้ **ยังไม่ควรเรียกว่า production-ready**. มีการแยกหน้าที่เชิงสถาปัตยกรรมที่ถูกทิศทาง: Go Nose เปิด Npcap แบบ passive แล้วส่ง event ไป named pipe; Zig เป็นผู้รับและส่งต่อเข้า detector/policy pipeline; Nose ไม่มีการเรียก WFP โดยตรง. อย่างไรก็ตาม เส้นทางจริงมีช่องว่างระดับความถูกต้องและความปลอดภัยที่กระทบความน่าเชื่อถือของ event ingress โดยตรง.

ประเด็นที่ต้องแก้ก่อนรับรองมีห้ากลุ่มหลัก. ประการแรก named pipe ไม่มี security descriptor หรือการตรวจตัวตนของ client ใน source ที่ตรวจพบ. ประการที่สอง length-prefix และ `readExact` ยอมให้ input ที่ควบคุมได้ตรึง reader หรือทำให้ shutdown ค้าง. ประการที่สาม event identity เป็น process-local, ถูกตรวจเพียงภายใน connection และ duplicate/non-monotonic event ยังถูก submit ต่อ. ประการที่สี่ wire path ที่ใช้งานจริงเป็น `4-byte length + 109-byte payload` ซึ่งข้าม frozen `WEV1 + CRC32` contract ขนาด 125 bytes. ประการที่ห้า adapter จาก canonical event ไป pipeline event ทิ้ง source/provenance และ session identity ทำให้ข้อมูลที่ตรวจพบไม่คงอยู่ครบตลอดเส้นทาง.

ผล local test ที่ทำได้มีข้อจำกัดจาก execution environment: ไม่มี `go` และ `zig` ใน `PATH`, จึงรัน Go/Zig unit tests ไม่ได้. Python reference codec self-test ผ่าน และ Python syntax compilation ของ test/reference files ผ่าน. ผลดังกล่าวยืนยันได้เฉพาะ Python reference ไม่ใช่หลักฐานว่า Windows Npcap, named pipe หรือ Go/Zig binary ทำงานถูกต้องจริง.

## Inventory และ files reviewed

ใช้ `git --no-optional-locks ls-files` และตรวจ path จริง. รายการด้านล่างเป็น path ที่อยู่ในขอบเขตหรือเป็น dependency โดยตรงของ ingress/canonical contract.

### Go Nose

- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/README_DEPLOY.txt`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/canonical.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/canonical_test.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/capture.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/cleanup_nose_mouth.bat`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/collectors.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/go.mod`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/go.sum`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/golden_path_ffi.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/inject.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/ipc_reader.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/main.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/model.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/pipe_writer.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/run_nose.bat`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/signature_classifier.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/nose/styles.go`

### Go aggregator

- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/README.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/alert.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/alert_test.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/collector.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/correlator.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/correlator_test.go`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/go.mod`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/go.sum`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/go/aggregator/main.go`

### Zig capture/ingress

- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/flow_engine.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/flow_table.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/flow_types.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/minifilter_reader.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/nose_contract.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/nose_pipe_reader.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/npcap_adapter.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/npcap_capture.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/npcap_test_live.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/packet_decoder.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/pipe_monitor.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/proto/parsers.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/stream_reassembly.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/capture/windows_capture.zig`
- `src/ingest/**/*` — **ไม่มีไฟล์ tracked และไม่พบ directory ใน repository**

### Canonical contracts, pipeline และ runtime wiring

- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/canonical_event.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/event.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/event_fabric.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/event_queue.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/runtime_manifest.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/runtime_spine.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/contract/wire_event.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/core/contract_freeze.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/core/priority_queue.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/daemon.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/event_processor.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/event_queue.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/packet_callback.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/runtime_state.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build.zig`

### Contract documents, C/Python reference และ test evidence

- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/docs/contracts/canonical-event-v1.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/event/canonical_event.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/control_protocol.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/protocol.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/protocol_version.json`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/versioning.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/wire_v1.h`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/protocol/wire_v1.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/schema/canonical_event_v1.h`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/wire/golden_path_ffi.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/wire/wire_codec.h`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/wire/wire_codec.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/capture/flow_table.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/capture/npcap_adapter.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/capture/packet_decoder.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/capture/proto/parsers.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/capture/stream_reassembly.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/cli/nose_pipe_e2e_cli.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/contract/event.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/contract/runtime_manifest.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/integration/golden_path_e3.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/integration/golden_path_ffi.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/tests/integration/nose_integration.zig`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/aegis_nose_test.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/tests/aegis_nose_test.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/README.md`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/event_v1_001.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/event_v1_002.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/event_v1_003.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/event_v1_004.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/event_v1_005.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/golden_vectors.json`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/event_vectors/vectors_metadata.json`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/contracts/event_vectors/generate_test_vectors.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/runtime/test_wire.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/test_e2e.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/test_golden_path.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/vectors/event_vectors.py`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/tests/contracts/canonical_event.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/tests/contracts/test_vectors.json`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/tests/contracts/wire_event.bin`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/configs/Rules.json`
- `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/configs/schema.json`

## Call/data/control flow ที่ตรวจพบ

### เส้นทาง Go Nose ซึ่งเป็น production network ingress ตาม daemon wiring

1. `nose/main.go:43-54` parse flags. เมื่อใช้ `-capture`, `main.go:104-117` สร้าง `stop` channel แล้วเริ่ม `runCapture` ใน goroutine. Go process รอ `os.Interrupt`; ไม่มี control pipe หรือ privilege transition ใน Nose.
2. `nose/capture.go:102-130` โหลด signature rules จาก path ใน environment หรือ `configs/Rules.json`, auto-select Npcap device ผ่าน `pcap.FindAllDevs`, เปิด `pcap.OpenLive(iface, 65535, false, 1s)`, ติด BPF `ip or ip6`, แล้วสร้าง `FrameWriter`.
3. `nose/capture.go:141-160` อ่าน packet ด้วย `ReadPacketData`, สร้าง gopacket แบบ `NoCopy`, เพิ่ม packet counter, เรียก `eventFromPacket`, เรียก `classifyNosePacket`, serialize canonical event และเรียก `FrameWriter.Send`. `Send` result ถูกทิ้งใน `capture.go:160`; ตัวนับ canonical ถูกเพิ่มก่อนยืนยันว่าผู้รับได้รับ frame.
4. `eventFromPacket` สร้าง `CanonicalEvent` ที่ `nose/capture.go:184-250`. Event ID มาจาก `atomic.AddUint64(&eventSequence, 1)`, source เป็น 9 (`npcap_sensor` ตาม Go/Zig implementation), event type เป็น forward, policy เป็น log-only. IPv4 เก็บ 5-tuple; IPv6 เก็บเพียง 4 bytes แรกของแต่ละ address. `MonotonicNS` ใช้ `time.Now().UnixNano()`, ซึ่งเป็น wall-clock Unix nanoseconds ไม่ใช่ monotonic clock.
5. `nose/pipe_writer.go:112-153` serialize 109-byte canonical payload แล้ว prepend u32 little-endian length `109`, รวมเป็น 113 bytes. `writeAll` ป้องกัน short write แต่ไม่มี timeout หรือ bounded write deadline. เมื่อ pipe ไม่พร้อมหรือ write ล้มเหลว event ถูก drop และ connection ถูกปิด.
6. `nose/inject.go:15-64` เป็น observe-only fixture path. มันใช้ retry 20 ครั้งทุก 100 ms แต่ retry นี้มีเฉพาะ injection; live capture ไม่มี bounded wait/retry semantics แบบเดียวกัน. Fixture ไม่ได้เรียก WFP.

### Boundary Go process → Zig process/privilege

Go Nose เป็น process แยกจาก Zig daemon และไม่มี code path ไป WFP. Named pipe `\\.\pipe\aegis_nose` เป็น local process boundary. Zig daemon startup ที่ `src/daemon.zig:406-418` ระบุว่า direct Zig Npcap path ถูกปิดใน production และ spawn `nose_pipe_reader.runPipeReaderLoop`; ดังนั้น production network ingress ที่ประกาศไว้คือ Go → named pipe → Zig.

### เส้นทาง Zig named-pipe reader → detector/policy

1. `src/capture/nose_pipe_reader.zig:101-131` สร้าง named pipe แบบ inbound, byte mode, NOWAIT, instance เดียว และ input buffer 256 frames. `lpSecurityAttributes` เป็น `null`.
2. `:207-249` poll `ConnectNamedPipe`, รองรับ reconnect ด้วย `DisconnectNamedPipe`, แล้วเมื่อ client connected เปลี่ยน handle เป็น blocking byte-mode ที่ `:238-239`.
3. `:133-158` อ่าน header/payload แบบ exact read. `:263-299` รับเฉพาะ length 109; length อื่นถูกอ่านทิ้ง. `:305-333` เรียก `canonical.deserializeFromBytes`, ตรวจ event ID ซ้ำ/ถอยหลังเฉพาะ connection แต่เพียง log/counter แล้ว submit ต่อ.
4. จุด submit จริงคือ `pipeline_queue.pushCanonicalEvent(&event)` ที่ `:324-333`, ไม่ใช่ `nose_contract.submitEvent`. `src/pipeline/event_queue.zig:70-103` แปลง canonical ไป `IpcEvent` และ enqueue bounded pipeline queue.
5. `pushCanonicalEventWithPayload` คัดลอก event ID, timestamp, IP, ports, protocol, rule, payload metadata และ context flags แต่ไม่คัดลอก `source`, `session_id`, `direction`, `is_pipe`, `policy_action` หรือ provenance อื่น. `IpcEvent` จึงไม่คง identity/provenance ครบ.
6. `src/pipeline/event_processor.zig:47-200` นำ `IpcEvent` ไป flow lookup, signature/anomaly/threat tracking, policy evaluation, PEP decision, action dispatcher และ forensic recording. Boundary นี้เป็น detection/policy/enforcement downstream; Go Nose เองไม่ได้ enforce.

### Zig direct Npcap path ซึ่งมีอยู่แต่ daemon ปิดไว้

`src/capture/npcap_adapter.zig` และ `src/pipeline/packet_callback.zig` เป็นอีก implementation หนึ่งของ Npcap. `packet_callback.captureThread` เปิด Npcap และ push `IpcEvent` โดยตรง. แต่ daemon ระบุชัดที่ `src/daemon.zig:406-412` ว่าปิด path นี้เพื่อไม่ให้ duplicate กับ Go Nose. `src/capture/npcap_capture.zig` เป็น dynamic-loader/parser และ live diagnostic (`npcap_test_live.zig`) มากกว่า production authority ตาม wiring ปัจจุบัน.

## Critical findings

### C-01 — Named pipe ไม่มี caller authorization หรือ explicit security descriptor

**หลักฐาน:** `src/capture/nose_pipe_reader.zig:54-63, 99-119`; Go client `nose/pipe_writer.go:100-109` เปิด path โดยตรง ไม่มี handshake/authentication.

`CreateNamedPipeW` รับ `lpSecurityAttributes = null` และ source ไม่มี SDDL, ACL allow-list, client-token impersonation หรือการตรวจว่า client เป็น Go Nose ที่ได้รับอนุญาต. Reader รับ canonical event จาก process ใดก็ตามที่เชื่อม `\\.\pipe\aegis_nose` ได้. การกำหนด `nMaxInstances=1` ช่วยเรื่อง ownership แต่ไม่ใช่ authentication. Input ที่ปลอมแปลงสามารถทำให้ detector/policy/forensic pipeline ประมวลผล event ที่อ้าง source, severity, rule และ identity ที่ผู้โจมตีเลือกเอง หรือยึด connection ของ Go Nose เพื่อทำ availability attack.

**ผลกระทบ:** เป็นการขาด trust boundary ในจุดนำข้อมูลเข้า privileged daemon. ยังไม่มีหลักฐานใน source ว่า named pipe มีสิทธิ์จำกัดตามที่ handoff กล่าวถึง. ห้ามถือว่า local named pipe ปลอดภัยโดยอัตโนมัติ.

**การแก้ที่ต้องมี:** ใช้ explicit security descriptor ที่จำกัด SID/service identity และตรวจ client token หลัง connect; ผูก protocol handshake กับ producer identity/epoch; reject client ที่ไม่ผ่าน authorization ก่อนอ่าน event. เพิ่ม Windows integration test ที่รันด้วย user ที่อนุญาตและไม่อนุญาต.

### C-02 — Unbounded length/discard และ blocking read ทำให้ reader ถูกตรึงและ shutdown/reconnect ไม่ deterministic

**หลักฐาน:** `src/capture/nose_pipe_reader.zig:133-158, 235-239, 263-290`.

`readExact` มี polling เมื่อ handle เป็น NOWAIT แต่ code เปลี่ยน handle เป็น blocking mode ทันทีหลัง connect (`:238-239`). หาก client ส่ง header แล้วไม่ส่ง payload ครบ `ReadFile` อาจค้างโดยไม่มี deadline และไม่สามารถสังเกต `stopSignal` ได้. นอกจากนี้เมื่อ `frameLen != 109`, code ใช้ค่า u32 ที่รับจาก peer เป็น `remaining` แล้วอ่านทิ้งจนหมด (`:281-286`) โดยไม่มี `MAX_DISCARD_BYTES`, deadline หรือ connection reset. ค่า length ขนาดใหญ่หรือ stream ที่ส่งข้อมูลช้าอาจตรึง single pipe instance เป็นเวลานานและทำให้ client ที่ถูกต้อง reconnect ไม่ได้.

**ผลกระทบ:** local unauthenticated peer สามารถทำให้ Go capture หยุดส่ง, reader ไม่รับ connection ใหม่ และ runtime shutdown/join ค้าง. นี่เป็น availability failure ใน ingress control plane ไม่ใช่แค่ malformed-frame counter.

**การแก้ที่ต้องมี:** คง overlapped I/O หรือใช้ read deadline/cancelable event; จำกัด length ก่อน discard เช่น reject-and-disconnect เมื่อไม่ใช่ 109; จำกัด bytes/time ของ resynchronization; เมื่อ partial frame timeout ให้ disconnect/reset instance; ทดสอบ byte-by-byte header/payload, stalled writer, oversized length และ shutdown ระหว่าง read.

### C-03 — Event identity ไม่ unique ข้าม restart/reconnect และ duplicate/non-monotonic ยังถูก submit

**หลักฐาน:** `nose/capture.go:40-42, 184-198`; `nose/inject.go:24-43`; `src/capture/nose_pipe_reader.zig:255-333`; contract `docs/contracts/canonical-event-v1.md:134-145`.

Go ใช้ `eventSequence` ที่เริ่มจากศูนย์ในแต่ละ process. หลัง Go restart ID กลับไป 1. Zig reader ตั้ง `previous_connection_event_id = 0` ใหม่ทุก connection และ comment ระบุว่าจงใจไม่เทียบข้าม generation (`:255-261`). เมื่อพบ duplicate หรือ ID ถอยหลัง code เพิ่ม counter/log ที่ `:313-320` แต่ยัง assign `g_last_event_id` และ submit event ที่ `:324-333`. `CanonicalEvent.session_id` ไม่ถูกเติมใน `eventFromPacket` หรือ fixture จึงเป็นศูนย์ทุก packet แม้ contract ระบุ source/session identity สำหรับ correlation.

**ผลกระทบ:** event_id ซ้ำข้าม restart และ event replay ถูกมองเป็น event ใหม่ได้; forensic linkage, exactly-once semantics, incident correlation และ replay defense ใช้ไม่ได้. Counter ที่ชื่อ duplicate/non-monotonic เป็น observability เท่านั้น ไม่ใช่ enforcement of identity invariant.

**การแก้ที่ต้องมี:** ใช้ durable producer epoch + counter หรือ random/cryptographic event ID ที่มี monotonic sequence ต่อ epoch; ส่ง epoch ใน protocol; persist/handshake last accepted identity; reject duplicate และ non-monotonic ตาม policy ที่กำหนด ไม่ใช่เพียง log; เติม stable source/session identity จาก 5-tuple หรือ capture session และทดสอบ restart/reconnect/replay.

### C-04 — Actual Nose pipe protocol ข้าม frozen WEV1/CRC32 contract และไม่มี integrity check ของ frame

**หลักฐาน:** frozen contract ระบุ 125 bytes, `WEV1`, payload length และ CRC ที่ `shared/protocol/protocol.md:10-30`, `shared/protocol/wire_v1.h:15-21`, `src/contract/wire_event.zig:6-14, 117-143`, `shared/wire/wire_codec.py:244-283`. แต่ actual path ระบุ `u32 LE length + 109 bytes` ที่ `nose/pipe_writer.go:9-15` และ `src/capture/nose_pipe_reader.zig:6-15`, แล้วส่ง/รับ frame 113 bytes ที่ `nose/pipe_writer.go:134-153` และ `nose_pipe_reader.zig:263-306`.

เส้นทาง production ไม่ได้เรียก `wire_event.deserializeEvent`, จึงไม่มี WEV1 magic, payload type, payload length contract และ CRC32. Named pipe เป็น byte stream; short write ถูกจัดการ แต่ corruption ที่เปลี่ยนหลาย byte แล้วคง canonical magic/version/size ไว้จะผ่าน deserializer ได้. เอกสารหลายชุดประกาศว่า cross-language communication ต้องใช้ 125-byte WEV1 frame ขณะที่ handoff/reader ใช้ protocol เฉพาะ 113-byte โดยไม่มีเอกสาร authoritative ที่ระบุ exception, versioning และ integrity semantics.

**ผลกระทบ:** ABI/protocol compatibility เป็น path-dependent และ corruption หรือ injection ที่ผ่าน header ขั้นต้นไม่ถูกตรวจพบ. Python/C/reference consumers ที่ใช้ WEV1 ไม่สามารถใช้ live Nose frame โดยตรง. การที่ test ผ่าน golden payload 109 bytes ไม่ได้พิสูจน์ frame contract ของ named pipe.

**การแก้ที่ต้องมี:** เลือก contract เดียว. ทางที่ปลอดภัยคือให้ Go ส่ง WEV1 125-byte frame และ Zig ใช้ `wire_event.deserializeEvent` ซึ่งตรวจ CRC; หากจำเป็นต้องคง 113-byte transport ต้องประกาศเป็น named-pipe protocol version แยก, เพิ่ม CRC/MAC และทดสอบ byte corruption, truncation, extra bytes, version mismatch และ cross-language decoder.

### C-05 — Reader bypasses Nose contract และ canonical-to-pipeline adapter ทิ้ง provenance/session identity

**หลักฐาน:** `src/capture/nose_contract.zig:3-18, 123-163` ระบุว่าสensors ต้อง submit ผ่าน contract; แต่ `src/capture/nose_pipe_reader.zig:324-333` เรียก `pipeline_queue.pushCanonicalEvent` โดยตรง. Mapping ที่ `src/pipeline/event_queue.zig:70-103` ไม่คัดลอก `source`, `session_id`, `direction`, `is_pipe` หรือ `policy_action` ไป `IpcEvent`.

นี่ทำให้ test ของ `nose_contract` และ `golden_path_e3` ซึ่งเรียก `nose.submitEvent` ไม่ใช่หลักฐานของ actual Go pipe path. Event ID และ network fields บางส่วนอยู่ต่อ แต่ source ของ producer/provenance และ session correlation ไม่อยู่ใน object ที่ detector, policy และ forensic ใช้. `IpcEvent.init` ยังเริ่ม source เป็น `.system` และ mapping ไม่ overwrite source ให้เป็น `capture_npcap`.

**ผลกระทบ:** สายตัดสินใจ downstream อาจเห็น event เป็น system event แทน network sensor และไม่สามารถผูก packet กับ session/source/producer ได้. Contract ที่ประกาศให้ sensor ผ่าน validation/priority facade ไม่ตรงกับ runtime path.

**การแก้ที่ต้องมี:** ให้ reader ใช้ canonical ingress facade เดียว หรือสร้าง adapter contract ที่ระบุชัดและตรวจใน test. ขยาย/ปรับ mapping ให้คง source, session/source ID, direction, is_pipe, policy metadata และ provenance ที่ downstream ต้องใช้; เพิ่ม assertion ว่า field สำคัญไม่เปลี่ยนหลัง pipe → queue → processor → forensic.

## Important findings

### I-01 — Live Go capture ไม่มี bounded retry และ backpressure semantics ไม่ตรง comment

**หลักฐาน:** `nose/pipe_writer.go:92-109, 116-153`; `nose/capture.go:158-164`; retry ที่มีจริงอยู่เฉพาะ `nose/inject.go:44-57`.

เมื่อ pipe ไม่พร้อม `Send` เพิ่ม dropped แล้ว dial หนึ่งครั้งและคืน false. เมื่อ write ล้มเหลวจะปิด connection และคืน false. live `runCapture` ทิ้งผลลัพธ์ที่ `:160`; packet ถูก drop ต่อไปจนกว่าจะมี packet ใหม่ที่ทำให้ `ensureConnected` สำเร็จ. ไม่มี queue bounded ระหว่าง capture กับ writer, ไม่มี retry deadline ต่อ event และไม่มี explicit policy ว่า drop หรือ sample อย่างไรเมื่อ consumer ช้า. `os.OpenFile` named-pipe open และ `file.Write` ไม่มี deadline; จึงมีความเสี่ยงทั้ง drop burst และ block capture ขึ้นกับ Windows pipe state.

แยกให้ชัดว่า observe injection มี bounded retry 2 วินาทีโดยประมาณ แต่ live capture ไม่ได้มี guarantee เดียวกัน. Counters `canonical` และ `droppedPipe` จึงไม่ใช่ end-to-end delivered/submitted truth.

### I-02 — Canonical field semantics ของ Go ไม่ตรง contract บางส่วน

**หลักฐาน:** `nose/capture.go:184-249`, `nose/canonical.go:242-275`; contract `docs/contracts/canonical-event-v1.md:18-23, 87-101, 134-145`.

`MonotonicNS` ใช้ `time.Now().UnixNano()` ซึ่งเป็น wall clock และเปลี่ยนย้อนหลังได้เมื่อ system clock ถูกปรับ. `PayloadHash` ใช้ FNV-1a-like `quickHash` ทั้ง payload (`:242-260`) แต่ contract ระบุ SHA-256 prefix. IPv6 ถูกลดเหลือ first 4 bytes (`:214-223`) ซึ่งทำให้ address identity ไม่ unique. `SessionID` ไม่ถูกเติม ทั้งที่ docs ระบุว่า Go Nose ต้อง derive source identity. นอกจากนี้ `nose/canonical.go:193-198` ตรวจ source แบบไม่ครอบคลุม closed enum และ `Deserialize` ที่ `:241-276` ถอด fields โดยไม่ตรวจ magic/version/struct size หรือ enum.

ผลคือ event ที่ serialize จาก Go อาจมี semantics ที่ consumer อื่นตีความไม่เหมือนกัน และ `Deserialize` public helper ยอมรับ malformed bytes หาก caller ใช้โดยไม่ผ่าน Zig receiver.

### I-03 — Validation ของ canonical event ยังต่ำกว่ากฎในเอกสาร

`src/contract/canonical_event.zig:273-279` ตรวจเพียง magic, version และ `struct_size`; `deserializeFromBytes:397-407` ตรวจ enum บางค่าและ confidence. ไม่ตรวจ `event_id > 0`, timestamp > 0, monotonic timestamp, severity 0–3, valid protocol, reserved bytes หรือ direction/is_pipe range ทั้งที่ `docs/contracts/canonical-event-v1.md:134-145` ระบุไว้. ดังนั้น frame ที่มี canonical header ถูกต้องแต่ zero identity/invalid semantic fields ผ่านเข้า queue ได้.

`src/capture/nose_pipe_reader.zig:305-333` ไม่เพิ่ม semantic gate อื่นและไม่ reject duplicate ID. ควรแบ่ง syntax validation, semantic validation และ producer authorization ให้ชัด พร้อม negative tests ทุก field.

### I-04 — Decoder implementations ซ้ำและ malformed packet handling ไม่สอดคล้องกัน

`src/capture/packet_decoder.zig:162-220` ตรวจ header bounds หลัก แต่ `decodeTcp` ไม่ reject `data_offset < 20`; อาจตีความ payload จากตำแหน่งที่ไม่ใช่ payload ของ TCP malformed. `src/pipeline/packet_callback.zig:41-75` อ่าน IPv4 IHL แล้วคำนวณ transport offset โดยไม่ตรวจ IHL >= 20, header อยู่ครบ, total length, checksum หรือ fragmentation. ขณะที่ parser ใน `npcap_capture.zig:392-480, 782-835` defensive กว่าและมี checks มากกว่า แต่ `packet_callback` เป็น direct `NpcapAdapter` path ที่ต่าง implementation.

ควรมี parser เดียวเป็น authority หรือทำ conformance suite ที่ป้อน malformed corpus เดียวกันให้ทุก implementation แล้ว assert ว่าผลลัพธ์เหมือนกัน. Direct adapter ไม่ใช่ production path ตาม daemon แต่ไม่ควรปล่อยให้มี parser ที่สามารถตีความ packet ต่างกันโดยไม่ประกาศ contract.

### I-05 — Nose counters และ identity state เป็น plain globals ที่อ่าน/เขียนข้าม threads

**หลักฐาน:** `src/pipeline/runtime_state.zig:93-101`; writes ใน `src/capture/nose_pipe_reader.zig:241-332`; reads ใน `src/control/state_machine.zig:330` และ `src/control/handler_registry.zig:598`.

`g_nose_connected`, frame counters, last ID และ duplicate counters เป็น `pub var` plain `bool/u64`; reader thread เพิ่มค่าและ control/health threads อ่านพร้อมกันโดยไม่มี atomic หรือ mutex. แม้แต่ละ operation จะเป็น single machine word แต่ concurrent read/write ของ non-atomic object เป็น data race ในภาษาและไม่ให้ snapshot ที่สอดคล้องกัน. ในทางปฏิบัติ health response อาจเห็น counters คนละ epoch หรือค่าไม่สัมพันธ์กัน เช่น submitted มากกว่า read/dropped ที่ snapshot เดียวกัน และมีความเสี่ยงเมื่อ build/architecture เปลี่ยน.

เปลี่ยน counters เป็น atomic ที่มี load order ชัดเจน หรือรวมไว้ใน lock-protected snapshot. แยก monotonic total counters จาก connection state และทดสอบ concurrent reader/control polling ภายใต้ race detector/TSAN-equivalent ที่ CI รองรับ.

### I-06 — Payload ที่ใช้ตรวจจับไม่ถึง actual Go pipe path และ queue มีการตัด payload เงียบ

**หลักฐาน:** Go Nose serialize เฉพาะ 109-byte metadata ที่ `nose/capture.go:158-160`; frozen contract ระบุ payload เป็น length/hash ไม่ใช่ bytes ที่ `shared/protocol/protocol.md:63-69`; `src/pipeline/event_queue.zig:11-20,45-49`; `src/pipeline/event_processor.zig:84-104`.

Go capture ไม่ส่ง raw packet bytes ผ่าน canonical frame. Zig reader เรียก `pushCanonicalEvent(&event)` โดยไม่มี payload ทำให้ `qe.payload_len` เป็นศูนย์ใน actual network path. Aho-Corasick stage จึงไม่สามารถตรวจ raw payload ของ packet ที่ Go จับได้ และต้องพึ่ง rule/event metadata ที่ upstream เติมเอง. ใน direct Zig path ที่ส่ง bytes ได้ `pushEvent` จำกัด payload ที่ 1500 bytes แต่ยังคง `ev.payload_len` เป็นค่าต้นฉบับ ซึ่งทำให้ metadata บอกความยาวเต็มแต่ forensic/signature เห็นเพียง prefix; ไม่มี flag ระบุ truncation.

ต้องตัดสินใจว่า ingress เป็น metadata-only sensor จริงหรือจะส่ง bounded payload reference/bytes แยก channel. หากตัด payload ต้องไม่อ้างว่า pipeline ทำ payload signature matching ครบ; หากเก็บ payload ต้องกำหนด maximum, truncation flag และ hash ของ bytes ที่ตรวจจริงให้ตรงกัน.

### I-07 — Npcap assumptions มี implementation สองชุดและ evidence ของ Windows ABI ยังไม่พอ

**หลักฐาน:** `src/capture/npcap_capture.zig:95-250,1053-1208`, `src/capture/npcap_adapter.zig:79-214`, `src/pipeline/packet_callback.zig:86-120`, `src/capture/npcap_test_live.zig:137-203`.

`npcap_capture.zig` ใช้ dynamic loader และตรวจ `caplen` ก่อน copy (`:1180-1190`), ขณะที่ `packet_callback.zig` ใช้ `pcap_next_ex` ผ่าน adapter อีกชุดและสร้าง slice จาก `hdr.caplen` (`:104-115`). Source มีทั้ง `NpcapSensor` และ `NpcapAdapter`, คนละ lifecycle/stats/parser และไม่มี compile-time conformance test ระหว่าง ABI declarations, `pcap_pkthdr` layout, calling convention, DLT และ timestamp signedness. Direct adapter ถูกปิดใน daemon แต่ยังมี public runtime-capable path และ live test ที่ต้องพึ่ง Windows/Npcap จริง.

ควรเลือก implementation เดียวเป็น owner, สร้าง Windows ABI smoke test ที่ตรวจ `pcap_findalldevs`, `pcap_open_live`, `pcap_next_ex`, `pcap_close`, DLT และ caplen/wirelen boundary โดยไม่ส่งผล enforcement, และกำหนด behavior เมื่อ Npcap DLL/version/device/filter ไม่พร้อม.

### I-08 — Resource/lifecycle behavior เมื่อ pipe หรือ Npcap ล้มเหลวไม่ครบ end-to-end

Go writer ปิด file เมื่อ write ล้มเหลว (`nose/pipe_writer.go:142-147`) แต่ไม่มี `FrameWriter.Close` ที่เรียกจาก `runCapture`/main อย่างชัดเจน และไม่มี deadline ตอน write. Zig reader มี reconnect loop แต่การเปลี่ยนเป็น blocking handle ทำให้ `stopSignal` ไม่สามารถยกเลิก read ที่ค้างได้. Npcap sensor มี `deinit/closeHandle` ใน `npcap_capture.zig:1096-1108`, แต่ direct `packet_callback.captureThread` ใช้ adapter คนละชุดและไม่มี test ที่บังคับ error ระหว่าง packet loop แล้วตรวจ close/reopen. หลักฐานจึงยังไม่พอสำหรับ shutdown, device removal, pipe peer crash และ restart storm.

กำหนด ownership/lifecycle table สำหรับทุก handle และใช้ defer/RAII ที่ทดสอบได้. เพิ่ม fault tests ให้ peer หายระหว่าง header, payload และ write; ยืนยันว่า handle ปิด, reader กลับไป accept, counter ไม่เพิ่มซ้ำ และ shutdown เสร็จภายใน deadline.

## Observe-only boundary และสิ่งที่ไม่ถือเป็นหลักฐาน enforcement

`nose/inject.go:10-64` ระบุและทำ fixture แบบ alert-only: `TypeForward`, `RuleID=0`, `ActionLogOnly`, `EnforcementStatus=0`; ไม่มี call ไป WFP/Firewall. `nose/main.go` เรียก path นี้เมื่อใช้ `-inject-observe`. จึงใช้เป็นหลักฐานได้เพียงว่า serializer/writer/reader linkage ตั้งใจไม่สร้าง host effect หาก pipe ทำงาน—not เป็นหลักฐานว่า policy block หรือ host enforcement ทำงาน.

Downstream `event_processor.zig:154-173` เรียก PEP/dispatcher เมื่อ policy match แต่ audit นี้ไม่ได้ใช้ `block_ip`, `netsh`, Windows Firewall API หรือ bookkeeping เป็นหลักฐานว่า action มีผลกับ host. Direct Zig Npcap ถูกปิดใน daemon (`src/daemon.zig:406-412`) และต้องไม่ถูกนับเป็น production network authority.

## Test และ evidence gaps

1. ใน execution environment นี้ `go` และ `zig` ไม่มีใน `PATH`; `go test ./...` ทั้ง `nose` และ `go/aggregator` และ `zig test` target ที่พยายามรันจบด้วย `command not found`. จึงยังไม่มีหลักฐาน compile/run ของ Windows Go/Zig implementation จากการตรวจครั้งนี้.
2. Python reference `shared/wire/wire_codec.py` self-test ผ่านครบ 8 กรณี และ `python3 -m py_compile` ของ `tests/runtime/test_wire.py`, vector generator และ `tests/test_golden_path.py` ผ่าน. หลักฐานนี้ยืนยันเฉพาะ Python 125-byte WEV1 reference ไม่ได้ยืนยัน 113-byte live Nose path.
3. `src/tests/capture/npcap_adapter.zig:1-10` และ `src/tests/capture/flow_table.zig:1-10` เป็นเพียง import-cleanly smoke tests. ไม่ทดสอบ ABI, Npcap, malformed frames หรือ concurrent access.
4. `src/tests/integration/golden_path_e3.zig:23-93` ทดสอบ `nose_contract.submitEvent/popEvent` โดยตรง ไม่ได้สร้าง named pipe, ใช้ Go serializer, ใช้ `readExact`, reconnect หรือ actual pipeline queue. `src/tests/cli/nose_pipe_e2e_cli.zig` มี harness แต่ไม่มี evidence ใน repository ว่าผ่านบน Windows กับ Go producer จริง.
5. ไม่มี test สำหรับ unauthorized named-pipe client, ACL/SID, producer handshake, partial header/payload, stalled peer, oversized length, disconnect during read, reconnect sequence, duplicate/replay across restart หรือ shutdown while blocking read.
6. ไม่มี cross-language golden test ที่ feed bytes จาก `nose/pipe_writer.go` ให้ Zig reader แล้ว assert field-for-field. Existing vectors ขนาด 109/125 bytes (`tests/contracts/...`) ครอบคลุม payload/reference wire แต่ไม่ครอบคลุม 4-byte length prefix ของ production pipe.
7. ไม่มี test ยืนยัน `source`, `session_id`, `direction`, `is_pipe`, policy metadata และ payload provenance หลัง canonical → `IpcEvent` → forensic. ไม่มี test ว่า duplicate/non-monotonic ถูก reject; มีเพียง counter/log path.
8. `tests/test_e2e.py` มี legacy C++ bridge/`block_ip` scenarios และตามขอบเขตนี้ไม่ใช้เป็น enforcement evidence. Tests ที่รันไม่ได้หรือ skip เพราะ binary/Windows dependency ต้องรายงานเป็น gap ไม่ใช่ pass.

## Recommended actions (เรียงความสำคัญ)

| Priority | Action ที่ทำได้จริง | เกณฑ์ปิดงาน |
|---|---|---|
| P0 | ผูก named pipe กับ explicit ACL/service SID และตรวจ caller token/handshake; reject peer ที่ไม่ authorized | unauthorized client ต่อไม่ได้หรือถูก reject ก่อน event ingress; authorized client ผ่าน Windows test |
| P0 | รวม protocol เป็น WEV1 125-byte + CRC32 หรือออกเอกสาร/เวอร์ชันเฉพาะของ 113-byte transport พร้อม integrity/MAC | Go bytes decode ได้ด้วย Zig/C/Python reference เดียวกัน; corruption/truncation/version mismatch ถูก reject |
| P0 | ทำ reader timeout/cancellation แบบ overlapped และจำกัด length/discard; partial/stalled/oversized frame ต้อง disconnect ได้ | malicious peer ไม่ตรึง reader; shutdown/reconnect จบภายใน bounded deadline |
| P0 | ออกแบบ producer epoch + durable/cryptographically unique event ID และ reject duplicate/non-monotonic/replay ตาม policy | restart/reconnect/replay test แสดง exactly-once หรือผล reject ที่ระบุได้; `session_id` ไม่เป็นศูนย์โดยไม่มีเหตุผล |
| P1 | ทำ canonical-to-pipeline adapter เดียวและ preserve provenance/session/policy fields; เลิก bypass `nose_contract` หรือบันทึก exception เป็น contract | field-by-field round-trip จาก real pipe ถึง forensic/policy ผ่าน; source ไม่กลายเป็น `.system` |
| P1 | ตัดสินใจ metadata-only กับ payload inspection; ถ้าส่ง payload ให้กำหนด cap/hash/truncation semantics, ถ้าไม่ส่งให้ปิด claim payload matching ใน path นี้ | tests ตรวจ payload length/hash/truncation และ rule result ตรงกับข้อมูลที่มีจริง |
| P1 | รวม packet parser/Npcap owner และ harden IHL/transport/total-length/fragmentation/DLT checks; ยืนยัน caplen/wirelen และ Windows ABI | malformed corpus ไม่ panic/อ่านเกิน; Npcap DLL/device/filter failure cleanup ผ่าน live smoke test |
| P1 | เปลี่ยน nose state/counters เป็น atomics หรือ lock-protected snapshot และทดสอบ concurrent health reads | race test ไม่มี data race; counters มี invariant ที่ตรวจได้ |
| P2 | เพิ่ม CI ที่ติดตั้ง Go/Zig versions จาก lock/toolchain, รัน Go tests, Zig tests, Python vectors, Windows named-pipe integration และ fuzz/mutation corpus | CI artifact แสดง compile + test pass ของ actual producer/consumer ไม่ใช่เฉพาะ reference |

## ข้อสรุปการรับรอง

โค้ดมี bounded queue บางส่วน, `writeAll`, canonical magic/version/size checks, Npcap `caplen` guard ใน implementation หนึ่ง และ observe-only fixture ที่ไม่เรียก host block. หลักฐานเหล่านี้เป็นจุดเริ่มต้นที่ดี แต่ไม่เพียงพอจะรับรองความลับของ producer, frame integrity, identity monotonicity, shutdown responsiveness, cross-language compatibility หรือ end-to-end delivery. จนกว่า C-01 ถึง C-05 และ P0 actions จะปิดพร้อม Windows integration evidence เส้นทาง Go Nose → Zig packet ingress ควรจัดเป็น **not production-ready / conditional review only**.
