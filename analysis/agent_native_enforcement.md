# AEGIS Native Enforcement Code Audit

**วันที่ตรวจ:** 2026-09-23  
**ขอบเขต:** `rust-src/`, `drivers/`, `src/windows/`, `bridge/`, `mouth/` โดยตรวจ source/config/test ที่เกี่ยวข้องและตัด binary, generated output, `build/`, `dist/` และ artifact ออก  
**เอกสารอ้างอิงหลัก:** `AEGISProductionHandoff.md` ซึ่งระบุว่า prevention gate ยังปิด และ production IPS blocker คือ provider-backed `EnforcementReceipt v1`, independent WFP read-back, restart-safe ownership และ post-cleanup absence proof [1]

## บทสรุปผู้บริหาร

โค้ดปัจจุบันยัง **ไม่ควรเปิด prevention gate**. เส้นทาง block และ exact-ID delete มีอยู่ใน source แต่หลักฐานที่ driver ส่งกลับยังเป็น state ที่เก็บไว้ใน global ของ driver ไม่ใช่การอ่านจาก WFP provider จริง. หลัง driver restart global identity หายไป แต่ filter ถูกสร้างด้วย `FWPM_FILTER_FLAG_PERSISTENT`; จึงไม่มี ownership/reconciliation path ที่พิสูจน์ได้. ยิ่งไปกว่านั้น API ฝั่ง Rust ปฏิเสธ `present=false` เป็น `None` ทำให้ไม่สามารถสร้างหลักฐาน “ลบแล้วและ provider ยืนยันว่าไม่มี filter” ผ่าน ABI ปัจจุบันได้.

พบปัญหา P0 ที่ต้องปิดก่อน proof ได้แก่ **read-back ไม่ provider-backed**, **persistent filter ownership/restart ไม่ปลอดภัย**, **privilege boundary ยังไม่ authenticate caller และ device ไม่ได้กำหนด ACL แบบจำกัด**, และ **tuple/layer semantics ไม่ตรงกับ proof ที่ handoff อนุมัติ**. พบ P1 หลายรายการที่ทำให้ Windows build, ABI, cleanup, concurrency และ telemetry ไม่น่าเชื่อถือ. ผลตรวจนี้เป็นการอ่านโค้ดจริง; ไม่มีการแก้ production source.

## สถานะหลักฐานและข้อจำกัด

| ประเภท | ผลตรวจ |
|---|---|
| **Verified fact** | พบจาก source ที่อ่านจริง พร้อม path และ line ด้านล่าง |
| **Inference** | ผลกระทบที่อนุมานจาก Windows/WFP semantics หรือจากการเชื่อมหลายโมดูล ต้องยืนยันด้วย WDK/Windows acceptance test |
| **Unknown** | ไม่สามารถสรุปจาก source อย่างเดียว เช่น filter ที่ติดตั้งอยู่บน host จริง, ACL ที่ถูกปรับภายนอก, หรือผล build ของ WDK |

ใน sandbox นี้ไม่มี `zig`, `cargo`, `rustc`, `g++`, `gcc`, `clang` หรือ `cmake` ใน `PATH`. ดังนั้นไม่สามารถยืนยัน Windows/WDK compile, DLL exports, driver install หรือ provider enumeration จากเครื่องนี้ได้. การที่ source มีไฟล์ `.sys`/`.dll` เดิมใน workspace ไม่ถูกใช้เป็นหลักฐาน เพราะถูกตัดออกจากการตรวจ.

## Inventory ที่ตรวจ

### Rust source

- `rust-src/lib.rs`
- `rust-src/shield/src/lib.rs`
- `rust-src/shield/src/main.rs`
- `rust-src/shield/src/pep.rs`
- `mouth/windows_sec_monitor.rs`

### C/C++ source และ headers

- `drivers/wfp_callout/aegis_wfp.c`, `aegis_wfp.h`, `aegis_wfp_callout.c`, `aegis_wfp_comm.c`
- `drivers/minifilter/aegis_minifilter.c`, `aegis_minifilter.h`, `aegis_minifilter_comm.c`, `aegis_minifilter_file.c`, `aegis_minifilter_proc.c`
- `src/windows/aegis_wfp.c`, `wfp_ioctl.c`, `etw_native.c`, `fim_native.c`
- `bridge/aegis_adapter.cpp`, `aegis_adapter.hpp`, `aegis_adapter_selftest_main.cpp`, `aegis_bridge_main.cpp`, `aegis_bridge_test.cpp`, `aegis_ipc.cpp`, `aegis_ipc.hpp`, `aegis_packet_parser.cpp`, `aegis_packet_parser.hpp`

### Supporting ABI/config/test filesที่อ่านเพื่อวิเคราะห์ cross-language contract

- `src/policy/pep_bindings.zig`, `src/policy/wfp_ioctl.zig`
- `src/core/rust_pep.zig`, `src/core/bridge_init.zig`
- `src/windows/cpp_adapter.zig`, `adapter_contract.zig`, `windows_adapters.zig`, `win32_io.zig`, `fim.zig`
- `bridge/CMakeLists.txt`, `bridge/aegis_bridge_ctypes.py`
- `drivers/wfp_callout/aegis_wfp.inf`, `drivers/minifilter/aegis_minifilter.inf`
- `mouth/Cargo.toml`, `mouth/build_mouth.bat`, `rust-src/shield/Cargo.toml`

ไม่รวม `*.sys`, `*.dll`, `*.exe`, `*.pdb`, `target/`, `build/`, `dist/` และ generated outputs.

# P0 — Production IPS blockers

## P0-1: Query ไม่ได้อ่าน WFP provider จริง และไม่สามารถยืนยัน absence หลัง cleanup

**Verified fact.** `AegisWfpQueryFilter` รับ `filter_id` แล้วตอบ `present=1` เมื่อ ID เท่ากับ `g_FilterId`; tuple มาจาก `g_BlockedIp`, `g_BlockedPort`, `g_BlockedProtocol` เท่านั้น. ไม่มี `FwpmFilterGetById0`, `FwpmFilterEnum0` หรือ provider enumeration ใดใน handler (`drivers/wfp_callout/aegis_wfp.c:374-400`). ดังนั้น response เป็น driver-owned shadow state ไม่ใช่ provider-backed read-back.

ฝั่ง C bridge ส่ง query เข้า driverและยอมรับ output ขนาด 20 bytes แต่ไม่ได้บังคับ `present` หรือ tuple matchเอง (`src/windows/wfp_ioctl.c:166-177`). ฝั่ง Rust `Adapter::query_filter` จะคืนค่าเฉพาะกรณี `rc == 0`, `present != 0` และ ID ตรงกัน (`rust-src/lib.rs:338-349`). `aegis_pep_query_filter` จึงคืน `-2` เมื่อ filter หายหรือ `present=0` และไม่ส่ง state ที่มี `provider_status=STATUS_NOT_FOUND` ให้ caller (`rust-src/lib.rs:577-604`). Zig wrapper ก็ถือ absent/error เป็น `null` (`src/policy/pep_bindings.zig:195-200`).

**ผลกระทบที่ยืนยันได้จาก contract.** API ปัจจุบันไม่สามารถสร้างหลักฐาน post-cleanup `present=false` ได้. Non-zero filter ID เพียงอย่างเดียวไม่ใช่ `EnforcementReceipt v1`, ตรงกับ blocker ใน handoff [1].

**ความรุนแรง:** P0. ปิด prevention gate โดยตรง.

**ข้อแก้ที่ทดสอบได้:** เพิ่ม provider query ที่คืนสถานะสามทางอย่างชัดเจน (`present`, `absent`, `query_error`) และคืน provider identity/status พร้อม tuple จาก object ที่ WFP enumerate จริง. ต้อง query ก่อน block, หลัง block และหลัง delete. Test ต้องยืนยันว่า filter ID ที่ไม่อยู่ใน provider ไม่ถูกตีความเป็น driver-local absence แบบสำเร็จ.

## P0-2: Persistent filter ไม่มี ownership/reconciliation ที่ปลอดภัยต่อ restart และ global ID ถูกใช้ซ้ำหลาย object

**Verified fact.** Block path เปิด dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) แต่สร้าง filter ด้วย `FWPM_FILTER_FLAG_PERSISTENT` (`drivers/wfp_callout/aegis_wfp.c:245-278`). เมื่อ add สำเร็จจะเขียน filter ID และ tuple ลง globals (`:279-289`). Unblock อนุญาตเฉพาะ `filterId == g_FilterId` แล้วลบด้วย `FwpmFilterDeleteById0` (`:315-371`). ไม่มี persistent owner key, provider key, boot/session generation, restart reconciliation หรือ enumeration ของ stale filters.

Capture path ก็เขียน filter ID ลง global เดียวกัน (`drivers/wfp_callout/aegis_wfp_callout.c:221-235`). จึงมี ID เดียวที่หมายถึงทั้ง capture filter และ proof filterใน lifecycle เดียวกัน. `AegisWfpUnregisterCallout` unregister runtime callout แล้วลบเพียง `g_FilterId` (`:239-265`); ไม่มีการเก็บ ID แยกสำหรับ provider callout กับ runtime callout และ branch ที่จะลบ provider callout หลัง `g_CalloutId = 0` ไม่สามารถทำงานได้.

**Inference ที่ต้องยืนยันบน Windows.** Persistent object มีแนวโน้มคงอยู่ข้าม engine/driver restart ตาม flag แต่ globals ถูก reset เมื่อ driver โหลดใหม่. หากเป็นเช่นนั้น filter เก่าจะยังมีผลแต่ driver รุ่นใหม่จะ query/unblock ไม่ได้. หาก dynamic-session semantics ปฏิเสธหรือปรับพฤติกรรมของ persistent filter การ block ก็อาจล้มเหลวอย่างเงียบๆ. ทั้งสองกรณีไม่ผ่าน production ownership contract.

**ความรุนแรง:** P0. Handoff ระบุให้ตัดสินใจ dynamic หรือ persistent; source ปัจจุบันใช้แบบผสมโดยยังไม่มี restart proof [1].

**ข้อแก้ที่ทดสอบได้:** ใช้ provider GUID/sublayer/owner metadata ที่ไม่ซ้ำและเก็บ provider-object ID กับ runtime callout ID แยกกัน. เพิ่ม startup reconciliation ที่ enumerate เฉพาะ object ของ AEGIS แล้วลบหรือรับช่วงอย่างมี generation/receipt policy. Acceptance test: add exact filter → restart service/driver → enumerate by owner → query by exact ID → cleanup → query absent; ต้องไม่ใช้ IP-only cleanup.

## P0-3: Privilege boundary ไม่ได้ authenticate caller และ device/port ถูกเปิดกว้างเกินจำเป็น

**Verified fact.** Driver สร้าง device ด้วย `IoCreateDevice` โดยไม่กำหนด security descriptor หรือ `IoCreateDeviceSecure` (`drivers/wfp_callout/aegis_wfp.c:62-65`). ไม่มี SDDL ใน source/INF ของ WFP device. User bridge เปิด `GENERIC_READ | GENERIC_WRITE` (`src/windows/wfp_ioctl.c:107-115`). IOCTL mutation ใช้ access bits `FILE_WRITE_DATA` (`drivers/wfp_callout/aegis_wfp.h:22-27`) แต่ไม่มี authorization layer ใน dispatch นอกจากที่ OS device ACL จะบังคับ ซึ่ง source ไม่ได้กำหนด.

Rust PEP ตรวจเพียง bit ใน `req.ctx.caller_capability_mask` (`rust-src/lib.rs:452-460`, `:551-563`). ค่า `caller_pid`, capability mask และ request ID มาจาก caller ผ่าน FFI; ไม่มีการอ่าน access token, process identity หรือ broker-authenticated channel. ผู้เรียกที่เข้าถึง DLL ได้สามารถส่ง capability bit เป็น `1`. `aegis_wfp_user.dll` ถูกโหลดจากชื่อ relative (`rust-src/lib.rs:277-289`) และไม่มี signature/path pinning ใน loader.

Minifilter communication port ใช้ `FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS)` (`drivers/minifilter/aegis_minifilter_comm.c:228-259`). แม้ port นี้เป็น telemetry ไม่ใช่ WFP mutation แต่เปิดข้อมูล kernel ให้ผู้ใช้ที่ไม่ควรเห็น และไม่ใช่ least privilege.

**ผลกระทบ:** PEP ไม่ใช่ authority ที่ตรวจ caller จริง; เป็น policy check บนข้อมูลที่ attacker ควบคุมได้. เมื่อรวมกับ writable WFP device จะกระทบ host enforcement boundary โดยตรง.

**ความรุนแรง:** P0.

**ข้อแก้ที่ทดสอบได้:** กำหนด restrictive SDDL ให้ device/port, เปิด read-only handle สำหรับ telemetry และแยก privileged broker handle สำหรับ mutation. PEP ต้องรับ authorization context จาก broker ที่ยืนยัน token/process identity ไม่ใช่ caller-supplied bit. DLL loader ต้องใช้ absolute path จาก verified installation root พร้อม signature/hash policy. Test ด้วย standard user, low-integrity process และ caller ที่ปลอม PID/capability; ทุก mutation ต้องถูกปฏิเสธ.

## P0-4: Block tuple และ WFP layer ไม่ตรงกับ approved inbound proof semantics

**Verified fact.** Rust request ส่งเพียง `remote_ipv4`, `remote_port`, `protocol` ไปยัง user bridge (`rust-src/lib.rs:495-505`). Kernel block filter ใช้ `FWPM_LAYER_ALE_AUTH_CONNECT_V4` และเงื่อนไข remote IP/port/protocol (`drivers/wfp_callout/aegis_wfp.c:251-275`). ไม่มี local IP, direction, interface, application identity หรือ explicit proof scope. Observe callout กลับลงทะเบียนที่ `FWPM_LAYER_INBOUND_TRANSPORT_V4` (`drivers/wfp_callout/aegis_wfp_callout.c:167-171`, `:213-220`).

Approved proof ใน handoff เป็น traffic จาก Kali ไป Windows host, destination TCP/49153 [1]. Source จึงใช้ inbound telemetry กับ outbound ALE connect mutation โดยไม่มี code ที่พิสูจน์ว่า “remote” ใน layer ที่เลือกหมายถึง tuple เดียวกับ destination ของ inbound proof.

**Inference.** Filter ที่ ALE connect อาจไม่ block inbound connection ไปยัง listening port ตามที่ proof ต้องการ; ต้องยืนยันด้วย WFP layer-specific test. แม้ block จะมีผล ก็ยังเป็นเงื่อนไขที่ไม่ครบ exact flow ตาม receipt contract.

**ความรุนแรง:** P0 จนกว่าจะมี layer/tuple proof.

**ข้อแก้ที่ทดสอบได้:** เลือก layer ตาม traffic direction ที่อนุมัติ เช่น inbound ALE receive/transport ที่เหมาะสม และระบุ local/remote tupleครบ. Provider query ต้องอ่าน object conditions และตรวจเทียบกับ request ทุก field ที่ contract กำหนด. ทดสอบ benign probe จาก Kali และ control ที่ไม่ตรง port/protocol เพื่อยืนยันไม่ block เกิน scope.

## P0-5: Rust PEP ยังออกเพียง response ที่ไม่ใช่ EnforcementReceipt v1

**Verified fact.** `PepResponse` มีเพียง `decision`, `reason`, `quota_remaining`, `signed_by`, `filter_id` (`rust-src/lib.rs:179-186`). ไม่มี receipt version, event ID, policy ID, provider string, status, host-effect confirmation, trace ID หรือ audit ID. `aegis_pep_enforce` เรียก block แล้วคืน filter ID ถ้า adapter ตอบสำเร็จ แต่ไม่ได้ query exact tuple ต่อ (`:495-532`). `signed_by` และ quota response ถูกตั้งเป็นศูนย์/default และไม่มีการ increment quota (`:443-447`, `:607-620`).

**ผลกระทบ:** `filter_id != 0` ถูกใช้เป็นผลสำเร็จของ adapter แต่ไม่ใช่หลักฐาน host effect. Zig `enforceFlow` จึงสร้าง receipt ที่เป็นเพียง subset และยังไม่มี query/tuple verification (`src/policy/pep_bindings.zig:151-187`).

**ความรุนแรง:** P0 ตาม requirement ใน handoff.

**ข้อแก้ที่ทดสอบได้:** ออกแบบ `EnforcementReceipt v1` เป็น ABI ที่ versioned และ fixed-size/length-delimited. Receipt ต้องสร้างได้หลัง provider query และ exact tuple match เท่านั้น. Audit/trace/event correlation ต้องถูกสร้างใน authority เดียวกัน. Block failure หรือ query mismatch ต้องคืน degraded/rejected ไม่ใช่ receipt ที่ดูเหมือน enforced.

# P1 — ความเสี่ยงสูงด้าน ABI, cleanup, build และ thread safety

## P1-1: WFP ABI มี layout/semantic drift ระหว่าง C driver, C bridge และ Zig

**Verified fact.** C driver/header และ C user bridgeกำหนด `AEGIS_RING_STATS` เป็น 6 x `ULONG` รวม 24 bytes (`drivers/wfp_callout/aegis_wfp.h:93-103`; `src/windows/wfp_ioctl.c:85-93`). แต่ Zig `WfpRingStats` มี 4 x `u32` รวม 16 bytes และเรียงเป็น `currentUsedBytes, capacity, totalEvents, droppedEvents` (`src/policy/wfp_ioctl.zig:54-60`). Driver คืน 24 bytes (`drivers/wfp_callout/aegis_wfp.c:292-312`). Zig ส่ง output buffer 16 bytes และต้องการอย่างน้อย 16 bytes (`src/policy/wfp_ioctl.zig:205-225`), จึงไม่ตรงทั้งขนาดและความหมาย.

`AEGIS_EVENT_HEADER` เป็น packed 44 bytes ตาม field จริง (`drivers/wfp_callout/aegis_wfp.h:73-91`; C bridge `src/windows/wfp_ioctl.c:66-83`). แต่ Zig `WfpEventHeader` เป็น `extern struct` ที่ไม่ได้ packed (`src/policy/wfp_ioctl.zig:37-52`); บน x64 `u64 timestamp` มีแนวโน้มทำให้ขนาด 48 bytes และ offset timestamp ต่างจาก C 44-byte wire. ความเห็นใน callout/C bridge ที่เรียก header 40 bytes (`drivers/wfp_callout/aegis_wfp_callout.c:15`, `src/windows/wfp_ioctl.c:66`) ก็ขัดกับ struct จริง.

**ความรุนแรง:** P1 และเป็น release gate สำหรับ telemetry/readiness.

**ข้อแก้ที่ทดสอบได้:** ย้าย structs ไป shared header/generated ABI schema เดียว หรือสร้าง C/Zig/Rust size/offset assertions ที่ compile ใน CI. ตรวจ `@sizeOf`, `@offsetOf`, `sizeof`, `offsetof` สำหรับทุก field และทดสอบ `DeviceIoControl` output length. อย่าใช้ comment เป็น ABI contract.

## P1-2: `aegis_wfp_comm.c` เป็น legacy duplicate path และไม่ใช่ authoritative dispatch

**Verified fact.** Driver build รวม `aegis_wfp.c`, `aegis_wfp_callout.c`, `aegis_wfp_comm.c` แต่ dispatch ที่ export จาก `aegis_wfp.c` เรียก handlers ของไฟล์เดียวกัน (`drivers/wfp_callout/aegis_wfp.c:43-52`, `:157-187`). `aegis_wfp_comm.c` มี static versions ของ create/read/block/stats/device-control (`:17-205`) ซึ่งไม่ถูกเรียกจาก `DriverEntry`; its block path ใช้ IP-only inbound filter, ไม่คืน exact receipt ID ใน output และไม่รองรับ unblock/query (`drivers/wfp_callout/aegis_wfp_comm.c:67-142`, `:170-205`).

**ผลกระทบ:** มีสอง contract ใน source เดียวกัน. Future edit ที่แก้ไฟล์ comm อาจไม่เปลี่ยน production path และ static analysis/test อาจตรวจผิด path.

**ข้อแก้:** ลบ dead path หรือรวม dispatch เป็น implementation เดียว. เพิ่ม build map ที่ยืนยัน source-to-binary และ test ที่เปิด IOCTL กับ driverจริง.

## P1-3: WFP ID cleanup และ callout lifecycle ไม่แยก provider ID กับ runtime ID

`FwpmCalloutAdd0` และ `FwpsCalloutRegister0` เขียนผลลง `g_CalloutId` เดียวกัน (`drivers/wfp_callout/aegis_wfp_callout.c:166-191`). Failure cleanup จึงอาจใช้ runtime ID ไป delete provider callout (`:193-199`, `:224-230`). ตอน unload code set `g_CalloutId=0` ทันทีหลัง unregister runtime แล้ว branch provider delete จึงไม่ทำงาน (`:239-265`). การลบ filterก็ ignore status. เพิ่ม `g_FilterId` proof ไปทับ capture filter ID ตาม P0-2.

**ข้อแก้:** เก็บ `provider_callout_id`, `runtime_callout_id`, `capture_filter_id`, `proof_filter_id` แยกกัน; ทำ state machine และ idempotent cleanup ที่ log status ทุก step. Test failure injection หลังแต่ละ WFP API.

## P1-4: Adapter โหลด DLL ซ้ำและไม่ปิด device handle ทำให้ leak/restart behavior ไม่แน่นอน

`Adapter::load()` โหลด DLL, resolve symbols และเรียก `open()` ทุกครั้ง (`rust-src/lib.rs:277-321`). `Drop` ทำเพียง `FreeLibrary` (`:354-357`) ไม่เรียก `aegis_wfp_ioctl_close`. C bridge เก็บ device handle เป็น static global (`src/windows/wfp_ioctl.c:96-125`). ดังนั้น provider-ready, block, unblock และ query ที่สร้าง adapter ชั่วคราวสามารถทิ้ง kernel handle หรือทำให้ DLL global state ผูกกับ module lifetimeผิด.

**Inference:** การ unload DLL ขณะที่ static device handle ยังเปิดอยู่จะทำให้ cleanup และการโหลดครั้งถัดไปมี behavior ขึ้นกับ Windows loader/refcount; ต้องยืนยันด้วย handle leak test.

**ข้อแก้:** ใช้ process-wide singleton ที่มี explicit init/close และ lock หรือให้ Adapter เป็น owner ที่เรียก close ก่อน `FreeLibrary`; test repeated load/block/query/unblock 10,000 รอบและตรวจ handle count.

## P1-5: WFP globals และ C++ bridge queue ไม่มี synchronization ที่เพียงพอ

Kernel globals `g_FilterId`, tuple fields และ engine handleถูกอ่าน/เขียนจาก device-control และ unload โดยไม่มี lock (`drivers/wfp_callout/aegis_wfp.c:23-41`, `:278-289`, `:327-371`, `:115-133`). Concurrent block requests อาจทำให้ ID ล่าสุดทับ ID ก่อนหน้าและ cleanup ผิด object.

`SharedRingBuffer` ระบุว่า thread-safe แต่ class ใช้ plain `m_head`, `m_tail`, `m_count`, `m_dropped` โดยไม่มี mutex/atomic (`bridge/aegis_ipc.hpp:232-294`). `aegis_bridge_push_event`, `pop_event`, `shutdown` เรียกใช้งานจากหลาย subsystem/thread โดยตรง (`bridge/aegis_ipc.cpp:251-322`). Shutdown สามารถ `Destroy()` ขณะ producer/consumer กำลังเข้าถึง buffer (`:275-284`).

**ข้อแก้:** ใส่ lock/atomic ที่พิสูจน์ได้หรือใช้ SPSC/MPSC queue ตาม topology, กัน shutdown ด้วย lifecycle refcount, และใช้ stress/TSAN-equivalent test.

## P1-6: C++ adapter poll มี buffer overflow risk เมื่อเรียกผ่าน C ABI

`aegis_adapter_poll` ตรวจเพียง `canonicalCap < f.size` ต่อ event (`bridge/aegis_adapter.cpp:427-449`). ไม่ตรวจว่า `canonicalCap >= (n+1) * f.size`; เมื่อ `maxOut > 1` และ buffer มีพื้นที่น้อยกว่าหลาย frame การเขียน `canonicalBuf + n*f.size` ล้น buffer. Zig wrapper ป้องกันบางกรณีด้วย `wire_buf.len >= out_set.len*109` (`src/windows/cpp_adapter.zig:116-126`) แต่ C/Python/third-party callers ไม่ถูกบังคับ.

**ข้อแก้:** ตรวจ `f.size != 0`, overflow ของ multiplication และ capacity ต่อ event ก่อน `memcpy`; เพิ่ม canary test ที่เรียก C ABI ด้วย capacity 109, maxOut 8.

## P1-7: Named pipe bridge ใช้ invalid-handle check และ overlapped I/O ผิดรูปแบบ

`CreateNamedPipeA`/`CreateFileA` ใช้ `FILE_FLAG_OVERLAPPED` แต่ `ConnectNamedPipe`, `ReadFile` และ `WriteFile` ถูกเรียกด้วย `NULL` `OVERLAPPED` (`bridge/aegis_ipc.cpp:75-90`, `:134-145`, `:172-227`). นี่ไม่ใช่รูปแบบที่ถูกต้องสำหรับ handle ที่เปิดแบบ overlapped. อีกทั้ง code ตรวจ failure ด้วย `handle == NULL`; Windows failure ของ `CreateFileA` คือ `INVALID_HANDLE_VALUE`, ไม่ใช่ NULL (`:83-93`, `:139-141`).

Health pipe ใน `aegis_bridge_main.cpp` ใช้ overlapped pattern ถูกกว่าบางส่วน (`:78-169`) แต่ไม่มี restrictive security attributes (`CreateNamedPipeA(..., NULL)`) และ thread ถูก detach (`:323-325`).

**ข้อแก้:** เลือก synchronous mode แล้วตัด flag ออก หรือใช้ OVERLAPPED/event/cancel อย่างครบ; ใช้ `INVALID_HANDLE_VALUE` ตรวจทุก CreateFile; ตั้ง pipe ACL และ test connect/read/write/disconnect/shutdown.

## P1-8: FIM worker มี race, stale event และ use-after-free หลัง timeout

`fim_thread` อ่าน `s->data_ready` นอก critical section ขณะที่ poll เขียน/ล้างค่าใน lock (`src/windows/fim_native.c:26-33`, `:49-52`, `:111-124`). Event เป็น manual-reset แต่ไม่มี `ResetEvent` ก่อน reissue `ReadDirectoryChangesW` (`:33-42`), จึงมีโอกาส wait จาก signal เก่าและวนผิดจังหวะ. ถ้า `WaitForSingleObject` ใน `aegis_fim_stop` ครบ 5 วินาที thread อาจยังรันอยู่ แต่ code ปิด handles, ลบ critical section และ free session ทันที (`:97-108`); worker อาจ dereference freed session.

ถ้า output buffer เล็กกว่า event, poll ล้าง `data_ready` และทิ้ง record (`:119-124`) โดยไม่แจ้ง overflow.

**ข้อแก้:** ใช้ lock/condition state, reset event, cancel + wait จน thread จบจริงก่อน free; preserve pending data เมื่อ output เล็ก. เพิ่ม test stop ระหว่าง pending IO, repeated restart และ undersized poll buffer.

## P1-9: ETW native helper มี compile/lifecycle/callback risks

`etw_native.c` เรียก `StopTrace(...)` (`src/windows/etw_native.c:175`, `:187`) แต่ source นี้ไม่มี declaration และ Windows ETW API ปกติใช้ `ControlTraceW`; ต้องยืนยัน WDK compile. `InitializeCriticalSection` ถูกเรียกใน start (`:104-110`) แต่ไม่มี `DeleteCriticalSection`; `aegis_etw_set_callback` ใช้ lock ก่อนมีการ initialize ได้ (`:202-207`). เมื่อ `CreateThread` ล้มเหลว source หยุด trace แต่ไม่ reset `session_handle` และไม่ free/null `properties` (`:171-179`), ทำให้ restart path ค้างหรือ leak.

`ext_len` เป็น `uint16_t` แต่สะสม extended data ได้ถึง 256 KB (`:69-82`); เมื่อเกิน 65535 ค่าที่ส่ง callback อาจ wrap. Callback pointer ถูกอ่านนอก lock (`:84-87`) ขณะที่ setterเขียนใต้ lock.

**ข้อแก้:** ใช้ `ControlTraceW`, explicit init/destroy lock, reset state ทุก failure path, ใช้ `size_t` ภายในและจำกัด ABI length อย่างชัดเจน, snapshot callback under lock.

## P1-10: Minifilter communication มี path/cleanup/security defects

Header ใช้ `L"\AegisMinifilterPort"` (`drivers/minifilter/aegis_minifilter.h:7-10`). `\A` เป็น escape ที่ไม่ใช่ backslash literal; path ที่ตั้งใจควรมี backslash สองตัวใน source. ต้องยืนยัน compiler behavior และ runtime name.

`AegisFilterDisconnect` เรียก `FltCloseCommunicationPort(g_ClientPort)` กับ client port (`drivers/minifilter/aegis_minifilter_comm.c:265-275`). Client port ต้องใช้ client-port close API ตาม WDK lifecycle; การใช้ server close API เสี่ยง cleanup ผิด object. Port security ใช้ `FLT_PORT_ALL_ACCESS` (`:235`) แทน ACL ที่แคบ.

INF เก็บ altitude เป็น DWORD (`drivers/minifilter/aegis_minifilter.inf:46-47`); minifilter altitude โดยปกติเป็น string registry value. ต้องยืนยันกับ installer/WDK เพราะอาจทำให้ load/install ล้มเหลว.

## P1-11: Export/build path ยังไม่มีหลักฐานว่า Rust จะ resolve symbols ได้

C functions ใน `src/windows/wfp_ioctl.c` และ `src/windows/aegis_wfp.c` ไม่มี `__declspec(dllexport)` หรือ `.def` ใน source. ในขณะที่ Rust ใช้ `GetProcAddress` สำหรับ `aegis_wfp_ioctl_open`, `...block_flow`, `...unblock_filter`, `...query_filter` (`rust-src/lib.rs:297-315`) และ build scriptคาดหวัง dumpbin exports (`scripts/build_wfp_user_bridge.ps1:55-75`). Workspace ที่ตรวจพบ `bridge/CMakeLists.txt` แต่ไม่มี root `CMakeLists.txt` ที่ชัดเจนสำหรับ target `aegis_wfp_user`; script `cmake -S $Repo ... --target aegis_wfp_user` จึงยังเป็น build dependency ภายนอก/unknown.

**ผลกระทบ:** หากไม่มี export mechanism ใน toolchain จริง `Adapter::load()` จะคืน `None` และ production IPS จะ degraded แม้ DLL มีอยู่.

**ข้อแก้:** เพิ่ม explicit `.def` หรือ export annotations, compile/export test ด้วย `dumpbin /exports`, pin source list ใน root build และตรวจ DLL hash/provenance ที่ตรงกับ PEP artifact.

# P2 — correctness และ test gaps ที่ควรปิดหลัง P0/P1

## P2-1: Packet parser ไม่จำกัด parsing ตาม IPv4/UDP declared length และไม่จัดการ fragments

`ProtocolParser<IPv4Header>` ตรวจ `totalLen < headerLen` แต่ไม่ตรวจ `totalLen <= dataLen` และ `ParsePacket` ใช้ `dataLen - ipHeaderLen` เป็น transport/payload length (`bridge/aegis_packet_parser.hpp:151-155`, `:249-315`). UDP parserไม่ตรวจ UDP length. Fragment ที่ไม่ใช่ first fragment ยังถูกตีความเป็น TCP/UDP header. ผลคือ false positives และการอ่านข้อมูลนอก logical packet boundary แม้ยังอยู่ใน caller buffer.

เพิ่ม tests สำหรับ total length เล็ก/ใหญ่กว่า buffer, UDP length mismatch, fragment offset, IHL options, unaligned input และ protocol unknown.

## P2-2: Timestamp และ IP representation ไม่สอดคล้องกัน

C++ adapter บันทึก `GetTickCount64()` ลง field ที่ canonical comment ระบุ epoch milliseconds (`bridge/aegis_adapter.cpp:108-114`, `:120-133`). Python `_ip_to_int` ใช้ big-endian (`bridge/aegis_bridge_ctypes.py:269-277`) แต่ C++ display และ legacy driver log แยก bytes low-to-high (`bridge/aegis_bridge_main.cpp:339-350`; `drivers/wfp_callout/aegis_wfp_comm.c:98-102`). ต้องกำหนด byte-order เดียวใน ABI และ golden test บน Windows.

## P2-3: Python control wrapper รายงาน “block” แม้ bridge ปฏิเสธ mutation

C++ `aegis_bridge_block_ip` และ `unblock_ip` ตั้งใจคืน `-2` (`bridge/aegis_ipc.cpp:347-362`). แต่ `ips_decide` เรียก `block_ip(src_ip)` แล้วคืน string `"block"` โดยไม่ตรวจ return code (`bridge/aegis_bridge_ctypes.py:338-355`). นี่ขัด control-plane truth และอาจทำให้ UI/forensic log แสดง decision เป็น host effect. ต้องคืน `degraded/rejected` เมื่อ call ล้มเหลว และเพิ่ม test ที่ยืนยันไม่มี mutation claim.

## P2-4: Test suite ยังมี expectation ของ legacy enforcement และ selftest ที่ fail ตาม source ปัจจุบัน

`bridge/aegis_bridge_test.cpp:166-169` คาด `aegis_bridge_block_ip`/`unblock_ip` คืน 0 แต่ implementation ปัจจุบันคืน -2. Test นี้จึงขัดกับ fail-closed design. `aegis_adapter_selftest` ต้องได้ event (`bridge/aegis_adapter.cpp:462-484`) แต่ Process adapter บน non-Windows คืน no event และบน Windows ก็ต้องมี process diff จึงไม่ deterministic. `mouth/build_mouth.bat:41-47` บังคับให้มี `aegis_mouth_tui.rs` ซึ่งไม่อยู่ใน inventory และไม่มีใน `mouth/Cargo.toml`.

เปลี่ยน tests ให้แยก negative-control enforcement test จาก telemetry selftest; ห้าม test block สำเร็จโดยไม่ provider proof.

## P2-5: C++ adapters ยังเป็น keepalive/stub ไม่ใช่ native telemetry ครบตามคำอธิบาย

`FimAdapter`, `RegistryAdapter` และ `EtwAdapter` สร้าง synthetic keepalive events (`bridge/aegis_adapter.cpp:213-290`). Zig `windows_adapters.zig` ระบุ Windows implementation เป็น “real” แต่ `start`/`nextEventImpl` ยังมี comments ว่า real Win32 integration เป็น future work และคืน `null` (`src/windows/windows_adapters.zig:135-170`, `:255-287`, `:377-410`). Network kind ถูก enum ไว้แต่ `registry_add` ไม่มี case จึง start ไม่ได้ (`bridge/aegis_adapter.cpp:361-377`). นี่เป็น test/evidence gap ไม่ใช่ host-enforcement proof.

## P2-6: Mouth monitor อาจนับ pending block เป็น blocked และมี stale-state/thread gaps

`TailReader` เพิ่ม `blocked_count` จากข้อความ `"Block"`/`"Drop"` โดยไม่ตรวจ receipt/host effect (`mouth/windows_sec_monitor.rs:603-619`), ขณะที่ mitigation feed ตรวจ `ENFORCED` และ `host_effect_confirmed` (`mouth/windows_sec_monitor.rs:497-513`). ทำให้ DEFCON ตัวเลขกับรายการ mitigation อาจขัดกัน: log เดียวกันอาจเพิ่ม blocked count แต่ไม่แสดงเป็น blocked mitigation. Dashboard footer ยังพิมพ์ `[ READY TO ENFORCE ]` โดยไม่อ้าง prevention gate หรือ control-plane status (`mouth/windows_sec_monitor.rs:899-905`), ทั้งที่ handoff กำหนด gate แยกจาก provider readiness และป้องกัน stale `ENFORCED` state [1].

Health server ใช้ detached thread และมี `SHUTDOWN` flag (`mouth/windows_sec_monitor.rs:111-118`, `:232-242`) แต่ `main` ไม่เรียก `health_pipe::shutdown()` และไม่มี signal/controlled shutdown path; เมื่อ log ถูก rotate หรือ truncate, `TailReader` ยังเก็บ offset เดิม (`:591-624`) และอาจหยุดเห็น events จนกว่าจะ restart process.

เพิ่ม test ที่ป้อน records แบบ `AUTHORIZED`, `SIMULATED`, `ENFORCED`, `ROLLBACK_PENDING`, `ROLLED_BACK` และตรวจทั้ง counters กับ UI state. เพิ่ม rotation/truncation test และให้ health state เปลี่ยนเป็น `DEGRADED` เมื่อ control daemon หรือ evidence source หาย.

## P2-7: Zig/C++ `IpcEvent` ABI ไม่ใช่ layout เดียวกัน

**Verified fact.** C++ bridge รับ `Aegis::Bridge::IpcEvent` ซึ่งเป็น packed struct 72 bytes และเริ่ม `event_type` ที่ offset 0 (`bridge/aegis_ipc.hpp:64-106`). Zig `src/core/bridge_init.zig` ประกาศ `AegisIpcEvent` ที่เพิ่ม `magic`, `version`, `struct_size` ก่อน `event_type` และมีเฉพาะ fields ถึง `defcon_impact` (`src/core/bridge_init.zig:58-83`). Function pointer ของ Zig ยังประกาศว่าฟังก์ชัน C++ รับ `*const AegisIpcEvent` (`:93-104`), แล้วส่ง pointer เดียวกันใน `pushEvent` (`:445-453`).


**ผลกระทบที่อนุมานโดยตรงจาก offsets.** C++ จะอ่าน Zig `magic` เป็น `event_type`, อ่าน version/size เป็นส่วนของ IP และอ่านเกินขนาด Zig object เมื่อใช้ fields extension. `validateIpcEvent` ไม่ได้ถูกเรียกโดย C++ และ C++ ไม่มี magic/version fields. นี่เป็น ABI corruption ใน event path และทำให้ health/readiness หรือ forensic correlation ไม่น่าเชื่อถือ แม้ไม่ใช่ direct WFP mutation.

**ความรุนแรง:** P1; ยกระดับเป็น P0 สำหรับ release ที่อ้าง real-sensor/forensic evidence.

**ข้อแก้ที่ทดสอบได้:** เลือก contract เดียว. ถ้าต้องการ header ให้เพิ่ม magic/version ใน C++ struct และ Python binding; ถ้าไม่ต้องการ ให้ Zig ใช้ C++ 72-byte layout และย้าย validation เป็น explicit versioned wrapper. เพิ่ม compile-time size/offset assertions และ canary test ที่ push event แล้วตรวจทุก field รวม extension.

## P2-8: Rust PEP, provider helper และ policy state ยังมี false-ready/false-capability paths

`aegis_pep_provider_ready` รายงาน ready เมื่อ `Adapter::load()` เปิด DLL และ device ได้ (`rust-src/lib.rs:402-416`) แต่ไม่ติดตั้ง filter, ไม่ query provider และไม่พิสูจน์ host effect. `aegis_pep_enforce` ไม่ใช้ `decision_kind`, `flow_id`, source tuple หรือ policy ID ใน authorization/evidence beyond passing some values to request (`rust-src/lib.rs:430-532`). Quota map ไม่เคยถูกเพิ่ม/นับ และ `two_person_rule` ไม่มี configuration/approval API (`rust-src/lib.rs:368-389`, `:449-493`, `:607-620`). สิ่งเหล่านี้ทำให้ provider readiness ถูกต้องในฐานะ capability probe เท่านั้น ไม่ใช่ IPS readiness.

`src/core/rust_pep.zig` มี safety model ที่ปฏิเสธ host-effect block และ legacy Boolean API (`src/core/rust_pep.zig:190-203`, `:283-313`), ซึ่งเป็น fail-closed ที่ดี แต่ยังเป็น Zig simulation แยกจาก Rust receipt path. ฝั่ง Rust federation TLS ยังมี stub ที่สร้าง server cert จาก empty vectors และ heartbeat คืน success โดยไม่เปิด network (`rust-src/lib.rs:642-669`); หากถูกผูกเข้า health จะเป็น false healthy.

เพิ่ม state machine ที่แยก `provider_ready`, `receipt_capable`, `enforcement_proof_active` และ `enforced`. Test ต้องยืนยันว่า `provider_ready=1` ไม่ทำให้ UI/control เรียก `ENFORCED`, และให้ stub transport ถูกปิดจาก production build.

# Testable next steps ที่ใช้เครดิตต่ำ

| ลำดับ | งาน | หลักฐานสำเร็จที่ต้องเก็บ |
|---|---|---|
| 1 | ทำ ABI compile matrix ก่อนแตะ host mutation | `sizeof/offsetof` ของ WFP request/response/query/state/event/stats และ Zig `@sizeOf/@offsetOf` ตรงทุก field; fail CI เมื่อเปลี่ยน |
| 2 | ลบหรือ quarantine duplicate `aegis_wfp_comm.c` path | source-to-binary map และ test dispatch หนึ่ง implementation ต่อ IOCTL |
| 3 | แก้ device/port ACL และ broker authentication | standard-user/low-integrity negative tests; ปลอม PID/capability ไม่ผ่าน |
| 4 | เปลี่ยน query เป็น provider enumeration และ tri-state result | pre-state, post-block exact tuple match, post-delete `present=false`, query error แยกจาก absent |
| 5 | เลือก dynamic proof filter หรือทำ persistent reconciliation | restart test ที่ตรวจ owner/provider/filter ID และไม่เหลือ stale object |
| 6 | แยก IDs และทำ serialized/idempotent cleanup | concurrent block test ไม่ overwrite receipt; cleanup ใช้ receipt ID เท่านั้น |
| 7 | แก้ Rust/C DLL ownership | repeated load/open/query/unblock/close test ไม่มี handle leak และ `FreeLibrary` เกิดหลัง close |
| 8 | เพิ่ม C/C++ sanitizer-style unit tests | ring full boundary, queue concurrent push/pop/shutdown, adapter canary capacity, parser length/fragment cases |
| 9 | สร้าง isolated host proof เฉพาะเมื่อ 1–8 ผ่าน | exact Kali tuple `192.168.126.10 → Windows:49153/TCP`, complete receipt, benign probe, exact cleanup, absent query |
| 10 | เก็บ provenance/evidence | driver/DLL/PEP hashes, provider filter pre/post records, event/trace/audit/receipt links, cleanup record |

## Minimal test commands บน Windows

หลังแก้ ABI ให้รัน test ที่ handoff ระบุ (`python -m pytest tests\\runtime\\test_operator_contracts.py -q`, `test_health.py`, `test_t8_rust_pep.py`, `test_t11_wfp_enforcement.py`, `zig build test -Doptimize=Debug`) และ WDK build (`powershell -ExecutionPolicy Bypass -File scripts\\wdk_build_production.ps1`) [1]. ก่อน proof ให้เพิ่ม test ใหม่ในลำดับนี้:

1. **ABI-only:** compile C header assertions, Zig layout tests และ Rust `#[test]`/C-side `static_assert`; ไม่เปิด driver mutation.
2. **Device negative:** standard user เปิด telemetry device ได้เฉพาะ read; mutation IOCTL ต้องได้ access denied.
3. **Provider fake/isolated:** mock provider enumeration หรือ dedicated disposable WFP sublayer เพื่อทดสอบ present/absent/query error.
4. **Lifecycle:** block → query → restart driver/service → query → unblock → query absent; ตรวจว่า old receipt ไม่สามารถลบ filter ใหม่.
5. **Concurrency:** สอง block requests พร้อมกันและ shutdown ระหว่าง request; ทุก receipt ต้องมี unique ID และ cleanup deterministic.
6. **Proof:** ใช้ control plane เท่านั้น ไม่ใช้ legacy ctypes/direct IP symbol และหยุดทันทีเมื่อ tuple, receipt หรือ cleanup ไม่ตรง.

## การจัดลำดับและเกณฑ์เปิด gate

ให้ถือ P0-1 ถึง P0-5 เป็น **hard stop**. การมี filter ID, provider DLL, successful `DeviceIoControl` หรือ UI decision ไม่พอ. Gate เปิดได้ต่อเมื่อมี provider-backed receipt ครบ requirement ทั้งหมด, independent tuple read-back ตรง, filter owner/restart policy พิสูจน์ได้, delete ใช้ receipt ID, query หลัง delete ยืนยัน absence และ evidence ถูก link ครบ. P1 ต้องปิดหรือมี signed exception ก่อน release candidate ใหม่; P2 ปิดก่อน production evidence matrix เพื่อไม่ให้ telemetry/GUI ลดทอนความหมายของหลักฐาน.

## References

[1]: /home/ubuntu/upload/AEGISProductionHandoff.md "AEGIS Production Handoff"
