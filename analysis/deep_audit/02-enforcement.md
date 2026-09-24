# Deep Audit 02 — Rust PEP, ABI และ WFP Enforcement

**Repository ที่ตรวจ:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`  
**ขอบเขต:** Rust PEP, Zig policy/FFI, user-mode WFP bridge, WFP kernel callout/IOCTL, C/C++ bridge, contracts, tests และ build/sign/install provenance  
**วิธีตรวจ:** ใช้ `git ls-files` เป็น inventory หลัก แล้วอ่าน source จริงตามเส้นทางที่ active; ไม่ใช้ `netsh`, Windows Firewall API, legacy `block_ip` หรือ bookkeeping เป็นหลักฐานว่า host ถูก block และไม่ได้รัน controlled host block หรือเปลี่ยนระบบภายนอก

## สรุปผลตรวจ

สถานะของขอบเขตนี้คือ **ยังไม่ผ่านการยอมรับด้าน enforcement และห้ามเรียกว่า production-ready**. โค้ดมีแนวคิด fail-closed และมีการแยก Rust PEP ออกจาก detection path ในหลายจุด แต่เส้นทาง port-specific ที่ควรเป็นเส้นทาง authoritative มีข้อผิดพลาดที่ทำให้ไม่สามารถพิสูจน์หรือรับ receipt ได้จาก source ปัจจุบัน:

1. `enforceFlow` ส่งค่า ordinal ของ `PepDecision.block` (`1`) เข้า Rust field `requested_action` ทั้งที่ Rust กำหนด `ACTION_BLOCK = 4`. ค่า `1` ถูกตีความเป็น `ACTION_LOG` จึงได้ `ALLOW` และไม่มี `filter_id` ก่อนถึง WFP driver
2. Kernel block filter ไม่กำหนด `filter.layerKey` ก่อนเรียก `FwpmFilterAdd0`
3. Kernel `AegisWfpDeviceControl` ไม่กำหนด `Irp->IoStatus.Information` หลังเขียน response ขนาด 12 ไบต์ ขณะที่ user bridge ต้องการ `out_len == sizeof(AEGIS_WFP_FLOW_RESPONSE)` และ `filter_id != 0`
4. Provider readiness ตรวจเพียงการโหลด DLL, การมี export และการเปิด device ไม่ได้ attest ว่า device เป็น driver binary ที่ provenance/hash ตรง, เป็น provider/sublayer ของ AEGIS หรือเป็น filter ที่ request นี้เป็นเจ้าของ
5. `g_FilterId` เป็น global เดียวที่ถูกใช้ร่วมทั้ง capture filter และ enforcement filter โดยไม่มี lock หรือ per-receipt ownership ทำให้เกิด race, cleanup ผิดตัว และ orphan filter ได้

ดังนั้นผลที่ถูกต้องคือ **NOT ACCEPTED**. Health, DLL load, compile log หรือ WFP API return code เพียงอย่างเดียวไม่ใช่หลักฐาน host enforcement; ต้องมี receipt ที่ตรวจได้และ traffic postcondition จาก Windows lab ซึ่งงานนี้ไม่ได้รันตามข้อห้ามของ task

## Inventory และไฟล์ที่ตรวจจริง

`git ls-files` พบไฟล์ในขอบเขตดังต่อไปนี้ รายการที่มีเครื่องหมาย `*` คือไฟล์ที่มีอยู่ใน working tree แต่ไม่พบใน `git ls-files`; จึงไม่ควรถือเป็น source-of-truth จนกว่าจะถูกจัดการ provenance ให้ชัดเจน

### Rust PEP และ shield

- `rust-src/lib.rs`
- `rust-src/shield/Cargo.toml`
- `rust-src/shield/src/lib.rs`
- `rust-src/shield/src/main.rs`
- `rust-src/shield/src/pep.rs`
- `Cargo.toml`
- `Cargo.lock`
- `shield/Cargo.toml`
- `shield/src/lib.rs`
- `shield/src/pep.rs`

### Zig policy และ FFI

- `src/policy/action_dispatcher.zig`
- `src/policy/control_ipc.zig`
- `src/policy/dispatcher.zig`
- `src/policy/dispatcher_phase_b.zig`
- `src/policy/pep_bindings.zig`
- `src/policy/policy_contract.zig`
- `src/policy/policy_engine.zig`
- `src/policy/policy_ir.zig`
- `src/policy/policy_plane.zig`
- `src/policy/policy_signing.zig`
- `src/policy/shadow_decision.zig`
- `src/policy/tier3_state.zig`
- `src/policy/trust_store.zig`
- `src/policy/wfp_ioctl.zig`
- `src/policy/wfp_production.zig`
- `src/policy/enforcement_receipt.zig`* — มีใน working tree แต่ไม่ tracked

### Windows user-mode และ adapter

- `src/windows/wfp_ioctl.c`
- `src/windows/aegis_wfp.c`
- `src/windows/cpp_adapter.zig`

### WFP kernel driver

- `drivers/wfp_callout/aegis_wfp.h`
- `drivers/wfp_callout/aegis_wfp.c`
- `drivers/wfp_callout/aegis_wfp_callout.c`
- `drivers/wfp_callout/aegis_wfp_comm.c`
- `drivers/wfp_callout/aegis_wfp.inf`
- `drivers/wfp_callout/aegis_minifilter.inf`

### C/C++ bridge

- `bridge/CMakeLists.txt`
- `bridge/__init__.py`
- `bridge/aegis_adapter.cpp`
- `bridge/aegis_adapter.hpp`
- `bridge/aegis_adapter_selftest_main.cpp`
- `bridge/aegis_bridge_ctypes.py`
- `bridge/aegis_bridge_main.cpp`
- `bridge/aegis_bridge_test.cpp`
- `bridge/aegis_ipc.cpp`
- `bridge/aegis_ipc.hpp`
- `bridge/aegis_packet_parser.cpp`
- `bridge/aegis_packet_parser.hpp`
- `bridge/bridge_status.py`

### Contracts และเอกสาร ABI ที่เกี่ยวข้อง

- `contracts/` มี directory อยู่จริง แต่ **ไม่มีไฟล์ tracked** ใน source-of-truth นี้
- `shared/abi/pep_abi.md`
- `shared/abi/runtime_abi.md`
- `shared/protocol/wire_v1.h`
- `shared/protocol/wire_v1.md`
- `shared/protocol/control_protocol.md`
- `shared/policy/policy_ir.md`
- `docs/platform/p4-enforcement-contract.md`
- `docs/WFP_IOCTL_STATUS.md`

### Build, sign, install และ release ที่เกี่ยวข้อง

- `CMakeLists.txt`
- `Makefile`
- `build.zig`
- `bridge/CMakeLists.txt`
- `scripts/build_all.bat`
- `scripts/build_and_check.ps1`
- `scripts/build_drivers.bat`
- `scripts/install_aegis.ps1`
- `scripts/install_drivers.bat`
- `scripts/package_release.ps1`
- `scripts/release_package.ps1`
- `scripts/verify_release.ps1`
- `scripts/wdk_build_production.ps1`
- `scripts/wfp_service.ps1`
- `scripts/wfp_sign.ps1`
- `release/aegis-nids-windows-6.0.0-20260916_223148/scripts/install_aegis.ps1`
- `scripts/build_wfp_user_bridge.ps1`* — มีใน working tree แต่ไม่ tracked
- `scripts/run_wfp_phase10_preflight.ps1`* — มีใน working tree แต่ไม่ tracked
- `scripts/run_vmware_lab_preflight.ps1`* — มีใน working tree แต่ไม่ tracked
- `scripts/run_host_production_preflight.ps1`* — มีใน working tree แต่ไม่ tracked

### Tests ที่เกี่ยวข้อง

- `tests/pep/test_t8_rust_pep.py`
- `tests/wfp/test_t11_wfp_enforcement.py`
- `tests/wfp/test_t11_windows_host.py`
- `src/tests/policy/pep_bindings.zig`
- `src/tests/policy/action_dispatcher.zig`
- `src/tests/integration/rust_pep_integration.zig`
- `src/tests/integration/policy_integration.zig`
- `src/tests/integration/policy_plane_integration.zig`
- `src/tests/integration/ips_canary_integration.zig`
- `src/tests/proofs/pep_enforcement_proof.zig`
- `src/tests/proofs/policy_plane_proof.zig`
- `tests/release/test_t17_perf_ci_installer.py`

## Call/data/control flow

### เส้นทาง block ที่ตั้งใจให้เป็น authoritative

1. ผู้เรียกที่มีสิทธิ์ส่ง control request เข้าสู่ Zig handler. `src/control/handler_registry.zig:520-565` ตรวจ `caller_role == privileged`, อ่าน `dst_ip`, `dst_port`, `protocol`, `policy_id` และ `severity` แล้วเรียก `PepEnforcer.enforceFlow`.
2. Handler ส่ง `caller_caps = 1` แบบค่าคงที่ไปยัง PEP ที่บรรทัด 559. ค่า capability นี้ไม่ได้ถูก derive จาก Windows access token ใน handler
3. `src/policy/pep_bindings.zig:147-182` สร้าง `PepRequest` แบบ `extern struct`, เรียก `aegis_pep_enforce`, แล้วรับเฉพาะ response ที่ `decision == block` และ `filter_id != 0` จึงจะสร้าง `PepEnforcementReceipt`
4. Rust `aegis_pep_enforce` ที่ `rust-src/lib.rs:398-502` ตรวจ null pointer, capability bit 0, action, two-person rule และโหลด `aegis_wfp_user.dll` บน Windows
5. `rust-src/lib.rs:248-317` ใช้ `LoadLibraryW`, `GetProcAddress` และ `transmute` เพื่อ bind export `aegis_wfp_ioctl_block_flow`, `aegis_wfp_ioctl_unblock_filter` และ `aegis_wfp_ioctl_open`. จากนั้น C bridge เปิด `\\.\AegisWfpDevice`
6. `src/windows/wfp_ioctl.c:121-131` ส่ง `IOCTL_AEGIS_BLOCK_FLOW` ด้วย request packed 8 ไบต์ และ buffer output 12 ไบต์. ต้องได้ `out_len == 12` และ `filter_id != 0`
7. Kernel dispatch ที่ `drivers/wfp_callout/aegis_wfp.c:151-178` เลือก `AegisWfpBlockFlow`. ฟังก์ชันที่บรรทัด 215-275 ควรสร้าง filter ด้วย remote IPv4, remote port และ protocol แล้วคืน `filter_id` กับ `provider_status`
8. หากทุก boundary ผ่าน Zig handler คืน JSON `status=ENFORCED` ที่ `handler_registry.zig:565`. ใน source ปัจจุบัน JSON นี้ยังไม่มี request/trace/audit/event/runtime-generation หรือ traffic postcondition

### เส้นทาง cleanup

`enforcement.unblock` ที่ `handler_registry.zig:568-588` รับ `filter_id` เท่านั้น แล้วเรียก `PepEnforcer.unblockFilter`. Rust export `aegis_pep_unblock_filter` ที่ `rust-src/lib.rs:528-552` ตรวจ non-zero ID และ capability ก่อนเรียก C bridge. C bridge ส่ง `IOCTL_AEGIS_UNBLOCK_FLOW` ด้วย `uint64_t` ที่ `src/windows/wfp_ioctl.c:134-138`. Kernel ตรวจว่า ID ตรงกับ global `g_FilterId` ที่ `drivers/wfp_callout/aegis_wfp.c:355-369`, เปิด WFP engine, เรียก `FwpmFilterDeleteById0` และล้าง global ที่บรรทัด 394-408

เส้นทางนี้เป็นคนละสัญญากับ legacy `aegis_pep_unblock_ip` ซึ่งยังเรียก `aegis_wfp_ioctl_unblock_ip` ด้วย IPv4 4 ไบต์. Kernel active path ต้องการ `UINT64 filter_id`; จึงไม่ใช่ cleanup ที่ใช้ได้กับ port-specific receipt

### Boundary และ privilege

Boundary หลักคือ **control pipe/handler ใน Zig → FFI Rust PEP → user-mode DLL/C IOCTL → kernel driver/WFP**. Rust และ Zig อยู่ใน process เดียวกัน จึงไม่มี process isolation ระหว่างผู้เรียก FFI กับ PEP. C bridge เป็น user-mode/kernel boundary ผ่าน `DeviceIoControl(METHOD_BUFFERED)`. Kernel driver ทำ WFP mutation และสร้าง filter ที่เป็น persistent.

`PepRequest` และ `PepResponse` ไม่ได้ผูก capability mask กับ Windows token หรือ caller PID ที่พิสูจน์ได้. Rust ใช้ค่าที่ผู้เรียกส่งมาโดยตรง; `caller_pid` และ `request_id` ถูกทิ้งใน `aegis_pep_unblock_ip` และ `aegis_pep_unblock_filter` ที่บรรทัด 511 และ 538. การป้องกันที่เหลือจึงขึ้นกับ control-plane authorization และ ACL ภายนอก FFI ซึ่งไม่ใช่การ attest caller ภายใน Rust ABI

## ABI, packing, endian และ enum

### จุดที่สอดคล้อง

`PepContext`, `PepRequest` และ `PepResponse` ใช้ `#[repr(C)]` ใน Rust และ `extern struct` ใน Zig. Field หลักเรียงลำดับเดียวกัน. `FlowRequest`/`FlowResponse` ใช้ `#[repr(C, packed)]` ใน Rust และ `#pragma pack(push,1)` ใน C header/source. IOCTL codes ใน `drivers/wfp_callout/aegis_wfp.h:22-26` และ `src/windows/wfp_ioctl.c:22-26` ตรงกันโดยข้อความ source.

### Finding ที่ทำให้ active block ใช้งานไม่ได้

**C-01 — ordinal ของ action ถูกส่งผิดชนิด (Critical).** `PepDecision.block` มีค่า `1` ที่ `src/policy/pep_bindings.zig:17-24`, แต่ Rust policy action กำหนด `ACTION_LOG = 1` และ `ACTION_BLOCK = 4` ที่ `rust-src/lib.rs:198-205`. `enforceFlow` บรรทัด 159-162 ใช้ `@intFromEnum(PepDecision.block)` เป็น `requested_action` แทน `@intFromEnum(policy.Action.block)`. Rust จึงเข้า branch `matches!(requested_action, ACTION_PASS | ACTION_LOG | ACTION_ALERT)` ที่บรรทัด 430 และตอบ `DECISION_ALLOW`; Zig บรรทัด 174 ปฏิเสธเพราะ response ไม่ใช่ `block` และไม่มี receipt. นี่เป็น bug ที่ deterministic และเกิดก่อน WFP IOCTL

**C-02 — filter ไม่กำหนด layer และ output length ไม่ถูกคืน (Critical).** `AegisWfpBlockFlow` ตรวจ input/output length ที่ `drivers/wfp_callout/aegis_wfp.c:228-231` และเติมสาม conditions ที่ `242-254`, แต่ไม่กำหนด `filter.layerKey` ก่อน `FwpmFilterAdd0` ที่ `266`. `filter` ถูก zero-initialize ที่ `256`, ดังนั้น layer GUID ไม่ได้มาจาก request หรือ constant ใด. นอกจากนี้ `AegisWfpDeviceControl` ที่ `152-178` ไม่ตั้ง `Irp->IoStatus.Information` เป็น `sizeof(AEGIS_WFP_FLOW_RESPONSE)`. ฝั่ง user bridge ที่ `src/windows/wfp_ioctl.c:121-131` ยอมรับผลสำเร็จเฉพาะเมื่อ `out_len == sizeof(*response)` และ `filter_id != 0`. ต่อให้ WFP เพิ่ม filter ได้ response length จึงไม่ผ่านสัญญา receipt ใน source ปัจจุบัน

**C-03 — provider readiness ไม่ใช่ provider attestation (Critical).** `aegis_pep_provider_ready` ที่ `rust-src/lib.rs:377-385` คืน 1 เมื่อ `wfp_adapter::Adapter::load()` สำเร็จ. Adapter ตรวจเพียง DLL exports และเรียก `aegis_wfp_ioctl_open` ที่เปิด device; ไม่ตรวจ SHA-256 ของ driver, service image path, signature chain, provider GUID, sublayer GUID, filter owner หรือ `provider_status`. `src/windows/aegis_wfp.c:31-50` เพิ่ม provider/sublayer แต่ block filter ใน kernel `aegis_wfp.c:256-265` ไม่กำหนด provider/sublayer key และไม่ได้เชื่อมกับ GUID เหล่านั้น. จึงไม่มี cryptographic หรือ semantic binding ระหว่าง “provider ready” กับ filter ที่กำลังจะ mutate host. การโหลด DLL ชื่อเดียวกันหรือ driver เก่าที่เปิด device ได้สามารถผ่าน readiness ได้

**C-04 — filter identity เดียวถูกใช้ข้าม lifecycle และ race ได้ (Critical).** Driver เก็บ `g_FilterId` เดียวใน `aegis_wfp.h:94-104`. Registration ของ callout เก็บ capture filter ID ใน `drivers/wfp_callout/aegis_wfp_callout.c:218-232`; block flow เขียนทับ global เดียวกันที่ `drivers/wfp_callout/aegis_wfp.c:266-273`. การ block พร้อมกันสอง request จึงเขียนทับ ID แรก และ cleanup จะตรวจ/ลบได้เฉพาะ ID ล่าสุด. ไม่มี spin lock หรือ interlocked ownership รอบ `g_FilterId`, `g_BlockedIp` และ WFP open/delete. เมื่อ unload เรียก `AegisWfpUnregisterCallout` ที่ `aegis_wfp_callout.c:236-263`, capture filter ID เดิมที่ถูกเขียนทับอาจกลายเป็น orphan และ persistent enforcement filter อาจค้างข้าม service/driver lifecycle. นี่ทำให้ exact cleanup และ absence-of-orphan invariant พิสูจน์ไม่ได้

## Findings ระดับ Important

**I-01 — legacy IP-only ABI ขัดกับ port-specific active ABI และยังถูก export (Important).** `src/windows/wfp_ioctl.c:107-117` ส่ง block/unblock ด้วย IPv4 4 ไบต์. Active kernel block ต้องการ `AEGIS_WFP_FLOW_REQUEST` 8 ไบต์ที่ `aegis_wfp.c:228-234`; active unblock ต้องการ filter ID 8 ไบต์ที่ `355-369`. Rust `aegis_pep_unblock_ip` ที่ `rust-src/lib.rs:504-525` ยังเรียก legacy export. แม้ legacy bridge จะ fail หรือคืน error ใน driver รุ่น active แต่การคง API นี้เปิดโอกาสให้ caller สับสนว่า IP-only cleanup ใช้ได้ และ test T11 ยังตรวจ contract เก่านี้

**I-02 — test ABI ของ `PepResponse` ล้าสมัยและไม่ตรวจ `filter_id` (Important).** Rust response มี `filter_id: u64` ที่ `rust-src/lib.rs:179-186`; Zig declaration มี field เดียวกันที่ `src/policy/pep_bindings.zig:47-53`. Layout ตาม `extern` จึงมี `filter_id` ที่ offset 16 และขนาดรวม 24 ไบต์บน x64. แต่ test ใน `pep_bindings.zig:275-285` คาดขนาด 16 และตรวจ offset เพียงถึง `signed_by` โดยไม่ตรวจ offset ของ filter ID. Test binary serialization ที่ `315-341` ก็ตรวจเพียง flow ID. นี่เป็นหลักฐานว่า ABI gate ไม่ได้ freeze สัญญาที่ receipt ใช้จริง

**I-03 — endian/packing มีคำอธิบายแต่ไม่มี executable proof ที่ครบ (Important).** C header ระบุ `remote_ipv4` เป็น network order และ `remote_port` เป็น host order ที่ `drivers/wfp_callout/aegis_wfp.h:28-43`; Zig และ Rust ส่งค่าตรงโดยไม่แปลง. `parseIpv4` ใน `src/policy/wfp_ioctl.zig:241-268` สร้างค่าแบบ dotted-quad integer แต่ไม่ได้พิสูจน์ byte sequence ที่ข้าม C `METHOD_BUFFERED` และ WFP condition. ไม่มี static assertion ของ offsets/size ใน C, ไม่มี test vector ของ `remote_port` หรือ `protocol`, และไม่มี test ที่อ่าน filter condition ที่ติดตั้งจริง. ต้องกำหนด byte order หนึ่งจุดและทดสอบ `192.168.126.20:8080/TCP` ข้ามทุก boundary ก่อนเรียก host proof

**I-04 — `provider_status` ถูกละทิ้ง และ error taxonomy ไม่พอสำหรับ receipt (Important).** C bridge ตรวจ `out_len` และ `filter_id` เท่านั้นที่ `src/windows/wfp_ioctl.c:126-131`; Rust `Adapter::block_flow` ก็คืน `Some(id)` โดยไม่ตรวจ `FlowResponse.provider_status` ที่ `rust-src/lib.rs:221-225` และ `288-310`. Handler สร้าง JSON `ENFORCED` จาก filter ID อย่างเดียวที่ `src/control/handler_registry.zig:565`. จึงขาดการตรวจ native status, provider identity, operation owner และ postcondition

**I-05 — unsafe FFI มี boundary แต่ไม่ตรวจ ABI ของ function pointer (Important).** `rust-src/lib.rs:242-246` ประกาศ Windows APIs เป็น `unsafe extern "system"`; `GetProcAddress` ถูกแปลงด้วย `transmute` ที่ `248-290` เป็น function pointers หลาย signature โดยไม่มี export version, architecture check, calling-convention probe หรือ ABI hash. `Adapter::Drop` ที่ `rust-src/lib.rs:317-319` เรียก `FreeLibrary` แต่ไม่ได้เรียก exported `aegis_wfp_ioctl_close`; C bridge ใช้ global handle `g_wfp_device` ที่ `src/windows/wfp_ioctl.c:72-80` โดยไม่มี mutex. การ load/block/unblock หลาย thread จึงมี race ที่ handle และ module lifetime และไม่มี deterministic close ใน normal Drop path

**I-06 — capability gate รับค่าที่ control handler สร้างขึ้นเอง (Important).** Handler บังคับ role เป็น privileged ที่ `src/control/handler_registry.zig:520-526` และ `568-573` แต่ส่ง capability mask `1` แบบ hard-coded ที่บรรทัด 559 และ 582. Rust ตรวจเพียง bit mask ที่ caller ใส่ให้ที่ `rust-src/lib.rs:427` และ `539`; ไม่ตรวจ token, PID หรือ signed capability grant. Direct caller ที่เข้าถึง DLL สามารถส่ง bit นี้ได้ และ control-plane role ไม่ได้ถูกผูกใน ABI receipt. ควรย้าย capability authority ไปสู่ authenticated context ที่ Rust ตรวจสอบได้ หรือไม่ก็ทำให้ PEP export ไม่รับ arbitrary caller-supplied mask

**I-07 — device access ไม่มี explicit ACL และ driver create/close ยอมรับทุก caller (Important).** `DriverEntry` สร้าง device/symlink ที่ `drivers/wfp_callout/aegis_wfp.c:52-81` โดยไม่พบ `IoCreateDeviceSecure`, SDDL หรือ explicit security descriptor. `AegisWfpCreate` และ `AegisWfpClose` ที่ `132-149` คืน success โดยไม่ตรวจ caller. IOCTL access bits อย่างเดียวไม่ใช่หลักฐานว่า privileged control-plane identity ถูกบังคับครบถ้วนใน driver boundary

**I-08 — มี implementation เก่าซ้ำใน build graph (Important).** `scripts/build_drivers.bat:188-210` compile ทั้ง `aegis_wfp.c`, `aegis_wfp_callout.c` และ `aegis_wfp_comm.c`. `aegis_wfp_comm.c:73-142` มี static IP-only `AegisWfpBlockFlow`; dispatch ของไฟล์นี้ที่ `171-204` ไม่มี unblock case. ส่วน active global dispatch ใน `aegis_wfp.c:151-178` ใช้ port-specific block/unblock. แม้ static linkage อาจทำให้ dispatch เก่าไม่ถูกเรียก แต่การ compile implementation สองแบบทำให้ binary provenance และ security review ไม่เป็น single source of truth

**I-09 — build/install/provenance path ไม่เป็นเส้นเดียวและยังรองรับ test signing (Important).** `CMakeLists.txt:23-35` build user DLL แต่ `BUILD_KERNEL_DRIVER` ที่ `64-71` จงใจ `FATAL_ERROR`; driver ใช้ script อื่น. `build_drivers.bat` ส่ง output หลายตำแหน่ง ขณะที่ `scripts/wfp_service.ps1:55-77` default เป็น `build\\x64\\wfp\\aegis_wfp.sys` และ `scripts/install_aegis.ps1:45-52` ใช้ install-root driver อีก path. `wfp_service.ps1:47-62` รายงาน signature แต่เตือนแล้วเดินหน้าต่อได้เมื่อ unsigned; `:138-140` hash เป็นการพิมพ์ค่า ไม่ใช่ equality gate กับ build artifact. `package_release.ps1:26-30` อ้าง source `drivers\\wfp_callout\\aegis_wfp.sys` ซึ่งไม่ใช่ output `.sys` จาก WDK build script โดยตรง. `wfp_sign.ps1` เป็น test-sign route ไม่ใช่ production signing evidence

**I-10 — authoritative production Zig boundary ยังเป็น no-op และเอกสารขัดกับ source driver (Important).** `src/policy/wfp_production.zig:16-21` ให้ `submitViaPep` คืน `.unavailable` เสมอ แม้ test manifest จะวาง module นี้เป็น REAL/golden path. ในทางกลับกัน `docs/WFP_IOCTL_STATUS.md:3-21` ระบุว่า driver อยู่ tracking-only และไม่มี block/unblock handler ทั้งที่ `drivers/wfp_callout/aegis_wfp.c` มี handler ใน source ปัจจุบัน. ความขัดแย้งนี้ทำให้ไม่ทราบว่า artifact ใดคือ enforcement authority ที่ build/install จริง และทำให้ static evidence ไม่น่าเชื่อถือ

**I-11 — receipt ไม่ผูก forensic และ host postcondition (Important).** Handler คืนเพียง `status`, `filter_id`, `reason`, flow fields ที่ `handler_registry.zig:565`; ไม่มี `request_id`, `trace_id`, `audit_id`, `event_id`, runtime generation, provider status, cleanup result หรือ traffic verification. `src/policy/enforcement_receipt.zig` ที่มีใน working tree แต่ไม่ tracked มี schema test บางส่วน จึงยังไม่ใช่ tracked contract. `filter_id` จาก WFP API return เพียงอย่างเดียวไม่พิสูจน์ว่า TCP traffic ถูก block หรือว่าการ cleanup คืน traffic ได้

## Reliability, concurrency และ resource cleanup

PEP state ใช้ `OnceLock<Mutex<PepState>>` สำหรับ quota และ approval ซึ่งเหมาะกับ state ส่วนนี้ แต่ lock ถูกปล่อยก่อน adapter call ที่ `rust-src/lib.rs:462`. จึงไม่มี serialization ระหว่าง authorization กับ mutation และไม่มี transaction linking request กับ filter ID. การเปิด adapter ใหม่ทุก enforcement ที่ `467-488` ทำให้เกิด DLL/device lifecycle ซ้ำและเพิ่ม latency. C global handle ไม่มี lock. Kernel global filter state ไม่มี lock และไม่รองรับมากกว่าหนึ่ง active receipt. `FwpmEngineOpen0` ใน block/unblock ใช้ session แยกแต่ละ request และปิด engineหลัง operation; เมื่อ filter เป็น persistent การปิด sessionไม่ใช่การลบ filter และต้องมี durable ownership/recovery protocol ซึ่ง source ยังไม่มี

Driver unload ทำความสะอาด ring/device/callout ตาม `aegis_wfp.c:108-130` แต่ไม่มีขั้นตอน enumerate-and-delete filters ที่เป็น persistent ของ AEGIS ทั้งหมด. การอาศัย `g_FilterId` เดียวไม่พอสำหรับ crash, restart, duplicate daemon หรือ filter ที่ถูกสร้างแล้ว process ตายก่อนบันทึก receipt. การ fail-open ไม่ปรากฏใน path หลัก แต่ failure semantics ยังอาจเป็น **stale block** ซึ่งเป็น reliability และ availability risk

## Test และ evidence gaps

- `tests/pep/test_t8_rust_pep.py` เป็น static/source contract checks และตรวจว่ามี unsafe boundary; ไม่ execute Windows DLL, IOCTL หรือ WFP filter
- `tests/wfp/test_t11_wfp_enforcement.py` ตรวจ source/manifest. ส่วน `:172-179` ยัง assert contract เก่าที่คาด `UINT32` IP unblock ซึ่งไม่ตรง active `UINT64 filter_id`
- `tests/wfp/test_t11_windows_host.py:52-54` skip นอก Windows และ skip จนกว่าจะตั้ง `AEGIS_RUN_WFP_HOST_TESTS=1`. จึงไม่มี host evidence จาก run นี้
- `src/tests/policy/pep_bindings.zig` import module และพึ่ง tests ภายใน แต่ ABI test ของ response คาดขนาดผิดตาม I-02
- ไม่มี test ที่ป้องกัน ordinal bug ใน `enforceFlow`; มีเพียง test ว่า enum แต่ละตัวมี ordinal ที่คาด
- ไม่มี test ที่ compile/run active WDK artifact แล้วตรวจ `filter.layerKey`, `IoStatus.Information`, `provider_status`, exact filter conditions, filter owner/provider key หรือ exact cleanup หลัง restart
- ไม่มี concurrency test สำหรับสอง block, block/unblock พร้อมกัน, duplicate receipt, driver unload ระหว่าง IOCTL และ stale filter recovery
- ไม่มี test สำหรับ device ACL, direct untrusted DLL caller, token-to-capability binding, SHA-256 build-vs-installed และ service image path equality
- ไม่มี cross-language golden vector ที่ตรวจ `remote_ipv4`, port byte order, protocol, packed sizes, offsets และ filter ID ตั้งแต่ Zig → Rust → C → kernel
- ใน sandbox นี้ไม่สามารถรัน local test ได้เพราะไม่มี `cargo`, `zig` และ `pytest` ใน PATH (`cargo_rc=127`, `pytest_rc=1`, `zig_rc=127`). ไม่ได้ติดตั้งเครื่องมือเพิ่ม และไม่ได้รัน controlled host mutation ตามข้อกำหนด
- ไม่พบหลักฐานที่ source นี้ว่า traffic baseline `HTTP 200` → block → cleanup → `HTTP 200` ถูกทำสำเร็จพร้อม filter ID เดิมและไม่มี orphan filter

## Action ที่แนะนำ เรียงตามความสำคัญ

1. **หยุดการอ้างว่า enforcement สำเร็จทันที** และปิด `enforcement.block` จาก acceptance gate จนแก้ C-01 และ C-02 แล้วทำ host proof ใหม่ครบ receipt/postcondition
2. แก้ `enforceFlow` ให้ส่ง `policy.Action.block` หรือสร้าง `ACTION_BLOCK` constant ที่ shared contract เดียวกัน; เพิ่ม test ที่ตรวจ request byte/ordinal และยืนยัน Rust branch เป็น `ACTION_BLOCK`
3. กำหนด `filter.layerKey` เป็น layer ที่ต้องการอย่างชัดเจน และกำหนด `Irp->IoStatus.Information = sizeof(AEGIS_WFP_FLOW_RESPONSE)` เฉพาะเมื่อ response ถูกเขียนครบ; เพิ่ม kernel/user integration test ที่ตรวจ out length
4. สร้าง shared ABI header หรือ generated contract เดียวระหว่าง Rust, Zig และ C พร้อม `_Static_assert`/compile-time assertions ของ size, offsets, enum ordinals, packed layout และ endianness. เพิ่ม vector สำหรับ IPv4/port/protocol ที่มี expected wire bytes
5. ออกแบบ provider attestation ใหม่ให้ตรวจ driver image path, SHA-256 ที่คาดหมายจาก signed build manifest, signature/trust mode, device identity, provider/sublayer GUID และ filter ownership. `provider_ready` ต้องไม่เป็นเพียง “เปิด device ได้”
6. เปลี่ยนจาก `g_FilterId` เดียวเป็น receipt ownership store ที่มี request/trace/policy/generation/filter identity และ lock ที่ชัดเจน. Cleanup ต้อง idempotent, ใช้ ID จาก receipt เดิม, handle restart/crash และ enumerate/remove เฉพาะ filters ที่มี AEGIS provider ownership
7. ตัด legacy IP-only exports หรือทำให้ return type/ชื่อชัดว่า unsupported; ให้ `aegis_pep_unblock_ip`, `aegis_wfp_ioctl_unblock_ip`, `aegis_wfp_comm.c` และ tests เก่าถูก quarantine หรือ migrate ไป exact filter ID
8. ผูก capability กับ authenticated control identity และ Windows token/ACL ที่ตรวจสอบได้. ห้าม handler เติม `caller_caps=1` แบบ hard-coded; เพิ่ม negative tests สำหรับ direct DLL caller และ role/capability mismatch
9. เพิ่ม explicit device security descriptor/SDDL และตรวจ access ใน driver create/IOCTL. จำกัด write IOCTL ให้ service identity ที่อนุมัติ
10. ทำให้ build graph มี source เดียว: เลือก implementation เดียวระหว่าง `aegis_wfp.c` กับ `aegis_wfp_comm.c`, ให้ CMake/script/INF/service/package ใช้ output path เดียว และ fail หาก build hash กับ installed hash ต่างกัน. Test signing ต้องแยกชัดจาก production signing
11. เติม live Windows test ใน disposable VM เท่านั้น: malformed request ต้องไม่สร้าง filter; valid TCP flow ต้องได้ baseline 200, receipt ต้องมี non-zero filter ID/provider status, traffic ต้อง fail, exact unblock ต้องคืน 200 และ enumerate ต้องไม่พบ orphan; ทำซ้ำหลัง driver/daemon restart
12. ขยาย forensic receipt ให้ link `request_id`, `trace_id`, `audit_id`, `event_id`, `policy_id`, runtime generation, provider status, host postcondition และ cleanup result ก่อนเปิด production acceptance
13. แก้หรือ quarantine เอกสาร `docs/WFP_IOCTL_STATUS.md`, `src/policy/wfp_production.zig` และ manifest ให้ตรงกับ source/build artifact จริง. ไฟล์ที่มีอยู่แต่ไม่ tracked เช่น `src/policy/enforcement_receipt.zig` และ `scripts/build_wfp_user_bridge.ps1` ต้องถูกนำเข้า version control หรือไม่ให้เป็นหลักฐาน

## ข้อสรุปตามหัวข้อที่ร้องขอ

- **ABI layout:** PepRequest โดยหลักตรงกัน แต่ PepResponse test ล้าสมัย; FlowRequest/Response packed ตรงตามข้อความแต่ไม่มี cross-language executable proof ครบ
- **Integer endian/packing:** มี comment ระบุ network IPv4/host port แต่ไม่มี conversion/byte-vector proof ที่ kernel condition; ต้องถือว่ายังไม่ verified
- **Enum ordinals:** พบ critical mismatch ระหว่าง `PepDecision.block=1` กับ `ACTION_BLOCK=4` ใน active `enforceFlow`
- **Pointer/calling convention/unsafe:** Rust ใช้ explicit unsafe boundary แต่ `GetProcAddress` + `transmute` ไม่ validate ABI และ Drop ไม่ปิด device handle โดยตรง
- **Capability gates:** มี bit check ใน Rust แต่ capability ถูกส่งเป็น hard-coded `1` จาก handler และไม่ผูกกับ authenticated token/PID
- **Provider attestation:** ตรวจเพียง DLL exports/device-open; ไม่ตรวจ provider identity, hash, signature หรือ filter ownership
- **Exact filter identity:** Receipt path ตั้งใจใช้ `u64 filter_id` แต่ global เดียวรองรับ filter เดียว, ถูกเขียนทับ และไม่ durable
- **Block/unblock cleanup:** exact ID path มีอยู่ แต่ legacy IP path ยังปะปน; output receipt path ปัจจุบันไม่ผ่าน; persistent/orphan cleanup ยังไม่พิสูจน์
- **IOCTL validation:** ตรวจขนาดขั้นต่ำและ null ใน user bridge/kernel บางส่วน แต่ไม่ตรวจ reserved bytes, output Information, provider status และ caller ACL ครบ
- **Driver lifecycle/provenance:** มี DriverEntry/unload และ ring cleanup แต่ persistent filter ownership, duplicate implementation, build path และ hash equality ยังไม่เป็นหลักฐาน production

**คำตัดสิน:** ขอบเขต Rust PEP/ABI/WFP enforcement **ไม่ผ่าน** และควรคงสถานะ `NOT ACCEPTED` จนกว่า critical findings และ evidence gaps ข้างต้นจะถูกแก้และพิสูจน์ด้วย artifact ที่สร้างจาก source-of-truth เดียว

## References

[1]: ../../rust-src/lib.rs "Rust PEP ABI, capability gate และ WFP adapter"
[2]: ../../src/policy/pep_bindings.zig "Zig-to-Rust PEP FFI และ enforcement receipt wrapper"
[3]: ../../src/control/handler_registry.zig "Privileged enforcement block/unblock handlers"
[4]: ../../src/windows/wfp_ioctl.c "User-mode WFP IOCTL bridge"
[5]: ../../drivers/wfp_callout/aegis_wfp.h "Kernel/user IOCTL and packed flow contract"
[6]: ../../drivers/wfp_callout/aegis_wfp.c "Kernel driver lifecycle, IOCTL dispatch และ flow mutation"
[7]: ../../drivers/wfp_callout/aegis_wfp_callout.c "WFP callout registration และ filter cleanup"
[8]: ../../drivers/wfp_callout/aegis_wfp_comm.c "Legacy duplicate communication implementation"
[9]: ../../tests/wfp/test_t11_wfp_enforcement.py "Static WFP enforcement contract tests"
[10]: ../../tests/wfp/test_t11_windows_host.py "Windows host-gated PEP/WFP test"
[11]: ../../scripts/build_drivers.bat "WDK driver build graph"
[12]: ../../scripts/wfp_service.ps1 "Driver service install/status lifecycle"
[13]: ../../scripts/wfp_sign.ps1 "Development test-signing path"
[14]: ../../CMakeLists.txt "Native user bridge build graph"
[15]: ../../src/policy/wfp_production.zig "Fail-closed Zig production boundary"
[16]: ../../docs/WFP_IOCTL_STATUS.md "Stale tracking-only WFP status document"

---

**รายงานนี้เป็น static source audit เท่านั้น. ไม่มีการเปลี่ยน source, ติดตั้ง driver, เปิด block host หรือแก้ระบบภายนอก**

**Files not present as tracked source:** `contracts/**/*` ไม่มีไฟล์ tracked; ไม่พบ shared contract ภายใต้ directory นี้ จึงใช้ `shared/abi/*`, `shared/protocol/*` และ source header เป็นเอกสารประกอบแทน

**Files reviewed but not tracked:** `src/policy/enforcement_receipt.zig`, `scripts/build_wfp_user_bridge.ps1`, `scripts/run_wfp_phase10_preflight.ps1`, `scripts/run_vmware_lab_preflight.ps1`, `scripts/run_host_production_preflight.ps1`. ไฟล์เหล่านี้ไม่ควรใช้เป็น provenance evidence จนกว่าจะถูก track และผูกกับ build manifest

---

**สถานะสุดท้าย: NOT ACCEPTED — ไม่ใช่ production-ready**

*หมายเหตุ: รายงานนี้ไม่ประกาศการ block สำเร็จจาก log, health, in-memory bookkeeping หรือ WFP API return code ใด ๆ*

---

[17]: ../../src/policy/enforcement_receipt.zig "Working-tree-only enforcement receipt schema"
[18]: ../../scripts/build_wfp_user_bridge.ps1 "Working-tree-only user bridge build helper"
[19]: ../../scripts/run_wfp_phase10_preflight.ps1 "Working-tree-only WFP preflight"
[20]: ../../scripts/run_vmware_lab_preflight.ps1 "Working-tree-only isolated lab preflight"
[21]: ../../scripts/run_host_production_preflight.ps1 "Working-tree-only host production preflight"

---

**End of report.**

---

[22]: ../../src/policy/wfp_ioctl.zig "Zig read-only WFP IOCTL module"
[23]: ../../bridge/aegis_ipc.cpp "C++ bridge legacy mutation containment"
[24]: ../../bridge/aegis_bridge_ctypes.py "Python ctypes bridge and legacy IP API"
[25]: ../../scripts/package_release.ps1 "Release packaging artifact paths"
[26]: ../../shared/abi/pep_abi.md "PEP ABI documentation"
[27]: ../../shared/protocol/control_protocol.md "Control protocol documentation"

---

**Scope boundary:** ไม่รวมการประเมิน detection accuracy, Npcap/Go Nose, UI, SIEM หรือ network traffic capture ยกเว้นจุดที่จำเป็นต่อการยืนยันว่า detection/receipt ไม่ใช่ enforcement evidence

---

[28]: ../../src/tests/policy/pep_bindings.zig "Zig PEP binding test aggregator"
[29]: ../../src/tests/proofs/pep_enforcement_proof.zig "PEP enforcement proof module"
[30]: ../../tests/pep/test_t8_rust_pep.py "Rust PEP static safety tests"

---

**ผู้ตรวจ:** Senior software audit subagent  
**วันที่ตรวจตาม execution context:** 21 กันยายน 2026

---

[31]: ../../rust-src/shield/src/lib.rs "Advisory Shield FFI boundary"
[32]: ../../rust-src/shield/src/pep.rs "Advisory Shield policy screening"

---

**Final disposition: BLOCKED FOR ACCEPTANCE.**

---

[33]: ../../scripts/install_aegis.ps1 "Bundle hash validation and service creation"
[34]: ../../scripts/wdk_build_production.ps1 "WDK/MSVC production driver build helper"
[35]: ../../drivers/wfp_callout/aegis_wfp.inf "WFP driver installation INF"

---

**No host mutation was performed.**

---

[36]: ../../src/windows/aegis_wfp.c "User-mode WFP engine/provider lifecycle helper"
[37]: ../../src/windows/cpp_adapter.zig "Windows C++ adapter FFI declarations"

---

**End.**

---

[38]: ../../bridge/CMakeLists.txt "C++ bridge build targets"
[39]: ../../build.zig "Zig build graph"
[40]: ../../Cargo.toml "Root Rust PEP Cargo manifest"

---

**Acceptance remains NOT ACCEPTED.**

---

[41]: ../../src/policy/policy_ir.zig "Policy action ordinal source"
[42]: ../../src/policy/policy_signing.zig "Signed policy verification path"
[43]: ../../src/policy/trust_store.zig "Trust store and key state"

---

**This report intentionally does not use external web sources; repository source-of-truth is the only evidence base.**

---

[44]: ../../drivers/wfp_callout/aegis_wfp.h "IOCTL numeric and packed struct source"

---

**End.**

---

[45]: ../../tests/release/test_t17_perf_ci_installer.py "Release/build installer tests"
[46]: ../../scripts/verify_release.ps1 "Release verification script"

---

**No production readiness claim is made.**

---

[47]: ../../src/policy/action_dispatcher.zig "Policy action dispatch"
[48]: ../../src/policy/dispatcher.zig "Policy dispatcher"
[49]: ../../src/policy/control_ipc.zig "Policy control IPC"

---

**Static evidence only; live proof remains outstanding.**

---

[50]: ../../drivers/wfp_callout/aegis_wfp.inf "Driver service/installation metadata"

---

**END**

---

[51]: ../../scripts/install_drivers.bat "Legacy driver installation script"
[52]: ../../scripts/build_all.bat "Top-level build script"
[53]: ../../scripts/build_and_check.ps1 "Build and native service checks"
[54]: ../../scripts/release_package.ps1 "Release package and checksum script"

---

**รายงานสิ้นสุด**
