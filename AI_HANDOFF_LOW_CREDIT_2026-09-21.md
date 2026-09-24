# AEGIS Windows NIDS/IPS — Low-Credit AI Handoff Report

**วันที่:** 21 กันยายน 2026  
**โครงการ:** `D:\NIDs_Windows`  
**ผู้รับช่วงต่อ:** AI session ถัดไปและผู้พัฒนา  
**วัตถุประสงค์:** ให้ AI ตัวถัดไปเข้าใจระบบและดำเนินงานต่อโดยไม่สแกนซ้ำทั้ง repository และไม่ใช้ workflow/subagent fan-out ที่มีค่าใช้จ่ายสูง

## 1. คำแนะนำเปิดงานสำหรับ AI ตัวถัดไป

ให้อ่านไฟล์นี้ก่อนเริ่มงาน แล้วอ่านเฉพาะไฟล์ที่ระบุในส่วน “Next Action” ห้ามเริ่มจากการ scan ทั้ง repository และห้ามสร้าง workflow หลาย agent เว้นแต่ผู้ใช้อนุมัติเป็นกรณีพิเศษ

> โปรเจกต์นี้เป็น Windows-native NIDS/IPS ที่ออกแบบให้ Zig เป็น runtime owner, Go Nose เป็น canonical ingress, Rust PEP เป็น privileged enforcement authority และ WFP kernel driver เป็น host-effect provider. สถานะยังเป็น `NOT ACCEPTED`. ห้ามใช้ `netsh`, Windows Firewall API, legacy `block_ip`, IP-only cleanup, in-memory blocked map, process existence หรือ bookkeeping เป็นหลักฐาน host block. ให้ทำงานต่อเฉพาะ P0 contract verification จากไฟล์ที่ระบุ และรายงานทุกครั้งว่า static proof, build proof และ Windows host proof แยกจากกันอย่างไร.

## 2. สถานะระบบโดยสรุป

AEGIS มี pipeline หลักดังนี้:

```text
Npcap / Go Nose
  -> CanonicalEvent
  -> named pipe
  -> Zig reader and event queue
  -> flow, detection, correlation and policy
  -> Rust PEP through FFI
  -> WFP user-mode bridge and IOCTL
  -> WFP kernel filter
  -> filter_id receipt
  -> real traffic postcondition
  -> forensic/audit linkage
  -> exact filter_id cleanup
```

ขอบเขต authority ที่ต้องรักษาไว้มีดังนี้:

| ชั้น | หน้าที่ | สิ่งที่ห้ามทำ |
|---|---|---|
| Go Nose | จับ packet, decode, serialize และส่ง canonical frame | ห้ามเรียก WFP หรือประกาศ block |
| Zig daemon | runtime owner, worker lifecycle, control pipe, queue และ health | ห้ามสร้าง daemon ซ้ำหรือ bypass PEP |
| Python/Cython/TypeScript | detection, enrichment และ policy preparation | ห้ามทำ host mutation |
| Rust PEP | authorization และ privileged action decision | ต้องตรวจ capability, policy และ provider result |
| WFP user bridge | ส่ง IOCTL ไป driver และคืน response | ไม่ใช่ policy authority |
| WFP kernel driver | สร้าง/ลบ host filter | ต้องรับคำสั่งผ่าน PEP path และคืน exact identity |
| Forensics/Mouth | แสดงหลักฐานและ linkage | ห้ามประกาศ block จาก log หรือ decision อย่างเดียว |

สถานะ production ที่ถูกต้องคือ:

```text
Runtime readiness       = เคยผ่านตาม Handoff แต่ต้องตรวจจาก current build
Static contract audit   = มี P0 defects ที่แก้แล้วบางส่วน
Rust/Zig/C build        = UNVERIFIED ใน sandbox นี้
Driver hash/install     = UNVERIFIED
Traffic block proof     = NOT RUN
Receipt forensic proof  = NOT COMPLETE
Production acceptance   = NOT ACCEPTED
```

## 3. ผลการวิเคราะห์ก่อนหน้า

การวิเคราะห์เชิงลึกแบ่งเป็น 7 โมดูล และพบว่า implementation หลายชุดมี contract drift. รายงานเต็มอยู่ที่:

- [รายงานวิเคราะห์รวม](AEGIS_DEEP_CODE_AUDIT_2026-09-21.md)
- [Zig runtime/control](deep_audit/01-runtime-zig.md)
- [Rust PEP/WFP/ABI](deep_audit/02-enforcement.md)
- [Go Nose/ingress](deep_audit/03-ingress.md)
- [Detection/policy/forensics](deep_audit/04-brain-policy.md)
- [Python control/CLI/dashboard](deep_audit/05-control-cli.md)
- [Windows scripts/installer/release](deep_audit/06-windows-scripts.md)
- [Tests/manifests/evidence](deep_audit/07-tests-docs.md)
- [Static inventory](deep_audit/static_inventory.md)

**ไม่ต้องอ่านรายงานย่อยทั้งหมดซ้ำ** เว้นแต่กำลังแก้โมดูลนั้นโดยตรง

## 4. P0 ที่พบและ patch แล้วใน session นี้

### 4.1 Action ordinal ผิดใน enforcement request

ก่อนแก้ `src/policy/pep_bindings.zig` ใช้:

```zig
.requested_action = @intFromEnum(PepDecision.block)
```

แต่ request field นี้ต้องใช้ `policy.Action` ไม่ใช่ response decision. Rust กำหนด:

```rust
const DECISION_BLOCK: u8 = 1;
const ACTION_BLOCK: u8 = 4;
```

แก้เป็น:

```zig
.requested_action = @intFromEnum(policy.Action.block)
```

ไฟล์ที่เกี่ยวข้อง:

- `src/policy/pep_bindings.zig`
- `src/policy/policy_ir.zig`
- `rust-src/lib.rs`

### 4.2 PepResponse ABI assertion ผิด

Rust `#[repr(C)] PepResponse` มี `filter_id: u64` จึงมีขนาด 24 bytes ตาม C alignment ไม่ใช่ 16 bytes. Zig tests ถูกปรับให้ตรวจ:

```text
size = 24
filter_id offset = 16
```

### 4.3 User-mode WFP response validation

`src/windows/wfp_ioctl.c` ถูกปรับให้มี compile-time size assertions:

```text
AEGIS_WFP_FLOW_REQUEST  = 8 bytes
AEGIS_WFP_FLOW_RESPONSE = 12 bytes
```

และรับผลสำเร็จเฉพาะเมื่อ:

```text
out_len == sizeof(response)
filter_id != 0
provider_status == 0
```

### 4.4 Kernel WFP response/layer

`drivers/wfp_callout/aegis_wfp.c` ถูกปรับให้:

```c
filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
Irp->IoStatus.Information = sizeof(*response);
```

จุดนี้ยังต้อง compile และทดสอบบน Windows WDK จริงก่อนถือว่าผ่าน

### 4.5 Regression checks

เพิ่ม static regression tests ใน:

```text
tests/pep/test_t8_rust_pep.py
```

เพิ่มตัวรันแบบไม่พึ่ง pytest ที่:

```text
analysis/deep_audit/run_p0_static_checks.py
```

## 5. ผล validation ที่ทำแล้ว

ผ่านแล้ว:

```text
Python unittest tests.runtime.test_aegisctl + tests.runtime.test_wire = 35 tests OK
Python syntax compilation = PASS
git diff --check = PASS
P0 static contract assertions = PASS (2)
```

คำสั่งที่ใช้ตรวจ static assertions:

```bash
python3 analysis/deep_audit/run_p0_static_checks.py
```

ข้อจำกัดของ sandbox session เดิม:

```text
cargo = absent
rustc = absent
zig   = absent
go    = absent
```

ดังนั้นห้ามรายงานว่า Rust, Zig, Go, C หรือ WDK build ผ่านจากผลรอบนี้. ต้องใช้ Windows development environment หรือ CI ที่มี toolchain จริง

## 6. สิ่งที่ยังไม่แก้และต้องทำต่อ

### P0-A — ตรวจ patch ด้วย compiler จริง

บน Windows development host หรือ disposable lab:

```powershell
Set-Location D:\NIDs_Windows

python -m py_compile tests\pep\test_t8_rust_pep.py tools\aegisctl\api\control_api.py

cargo test --manifest-path .\Cargo.toml

zig build
zig build test

# ใช้ script canonical ของ repository หลังตรวจ source ก่อน
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build_wfp_user_bridge.ps1 -Configuration Release

cmd.exe /c .\scripts\build_drivers.bat wfp
```

ถ้า `scripts\build_wfp_user_bridge.ps1` ไม่มีใน clean checkout ให้หยุดและรายงาน missing artifact ห้ามสร้าง command ใหม่ที่ bypass build graph โดยพลการ

### P0-B — ตรวจ ABI ข้ามภาษา

ตรวจค่าต่อไปนี้ให้ตรงกันทุกจุด:

| Field/contract | ค่าที่ต้องตรง |
|---|---:|
| `policy.Action.block` / `ACTION_BLOCK` | 4 |
| `PepDecision.block` / `DECISION_BLOCK` | 1 |
| `PepResponse` size | 24 bytes |
| `PepResponse.filter_id` offset | 16 |
| `FlowRequest` size | 8 bytes |
| `FlowResponse` size | 12 bytes |
| IPv4 | network-order ตาม contract เดียว |
| port | host-order ตาม header ปัจจุบัน |
| protocol | IANA value, TCP = 6 |
| WFP layer | `FWPM_LAYER_ALE_AUTH_CONNECT_V4` |

หากพบ mismatch ให้แก้ generated/shared contract ก่อน ไม่ควรแก้เฉพาะ test ให้ผ่าน

### P0-C — ตรวจ capability และ receipt linkage

ยังมี known gap ใน `src/control/handler_registry.zig`:

```zig
pep.enforceFlow(..., ctx.caller_pid, 1, ctx.request_id)
```

ค่า capability `1` ถูก hard-code. ต้องเปลี่ยนให้ผูกกับ authenticated caller/token capability หลังจากตรวจ control protocol แล้ว ห้ามแก้เป็นการรับค่า capability จาก JSON โดยตรง

Receipt ปัจจุบันยังมีเพียงข้อมูลลักษณะนี้:

```json
{
  "status": "ENFORCED",
  "filter_id": 123,
  "reason": 0,
  "dst_ip": 0,
  "dst_port": 8080,
  "protocol": 6
}
```

ก่อน production ต้องเพิ่มและตรวจ linkage ของ:

```text
request_id
trace_id
audit_id
event_id
policy_id
runtime_generation
provider_status
host_postcondition
cleanup_result
```

### P0-D — ห้ามเริ่ม controlled block proof จนกว่าจะครบ

ลำดับที่ถูกต้องคือ:

1. clean build จาก source-of-truth เดียว
2. ตรวจ artifact SHA-256
3. sign/install driver ตาม lab policy
4. ตรวจ installed driver hash เท่ากับ build hash
5. หยุด daemon เดิมทั้งหมด
6. start daemon เพียงหนึ่ง process
7. ตรวจ authoritative health จาก control pipe
8. รัน observe-only 10-frame proof
9. ทดสอบ malformed block request ต้อง reject และไม่สร้าง filter
10. ตรวจ baseline HTTP 200 ที่ `192.168.126.20:8080`
11. ส่ง block ผ่าน Control Pipe → Zig → Rust PEP → WFP เท่านั้น
12. ตรวจ receipt มี non-zero `filter_id`
13. ตรวจ traffic จริงถูก block
14. ตรวจ forensic linkage ครบ
15. ส่ง unblock ด้วย `filter_id` จาก receipt เดิม
16. ตรวจ HTTP กลับเป็น 200 และไม่มี orphan filter
17. รัน lifecycle recovery proof

## 7. Known critical issues จาก audit ที่ยังค้าง

1. WFP driver ใช้ `g_FilterId` global เดียว ไม่มี per-receipt registry และไม่มี concurrency ownership
2. WFP device ถูกสร้างด้วย `IoCreateDevice` แต่ยังไม่มีหลักฐาน explicit SDDL/least-privilege caller authorization
3. Provider readiness ตรวจเพียง DLL/device open ไม่ใช่ hash/signature/provider identity attestation
4. Go Nose pipe ไม่มี producer authentication และ live framing ไม่ตรง WEV1 เอกสาร
5. Event sequence reset ต่อ connection และ provenance/session fields สูญหายบางส่วน
6. Policy dispatcher มี fail-open/no-op behavior เมื่อ policy หรือ PEP ไม่พร้อม
7. Signed policy bytes ไม่เป็น canonical stream เดียวกันระหว่าง TypeScript, Zig และ Python
8. Shared counters และ audit IDs มี data race risk ระหว่าง control/pipeline threads
9. Bridge spool thread ไม่ได้ถูกเก็บ handle เพื่อ join อย่างครบถ้วน
10. Dashboard bind `0.0.0.0` โดยไม่มี authentication
11. Backup restore มี path traversal/arbitrary write risk
12. Installer/build/release มีหลาย graph และหลาย version/provenance identity
13. Evidence maps อ้าง HEAD เก่าและ host tests หลายชุด skip ได้

ให้แก้ทีละ issue ตาม P0 → P1 ไม่ควรแก้หลาย subsystem พร้อมกัน

## 8. วิธีทำงานแบบประหยัด credit

AI ตัวถัดไปควรปฏิบัติตามนี้:

- ห้ามใช้ workflow หรือ fan-out agents
- ห้ามอ่าน 827 files ซ้ำ
- อ่านเฉพาะไฟล์ 2–6 ไฟล์ที่เกี่ยวข้องกับ issue ปัจจุบัน
- ใช้ `git diff -- <specific files>` แทนการ scan repository
- ใช้ `git grep` เฉพาะ symbol ที่เกี่ยวข้อง
- รัน test เฉพาะ module ที่แก้
- เขียน test runner ลงไฟล์ก่อน execute ไม่ใช้ script ยาวแบบ inline
- สรุปผลทุก milestone และหยุดเมื่อ validation ถึงขอบเขต
- ไม่ติดตั้ง package หรือ toolchain เพิ่มโดยไม่จำเป็น
- ไม่ทำ browser, web search หรือ external research เพราะเป็นงาน source-local
- ไม่ทำ WFP mutation หรือ driver install จนผู้ใช้ระบุ Windows lab พร้อมใช้งาน

รูปแบบรายงานแต่ละ milestoneควรเป็น:

```text
Files read:
Files changed:
Invariant fixed:
Tests run:
Tests passed:
Tests unavailable:
Host mutation: NOT RUN / RUN with evidence
Remaining risk:
Next exact command:
```

## 9. ข้อควรระวังเรื่อง working tree

ก่อน patch รอบนี้ repository มีการเปลี่ยนแปลงในหลายไฟล์จากงานก่อนหน้าอยู่แล้ว. `git diff --stat` มีขนาดใหญ่กว่าการแก้เฉพาะ P0 รอบนี้ ดังนั้น AI ตัวถัดไปต้อง:

1. ไม่ reset หรือ checkout ทิ้ง working tree
2. ไม่ใช้ `git clean -fd`
3. ไม่ overwrite manifests หรือ reports โดยไม่ตรวจ diff
4. ตรวจ `git diff -- <file>` เฉพาะไฟล์ก่อนแก้
5. แยก “การเปลี่ยนแปลงเดิมที่มีอยู่แล้ว” ออกจาก patch ใหม่
6. ถ้าจะ commit ให้ผู้ใช้ตัดสินใจก่อน และควรทำ commit แยกเฉพาะ P0

## 10. Acceptance criteria ของ P0 รอบนี้

P0 contract รอบนี้จะถือว่าผ่านเมื่อมีหลักฐานครบทุกข้อ:

- Zig request ใช้ `policy.Action.block = 4`
- Rust constants แยก request action กับ response decision
- Zig/Rust `PepResponse` size และ offsets ตรงกัน
- C user bridge และ kernel ใช้ FlowRequest/Response layout เดียวกัน
- C compile-time assertions ผ่าน
- Kernel ตั้ง WFP layer อย่างชัดเจน
- Kernel response `IoStatus.Information` ตรงกับ response size
- User bridge ตรวจ response length, non-zero filter ID และ provider status
- Rust unit tests ผ่าน
- Zig unit tests ผ่าน
- Windows driver/user bridge build ผ่าน
- ไม่มี host block proof จนกว่าจะตรวจ installed hash ตรง build hash

จนกว่าจะครบ ให้รายงาน:

```text
P0 contract = STATIC PATCHED, BUILD UNVERIFIED
Production acceptance = NOT ACCEPTED
```

## References

[1]: ./AEGIS_DEEP_CODE_AUDIT_2026-09-21.md "AEGIS deep code audit"
[2]: ./deep_audit/02-enforcement.md "Rust PEP, WFP and ABI audit"
[3]: ./deep_audit/01-runtime-zig.md "Zig runtime and control audit"
[4]: ../src/policy/pep_bindings.zig "Zig PEP bindings"
[5]: ../rust-src/lib.rs "Rust PEP implementation"
[6]: ../src/windows/wfp_ioctl.c "WFP user-mode IOCTL bridge"
[7]: ../drivers/wfp_callout/aegis_wfp.c "WFP kernel driver implementation"
[8]: ../drivers/wfp_callout/aegis_wfp.h "WFP shared header"
[9]: ../tests/pep/test_t8_rust_pep.py "PEP authority and contract tests"
[10]: ../analysis/deep_audit/run_p0_static_checks.py "P0 static assertion runner"
[11]: ../PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md "Production completion runbook"
[12]: ../AEGISWindowsNIDS_IPS—ProductionHandoffReport.md "Original production handoff"
