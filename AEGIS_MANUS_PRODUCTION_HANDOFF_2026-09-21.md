# AEGIS Windows NIDS/IPS — Production Handoff Report

**วันที่:** 21 กันยายน 2026  
**ผู้จัดทำ:** Manus AI  
**ผู้รับช่วงต่อ:** Manus AI session ถัดไป, ผู้พัฒนา และผู้ตรวจรับระบบ  
**โครงการ:** `D:\NIDs_Windows`  
**สถานะโดยรวม:** **Runtime READY แต่ยังไม่ Production-accepted**

---

## 1. คำสั่งสำหรับ Manus AI ที่รับช่วงต่อ

ให้อ่านเอกสารนี้เป็น handoff หลัก และดำเนินงานต่อโดยยึดกฎต่อไปนี้:

1. ห้ามใช้ `netsh`, Windows Firewall API, legacy `block_ip`, หรือการแก้ไฟล์ bookkeeping เพื่ออ้างว่าเกิด host block
2. การป้องกันต้องผ่านเส้นทางเดียวเท่านั้น: **Control Pipe → Zig handler → Rust PEP → WFP user bridge → Kernel driver**
3. การประกาศว่า block สำเร็จต้องมี `filter_id` จาก WFP และต้องตรวจ host postcondition ด้วย traffic จริง
4. Cleanup ต้องใช้ `filter_id` จาก receipt เดิมเท่านั้น ห้ามลบด้วย IP อย่างเดียว
5. หาก health daemon ใช้งานไม่ได้ ให้ถือว่า runtime เป็น `DEGRADED` และห้ามใช้ process scan แทน authoritative health
6. ต้องมี daemon เพียงหนึ่ง process ก่อนการทดสอบ enforcement
7. ห้ามเริ่ม controlled block proof จนกว่า build artifact กับ installed driver จะมี SHA-256 ตรงกัน
8. การทดสอบต้องใช้ disposable VMware lab เท่านั้น โดยใช้เป้าหมายที่ผู้ใช้ยืนยันไว้แล้ว:
   - Target: `192.168.126.20`
   - Protocol: TCP
   - Destination port: `8080`
   - Expected baseline: HTTP `200`
   - Block duration: ประมาณ 30 วินาที หรือจนกว่าจะ cleanup สำเร็จ

---

## 2. Executive conclusion

AEGIS มีสถาปัตยกรรมหลายภาษาและมีการแยก authority ที่ถูกต้องในระดับสำคัญแล้ว โดย Zig เป็น runtime owner, Go Nose เป็น canonical ingress, Rust PEP เป็น enforcement authority และ WFP เป็น host-effect provider

สิ่งที่ผ่านแล้วมีดังนี้:

- Go Nose observe-only ingress ผ่านครบ `10/10` frames
- Zig daemon health ผ่านครบทุก worker
- Rust PEP พร้อมใช้งานและ provider attestation ผ่าน
- WFP user-mode bridge build และ install ผ่าน
- WFP kernel driver รุ่นใหม่ compile/link สำเร็จ
- Driver รุ่นใหม่ถูก sign ด้วย test certificate สำเร็จ
- Runtime health แสดง `RUNNING`, `degraded=false`, `pep_ready=true`, `provider_ready=true`, `host_effect_capable=true`, และ `wfp=READY`
- WFP IOCTL log ระบุว่า device เปิดได้จริง
- มีการแก้ reconnect/readExact ของ named pipe ให้ Nose ผ่าน 10 frames

อย่างไรก็ตาม ระบบยังไม่ควรถูกส่งมอบเป็น Production เพราะยังมี gap สำคัญ:

1. มีช่วงที่ installed driver hash ไม่ตรงกับ build artifact รุ่นใหม่
2. มี daemon ซ้ำสอง process ซึ่งทำให้ control-plane ownership ไม่ deterministic
3. Control API เดิมยัง fail-closed เพราะไม่มี receipt command route
4. มีการเพิ่ม `enforcement.block` และ `enforcement.unblock` route ใน source แล้ว แต่ยัง **ไม่ได้ build และทดสอบหลัง patch ล่าสุด**
5. Forensic linkage ระหว่าง receipt, request, trace, audit และ filter identity ยังต้องพิสูจน์ด้วย live proof
6. Controlled WFP block/unblock proof ยังไม่เสร็จ
7. คำสั่ง `cargo test --manifest-path rust-src\Cargo.toml` ล่าสุดล้มเหลวเพราะ `rust-src\Cargo.toml` ไม่มีอยู่จริง ต้องใช้ root Cargo manifest ตามที่ตรวจพบใน session ก่อนหน้า หรือค้นหา manifest ที่ถูกต้องก่อนรันใหม่

สถานะที่ถูกต้อง ณ handoff คือ:

```text
Runtime readiness       = PASS
WFP provider readiness  = PASS ใน health ของ daemon
Kernel driver build     = PASS
Kernel driver install   = ต้องตรวจ hash ให้ตรงอีกครั้ง
Receipt control route   = PATCHED, UNVERIFIED
Host block proof        = NOT RUN
Forensic linkage proof  = NOT COMPLETE
Production acceptance   = NOT YET
```

---

## 3. สถาปัตยกรรมและ authority boundaries

### 3.1 Runtime owner — Zig

Zig daemon เป็นเจ้าของ runtime เพียงหนึ่งเดียว มีหน้าที่:

- startup และ shutdown
- worker lifecycle
- readiness barrier
- named control pipe
- event queue และ pipeline
- health aggregation ที่มาจาก daemon จริง
- forensic coordination
- เรียก Rust PEP ผ่าน FFI boundary

CLI, PowerShell, Python API และ UI ห้ามสร้าง worker set ใหม่เอง การมี daemon สอง process เป็น violation ของ runtime ownership แม้ health ของ process หนึ่งจะยังตอบ `RUNNING` ก็ตาม

### 3.2 Go Nose — canonical ingress

Go Nose ทำหน้าที่:

- Npcap capture
- packet decode
- CanonicalEvent serialization
- length-prefixed named pipe delivery
- reconnect/retry ที่ bounded
- frame counters และ event identity

Nose ห้าม:

- เรียก WFP
- ตัดสินใจ block
- อ้างว่า packet ถูก block
- เปลี่ยน policy authority

Wire shape ที่ได้รับการพิสูจน์:

```text
4-byte little-endian length prefix + 109-byte canonical payload = 113-byte frame
```

### 3.3 Python/Cython brain

Python และ Cython ทำ detection, regex scan, enrichment, context และ policy input preparation เท่านั้น การตรวจพบภัยคุกคามไม่ใช่ host enforcement

ต้องแยกสถานะต่อไปนี้:

```text
DetectionResult
  != PolicyDecision
  != PEP authorization
  != WFP host effect
  != verified postcondition
```

### 3.4 Rust PEP

Rust PEP เป็น authority เดียวที่อนุญาต privileged action โดยตรวจ:

- caller capability mask
- action type
- severity
- policy id
- two-person rule หากเปิดใช้
- provider availability
- WFP adapter result
- filter identity

Rust PEP รุ่นปัจจุบันมี `FlowRequest` ที่รองรับ:

```text
remote IPv4 + destination port + protocol
```

และคืน `filter_id` จาก provider เมื่อ `block_flow` สำเร็จ

### 3.5 WFP provider

WFP kernel driver ทำ host mutation โดยสร้าง filter exact flow และลบด้วย exact filter identity

WFP ห้ามเป็น policy authority เอง โดยต้องรับคำสั่งจาก Rust PEP ผ่าน user-mode bridge และ IOCTL contract ที่ตรวจสอบร่วมกัน

### 3.6 Forensics และ Mouth

Mouth และ forensic output ห้ามประกาศ `BLOCKED_CONFIRMED` จาก log หรือ decision เท่านั้น ต้องตรวจ receipt ที่มีอย่างน้อย:

```text
status = ENFORCED
filter_id != 0
request_id != 0
trace_id != 0
incident/audit linkage valid
host postcondition confirmed
cleanup result recorded
```

---

## 4. สิ่งที่ดำเนินการแล้วตามลำดับเวลา

### Phase A — Safety containment

แก้ architectural paths ที่อาจทำให้ Zig หรือ legacy bridge mutate WFP โดยตรงให้ fail-closed หรือ quarantine

ผลลัพธ์:

- Rust PEP ถูกกำหนดเป็น enforcement authority
- legacy boolean `block_ip` ไม่สามารถอ้าง host effect
- simulation ไม่สามารถรายงานเป็น executed
- provider unavailable ไม่ถูกแปลงเป็น allow

### Phase B — Trust boundary

เพิ่ม capability gate ใน Rust PEP และใช้ privileged role ใน control plane

Unsigned/ad-hoc blocking request ต้องไม่ถูกประกาศเป็น authorized production action จนกว่าจะมี policy authority และ signed policy contract ที่ตรวจสอบได้

### Phase C — Control plane hardening

Named pipe authorization ใช้ explicit SDDL และ client-token impersonation แทนการเชื่อ daemon token ของตัวเอง

Health API ถูกปรับให้:

- daemon response เป็น operational truth
- process scan เป็น diagnostic เท่านั้น
- daemon unavailable ต้องคืน `runtime_available=false` และ `DEGRADED`

### Phase D — Lifecycle truth

แก้ shutdown sequence ให้รายงาน `STOPPED` หลัง worker ทั้งหมด join แล้วเท่านั้น และเพิ่ม recovery proof สำหรับ process generation ใหม่

### Phase E — Manifest/provenance

Regenerate:

- `runtime_manifest.json`
- `build_manifest.json`
- `inventory.json`
- `reference_map.json`

Manifest ล่าสุดระบุประมาณ 61 modules และ 23 authority invariants ตาม handoff เดิม

### Phase F — Nose ingress

แก้:

- `nose/pipe_writer.go`
- `nose/inject.go`
- `src/capture/nose_pipe_reader.zig`

รายละเอียด:

- `FrameWriter.Send` คืน success boolean
- observe-only injector มี bounded retry
- pipe reader รองรับ reconnect และ `ERROR_NO_DATA`
- `readExact` ไม่หลุดเมื่อ pipe อยู่ใน NOWAIT cadence

ผลพิสูจน์ล่าสุด:

```text
frames_read       = 10
frames_submitted  = 10
frames_dropped    = 0
frames_rejected   = 0
pipe_errors       = 0
duplicate_ids     = 0
non_monotonic     = 0
```

### Phase G — WFP port-specific contract

แก้ source ต่อไปนี้:

- `drivers/wfp_callout/aegis_wfp.h`
- `drivers/wfp_callout/aegis_wfp.c`
- `drivers/wfp_callout/aegis_wfp_comm.c`
- `src/windows/wfp_ioctl.c`
- `rust-src/lib.rs`
- `src/policy/pep_bindings.zig`

Contract ใหม่มี:

```text
remote_ipv4: u32
destination_port: u16
protocol: u8
filter_id: u64
```

Unblock ต้องใช้ `filter_id` ที่คืนจาก block receipt

### Phase H — WDK build correction

พบว่า WDK ติดตั้งจริงใน versioned layout:

```text
C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0\km
C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64
```

เดิม script ตรวจผิดที่ `Include\km` จึงแก้ `scripts/build_drivers.bat` ให้:

- detect WDK version ล่าสุด
- ใช้ short path `C:\Progra~2` เพื่อหลีกเลี่ยง cmd parser error จาก `(x86)`
- หา MSVC compiler จาก Visual Studio Enterprise
- ใช้ SDK `um\x64` library path สำหรับ `uuid.lib`
- ใช้ MSVC runtime library path สำหรับ `LIBCMT.lib`
- ใช้ `/NODEFAULTLIB`
- ใช้ `/GS-`
- ใช้ `/ENTRY:DriverEntry` แทน `GsDriverEntry`

ใน `aegis_wfp.c` เพิ่ม:

```c
#define INITGUID
```

เพื่อให้ custom `AEGIS_CALLOUT_KEY` ถูก define จริงใน translation unit

ผล build:

```text
Compiler: MSVC 19.44.35228
Linker:   MSVC 14.44.35228
Result:   aegis_wfp.sys built successfully
Size:     12,800 bytes
```

### Phase I — Driver signing/install

Driver รุ่นใหม่ถูก sign ด้วย test certificate:

```text
CN=AEGIS NIDS Test Signing
```

`wfp_sign.ps1` รายงาน `SIGN OK` และหลังติดตั้ง certificate ลง LocalMachine Root/TrustedPublisher แล้ว signature เป็น `Valid`

เคยพบ service deletion race:

```text
DeleteService FAILED 1072
The specified service has been marked for deletion
```

วิธีแก้คือรอให้ deletion เสร็จ หรือ reboot หาก service handle ค้าง

### Phase J — Runtime readiness

ผล health ที่ผ่านแล้ว:

```json
{
  "state": "RUNNING",
  "runtime_state": "RUNNING",
  "degraded": false,
  "pep_ready": true,
  "policy_authority": true,
  "provider_ready": true,
  "host_effect_capable": true,
  "wfp": "READY",
  "workers_ready": true
}
```

Log ยืนยัน:

```text
[WFP IOCTL] Device opened successfully
Bridge status: 3/3 active (wfp=true cpp=true udp=true)
control pipe ready at \\.\pipe\aegis_control
System: STARTING -> RUNNING
```

---

## 5. ปัญหาปัจจุบันที่ต้องแก้ต่อ

### 5.1 Driver hash mismatch

ผลตรวจใน host session ล่าสุดแสดง:

```text
BuildHash     = 52DFBDD4E19C43682231E7D799961780BB5B3D96593E125942F717D034ED0200
InstalledHash = 49F7B3E3568...
Match         = False
```

ต้องหยุด service, copy `build\drivers\wfp\aegis_wfp.sys` ไปยัง `C:\Windows\System32\drivers\aegis_wfp.sys`, แล้วตรวจ full hash จน `Match=True`

Service ต้องชี้ไปยัง:

```text
C:\Windows\System32\drivers\aegis_wfp.sys
```

### 5.2 Duplicate daemon

มีช่วงที่พบ:

```text
PID 7432
PID 20352
```

และต่อมาพบ:

```text
PID 10888  <- health PID
PID 23448  <- duplicate old process
```

การหยุด PID เก่าจาก session ของ Manus ได้ `Access is denied` จึงต้องใช้ Administrator PowerShell บน host:

```powershell
taskkill.exe /PID 23448 /F /T
```

จากนั้นตรวจ:

```powershell
Get-Process aegis_nids | Select-Object Id,StartTime
```

ต้องมีเพียงหนึ่ง process

หากไม่แน่ใจว่า PID ใดเป็น authority ให้ query health ก่อน แล้วรักษา PID ที่ health ตอบกลับ และหยุด PID อื่นเท่านั้น

### 5.3 Control API ยังไม่มี route ก่อน patch ล่าสุด

เดิม `request_enforcement_via_pep` ใน `tools/aegisctl/api/control_api.py` เป็น fail-closed stub:

```text
FAILED: enforcement receipt unavailable; prevention gate is closed
```

นี่เป็น behavior ที่ปลอดภัย แต่ทำให้ Gate 4 เรียก enforcement จริงไม่ได้

### 5.4 Receipt route ที่เพิ่งเพิ่มยังไม่ verified

เพิ่ม source route แล้ว:

- `enforcement.block = 803`
- `enforcement.unblock = 804`
- privileged control contract
- Zig handler ที่เรียก `PepEnforcer.enforceFlow`
- Rust export `aegis_pep_unblock_filter`
- Python API route ผ่าน `enforcement.block`

แต่ยังไม่ได้ build/test หลัง patch ล่าสุด เพราะ command validation ล่าสุดใช้ manifest path ผิด:

```text
cargo test --manifest-path rust-src\Cargo.toml
error: manifest path rust-src\Cargo.toml does not exist
```

ต้องค้นหา root `Cargo.toml` ก่อน:

```powershell
Get-ChildItem D:\NIDs_Windows -Filter Cargo.toml -Recurse | Select-Object FullName
```

จากนั้นรัน cargo test ด้วย manifest ที่มีอยู่จริง หรือใช้คำสั่ง root ที่เคยผ่านใน session ก่อนหน้า

### 5.5 Forensic linkage ยังไม่เสร็จ

Handler ใหม่คืน receipt JSON ที่มี:

```json
{
  "status": "ENFORCED",
  "filter_id": 123,
  "reason": 0,
  "dst_ip": 3232251412,
  "dst_port": 8080,
  "protocol": 6
}
```

แต่ยังต้องตรวจว่า receipt ถูก link เข้า forensic ring พร้อม:

- request_id
- trace_id
- audit_id
- policy_id
- event_id
- runtime generation
- cleanup result

ห้ามประกาศ final production acceptance ก่อน linkage proof เสร็จ

---

## 6. Source files สำคัญและหน้าที่

| ไฟล์ | หน้าที่ | ต้องตรวจต่อ |
|---|---|---|
| `src/daemon.zig` | runtime owner/startup/workers | duplicate owner, lifecycle |
| `src/control/protocol.zig` | command enum/authorization contract | new enforcement commands |
| `src/control/handler_registry.zig` | control handlers | receipt/audit/postcondition |
| `src/policy/pep_bindings.zig` | Zig↔Rust ABI | receipt layout, filter cleanup |
| `rust-src/lib.rs` | Rust PEP and WFP adapter | export, capability, receipt |
| `drivers/wfp_callout/aegis_wfp.h` | shared kernel IOCTL contract | packing/ABI |
| `drivers/wfp_callout/aegis_wfp.c` | kernel driver entry/filter | DriverEntry, filter conditions |
| `drivers/wfp_callout/aegis_wfp_comm.c` | IOCTL dispatch | exact filter ID cleanup |
| `src/windows/wfp_ioctl.c` | user-mode bridge | exported block/unblock API |
| `nose/pipe_writer.go` | canonical frame writer | bounded retry semantics |
| `nose/inject.go` | observe proof injector | 10/10 proof |
| `src/capture/nose_pipe_reader.zig` | Zig pipe consumer | reconnect/readExact |
| `tools/aegisctl/api/control_api.py` | Python control/business API | receipt route and error handling |
| `scripts/build_drivers.bat` | WDK/MSVC build | versioned SDK and linker paths |
| `scripts/wfp_sign.ps1` | test signing | lab-only signature |
| `scripts/wfp_service.ps1` | service lifecycle | clean install/rollback |
| `scripts/run_controlled_proof.ps1` | observe-only proof | not yet block proof |
| `PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md` | final gate sequence | Gate 4 and closure |

---

## 7. วิธีวิเคราะห์ระบบต่อให้ครบ Production

Manus AI ที่รับช่วงควรใช้ลำดับนี้ ไม่ควรแก้แบบสุ่ม:

### Step 1 — Freeze source of truth

ยืนยัน root:

```powershell
Set-Location D:\NIDs_Windows
Get-Process aegis_nids -ErrorAction SilentlyContinue
Get-Item .\zig-out\bin\aegis_nids.exe
```

อย่าใช้ Visual Studio project ที่อยู่ใน `C:\Users\User\source\repos\aegis_wfp` เป็น source โดยอัตโนมัติ เพราะ source files ที่ค้นจาก project นั้นไม่ตรงกับ runtime source-of-truth ใน `D:\NIDs_Windows`

### Step 2 — Run static contract audit

ตรวจ ABI fields, packed structs, enum ordinals, pointer width, calling convention, and filter identity ผ่านทุกภาษา:

```powershell
Get-ChildItem .\drivers,.\src,.\rust-src,.\nose -Recurse -File |
  Select-String -Pattern 'filter_id|remote_ipv4|dst_port|protocol|PepResponse|PepRequest'
```

ตรวจว่าไม่มี direct legacy mutation ที่ active:

```powershell
Get-ChildItem .\src,.\tools,.\brain,.\nose -Recurse -File |
  Select-String -Pattern 'block_ip|unblock_ip|netsh|FwpmFilterAdd|FwpmFilterDeleteById'
```

ทุก match ต้องถูกจัดประเภทว่า active authority, compatibility, test, หรือ quarantine

### Step 3 — Build all artifacts

ต้อง build ตามลำดับ:

```powershell
python -m py_compile tools\aegisctl\api\control_api.py

zig build

Get-ChildItem D:\NIDs_Windows -Filter Cargo.toml -Recurse
cargo test --manifest-path <manifest ที่มีอยู่จริง>

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build_wfp_user_bridge.ps1 `
  -Configuration Release

cmd.exe /c .\scripts\build_drivers.bat wfp
```

ตรวจ artifact:

```powershell
Get-Item .\zig-out\bin\aegis_nids.exe
Get-Item .\zig-out\bin\aegis_pep.dll
Get-Item .\build\drivers\wfp\aegis_wfp.sys
Get-Item .\zig-out\bin\aegis_wfp_user.dll
```

### Step 4 — Sign/install driver cleanly

ใน Administrator Developer PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\wfp_sign.ps1 `
  -SysPath .\build\drivers\wfp\aegis_wfp.sys
```

หยุด service, รอ stop, copy artifact ใหม่, ตรวจ hash, แล้วสร้าง service ใหม่

เกณฑ์:

```text
Signature = Valid
BuildHash = InstalledHash
Service   = RUNNING
```

### Step 5 — Start exactly one daemon

```powershell
Get-Process aegis_nids -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process .\zig-out\bin\aegis_nids.exe `
  -WorkingDirectory D:\NIDs_Windows `
  -RedirectStandardOutput .\admin-evidence\daemon-final.stdout.log `
  -RedirectStandardError .\admin-evidence\daemon-final.stderr.log
```

รอ 3–5 วินาที ตรวจ health และตรวจมี process เดียว

### Step 6 — Verify ingress

รัน observe proof:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_observe_only_proof.ps1 `
  -Count 10
```

ต้องได้:

```text
frames_read = 10
frames_submitted = 10
frames_dropped = 0
frames_rejected = 0
pipe_errors = 0
```

### Step 7 — Verify control route without host mutation

หลัง build ใหม่ ให้เรียก route ที่ malformed เพื่อทดสอบ fail-closed ก่อน:

```powershell
python tools\aegisctl.py health --json
```

ควรมี command wrapper สำหรับส่ง JSON control request หาก CLI ยังไม่มี ให้ใช้ Python API หรือเพิ่ม CLI thin client ห้ามทำ direct WFP call จาก CLI

ทดสอบ invalid payload:

```json
{
  "command": "enforcement.block",
  "payload": {
    "dst_ip": 3232251412,
    "dst_port": 0,
    "protocol": 6,
    "policy_id": 1
  }
}
```

ต้อง reject โดยไม่สร้าง filter

### Step 8 — Baseline target traffic

บน target VM `192.168.126.20` ต้องมี listener จริง:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen
```

ถ้าไม่มี listener ให้เริ่ม disposable server เช่น:

```powershell
python -m http.server 8080 --bind 0.0.0.0
```

ตรวจจาก attacker `192.168.126.10`:

```bash
curl --connect-timeout 3 http://192.168.126.20:8080/
```

ต้องได้ HTTP `200` ก่อน block

### Step 9 — Controlled block proof

ส่ง request ผ่าน `enforcement.block` เท่านั้น:

```json
{
  "command": "enforcement.block",
  "payload": {
    "dst_ip": 3232251412,
    "dst_port": 8080,
    "protocol": 6,
    "policy_id": 1,
    "severity": 9,
    "reason": "isolated reversible WFP proof"
  }
}
```

`3232251412` คือค่าจำนวนเต็มของ `192.168.126.20` แบบ network-order ที่ต้องตรวจให้ตรงกับ driver contract ก่อนใช้จริง หาก adapter ใช้ host-order ต้องแปลงในจุดเดียวและเพิ่ม test vector

ผลที่ต้องได้:

```json
{
  "status": "ENFORCED",
  "filter_id": 12345
}
```

จากนั้นตรวจจาก attacker:

```bash
curl --connect-timeout 3 http://192.168.126.20:8080/
```

ต้องล้มเหลวหรือ timeout ตาม behavior ของ filter

ตรวจ WFP filter ด้วย host tooling ที่อ่านได้ แต่ห้ามใช้ tooling นั้นเป็น authority แทน receipt

### Step 10 — Receipt and forensic verification

ตรวจว่า:

- receipt status เป็น `ENFORCED`
- filter_id ไม่เป็นศูนย์
- WFP response provider status สำเร็จ
- event/request/trace/audit IDs ไม่เป็นศูนย์
- forensic ring เพิ่ม record ที่ link กับ receipt
- `forensics verify` ยังเป็น `verified=true`

หาก receipt ไม่มี forensic linkage ต้องถือว่า Gate 4 ไม่ผ่าน แม้ TCP ถูก block จริง

### Step 11 — Exact cleanup

ส่ง:

```json
{
  "command": "enforcement.unblock",
  "payload": {
    "filter_id": 12345
  }
}
```

ห้ามส่ง IP-only cleanup

ตรวจหลัง cleanup:

```bash
curl --connect-timeout 3 http://192.168.126.20:8080/
```

ต้องกลับมา HTTP `200`

ตรวจว่า filter เดิมหาย และไม่มี orphan filter จาก AEGIS

### Step 12 — Lifecycle recovery

รัน lifecycle proof หลัง cleanup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_lifecycle_recovery_proof.ps1
```

ต้องตรวจ:

- old PID หยุดจริง
- control pipe ถูก release
- new PID generation ต่างจากเดิม
- workers พร้อม
- health authoritative
- forensic ring ของ generation ใหม่ verify ได้
- ไม่มี stale filter หรือ stale service handle

### Step 13 — Final acceptance

Production acceptance ต้องมีหลักฐานครบ:

| Gate | เกณฑ์ |
|---|---|
| Build | Zig/Rust/Go/Python/C/C++ build ผ่าน |
| Static security | ไม่มี direct enforcement bypass active |
| Ingress | 10/10 canonical frames |
| Health | RUNNING, degraded=false, workers ready |
| Driver | signed, installed hash ตรง build hash |
| Provider | device open และ provider attestation ผ่าน |
| Block | TCP/8080 baseline 200 แล้วถูก block จริง |
| Receipt | filter_id และ authoritative fields ครบ |
| Forensics | receipt linked และ hash chain verified |
| Cleanup | exact filter_id ลบได้ |
| Recovery | restart/recovery ผ่าน ไม่มี stale ownership |
| Packaging | installer/manifest/hash/provenance ครบ |

หาก gate ใดไม่ผ่าน ให้รายงาน `NOT ACCEPTED` พร้อม evidence และห้ามเปลี่ยนเป็น `PRODUCTION_ATTESTED`

---

## 8. สิ่งที่ไม่ควรทำ

ห้ามใช้วิธีต่อไปนี้เพื่อทำให้ demo ผ่าน:

- เปลี่ยน health JSON ให้รายงาน READY โดยไม่ผ่าน daemon
- เรียก `netsh advfirewall` โดยตรง
- แก้ `configs/policies.json` เพื่อจำลอง receipt
- ใช้ in-memory blocked map เป็น host-effect proof
- ใช้ process existence แทน control-pipe health
- start daemon ซ้ำหลายตัว
- ใช้ driver binary เก่าที่ hash ไม่ตรง source build
- ใช้ IP-only unblock หลังมี port-specific filter
- ประกาศ `BLOCKED_CONFIRMED` จาก WFP API return code โดยไม่มี traffic postcondition
- ข้าม signature/test-signing evidence
- ใช้ `zig build run` หลายครั้งพร้อมกันจนเกิด duplicate owners

---

## 9. Known test/build issue

คำสั่งล่าสุดนี้ไม่ถูกต้อง:

```powershell
cargo test --manifest-path rust-src\Cargo.toml
```

ผลคือ:

```text
manifest path rust-src\Cargo.toml does not exist
```

นี่ไม่ได้แปลว่า Rust source test fail แต่แปลว่าเลือก manifest path ผิด ให้ค้นหา manifest จริงก่อน:

```powershell
Get-ChildItem D:\NIDs_Windows -Filter Cargo.toml -Recurse | Select-Object FullName
```

จากนั้นใช้ manifest ที่มีจริง และเก็บ output ลง evidence file

ต้องรันใหม่หลัง patch ล่าสุดของ:

- `rust-src/lib.rs`
- `src/policy/pep_bindings.zig`
- `src/control/protocol.zig`
- `src/control/handler_registry.zig`
- `tools/aegisctl/api/control_api.py`

---

## 10. Recommended next session opening message

ให้ส่งข้อความนี้เป็น opening prompt ให้ Manus AI อีกตัว:

> โปรดอ่านไฟล์ `AEGIS_MANUS_PRODUCTION_HANDOFF_2026-09-21.md` จาก `D:\NIDs_Windows` ก่อนดำเนินการใด ๆ งานนี้เป็น Windows-native NIDS/IPS ที่มี safety baseline แล้ว ห้าม bypass Rust PEP, ห้ามใช้ legacy WFP mutation, ห้ามรัน block proof ก่อนตรวจ driver hash, daemon singleton, receipt route และ forensic linkage ให้ครบ โปรดเริ่มจากตรวจ git diff ของ patch ล่าสุด, ค้นหา root Cargo.toml ที่ถูกต้อง, build/test ทุกภาษา, ตรวจ `enforcement.block/unblock` route, แล้วจึงทำ isolated TCP/8080 proof ตามลำดับใน handoff โดยเก็บหลักฐานทุก gate

---

## References

[1]: ./PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md "AEGIS production completion runbook"
[2]: ./PHASE_10_VMWARE_ISOLATED_LAB_PLAN_2026-09-19.md "VMware isolated lab plan"
[3]: ./scripts/run_observe_only_proof.ps1 "Canonical observe-only proof"
[4]: ./scripts/run_lifecycle_recovery_proof.ps1 "Lifecycle recovery proof"
[5]: ./scripts/run_controlled_proof.ps1 "Controlled proof helper"
[6]: ./src/control/protocol.zig "Control protocol and authorization contracts"
[7]: ./src/control/handler_registry.zig "Control handler registry"
[8]: ./src/policy/pep_bindings.zig "Zig to Rust PEP bindings"
[9]: ./rust-src/lib.rs "Rust PEP and WFP adapter"
[10]: ./drivers/wfp_callout/aegis_wfp.h "Kernel WFP IOCTL contract"
[11]: ./drivers/wfp_callout/aegis_wfp.c "WFP kernel driver entry and filter implementation"
[12]: ./src/windows/wfp_ioctl.c "User-mode WFP bridge"
[13]: ./nose/pipe_writer.go "Go Nose frame writer"
[14]: ./nose/inject.go "Go Nose observe injector"
[15]: ./src/capture/nose_pipe_reader.zig "Zig Nose named-pipe reader"
[16]: ./tools/aegisctl/api/control_api.py "Python control-plane API"
[17]: ./scripts/build_drivers.bat "WDK and MSVC driver build script"
[18]: ./scripts/wfp_sign.ps1 "Development driver signing script"
[19]: ./scripts/wfp_service.ps1 "Driver service lifecycle script"
[20]: ./runtime_manifest.json "Runtime module and authority manifest"
[21]: ./build_manifest.json "Build provenance manifest"
