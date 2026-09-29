

## Addendum: Runtime diagnosis and health convergence — 2026-09-27

### ตรวจพบจาก runtime รุ่นเก่า

หลักฐานก่อน rebuild พบว่า process เก่าค้างอยู่และ log เก่ามีอาการ:

```text
loaded 0 rules from configs/Rules.json
WFP IOCTL: device not available
C++ Bridge not found
create pipe server failed: error 231
Segmentation fault during ACL setup
pcap_create failed: error 123
```

`aegis_nids.exe` และ `nose_dashboard.exe` เป็น process ที่เปิดด้วย Administrator token จึงหยุดผ่าน `aegisctl stop --all` จาก non-admin session ไม่ได้ และ binary ถูกล็อกระหว่าง build

### Patches ที่ทำและยืนยันแล้ว

1. `src/daemon.zig`
   - ถ้า `Rules.json` โหลดได้ 0 rules จะคืน `error.RulesUnavailable` และไม่เริ่ม runtime เป็น NIDS ที่ไม่มี detection
   - startup state จะเป็น `DEGRADED` หาก required bridge ไม่ active แทนการประกาศ fully `RUNNING`

2. `src/control/state_machine.zig`
   - แก้ health payload ไม่ให้ `state=RUNNING` ขัดกับ `degraded=true`
   - state จะเป็น `DEGRADED` เมื่อ WFP/required bridge ไม่พร้อม แม้ control/pipeline ยังให้บริการ diagnostics ได้

3. `tools/aegisctl/api/control_api.py`
   - daemon `runtime_state` มี precedence เหนือ compatibility calculator รุ่นเก่า
   - ห้าม promote canonical `DEGRADED` เป็น `READY`

### Build and runtime verification

Build ใหม่จาก Windows ผ่าน:

```text
zig build --summary all
Build Summary: 10/10 steps succeeded
install aegis_nids success
zig build-exe aegis_nids Debug x86_64-windows success
EXIT_CODE=0
```

Python API syntax ผ่าน:

```text
python -m compileall -q tools\\aegisctl
COMPILE_EXIT=0
```

Binary รุ่นใหม่เริ่มได้โดยไม่มี crash และโหลด config ครบ:

```text
loaded 22 rules from configs/Rules.json
loaded 6 policies from configs/policies.json
C++ IPC Bridge initialized (rc=0)
Bridge status: 2/3 active (wfp=false cpp=true udp=true)
STATE: STARTING -> DEGRADED
```

Raw/normalized health หลัง patch:

```text
state=DEGRADED
runtime_state=DEGRADED
degraded=true
rules_loaded=22
wfp=false
cpp_bridge=true
udp_brain=true
forensic integrity=ok
```

Readiness gate:

```text
ready=false
overall_gate=false
failure_reasons=[cpp_windows_telemetry_not_ready, etw_init_failed]
missing=[etw_ready]
```

สาเหตุที่ยัง degraded เป็นสิทธิ์ Windows ของ session ที่ใช้ทดสอบ:

```text
WFP device open error=0x5 (ACCESS_DENIED)
ETW StartTraceW status=5 (ACCESS_DENIED)
```

จึงยังต้องเริ่ม daemon จาก **Administrator PowerShell** เพื่อพิสูจน์ WFP/ETW readiness และเริ่ม Go Nose หลัง core พร้อม

### ขอบเขตที่ยังไม่ผ่าน

- WFP provider/host-effect capability ยัง false ใน non-admin run
- ETW ยังไม่พร้อมจาก access denied
- Nose ยังไม่ได้ส่ง real packet ใน evidence ล่าสุด
- `nose_connected`, `nose_frames_read`, `nose_frames_submitted` ยังเป็น 0 ในรอบนี้
- ยังไม่มี current-head EnforcementReceipt ที่ยืนยัน WFP host effect

### ขั้นตอนถัดไปที่ถูกต้อง

เปิด Administrator PowerShell:

```powershell
Set-Location D:\NIDs_Windows
Get-Process aegis_nids,nose_dashboard -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
zig build --summary all
Start-Process -FilePath .\\zig-out\\bin\\aegis_nids.exe `
  -WorkingDirectory (Get-Location) `
  -WindowStyle Hidden `
  -RedirectStandardOutput .\\admin-evidence\\admin-core.stdout.log `
  -RedirectStandardError .\\admin-evidence\\admin-core.stderr.log
Start-Sleep -Seconds 6
python tools\\aegisctl.py health --json
python tools\\aegisctl.py readiness
```

ต้องได้ก่อนเริ่ม Nose:

```text
runtime_state=RUNNING หรือ readiness พร้อมตาม contract
wfp=true
etw_ready=true
workers.failed=false
```

จากนั้น build/start canonical Nose เพียงหนึ่ง process และพิสูจน์ traffic จริงจาก Kali VMnet1:

```powershell
Set-Location D:\NIDs_Windows\\nose
go test ./... -timeout 30s
go build -o ..\\dist\\nose_dashboard.exe .
Set-Location D:\NIDs_Windows
Start-Process .\\dist\\nose_dashboard.exe -ArgumentList @('--capture','--iface','\\Device\\NPF_{56055AA2-3423-483D-A7F9-278770579E3D}') -WorkingDirectory (Get-Location)
```

ห้ามเริ่ม observe injector ขณะ live Nose ครอง `\\.\\pipe\\aegis_nose`.


## Acceptance update: Administrator runtime ready — 2026-09-27 01:52

ผลล่าสุดจาก Administrator runtime:

```text
state=RUNNING
runtime_state=RUNNING
degraded=false
overall_gate=true
worker_gate=true
wfp=true
pep_ready=true
provider_ready=true
host_effect_capable=true
etw_ready=true
fim_ready=true
registry_ready=true
nose_connected=true
nose_frames_read=0
nose_frames_submitted=0
nose_frames_rejected=0
nose_pipe_errors=0
```

Metrics ล่าสุด:

```text
detections=183
events_processed=102
forensic_records=102
incidents_open=1
rules_loaded=22
packets_captured=0
```

การตีความที่ถูกต้อง:

- Runtime และ privileged dependencies พร้อมแล้ว
- WFP/PEP host-effect capability พร้อมในระดับ readiness
- ETW/FIM/Registry สร้าง events ได้จริง เพราะ events_processed และ detections เพิ่มขึ้น
- Nose เชื่อมต่อแล้ว แต่ยังไม่มี packet จาก network path เข้ามา จึงยังไม่ผ่าน live network ingress gate
- `packets_captured=0` และ `nose_frames_read=0` ไม่ใช่ปัญหา pipe ในตอนนี้ แต่เป็นหลักฐานว่าต้องสร้าง traffic ผ่าน VMware VMnet1 หรือเลือก adapter/route ให้ถูกต้อง
- ยังไม่ควรเริ่ม WFP enforcement proof จนกว่าจะได้ live packet evidence

Next gate:

```text
Kali traffic -> VMnet1 -> Npcap -> Go Nose -> aegis_nose -> Zig -> forensic
```

ต้องได้อย่างน้อย:

```text
nose_frames_read > 0
nose_frames_submitted > 0
packets_captured > 0
nose_frames_rejected = 0
nose_pipe_errors = 0
duplicate_event_ids = 0
non_monotonic_event_ids = 0
```


## Addendum: Canonical authority naming — 2026-09-27 01:58

ผู้ใช้ส่งผล Administrator runtime ล่าสุดซึ่งผ่านทุก readiness gate:

```text
state=RUNNING
runtime_state=RUNNING
degraded=false
overall_gate=true
worker_gate=true
wfp=true
provider_ready=true
host_effect_capable=true
nose_connected=true
nose_frames_read=14
nose_frames_submitted=14
packets_captured=14
nose_frames_rejected=0
nose_pipe_errors=0
duplicate_event_ids=0
non_monotonic_event_ids=0
forensic integrity=ok
records=178
```

ค่าของ `rust_shield`, `rust_pep`, `tier3` และ `go` ใน output เดิมไม่ใช่ error เพราะทุก `error` เป็น `null` และทุก state เป็น `RUNNING/READY` โดยมี PID เดียวกันคือ runtime process เดียว (`9732`).

อย่างไรก็ตามพบ naming ambiguity:

- `rust_pep` คือ canonical Rust Policy Enforcement Point และ sole enforcement authority
- `tier3` คือ authorization/readiness layer ที่พึ่ง Rust PEP ไม่ใช่ enforcement process ที่สอง
- `rust_shield` เป็นชื่อ compatibility projection เดิม ไม่ใช่ process/component ที่สอง
- `go` ใน Zig health เป็น registered Nose subsystem ของ runtime; Go Nose process ที่เชื่อม pipe ต้องดูผ่าน `nose_connected` และ data-plane counters

แก้แล้ว:

```text
tools/aegisctl/api/control_api.py
tools/aegisctl/web_dashboard/app.py
```

Health API ตอนนี้ประกาศ:

```json
{
  "canonical_enforcement_authority": "rust_pep",
  "compatibility_aliases": {"rust_shield": "rust_pep"},
  "rust_pep": {
    "canonical": true,
    "authority": "sole_enforcement_authority"
  },
  "rust_shield": {
    "canonical": false,
    "alias_of": "rust_pep"
  }
}
```

Dashboard เปลี่ยนไปอ่าน `rust_pep` ก่อน `rust_shield` และแสดง label `Rust PEP / WFP`.

Python compile และ health query หลัง patch ผ่านด้วย exit code 0.
