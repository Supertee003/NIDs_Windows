# AEGIS NIDS Operator Usage Manual

## ภาพรวม

เอกสารนี้เป็นคู่มือมาตรฐานสำหรับผู้ดูแล AEGIS NIDS บน Windows ตั้งแต่การเตรียมเครื่อง การติดตั้ง release bundle การเริ่มระบบ การตรวจสุขภาพ การใช้งาน CLI/TUI/Dashboard/Threat Graph การจัดการ Rules การตรวจ forensic และการวิเคราะห์ปัญหา

AEGIS มีจุดควบคุมหลักเพียงจุดเดียวคือ **Control Center** ผู้ใช้งานควรเรียกผ่าน unified launcher แทนการเรียก Python script ภายในโดยตรง

```text
Operator
  ↓
scripts\aegis.ps1 หรือ scripts\aegis.bat
  ↓
tools\aegisctl.py
  ↓
Control Center pipe
  ↓
AEGIS runtime
```

> `RUNNING` ของ process ไม่ได้แปลว่า detection หรือ enforcement พร้อมเสมอ ต้องตรวจ `health`, worker readiness, data-plane counters และ forensic integrity ร่วมกัน

## 1. ข้อกำหนดของเครื่อง

เครื่อง Windows ต้องมีสิทธิ์ Administrator สำหรับการติดตั้ง driver และการเปลี่ยนแปลง service ส่วนการตรวจสอบแบบ read-only ใช้สิทธิ์ผู้ใช้ทั่วไปได้เมื่อ named pipe ACL อนุญาต

ต้องมีองค์ประกอบต่อไปนี้ก่อนเริ่มใช้งาน:

- AEGIS release bundle ที่มี `manifest.json`
- `aegis_nids.exe` และ native helper ที่มี hash ตรงกับ manifest
- WFP driver `aegis_wfp.sys` หากต้องการ enforcement
- Python ที่เรียก `tools\aegisctl.py` ได้
- Rust dashboard binary หรือ Rust/Cargo สำหรับ build dashboard
- ไฟล์ `configs\Rules.json`
- สิทธิ์อ่านและเขียน logs, reports และ runtime directories

หากต้องการยืนยัน Python:

```powershell
python --version
python tools\aegisctl.py version
```

## 2. รูปแบบคำสั่งหลัก

เปิด PowerShell แล้วเข้าสู่ project root:

```powershell
cd D:\NIDs_Windows
```

แสดงคำสั่งทั้งหมด:

```powershell
.\scripts\aegis.ps1 help
```

จาก Command Prompt ใช้ batch shim:

```cmd
cd /d D:\NIDs_Windows
scripts\aegis.bat help
```

ทุกตัวอย่างในคู่มือนี้ใช้ PowerShell เป็นหลัก

## 3. ติดตั้ง Production Bundle

สร้าง bundle จาก development machine:

```powershell
cd D:\NIDs_Windows
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1 -Version 6.0.0
```

เลือก directory ล่าสุดใน `release` และตรวจ manifest:

```powershell
$bundle = Get-ChildItem .\release -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

Get-Content "$($bundle.FullName)\manifest.json" -Raw |
  ConvertFrom-Json | Format-List
```

ติดตั้งบนเครื่องเป้าหมายด้วย PowerShell แบบ Administrator:

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\install_aegis.ps1 `
  -BundleRoot "$($bundle.FullName)"
```

ค่าเริ่มต้นของ install root คือ:

```text
C:\Program Files\AEGIS NIDS
```

Installer จะตรวจ SHA-256 ของ artifact ทุกไฟล์ก่อน copy ถ้าไฟล์หายหรือ hash ไม่ตรง การติดตั้งจะหยุดก่อนแก้ไข installation เดิม

## 4. Start และ Stop Runtime

จาก development tree ให้เริ่ม component ผ่าน launcher ก่อนตรวจ health:

```powershell
cd D:\NIDs_Windows
.\scripts\aegis.ps1 start
```

คำสั่งนี้เรียก `python tools\aegisctl.py start --all` และจะรายงาน `[MISSING]` หาก artifact ของ component ใดไม่มีอยู่ ต้องแก้ missing artifact และตรวจ exit code ก่อนทำ smoke test

หลังติดตั้ง ให้ตรวจ driver:

```powershell
sc.exe query AegisWfp
fltmc filters
```

เริ่ม WFP driver เมื่อ service มีอยู่และเป็น driver ที่ได้รับอนุญาต:

```powershell
sc.exe start AegisWfp
sc.exe query AegisWfp
```

เริ่ม core จาก installation directory:

```powershell
$install = 'C:\Program Files\AEGIS NIDS'
Start-Process "$install\runtime\aegis_nids.exe" -WorkingDirectory $install
```

สำหรับ development tree ให้ใช้ binary ที่ build แล้ว:

```powershell
cd D:\NIDs_Windows
Start-Process .\zig-out\bin\aegis_nids.exe -WorkingDirectory .
```

ตรวจหลัง start:

```powershell
Start-Sleep -Seconds 5
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 status
```

ก่อนหยุดหรือ restart ให้ใช้ lifecycle command ของ supervisor ที่ติดตั้งไว้ หากไม่มี command ดังกล่าวให้หยุด process ผ่านวิธีที่ release procedure กำหนด ห้ามใช้ `taskkill /F /IM *` เพราะอาจกระทบ process อื่นของเครื่อง

Rollback release:

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\install_aegis.ps1 `
  -BundleRoot 'C:\Program Files\AEGIS NIDS' `
  -Rollback
```

Rollback ต้องทำเมื่อ runtime หยุดแล้วและควรตรวจ `health` หลังเริ่ม version เดิมอีกครั้ง

## 5. ตรวจสุขภาพระบบ

สำหรับ command options, exit codes, alias ของ `forensic/forensics`, readiness gate และ workflow ระดับ Pro ให้ดู [AEGIS Command Center Pro Reference](./AEGIS_Command_Center_Pro_Reference.md)

### 5.1 Health

```powershell
.\scripts\aegis.ps1 health
```

ตรวจค่าต่อไปนี้:

| ค่า | ความหมาย | เกณฑ์ที่ควรได้ |
|---|---|---|
| `State` | สถานะ runtime รวม | `RUNNING` |
| `Degraded` | มี dependency หรือ worker ไม่พร้อม | `False` |
| `failure_mask` | bitmask ของ worker ที่ init ไม่ผ่าน | `0` |
| `pipeline_ready` | pipeline รับงานได้ | `READY` |
| `sensor_ready` | sensor initialized | `READY` |
| `nose_ready` | Go Nose พร้อมส่ง event | `READY` |
| `etw_ready` | ETW พร้อม | `READY` หรือมีเหตุผลที่ยอมรับได้ใน detection-only |
| `fim_ready` | FIM พร้อม | `READY` |
| `registry_ready` | Registry monitor พร้อม | `READY` |

### 5.2 Status และ diagnostics

```powershell
.\scripts\aegis.ps1 status
.\scripts\aegis.ps1 doctor
.\scripts\aegis.ps1 version
```

`doctor` ใช้ตรวจ readiness และ failure reasons เพิ่มเติม ส่วน `status` ใช้ดูภาพรวม component และ PID

### 5.3 Machine-readable snapshot

```powershell
python tools\aegisctl.py snapshot
```

คำสั่งนี้คืน JSON ที่รวม `health`, `metrics` และ `forensic` สำหรับ dashboard หรือ automation ไม่ควร parse output แบบข้อความของ `health` หากต้องการนำไปใช้ใน script

## 6. Metrics และ Data Plane

```powershell
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 events stats
.\scripts\aegis.ps1 events count
.\scripts\aegis.ps1 events tail --count 20
```

ตัวชี้วัดสำคัญคือ events processed, detections, blocks, errors, dropped events, forensic records, frames read, frames submitted, duplicate event IDs และ non-monotonic event IDs

ค่าที่ควรตรวจหลัง smoke test:

```text
events_processed > 0
forensic_records > 0
dropped = 0
duplicate_event_ids = 0
non_monotonic_event_ids = 0
```

ค่าศูนย์ของ detections อาจถูกต้องหาก fixture ไม่ตรง rule หรือระบบทำงานใน detection path ที่ยังไม่มี event นั้น จึงต้องดู event และ forensic record ประกอบ ไม่ควรสรุปจาก counter เดียว

## 7. Rules Lifecycle

Canonical rules file คือ:

```text
configs\Rules.json
```

ดู Rules:

```powershell
.\scripts\aegis.ps1 rules list
.\scripts\aegis.ps1 rules list --severity Critical
.\scripts\aegis.ps1 rules list --category Injection
.\scripts\aegis.ps1 rules show --id R9059
```

ตรวจความถูกต้องก่อน reload:

```powershell
.\scripts\aegis.ps1 rules validate
```

reload ผ่าน Control Center:

```powershell
.\scripts\aegis.ps1 rules reload
```

ลำดับที่ถูกต้องคือ:

```text
แก้ configs\Rules.json
→ rules validate
→ rules reload
→ health/metrics
→ forensic verify
```

ห้ามแก้ Rules ใน path สำเนา เช่น `config\Rules.json` แล้วคาดว่า daemon จะโหลด เพราะ runtime ใช้ `configs\Rules.json` เป็น canonical path

## 8. TUI

เปิด TUI:

```powershell
.\scripts\aegis.ps1 tui
```

TUI จะพยายามอ่านจาก Control Center ก่อน และจะแสดงแหล่งข้อมูลว่า `Control Center` หรือ `fallback process scan`

เมื่อ Control Center พร้อม TUI จะแสดง:

- Runtime state และ degraded state
- Worker readiness
- Data-plane read, submitted และ dropped
- Duplicate และ non-monotonic counters
- Forensic integrity และจำนวน records
- DEFCON และ operational overview

ถ้าเห็น `CONTROL UNAVAILABLE` ให้ถือว่าเป็น diagnostic fallback ไม่ใช่หลักฐานว่า runtime healthy

## 9. Dashboard

เปิด dashboard:

```powershell
.\scripts\aegis.ps1 web
```

ถ้ามี binary จะเปิด:

```text
aegis_dashboard\target\release\aegis_dashboard.exe
```

ถ้าไม่มี binary launcher จะพยายามใช้ Cargo:

```powershell
cd D:\NIDs_Windows\aegis_dashboard
cargo build --release
cd D:\NIDs_Windows
.\scripts\aegis.ps1 web
```

Dashboard แบ่งข้อมูลเป็นสองประเภท:

- `RUNTIME`: health จาก Control Center ผ่าน `aegisctl snapshot`
- `EVIDENCE`: records จาก `logs\aegis_core.ndjson`

ใช้ Dashboard สำหรับ overview และ investigation แต่ใช้ `aegis health` เป็นคำสั่งตัดสิน readiness อย่างเป็นทางการ

## 10. Threat Graph

สร้าง graph จาก canonical event log:

```powershell
.\scripts\aegis.ps1 graph
```

ผลลัพธ์เริ่มต้น:

```text
reports\threat_graph.html
```

กำหนดไฟล์เอง:

```powershell
.\scripts\aegis.ps1 graph `
  --log .\logs\aegis_core.ndjson `
  --output .\reports\threat_graph.html
```

Graph แสดงความสัมพันธ์:

```text
Source IP → Rule → AEGIS NIDS
```

Graph เป็นเครื่องมือวิเคราะห์ความสัมพันธ์ ไม่ใช่ runtime health monitor และไม่ควรใช้แทน forensic verification

## 11. Golden-path Smoke Test

รัน fixture ที่ไม่เป็นอันตราย:

```powershell
.\scripts\aegis.ps1 test golden-path
```

หรือเรียก generator โดยตรง:

```powershell
python scripts\aegis_event_gen.py `
  --pipe `
  --fixture xss `
  --count 1
```

หลังส่ง event ให้ตรวจ:

```powershell
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 events stats
.\scripts\aegis.ps1 forensic verify
```

ผลที่ต้องตรวจคือ event ถูกส่งผ่าน pipe, counter เพิ่ม, forensic record ถูกสร้าง และ hash chain ยัง `ok` การที่ transport รายงาน `OK` เพียงอย่างเดียวไม่เพียงพอ

Smoke test นี้ไม่ใช่ Controlled Attack Test และไม่ควรใช้ payload โจมตีจริงบน production host

## 12. Forensic Verification

```powershell
.\scripts\aegis.ps1 forensic verify
.\scripts\aegis.ps1 forensic list
```

ควรได้สถานะลักษณะนี้:

```text
integrity: ok
verified: true
records: <จำนวนที่สอดคล้องกับ event>
```

หาก integrity ไม่ผ่าน ให้เก็บผล `doctor`, `metrics`, `snapshot` และรายงานก่อนแก้หรือหมุน log ห้ามลบ evidence เพื่อทำให้ counter กลับมาเป็นศูนย์

## 13. Prometheus Metrics

หากใช้ exporter ที่มีอยู่:

```powershell
python scripts\aegis_metrics.py --print
python scripts\aegis_metrics.py --port 9100
```

endpoint คือ:

```text
http://127.0.0.1:9100/metrics
```

ควรตรวจว่า metric exporter ไม่ถูกใช้เป็นแหล่งตัดสิน runtime readiness แทน Control Center เพราะ exporter อาจอ้างอิง log ที่ล่าช้าหรือเก่า

## 14. Failure diagnosis

### Control pipe unavailable

ตรวจว่า core process ทำงานจริงและมี named pipe:

```powershell
.\scripts\aegis.ps1 status
.\scripts\aegis.ps1 doctor
Get-Process aegis_nids -ErrorAction SilentlyContinue
```

หากไม่มี process ให้เริ่ม core ใหม่ หาก process มีแต่ pipe ไม่มี ให้ตรวจ binary ที่รันอยู่, working directory, permission และ startup output

### State เป็น DEGRADED

เริ่มจาก:

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 doctor
python tools\aegisctl.py snapshot
```

ดู `failure_reasons` และ `failure_mask` ก่อนแก้เฉพาะจุด ตัวอย่างเช่น `etw_init_failed` ต้องตรวจ ETW session/provider และ `fim_init_failed` ต้องตรวจ watcher path และ permission

### WFP ไม่พร้อม

```powershell
sc.exe query AegisWfp
fltmc filters
```

ตรวจว่า driver อยู่ใน bundle, service path ถูกต้อง, driver signature และสิทธิ์ Administrator ครบ อย่าถือว่า process `RUNNING` หมายถึง enforcement พร้อมเมื่อ `wfp=false`

### Rules reload ล้มเหลว

```powershell
.\scripts\aegis.ps1 rules validate
python tools\aegisctl.py snapshot
```

ตรวจ canonical path, JSON syntax, named pipe availability และ runtime version ที่กำลังรันอยู่ หาก reload response ว่างหรือ parse JSON ไม่ได้ ให้เก็บ debug output และไม่แก้ไฟล์ซ้ำจนกว่าจะยืนยัน process/binary ที่ใช้งานจริง

### Events ส่งสำเร็จแต่ metrics ไม่เพิ่ม

ตรวจลำดับต่อไปนี้:

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 events stats
.\scripts\aegis.ps1 forensic verify
```

จากนั้นตรวจว่า event generator ต่อ pipe ของ core ตัวเดียวกับที่ `health` รายงานหรือไม่ ตรวจ data-plane submitted, dropped, duplicate และ event ID monotonicity

### Dashboard เปิดไม่ได้

ตรวจ binary หรือ build ใหม่:

```powershell
Test-Path .\aegis_dashboard\target\release\aegis_dashboard.exe
cd .\aegis_dashboard
cargo build --release
```

หาก dashboard เปิดได้แต่แสดง `Control Center unavailable` ให้ตรวจ `python tools\aegisctl.py snapshot` จาก project root และตรวจ working directory ของ process dashboard

## 15. Exit code และ automation

สำหรับ automation ให้ใช้ `aegisctl.py snapshot` และตรวจ JSON แทนการ parse สีหรือข้อความของ TUI

หลักการตีความผล:

| ผล | การดำเนินการ |
|---|---|
| `RUNNING`, degraded false, failure mask 0 | ดำเนินการตรวจขั้นถัดไป |
| `DEGRADED` หรือ worker ไม่พร้อม | หยุด attack test และเข้า diagnostic |
| Control Center unavailable | หยุด operational mutation และตรวจ lifecycle |
| forensic integrity ไม่ใช่ `ok` | หยุดการทดสอบและ preserve evidence |
| dropped/duplicate/non-monotonic เพิ่ม | ตรวจ data-plane contract ก่อนใช้งานต่อ |

## 16. Production readiness checklist

ก่อนประกาศใช้งานจริง ให้ตรวจตามลำดับนี้:

```powershell
.\scripts\aegis.ps1 version
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 doctor
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensic verify
.\scripts\aegis.ps1 test golden-path
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensic verify
```

เกณฑ์ขั้นต่ำคือ runtime `RUNNING`, ไม่มี unexpected degraded worker, rule validation ผ่าน, event path มีหลักฐาน, dropped/duplicate/non-monotonic เป็นศูนย์ใน test window และ forensic chain verified

## 17. ขอบเขตการใช้งานอย่างปลอดภัย

Controlled Attack Test ต้องทำใน Lab หรือ environment ที่ได้รับอนุญาตเท่านั้น ต้องกำหนด scope, source, target, time window และ rollback ก่อนเริ่ม การทดสอบบน production ต้องเริ่มจาก detection-only และ benign fixture ก่อนเสมอ

เมื่อ PEP, WFP, driver หรือ native telemetry ไม่พร้อม ระบบต้องแสดงสถานะ non-enforcing/degraded อย่างชัดเจน ห้ามสรุปว่า policy `ALLOW` คือการบังคับใช้สำเร็จ

## 18. แหล่งอ้างอิงภายในโครงการ

- [Operator CLI Guide](./AEGIS_Operator_CLI.md)
- [Operator UX Specification](./AEGIS_Operator_UX_Specification.md)
- [New Roadmap and Production Readiness](./AEGIS_NIDS_New_Roadmap_and_Production_Readiness.md)
- [Project README](../README.md)

## References

[1]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query "Microsoft sc query command documentation"
[2]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fltmc "Microsoft fltmc command documentation"
