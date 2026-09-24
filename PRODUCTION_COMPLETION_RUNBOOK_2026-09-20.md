# AEGIS Production Completion Runbook

## เป้าหมาย

Runbook นี้ใช้ปิดงาน AEGIS ให้ถึง production delivery โดยแบ่งการรับรองเป็น gates ที่ตรวจสอบได้จริงบน Windows host ของผู้พัฒนา การผ่าน unit test หรือ static contract เพียงอย่างเดียวไม่ถือว่าเป็นหลักฐานว่า WFP สามารถ block traffic ได้จริง

> **หลักการสำคัญ:** ระบบจะไม่รายงาน `ENFORCED`, `BLOCKED` หรือ `host_effect_confirmed` จนกว่าจะมี provider-owned enforcement receipt ที่ผูกกับ request, policy, target, filter และผลตรวจสอบบน host จริง

## สถานะก่อนเริ่ม admin validation

Baseline ใน sandbox และ Windows toolchain ผ่านแล้ว ได้แก่ Zig, Rust, Go, Python acceptance suite, targeted golden/release tests, compileall, diff check และ release artifact digest verification รายละเอียดอยู่ใน `analysis/PRODUCTION_SAFETY_HANDOFF_2026-09-20.md`

สิ่งที่ยังต้องพิสูจน์บน Windows host คือ signed provider/driver, device ACL, WFP filter effect, removal/recovery, duplicate/idempotency และ behavior เมื่อ provider หรือ driver หาย

## Gate 0 — สร้างจุดย้อนกลับและเก็บ baseline

ทำบนเครื่อง Windows ที่ใช้ทดสอบเท่านั้น ควรใช้ VM หรือ snapshot ที่ย้อนกลับได้ และไม่ใช้ IP ของระบบ production อื่นเป็น target

เปิด **PowerShell as Administrator** แล้วรัน:

```powershell
Set-Location D:\NIDs_Windows
New-Item -ItemType Directory -Force .\admin-evidence | Out-Null
Get-Date -Format o | Tee-Object .\admin-evidence\gate0-start.txt
whoami /all | Out-File .\admin-evidence\identity.txt -Encoding utf8
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber | Out-File .\admin-evidence\os.txt -Encoding utf8
Get-Service AegisWfp -ErrorAction SilentlyContinue | Format-List * | Out-File .\admin-evidence\service-before.txt -Encoding utf8
```

ต้องเก็บ snapshot หรือ restore point ของ VM ก่อนทดสอบ block จริง หากระบบเป็นเครื่องจริงให้กำหนด target เป็น test-only IP และเตรียมคำสั่ง rollback ก่อนเริ่ม

## Gate 1 — Native build and regression

```powershell
Set-Location D:\NIDs_Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\analysis\run_native_validation.ps1
python -m pytest -q brain tests tools
python tools\release_engineering.py --verify
```

เกณฑ์ผ่านคือ native summary ทุกค่าเป็น `0`, Python suite ไม่มี failure และ release verifier รายงาน `384 artifacts present` พร้อม digest ตรงกัน หรือจำนวนใหม่ที่ manifest ระบุหลังมีการเปลี่ยนแปลงอย่างถูกต้อง

## Gate 2 — Read-only host preflight

สคริปต์นี้ต้องไม่พยายาม block traffic และใช้ตรวจสิทธิ์, service, health, Tier-3, PEP และ provider readiness:

```powershell
Set-Location D:\NIDs_Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_host_production_preflight.ps1 `
  -HealthRetries 3 `
  -RetryDelaySeconds 2 `
  *> .\admin-evidence\gate2-host-preflight.txt
$LASTEXITCODE
```

ก่อนอนุญาตให้ไป Gate 3 ต้องตรวจ JSON ที่ได้ด้วยตนเองและบันทึกค่า `administrator`, `service_installed`, `service_running`, `device_attested`, `tier3_ready`, `pep_ready` และ `provider_ready`

ถ้า `provider_ready` หรือ `device_attested` เป็น false ให้หยุดที่ Gate 2 ห้ามทดสอบ block จริง ระบบต้องคงสถานะ fail-closed

## Gate 3 — WFP provider readiness

```powershell
Set-Location D:\NIDs_Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_wfp_phase10_preflight.ps1 `
  *> .\admin-evidence\gate3-wfp-preflight.txt
$LASTEXITCODE
```

Gate นี้ต้องแสดงหลักฐานของ service/device/provider ที่สอดคล้องกัน ไม่ใช่เพียง service อยู่ในสถานะ `RUNNING` หาก output ระบุว่า `host_effect_capable=false` หรือ `enforcement_attempted=false` ให้ถือว่ายังไม่พร้อมสำหรับ Gate 4

## Gate 4 — Controlled block proof

ใช้เฉพาะ test target ที่สร้างไว้สำหรับห้องทดลอง และบันทึก target, timestamp, policy hash, request ID และ expected result ทุกครั้ง คำสั่งจริงของ Gate นี้ต้องมาจาก provider implementation ที่มีอยู่ใน working tree ปัจจุบันและต้องตรวจสอบ receipt หลังคำสั่ง ไม่ควรใช้ `netsh`, local JSON bookkeeping หรือคำสั่งที่ bypass Rust PEP

รูปแบบการบันทึกผลที่ต้องมี:

```text
request_id=
policy_id=
policy_version=
target=
provider_operation=
filter_id=
receipt_status=
receipt_hash=
host_observation=
```

Positive proof ต้องพิสูจน์ว่า test flow ถูก block บน host จริง Negative proof ต้องพิสูจน์ว่า unrelated flow ยังทำงานได้ และผลทั้งหมดต้องมี receipt ที่ตรวจสอบได้จาก daemon/provider ไม่ใช่ข้อความจาก CLI เพียงอย่างเดียว

## Gate 5 — Remove, duplicate, and recovery proof

ต้องทดสอบครบตามลำดับต่อไปนี้:

1. ส่ง block request ซ้ำด้วย request เดิมและ target เดิม ต้องไม่สร้าง filter ซ้ำโดยไม่มีเหตุผล
2. ส่ง remove request ด้วย authorization ที่ถูกต้อง ต้องลบ filter ที่ receipt อ้างถึง
3. ตรวจ unrelated flow หลัง remove
4. จำลอง provider unavailable หรือ driver unload ใน test VM
5. ตรวจว่า request ใหม่ fail-closed และไม่ claim host effect
6. คืน provider/driver แล้วตรวจ recovery และ readiness ใหม่
7. ตรวจว่า stale receipt หรือ receipt ที่ request ID ไม่ตรงถูกปฏิเสธ

ทุกกรณีต้องเก็บ output ไว้ใน `admin-evidence` และต้องมี host observation ประกอบ

## Gate 6 — Security negative testing

ก่อนส่งมอบต้องตรวจอย่างน้อย:

- client ที่ไม่มีสิทธิ์ไม่สามารถเรียก privileged control operation ได้
- client ที่ปลอม request ID หรือ policy hash ไม่สามารถสร้าง receipt ที่ valid ได้
- unsigned หรือ revoked policy ถูกปฏิเสธ
- unknown action ไม่ถูก map เป็น allow/pass
- direct WFP mutation จาก CLI, Python brain, Go ingress หรือ Zig module อื่นไม่มีผล
- provider failure ไม่ทำให้ UI รายงาน block สำเร็จ
- daemon stop รายงาน `STOPPING` ก่อน และ `STOPPED` หลัง worker join จริง
- forensic replay ตรวจพบ receipt ที่หายหรือ field chain ที่ถูกแก้ไข

การทดสอบโจมตีควรเริ่มจาก VM snapshot และ test account ไม่ควรเริ่มบนเครื่องที่มี traffic สำคัญ

## Gate 7 — Runtime metrics and installer closure

ก่อน delivery ต้องปิด project gaps ที่ manifest ระบุไว้:

- `packets_captured`, `flows_active` และ counters อื่นต้องอ่านจาก runtime state จริง ไม่ใช่ค่า placeholder
- installer ต้องใช้ manifest/current configuration ไม่ฝัง stale CI/config
- install, upgrade, rollback, uninstall และ service recovery ต้องผ่านบน clean VM
- artifact hashes ใน `build_manifest.json` ต้องตรงหลัง build สุดท้าย
- deployment log ต้องระบุ source commit, toolchain versions, driver version และ policy trust-store version

## Gate 8 — Final release decision

ให้ถือว่าส่งงานได้เมื่อทุกเงื่อนไขต่อไปนี้เป็นจริงพร้อมกัน:

- Gates 1–7 ผ่าน
- มี admin evidence ครบและ replay ได้
- มี real provider receipt สำหรับ positive และ negative WFP proofs
- ไม่มี test failure หรือ known placeholder ที่กระทบ contract
- release manifest verify ผ่านหลัง final build
- rollback ทำงานได้จาก clean snapshot
- final package ถูกสร้างจาก commit เดียวกับ manifest

หาก Gate 4 หรือ Gate 5 ยังไม่ผ่าน ให้ส่งมอบได้เฉพาะ **observe-only/detection build** และต้องระบุอย่างชัดเจนว่า host prevention ยังไม่พร้อม

## หลักฐานที่ต้องส่งกลับมาในการรันรอบถัดไป

ส่งเนื้อหาหรือไฟล์ต่อไปนี้กลับมาโดยไม่ต้องส่ง secret:

- `admin-evidence/gate0-start.txt`
- `admin-evidence/identity.txt`
- `admin-evidence/os.txt`
- `admin-evidence/service-before.txt`
- `admin-evidence/gate2-host-preflight.txt`
- `admin-evidence/gate3-wfp-preflight.txt`
- output ของ Gate 4–5 ที่ลบ IP, hostname, token และ secret แล้ว
- `analysis/native-validation/summary.txt`
- ผล `python -m pytest -q brain tests tools`
- ผล `python tools/release_engineering.py --verify`

ห้ามส่ง private key, access token, policy signing secret หรือข้อมูล credential ใด ๆ
