# AEGIS Operator CLI

AEGIS ใช้คำสั่งหลักเพียงจุดเดียวสำหรับงานปฏิบัติการ โดย launcher จะส่งคำสั่ง runtime ไปยัง `aegisctl.py` และให้ Control Center เป็น authority เดียว การเรียก script ภายในโดยตรงควรใช้เฉพาะ development หรือ diagnostic ที่ระบุไว้เท่านั้น

## เริ่มใช้งาน

เปิด PowerShell หรือ Command Prompt ในโฟลเดอร์โปรเจกต์:

```powershell
cd D:\NIDs_Windows
```

ใน PowerShell:

```powershell
.\scripts\aegis.ps1 help
```

ใน Command Prompt:

```cmd
scripts\aegis.bat help
```

## คำสั่งประจำวัน

```powershell
.\scripts\aegis.ps1 status
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 doctor
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 version
```

`status` ใช้ดู component, `health` ใช้ตรวจ readiness, `doctor` ใช้ดู diagnostics และ `metrics` ใช้ดู counters จาก runtime จริง

## Rules

```powershell
.\scripts\aegis.ps1 rules list
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 rules reload
```

การ reload ต้องทำผ่าน Control Center เท่านั้น:

```text
แก้ configs\Rules.json
→ aegis rules validate
→ aegis rules reload
→ aegis metrics
```

## Events และ Forensics

```powershell
.\scripts\aegis.ps1 events stats
.\scripts\aegis.ps1 events count
.\scripts\aegis.ps1 events tail --count 20
.\scripts\aegis.ps1 forensic verify
.\scripts\aegis.ps1 forensic list
```

## TUI, Dashboard และ Threat Graph

ใช้ entrypoint เดียวกันเพื่อเปิดส่วนแสดงผลของระบบ:

```powershell
.\scripts\aegis.ps1 tui
.\scripts\aegis.ps1 web
.\scripts\aegis.ps1 graph
```

TUI เดิมถูกเก็บไว้เป็น compatibility view และควรใช้ `health`, `metrics` และ `events` จาก Control Center เป็นค่าหลักในการตัดสิน readiness เสมอ Dashboard Rust ใช้ `logs\aegis_core.ndjson` และ `configs\Rules.json` ส่วน graph ใช้ event log เดียวกันและสร้างรายงานที่ `reports\threat_graph.html` โดยเชื่อม source IP → rule → AEGIS NIDS

การสร้าง graph จากไฟล์อื่นทำได้ดังนี้:

```powershell
.\scripts\aegis.ps1 graph --log .\logs\aegis_core.ndjson --output .\reports\threat_graph.html
```

## Golden-path test

คำสั่งนี้ใช้ fixture ที่ไม่เป็นอันตรายและเหมาะสำหรับ smoke test หลัง start หรือ deploy:

```powershell
.\scripts\aegis.ps1 test golden-path
```

คำสั่งนี้ส่ง XSS fixture ผ่าน sensor pipe แล้วอ่าน metrics จาก Control Center ไม่ควรใช้แทน Controlled Attack Test หรือ production monitoring

## หลักการออกแบบ

Launcher นี้เป็น UX layer ไม่ใช่ runtime authority โดยมีหลักการดังนี้:

- runtime mutation ใช้ protected Control Center pipe
- `configs\\Rules.json` เป็น canonical rules path
- CLI, TUI, dashboard และ graph แสดงข้อมูลคนละหน้าที่ แต่ใช้ canonical runtime evidence เดียวกัน
- scripts เฉพาะทางยังคงมีไว้สำหรับ build, packaging และ diagnostic
- operator ไม่ต้องจำชื่อไฟล์ Python หลายไฟล์
- คำสั่งที่ไม่มีหลักฐานสำเร็จต้องคืน exit code ไม่เป็นศูนย์
- การทดสอบ attack ต้องแยกจาก smoke test และต้องอยู่ใน Lab ที่ได้รับอนุญาต

## Production operator sequence

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensic verify
```

ถ้า `health` ไม่ใช่ `RUNNING`, `Degraded` เป็น `True`, `failure_mask` ไม่เป็นศูนย์ หรือ forensic integrity ไม่ใช่ `ok` ให้หยุด operational testing และเข้าสู่ diagnostic workflow
