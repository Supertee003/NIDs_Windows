# AEGIS Command Center: Pro Operator Reference

## ความหมายของสถานะล่าสุด

หาก health แสดง:

```text
State: RUNNING
Degraded: True
CPP: DEGRADED
error: windows_telemetry_not_ready
```

แปลว่า runtime spine และ worker หลักทำงานแล้ว แต่ Windows telemetry/C++ adapter ยังไม่พร้อม จึงยังไม่ใช่ fully healthy state การมี `failure_mask: 0` หมายถึง worker initialization ผ่าน ไม่ได้ลบล้าง subsystem degradation ของ CPP

ให้ใช้คำสั่งต่อไปนี้แยกคำถามให้ถูก:

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 doctor
```

`health` แสดง payload เต็ม, `readiness` เป็น gate สำหรับ automation และ `doctor` แสดงคำอธิบายเชิงวินิจฉัย

ผล `readiness` แยกสองชั้นอย่างตั้งใจ:

- `worker_gate`: worker ที่จำเป็นต่อ event pipeline initialize สำเร็จหรือไม่
- `overall_gate`: runtime และ subsystem ทั้งหมดพร้อมโดยไม่มี `degraded` หรือไม่

ดังนั้นกรณี `missing: []`, `worker_gate: true`, `overall_gate: false` หมายถึง worker หลักพร้อม แต่มี subsystem อื่น degraded เช่น `cpp_windows_telemetry_not_ready`

## Command groups

| Command | ใช้ตอบคำถาม |
|---|---|
| `status` | component และ PID อยู่หรือไม่ |
| `health` | runtime contract รายงานอะไร |
| `readiness` | พร้อมผ่าน gate หรือยัง |
| `doctor` | worker/native failure เกิดจากอะไร |
| `snapshot` | ขอ JSON ชุดเดียวให้ dashboard/automation |
| `metrics` | counters จาก Control Center |
| `rules` | validate/list/show/reload/mutate rules |
| `events` | นับ ดูสถิติ และ follow event evidence |
| `forensics` | verify/list hash-chain evidence |
| `tui` | terminal operator view |
| `web` | desktop dashboard |
| `graph` | source → rule → target analysis |

## Read-only diagnostics

```powershell
.\scripts\aegis.ps1 status
.\scripts\aegis.ps1 status --json
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 health --json
.\scripts\aegis.ps1 health --json --strict
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 doctor
.\scripts\aegis.ps1 snapshot
.\scripts\aegis.ps1 metrics
```

`health --strict` คืน exit code `1` เมื่อ `degraded=true` เหมาะสำหรับ CI หรือ preflight gate ส่วน `health` ปกติยังคืนข้อมูลเพื่อไม่ทำลาย workflow เดิม

ตัวอย่าง automation:

```powershell
python tools\aegisctl.py readiness --pretty
if ($LASTEXITCODE -ne 0) { throw 'AEGIS readiness gate failed' }
```

## Rules lifecycle

```powershell
.\scripts\aegis.ps1 rules list
.\scripts\aegis.ps1 rules list --severity Critical
.\scripts\aegis.ps1 rules list --category Injection
.\scripts\aegis.ps1 rules show --id R9059
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 rules reload
```

แก้ไฟล์ `configs\Rules.json` เท่านั้น แล้วทำ `validate → reload → metrics` ตามลำดับ การ reload เป็น mutation ที่ต้องผ่าน Control Center

## Event investigation

```powershell
.\scripts\aegis.ps1 events count --json
.\scripts\aegis.ps1 events stats --json
.\scripts\aegis.ps1 events tail --count 20 --json
.\scripts\aegis.ps1 events tail --count 10 --follow --interval 1
```

กด `Ctrl+C` เพื่อหยุด `--follow` อย่างปลอดภัย

## Forensic investigation

ใช้ชื่อกลุ่มพหูพจน์เป็น canonical command:

```powershell
.\scripts\aegis.ps1 forensics verify
.\scripts\aegis.ps1 forensics verify --json
.\scripts\aegis.ps1 forensics list
```

เพื่อรองรับ workflow ที่คนคุ้นเคย launcher ยังยอมรับ alias นี้:

```powershell
.\scripts\aegis.ps1 forensic verify
.\scripts\aegis.ps1 forensic list
```

ภายในจะ route ไปยัง `forensics verify` ที่ถูกต้อง ไม่ส่งเข้า parser ของ record operations (`show/search/export`)

## Golden-path procedure

```powershell
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 test golden-path
.\scripts\aegis.ps1 metrics
.\scripts\aegis.ps1 forensics verify
```

หาก readiness ไม่ผ่าน ให้หยุดก่อนส่ง fixture หาก transport ส่งสำเร็จแต่ metrics ไม่เพิ่ม ให้ตรวจ `snapshot`, data-plane counters และ event ID counters ก่อนทำซ้ำ

## Start behavior

```powershell
.\scripts\aegis.ps1 start
python tools\aegisctl.py start --all
python tools\aegisctl.py start --component core
```

คำสั่ง start จะรายงาน artifact ที่หายด้วย `[MISSING]` และไม่ควรถือว่า start สำเร็จจนกว่า `health` หรือ `readiness` จะยืนยันผล

## Exit code policy

| Code | ความหมาย |
|---:|---|
| 0 | คำสั่งสำเร็จ หรือ health query สำเร็จในโหมดไม่ strict |
| 1 | readiness/degraded gate ไม่ผ่าน หรือไม่พบ record/rule |
| 2 | syntax หรือ option ไม่ถูกต้อง |
| 3 | Control Center query ไม่สำเร็จ |
| 4 | Control API หรือ local dependency ใช้งานไม่ได้ |

## การวิเคราะห์ปัญหาในผลล่าสุด

กรณีที่ `CPP` เป็น `DEGRADED` แต่ worker ทั้งหกเป็น `READY` ให้ตรวจ native telemetry adapter, WFP/ETW/FIM diagnostics และ binary/driver ที่ใช้งานจริง ไม่ควรแก้ Rules หรือ rerun fixture เพราะไม่ใช่ปัญหาของ rule path

กรณีที่ `Control query failed: metrics.snapshot` ให้ตรวจ named pipe และ runtime process ก่อน:

```powershell
.\scripts\aegis.ps1 status
Get-Process aegis_nids -ErrorAction SilentlyContinue
python tools\aegisctl.py snapshot
```

กรณีที่ `WaitNamedPipe` หา pipe ไม่พบ ให้เริ่ม core ก่อน:

```powershell
.\scripts\aegis.ps1 start
Start-Sleep -Seconds 5
.\scripts\aegis.ps1 health
```

กรณีที่ `forensic verify` ถูกปฏิเสธด้วย invalid choice ให้ใช้ `forensics verify` หรือ launcher รุ่นปัจจุบันซึ่ง route alias ให้แล้ว

## Recommended aliases

สำหรับมนุษย์:

```powershell
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 forensics verify
```

สำหรับ automation:

```powershell
python tools\aegisctl.py snapshot
python tools\aegisctl.py readiness
python tools\aegisctl.py health --json --strict
```

สำหรับ dashboard:

```powershell
python tools\aegisctl.py snapshot
```

ไม่ควร parse output จาก TUI หรือข้อความสีใน automation

## Safety boundary

คำสั่งดูข้อมูลเป็น read-only แต่ `rules reload`, rule mutation, block, quarantine และ enforcement เป็น operational mutation ต้องใช้ Control Center, ต้องเก็บ audit และต้องตรวจ health ก่อนทำงาน การมี command ใน parser ไม่ใช่หลักฐานว่า native enforcement พร้อม

## References

[1]: https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exit-codes "Microsoft PowerShell exit code guidance"
[2]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query "Microsoft sc query command documentation"
