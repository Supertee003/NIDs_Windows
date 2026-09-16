# AEGIS Pro Control Center Console

## แนวคิด

Console รุ่น Pro เป็น **control surface** สำหรับผู้ใช้งาน ไม่ใช่ runtime authority ชุดใหม่ ข้อมูล read-only มาจาก Control Center snapshot ส่วนการเปลี่ยนแปลงที่มีผลต่อ runtime ต้องผ่าน role และ command contract ที่มีอยู่

แบ่งผู้ใช้งานเป็นสองบทบาท:

| Role | สิทธิ์ |
|---|---|
| Operator | ดู health, worker, data plane, Mouth/Nose path, event และ forensic |
| Admin | ทุกอย่างของ Operator รวมถึง start, stop และ rules reload โดยต้องใช้ Administrator shell บน Windows |

## เปิด Console รุ่น Pro

จาก project root:

```powershell
cd D:\NIDs_Windows
.\scripts\aegis.ps1 console
```

เลือก role ให้ชัดเจน:

```powershell
.\scripts\aegis.ps1 console --role operator
.\scripts\aegis.ps1 console --role admin
```

ดู snapshot แบบไม่เข้า interactive menu:

```powershell
.\scripts\aegis.ps1 console --mode snapshot
```

ดู component map:

```powershell
.\scripts\aegis.ps1 console --mode components
```

ดู Mouth/Nose path:

```powershell
.\scripts\aegis.ps1 console --mode mouth-nose
```

## หน้าหลัก

หน้าหลักแสดงข้อมูลตามลำดับที่ผู้ปฏิบัติงานต้องตัดสินใจ:

1. Runtime state และ overall gate
2. PID, version และ uptime
3. Worker readiness และ failure mask
4. Data-plane read, submitted และ dropped
5. Exactly-once duplicate/non-monotonic counters
6. Forensic integrity และจำนวน records
7. Mouth/Nose data path
8. คำสั่งที่ role ปัจจุบันมีสิทธิ์ใช้

การกด `1` จะ refresh snapshot แบบ on-demand ไม่มี background refresh ในเมนูหลัก จึงไม่รบกวนการอ่านหรือรับ input

## Mouth/Nose view

กด `3` ในเมนู หรือใช้:

```powershell
.\scripts\aegis.ps1 console --mode mouth-nose
```

ข้อมูลที่เห็น:

```text
NOSE  : ingress state, worker readiness, pipe connection, frames read/submitted
MOUTH : Rust PEP/Tier3 state, WFP capability
PATH  : NOSE → canonical event → detection → policy → MOUTH/PEP → forensic
```

`MOUTH` ใน Console หมายถึงฝั่ง policy/enforcement view ไม่ใช่หลักฐานว่า firewall mutation สำเร็จทุกครั้ง ต้องตรวจ PEP/WFP evidence และ `health.capabilities` เพิ่มเติม

## Operator actions

Operator ใช้ได้เฉพาะ read-only controls:

```text
Refresh snapshot
Component/readiness detail
Mouth/Nose detail
Events statistics
Forensic verification
Open legacy TUI
Exit
```

ถ้า Operator พยายามสั่ง start, stop หรือ rules reload ระบบจะปฏิเสธและแจ้งให้ใช้ `--role admin`

## Admin actions

เปิด PowerShell แบบ Administrator:

```powershell
.\scripts\aegis.ps1 console --role admin
```

### Start runtime

กด `A` หรือใช้ CLI โดยตรง:

```powershell
.\scripts\aegis.ps1 start
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 readiness --pretty
```

### Validate และ reload rules

กด `R` หรือใช้:

```powershell
.\scripts\aegis.ps1 rules validate
.\scripts\aegis.ps1 rules reload
```

Console จะไม่เรียก reload หาก validation ไม่ผ่าน

### Stop runtime

กด `S` ใน Admin Console ระบบจะเรียก canonical `scripts\stop_aegis.bat` หากไม่พบ script จะปฏิเสธและไม่ใช้การ kill process แบบกว้างโดยอัตโนมัติ

## Legacy TUI

TUI เดิมยังเปิดได้จากเมนู Pro ด้วยตัวเลือก `6` หรือเรียกโดยตรง:

```powershell
.\scripts\aegis.ps1 tui
```

TUI เดิมเหมาะกับ compatibility menu และเครื่องมือเก่า เช่น log view, graph, test menu และ mouth build menu แต่ไม่ใช่หน้าหลักสำหรับตัดสิน runtime readiness ให้ใช้ Pro Console หรือ `aegis health/readiness` เป็นหลัก

Realtime dashboard ของ legacy TUI ควบคุม refresh ได้:

```powershell
.\scripts\aegis.ps1 tui --mode dashboard --interval 5
.\scripts\aegis.ps1 tui --mode dashboard --once
```

## Control rules

Console รุ่น Pro ใช้กฎต่อไปนี้:

- ไม่สร้าง runtime authority ซ้ำ
- ไม่รายงาน `OK` จาก local file write เพียงอย่างเดียว
- Admin mutation ต้องผ่าน role check
- Windows privileged action ต้องรันจาก Administrator shell
- Rules reload ต้อง validate ก่อน
- Stop ต้องใช้ canonical lifecycle script
- Health และ readiness อ่านจาก Control Center
- Mouth/Nose เป็น data-path view และไม่ใช่การรับรอง enforcement โดยลำพัง

## Troubleshooting

### Snapshot unavailable

```powershell
.\scripts\aegis.ps1 status
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 start
```

### Overall gate false แต่ worker gate true

```powershell
.\scripts\aegis.ps1 readiness --pretty
.\scripts\aegis.ps1 doctor
```

ให้ดู `degraded_components` และ `failure_reasons` เช่น `cpp_windows_telemetry_not_ready`

### Admin action blocked

เปิด PowerShell แบบ Run as administrator แล้วเรียก:

```powershell
.\scripts\aegis.ps1 console --role admin
```

## References

[1]: https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview "Microsoft User Account Control overview"
