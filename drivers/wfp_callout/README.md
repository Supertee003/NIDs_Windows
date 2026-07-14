# Aegis WFP Callout Driver

WFP (Windows Filtering Platform) callout driver สำหรับดัก network packets ที่ kernel level แล้วส่งต่อไปให้ user-mode Zig sensor ตรวจสอบ

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ Kernel Mode (aegis_wfp.sys)                              │
│                                                          │
│  WFP Engine ───► AegisClassifyFn ───► Ring Buffer (2MB) │
│                       │                                  │
│                       ├─ ดึง 5-tuple (src/dst ip/port/proto) │
│                       ├─ ดึง payload จาก NBL              │
│                       └─ Build AEGIS_EVENT_HEADER        │
│                                                          │
│  IOCTL_AEGIS_READ_EVENTS ◄── User-mode (Zig)            │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ User Mode (windows_capture.zig in aegis-nids.exe)        │
│                                                          │
│  DeviceIoControl(device, IOCTL_AEGIS_READ_EVENTS, ...)   │
│   → batch-read events จาก ring buffer                    │
│   → parse: [AEGIS_EVENT_HEADER][payload]                 │
│   → inspect_event(header, payload)                       │
└──────────────────────────────────────────────────────────┘
```

## Build Requirements

- **Windows 10/11 SDK** + **WDK (Windows Driver Kit)** — ติดตั้งจาก Visual Studio Installer
- **Visual Studio 2022** พร้อม "Desktop development with C++" + "Spectre-mitigated libs"
- WDK version ที่ match กับ Windows SDK ของคุณ

## Build Instructions

### 1. Create Driver Project

เปิด Visual Studio 2022 → New Project → "Empty WDM Driver" (หรือ "Kernel Mode Driver, Empty")

เพิ่มไฟล์ต่อไปนี้เข้าโปรเจ็กต์:
- `aegis_wfp.h`
- `aegis_wfp.c`
- `aegis_wfp_callout.c`
- `aegis_wfp_comm.c`
- `aegis_wfp.inf` (set as "Package" — copy to output)

### 2. Configure Project

ใน Project Properties:
- **C/C++ → General → Additional Include Directories**: ระบุ path ของ WDK headers
- **Linker → Input → Additional Dependencies**: เพิ่ม `fwpkclnt.lib`, `ndis.lib`, `uuid.lib`
- **Driver Settings → Target Platform**: `Universal`
- **Inf2Cat → Run Inf2Cat**: `Yes` (สร้าง .cat file สำหรับ signing)

### 3. Build

```
Build → Build Solution (Release x64)
```

ผลลัพธ์จะได้:
- `aegis_wfp.sys` — driver binary
- `aegis_wfp.inf` — installation INF
- `aegis_wfp.cat` — catalog file สำหรับ signing

## Install / Test

> ⚠️ **ทดสอบใน VM เท่านั้น** — kernel driver อาจทำให้ Windows BSOD ได้

### 1. เปิด Test Signing (จำเป็นสำหรับ unsigned driver)

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

หลัง restart จะเห็น "Test Mode" ที่มุมขวาล่างของ desktop

### 2. ติดตั้ง Driver

วิธี A — ใช้ `sc` command:
```cmd
sc create AegisWfp type= kernel binPath= "C:\drivers\aegis_wfp.sys"
sc start AegisWfp
```

วิธี B — ใช้ `pnputil`:
```cmd
pnputil /add-driver aegis_wfp.inf /install
```

วิธี C — Right-click `aegis_wfp.inf` → Install

### 3. ตรวจสอบ Driver ทำงาน

```cmd
sc query AegisWfp
fltmc filters    ; ไม่ใช่ minifilter — ใช้ดูแค่เช็ค service status
```

Debug output (ด้วย DebugView จาก Sysinternals):
```
[AEGIS-WFP] DriverEntry: loading...
[AEGIS-WFP] Driver loaded successfully.
[AEGIS-WFP] Callout registered. Filters inbound=... outbound=...
```

### 4. รัน User-Mode Sensor

```cmd
:: รัน Brain (Python) ก่อน
python windows_brain.py

:: รัน NIDS (Zig)
zig build run
```

ถ้า driver ทำงาน Zig จะ print:
```
[WFP READER] Connected to \\.\AegisWfpDevice. Reading events via IOCTL...
```

### 5. ทดสอบด้วย ncat

```cmd
:: ส่ง SQL injection pattern ผ่าน TCP
echo "' OR 1=1 --" | ncat 127.0.0.1 12345

:: ดู Brain log
type logs\anomalous.json
```

## Troubleshooting

| ปัญหา | สาเหตุ | แก้ไข |
|------|------|------|
| `sc start` fails with `1275` | Test Signing ยังไม่เปิด | `bcdedit /set testsigning on` + restart |
| `CreateFile` returns `2` (file not found) | Driver ยังไม่ load หรือ symbolic link ไม่ถูกสร้าง | เช็ค `sc query AegisWfp`, ดู DebugView ว่ามี error ไหม |
| BSOD เมื่อโหลด driver | Bug ใน classify function | ตรวจสอบ pointer ที่ deref โดยไม่ check null, IRQL ที่ใช้ API ผิด |
| Ring buffer overflow | Traffic เยอะเกินไป | เพิ่ม `AEGIS_RING_SIZE` ใน header (ปัจจุบัน 2MB) |

## Future Enhancements

- **IPS Mode**: ใช้ `IOCTL_AEGIS_BLOCK_FLOW` ส่ง flow_id กลับ driver → classify function ตรวจแล้ว return `FWP_ACTION_BLOCK`
- **Layer expansion**: เพิ่ม `FWPM_LAYER_ALE_AUTH_CONNECT_V4` เพื่อตรวจ connection establishment
- **IPv6 support**: เพิ่ม filter ที่ `FWPM_LAYER_INBOUND_TRANSPORT_V6`
- **Performance**: ใช้ lock-free ring buffer (Single-Producer Single-Consumer) แทน spinlock
