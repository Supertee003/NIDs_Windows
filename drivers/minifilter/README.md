# Aegis Minifilter Driver

Filesystem minifilter driver สำหรับดัก file I/O (CREATE/WRITE/RENAME/DELETE) และ process creation ที่ kernel level แล้วส่งต่อไปให้ user-mode Zig sensor ตรวจสอบ

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Kernel Mode (aegis_minifilter.sys)                         │
│                                                            │
│  FilterManager ────► AegisPreCreate / PreWrite / PreSetInfo│
│         │                  │                               │
│         │                  ├─ Get normalized file path     │
│         │                  ├─ Build AEGIS_EVENT_HEADER     │
│         │                  └─ AegisSendEvent               │
│         │                       │                          │
│         │                       ▼                          │
│         │              FltSendMessage ───► Comm Port       │
│         │                                                  │
│  PsSetCreateProcessNotifyRoutineEx ───► AegisProcessNotify │
│         │                  │                               │
│         │                  ├─ Get ImageFileName            │
│         │                  ├─ Build AEGIS_EVENT_HEADER     │
│         │                  └─ AegisSendEvent               │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────────┐
│ User Mode (minifilter_reader.zig in aegis-nids.exe)        │
│                                                            │
│  FilterConnectCommunicationPort("\\AegisMinifilterPort")   │
│  FilterGetMessage() วนลูป                                   │
│   → parse: [FILTER_MESSAGE_HEADER][AEGIS_EVENT_HEADER][payload] │
│   → inspect_event(header, payload)                         │
└────────────────────────────────────────────────────────────┘
```

## Build Requirements

เหมือน WFP driver — ต้องการ WDK + Visual Studio 2022

## Build Instructions

### 1. Create Driver Project

เปิด Visual Studio 2022 → New Project → "Windows Driver" → "File System Minifilter Driver" (empty template)

เพิ่มไฟล์:
- `aegis_minifilter.h`
- `aegis_minifilter.c`
- `aegis_minifilter_file.c`
- `aegis_minifilter_proc.c`
- `aegis_minifilter_comm.c`
- `aegis_minifilter.inf` (set as "Package")

### 2. Configure Project

ใน Project Properties:
- **Linker → Input → Additional Dependencies**: `fltMgr.lib`, `ntstrsafe.lib`
- **C/C++ → Preprocessor → Preprocessor Definitions**: `NTDDI_VERSION=0x0A000000` (target Windows 10+)

### 3. Build

```
Build → Build Solution (Release x64)
```

ผลลัพธ์: `aegis_minifilter.sys`, `aegis_minifilter.inf`, `aegis_minifilter.cat`

## Install / Test

> ⚠️ **ทดสอบใน VM เท่านั้น** — minifilter บั๊กอาจทำให้ระบบ hang หรือ BSOD ได้

### 1. เปิด Test Signing

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

### 2. ติดตั้ง

วิธี A — ใช้ `fltmc` (เร็ว):
```cmd
fltmc load aegis_minifilter.sys
fltmc filters   ; ดู minifilter ที่ load อยู่
```

วิธี B — ใช้ service:
```cmd
sc create AegisMinifilter type= filesys binPath= "C:\drivers\aegis_minifilter.sys"
sc start AegisMinifilter
```

วิธี C — ใช้ `pnputil`:
```cmd
pnputil /add-driver aegis_minifilter.inf /install
```

### 3. ตรวจสอบ

```cmd
fltmc filters   ; AegisMinifilter ต้องอยู่ใน list, altitude 370000
```

Debug output (DebugView):
```
[AEGIS-MINI] DriverEntry: loading...
[AEGIS-MINI] Communication port created: \AegisMinifilterPort
[AEGIS-MINI] Driver loaded successfully.
[AEGIS-MINI] User-mode client connected
```

### 4. ทดสอบกับ Zig sensor

```cmd
python windows_brain.py
zig build run
```

ถ้าทุกอย่างทำงาน Zig จะ print:
```
[MINIFILTER] Connected to port. Reading messages...
```

ทดสอบสร้างไฟล์ใน `C:\Windows\System32\test.txt` → Brain จะรับ alert:
```
[AEGIS KERNEL] KERNEL_FILE match: \Windows\System32\test.txt (rule=R1001)
```

ทดสอบเปิด `mimikatz.exe` → Brain จะรับ alert:
```
[AEGIS KERNEL] KERNEL_PROCESS match: ...\mimikatz.exe (rule=R2001)
```

## Microsoft Rules Compliance

⚠️ กฎ Microsoft สำหรับ Minifilter ที่ต้องระวัง:

| กฎ | รายละเอียด |
|----|----------|
| ห้าม fail IRP_MJ_CLEANUP / IRP_MJ_CLOSE | Return `FLT_PREOP_SUCCESS_NO_CALLBACK` เสมอ |
| ใช้ FLT_FILE_NAME_NORMALIZED ใน PreCreate เท่านั้น | PostCreate ใช้ FLT_FILE_NAME_OPENED |
| อย่า hold spinlock ข้าม callback boundaries | ใช้ `FAST_MUTEX` แทน หรือ release ก่อน return |
| ระวัง re-entrant calls | Minifilter callback อาจถูกเรียกซ้ำ — ตรวจ stack recursion |
| Alitude ต้องจองกับ Microsoft | สำหรับ production ต้องขอจาก Microsoft แบบเป็นทางการ |

## Troubleshooting

| ปัญหา | สาเหตุ | แก้ไข |
|------|------|------|
| `fltmc load` fails | Test Signing ยังไม่เปิด, หรือ driver binary ไม่ match INF | `bcdedit /set testsigning on` + restart |
| Driver loads แต่ไม่เห็น events | User-mode ยังไม่ connect หรือ port name ผิด | ตรวจ Zig log — ต้องเห็น `Connected to port` |
| Hang หนังสือการเปิดไฟล์ | ใช้ spinlock ระหว่าง FltGetFileNameInformation | ใช้ FAST_MUTEX หรือใช้ Post-op แทน Pre-op |
| BSOD IRQL_NOT_LESS_ORIGINAL | ดึง file name ที่ IRQL สูงเกิน | เช็ค `KeGetCurrentIrql() <= APC_LEVEL` ก่อน |

## Future Enhancements

- **Registry monitoring**: เพิ่ม `CmRegisterCallbackEx` สำหรับ registry writes
- **Pipe creation monitoring**: ใช้ `FltRegisterFilter` ที่ `\\Device\\NamedPipe` (special case)
- **Async send**: ใช้ worker thread + queue แทนการ `FltSendMessage` synchronous ใน callback
- **Filter condition**: กรองเฉพาะ paths ที่น่าสนใจ (System32, Startup, etc.) เพื่อลด noise
