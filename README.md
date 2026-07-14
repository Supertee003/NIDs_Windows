# AEGIS NIDS — Windows Network & Host Intrusion Detection System

ระบบตรวจจับการบุกรุกแบบ 3-Layer Hybrid สำหรับ Windows ที่รวมการตรวจสอบทั้ง Network, File/Process และ IPC/Pipe ไว้ในระบบเดียว

---

## 🎯 ภาพรวมระบบ

```
┌─────────────────────────────────────────────────────────────────┐
│ Kernel Mode                                                     │
│   ┌──────────────────────────┐   ┌──────────────────────────┐   │
│   │ aegis_wfp.sys            │   │ aegis_minifilter.sys     │   │
│   │ WFP Callout (5-tuple)    │   │ File I/O + Process       │   │
│   │ Ring Buffer 2MB          │   │ FilterComm Port          │   │
│   └──────────┬───────────────┘   └──────────┬───────────────┘   │
└──────────────┼──────────────────────────────┼──────────────────┘
               │ IOCTL_AEGIS_READ_EVENTS       │ FilterGetMessage
               ▼                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ User Mode — aegis-nids.exe (Zig + Rust FFI)                     │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │ Thread 1: TCP :12345 + Named Pipe aegis_nids (analyze)   │  │
│   │ Thread 2: Sensor Pipe aegis_sensor_pipe (จาก Python)     │  │
│   │ Thread 3: WFP device reader (IOCTL)                      │  │
│   │ Thread 4: Minifilter reader (FilterGetMessage)           │  │
│   │ Thread 5: Pipe monitor (poll \\.\pipe\)                  │  │
│   └────────────────────┬─────────────────────────────────────┘  │
│                        │ inspect_event(header, payload)         │
│                        ▼                                         │
│   Engine: Rust shield → AC (Aho-Corasick) → AND → Brain UDP     │
└────────────────────────┬────────────────────────────────────────┘
                         │ UDP:9999 JSON
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Brain + Visualization                                            │
│   windows_brain.py → logs/anomalous.json                        │
│     ├─ Dashboard.py (TUI)                                       │
│     ├─ windows_sec_monitor.rs (DEFCON display)                  │
│     ├─ windows_perf.go (stats monitor)                          │
│     └─ threat_graph.html (vis-network graph)                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📂 โครงสร้างโปรเจกต์

```
NIDs_Windows/
├── nids_main.zig              # Entry point — spawn 5 threads
├── nids_analyze.zig           # Core engine: AC + AND + EventHeader + inspect_event
├── nids_capture.zig           # Sensor pipe (Python → Zig)
├── windows_capture.zig        # WFP device reader (IOCTL)
├── minifilter_reader.zig      # Minifilter communication port reader
├── pipe_monitor.zig           # Polling named pipe detector
│
├── src/lib.rs                 # Rust FFI: NOP-sled detector (sec_monitor.dll)
├── Cargo.toml                 # Rust crate config
├── build.zig                  # Zig build script
│
├── windows_brain.py           # Tier-2/3 Brain (regex + IPS)
├── Dashboard.py               # TUI log viewer
├── aegis_console.py           # Console UI
├── aegis_graph.py             # Threat graph generator
├── windows_sec_monitor.rs     # Rust DEFCON display
├── windows_perf.go            # Go perf monitor (real stats)
│
├── Rules.json                 # Rules (NETWORK + KERNEL_FILE + KERNEL_PROCESS + PIPE_MONITOR)
├── Back Rules.json            # Old 40+ rules (reference)
│
├── drivers/
│   ├── wfp_callout/           # WFP kernel driver source
│   │   ├── aegis_wfp.h
│   │   ├── aegis_wfp.c
│   │   ├── aegis_wfp_callout.c
│   │   ├── aegis_wfp_comm.c
│   │   ├── aegis_wfp.inf
│   │   └── README.md
│   └── minifilter/            # Minifilter driver source
│       ├── aegis_minifilter.h
│       ├── aegis_minifilter.c
│       ├── aegis_minifilter_file.c
│       ├── aegis_minifilter_proc.c
│       ├── aegis_minifilter_comm.c
│       ├── aegis_minifilter.inf
│       └── README.md
│
├── run_aegis.bat              # Launcher script
└── README.md                  # ← ไฟล์นี้
```

---

## 🚀 Quick Start

### Prerequisites

| Component | เวอร์ชัน | หมายเหตุ |
|-----------|--------|--------|
| **Zig** | 0.13.0+ | Build NIDS core |
| **Rust** | 1.70+ | Build sec_monitor.dll |
| **Python** | 3.10+ | Run Brain + Dashboard |
| **Go** | 1.21+ | Run perf monitor (optional) |
| **Windows SDK** | 10.0.19041+ | Build drivers |
| **WDK** | match SDK | Build kernel drivers |

### 1. Build Rust FFI Library

```cmd
cargo build --release
:: Output: target/release/sec_monitor.dll
```

### 2. Build Zig NIDS

```cmd
zig build
:: Output: zig-out/bin/aegis-nids.exe
```

### 3. รันระบบ (User-Mode only — ไม่ต้อง build drivers)

เปิด 3 terminals:

**Terminal 1 — Brain:**
```cmd
python windows_brain.py
```

**Terminal 2 — NIDS Core:**
```cmd
zig build run
:: หรือ: zig-out\bin\aegis-nids.exe
```

**Terminal 3 — Dashboard (optional):**
```cmd
python Dashboard.py
```

### 4. ทดสอบ

```cmd
:: ส่ง SQL injection ผ่าน TCP
echo "' OR 1=1 --" | ncat 127.0.0.1 12345

:: ส่ง XSS ผ่าน named pipe (Python)
python -c "import win32pipe, win32file; p=win32file.CreateFile(r'\\.\pipe\aegis_sensor_pipe',0x40000000,0,None,3,0,None); win32file.WriteFile(p, b\"<script>alert(1)</script>\")"
```

Brain ควรจะ print:
```
[TIER-1 ALERT] 2026-01-01 12:34:56 | SQL Injection (Auth Bypass) | policy=DROP | src=TCP_SOCKET
[CORE] IP Unknown BLOCKED by rule: SQL Injection (Auth Bypass)
```

---

## 🛡️ การใช้งาน Kernel Drivers (Optional — สำหรับการตรวจจับที่ครบ 3 ชั้น)

> ⚠️ **ทดสอบใน VM เท่านั้น** — kernel drivers อาจทำให้ Windows BSOD ได้
> 
> แนะนำให้สร้าง Windows 10/11 VM ใน Hyper-V / VirtualBox และ snapshot ก่อนเริ่ม

### 1. เปิด Test Signing

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

### 2. Build Drivers

ดูวิธี build ใน `drivers/wfp_callout/README.md` และ `drivers/minifilter/README.md`

### 3. ติดตั้ง Drivers

```cmd
:: WFP Driver
sc create AegisWfp type= kernel binPath= "C:\drivers\aegis_wfp.sys"
sc start AegisWfp

:: Minifilter Driver
sc create AegisMinifilter type= filesys binPath= "C:\drivers\aegis_minifilter.sys"
sc start AegisMinifilter
:: หรือ: fltmc load aegis_minifilter.sys
```

### 4. รัน NIDS — drivers จะถูก auto-detect

เมื่อรัน `zig build run` จะเห็น:
```
[WFP READER] Connected to \\.\AegisWfpDevice. Reading events via IOCTL...
[MINIFILTER] Connected to port. Reading messages...
[PIPE-MON] Thread started. Polling \\.\pipe\ every 2s...
```

ทดสอบ kernel events:
- เปิดไฟล์ใน `C:\Windows\System32\` → alert `R1001 Suspicious write to System32`
- รัน `mimikatz.exe` → alert `R2001 Suspicious process: mimikatz`
- รัน Cobalt Strike → alert `R3001 Cobalt Strike default named pipe`

---

## 📋 Rules Format

แต่ละ rule ใน `Rules.json` มี fields:

```json
{
    "rule_id": "R1001",
    "name": "Suspicious write to System32",
    "category": "File Integrity",
    "layer": "KERNEL_FILE",          // NETWORK | KERNEL_FILE | KERNEL_PROCESS | KERNEL_REGISTRY | PIPE_MONITOR
    "fast_pattern": "System32",      // สั้น ๆ ใช้สำหรับ AC engine
    "match_pattern": "\\Windows\\System32",  // แยกด้วย | สำหรับ AND/OR match
    "regex_pattern": "...",          // (optional) สำหรับ Brain Tier-2/3
    "file_operations": ["CREATE", "WRITE"],  // (optional) สำหรับ KERNEL_FILE
    "parent_exclude": ["services.exe"],      // (optional) สำหรับ KERNEL_PROCESS
    "severity": "Critical",          // Low | Medium | High | Critical
    "action": "Alert"                // Alert | Block | Drop (case-insensitive)
}
```

### Layer Routing

| Layer | ใช้กับ source | Detection method |
|-------|--------------|------------------|
| `NETWORK` | TCP_SOCKET, WFP_PACKET, PIPE_IPC | Rust shield → AC automaton → AND match → Brain regex |
| `KERNEL_FILE` | KERNEL_FILE (from minifilter) | Substring match บน path + file_operations filter |
| `KERNEL_PROCESS` | KERNEL_PROCESS (from minifilter) | Substring match บน image name + parent_exclude |
| `KERNEL_REGISTRY` | KERNEL_REGISTRY (future) | TBD |
| `PIPE_MONITOR` | PIPE_MONITOR (from polling) | Substring match บน pipe name |

---

## 🧪 Verification Plan

### Automated Tests (User-Mode)

```cmd
:: Build
zig build
cargo build --release

:: Unit tests (TBD — เพิ่ม tests ใน nids_analyze.zig)
zig build test

:: ทดสอบ EventHeader packing (sizeof == 40)
:: ทดสอบ rule filtering (layer match)
:: ทดสอบ case-insensitive action comparison
```

### Manual Tests

```cmd
:: 1. ทดสอบ TCP listener
echo "' OR 1=1 --" | ncat 127.0.0.1 12345

:: 2. ทดสอบ Pipe IPC
python -c "import win32pipe, win32file; p=win32file.CreateFile(r'\\.\pipe\aegis_sensor_pipe',0x40000000,0,None,3,0,None); win32file.WriteFile(p, b\"<script>alert('xss')</script>\")"

:: 3. ทดสอบ Brain UDP
python -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 9999))
data, addr = s.recvfrom(65536)
print(json.loads(data))
"

:: 4. ทดสอบ Pipe Monitor (สร้าง pipe ใหม่)
python -c "import win32pipe; win32pipe.CreateNamedPipe(r'\\.\pipe\MSSE-test', 0x3, 0, 1, 0, 0, 0, None); input()"
```

### Driver Tests (ใน VM เท่านั้น)

1. Snapshot VM ก่อน
2. Load drivers ตามวิธีใน `drivers/*/README.md`
3. ทดสอบ file write ใน System32 → ต้องเห็น alert ใน Brain
4. ทดสอบรัน mimikatz → ต้องเห็น alert ใน Brain
5. ทดสอบสร้าง pipe ชื่อ `\\.\pipe\MSSE-test` → ต้องเห็น alert ใน Brain
6. Load test: ส่ง traffic จำนวนมาก → ตรวจสอบ ring buffer ไม่ overflow
7. Stress test: สร้าง/ลบไฟล์จำนวนมาก → ตรวจสอบ minifilter performance

---

## 🔧 Configuration

### Rules.json

ดูรายละเอียดใน section "Rules Format" ด้านบน — สามารถแก้ไขได้ขณะ NIDS ทำงาน
Brain จะ auto-reload เมื่อไฟล์ถูก save

### Brain Settings (windows_brain.py)

```python
LOG_FILE = "logs/anomalous.json"
RULES_FILE = "Rules.json"
MAX_PAYLOAD_SIZE = 4096
UDP_IP = "127.0.0.1"
UDP_PORT = 9999
```

### Zig Settings (nids_analyze.zig)

```zig
// Thread pool limit
var connection_semaphore: std.Thread.Semaphore = .{ .permits = 100 };

// AC engine pattern limit (max rules)
// ไม่จำกัด — dynamic ArrayList

// UDP buffer
// ไม่จำกัด — dynamic ArrayList ต่อ message
```

### WFP Driver Settings (aegis_wfp.h)

```c
#define AEGIS_RING_SIZE         (2 * 1024 * 1024)  // 2MB ring buffer
// ปรับขนาดได้ตามต้องการ — ยิ่งใหญ่ยิ่งลด drop แต่กิน memory
```

### Minifilter Settings (aegis_minifilter.h)

```c
#define AEGIS_MINIFILTER_ALTITUDE     L"370000"  // Anti-virus range
// ⚠️ สำหรับ production ต้องขอ altitude จาก Microsoft แบบเป็นทางการ
```

---

## 🐛 Troubleshooting

### Zig build fails: "library sec_monitor not found"

```cmd
:: ต้อง build Rust ก่อน
cargo build --release
:: ตรวจสอบ target/release/sec_monitor.dll มีอยู่
```

### Zig build fails: "fltlib not found"

```cmd
:: ต้องติดตั้ง Windows SDK
:: ดาวน์โหลดจาก https://developer.microsoft.com/windows-sdk
```

### Brain: "WinError 10048" (port 9999 ค้าง)

```cmd
:: หา process ที่ใช้ port 9999
netstat -ano | findstr :9999
taskkill /PID <pid> /F
```

### WFP Driver: CreateFile returns 2 (file not found)

- ตรวจ `sc query AegisWfp` — service ต้องเป็น RUNNING
- ตรวจ DebugView สำหรับ error messages จาก driver

### Minifilter: fltmc filters ไม่เห็น AegisMinifilter

- ตรวจ altitude ใน INF ต้องเป็น "370000"
- ตรวจ `sc query AegisMinifilter` — service ต้องเป็น RUNNING

### Pipe Monitor ไม่เห็น pipe ใหม่

- ตรวจสิทธิ์ — ต้องรันด้วยสิทธิ์ admin สำหรับ pipe บางประเภท
- ลองสร้าง pipe จาก admin cmd prompt

---

## 📈 Performance Tuning

| Component | Tuning | Default |
|-----------|--------|---------|
| WFP Ring Buffer | เพิ่มขนาดใน `aegis_wfp.h` | 2MB |
| AC Engine | ใช้ Aho-Corasick (single pass, multi-pattern) | ✓ |
| Brain Regex | Compile ครั้งเดียว + auto-reload on change | ✓ |
| Pipe Monitor Poll | ปรับ `POLL_INTERVAL_NS` | 2s |
| WFP Retry | ปรับ `RETRY_INTERVAL_NS` | 30s |
| Thread Pool | ปรับ `connection_semaphore.permits` | 100 |

---

## 🤝 Contributing

1. Fork repo แล้ว create feature branch
2. Test ใน VM ก่อน push — kernel driver changes ต้องทดสอบอย่างละเอียด
3. Run `zig build test` ก่อน commit
4. Follow code style — ดู existing files เป็นตัวอย่าง

---

## 📜 License

MIT — ดู LICENSE file (TBD)
