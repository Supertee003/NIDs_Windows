# บทที่ 3

# การออกแบบและพัฒนาระบบ

บทนี้นำเสนอการออกแบบและพัฒนาระบบตรวจจับการบุกรุกภายในเครือข่าย AEGIS (Aegis Network Intrusion Detection System) ซึ่งถูกออกแบบมาเพื่อแก้ปัญหาคอขวด (Bottleneck) ในการวิเคราะห์ข้อมูลจำนวนมาก และเพื่อลดการพึ่งพาไฟร์วอลล์หลัก โดยใช้ภาษาโปรแกรม 5 ภาษาที่มีจุดเด่นแตกต่างกัน ได้แก่ Zig, Rust, Python, Go และ C++ โดยแต่ละภาษาทำหน้าที่ในส่วนที่เหมาะสมกับคุณสมบัติของภาษานั้น ๆ เพื่อให้ระบบทำงานได้อย่างมีประสิทธิภาพสูงสุดและสอดคล้องกับหลักสุขอนามัยทางไซเบอร์ (Cyber Hygiene)

## 3.1 ภาพรวมสถาปัตยกรรมระบบ (System Architecture Overview)

ระบบ AEGIS NIDS ถูกออกแบบด้วยสถาปัตยกรรมแบบไฮบริด (Hybrid Architecture) ที่แบ่งการทำงานออกเป็น 2 โหมดหลัก คือ Kernel Mode และ User Mode โดยมีการสื่อสารระหว่างกันผ่านกลไกการสื่อสารระหว่างกระบวนการ (Inter-Process Communication — IPC) ที่มีความหน่วงต่ำ การออกแบบนี้ช่วยให้ระบบสามารถตรวจจับภัยคุกคามได้ในหลายชั้นของระบบปฏิบัติการ ทั้งในระดับเครือข่าย ระดับไฟล์และโปรเซส และระดับไปป์ (Named Pipe) สำหรับการสื่อสารระหว่างโปรเซส

### 3.1.1 แผนภาพสถาปัตยกรรม 3 ชั้น (3-Layer Architecture)

ระบบถูกออกแบบให้ครอบคลุมการตรวจจับภัยคุกคามใน 3 ชั้นหลัก ดังแสดงในรูปที่ 3.1 ได้แก่:

1. **ชั้นเครือข่าย (Network Layer)** — ตรวจจับภัยคุกคามจากแพ็กเก็ตข้อมูลที่วิ่งผ่านเครือข่าย โดยใช้ WFP Callout Driver ใน Kernel Mode และ TCP Socket Listener ใน User Mode ตรวจสอบทั้งการโจมตีแบบ Signature-based (เช่น SQL Injection, XSS) และ Anomaly-based (เช่น ICMP Flood, Port Scan)

2. **ชั้นไฟล์และโปรเซส (File/Process Layer)** — ตรวจสอบการเข้าถึงและการแก้ไขไฟล์ระบบที่สำคัญ (เช่น System32, Startup folder) รวมถึงการสร้างโปรเซสที่น่าสงสัย (เช่น mimikatz, procdump) โดยใช้ Minifilter Driver ใน Kernel Mode ที่ดักการทำงาน IRP_MJ_CREATE, IRP_MJ_WRITE และ IRP_MJ_SET_INFORMATION

3. **ชั้นไปป์ (Pipe Layer)** — ตรวจสอบการสร้าง Named Pipe ของโปรเซสอื่นในระบบ เพื่อตรวจจับการสื่อสารระหว่างโปรแกรมประสงค์ร้ายกับ Command and Control (C2) server เช่น Cobalt Strike default pipes (\\MSSE-*, \\status_*, \\postex_*) และ PsExec service pipes (\\PSEXESVC)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Kernel Mode (C++)                              │
│   ┌──────────────────────────┐    ┌────────────────────────────┐    │
│   │ aegis_wfp.sys            │    │ aegis_minifilter.sys       │    │
│   │ WFP Callout Driver       │    │ File/Process Monitor       │    │
│   │ (5-tuple + payload)      │    │ (IRP_MJ_CREATE/WRITE/SET)  │    │
│   │ Ring Buffer 2MB          │    │ FilterCommunicationPort    │    │
│   └─────────────┬────────────┘    └─────────────┬──────────────┘    │
└─────────────────┼───────────────────────────────┼───────────────────┘
                  │ IOCTL_AEGIS_READ_EVENTS        │ FilterGetMessage
                  ▼                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     User Mode — AEGIS Core (Zig)                    │
│   ┌──────────────────────────────────────────────────────────┐      │
│   │ Thread 1: TCP :12345 + Pipe aegis_nids (analyze)         │      │
│   │ Thread 2: Sensor Pipe aegis_sensor_pipe (from Python)    │      │
│   │ Thread 3: WFP device reader (IOCTL)                      │      │
│   │ Thread 4: Minifilter reader (FilterGetMessage)           │      │
│   │ Thread 5: Pipe monitor (poll \\.\pipe\)                   │      │
│   └────────────────────┬─────────────────────────────────────┘      │
│                        │ inspect_event(header, payload)             │
│                        ▼                                           │
│   Engine: Rust Shield → AC (Aho-Corasick) → AND match → Brain UDP  │
└────────────────────────┬────────────────────────────────────────────┘
                         │ UDP:9999 JSON
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Brain + Visualization (Python + Go + Rust)         │
│   windows_brain.py → logs/anomalous.json                            │
│     ├─ Dashboard.py (TUI)                                           │
│     ├─ windows_sec_monitor.rs (DEFCON display)                      │
│     ├─ windows_perf.go (Goroutines-based stats monitor)             │
│     └─ threat_graph.html (vis-network graph)                        │
└─────────────────────────────────────────────────────────────────────┘
```

*รูปที่ 3.1 สถาปัตยกรรม 3 ชั้นของระบบ AEGIS NIDS*

### 3.1.2 การเลือกใช้ภาษาโปรแกรม 5 ภาษา

การเลือกใช้ภาษาโปรแกรม 5 ภาษาเกิดจากการพิจารณาจุดเด่นของแต่ละภาษาที่เหมาะสมกับงานเฉพาะด้านในระบบ NIDS ดังแสดงในตารางที่ 3.1

**ตารางที่ 3.1 การเลือกใช้ภาษาโปรแกรมในระบบ AEGIS NIDS**

| ภาษา | บทบาทในระบบ | เหตุผลในการเลือก |
|------|------------|-----------------|
| **Zig** | Core Engine + Packet Capture + Tier-1 Fast Pattern Match | ควบคุมหน่วยความจำแบบ Manual ไม่มี Hidden Allocations, ประสิทธิภาพระดับ Native, Explicit Error Handling |
| **Rust** | Tier-3 Memory Safety Shield | Ownership ป้องกัน Buffer Overflow และ Race Condition, Zero-cost Abstractions, ป้องกันการโจมตีตัว NIDS เอง |
| **Python** | Tier-2 Deep Inspection (Regex) + Brain + CLI Daemon Manager | ความสะดวกในการเขียน Regex, Library ด้าน Security ครบครัน, Readability สูง |
| **Go** | Performance Dashboard + DEFCON Calculator | Goroutines สำหรับ Concurrency, Channel-based Architecture, แสดงผลเรียลไทม์ |
| **C++** | Kernel Mode Drivers (WFP + Minifilter) | ภาษามาตรฐานสำหรับ Windows Driver Development, เข้ากับ WDK และ FilterManager API ได้ดีที่สุด |

สำหรับภาษา C++ ผู้จัดทำขอเคลียร์ให้ชัดเจนว่า **C++ ถูกใช้ใน Kernel Mode เท่านั้น** ในส่วนของการพัฒนา Kernel Drivers ทั้ง WFP Callout Driver และ Minifilter Driver โดยไฟล์ต้นฉบับ C++ ประกอบด้วย:

- `drivers/wfp_callout/aegis_wfp.c` — Driver lifecycle (DriverEntry/Unload)
- `drivers/wfp_callout/aegis_wfp_callout.c` — WFP callout registration + classify function
- `drivers/wfp_callout/aegis_wfp_comm.c` — Ring buffer + IOCTL dispatch
- `drivers/minifilter/aegis_minifilter.c` — Minifilter lifecycle (FltRegisterFilter)
- `drivers/minifilter/aegis_minifilter_file.c` — Pre-operation callbacks สำหรับ file I/O
- `drivers/minifilter/aegis_minifilter_proc.c` — Process creation notification
- `drivers/minifilter/aegis_minifilter_comm.c` — FilterCommunicationPort kernel side

ส่วน User Mode ทั้งหมด (Capture, Analyze, Brain, Dashboard) พัฒนาด้วย Zig, Rust, Python และ Go เท่านั้น ไม่มี C++ ใน User Mode เนื่องจาก Zig สามารถเรียก Windows API ผ่าน extern declarations ได้โดยตรง และมี Memory Safety ที่ดีกว่า C++ ใน User Mode

## 3.2 การออกแบบและพัฒนาหน่วยดักจับแพ็กเก็ต (Capture Unit)

หน่วยดักจับแพ็กเก็ต (Capture Unit) เป็นส่วนแรกของระบบที่ทำหน้าที่ดักจับข้อมูลจากแหล่งต่าง ๆ ทั้งจากเครือข่ายและจากระบบปฏิบัติการ โดยแบ่งเป็น 3 แหล่งหลัก ได้แก่:

### 3.2.1 การดักจับจากเครือข่าย (Network Capture)

การดักจับแพ็กเก็ตเครือข่ายใช้ 2 วิธีควบคู่กัน:

**(1) TCP Socket Listener (User Mode)** — พัฒนาด้วยภาษา Zig ในไฟล์ `nids_analyze.zig` โดยเปิด TCP socket ที่ port 12345 สำหรับรับข้อมูลจากแอปพลิเคชันที่ต้องการให้ NIDS ตรวจสอบ ตัวอย่างเช่น:

```zig
fn tcp_listener() !void {
    var addr = net.Address.parseIp4("0.0.0.0", 12345) catch return;
    var server = addr.listen(.{ .reuse_address = true }) catch return;
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        connection_semaphore.wait();
        const t = std.Thread.spawn(.{}, handle_tcp_client, .{conn.stream}) catch {
            conn.stream.close();
            connection_semaphore.post();
            continue;
        };
        t.detach();
    }
}
```

การใช้ Thread Pool ที่จำกัดด้วย `connection_semaphore` (100 permits) ช่วยป้องกันการโอเวอร์โหลดเมื่อมีการเชื่อมต่อจำนวนมากพร้อมกัน ซึ่งเป็นการป้องกันการโจมตีแบบ Connection Exhaustion ได้ในตัว

**(2) WFP Callout Driver (Kernel Mode)** — พัฒนาด้วยภาษา C++ ในไฟล์ `drivers/wfp_callout/` เพื่อดักจับแพ็กเก็ตในระดับ Kernel ที่สามารถเห็น traffic ทั้งหมดที่วิ่งผ่าน Network Stack ของ Windows โดยใช้ Windows Filtering Platform (WFP) API ซึ่งเป็นเทคโนโลยีที่ Microsoft แนะนำสำหรับการพัฒนาระบบ Network Security

WFP Callout Driver ทำงานที่ Layer `FWPM_LAYER_INBOUND_TRANSPORT_V4` และ `FWPM_LAYER_OUTBOUND_TRANSPORT_V4` โดย Classify Function จะถูกเรียกทุกครั้งที่มีแพ็กเก็ตวิ่งผ่าน และทำหน้าที่ดังนี้:

1. ดึงข้อมูล 5-tuple (Source IP, Destination IP, Source Port, Destination Port, Protocol) จาก `inFixedValues`
2. ดึง Payload จาก `NET_BUFFER_LIST` (NBL) ผ่าน `NdisGetDataBuffer`
3. สร้าง `AEGIS_EVENT_HEADER` (ขนาด 40 bytes) พร้อมข้อมูล metadata
4. เขียนลง Ring Buffer ขนาด 2MB โดยใช้ Spinlock ป้องกัน Race Condition
5. คืนค่า `FWP_ACTION_PERMIT` (IDS mode — ปล่อยผ่านแพ็กเก็ต แล้วให้ User Mode ตัดสินใจภายหลัง)

ผู้ใช้สามารถอ่าน events จาก Ring Buffer ผ่าน IOCTL `IOCTL_AEGIS_READ_EVENTS` โดย Zig Sensor จะเรียก `DeviceIoControl()` แบบ batch read เพื่อลด overhead ของการสื่อสารระหว่าง Kernel และ User Mode

### 3.2.2 การดักจับจากไฟล์และโปรเซส (File/Process Capture)

การดักจับเหตุการณ์ในระดับไฟล์และโปรเซสใช้ Minifilter Driver ที่พัฒนาด้วยภาษา C++ ในไฟล์ `drivers/minifilter/` โดยลงทะเบียน Pre-operation Callbacks สำหรับ:

- **IRP_MJ_CREATE** — ดักการเปิดไฟล์ ใช้สำหรับตรวจจับการเข้าถึงไฟล์ระบบที่สำคัญ
- **IRP_MJ_WRITE** — ดักการเขียนไฟล์ ใช้สำหรับตรวจจับการแก้ไขไฟล์โดยไม่ได้รับอนุญาต
- **IRP_MJ_SET_INFORMATION** — ดักการเปลี่ยนชื่อและการลบไฟล์ ใช้สำหรับตรวจจับพฤติกรรม Ransomware

นอกจากนี้ยังลงทะเบียน `PsSetCreateProcessNotifyRoutineEx` สำหรับดักการสร้างและการสิ้นสุดโปรเซส โดยเมื่อมีโปรเซสใหม่ถูกสร้าง จะดึง ImageFileName และ ParentProcessId ส่งไปให้ User Mode ตรวจสอบว่าเป็นโปรแกรมที่น่าสงสัยหรือไม่ (เช่น mimikatz, procdump)

การสื่อสารระหว่าง Minifilter กับ User Mode ใช้ `FilterCommunicationPort` ที่สร้างด้วย `FltCreateCommunicationPort` ใน Kernel Mode และ User Mode จะเชื่อมต่อด้วย `FilterConnectCommunicationPort` แล้วรอรับ messages ด้วย `FilterGetMessage` ในลูป

### 3.2.3 การดักจับจากไปป์ (Pipe Monitor)

การดักจับการสร้าง Named Pipe ของโปรเซสอื่นใช้วิธี Polling ใน User Mode โดยพัฒนาด้วยภาษา Zig ในไฟล์ `pipe_monitor.zig` ซึ่งจะ enumerate directory `\\.\pipe\*` ทุก 2 วินาทีโดยใช้ `FindFirstFileA` และ `FindNextFileA` จากนั้นเปรียบเทียบกับรายการ pipes ที่เคยเห็น หากพบ pipe ใหม่จะส่งไปตรวจสอบกับกฎแบบ PIPE_MONITOR

วิธีนี้เป็นวิธีที่เรียบง่ายและไม่ต้องใช้ Kernel Hooking แต่มีข้อจำกัดคือไม่สามารถตรวจจับ pipe ที่สร้างและถูกทำลายภายใน 2 วินาทีได้ ในอนาคตอาจพัฒนาเป็น ETW (Event Tracing for Windows) เพื่อให้ตรวจจับได้แบบ Real-time

## 3.3 สถาปัตยกรรมการไหลของข้อมูลและลำดับการประมวลผล (System Data Flow and Processing Pipeline)

เพื่อให้ระบบ AEGIS NIDS สามารถทำงานได้อย่างต่อเนื่องและไม่เกิดคอขวด (Bottleneck) ในขณะที่มีทราฟฟิกปริมาณมาก การออกแบบจึงเน้นการประมวลผลแบบขนานและการส่งต่อข้อมูลอย่างเป็นระบบ

### 3.3.1 โมเดล EventHeader แบบรวม (Unified Event Header Model)

เพื่อให้ทุกแหล่งข้อมูล (Network, File, Process, Pipe) สามารถส่งผ่าน Engine เดียวกันได้ ผู้จัดทำออกแบบ `EventHeader` เป็น extern struct ขนาด 40 bytes ที่ใช้ร่วมกันระหว่าง Kernel Mode (C++) และ User Mode (Zig) โดยมีโครงสร้างดังนี้:

```zig
pub const EventHeader = extern struct {
    event_type: u32,        // EventSource enum
    event_size: u32,        // total size including payload
    timestamp: u64,         // nanoseconds since epoch
    process_id: u32,        // PID
    src_ip: u32,            // Network fields (zero if N/A)
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,           // TCP=6, UDP=17
    direction: u8,          // 0=inbound, 1=outbound
    payload_length: u16,
    path_offset: u16,       // offset for file/process events
    path_length: u16,
    operation: u16,         // IRP_MJ_CREATE=0, etc.
    _reserved: u16,
};
```

`EventSource` enum กำหนดประเภทของแหล่งข้อมูล 7 แบบ ได้แก่:

1. `TCP_SOCKET` (0) — จาก TCP listener port 12345
2. `WFP_PACKET` (1) — จาก WFP Callout Driver
3. `KERNEL_FILE` (2) — จาก Minifilter (file I/O)
4. `KERNEL_PROCESS` (3) — จาก Minifilter (process create/exit)
5. `KERNEL_REGISTRY` (4) — จาก Registry callback (อนาคต)
6. `PIPE_MONITOR` (5) — จาก pipe polling
7. `PIPE_IPC` (6) — จาก sensor pipe (aegis_sensor_pipe)

ฟังก์ชัน `inspect_event(header, payload)` ทำหน้าที่ route event ไปยัง handler ที่เหมาะสมตาม `event_type` โดยใช้ `switch` statement ดังนี้:

- Network events (TCP_SOCKET, WFP_PACKET, PIPE_IPC) → เรียก `inspect_network_payload()` ที่ใช้ Aho-Corasick engine
- File/Process events (KERNEL_FILE, KERNEL_PROCESS, KERNEL_REGISTRY) → เรียก `inspect_path_event()` ที่ใช้ substring match แบบ case-insensitive
- Pipe events (PIPE_MONITOR) → เรียก `inspect_path_event()` เช่นกัน เพราะใช้ path matching เหมือนกัน

### 3.3.2 กลไกการวิเคราะห์ภัยคุกคามแบบ 3 ระดับ (3-Tier Detection Engine Strategy)

เพื่อความแม่นยำและประสิทธิภาพ ระบบได้ออกแบบลำดับการตรวจจับไว้ 3 ระดับ โดยแต่ละระดับทำหน้าที่กรองข้อมูลและตรวจสอบในระดับความซับซ้อนที่เพิ่มขึ้น ดังแสดงในรูปที่ 3.2

```
┌─────────────────────────────────────────────────────────────┐
│  TIER 3: Rust Memory Safety Shield (Pre-screen)             │
│  ─────────────────────────────────────────────────────       │
│  ตรวจสอบก่อนส่งเข้า Tier 1:                                  │
│    • NOP Sled Detection (>50 consecutive 0x90)              │
│    • Buffer Overflow Patterns (heap spray, 0x0c pattern)     │
│    • Suspicious Packet Sizes (>65KB without valid IP header) │
│    • Malformed Headers (all-zero, all-0xFF, repeated pattern)│
│    • Metasploit Signatures (meterpreter string)             │
│  คืนค่า: true (ปลอดภัย → ส่งต่อ Tier 1)                       │
│        false (อันตราย → Drop ทันที)                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  TIER 1: Zig Fast Pattern Match (Aho-Corasick)               │
│  ─────────────────────────────────────────────────────       │
│  • สแกน payload ด้วย AC automaton (single-pass, multi-pattern)│
│  • ตรวจ logical AND match (keywords คั่นด้วย |)               │
│  • Layer-based filtering (NETWORK/KERNEL_FILE/PIPE_MONITOR)  │
│  • Case-insensitive action comparison (Block/BLOCK/block)    │
│  คืนค่า: true (match → ส่ง alert ไป Brain)                    │
│        false (no match → forward ไป Tier 2)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │ UDP:9999 JSON
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  TIER 2: Python Deep Inspection (Regex Engine)               │
│  ─────────────────────────────────────────────────────       │
│  • Compile regex rules ครั้งเดียว เก็บใน memory                │
│  • Auto-reload เมื่อ Rules.json เปลี่ยน (mtime check)         │
│  • ตรวจ SQL Injection, XSS, Path Traversal, Log4Shell ฯลฯ   │
│  • Apply firewall policy (netsh advfirewall) ถ้า policy=BLOCK│
│  คืนค่า: เขียน log + สั่ง IPS ถ้าจำเป็น                         │
└─────────────────────────────────────────────────────────────┘
```

*รูปที่ 3.2 กลไกการวิเคราะห์ภัยคุกคามแบบ 3 ระดับ*

**Tier 3: Rust Memory Safety Shield** — เป็นด่านหน้าที่ทำงานก่อน Tier 1 เพื่อป้องกันการโจมตีที่มุ่งเป้าไปที่ตัว NIDS เอง (Self-Protection) พัฒนาด้วยภาษา Rust ในไฟล์ `src/lib.rs` โดยใช้ Ownership และ Zero-copy slice ทำให้ไม่มี overhead จากการจองหน่วยความจำเพิ่ม ตรวจสอบ 4 ประเภทของภัยคุกคาม ได้แก่:

1. **Suspicious Packet Sizes** — แพ็กเก็ตที่ใหญ่กว่า 65KB โดยไม่มี valid IP header signature (อาจเป็น Ping of Death หรือ Oversized ICMP)
2. **NOP Sled Detection** — ตรวจหา `\x90` ติดกันเกิน 50 bytes (Shellcode signature)
3. **Buffer Overflow Patterns** — ตรวจหา heap spray (200+ bytes ซ้ำกัน), NOP sled markers, Metasploit meterpreter string
4. **Malformed Headers** — ตรวจหา all-zero payload, all-0xFF payload, repeated 2-byte patterns

**Tier 1: Zig Fast Pattern Match** — ใช้อัลกอริทึม Aho-Corasick สำหรับการค้นหาหลาย pattern ใน single pass ซึ่งมีประสิทธิภาพ O(n) โดยไม่ขึ้นกับจำนวน patterns ตัว AC automaton ถูกสร้างจาก `fast_pattern` field ของแต่ละ rule ใน `Rules.json` และมี failure links สำหรับกรณีที่ pattern ซ้อนทับกัน

หลังจาก match ใน Tier 1 แล้ว จะมีการตรวจสอบ Tier 2 ด้วย Logical AND matching โดยตรวจว่าทุก keyword ใน `match_pattern` (คั่นด้วย `|`) ปรากฏใน payload หรือไม่ ถ้า match ทั้งหมดจะถือว่าเป็นการโจมตีจริง

**Tier 2: Python Deep Inspection** — ใช้ Regular Expression engine ของ Python สำหรับการวิเคราะห์รูปแบบการโจมตีที่ซับซ้อน เช่น SQL Injection แบบ Auth Bypass (`' OR 1=1`), OS Command Injection (`; cat /etc/passwd`), หรือ Log4Shell (`${jndi:ldap://...}`) โดย rules ทั้งหมดถูก compile ครั้งเดียวตอนเริ่มระบบ และจะ reload อัตโนมัติเมื่อ `Rules.json` ถูกแก้ไข

### 3.3.3 การสื่อสารระหว่างกระบวนการ (Inter-Process Communication)

ระบบใช้ 3 ช่องทางการสื่อสารระหว่างกระบวนการ:

**(1) Named Pipes IPC** — ใช้สำหรับส่งข้อมูลระหว่าง Python (sensor) กับ Zig (engine) ผ่าน `\\.\pipe\aegis_sensor_pipe` และ `\\.\pipe\aegis_nids` โดย Zig ทำหน้าที่เป็น server และ Python เป็น client

**(2) UDP Socket** — ใช้สำหรับส่ง alerts จาก Zig (Tier 1) ไปยัง Python Brain (Tier 2) ผ่าน UDP port 9999 โดยใช้ JSON format ที่ส่งข้อมูลแบบ fire-and-forget (ไม่รอ response) เพื่อลด latency

**(3) IOCTL + FilterCommunicationPort** — ใช้สำหรับสื่อสารระหว่าง Kernel Mode กับ User Mode โดย WFP Driver ใช้ IOCTL ผ่าน `DeviceIoControl` และ Minifilter ใช้ `FilterGetMessage`

## 3.4 การออกแบบส่วนติดต่อผู้ใช้และการตอบสนอง (Interface and Active Response Design)

### 3.4.1 การควบคุมผ่าน Command Line Interface (CLI) Daemon Manager

ระบบออกแบบมาให้ทำงานในลักษณะ Daemon หรือ Service พื้นหลัง โดยผู้ดูแลระบบสามารถควบคุมและสั่งการได้ผ่าน CLI Daemon Manager ที่พัฒนาด้วยภาษา Python ในไฟล์ `aegis_daemon.py` ซึ่งรองรับคำสั่งดังตารางที่ 3.2

**ตารางที่ 3.2 คำสั่ง CLI Daemon Manager**

| คำสั่ง | คำอธิบาย | ตัวอย่างการใช้งาน |
|-------|---------|------------------|
| `start` | เริ่มระบบ NIDS ทั้งหมดใน background | `python aegis_daemon.py start` |
| `stop` | หยุดระบบทั้งหมดอย่างสง่างาม (graceful) | `python aegis_daemon.py stop` |
| `restart` | รีสตาร์ทระบบ (stop + start) | `python aegis_daemon.py restart` |
| `status` | แสดงสถานะการทำงานของทุก subsystem | `python aegis_daemon.py status` |
| `rules` | Hot-reload Rules.json (touch mtime) | `python aegis_daemon.py rules` |
| `logs` | Tail logs/anomalous.json แบบ real-time | `python aegis_daemon.py logs` |
| `health` | ตรวจสุขภาพระบบ (CPU, memory, network) | `python aegis_daemon.py health` |
| `install` | ติดตั้งเป็น Windows Service (placeholder) | `python aegis_daemon.py install` |
| `uninstall` | ถอนการติดตั้ง Windows Service | `python aegis_daemon.py uninstall` |

Daemon Manager ทำงานโดยใช้ไลบรารี `psutil` สำหรับจัดการ processes และเก็บ PID files ใน `logs/pids/` เพื่อ track กระบวนการที่กำลังทำงาน การหยุดระบบใช้การส่งสัญญาณ terminate ก่อน และถ้าไม่หยุดภายใน 5 วินาที จะใช้ kill signal เพื่อบังคับหยุด

### 3.4.2 กลไกการตอบสนองเชิงรุก (Active Response Mechanism)

เมื่อเอนจินการตรวจจับยืนยันการบุกรุก (Confirmed Match) ระบบจะดำเนินการตามนโยบาย (Policy) ที่กำหนดไว้ใน `Rules.json` โดยอัตโนมัติ โดยแบ่งเป็น 3 ระดับการตอบสนอง:

1. **Log & Alert** — บันทึกรายละเอียดการโจมตีลง `logs/anomalous.json` (JSONL format) และแจ้งเตือนผ่าน Dashboard และ DEFCON display

2. **Active Block** — เรียกใช้คำสั่งระดับระบบปฏิบัติการผ่าน `netsh advfirewall firewall add rule` เพื่อเพิ่มกฎการบล็อก IP Address ของผู้โจมตีเข้าสู่ Windows Firewall ทันที โดยใช้ `subprocess.run()` ใน Python ดังนี้:

```python
def apply_firewall_block(ip_address, rule_name="Aegis-NIDS"):
    fw_rule_name = f"AEGIS_BLOCK_{ip_address}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={fw_rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        f"description=Blocked by Aegis NIDS rule: {rule_name}",
    ]
    subprocess.run(cmd, capture_output=True, check=True)
```

3. **In-band Block (IPS Mode)** — สำหรับ WFP Driver ในอนาคต จะใช้ IOCTL `IOCTL_AEGIS_BLOCK_FLOW` เพื่อส่ง flow_id กลับไปยัง driver แล้ว classify function จะ return `FWP_ACTION_BLOCK` แทน `FWP_ACTION_PERMIT` เพื่อบล็อกแพ็กเก็ตใน Kernel Mode ก่อนถึงแอปพลิเคชัน

### 3.4.3 การแสดงผลแบบเรียลไทม์ (Real-time Visualization)

ระบบมี 3 ส่วนแสดงผลที่ทำงานพร้อมกัน:

**(1) Dashboard.py (Python TUI)** — แสดงตาราง log ล่าสุด 12 รายการ พร้อมสถิติแยกตาม source type, layer, severity อัปเดตทุก 1 วินาที

**(2) windows_perf.go (Go — Goroutines-based)** — ใช้ Goroutines 3 ตัวสำหรับ:
- Goroutine 1: Log File Reader — อ่าน `logs/anomalous.json` ทุก 1 วินาที ส่งผ่าน channel `threatCh`
- Goroutine 2: DEFCON Calculator — รับ stats จาก `threatCh` คำนวณ DEFCON level (1-5) ส่งไป `defconCh`
- Goroutine 3: System Stats Collector — เก็บ memory stats ทุก 2 วินาที ส่งไป `sysCh`

Main goroutine รวมข้อมูลจากทั้ง 3 channels แล้ว render ทุก 1 วินาที โดยใช้ `select` statement สำหรับรอข้อมูลจากหลาย channels พร้อมกัน

**(3) windows_sec_monitor.rs (Rust DEFCON Display)** — แสดงระดับ DEFCON แบบสี (เขียว/เหลือง/ส้ม/แดง/ม่วง) สำหรับระดับความรุนแรงของการโจมตี

## 3.5 ลำดับขั้นตอนการทำงานและการตัดสินใจของระบบ (Processing Logic)

จากแผนผังภาพรวมและ Flowchart การทำงานข้างต้น ระบบ AEGIS NIDS ถูกออกแบบมาเพื่อแก้ปัญหาคอขวด (Bottleneck) ในการวิเคราะห์ข้อมูลจำนวนมาก โดยแบ่งระดับการตัดสินใจออกเป็น 2 ระดับหลัก (Tiered Defense):

### 3.5.1 การตัดสินใจระดับ Tier-1 (Zig Engine)

เน้นความเร็วสูงสุด (Speed Optimization) ระบบจะทำการดักจับและตรวจสอบข้อมูลดิบในระดับไบนารีทันที โดยมีลำดับการตัดสินใจดังนี้:

1. รับ payload จาก source (TCP socket, WFP IOCTL, Minifilter port, Pipe monitor)
2. เรียก Rust `validate_payload_safety()` สำหรับ Tier-3 Pre-screening
3. ถ้า Rust คืนค่า false → Drop payload ทันที (Tier-3 threat)
4. ถ้าผ่าน → ใช้ Aho-Corasick engine สแกน payload เทียบกับ rules ทั้งหมดในเลเยอร์ที่ตรงกับ source
5. ถ้า match → ตรวจ Tier 2 (Logical AND) ยืนยัน match
6. ถ้า Tier 2 ผ่าน → ส่ง alert ไป Brain ผ่าน UDP:9999 พร้อมตรวจ action (Alert/Block/Drop)
7. ถ้าไม่ match → forward payload ไป Brain สำหรับ Tier-2 Deep Inspection

### 3.5.2 การตัดสินใจระดับ Tier-2 (Python Brain)

ในกรณีที่ข้อมูลมีความซับซ้อน (Deep Inspection) ข้อมูลจะถูกส่งต่อผ่าน UDP ไปยัง Python Brain ซึ่งทำงานดังนี้:

1. รับ JSON message จาก UDP:9999
2. แยกประเภท: ถ้าเป็น Tier-1 match → บันทึก log + apply firewall policy ถ้าจำเป็น
3. ถ้าเป็น forward (no Tier-1 match) → สแกนด้วย regex engine (Tier-2/3)
4. ถ้า regex match → บันทึก log + apply firewall policy + ส่ง DEFCON update ไป Go dashboard
5. ถ้าไม่ match → บันทึกเป็น "Unmatched" เพื่อวิเคราะห์ภายหลัง

### 3.5.3 การตัดสินใจระดับ Kernel (C++ Drivers)

Kernel Mode drivers ทำหน้าที่เพียง capture events และส่งต่อไป User Mode โดยไม่ตัดสินใจเอง (IDS mode) ยกเว้นในกรณีที่ระบบตั้งค่าเป็น IPS mode ที่ driver จะตรวจ block table และ return `FWP_ACTION_BLOCK` สำหรับ flows ที่ถูกบล็อก

## 3.6 โครงสร้างไฟล์โปรเจกต์ (Project File Structure)

โครงสร้างไฟล์ของระบบ AEGIS NIDS แสดงในรูปที่ 3.3

```
NIDs_Windows/
├── nids_main.zig              # Entry point — spawn 5 threads
├── nids_analyze.zig           # Core engine: AC + AND + EventHeader + inspect_event
├── nids_capture.zig           # Sensor pipe server (Python → Zig)
├── windows_capture.zig        # WFP device reader (IOCTL)
├── minifilter_reader.zig      # Minifilter communication port reader
├── pipe_monitor.zig           # Polling named pipe detector
├── build.zig                  # Zig build script
│
├── src/lib.rs                 # Rust FFI: Tier-3 Memory Safety Shield
├── Cargo.toml                 # Rust crate config
│
├── windows_brain.py           # Tier-2 Brain: regex + IPS
├── Dashboard.py               # TUI log viewer (real-time)
├── aegis_console.py           # Rule management UI
├── aegis_daemon.py            # CLI Daemon Manager
├── aegis_graph.py             # Threat graph generator (vis-network)
│
├── windows_sec_monitor.rs     # Rust DEFCON display
├── windows_perf.go            # Go perf monitor (Goroutines-based)
│
├── Rules.json                 # Active rules (NETWORK + KERNEL + PIPE_MONITOR)
├── run_aegis.bat              # Windows launcher script
│
├── drivers/
│   ├── wfp_callout/           # WFP kernel driver (C++)
│   │   ├── aegis_wfp.h        # Shared header (40-byte EventHeader, IOCTL codes)
│   │   ├── aegis_wfp.c        # DriverEntry/Unload + device creation
│   │   ├── aegis_wfp_callout.c # WFP callout registration + classify function
│   │   ├── aegis_wfp_comm.c   # Ring buffer + IOCTL dispatch
│   │   ├── aegis_wfp.inf      # Driver installation INF
│   │   └── README.md
│   └── minifilter/            # Minifilter driver (C++)
│       ├── aegis_minifilter.h
│       ├── aegis_minifilter.c # FLT_REGISTRATION + process notify
│       ├── aegis_minifilter_file.c   # Pre-callbacks for file I/O
│       ├── aegis_minifilter_proc.c   # Process create/exit callback
│       ├── aegis_minifilter_comm.c   # FltCreateCommunicationPort
│       ├── aegis_minifilter.inf
│       └── README.md
│
├── logs/                      # Runtime logs (gitignored)
│   ├── anomalous.json         # Threat alerts (JSONL)
│   ├── daemon.log             # Daemon manager log
│   └── pids/                  # PID files for tracking processes
└── README.md                  # Main documentation
```

*รูปที่ 3.3 โครงสร้างไฟล์โปรเจกต์ AEGIS NIDS*

## 3.7 สรุปการออกแบบ

การออกแบบระบบ AEGIS NIDS ที่นำเสนอในบทนี้มีจุดเด่น 5 ประการ ได้แก่:

1. **สถาปัตยกรรม 3 ชั้น (3-Layer Architecture)** — ครอบคลุมการตรวจจับในทุกระดับของระบบปฏิบัติการ ตั้งแต่เครือข่าย, ไฟล์/โปรเซส, ไปจนถึง Named Pipe ทำให้สามารถตรวจจับภัยคุกคามได้ครอบคลุมกว่า NIDS ทั่วไปที่ตรวจเฉพาะในระดับเครือข่าย

2. **การใช้ภาษาโปรแกรม 5 ภาษาตามจุดเด่น** — Zig สำหรับ performance, Rust สำหรับ memory safety, Python สำหรับ regex + library ecosystem, Go สำหรับ concurrency + visualization, C++ สำหรับ kernel driver development ทำให้แต่ละส่วนทำงานได้อย่างเหมาะสมที่สุด

3. **เอนจินตรวจจับ 3 ระดับ (3-Tier Engine)** — Tier 3 Rust pre-screen → Tier 1 Zig AC automaton → Tier 2 Python regex ช่วยลดภาระการประมวลผลและเพิ่มความแม่นยำในการตรวจจับ

4. **Unified EventHeader Model** — โครงสร้างข้อมูล 40 bytes ที่ใช้ร่วมกันระหว่าง Kernel Mode (C++) และ User Mode (Zig) ทำให้สามารถเพิ่ม source type ใหม่ได้ง่ายโดยไม่ต้องแก้ engine

5. **CLI Daemon Manager** — รองรับการทำงานแบบ background service พร้อมคำสั่ง start/stop/status/rules/health ทำให้ผู้ดูแลระบบสามารถควบคุมได้สะดวก
