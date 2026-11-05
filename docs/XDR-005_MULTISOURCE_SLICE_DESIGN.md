# XDR-005 Multi-Source Slice — Design & Patch Declaration

**Status:** DESIGN ONLY — เอกสารนี้ไม่มีการแก้โค้ด, build, ติดตั้ง, restart service หรือ push
**Prepared:** 2026-11-04
**Target HEAD:** `bb61f35` (build source commit `f7c626d`)
**Flow ID:** `IDS-XDR-005`
**Gap:** `IDS-XDR-005-WIRING-OPEN`
**Blocker:** `XDR-005-LIVE-MULTISOURCE-UNREACHABLE`

**Owner constraints ที่ต้องคงไว้ตลอด slice นี้**

- AEGIS เป็น detection-only: WFP observe-only, Rust PEP assessment-only,
  `prevention_gate=closed`, ไม่มี production host-effect path.
- XDR เป็น advisory evidence fabric: ห้ามไหลเข้า policy, PEP, DEFCON,
  ActionDispatcher, scoring หรือ host effect ใด ๆ
- ห้ามสร้าง detection identity ปลอมเพื่อให้ผ่าน gate
- หลักฐาน E5 ต้องมาจาก host จริง ไม่ใช่จาก mock หรือการแก้ JSON
- การ deploy/restart service ต้องประสาน UAC และขออนุมัติแยก
- ห้าม push จนกว่าจะได้รับอนุมัติแยก

---

## 1. ปัญหาที่ต้องปิด

ที่ current HEAD การ freeze ของ XDR ต้องมี `distinctSources() >= 2`
(`src/xdr/xdr_runtime.zig:173`) แต่ entity key ที่ live pipeline ใช้คือ
source IP ของ event (`src/pipeline/event_processor.zig:49-69, 412`)
และมีเพียง network sources (`capture_npcap`, `capture_wfp`) ที่เติม
`src_ip`; ทั้งสอง map ไป category เดียวกันคือ `network`
(`src/xdr/xdr_runtime.zig:72-81`)

ผลคือ:

- ETW / FIM / Registry / Minifilter ไม่เติม `src_ip` → entity ว่าง → ถูกทิ้ง
- Federation เป็น status-only ใน standalone daemon
- live incident ทุกตัวจึงมี `distinct_sources=1`
- `receipts_recorded` ยังเป็น 0 by construction

blocker นี้ถูกบันทึกพร้อมหลักฐาน file:line ใน
`admin-evidence/xdr-005-reachability-20261104/closeout.md` แล้ว

เป้าหมายของ slice นี้คือทำให้ **host-side observation จริง** จาก Windows
host ถูก fold เข้ากับ network evidence บน entity เดียวกันได้ โดยไม่เพิ่ม
authority และไม่สร้าง host effect

---

## 2. หลักฐานจาก current HEAD

| หลักฐาน | ตำแหน่ง |
|---|---|
| XDR feed gate | `src/pipeline/event_processor.zig:409-419` |
| Entity key = source IP, zero → empty | `src/pipeline/event_processor.zig:49-69` |
| Host source list | `src/pipeline/event_processor.zig:40-44` |
| Category map | `src/xdr/xdr_runtime.zig:72-81` |
| Freeze condition | `src/xdr/xdr_runtime.zig:173` |
| Incident limits | `src/xdr/xdr_incident_fabric.zig:70-72` |
| Dedup/fold semantics | `src/xdr/xdr_incident_fabric.zig:200-223` |
| Receipt route | `src/pipeline/event_processor.zig:130-160` |
| Snapshot encode/replay | `src/xdr/xdr_evidence_flow.zig:85-186` |
| No live replay surface | `forensics.replay` เป็น integrity-only (`src/control/handler_registry.zig:1524-1533`) |
| P2 gate pin | `tests/security/test_xdr_wire_advisory.py:54-82` |
| ETW live providers | `src/pipeline/telemetry_threads.zig:114-118` |
| ETW native decoding | `src/windows/etw_native.c:122-175, 256-269` |
| EventKind/Source ABI | `src/contract/event.zig:31-76, 103-149` |
| Canonical source mapping | `src/forensic/forensic_pipeline.zig:184-201`; `src/forensic/ids_evidence_receipt.zig:85-98` |

---

## 3. ข้อจำกัดที่ design ต้องผ่าน

1. **Entity ต้องตรงกัน** — host evidence ต้องใช้ key เดียวกับ network
   evidence คือ IP ของ peer ที่เป็น attacker ในทิศทาง inbound
2. **ต้องเป็น observation จริง** — ห้ามประกอบ `rule_id` ปลอม, ห้ามยัด
   host event เข้า feed ด้วยข้ออ้างว่าเป็น signature detection
3. **ห้ามสร้าง incident จาก host-only evidence** — ไม่เช่นนั้นตาราง
   `MAX_INCIDENTS=128` จะเต็มด้วย connection ของ browser/update
4. **ต้องรองรับลำดับสลับ** — host evidence อาจมาก่อนหรือมาหลัง network
   evidence ภายในหน้าต่างเวลาเดียวกัน
5. **ต้องมีขอบเขตหน่วยความจำ** — pending table, recent table, tracker
   ทุกตัวต้องมี cap และ TTL
6. **ต้องไม่แตะ 96-byte `IpcEvent` หรือ 109-byte canonical wire ABI**
   — เพิ่ม enum value แบบ additive เท่านั้น
7. **ต้องไม่เพิ่ม authority** — host-net adapter เป็นผู้สังเกต ไม่ใช่
   ผู้ตัดสินหรือผู้บังคับใช้
8. **ต้องพิสูจน์ replay ได้** — receipt ถูก discard by design จึงต้องมี
   read-only surface ที่ replay snapshot จาก forensic ring ได้

---

## 4. ทางเลือกที่ประเมิน

### 4.1 ETW Kernel-Network — ไม่เลือก

ข้อดี: ได้ connect/accept event พร้อม PID แบบ real-time และมี field
`local_ip`/`remote_ip` อยู่ใน `EtwEventRecord` แล้ว
(`src/windows/etw_realtime.zig:192-196`)

เหตุผลที่ไม่เลือก:

- `Microsoft-Windows-Kernel-Network` เป็น classic MOF provider;
  `wevtutil gp ... /ge:true` บน host นี้ไม่คืน template ให้ TDH decode
  (ตรวจเมื่อ 2026-11-04) ขณะที่ native helper ปัจจุบัน decode เฉพาะ
  TLV ที่มี magic `AEGT` (`src/windows/etw_realtime.zig:980-1003`)
- `etw_native.c` เปิด provider ด้วย `TRACE_LEVEL_VERBOSE` และ
  `MatchAnyKeyword=0` (`src/windows/etw_native.c:263-264`) ไม่มี
  per-provider keyword filter; การเพิ่ม network provider จะรับ
  send/recv ทุก packet-level event → ETW buffer/session loss risk
- ต้องแก้ C ABI ของ helper เพื่อส่ง keyword ต่อ provider และเพิ่ม
  fixed-layout decoder ที่ยังไม่ถูกพิสูจน์บน build นี้
- เป็นการเพิ่มความเสี่ยงสูงให้กับ slice ที่มีเป้าหมายเพียง proof
  ของ multi-source evidence

**สรุป:** เก็บเป็น future work; ไม่ใช้ใน slice นี้

### 4.2 TCP table polling (`GetExtendedTcpTable`) — เลือก

ข้อดี:

- เป็น Win32 API มาตรฐาน (`iphlpapi.dll`) ไม่ต้องมี driver, ไม่ต้องมี
  ETW session, ไม่ต้องแก้ C ABI
- คืนเฉพาะ established TCP connections พร้อม owning PID
- ปริมาณต่ำและควบคุมได้ด้วย poll interval + diff
- ให้หลักฐาน host จริง: "ณ เวลาที่ poll พบ established connection
  จาก peer IP นี้ไปยัง local endpoint นี้"
- ไม่มี packet storm และไม่กระทบ network capture path

ข้อเสียที่ยอมรับ:

- มองไม่เห็น connection ที่เกิดและจบระหว่าง poll (short-lived)
- เป็น state observation ไม่ใช่ "open event" จึงต้องตั้งชื่อ kind ให้ตรง
- ต้องเพิ่ม `iphlpapi` link (ไม่มี ABI change)

**สรุป:** เลือกทางนี้

### 4.3 Synthetic detector rule id — ไม่เลือก

การตั้ง `rule_id` ปลอมให้ host observation เพื่อให้ผ่าน
`detection_rule_id != 0` จะทำให้ forensic/receipt อ้างว่าเป็น
signature/anomaly detection ที่ไม่มีอยู่จริง ขัดกับ truthfulness และ
semantics ของ `MULTI_SOURCE_RULE_ID`

### 4.4 เรียก `xdr_runtime` ตรงจาก poller thread — ไม่เลือก

จะข้าม pipeline queue และ forensic recording, ทำให้ observation
ไม่ปรากฏใน event/forensic surface และแตก single-consumer model
ของ pipeline

---

## 5. สถาปัตยกรรมที่เสนอ

```
GetExtendedTcpTable (iphlpapi)
        │  established TCP rows (v4/v6)
        ▼
windows/host_net.zig
  parse rows → filter → tracker.diff() → new connections only
        │
        ▼
pipeline/telemetry_threads.hostNetThread
  build IpcEvent (source=capture_host_net, kind=host_socket_observed)
  ev.src_ip = remote peer (BE), ev.dst_ip = local
  pushEvent / pushEventWithAddrs
        │
        ▼
pipeline/event_queue  (source ordinal 6, host telemetry tail)
        │
        ▼
pipeline/event_processor
  host telemetry bypass: policy / tracking / PEP
  XDR admission: exact host-observation predicate
        │
        ▼
xdr_runtime
  recent-network table (TTL) + pending-host table (TTL)
  network arrives → join pending host on same entity
  host arrives after network → join immediately
        │
        ▼
xdr_incident_fabric  distinctSources >= 2 → freeze
        │
        ▼
xdr_evidence_flow.recordAssessment → forensic ring + IDS receipt
        │
        ▼
xdr.list (counters) + xdr.verify (read-only snapshot replay)
```

---

## 6. Host source specification

### 6.1 Module ใหม่

`src/windows/host_net.zig` รับผิดชอบเฉพาะ Win32 table + parsing +
tracker; ไม่มี policy/PEP/DEFCON/dispatch

```zig
pub const Family = enum { v4, v6 };

pub const Observed = struct {
    family: Family,
    local_addr: [16]u8,   // v4 อยู่ใน 4 byte แรก
    local_port: u16,      // host order
    remote_addr: [16]u8,
    remote_port: u16,     // host order
    owning_pid: u32,
};

pub const Tracker = struct {
    // fixed arrays, ไม่มี heap allocation ใน hot path
    prev: [MAX_TRACKED]Key,
    prev_count: usize,
    seeded: bool,
    pub fn diff(self: *Tracker, rows: []const Observed, out: []Observed) usize;
};
```

ค่าคงที่:

- `MAX_TRACKED = 1024`
- `MAX_EMIT_PER_POLL = 64` — ถ้ามี connection ใหม่เกิน cap ต่อ poll
  ส่วนที่เกินจะ **ไม่ถูกเพิ่มลง `prev`** จึงถูกตรวจพบใหม่ใน poll ถัดไป
  และนับ `emit_deferred` (ไม่มีการทิ้งแบบเงียบ)
- `POLL_MS = 2000` (override ด้วย `AEGIS_HOSTNET_POLL_MS`, clamp 500..4000
  เพื่อให้ beat ห่างไม่เกิน watchdog timeout 5s)
- `AEGIS_HOSTNET=0` = ปิด source นี้ (kill switch; default เปิด)

### 6.2 การอ่านตาราง

- v4: `GetExtendedTcpTable(..., AF_INET, TCP_TABLE_OWNER_PID_ALL)`
- v6: `GetExtendedTcpTable(..., AF_INET6, TCP_TABLE_OWNER_PID_ALL)`
- ตรวจ `dwNumEntries` แล้ว parse `MIB_TCPROW_OWNER_PID` /
  `MIB_TCP6ROW_OWNER_PID`
- เก็บเฉพาะ `MIB_TCP_STATE_ESTAB = 5`
- ข้าม loopback (`127.0.0.0/8`, `::1`) และ unspecified address
- buffer sizing: เรียกครั้งแรกด้วย null เพื่อเอา size, จัดสรร,
  เรียกซ้ำ; ถ้า `ERROR_INSUFFICIENT_BUFFER` อีกให้ retry แบบมี cap
  (สูงสุด 4 MiB) แล้วนับ `poll_errors`; `ERROR_NO_DATA` = 0 rows
- parse เป็น pure function แยก (`parseV4Table`, `parseV6Table`) เพื่อ
  unit-test ด้วย synthetic buffer โดยไม่ต้องพึ่ง API จริง

### 6.3 Byte-order rule (สำคัญ)

- `MIB_TCPROW_OWNER_PID.dwRemoteAddr` / `dwLocalAddr` เก็บ IPv4 เป็น
  4 byte ใน **network byte order** ภายในหน่วยความจำ
- ค่าที่ใช้เป็น entity ต้องเป็น numeric เดียวกับที่ nose ส่ง:
  `binary.BigEndian.Uint32(srcIP)` (`nose/capture.go:220-223`) ซึ่ง Zig
  อ่านกลับมาเป็นตัวเลขเดียวกัน (`src/contract/canonical_event.zig:601`)
  และ `xdrEntityKey` พิมพ์ MSB ก่อน (`src/pipeline/event_processor.zig:63-68`)
- ดังนั้นใน `toIpcEvent`:
  - v4: `ev.src_ip = std.mem.readInt(u32, observed.remote_addr[0..4], .big)`
    (หรือ `@byteSwap(row.dwRemoteAddr)` เทียบเท่า) — **อ่าน big-endian
    หนึ่งครั้ง** ไม่ใช่ปล่อยเป็น native u32 แล้วค่อย swap ซ้ำ
  - v6: copy 16 byte ตามเดิม (เป็น network order อยู่แล้ว) และส่งผ่าน
    `pushEventWithAddrs`
- ports: `dwRemotePort`/`dwLocalPort` เป็น network order ใน low 16 bits
  → `@byteSwap(@as(u16, @truncate(value)))` ก่อนใส่ `src_port`/`dst_port`
- unit test ต้อง pin ค่าตัวอย่าง `192.168.126.10` → numeric
  `0xC0A87E0A` และ entity string `v4:192.168.126.10`

### 6.4 Tracker semantics

- poll แรกสำเร็จ = **seed only**: เก็บ snapshot ลง `prev` แต่ **ไม่ emit**
  (ไม่กล่าวอ้างว่า connection ที่มีอยู่ก่อนถูกเปิดตอนนั้น)
- poll ถัดไป: emit เฉพาะ key ที่ไม่ปรากฏใน `prev`
- key = (family, local_addr, local_port, remote_addr, remote_port, pid)
- connection ที่หายไปถูกถอดออกจาก `prev`; ถ้ากลับมาอีกจะ emit ใหม่
  (เป็น observation ใหม่ ไม่ใช่การกล่าวอ้างว่าเป็น connection เดิม)
- ถ้าจำนวน row เกิน `MAX_TRACKED`: เก็บ subset แรก, นับ `overflow`,
  ไม่ emit ส่วนเกิน (ไม่ silent)

### 6.5 Event ที่สร้าง

```zig
var ev = event.IpcEvent.init(.host_socket_observed);
ev.source = .capture_host_net;
// Windows Zig 0.13: nanoTimestamp() = GetSystemTimeAsFileTime (epoch ns,
// 100 ns granularity) -> same epoch domain as nose UnixNano, so the
// evidence ts_ms of host and network rows stay comparable. TTLs do NOT
// use this value (see 7.2.1).
ev.timestamp_ns = @intCast(std.time.nanoTimestamp());
ev.event_id = diag.metrics.events_emitted.next();
ev.src_ip = std.mem.readInt(u32, observed.remote_addr[0..4], .big); // peer = XDR entity
ev.dst_ip = std.mem.readInt(u32, observed.local_addr[0..4], .big);
ev.src_port = remote_port;       // host order
ev.dst_port = local_port;        // host order
ev.protocol = 6;
ev.rule_id = 0;                  // observation ไม่ใช่ detection
ev.severity = .info;
```

Payload เป็นข้อความสั้นเพื่อ forensic readability เท่านั้น:

```
hostnet tcp 192.168.126.10:49812 -> 192.168.126.1:445 pid=1234
```

> `GetExtendedTcpTable` เห็นเฉพาะ TCP endpoint ที่เป็นของเครื่องที่รัน
> daemon (NIDS host `.1`) เท่านั้น; traffic VM-to-VM บน VMnet1
> (Kali `.10` → victim VM `.20`) ไม่ปรากฏใน TCP table ของ `.1`
> แม้ Npcap จะ capture ได้ก็ตาม. E5 จึงต้องยิง canary ไปที่ `.1`
> (ดูหัวข้อ 11) ไม่ใช่ `.20`.

- v6 ใช้ `pushEventWithAddrs(ev, payload, remote6, local6)`
- v4 ใช้ `pushEvent(ev, payload)`
- **ห้ามให้ AC matcher กวาด payload นี้**: เพิ่ม guard
  `ev.source != .capture_host_net` ใน AC block
  (`src/pipeline/event_processor.zig:248-267`) เพราะ payload นี้ไม่ใช่
  packet bytes; ไม่แตะพฤติกรรม AC ของ ETW/FIM/Registry เดิม
- **ไม่ assign flow id** สำหรับ source นี้:
  `assignFlowId` ถูกเรียกเฉพาะเมื่อ `ev.source != .capture_host_net`
  เพื่อไม่สร้าง phantom flow จาก state observation
  (ผลคือ `flow_id=0` และ receipt ของ host-triggered freeze จะมี
  `flow_id=0` ซึ่ง `Receipt.validate()` ยอมรับ)

### 6.6 Thread integration

- `telemetry_threads.hostNetThread()` วน poll ตาม interval
- **beat watchdog ทุก loop แม้ poll ล้มเหลว** (นับ `poll_errors` แล้วไปต่อ)
  เพื่อไม่ให้ source ที่เป็น advisory ทำให้ watchdog restart daemon
- daemon spawn หลัง registry thread, join ใน `RuntimeSupervisor.shutdown`
- `state.g_wd_hostnet_slot` + `registerThread(.host_telemetry, "hostnet")`
- ถ้า `AEGIS_HOSTNET=0` → ไม่ spawn thread; `queue.stats.host_net`
  รายงาน `enabled=false, ready=false`
- **ไม่เพิ่ม subsystem ใน `status`** (คง 7 subsystems) และ
  **ไม่ใส่ใน readiness barrier** เพราะเป็น advisory source; ถ้า poll
  ล้มเหลวต้องไม่ทำให้ daemon startup ค้างหรือ degrade ทั้งระบบ
- สุขภาพของ source ดูได้จาก `queue.stats.host_net` และ
  `xdr.list.host_net`

---

## 7. XDR admission และ pending join

### 7.1 Admission predicate (แคบและตรวจสอบได้)

```zig
fn isXdrHostSocketObservation(ev: *const event.IpcEvent, src6: ?[16]u8) bool {
    return ev.source == .capture_host_net and
        ev.kind == .host_socket_observed and
        ev.rule_id == 0 and
        (ev.src_ip != 0 or src6 != null);
}
```

Feed site เปลี่ยนจาก:

```zig
if (detection_rule_id != 0) { ... observeEvent(...) }
```

เป็น:

```zig
const host_obs = isXdrHostSocketObservation(ev, qe.src_ipv6);
if (detection_rule_id != 0 or host_obs) {
    ...
    if (host_obs and detection_rule_id == 0) {
        _ = xdr_runtime.observeHostObservation(&out, entity, sev, ev);
    } else {
        _ = xdr_runtime.observeEvent(&out, cat, entity, sev, ev);
    }
    _ = recordXdrAdvisoryReceipt(ring, &out, ev);
}
```

เหตุผลที่ต้องมี branch นี้แทนการปลอม `rule_id`:

- `rule_id != 0` มีความหมายว่า "มี detection identity" ใน forensic,
  receipt และ SIEM; host observation ไม่มีคุณสมบัตินั้น
- predicate ถูก pin ด้วย test ว่าเป็น tuple เดียวเท่านั้น และ
  ไม่มี non-detection ชนิดอื่นถูก admit

### 7.2 Pending-host table

`src/xdr/xdr_runtime.zig` เพิ่ม (ภายใต้ `g_mutex` เดิม):

- `recent_network: [64]RecentNetwork` — entity + last_seen_ms
  ของ network evidence ที่ admit แล้ว (เต็ม → evict oldest,
  `recent_evicted++`)
- `pending_host: [32]PendingHost` — entity + Evidence row + added_ms
- `HOST_TTL_MS = 120_000`, `RECENT_TTL_MS = 120_000`
- linear scan ภายใต้ mutex; ไม่มี allocation

#### 7.2.1 TTL clock (ตัดสินแล้ว: monotonic elapsed)

TTL ของ `recent_network` / `pending_host` **ห้ามคำนวณจาก
`source_event.timestamp_ns`** เพราะ:

- เป็น wall clock (`GetSystemTimeAsFileTime` / `UnixNano`) ซึ่งกระโดดได้
  เมื่อ NTP adjust; TTL 120 s จะสั้น/ยาวผิดโดยไม่มีการบอก
- transport ต่างๆ อาจให้ความละเอียด/ที่มาไม่เหมือนกัน (nose epoch ns,
  ETW 100 ns, synthetic tests) การเทียบข้าม source จึงไม่น่าเชื่อถือ

กติกา:

- `startLive()` เก็บ `g_clock_origin: std.time.Instant` (QPC บน Windows)
  ไว้ครั้งเดียว **ภายใต้ `g_mutex`**; `fabricNowMsLocked()` =
  `now.since(origin) / ns_per_ms` เรียกขณะถือ mutex (origin ไม่เป็น
  data race กับ `startLive()`)
- ถ้า `Instant.now()` ใช้ไม่ได้ หรือ `now < origin` → ใช้
  `std.time.milliTimestamp()` และรายงาน `clock:"wall"` ใน
  `xdr.list.host_net` (honest degradation)
- `added_ms`, `last_seen_ms` ใน pending/recent เป็น **fabric-relative
  elapsed ms** ใช้เพื่อ TTL เท่านั้น; ห้ามส่งออกเป็น evidence timestamp
- `Evidence.ts_ms` และ decision `made_ms` ยังคงมาจาก `timestamp_ns`
  ของ event ตามเดิม (ไม่แตะ snapshot/replay semantics ของ PATCH B)
- `startLive()` ใหม่ = origin ใหม่ + ตารางว่าง (behavior เดิมของ restart)
- เพื่อให้ E2 ทดสอบ TTL ได้โดยไม่พึ่งนาฬิกาจริง:
  `observeEventAt(..., now_ms)` และ `observeHostObservationAt(..., now_ms)`
  เป็น seam ที่รับ clock ชัดเจน; public wrapper เรียกด้วย `fabricNowMs()`

`observeHostObservation()`:

1. validate `event_id != 0`, `entity.len in 1..64`
2. sweep pending ที่หมดอายุ → `host_expired++`
3. ถ้า `recent_network` มี entity นี้และยังไม่หมด TTL:
   - fold host evidence เข้า fabric
   - `host_joined++`, `evidence_total++`
   - ตรวจ freeze (distinctSources >= 2)
4. ถ้าไม่มี:
   - เก็บลง `pending_host` (แทนที่ row เดิมของ entity เดียวกัน)
   - ถ้าเต็ม ให้ evict รายการที่เก่าที่สุด → `host_evicted++`
   - `host_deferred++`
   - **ไม่สร้าง incident**

`observeEvent()` (network/detection path) เพิ่ม:

1. หลัง ingest สำเร็จและ category เป็น `.network`
   → อัปเดต `recent_network[entity]`
2. ถ้ามี `pending_host[entity]` → fold host row **ก่อน** ตรวจ freeze
   แล้วลบ pending
3. ตรวจ freeze ครั้งเดียวหลัง fold ทั้งหมด

หมายเหตุ: host detection ที่มี `rule_id != 0` (IDS-HOST-004) ยังใช้
`observeEvent` ตามเดิมและอาจสร้าง incident ของตัวเองได้; กติกา
"host-only ไม่สร้าง incident" ในที่นี้หมายถึงเฉพาะ host_net
observation ที่ผ่าน `observeHostObservation` (rule_id = 0)

ตารางกรณี:

| ลำดับ | ผล |
|---|---|
| network → host (ภายใน TTL) | freeze ทันที, rows=2 |
| host → network (ภายใน TTL) | network fold แล้วตามด้วย pending host, freeze, rows=2 |
| host → ไม่มี network ภายใน TTL | pending หมดอายุ, ไม่มี incident, `host_expired++` |
| host-only หลายตัว | ไม่มี incident ใด ๆ, pending cap 32 |
| network ซ้ำหลายตัว | incident เดิม, refresh TTL |
| host ซ้ำ entity เดิม | แทน pending row เดิม (ไม่โต) |

### 7.3 Counter ที่เพิ่ม (additive JSON)

`xdr.list`:

```json
"host_net": {
  "clock": "monotonic",
  "offered": 0,
  "pending": 0,
  "joined": 0,
  "expired": 0,
  "evicted": 0,
  "recent_evicted": 0
}
```

per incident เพิ่ม:

```json
"source_categories": ["network", "host"]
```

(สร้างจาก `SourceCategory` + `hasSource`; ไม่มี action/enforce field)

`queue.stats` เพิ่ม block จาก host_net module:

```json
"host_net": {
  "enabled": true,
  "ready": true,
  "seeded": false,
  "polls": 0,
  "poll_errors": 0,
  "rows_seen": 0,
  "tracked": 0,
  "emitted": 0,
  "emit_deferred": 0,
  "overflow": 0,
  "last_poll_ms": 0
}
```

`by_source` จะมี `capture_host_net` อัตโนมัติเมื่อมี push/drop เพราะ
`legacySourceName` รู้จัก ordinal 6

---

## 8. PATCH A — Source slice (host socket telemetry + XDR join)

```
PATCH-ID: XDR-005-A
FLOW-ID: IDS-XDR-005
TARGET HEAD: bb61f35 (build source f7c626d)
```

### Target files

| ไฟล์ | การเปลี่ยนแปลง |
|---|---|
| `src/windows/host_net.zig` | **ใหม่**: Win32 table parser, tracker, counters |
| `src/tests/windows/host_net.zig` | **ใหม่**: parser/tracker/byte-order tests |
| `src/pipeline/telemetry_threads.zig` | `hostNetThread`, emission, watchdog beat |
| `src/pipeline/runtime_state.zig` | `g_wd_hostnet_slot` |
| `src/daemon.zig` | supervisor field, register watchdog, spawn/join |
| `src/contract/event.zig` | `host_socket_observed=78`, `capture_host_net=6`, name map |
| `src/pipeline/event_processor.zig` | predicate, admission branch, host source list, AC/flow guards |
| `src/xdr/xdr_runtime.zig` | pending/recent tables, `observeHostObservation`, counters, `listJson` |
| `src/forensic/forensic_pipeline.zig` | canonical mapping `.capture_host_net => .host_telemetry` |
| `src/forensic/ids_evidence_receipt.zig` | mapping เดียวกัน |
| `src/control/handler_registry.zig` | `queue.stats.host_net` block |
| `src/all_tests.zig` | import test file |
| `build.zig` | **ไม่เปลี่ยน** — ดู ABI impact (DynLib แทน import lib) |
| `tests/security/test_xdr_wire_advisory.py` | P2 contract update + host-net pins |
| `docs/...`, maps | ตามหัวข้อ 15 |

### Target symbols

`host_net.poll`, `host_net.parseV4Table`, `host_net.parseV6Table`,
`host_net.Tracker.diff`, `telemetry.hostNetThread`,
`event.EventKind.host_socket_observed`, `event.EventSource.capture_host_net`,
`event.legacySourceName`, `event_processor.isXdrHostSocketObservation`,
`event_processor.processEvent`, `xdr_runtime.observeHostObservation`,
`xdr_runtime.observeHostObservationAt`, `xdr_runtime.observeEventAt`,
`xdr_runtime.fabricNowMsLocked`, `xdr_runtime.listJson`, `host_net` counters

### In-scope / out-of-scope

**In-scope**

- v4 + v6 established TCP observation
- seed/diff/dedup, bounded tracker
- XDR host admission + pending join
- additive counters/JSON
- E2 tests และ E5 canary plan
- docs/maps/evidence index

**Out-of-scope**

- ETW Kernel-Network
- เปลี่ยน entity key ของ network evidence
- outbound C2 join semantics
- receipt persistence / snapshot v2
- `xdr.verify` (อยู่ PATCH B)
- policy/PEP/DEFCON/action ใด ๆ

### Contract impact

- `EventKind` +1 ค่า (78) — additive, ค่าเดิมไม่เปลี่ยน
- `EventSource` +1 ค่า (6) — additive, ค่าเดิมไม่เปลี่ยน
- `legacySourceName(6) = "capture_host_net"`
- canonical mapping ไป `.host_telemetry` (ไม่เพิ่ม canonical enum)
- forensic record ใช้ canonical source space: `.capture_host_net`
  ถูก canonicalize เป็น `.host_telemetry` ใน header (เหมือน host
  telemetry อื่น) จึงแยก host_net จาก ETW ใน forensic record ไม่ได้;
  ให้ใช้ `queue.stats.by_source.capture_host_net` และ
  `xdr.list.source_categories` เป็นหลักฐานระบุ source
- `xdr.list` / `queue.stats` JSON additive
- P2 security pin เปลี่ยนจาก literal gate เป็น semantic gate + exact tuple

### ABI impact

- ไม่แตะ `IpcEvent` 96 bytes หรือ canonical 109 bytes
- ไม่แตะ C ABI (`aegis_etw_helper`, FIM helper, PEP)
- ไม่เพิ่ม system library link: Zig 0.13 ไม่มี x86_64 import lib ของ
  `iphlpapi` (มีแต่ `.def`), จึง resolve `GetExtendedTcpTable` ด้วย
  `std.DynLib.open("iphlpapi.dll")` แล้ว `lookup`; ถ้าโหลดไม่ได้
  `queue.stats.host_net.poll_errors` จะเพิ่มขึ้นและ watchdog ยังเต้น
  (ไม่ทำให้ daemon restart)

### Authority impact

- เพิ่ม observe-only host telemetry adapter ใน Zig
  (`src/windows/host_net.zig`) — Zig  owns runtime/host telemetry อยู่แล้ว
  ตาม precedent `registry_monitor.zig`
- ไม่มีการโอน authority ไป policy/PEP/enforcement
- `AUTHORITY_MAP` ต้องระบุว่า adapter นี้เป็น evidence-only

### State impact

- in-memory bounded tables: 64 recent + 32 pending
- tracker 1024 keys
- ไม่มี persistent state ใหม่
- forensic ring: host observation ถูกเขียนเป็น record ปกติ (ทุก event
  ถูกเขียนอยู่แล้ว); อัตราต่ำเพราะ emit เฉพาะ connection ใหม่

### Test impact

- unit tests ใหม่ใน `host_net` / `xdr_runtime` / `event_processor`
- P2 pin update
- contract tests ยังต้องผ่าน
- ไม่มี test ใดเขียนทับ tracked artifacts

### Evidence impact

- E2: unit + security pins
- E5: canary ใหม่ (หัวข้อ 11) ปิด `IDS-XDR-005-WIRING-OPEN`
- `EVIDENCE_INDEX.json`: evidence entry ใหม่, ปิด blocker
  `XDR-005-LIVE-MULTISOURCE-UNREACHABLE`, อัปเดต `E5_count`

---

## 9. PATCH B — Read-only replay verification surface

เหตุผล: `replayFromReceipt` มีอยู่ แต่ไม่มี live/control surface เรียก
(`src/xdr/xdr_evidence_flow.zig:135-186`; `forensics.replay` เป็น
integrity-only และ `events_replayed=0`) และ receipt ถูก discard by design
จึงต้องมี surface ที่ replay **snapshot ที่ persisted แล้ว** ได้

```
PATCH-ID: XDR-005-B
FLOW-ID: IDS-XDR-005
TARGET HEAD: <HEAD หลัง PATCH A>
```

### Target files

| ไฟล์ | การเปลี่ยนแปลง |
|---|---|
| `src/xdr/xdr_evidence_flow.zig` | `replayRecord(slot)` + shared replay helper |
| `src/control/protocol.zig` | `xdr_verify = 511`, name map, contract READ/no-mutation |
| `src/control/handler_registry.zig` | register + `xdrVerify` |
| `tools/aegisctl.py` | `aegisctl xdr list/verify` |
| `shared/protocol/control_protocol.md` | table row `xdr.verify` |
| `tests/security/test_xdr_wire_advisory.py` | pin `xdr.verify` read-only |
| `tests/...` | handler/replay tests |
| docs/maps | contract map, CLI docs, evidence index |

### `replayRecord` semantics

- verify CRC + hash chain ของ slot
- header ต้องเป็น `correlation_match`, `rule_id = MULTI_SOURCE_RULE_ID`,
  `policy_id = 0`, `pep_decision = 0`
- decode snapshot (magic/version)
- rebuild fabric, ตรวจ single incident / unique evidence /
  source event อยู่ใน evidence
- คำนวณ decision ใหม่แล้วเทียบกับ snapshot (severity/confidence/
  categories/made_ms)
- คืน `forensic_sequence`, `incident_id`, `source_event_id`, decision
- **ไม่ re-execute detection/policy/PEP** และไม่เขียน ring

ข้อจำกัดที่ต้องเขียนในเอกสาร: receipt token ไม่ถูก persist ดังนั้น
post-hoc verification พิสูจน์ว่า "snapshot record นี้ replay ได้และ
ตรงกับ decision ที่บันทึก" ไม่ใช่ "receipt token นี้เคยออกจริง";
การออก receipt ถูกพิสูจน์ด้วย `receipts_recorded/failed` จาก live run

### `xdr.verify` handler

- role `read`, `is_mutation=false`, `has_postcondition=false`
- ถ้า ring ไม่มี → `{"available":false,...}` (ไม่ throw)
- สแกนจาก newest → oldest, จำกัด `limit` (default 8, max 64)
- prefilter header kind/rule ก่อนเรียก `replayRecord`
- JSON ต่อ record: `sequence`, `incident_id`, `source_event_id`,
  `source_categories`, `severity`, `confidence`, `verified`, `error`
- top-level: `available`, `ring_records`, `scanned`, `xdr_records`,
  `verified`, `failed`, `note` (อธิบายข้อจำกัด receipt)

---

## 10. Test matrix (E2)

| Test | สิ่งที่พิสูจน์ |
|---|---|
| `host_net.parseV4Table` synthetic | offsets/ports/address BE |
| `host_net.parseV6Table` synthetic | 16-byte addr + ports |
| `Tracker` seed | poll แรกไม่ emit |
| `Tracker.diff` | emit เฉพาะใหม่, หายแล้วกลับมา emit ใหม่ |
| `Tracker` overflow | cap 1024 + counter |
| `Tracker` emit cap | `emit_deferred` และ key ถูกตรวจพบใหม่ poll ถัดไป |
| `Tracker` clock independence | diff ไม่ขึ้นกับ wall clock |
| `toIpcEvent` | source/kind/severity/rule_id/ports/addresses |
| `isXdrHostSocketObservation` | รับเฉพาะ tuple ที่กำหนด และ `rule_id == 0` |
| `event_processor` feed | host obs เข้า XDR; host event อื่นไม่เข้า |
| `xdr_runtime` host-only | ไม่สร้าง incident, pending++ |
| `xdr_runtime` host→network | freeze, rows=2, joined |
| `xdr_runtime` network→host | freeze, rows=2 |
| `xdr_runtime` TTL (explicit `now_ms`) | expired, ไม่มี incident; ไม่ขึ้นกับ event ts |
| `xdr_runtime` pending cap | evict oldest, bounded |
| `xdr_runtime` recent cap | evict oldest, `recent_evicted++`, bounded |
| `xdr_runtime` listJson | host counters + `clock` + source_categories, ไม่มี action/enforce |
| `xdr_evidence_flow.replayRecord` | record ดี replay ผ่าน |
| `replayRecord` corruption | CRC/hash/snapshot mismatch → error |
| security P2 | gate = detection หรือ exact host tuple เท่านั้น |
| security P8 | `host_net.zig` ไม่ import policy/PEP/defcon/dispatch |
| security P3/P9 | `xdr.verify` read-only/non-mutation |
| control contract | `xdr.verify` ตรงกับ protocol.zig |
| queue stats | `host_net` block + `capture_host_net` bucket |

คำสั่ง:
```powershell
zig build test
python -m pytest tests/security/test_xdr_wire_advisory.py tests/security/test_control_contract.py -q
python -m pytest tests/contracts -q
```

---

## 11. E5 canary plan (หลัง PATCH A+B)

### 11.1 เตรียม

1. Build + unit/security tests ผ่าน
2. Deploy ด้วยขั้นตอนเดิม (UAC coordination; ห้าม restart โดยไม่แจ้ง)
3. ตั้ง daemon pin `\Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}`
   (VMnet1) ตาม RB-021
4. Restart daemon ให้ fabric ว่าง; เก็บ baseline:
   - `aegisctl xdr list --json` → ต้องไม่มี incident ของ
     `192.168.126.10`, `receipts_recorded=0`
   - `aegisctl queue stats --json` → `host_net.ready=true`
   - รอจน `host_net.seeded=true` (poll แรกสำเร็จ = seed แล้ว)
     ก่อนเปิด connection จาก Kali; ถ้า connect ก่อน seed
     connection นั้นจะถูกนับเป็น baseline และไม่ emit

> **ทำไม target คือ `.1` ไม่ใช่ `.20`:** `GetExtendedTcpTable` อ่าน TCP
> endpoint ของเครื่องที่รัน daemon เท่านั้น. Kali → Win11 VM `.20`
> เป็น traffic ที่ผ่าน virtual switch; TCP stack ของ NIDS host `.1`
> ไม่มี connection นั้น จึงไม่มี host observation ให้ join. E5 ของ
> slice นี้จึงยิงไปที่ NIDS host `.1` ซึ่งเป็น endpoint จริงของ
> host source. Npcap บน VMnet1 ยัง capture การยิงไป `.1` ได้เหมือนเดิม
> (RB-021 L4 proof ก่อนหน้าก็ยิง target `.1`).

### 11.2 Negative control (พิสูจน์ว่า host-only ไม่สร้าง incident)

บน Kali:

```bash
python3 - <<'PY'
import socket, time
s = socket.create_connection(("192.168.126.1", 445), timeout=5)
print("held", s.getsockname())
time.sleep(180)
PY
```

รอ ≥ 2 poll intervals แล้วเก็บ:
- `xdr.list.host_net.pending >= 1`
- ไม่มี incident ของ `v4:192.168.126.10`
- `receipts_recorded == 0`

ถ้าเงื่อนไขนี้ไม่ผ่าน = **หยุด** (join logic ผิดหรือ source ไม่ทำงาน)

### 11.3 Positive canary

ยิง targeted canary จาก Kali ไปที่ **NIDS host `.1`** (ไม่ใช่ `.20`):

- R9064: ส่ง literal `;whoami` ผ่าน TCP ไปที่ `192.168.126.1:445`
  (หรือ port ที่ rule จับ payload ได้) เพื่อให้ network detection มี
  entity `.10` เดียวกับ host observation
- R9002 (เสริม): ICMP rate canary ไปที่ `.1` ตาม runbook เดิม
  (target-independent; ไม่สร้าง TCP host observation แต่ join ด้วย
  entity เดียวกันได้)

**ข้อกำหนดด้านเวลา:** ต้องเริ่ม positive canary ภายใน 90 วินาทีหลัง
ยืนยัน `pending >= 1` เพราะ pending TTL 120 วินาทีเริ่มนับจาก
host observation ครั้งแรก (ไม่ได้ refresh ระหว่างที่ connection ค้าง).
หาก canary ใช้เวลานานกว่า ให้คง connection ไว้แล้วยืนยัน
`pending >= 1` ใหม่ก่อนเริ่มรอบถัดไป; script ที่ hold 180 วินาที
มีไว้เพื่อให้ connection ไม่หลุดระหว่าง canary เท่านั้น

### 11.4 เกณฑ์ผ่าน

- `xdr.list` มี incident `v4:192.168.126.10`
  - `distinct_sources = 2`
  - `source_categories` มี `network` และ `host`
  - `advisories_total >= 1`
  - `receipts_recorded >= 1`, `receipts_failed == 0`
- `aegisctl xdr verify --json`
  - `verified >= 1`, `failed == 0`
  - `sequence`/`incident_id` ตรงกับ `xdr.list`
- `aegisctl forensics verify` → `integrity:ok`
- `aegisctl events count --src-ip 192.168.126.10` ≥ baseline
- `blocks == 0`, `tier3_enforcing == false`, gate closed
- ไม่มี host effect ใด ๆ; `enforcement_status=observed`

### 11.5 Restore

- ปิด Kali connection
- คืน service env/pin ตาม RB-021
- ตรวจ packet flow กลับมา (packets เพิ่มในช่วง 12 วินาที)
- เก็บ evidence ทั้งหมดใน
  `admin-evidence/xdr-005-multisource-20261104/`
  (JSON ดิบ, timestamps, hashes, closeout.md)

---

## 12. Rollback

- ปิด source ด้วย `AEGIS_HOSTNET=0` + restart (ไม่ต้อง redeploy)
- ถ้าต้อง rollback binary: คืน `aegis_nids.exe` hash
  `D34D350A...763439` ตาม E5-DEPLOY-F7C626D
- `xdr.verify` เป็น read-only จึง rollback ได้โดยไม่กระทบ state
- ไม่มี schema/persistent migration ที่ต้องย้อน

---

## 13. ความเสี่ยงและข้อจำกัดที่ต้องยอมรับ

1. **Outbound join ไม่ครอบคลุม**: entity ของ network evidence คือ
   source IP; ถ้า detection เป็น outbound (victim → C2) entity จะเป็น
   victim ไม่ใช่ C2 จึงไม่ join กับ host peer ที่เป็น C2
   — slice นี้พิสูจน์ inbound join เท่านั้น
2. **Short-lived connections อาจถูกมองข้าม** ตาม poll interval
3. **Local process สามารถสร้าง connection ไปยัง peer ใดก็ได้** เพื่อ
   ทำให้เกิด host-side corroboration; XDR เป็น advisory ไม่ enforce
   จึงไม่ถือเป็นหลักฐานการโจมตีโดยลำพัง
4. **Receipt token ไม่ถูก persist**; `xdr.verify` พิสูจน์ snapshot
   replay ไม่ใช่ receipt token ย้อนหลัง
5. **Forensic ring รับ record เพิ่ม** จาก host observations;
   อัตราต่ำแต่ต้องติดตาม retention ใน E5
6. **ETW network ยังไม่ถูกเปิด**; ถ้าต้องการ process-level network
   attribution ในอนาคตต้องมี slice แยกพร้อม native ABI/keyword filter
7. **TTL เป็น monotonic elapsed ไม่ใช่ event time**: ถ้า daemon suspend
   (sleep/hibernate) QPC ยังเดินต่อ therefore pending อาจหมดอายุระหว่าง
   suspend; เป็นพฤติกรรมที่ยอมรับได้เพราะเป็น advisory join window
   และไม่มีการอ้างว่า incident เกิดขึ้นตอน suspend
8. **Host TCP table เห็นเฉพาะ endpoint ของเครื่องที่รัน daemon**:
   VM-to-VM traffic บน VMnet1 (Kali `.10` → victim VM `.20`) ถูก
   Npcap capture ได้ แต่ไม่อยู่ใน TCP table ของ NIDS host `.1` จึงไม่มี
   host observation สำหรับ flow นั้น. การ join ฝั่ง host ใน slice นี้
   ครอบคลุมเฉพาะ traffic ที่มีปลายทาง/ต้นทางเป็น NIDS host เอง;
   ถ้าต้องการ host evidence จากภายใน VM ต้องติดตั้ง agent ใน VM
   (out of scope).

---

## 14. Completion gate

`IDS-XDR-005-WIRING-OPEN` ปิดได้เมื่อ:

- [ ] PATCH A ผ่าน E2 ทั้งหมด และ worktree สะอาด
- [ ] PATCH B ผ่าน E2 และ `xdr.verify` read-only pin
- [ ] build/deploy current source พร้อม UAC coordination
- [ ] E5 canary ผ่านทั้ง negative control และ positive canary
- [ ] `receipts_recorded >= 1`, `receipts_failed == 0`, `xdr.verify` ผ่าน
- [ ] `forensics verify` integrity ok, `blocks=0`, gate closed
- [ ] restore ผ่าน (pin/env/packet flow)
- [ ] truth maps rebaseline + `python tools/truth.py verify` = TRUTH_VALID
- [ ] `python tools/release_engineering.py --verify` ผ่าน
- [ ] evidence index + closeout + docs อัปเดต
- [ ] ไม่มี push จนได้รับอนุมัติ

---

## 15. Truth rebaseline หลัง patch

ลำดับสำคัญ: `truth.py verify` บังคับว่า source/build worktree สะอาด
และ build source commit ต้องเป็น ancestor ของ HEAD ดังนั้นต้อง
**commit การเปลี่ยนแปลง source/build ก่อน** แล้วจึง rebaseline

1. commit PATCH (source/build: `src`, `build.zig`, `shared`) หลัง test ผ่าน
2. บันทึก final HEAD และ build source commit ใหม่
3. `python tools/rebuild_truth.py` (regenerate + stamp build source commit;
   ครอบ `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`,
   `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `inventory.json`,
   `reference_map.json`, `runtime_manifest.json`)
4. `python tools/truth.py verify` ต้องเป็น `TRUTH_VALID`
5. `python tools/release_engineering.py --verify` ต้องผ่าน
6. อัปเดต `AI_CONTEXT.md`, `docs/ai-context/10-current-phase.md`,
   `docs/runbooks/RB-021-hostonly-lab-proof.md`
7. ระบุ gap ที่ปิดและ blocker ที่เหลือ
8. หมายเหตุ: `tests/`, `docs/`, `admin-evidence/` เป็น records-only
   ไม่ทำให้ build source commit เปลี่ยน

---

## 16. สิ่งที่ต้องอนุมัติก่อนลงมือ

1. **เลือก TCP table polling** เป็น host source (แทน ETW Kernel-Network)
2. **default-on + `AEGIS_HOSTNET=0` kill switch** หรือต้องการ opt-in
3. **poll interval 2s** และ pending/recent TTL 120s โดยใช้ monotonic
   elapsed clock (`std.time.Instant`) ไม่ใช่ event timestamp
4. **`xdr.verify` เป็น READ command** (ไม่ใช่ OPERATE)
5. ลำดับ patch A → B และการขอ UAC/deploy window

หากอนุมัติแล้ว ขั้นถัดไปคือเปิด PATCH A แบบ patch transaction เดียว
พร้อม test/evidence ตาม AGENTS.md (ยังไม่ push)
