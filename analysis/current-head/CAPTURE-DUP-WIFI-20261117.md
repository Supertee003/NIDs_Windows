# CAPTURE-DUP-WIFI-20261117 — duplication วัดใหม่ที่ระดับ bytes: ไม่ reproduce, ตัวเลขเดิมเป็น metric artifact

**วันที่:** 2026-11-17 (window 09:34–09:52 UTC / 16:34–16:52 local)
**Base HEAD:** `aade7a3` (records), build source `7c604d5`
**Gap:** `CAPTURE-DUP-WIFI-001` (E5, เดิม OPEN)
**Patch record:** `PATCH-ID CAPTURE-DUP-BYTE-CLOSE-20261117` / `FLOW-ID DATA-001`

---

## 1. ข้อสรุป (อ่านบรรทัดนี้ก่อน)

1. **ตัววัดเดิมของ gap นี้ผิด** — `g3_dup_ratio.py` ใช้ key
   `(ip.src, ip.dst, ip.id, tcp.seq|udp.length, frame.len)` ซึ่ง **นับ TCP Dup ACK
   เป็น duplicate** (Dup ACK มี Seq/Ack/Len=0 ซ้ำกันโดยธรรมชาติ และไม่มี payload)
   → ตัวเลข "adjacent duplicate pairs" ของวันนี้ (11/89, 1/113) **ไม่ใช่ frame ซ้ำ**
2. **วัดใหม่ที่ระดับ raw bytes** (length + sha256 เท่ากันภายใน 2 ms):
   - pcap ประวัติศาสตร์ `wifi-dup-45007.pcapng` (02:39) → **5/5 ของ frame ที่ host
     ส่งออก duplicated จริง** (3.1–12.6 µs) — ยืนยันว่าเหตุการณ์เดิมมีจริง
   - capture ทั้งหมดของวันนี้ **0 duplicate ใน 29,060 frame** (19 captures)
3. **`Dot11Support=0` ไม่ใช่สาเหตุและไม่ใช่ยาแก้** — A/B แล้วทั้งสองค่าได้ 0 ทั้งคู่
   (และ 09:34 capture ก่อนแก้ config ใด ๆ ก็ 0 อยู่แล้ว)
4. **พบวิธี reload Npcap โดยไม่ต้อง reboot** — หยุด `AegisNids` + ปิด `aegis-nose`
   แล้ว `sc stop/start npcap` สำเร็จ (`STOPPED` → `RUNNING`, devices 13)
   คำเตือน "reboot required" ในสคริปต์เดิม **ไม่จริง** เมื่อ handle ถูกปลดก่อน
5. **path ของ product ไม่ได้ทำซ้ำ** — nose: `packets=26300 canonical=26300 dropped=0`
   (1 event ต่อ 1 frame) และ adapter VMnet1 ไม่มี duplicate
6. **สรุปสถานะ:** gap นี้ถูกปิดแบบ *not reproducible / no product defect* พร้อม
   เงื่อนไข reopen ที่วัดได้ (§8) — ไม่ได้อ้างว่าพบ root cause ของเหตุการณ์ 02:39

---

## 2. ทำไมตัวเลขเดิมเชื่อไม่ได้

`g3_dup_ratio.py` (kit v3) นับคู่ที่ field ตรงกันทั้งหมดภายใน 2 ms แต่ field ชุดนั้น
ไม่ระบุตัว frame จริง:

```text
ip.src, ip.dst, ip.id, tcp.seq|udp.length, frame.len
```

TCP Dup ACK คือ segment ที่ **ตั้งใจ** ส่งซ้ำด้วย Seq/Ack เดิม, Len=0 ไม่มี payload
→ ตรง key ทุกช่อง และมาห่างกัน < 1 ms จึงถูกนับเป็น "duplicate"

พิสูจน์ด้วย `tshark` บน capture เดียวกัน (T3 ของวันนี้): คู่ที่ถูกนับติดป้าย
`[TCP Dup ACK 143#1]`, `#2`, ... และมี `ip.src`/`ip.dst` ว่าง (เป็น IPv6) —
ไม่ใช่ frame เดียวกันเลย

**ตัววัดที่ถูกต้อง** (`g3_dup_bytes.py`): parse pcapng เอง, เทียบ
**ความยาว + sha256 ของ raw frame** และต้องอยู่ห่างกัน ≤ 2 ms
สอง frame ที่ bytes เหมือนกันทุกไบต์ภายในไม่กี่ไมโครวินาทีเป็นไปไม่ได้บนสายอากาศ
(ต้องมี SIFS + backoff) → เป็นการ deliver ซ้ำของ capture path

---

## 3. ผลวัด (byte-level, window 2 ms)

`admin-evidence/capture-dup-20261117/dup-summary-20261117T0950Z.json`
(sha256 `951451A7DEC9F78B8FFE774E7FCE638D9C25DDC2857D11AB4DB10DFFB477A6BF`)

| กลุ่ม capture | สภาพ | frames | byte pairs | ratio |
|---|---|---|---|---|
| `wifi-dup-20261117/wifi-dup-45007` | 02:39, association เดิม | 14 | **5** | 0.3571 |
| `wifi-dup-20261117/vmnet1-control-arp` | control (VMnet1) | 3 | 0 | 0.0 |
| `capture-dup-20261117` (2 runs) | 09:34, **ก่อนแก้ config ใด ๆ** | 202 | 0 | 0.0 |
| `capture-dup-20261117-postreload` (6 runs) | Dot11Support=**0** | 570 | 0 | 0.0 |
| `capture-dup-20261117-dot11-1` (4 runs) | Dot11Support=**1** | 542 | 0 | 0.0 |
| `capture-dup-20261117-stimulus` (3 runs) | filter แคบแบบเดียวกับ 02:39 | 55 | 0 | 0.0 |
| `capture-dup-20261117-rateload` (no nose) | 1,095 fps | 13,901 | 0 | 0.0 |
| `capture-dup-20261117-rateload` (nose running) | 1,126 fps, 2 handles | 13,787 | 0 | 0.0 |
| **รวม** | | **29,074** | **5** | **0.000172** |

`5` ทั้งหมดอยู่ใน capture ประวัติศาสตร์ตัวเดียว; capture ของวันนี้ = **0**

### 3.1 capture ประวัติศาสตร์ (ยืนยันของจริง)

```json
{"frames":14,"identical_byte_pairs":5,"consecutive_duplicate_groups":5,
 "direction_mix":{"host_tx":5},
 "samples":[{"frame_a":1,"frame_b":2,"gap_us":7.2,"len":66},
            {"frame_a":4,"frame_b":5,"gap_us":3.8,"len":54},
            {"frame_a":6,"frame_b":7,"gap_us":6.9,"len":72},
            {"frame_a":11,"frame_b":12,"gap_us":3.1,"len":54},
            {"frame_a":13,"frame_b":14,"gap_us":12.6,"len":54}]}
```

ทิศทาง: **host_tx ทั้ง 5 คู่** — frame ที่เครื่องนี้ส่งออกถูก deliver 2 ครั้ง
ส่วน inbound (frame 3, 8, 9, 10) มาใบเดียว

---

## 4. Dot11Support A/B และการ reload โดยไม่ reboot

### 4.1 reload ที่ทำได้จริง

| ขั้น | ผล |
|---|---|
| `g3_dup_config.ps1` (elevated) | `SET_TO=0` (previous=1) ที่
`HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters` |
| `g3_npcap_reload.ps1` (elevated) | `sc stop npcap` → `STOP_PENDING`, `sc start` → **1056**
(handle ยังถูกถือ) → `REBOOT_REQUIRED` |
| `g3_npcap_cycle.ps1` (elevated) | หยุด `AegisNids` + ปิด `aegis-nose` →
`STATE_AFTER_HANDLES_RELEASED=STOPPED` → `sc start npcap` → `RUNNING`,
`DEVICES_AFTER=13` → `AegisNids=Running`, `AegisWfp=Running` |
| `g3_dot11_reload.ps1 -Value 1` | `VALUE 0→1`, `STOPPED=True`, `STARTED=True`,
`STATE_AFTER=RUNNING`, `DEVICES_AFTER=13`, `NIDS_AFTER=Running` |
| `g3_dot11_reload.ps1 -Value 1` (ซ้ำ) | daemon restart สะอาด, `RELOADED=True` |

→ การเปลี่ยน config ของ Npcap **มีผลทันทีหลัง driver reload** ไม่ต้อง reboot
(ข้อความ "A reboot is required" ในคอมเมนต์เดิมของ `g3_dup_config.ps1`
ถูกแทนด้วยขั้นตอนนี้แล้ว)

### 4.2 ผล A/B

| arm | capture | frames | byte pairs |
|---|---|---|---|
| Dot11Support=0 (หลัง reload) | 6 runs (8–10 s, 0–60 req) | 570 | 0 |
| Dot11Support=1 (หลัง reload) | 4 runs (8–10 s, 0–60 req) | 542 | 0 |
| Dot11Support=1 (high rate, no nose) | 12 s, 1,095 fps | 13,901 | 0 |
| Dot11Support=1 (high rate, nose running) | 12 s, 1,126 fps | 13,787 | 0 |

**ไม่ได้รัน:** high-rate run ที่ Dot11Support=0 — UAC prompt ถูกยกเลิก 2 ครั้ง
(ไม่มีผู้กดยืนยัน) จึงไม่มีการอ้างผลในช่องนั้น; arm Dot11=0 มีเฉพาะ low-rate (570 frame)

---

## 5. ทำไมจึงสรุปว่าเป็น transient ของ link ไม่ใช่ config

timeline จาก `Microsoft-Windows-WLAN-AutoConfig/Operational`:

| เวลา | event |
|---|---|
| 02:39 | capture ที่แสดง doubling (association เดิม) |
| **03:35:05** | **11004 Wireless security stopped** (association เดิมจบ) |
| 14:31:01 | 11010/11005 Wireless security started + succeeded (association ใหม่) |
| 09:34–09:52 (วันเดียวกัน) | capture ทั้งหมด 0 duplicate |

association ใหม่: 802.11ac, 5 GHz, ch 157, signal 92%, RSSI -43, 866.7 Mbps

ข้อสรุปเชิงประจักษ์: doubling เกิดใน association ที่จบไปตอน 03:35 และไม่เกิดใน
association ปัจจุบัน ไม่ว่า Dot11Support จะเป็น 0 หรือ 1, ที่ 1,100 fps หรือไม่มี
traffic, มี nose ถือ handle หรือไม่มี

**root cause ของเหตุการณ์ 02:39 ไม่ถูกระบุ** — ที่ตรวจแล้วตัดออก: product path
(nose 1 event/frame, duplicate counters 0), VMnet1 (0), Dot11Support, filter shape,
อัตรา frame, การมีสอง capture handle

---

## 6. หลักฐานฝั่ง product ว่าไม่ได้ทำซ้ำ

| หลักฐาน | ค่า |
|---|---|
| nose ระหว่าง high-rate run | `packets=26300 canonical=26300 dropped=0` (1:1:0) |
| daemon acquisition mode | `npcap_primary reason=none packet=true` (ไม่มี `nose_stalled`) |
| `capture_npcap` queue drops | `dropped: 0` |
| VMnet1 control capture | 3 frames, 0 byte pairs |
| daemon/PEP/driver hash | ไม่เปลี่ยน (`7955A6E3` / `362B069A` / `06CC8E23`) |

---

## 7. สภาพเครื่องหลังจบงาน (ตรวจแล้ว)

```text
DAEMON=7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18
PEP=362B069AFF007B6C72494D2B9E689893C1A8EB559B8266B38534AA17D543D118
DRIVER=06CC8E238B79BEC3782F4036BACF058D6B5291B030E59D061FD692F82FB96B50
POLICIES=B7224FA01572A637336AF6629D2A63C44FD9C53854DFD401D6264E5249CA3A4E
SIG_PRESENT=False  TRUST_PRESENT=False
SVC_ENV=AEGIS_LOSS_BUDGET=3500
DOT11=1  NPCAP_STATE=RUNNING  PROCS=aegis_nids:6348,aegis-nose:18832
GATE=closed  TIER3_ENFORCING=False  HOST_EFFECT_CAPABLE=False  MODE=detection-only
confirmed_quarantines=0  confirmed_blocks=0
```

ไม่มี firewall rule, ไม่มี signed policy artifact, ไม่มี filter ของ AEGIS,
Dot11Support กลับเป็นค่า baseline (1), nose กลับมาทำงานและเชื่อม pipe ได้
(`[NOSE PIPE] connected`, `first canonical frame sent`)

---

## 8. ผลต่อ gap และเงื่อนไข reopen

`CAPTURE-DUP-WIFI-001` เขียนว่า "delivers every frame twice, doubling detections"
— วัดที่ระดับ bytes แล้ว **ไม่เป็นจริงกับสภาพปัจจุบัน** และข้อกล่าวหาฝั่ง product
(1 event ต่อ 1 frame) ก็ถูกตรวจซ้ำแล้วว่าเป็นจริง

**สถานะที่บันทึก:** `CLOSED` — `result = NOT_REPRODUCIBLE_NO_PRODUCT_DEFECT`,
ระดับ E5

**สิ่งที่ gap นี้ยอมรับว่าไม่ได้ทำ:**
- ไม่ได้ระบุ root cause ของเหตุการณ์ 02:39
- high-rate ที่ Dot11Support=0 ไม่ได้รัน (UAC ถูกยกเลิก)
- ไม่ได้ทดสอบ association อื่น/new SSID ซ้ำ (ทำได้เมื่อ link เปลี่ยน)

**Reopen criteria (วัดได้ ไม่ใช่ความเห็น):** ถ้า `g3_dup_bytes.py` บน capture
ของ Wi-Fi adapter รายงาน `identical_byte_pairs > 0` ในสถานะปกติ (ไม่มี lab
artifact) → เปิด gap นี้ใหม่ทันทีพร้อม capture + hash; ถ้าเป็น traffic
`host_tx` ทั้งหมดและห่าง ≤ 20 µs ให้ถือเป็น capture-path duplication

---

## 9. หลักฐาน (local-only, `admin-evidence/` git-ignored)

| ไฟล์ | sha256 | bytes |
|---|---|---|
| `capture-dup-20261117/dup-summary-20261117T0950Z.json` | `951451A7DEC9F78B8FFE774E7FCE638D9C25DDC2857D11AB4DB10DFFB477A6BF` | 6,963 |
| `wifi-dup-20261117/wifi-dup-45007.pcapng` | `4218C372980440C94967F747C739EABF6B3D41E1709DE46F04573D67569191FD` | 2,196 |
| `capture-dup-20261117/` (2 captures pre-change) | 0 duplicate, 202 frames | — |
| `capture-dup-20261117-postreload/` (6 captures, Dot11=0) | 0 duplicate, 570 frames | — |
| `capture-dup-20261117-dot11-1/` (4 captures, Dot11=1) | 0 duplicate, 542 frames | — |
| `capture-dup-20261117-stimulus/` (3 captures) | 0 duplicate, 55 frames | — |
| `capture-dup-20261117-rateload/` (2 captures) | 0 duplicate, 27,688 frames | — |
| `g2-single-host-20261117/npcap-dot11-20261117T093611Z/dot11-backup.json` | `D478C5072894972B2E07C179323E608BA1E57A7E72771CD7CDA381F4E50A0793` | 65 |
| `g2-single-host-20261117/npcap-reload-20261117T093631Z/reload.json` | `3A51E548999087C850417AE09C7835E50FD149238AFA71C53C04A2954FBE352B` | 1,148 |
| `g2-single-host-20261117/npcap-cycle-20261117T093735Z/cycle.json` | `957FC90AC83AE78E67F83B42F55512709B3AC688B1AEA71776D24F69A97B512D` | 1,015 |
| `g2-single-host-20261117/dot11-ab-20261117T094045Z/dot11-ab.json` | `282F5DCF4F63B6DC1D94B160A32B622209609A281A83D15B091B20C02494FD1B` | 1,163 |
| `g2-single-host-20261117/dot11-ab-20261117T094620Z/dot11-ab.json` | `ED9D65D5F753BD9D663DB27E0AC77C896428DCCA2FE7E787FCD97FCC5FBD79D8` | 1,163 |
| `capture-dup-20261117/nose-capture.log.err` | nose 1:1:0 counters (local) | — |
| `g2-single-host-20261117/window-20261117/post-dup-experiment.json` | posture ปิดงาน | — |

**เครื่องมือ (kit v3, local-only):**

| ไฟล์ | sha256 | bytes |
|---|---|---|
| `g3_dup_bytes.py` (ตัววัดใหม่) | `FBC33E50F75A36D7BD8B87FD10C205A0B650A547503DB8D15473C7693EBE91DC` | 5,271 |
| `g3_dup_summary.py` | `9A8ADBF486228090AFF8723A24F17C8CA57D44029A9EDE672D447BBAC46DF1FC` | 3,004 |
| `g3_dup_stimulus.py` | `1EF7DBBA1159C32CE87815F48C7516679A3F8F11675E879E342F25CC43574C90` | 2,829 |
| `g3_dup_rateload.py` | `A53D725B4528C208C5A54DA2A75766BBFAB476C43E7D53E0A83A843F8C589A45` | 2,991 |
| `g3_dup_ratio.py` (ตัวเดิม, มี artifact) | `E4AAAB441CD57088425B38DE161EE79D2A8F03C1F44875A7134613C9A24120D1` | 3,664 |
| `g3_dot11_reload.ps1` | `1713073C27A88B7AF5930DE1D988783A6DED0C7FB544A673DD80F7EB5801EC49` | 3,704 |
| `g3_npcap_cycle.ps1` | `91AC8220B17797E17CC1FEC9236E799415325E48828D818C3C685F0327D224AB` | 4,010 |
| `g3_npcap_reload.ps1` | `1FC9DDB6E517926FB563B7B6332D8FA49EA0E95F6AE6AA9F8CE9AFEA13EE3761` | 2,890 |
| `g3_dup_config.ps1` (แก้ key เป็น `\Parameters`) | `4019DA9E6AD12EC11580C094F9C08ABB48011C5FBD726560C154C30B08B664D9` | 2,141 |

> `g3_dup_ratio.py` **ไม่ถูกลบ** เพราะเป็นเครื่องมือที่ใช้ในหลักฐานเก่า — แต่มันถูก
> ทำเครื่องหมายในเอกสารนี้ว่าตัวเลข "duplicate" ของมันใช้ตัดสินไม่ได้
> ตัวตัดสินคือ `g3_dup_bytes.py`

---

## 10. Patch record

```text
PATCH-ID:        CAPTURE-DUP-BYTE-CLOSE-20261117
FLOW-ID:         DATA-001
TARGET HEAD:     aade7a3
TARGET FILES:    EVIDENCE_INDEX.json
                 analysis/current-head/CAPTURE-DUP-WIFI-20261117.md (new)
                 analysis/current-head/CLOSURE-PLAN-5GAPS-20261117.md (rev.4 note)
                 AI_CONTEXT.md (open-gap count)
IN-SCOPE:        byte-level re-measurement + gap classification + records
OUT-OF-SCOPE:    any src/, driver, PEP, Rust, build, release, tag change
CONTRACT IMPACT: none
ABI IMPACT:      none
AUTHORITY IMPACT: none
STATE IMPACT:    npcap driver reloaded twice; Dot11Support back to baseline 1;
                 AegisNids restarted; aegis-nose restarted and connected
TEST IMPACT:     none
EVIDENCE IMPACT: +1 E5 evidence entry; CAPTURE-DUP-WIFI-001 OPEN -> CLOSED
```

**ROLLBACK:** ตั้ง `Dot11Support=1` (ค่าปัจจุบันอยู่แล้ว) — ไม่มี artifact อื่นบนเครื่อง;
records rollback = revert commit นี้
