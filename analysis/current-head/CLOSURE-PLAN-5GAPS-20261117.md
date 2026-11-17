# CLOSURE-PLAN-20261117 — วิธีปิด 5 gap ที่เหลือ และ 4 ข้อ distribution

**Created:** 2026-11-17
**Base:** v2.0.0 detection-only, build source `7c604d5`, installed `7955A6E3...`,
tag `v2.0.0` → `7b484a1`
**Companion:** `docs/BACKLOG-v1.1.md`, `analysis/current-head/PROJECT-CLOSEOUT-20261117.md`

เอกสารนี้ตอบคำถามเดียว: **แต่ละ gap ที่ยังเปิด ปิดได้ด้วยวิธีใด ต้องใช้อะไร
หลักฐานระดับไหน และมีข้อจำกัดจริงตรงไหน** ทุกข้อถูกเขียนให้ปิดได้โดยไม่ต้อง
ปลอมหลักฐาน และไม่แตะ signed tree (`release/T20-final/9ebee9b`) หรือ tag
`v2.0.0`

---

## 0. หลักการที่ใช้ตัดสินทุกข้อ

1. **ห้ามแก้ signed tree.** ทุกการแก้ `SOURCE_PATHS` (`src`, `drivers`, `nose`,
   `configs`, `build.zig`, ...) ต้อง rebuild + re-sign + soak ใหม่ และต้องออก
   release ใหม่ ไม่ใช่ patch ของ v2.0.0
2. **หลักฐานต้องตรงระดับ.** E5 = Windows host จริง, E2 = unit/component,
   E7 = release. ห้ามอ้าง E5 จาก E2
3. **Loss ต้องมองเห็น.** ทุกกลไกที่ลดปริมาณต้องมี counter และต้องไม่ทำให้
   event ที่ต่างกันจริงหายไป (ADR-0010/ADR-0012)
4. **Detection-only คงเดิม.** ไม่มีข้อใดในแผนนี้เปิด `prevention_gate` บน
   production build; งาน enforcement เป็น lab build เท่านั้น

---

## 1. ภาพรวม: 5 gap + 4 distribution

| # | Item | ระดับปัจจุบัน | สิ่งที่ขาดจริง | ต้องใช้อะไรปิด | แก้ source? | เวลาประมาณ |
|---|---|---|---|---|---|---|
| 1 | `RULE-LAYER-SCOPE-001` | E1 | AC เดียวใช้ rule ข้าม layer กับ network bytes | patch rule layer + pins + build + soak | **ใช่** (`src`) | 1–2 วัน + soak |
| 2 | `CAPTURE-DUP-WIFI-001` | E5 | frame ซ้ำบน Wi-Fi/Npcap นี้ | เปลี่ยน link (Ethernet) หรือ counted dedup ใน Nose | อย่างหลังใช่ | 30 นาที หรือ 2–3 วัน + soak |
| 3 | `GAP-QLOSS-ISOLATION-002` | E2 | ingress FIM/ETW จาก storm ไม่ลด | ETW delete filter + consumer throughput หรือ accepted envelope | **ใช่** | 2–4 วัน + soak |
| 4 | `ADR-0012-DUP-RATIO-E5` | E5 | ยังไม่พิสูจน์ว่า repeat = distinct open | create-once measurement (ไม่แก้ source) → decision | ไม่ (measurement) | 2–4 ชั่วโมง |
| 5 | `EVI-G2-PEP-CACHE-001-LAB` | E5 (lab) | duplicate canary ไม่ถึง PEP เพราะ filter เดิมบล็อกก่อน | Win11 VM เป็น host ที่สอง + lab build + kit v2 | ไม่ (lab kit) | 3–6 ชั่วโมง |
| D1 | Driver signing (EV + attestation/HLK) | — | ไม่มี EV cert/Partner Center | procurement + CI + clean-VM install proof | ไม่ | สัปดาห์ (ภายนอก) |
| D2 | Installer 6.0.0 label | — | product version ใน `src` เป็น `5.0.0` | bump version รวมกับ v1.1 build | **ใช่** | รวมใน v1.1 |
| D3 | Production rebuild | — | ยังไม่ได้ rebuild จาก source เพื่อ cut production | CI build + hash compare + clean VM | ไม่ | 1–2 วัน |
| D4 | Fresh-install boot model | — | ยังไม่ทดสอบติดตั้งบนเครื่องสะอาด | Win11 VM + installer ปัจจุบัน | ไม่ | 1–2 ชั่วโมง |

ข้อมูลเครื่อง ณ 2026-11-17 (ใช้ตัดสินความเป็นไปได้):

- VMware Workstation **17.5.2**, Kali VM ทำงานอยู่, **ไม่มี Windows VM**
- Windows 11 25H2 ISO พร้อม: `D:\Downloads\Win11_25H2_English_x64_v2.iso`
  (8,471,603,200 bytes)
- Hyper-V เปิดอยู่ (`InstallState=1`) แต่ผู้ใช้ไม่มีสิทธิ์สร้าง VM
  (`Get-VM` = access denied) → ใช้ VMware
- RAM 16 GB, D: ว่าง 372 GB, C: ว่าง 30.7 GB
- test-signing certs มีใน `LocalMachine\My`: `CN=AEGIS NIDS Test Signing`,
  `CN=AEGIS Test Signer`; **ไม่มี EV code-signing cert**
- signtool / Inf2Cat / HLK Testing มีใน Windows Kits 10.0.28000.0
- Npcap 1.10.6, `Dot11Support=1`, `LoopbackSupport=1`
- lab kit เดิมพร้อม: `admin-evidence/g2-direction-20261022/lab-kit-20261022-v2/`
  (binary + 4 สคริปต์ + INSTALL.txt + RUN-CHECKLIST.md + SHA256SUMS.txt)

---

## 2. `RULE-LAYER-SCOPE-001` (P3, E1)

### 2.1 ข้อเท็จจริง

- `src/pipeline/rule_loader.zig:301-328` โหลดทุก rule ที่ไม่ใช่ L4 เข้า
  Aho-Corasick **ตัวเดียว** (`g_active_ac`) โดยไม่เก็บ `layer`
- `src/pipeline/event_processor.zig:280-299` รัน AC กับ payload ของทุก source
  ยกเว้น `capture_host_net`; payload ของ network มาจาก L7 extraction
- `configs/Rules.json` มี 23 rules: `L7` 5, `KERNEL_FILE` 5,
  `KERNEL_PROCESS` 5, `L2_PIPE` 5, `L4` 3
- ผลคือ TLS/HTTP bytes ที่บังเอิญมีคำว่า `IEX` (R2003), `mimikatz` (R2001)
  หรือ `C:\Windows\System32` (R1001) จะถูกตีเป็น signature match ระดับ
  KERNEL_PROCESS/KERNEL_FILE บน traffic ที่ไม่เกี่ยวกับ kernel เลย
- P3 เพราะไม่ใช่ enforcement (gate ปิด) แต่ทำให้ detection evidence ผิด
  layer และอาจไปถึง policy assessment ในฐานะ match

### 2.2 วิธีปิด (ต้องแก้ source)

**Patch A (แนะนำ): per-layer automata**

1. `rule_loader.zig`: parse `layer` ของแต่ละ rule, สร้าง AC แยกชุด
   `network` (L7 เท่านั้น), `kernel_file`, `kernel_process`, `l2_pipe`
   (L4 ยังอยู่ที่ `l4_rules` เหมือนเดิม) แล้ว swap ทั้งชุดใต้ `g_ac_mutex`
   แบบ atomic พร้อม `g_active_ac` เดิม (คง hot-reload semantics)
2. `runtime_state.zig`: เก็บ pointer ต่อ layer + counter จำนวน rule ต่อ layer
3. `event_processor.zig`: เลือก automaton ตาม `ev.source`
   - `capture_npcap` (รวม Go Nose ผ่าน ContextFlags), `capture_wfp`,
     `capture_host_net` (ยังไม่รัน) → **network/L7 เท่านั้น**
   - `capture_fim` / `minifilter` → `kernel_file`
   - `capture_etw` process events → `kernel_process`; registry → `kernel_file`
   - pipe events → `l2_pipe`
4. ถ้า source ไม่รู้จัก → **ไม่รัน AC** และไม่แต่ง rule id (fail closed ต่อ
   การสร้าง detection ผิด layer) พร้อม counter `ac_skipped_unknown_source`

**Pins ที่ต้องมีใน patch เดียวกัน**

| Pin | ชนิด | ต้อง fail ถ้า |
|---|---|---|
| TLS record ที่มี bytes `IEX` / `DownloadString` | Zig unit | ได้ rule id ของ R2003 |
| HTTP payload ที่มี `<script>` | Zig unit | ไม่ได้ R9059 (กันแก้จน L7 หาย) |
| FIM path ที่มีคำว่า `IEX` | Zig unit | ได้ R2003 (ต้องได้เฉพาะ KERNEL_FILE) |
| process command line ที่มี `IEX` | Zig unit | ไม่ได้ R2003 |
| rule count ต่อ layer หลัง load | Zig unit | จำนวนรวมไม่เท่า `Rules.json` (กัน rule หายเงียบ) |
| reload สลับชุดแล้วยังทำงาน | Zig unit | ชุดเก่ายังถูกใช้หลัง swap |
| source scan | Python | `event_processor.zig` รัน AC โดยไม่เลือก layer |

**Acceptance (E5):** one RB-022 window ที่ยิง TLS/HTTPS + HTTP ปกติ
→ 0 rows ของ `R2001/R2002/R2003/R2004/R2005/R3001-R3005` จาก network source;
ยิง PowerShell cradle จริงบน host → ยังได้ R2003 1 row

**ต้นทุน/ความเสี่ยง:** ~150–300 LOC + tests, build ใหม่, re-sign, soak 24 h;
ความเสี่ยงปานกลางเพราะแตะ detection semantics แต่ลดเฉพาะ false positive
ข้าม layer (ไม่ลด coverage ของ rule เดิม)

---

## 3. `CAPTURE-DUP-WIFI-001` (P3, E5)

### 3.1 ข้อเท็จจริง

- dumpcap handle เดียวบน Wi-Fi: frame ซ้ำทุกเฟรม, `ip.id`/TCP seq/bytes
  เหมือนกัน, ห่าง ~7 µs, Ethernet interface block เดียว
- VMnet1 control (ARP) ไม่มี duplication
- **ทดสอบใหม่ 2026-11-17:** `dumpcap -y IEEE802_11` บน adapter นี้ →
  `IEEE802_11 is not one of the DLTs supported by this device` → **แก้ด้วย raw
  802.11 ไม่ได้บน adapter นี้** แม้ `Dot11Support=1`
- Killer E2600 Gigabit Ethernet มีอยู่แต่ **ไม่ได้ต่อสาย** (`Disconnected`)

### 3.2 วิธีปิด

**ทาง A — เปลี่ยน link เป็น Ethernet (ไม่แก้ source; แนะนำเป็นทางแรก)**

1. ต่อสาย LAN เข้า Killer E2600 (หรือ USB Ethernet) ให้ `Status=Up`
2. `dumpcap -i <ethernet>` ระหว่าง Kali ยิง canary ชุดเดิม
3. ถ้าไม่มี duplication → ตั้ง `AEGIS_NOSE_IFACE` เป็น Ethernet แล้วรัน RB-022
   window เทียบ wire count กับ detection count
4. Acceptance: attributed rows = 1 ต่อ stimulus (ไม่ใช่ 2), counter
   `nose_duplicate_event_ids=0`, ไม่มี restart ของ production image ที่ติดตั้ง
5. ปิด gap ด้วย evidence "duplication เป็นสมบัติของ Wi-Fi/Npcap path นี้;
   production ใช้ Ethernet ซึ่งไม่ซ้ำ"

ต้องมีจากเจ้าของ: สาย LAN + switch/AP ที่ไม่ทำ client isolation

**ทาง B — ปรับ Npcap/Killer (ไม่แก้ source, โอกาสสำเร็จต่ำ)**

- ถอน/ติดตั้ง Npcap ใหม่แบบไม่บังคับ raw 802.11 หรือเลือก WinPcap API-only
- ปิด Killer "packet prioritization"/coalescing แล้ววัดซ้ำ
- ข้อควรระวัง: การติดตั้ง Npcap ใหม่ตัด capture ชั่วคราว → ต้องยอมรับว่า
  process window เดิมจบ (soak ผ่านแล้ว) และห้ามสลับ binary ที่ติดตั้ง

**ทาง C — counted dedup ใน Nose (Go; ต้อง rebuild + soak)**

- dedup key: `(ip.id, tcp.seq, direction, payload hash)` ภายในหน้าต่างสั้น
  (< 1 ms) เท่านั้น; เก็บ frame แรก, นับที่เหลือใน
  `nose_dedup_suppressed`
- pin: retransmission จริงที่ +200 ms ต้องไม่ถูกกลืน; frame ที่ payload
  ต่างกันต้องไม่ถูกกลืน; TCP seq กลับมาใช้ใหม่หลัง window ต้องผ่าน
- Acceptance: canary บน Wi-Fi ได้ 1 row ต่อ stimulus, counter > 0,
  retransmit pin ผ่าน, ไม่มี event loss อื่น
- ต้นทุน: patch Go + tests + build + soak 24 h; ความเสี่ยงปานกลาง
  (แตะ capture path ที่เป็น ingress หลัก)

**ไม่แนะนำ:** dedup ใน Zig pipeline เพราะจะทำให้ frame ที่ต่างกันจริง
(เช่น retransmission) หายหลังผ่าน admission แล้ว และผิดหลัก "loss ต้อง
มองเห็นที่ producer"

---

## 4. `GAP-QLOSS-ISOLATION-002` + `ADR-0012-DUP-RATIO-E5`

สองข้อนี้เกี่ยวกันแต่ **ไม่ใช่ข้อเดียวกัน**:

- `ADR-0012` ถามว่า repeat ที่วัดได้เป็น "สำเนาที่ปลอดภัยต่อการรวม" หรือไม่
- `QLOSS-ISOLATION-002` ถามว่าปริมาณ ingress จาก source ที่ storm ลดได้ไหม

### 4.1 ข้อมูลสดจาก installed daemon (2026-11-17)

`python tools/aegisctl.py queue --json`:

| counter | ค่า |
|---|---|
| `pushed_total` | 40,742,151 |
| `dropped_total` / `source_quota_shed` | 4,321 / 4,321 |
| `shed_overload` | 23,437 |
| `reserved_tail_shed` | 0 |
| `source_occupancy_cap` | 7,168 |
| `capture_etw` pushed / dropped | 31,394,792 / 4,321 |
| `capture_fim` pushed / dropped | 2,412,363 / 0 |
| ETW `file_name_delete` → `fim_change` | 18,151,604 |
| ETW `file_write_filtered` | 15,510,237 |
| ETW `name_create_deduped` | 20,346,756 |
| `fim_probe.batch_records` | 2,412,363 |
| `fim_probe.batch_duplicates` | 1,147,079 (47.5%) |
| `fim_probe.minifilter.records` | 2,389,480 |
| `fim_probe.minifilter.duplicates` | 1,139,107 |
| `...duplicates_per_pid` | 1,012,763 |
| `...duplicates_same_ts` | 639,915 |
| `fim_probe.batch_overflow` | 0 |

ข้อสังเกตสำคัญ:

1. **lane ที่ใหญ่ที่สุดคือ ETW NameDelete** (18.15M rows) ไม่ใช่ minifilter
   (2.4M) — การลด minifilter ไม่ช่วย ETW quota และกลับกัน
2. ETW มี counted filter อยู่แล้ว 2 ตัว (write filter, name-create dedupe)
   และมี `shed_overload` แยก → มี pattern ที่ยอมรับแล้วให้ลอกใช้
3. `duplicates_same_ts` 639,915 **ไม่ใช่หลักฐานของ duplicate delivery**
   เพราะ `KeQuerySystemTime` มี granularity ~15.6 ms ทำให้ open ต่างกัน
   ตกลง timestamp เดียวกันได้ — ต้องแยกด้วยการทดลอง create-once

### 4.2 Phase 1 — ปิด `ADR-0012` ด้วยการวัด (ไม่แก้ source, ไม่ต้อง restart)

การทดลอง **create-once unique path**:

1. สร้าง `D:\tmp\aegis-storm-<ts>\` และ write ledger ของทุก operation
   (path, pid, op, timestamp) จาก harness เดียว
2. อ่าน `fim_probe` baseline (idle 60 s) → รัน churn ไฟล์ชื่อไม่ซ้ำ
   หนึ่งครั้งต่อไฟล์ → อ่าน `fim_probe` อีกครั้ง
3. เทียบ `Δminifilter.duplicates_per_pid` กับ ledger:
   - ถ้าไฟล์แต่ละไฟล์ถูก open ครั้งเดียวโดย pid เดียว และ
     `duplicates_per_pid` ไม่เพิ่ม (หรือเพิ่มเฉพาะ ambient ที่อธิบายได้)
     → **ไม่มีการส่งซ้ำจาก driver/reader**; repeat 47% ในงานจริงคือ
     distinct opens → **ADR-0012 = Rejected (ห้าม suppressing coalescer)**
     ปิด gap ด้วย decision record + ตัวเลขจริง
   - ถ้า `duplicates_per_pid` เพิ่มตามจำนวนไฟล์ → **มี duplicate delivery
     จริง** → เดิน Phase 2 ข้อ (a)

    เหตุผลที่วิธีนี้ใช้ได้: minifilter บันทึก 1 record ต่อ successful
    `IRP_MJ_CREATE`; ถ้า path ไม่ซ้ำและ open ครั้งเดียว การเห็น path เดิม
    สองครั้งใน batch เดียวกันย่อมไม่ใช่ "open ต่างกัน"

4. ต้องทำตอน service ว่างพอสมควร (ไม่มี canary/สแกนอื่น) และบันทึก
   Δ ของ `minifilter.dropped`, `ring_written`, `pipeline_dropped` ด้วย

**Acceptance:** decision record ที่มีตัวเลข Δrecords/Δduplicates/Δper_pid
+ ledger count + ช่วงเวลา + hash ของ build ที่ติดตั้ง; ถ้า reject coalescer
ต้องระบุด้วยว่า ETW lane ใช้ dedupe คนละแบบและไม่ถูกนำมาเป็นเหตุผลร่วม

### 4.3 Phase 2 — ปิด `QLOSS-ISOLATION-002` (ต้องแก้ source + soak)

เลือกได้ 2 แนวที่ซื่อสัตย์:

**แนว 1: ลด ingress ที่ producer ด้วย counted filter (ลอกจาก write filter)**

- เพิ่ม `QLOSS-ETW-DELFILTER-001`: ETW `NameDelete` ที่ payload ไม่ match
  rule path ใดเลย → drop พร้อม counter `file_delete_filtered`
- เก็บ delete ที่อยู่ใน path วิกฤต (System32, Startup, hosts, `.locked`)
  และเพิ่ม **mass-delete aggregate**: นับ delete ต่อวินาทีและ emit summary
  1 row เมื่อเกิน threshold เพื่อไม่ให้ ransomware mass-delete มองไม่เห็น
- ผลคาดหมาย: ETW lane ลดจาก ~18M → หลักแสน, `shed_overload`/ETW drop ลด
- ต้อง pin: delete ที่ System32 ยังเข้า, summary ยังเกิด, counter ตรง

**แนว 2: เพิ่ม consumer throughput (ADR-0010 item 2)**

- batched forensic append (ลด per-row 4 KiB zero/hash/CRC cost)
- semantics-neutral, ไม่ทิ้ง event; ลด drop จาก queue เต็ม
- ต้องมี benchmark ก่อน/หลังที่ workload เดียวกัน

**แนว 3: accepted envelope (ไม่แก้ source)**

- ถ้า Phase 1 พิสูจน์ว่า volume เป็นของจริงทั้งหมด และทั้ง 2 แนวข้างต้น
  ยังคุ้มไม่พอ → ปิดแบบ "accepted envelope" เหมือน #29: ระบุ budget
  (เช่น drops ≤ 1% ของ pushed), counter ที่มองเห็น, และ owner sign-off
- ต้องไม่เรียกสิ่งนี้ว่า "แก้แล้ว" — ต้องระบุว่าเป็น decision

**Acceptance (E5) สำหรับแนว 1/2:** churn ชุดเดิม + รัน 24 h:
`source_quota_shed`/`shed_overload` ลดลงอย่างมีนัยสำคัญเทียบ baseline,
`minifilter.dropped=0`, ring 0, readiness ไม่ผ่อน, ไม่มี event ที่ควรเข้า
ถูกทิ้ง (pin)

**ต้นทุน:** Phase 1 = 2–4 ชั่วโมง; แนว 1 หรือ 2 = 1–3 วัน + soak 24 h

---

## 5. `EVI-G2-PEP-CACHE-001-LAB` (E5, lab-only)

### 5.1 สิ่งที่ขาด

จาก `EVIDENCE_INDEX.json` และ `admin-evidence/g2-direction-20261022/`:

- PEP cache swap PASS, direction verify PASS, unblock PASS, base restore PASS
- **duplicate canary = `BLOCKED_OR_TIMEOUT`**: connection ที่สองถูก WFP filter
  เดิม (id 78056) บล็อกก่อนที่ PEP/daemon จะออก receipt ครั้งที่สอง
- ดังนั้น "duplicate PEP block path + receipt/counter increment" ยังไม่ถูกพิสูจน์
- blocker เดิม: ต้องมี host ที่สอง + สิทธิ์ enforcement; session ก่อนหน้าไม่มี

### 5.2 วิธีปิด: Win11 VM เป็น lab host

ทรัพยากรพร้อม: ISO Win11 25H2, VMware 17.5.2, D: 372 GB, lab kit v2,
build option `-Dlab-prevention-gate=true` (lab-only, ไม่ขึ้น release)

ขั้นตอน:

1. สร้าง VM: Win11 x64, 4 vCPU / 6–8 GB RAM, disk 60 GB, vTPM + Secure Boot
   (VMware 17.5 รองรับ; ต้องเข้ารหัส VM สำหรับ vTPM)
2. ใน guest: เปิด test signing (`bcdedit /set testsigning on`), reboot,
   ติดตั้ง cert `AEGIS NIDS Test Signing`, ตรวจ `signtool verify /pa`
3. build lab binary จาก source ปัจจุบัน:
   `zig build -Dlab-prevention-gate=true` แล้วคัดลอก
   `aegis_nids.exe` + `aegis_pep.dll` + `aegis_wfp.sys` +
   `aegis_wfp_user.dll` เข้า guest (ห้ามใช้ lab binary บน host นี้)
4. รัน `lab-kit-20261022-v2` ตาม `RUN-CHECKLIST.md` แต่เพิ่มขั้น
   **unblock filter 78056 ก่อน duplicate canary** เพื่อให้ canary ที่สอง
   ไปถึง PEP จริง (นี่คือ root cause ที่ค้าง)
5. เก็บ: PEP cache swap log, direction verify, `confirmed_quarantines`
   +1 หรือ receipt ที่สอง, unblock, base restore (gate closed,
   `host_effect_capable=false`, proof count 0)
6. ปิด gap เฉพาะเมื่อได้ receipt/quarantine ที่สองจริง; ถ้ายังถูกบล็อกด้วย
   reason อื่น ให้บันทึกเป็นหลักฐานว่าติดอะไร ไม่ใช่ปิด

**Acceptance (E5):** duplicate canary ได้ confirmed quarantine/receipt ที่สอง
(or documented block พร้อมเหตุผลระดับ filter/PEP) + base restore กลับ
detection-only ครบ + ไม่มี artifact ของ lab หลุดเข้า release tree

**ความเสี่ยง:** Win11 vTPM/Hyper-V coexistence, RAM 16 GB (ปิด Kali ระหว่างรัน),
เวลา 3–6 ชั่วโมง; ทั้งหมดอยู่ใน guest ไม่กระทบ production image

---

## 6. Distribution (4 ข้อ)

### D1. Driver signing — EV + Microsoft attestation/HLK

- ต้องมี: นิติบุคคล, EV code-signing cert (HSM/token), Partner Center,
  HLK ผ่านบนเครื่องทดสอบ, submission
- ปิดได้อย่างไร: sign `aegis_wfp.sys`/`aegis_minifilter.sys` ด้วย EV,
  รัน HLK, ส่ง attestation, แล้วติดตั้งบน clean Win11 VM ที่ **ปิด**
  test-signing → `signtool verify /kp` ผ่าน + driver โหลดได้
- ระดับหลักฐาน: E7; ทำในเครื่องนี้ไม่ได้เพราะไม่มี cert/บัญชี
- สิ่งที่เตรียมได้ตอนนี้: checklist + CI step + clean-VM harness (ใช้ VM
  เดียวกับ D4) และ `signtool verify /pa` สำหรับ test cert

### D2. Installer 6.0.0

- product version `5.0.0` ฝังใน source หลายจุด:
  `src/control/state_machine.zig`, `src/daemon.zig`,
  `src/control/handler_registry.zig` (version JSON),
  `src/main.zig` (banner), `src/forensic/*`
- ทางเลือก:
  - **A (แนะนำ):** คง label `5.0.0` สำหรับ v2.0.0 และ bump เป็น 6.0.0
    ครั้งเดียวรวมกับ v1.1 source batch (เลี่ยง soak เพิ่ม)
  - B: bump ตอนนี้ = source change + build + re-sign + soak + installer ใหม่
- Acceptance: ทุก surface (`status`, `version`, artifact contract,
  installer metadata) ตรงกัน; ไม่มี installer ที่ label สูงกว่า binary

### D3. Production rebuild

- ปิดได้ด้วย: CI build จาก clean checkout → hash compare กับ `SHA256SUMS`
  → ติดตั้งบน clean VM → รัน golden path
- ต้องตัดสินใจเรื่อง deterministic build (path/timestamp embedding)
- ระดับ E7; 1–2 วัน infra

### D4. Fresh-install boot model (ทำได้ตอนนี้)

- ใช้ Win11 VM เดียวกับ §5: รัน `aegis-installer-5.0.0-current.exe`
  (ที่ build แล้ว 6,130,207 bytes) บนเครื่องสะอาด
- ตรวจ: service start mode, boot ordering, driver load, uninstall,
  ไม่มี artefact ค้าง, `status` ขึ้น 7/7
- ปิดได้ที่ E5 โดยไม่ต้องมี EV cert (ยังไม่ใช่ E7)

---

## 7. ลำดับที่แนะนำ (dependency order)

```
Phase 0  (วันนี้, ไม่แตะ release)
  └─ ADR-0012 create-once measurement            → ปิด ADR-0012 หรือได้ proof
  └─ เตรียม Win11 VM                             → D4 fresh-install + §5 lab

Phase 1  (owner อนุมัติ)
  └─ D4 fresh-install test (E5)
  └─ EVI-G2 lab duplicate canary (E5)

Phase 2  (v1.1 source batch, build เดียว)
  └─ RULE-LAYER-SCOPE-001
  └─ QLOSS ETW delete filter + consumer throughput
  └─ CAPTURE-DUP-WIFI-001 (ถ้าเลือกทาง C)
  └─ D2 version bump 6.0.0
  └─ build → tests → soak 24 h → re-sign → new release tag

Phase 3  (distribution)
  └─ D3 production rebuild + hash compare
  └─ D1 EV cert + HLK/attestation → E7
```

## 8. สิ่งที่ต้องได้จากเจ้าของ (ไม่ใช่โค้ด)

1. อนุมัติสร้าง Win11 VM บน VMware (RAM/disk) สำหรับ §5 + D4
2. สาย LAN + switch สำหรับทาง A ของ `CAPTURE-DUP-WIFI-001`
3. การตัดสินใจ: `QLOSS-ISOLATION-002` จะปิดด้วย counted filter + throughput
   หรือ accepted envelope
4. EV certificate + Partner Center สำหรับ D1
5. อนุมัติ v1.1 build/soak/re-sign รอบใหม่ (ทุกข้อใน Phase 2)

## 9. กติกาหลักฐานของแผนนี้

- ทุกข้อต้องมี entry ใน `EVIDENCE_INDEX.json` พร้อม `level` จริง
- ห้ามอ้าง E5 จาก E2/E3; ห้ามอ้าง PASS จาก run ที่ไม่ได้รัน
- ทุก patch ที่แตะ `SOURCE_PATHS` ต้องมี soak 24 h ใหม่และ release ใหม่
- `release/T20-final/9ebee9b` และ tag `v2.0.0` ต้องไม่ถูกแก้
- ถ้าปิดไม่ได้เพราะข้อจำกัดภายนอก ให้บันทึกเป็น blocked พร้อมเหตุผล
  ไม่ใช่ปิดแบบไม่มีหลักฐาน
