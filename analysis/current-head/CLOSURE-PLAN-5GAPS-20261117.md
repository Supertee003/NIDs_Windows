# CLOSURE-PLAN-20261117 (rev.2) — ปิด 5 gap + 4 distribution ภายใต้โมเดล victim = เครื่อง NIDS

**Created:** 2026-11-17
**Revised:** 2026-11-17 (rev.2) — เปลี่ยนโมเดลทดสอบ: **victim = เครื่อง NIDS นี้เอง**
**Base:** v2.0.0 detection-only, build source `7c604d5`, installed runtime `7955A6E3...`,
tag `v2.0.0` → `7b484a1`
**Companion:** `docs/BACKLOG-v1.1.md`, `analysis/current-head/PROJECT-CLOSEOUT-20261117.md`

> **rev.2 แทนที่ rev.1 ทั้งฉบับ.** rev.1 ตั้งสมมติฐานว่ามี **Win11 victim VM**
> (`192.168.126.20`) เป็นเครื่องเป้าหมาย และต้องมี "host ที่สอง" สำหรับ lab
> enforcement — สมมติฐานนั้นผิดกับโมเดลปัจจุบัน จึงถูกถอดออกทั้งหมดในเอกสารนี้

---

## 0. โมเดลทดสอบใหม่ (อ่านก่อนทุกข้อ)

### 0.1 บทบาทของเครื่อง

| บทบาท | เครื่อง | ที่อยู่ / อินเทอร์เฟซ | หมายเหตุ |
|---|---|---|---|
| **Victim (เป้าหมาย)** | **เครื่อง NIDS นี้ (Windows 11 host)** | VMnet1 `192.168.126.1` (daemon), Wi-Fi `192.168.1.39` (nose) | NIDS รันบนเครื่องเดียวกับเป้าหมาย |
| **Attacker** | Kali VM (VMware, host-only) | `192.168.126.10` บน VMnet1 | สั่งโจมตีเข้ามาที่ host |
| **Sensor** | `aegis_nids.exe` ที่ติดตั้งอยู่ | `AEGIS_DAEMON_IFACE` = VMnet1 (`CE375996...`), `AEGIS_NOSE_IFACE` = Wi-Fi (`5FD31C6E...`) | เห็นทราฟฟิกจาก Kali บน VMnet1 |
| **ไม่มี** | Win11 victim VM / host ที่สอง | — | ตัดออกเพื่อลดการทดสอบ |

### 0.2 กติกาที่เปลี่ยน

1. **ทุกการทดสอบทำบนเครื่องนี้** ไม่มีการสร้าง VM ใหม่ ไม่มีการย้าย binary ไปเครื่องอื่น
2. lab enforcement ทำเป็น **maintenance window บนเครื่องนี้** โดยมี hash-verified rollback
   กลับไปยัง binary ที่ติดตั้งจริง (ดู §3.3)
3. Kali เป็น **attacker ตัวเดียว** ที่เราคุมได้ (แก้ tuple/port/เวลาได้) — ใช้ทดสอบ
   inbound canary, L7 rule scope และ network duplication
4. สิ่งที่ต้องขอจากเจ้าของคือ **อนุมัติ window** ไม่ใช่ "อนุมัติสร้าง VM"
5. ระดับหลักฐานคงเดิม: E5 = Windows host จริง (เครื่องนี้), E2 = unit/component,
   E7 = release — ห้ามอ้าง E5 จาก E2 หรือจาก run ที่ไม่ได้รัน

### 0.3 โมเดลนี้พิสูจน์อะไรได้ / ไม่ได้

**พิสูจน์ได้ (E5):** detection semantics บน payload จริง, rule-layer scope, FIM/ETW
ingress volume, WFP duplicate-filter idempotence + documented block, unblock/absence,
in-place install/uninstall, gate-closed restore

**พิสูจน์ไม่ได้ (ต้องบันทึกเป็นข้อจำกัด ไม่ใช่ปิดแบบเงียบ):**
- พฤติกรรมบนเครื่องสะอาดที่ไม่มี toolchain/Npcap/test-cert (clean-machine boot model)
- HLK/attestation บน target แยกจาก controller (`D1`)
- wire count ของเครือข่ายภายนอกจริง (Kali เป็น VM บนเครื่องเดียว จึงเป็น local traffic)
- พฤติกรรม enforcement ระยะยาว (lab window สั้น ไม่ใช่ soak)

---

## 1. ภาพรวม: 5 gap + 4 distribution (rev.3)

> สถานะล่าสุด (rev.3, 2026-11-17): `ADR-0012` **ปิดแล้ว** (E5) และ
> `EVI-G2-PEP-CACHE-001-LAB` **ปิดแบบ superseded by scope retirement** (E5) —
> เหลือ 3 gap ที่ยังทำงานได้
>
> **rev.3 แก้ rev.2 เฉพาะแถวที่ 1** — rev.2 ถือว่า G2 เป็นงาน enforcement ที่ยัง
> เปิดอยู่ ซึ่งขัดกับ `AUTHORITY_MAP.json` / `RETIRE-HOST-EFFECT-001` (issue #25)
> ที่ retire host effect ไปแล้ว เหตุผลเต็มอยู่ใน §10 และ
> `analysis/current-head/G2-ENFORCEMENT-RETIRED-20261117.md`

| # | Item | ระดับปัจจุบัน | สิ่งที่ขาดจริง | วิธีปิดบนเครื่องนี้ | แก้ source? | เวลา |
|---|---|---|---|---|---|---|
| 1 | `EVI-G2-PEP-CACHE-001-LAB` | E5 | ~~duplicate canary~~ → **ไม่มี filter ให้พิสูจน์ได้อีกแล้ว** (PEP คืน `reason=8`, `filter_id=0`) | **ปิดแล้ว 2026-11-17** — policy match ถึง PEP จริง + ABI probe ยืนยันการ retire + hash restore | ไม่ | **ปิดแล้ว** |

| 2 | `RULE-LAYER-SCOPE-001` | E1 | AC ตัวเดียวใช้ rule ข้าม layer กับ network bytes | แยก AC ตาม layer + pins + build + soak | **ใช่** | 1–2 วัน + soak |
| 3 | `CAPTURE-DUP-WIFI-001` | E5 | frame ซ้ำบน Wi-Fi/Npcap นี้ | ทดลอง config Npcap ก่อน → ถ้าไม่หาย ใช้ counted dedup ใน Nose | อย่างหลังใช่ | 1 ชม. หรือ 2–3 วัน + soak |
| 4 | `GAP-QLOSS-ISOLATION-002` | E2 | ingress FIM/ETW จาก storm ไม่ลด | ETW delete filter + consumer throughput (หรือ accepted envelope) | **ใช่** | 2–4 วัน + soak |
| 5 | `ADR-0012-DUP-RATIO-E5` | E5 | ยังไม่พิสูจน์ว่า repeat = distinct open | create-once unique-path measurement บนเครื่องนี้ | ไม่ | **ปิดแล้ว 2026-11-17** |
| D1 | Driver signing (EV + attestation/HLK) | — | ไม่มี EV cert/Partner Center และไม่มี target แยก | ภายนอกเครื่องนี้ | ไม่ | สัปดาห์ |
| D2 | Installer 6.0.0 label | — | product version `5.0.0` ใน source | รวมใน v1.1 build เดียว | **ใช่** | รวม v1.1 |
| D3 | Production rebuild | — | ยังไม่ rebuild จาก source เพื่อ cut | CI/clean checkout + hash compare บนเครื่องนี้ | ไม่ | 1–2 วัน |
| D4 | Fresh-install boot model | — | ยังไม่ทดสอบ install บนเครื่องสะอาด | **in-place reinstall บนเครื่องนี้** (จำกัดขอบเขต) | ไม่ | 1–2 ชม. |

### 1.1 ผลกระทบของโมเดลใหม่ต่อแผนเดิม

| หัวข้อ | แผนเดิม (rev.1) | แผนใหม่ (rev.2) |
|---|---|---|
| `EVI-G2` | สร้าง Win11 VM เป็น lab host | window บนเครื่องนี้ + Kali + hash rollback |
| `CAPTURE-DUP-WIFI` | ต้องต่อสาย Ethernet หรือเปลี่ยน adapter | ทดลอง Npcap config บนเครื่องนี้ก่อน (ไม่มีค่าใช้จ่าย) แล้วจึง dedup |
| `RULE-LAYER-SCOPE` E5 | Kali + Win11 target | Kali → host service บน VMnet1 + local positive controls |
| `QLOSS` / `ADR-0012` | เหมือนเดิม (วัดบน host) | เหมือนเดิม แต่ชัดว่าไม่ต้องใช้ VM เลย |
| `D4` | Win11 VM สะอาด | in-place uninstall/reinstall + ระบุข้อจำกัด |
| สิ่งที่ขอจากเจ้าของ | อนุมัติสร้าง VM | อนุมัติ maintenance window + การยอมรับข้อจำกัด |

---

## 2. ข้อเท็จจริงของเครื่อง ณ 2026-11-17 (ใช้ตัดสินความเป็นไปได้)

**Runtime ที่ติดตั้งจริง** (`C:\Program Files\AEGIS NIDS\runtime\`):

| ไฟล์ | SHA256 | ขนาด |
|---|---|---|
| `aegis_nids.exe` | `7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18` | 5,247,488 |
| `aegis_nids.exe.prev` | (backup ของรอบก่อน) | 5,241,856 |
| `aegis_pep.dll` | `362B069AFF007B6C72494D2B9E689893C1A8EB559B8266B38534AA17D543D118` | 2,702,336 |
| `aegis_wfp_user.dll` | `76B46CD6073C6B78918821B19D1A2A9E581EE8481E5BE2740809432454962E1A` | 14,336 |
| `aegis_minifilter.sys` | `8AC348372321ECFE5BD535B9A9A19F6F6567C58145395359764AFCAF5C2480E0` | 11,752 |
| `aegis_wfp.sys` | `06CC8E238B79BEC3782F4036BACF058D6B5291B030E59D061FD692F82FB96B50` | 42,896 |

**ข้อเท็จจริงที่สำคัญ:**

- `aegis_wfp.sys.bak` / `.pre-evt213` = `D58E2EEF...` (11,640 B) → มี backup เก่า แต่
  **ไม่ใช่** รุ่นที่ติดตั้งปัจจุบัน; rollback ต้องใช้ hash ที่บันทึกใน §3.2 ไม่ใช่ `.bak`
- build output ปัจจุบัน: `build\x64\wfp\aegis_wfp.sys` = `2ECE7D52...` (41,472 B)
  **ต่างจาก driver ที่ติดตั้ง** (`06CC8E23...`, 42,896 B) และ
  `shield\target\release\aegis_pep.dll` **ไม่มีอยู่** → **ห้ามสลับ driver จาก build ใหม่**
  ใน lab window นี้; ใช้ signed driver ที่ติดตั้งอยู่เท่านั้น
- gate เป็น **compile-time**: `zig build -Dlab-prevention-gate=true`
  (`build.zig:25`, `src/daemon.zig:615-634`); เปิดเมื่อ PEP available + provider ready +
  tier3 ready + forensic ring; เป็น **in-memory** (restart = ปิดกลับ) และเขียน
  `lab_prevention_gate_open` ลง forensic log
- `AegisNids` = Running / Manual; `AegisWfp` มีอยู่แยก
- VMnet1 = `192.168.126.1`, VMnet2 = `192.168.127.1`; Kali VMX = `hostonly`
  (ปัจจุบัน **Kali ไม่ได้รัน** — ต้องสตาร์ทจาก snapshot)
- `netsh wfp show filters` ต้อง **elevation** (ทดสอบแล้ว: `error 5` เมื่อไม่ elevated)
- lab kit v2 อยู่ที่ `admin-evidence/g2-direction-20261022/lab-kit-20261022-v2/`
  (daemon/PEP/bridge/driver + 4 สคริปต์ + RUN-CHECKLIST + SHA256SUMS)
  **แต่สคริปต์ hardcode** `C:\AEGIS\NIDs_Windows\tools`, `SRC_IP=192.168.126.1`,
  `DST_PORT=443` → ต้องทำ **kit v3** (§3.1)
- หลักฐานเดิม `G2-DUPFILTER-HOST-PROOF-E5-20261028` (E5 PASS) พิสูจน์ duplicate filter
  idempotence ด้วย direct-PEP harness บน driver `49E65BB1...` / PEP `C7F2...` /
  bridge `2E7F...` และถูกทำเครื่องหมาย `historical: true` → ต้อง re-run บน hash ปัจจุบัน
- หลักฐาน 2026-10-23: filter `78056` เป็นตัวบล็อก duplicate canary ก่อนถึง PEP
  → **อย่าลบ filter ที่ไม่รู้ที่มา**; ใช้ tuple ใหม่ (port 8443) และ enumerate ก่อน

---

## 3. `EVI-G2-PEP-CACHE-001-LAB` — **SUPERSEDED 2026-11-17** (อ่าน §10 ก่อน)

> rev.3: ขั้นตอนใน §3.1–§3.7 ถูกเก็บไว้เป็นประวัติ แต่ **ใช้ไม่ได้กับ source ปัจจุบัน**
> เพราะ PEP ตอบ `reason=8` (`detection-only: host effect retired by product scope`)
> และไม่สร้าง filter id ให้ตั้งแต่ต้น ผลจริงของ window 2026-11-17 อยู่ใน §11

### 3.1 สิ่งที่ขาดจริง และเกณฑ์ที่ Gap นี้ยอมรับอยู่แล้ว

`expected` ของ gap นี้เขียนไว้ตั้งแต่ต้นว่า duplicate canary ต้องได้
**"a second confirmed quarantine/receipt หรือ a documented block"**
→ การปิดด้วย documented block **ไม่ใช่การเลื่อนประตู** แต่ต้องพิสูจน์ให้ครบว่า:

1. block ที่เกิด **มาจาก filter ของ AEGIS** (filter id เดียวกัน, direction inbound,
   remote = Kali `192.168.126.10`, port ที่ยิง)
2. ไม่มี **escalate reason=4** และไม่มี **filter ซ้ำใหม่**
3. **counter ไม่บวกซ้ำ** (`confirmed_quarantines` คงที่) = block เป็น idempotent
4. หลัง unblock แล้ว canary **ผ่านได้จริง** (reachability กลับมา)

### 3.2 Preflight ( elevated, บันทึกทุกค่า )

1. หยุด `AegisNids` และ `AegisWfp`; บันทึก `Get-Service` state
2. hash ทั้ง runtime dir + driver → `admin-evidence/g2-single-host-<ts>/preflight-hashes.json`
3. backup ทั้ง `C:\Program Files\AEGIS NIDS\runtime\` + `C:\Windows\System32\drivers\aegis_wfp.sys`
   ไป `admin-evidence/g2-single-host-<ts>/backup/` (พร้อม hash)
4. `netsh wfp show filters file=preflight-filters.xml` + proof filter count (ต้องเป็น 0
   ก่อนเริ่ม; ถ้าไม่ใช่ 0 ให้ระบุที่มาและหยุด)
5. ตรวจว่า port 8443 ไม่มี listener และไม่มี filter ค้างที่ match tuple นี้
6. บันทึก `AEGIS_DAEMON_IFACE` / `AEGIS_NOSE_IFACE` และ Kali snapshot ปัจจุบัน

### 3.3 Lab build (ไม่แตะ release, ไม่แตะ driver)

```powershell
zig build -Dlab-prevention-gate=true
# ได้ zig-out\bin\aegis_nids.exe (lab) — บันทึก hash ว่าเป็น LAB ARTIFACT
```

- **ไม่** คัดลอก `aegis_wfp.sys` จาก build ใหม่ (hash ต่างจาก installed)
- **ไม่** แตะ `release/T20-final/9ebee9b`, tag `v2.0.0`, หรือ `SHA256SUMS`
- binary ที่ swap มีเพียง `aegis_nids.exe` (และ `aegis_pep.dll` **เฉพาะเมื่อ** ต้องการ
  cache variant — ต้อง build จาก `shield/` และบันทึก hash)
- เก็บ binary เดิมเป็น `aegis_nids.exe.prev` (มีอยู่แล้ว) + backup ใน §3.2

### 3.4 ติดตั้ง lab และพิสูจน์ว่า gate เปิดเฉพาะ lab

1. copy lab binary ไป runtime dir
2. start `AegisWfp` → `AegisNids`
3. ต้องเห็น log `LAB: prevention gate OPEN` / forensic `lab_prevention_gate_open`
   และ `tier3_enforcing=true`
4. ถ้า gate ไม่เปิด → **หยุด** และ rollback (ไม่ใช่แก้ config ให้เปิด)

### 3.5 รัน canary (Kali = attacker)

ต้องมี **listener scoped** บน host ที่ bind `192.168.126.1:8443` และ log บรรทัด ACCEPT
(ใช้สคริปต์ชั่วคราวใน `admin-evidence/.../listener.py`; ปิดทันทีเมื่อจบ)

| ขั้น | การกระทำ | ต้องได้ |
|---|---|---|
| C1 | Kali: `connect 192.168.126.1:8443` (canary #1) | listener ACCEPT + policy match (dst_port 8443) + PEP quarantine confirmed + filter id **F** |
| C2 | query filter F (elevated) | layer `ALE_AUTH_RECV_ACCEPT_V4`, action BLOCK, remote `192.168.126.10`, port 8443, proto 6 |
| C3 | direction-aware verify F | `verified=true, present=true, direction=1, postcondition=MATCH` |
| C4 | Kali: canary #2 tuple เดิม | `BLOCKED_OR_TIMEOUT` ≤ 3 s |
| C5 | ระหว่าง C4: metrics + filter inventory | `confirmed_quarantines` **ไม่เพิ่ม**; filter count ไม่เพิ่ม; ไม่มี filter id ใหม่; ไม่มี escalate reason=4 |
| C6 | unblock F (receipt-aware) | `ROLLED_BACK`/`ABSENT`, postcondition ABSENT, proof count 0 |
| C7 | Kali: canary #3 | ACCEPT (reachability กลับมา) |

**บันทึกเป็น documented block** เมื่อ C4–C5 ครบ; ถ้า C4 ได้ ACCEPT และเกิด quarantine
ครั้งที่สอง ก็ปิดได้เช่นกัน (บันทึก counter +1 + filter id เดิม) — ทั้งสองทางเป็นผลที่
gap ยอมรับ แต่ต้องมีหลักฐานตรงตามที่เกิดขึ้นจริง

### 3.6 เสริม (ไม่บังคับแต่แนะนำ): direct-PEP duplicate harness บน hash ปัจจุบัน

รัน `scripts/run_g2_dupfilter_proof.ps1` (elevated) เพื่อพิสูจน์ idempotent duplicate
add บน **driver/PEP/bridge hash ที่ติดตั้งอยู่จริง** — เป็นการ refresh หลักฐาน
`G2-DUPFILTER-HOST-PROOF-E5-20261028` ที่เป็น `historical` ให้ตรงรุ่น

### 3.7 Rollback + ปิด window (ขาดไม่ได้)

1. หยุด `AegisNids` / `AegisWfp`
2. คืน binary จาก backup §3.2 (copy ทับ + `Get-FileHash` เทียบ **ทุกไฟล์**)
3. คืน `aegis_wfp.sys` เฉพาะเมื่อมีการแตะ (แผนนี้ไม่แตะ)
4. start กลับ; ตรวจ `prevention_gate=closed`, `tier3_enforcing=false`,
   `host_effect_capable=false`, proof count 0
5. ลบ listener / firewall rule / lab policy / trust ที่สร้างใน window
6. ตรวจ `aegisctl status` 7/7 + queue ปกติ; เก็บหลักฐาน rollback hash

**Acceptance:** C1–C7 ครบ + rollback hash ตรงทุกไฟล์ + gate closed + proof count 0
+ ไม่มี artifact ของ lab หลุดเข้า release tree

**ความเสี่ยง:** window นี้ "บล็อกทราฟฟิกเข้าจริง" บนเครื่องที่ใช้ทำงาน → จำกัดที่
tuple เดียว/port เดียว, ทำนอกเวลาที่ต้องเฝ้า, เตรียม console ในเครื่องไว้, และ
ปิด filter ทันทีเมื่อจบ (C6)

---

## 4. `RULE-LAYER-SCOPE-001` (P3, E1 → ต้องเป็น E5)

### 4.1 ข้อเท็จจริง

- `src/pipeline/rule_loader.zig:301-328` โหลดทุก rule ที่ไม่ใช่ L4 เข้า AC **ตัวเดียว**
  (`g_active_ac`) โดยไม่เก็บ `layer`
- `src/pipeline/event_processor.zig:280-299` รัน AC กับ payload ของทุก source
  (ยกเว้น `capture_host_net`)
- `configs/Rules.json` 23 rules: L7 5, KERNEL_FILE 5, KERNEL_PROCESS 5, L2_PIPE 5, L4 3
- ผล: TLS/HTTP bytes ที่มีคำว่า `IEX` ถูกตีเป็น R2003 (KERNEL_PROCESS) ทั้งที่เป็น network

### 4.2 Patch (v1.1 source batch)

1. `rule_loader.zig`: parse `layer` → สร้างชุด AC แยก `network` (L7), `kernel_file`,
   `kernel_process`, `l2_pipe`; swap ทั้งชุดใต้ `g_ac_mutex` แบบ atomic (hot reload คงเดิม)
2. `runtime_state.zig`: pointer ต่อ layer + counter จำนวน rule ต่อ layer
3. `event_processor.zig`: เลือกชุดตาม `ev.source`
   - `capture_npcap` / `capture_wfp` → network (L7)
   - `capture_fim` / minifilter → kernel_file
   - `capture_etw` process → kernel_process; registry → kernel_file
   - pipe → l2_pipe
   - source ที่ไม่รู้จัก → **ไม่รัน AC** + counter `ac_skipped_unknown_source`
4. pins: TLS ที่มี `IEX` ต้องไม่ได้ R2003; HTTP `<script>` ต้องได้ R9059; FIM path ที่มี
   `IEX` ต้องไม่ได้ R2003; cmdline ที่มี `IEX` ต้องได้ R2003; จำนวน rule ต่อ layer ครบ 23;
   reload แล้วชุดใหม่ถูกใช้จริง

### 4.3 E5 บนเครื่องนี้ (ไม่ต้องมี VM)

1. เปิด listener HTTP บน host (VMnet1:8080) และยิงจาก Kali: `<script>alert(1)</script>`,
   `' OR 1=1`, `../../etc/passwd`, และ payload ที่มี `IEX` / `mimikatz` /
   `C:\Windows\System32` (TLS-like bytes)
2. **ต้องได้**: R9059 / R0056 / R0088 จาก `capture_npcap` ตามจริง
3. **ต้องไม่ได้**: R2001–R2005, R1001–R1005, R3001–R3005 จาก network source
4. Positive controls บน host: PowerShell cradle ที่มี `IEX` → R2003;
   สร้างไฟล์ `.locked` ใน temp → R1002; named pipe `MSSE-` → R3001
5. ตรวจ attribution ด้วย `aegisctl forensics` (source + rule + layer) — ต้องแยกได้ชัด

**Acceptance E5:** ข้อ 1–5 ผ่านใน RB-022 window เดียว, ไม่มี restart, ไม่มี
dropped/shed delta ที่อธิบายไม่ได้

---

## 5. `CAPTURE-DUP-WIFI-001` (P3, E5)

### 5.1 ข้อเท็จจริง

- Wi-Fi (Killer AX1650i) + Npcap 1.10.6: ทุกเฟรมมาสองครั้ง (`ip.id`/TCP seq/bytes เดียวกัน
  ห่าง ~7 µs) — VMnet1 control ไม่ซ้ำ
- `dumpcap -y IEEE802_11` → `IEEE802_11 is not one of the DLTs supported by this device`
  แม้ `Dot11Support=1`
- Killer E2600 Ethernet มีแต่สายไม่ต่อ (`Disconnected`)
- **ผลจากโมเดลใหม่:** ทราฟฟิก lab ทั้งหมดมาจาก Kali บน **VMnet1** ซึ่งไม่ซ้ำ →
  duplication กระทบเฉพาะ **production nose path (Wi-Fi)** ไม่ใช่ detection semantics

### 5.2 ลำดับการปิด (ถูกที่สุดก่อน)

**A. ทดลอง config Npcap (ไม่แก้ source — ทำก่อน)**
1. ตั้ง `Dot11Support=0` (หรือติดตั้ง Npcap ใหม่แบบไม่ raw 802.11) แล้ว reboot
2. วัดซ้ำด้วย `dumpcap` handle เดียวบน Wi-Fi ระหว่าง Kali bridged ยิง canary
3. ถ้า duplication หาย → **ปิด gap ที่ E5 ด้วย deployment config** (บันทึกค่า registry,
   hash ของ Npcap, ก่อน/หลัง, และข้อจำกัดว่าเป็นการตั้งค่าเครื่อง ไม่ใช่โค้ด)
4. ถ้าไม่หาย → คืนค่าเดิม (`Dot11Support=1`) แล้วไปข้อ B

**B. Counted dedup ใน Nose (Go; ต้อง build + soak)**
- key `(ip.id, tcp.seq, direction, payload hash)` ภายในหน้าต่าง < 1 ms, เก็บเฟรมแรก,
  นับที่เหลือใน `nose_dedup_suppressed`
- pins: retransmission จริงที่ +200 ms **ต้องไม่ถูกกลืน**; payload ต่างต้องไม่ถูกกลืน;
  TCP seq reuse หลัง window ต้องผ่าน
- Acceptance: canary บน Wi-Fi ได้ 1 row ต่อ stimulus, counter > 0, pin ผ่าน,
  ไม่มี event loss อื่น

**C. Ethernet (ถ้ามีสาย)** — ยังใช้ได้ แต่ไม่ใช่เงื่อนไขของแผนแล้ว เพราะไม่มีสาย
และ traffic ของ Kali VM จะออกทาง host อยู่ดี

**ห้าม:** dedup ใน Zig pipeline หลัง admission (ทำให้ loss มองไม่เห็นที่ producer)

---

## 6. `GAP-QLOSS-ISOLATION-002` + `ADR-0012-DUP-RATIO-E5`

### 6.1 ข้อมูลสดจาก daemon ที่ติดตั้ง (2026-11-17)

| counter | ค่า |
|---|---|
| `pushed_total` | 40,742,151 |
| `source_quota_shed` / `dropped_total` | 4,321 / 4,321 |
| `shed_overload` | 23,437 |
| `source_occupancy_cap` | 7,168 |
| `capture_etw` pushed / dropped | 31,394,792 / 4,321 |
| `capture_fim` pushed | 2,412,363 |
| ETW `file_name_delete` → `fim_change` | **18,151,604** |
| ETW `file_write_filtered` | 15,510,237 |
| `name_create_deduped` | 20,346,756 |
| `fim_probe` duplicates | 1,147,079 (47.5%) |
| `...duplicates_per_pid` | 1,012,763 |
| `...duplicates_same_ts` | 639,915 |
| `fim_probe.batch_overflow` | 0 |

**ข้อสรุป 2 ข้อ:** (1) lane ใหญ่สุดคือ **ETW NameDelete 18.15M** ไม่ใช่ minifilter 2.4M
→ ลด minifilter ไม่ช่วย ETW quota; (2) `duplicates_same_ts` **ไม่ใช่หลักฐาน duplicate
delivery** เพราะ `KeQuerySystemTime` granularity ~15.6 ms

### 6.2 Phase 1 — ปิด `ADR-0012` ด้วยการวัดบนเครื่องนี้ (ปิดแล้ว 2026-11-17)

**ผลลัพธ์จริง:** create-once 1,000 ไฟล์ (churn 0.304 s) → 1,015 records / 6
per-PID repeats เทียบ ambient 0.7; create-once 20,000 ไฟล์ (churn 5.822 s) →
20,042 records / 12 repeats เทียบ ambient 11.8 (excess 0.2, ratio ~0.00001)
→ **ไม่มีการส่งซ้ำที่ delivery layer**; repeat 47.5% ในงานจริง = distinct opens
→ **minifilter coalescer ถูก reject** และปิด gap ที่ E5
(evidence `ADR-0012-SINGLE-HOST-E5-20261117`, record
`ADR-0012-DECISION-20261117.md`) — ไม่ต้อง restart, ไม่แตะ source/release

ขั้นตอนที่ใช้ (เก็บไว้ทำซ้ำได้):

1. สร้าง `D:\tmp\aegis-storm-<ts>\` + ledger (path, pid, op, timestamp)
2. อ่าน `fim_probe` baseline (idle 60 s)
3. churn **ชื่อไฟล์ไม่ซ้ำ ไฟล์ละหนึ่งครั้ง** (สร้าง+เขียน+ปิด) จำนวนคงที่ (เช่น 20,000)
4. อ่าน `fim_probe` อีกครั้ง + Δ `minifilter.dropped`, `ring_written`, `pipeline_dropped`
5. ตีความ:
   - `Δduplicates_per_pid` ไม่เพิ่มตามจำนวนไฟล์ → **ไม่มีการส่งซ้ำ**; 47% ในงานจริง =
     distinct opens → **ADR-0012 = Rejected (ห้าม suppressing coalescer)** ปิดด้วย
     decision record + ตัวเลข
   - เพิ่มตามจำนวนไฟล์ → มี duplicate delivery จริง → ทำ coalescer ที่มี identity + counter

**Acceptance:** decision record ที่มี Δrecords/Δduplicates/Δper_pid + ledger count +
ช่วงเวลา + hash ของ build ที่ติดตั้ง

### 6.3 Phase 2 — ปิด `QLOSS-ISOLATION-002` (แก้ source + soak)

1. **`QLOSS-ETW-DELFILTER-001`**: drop ETW `NameDelete` ที่ไม่ match rule path ใดเลย
   + counter `file_delete_filtered` + **mass-delete aggregate** (summary 1 row เมื่อเกิน
   threshold) เพื่อไม่ให้ ransomware mass-delete มองไม่เห็น
2. **Consumer throughput**: batched forensic append (ADR-0010 item 2) — semantics-neutral
3. **Accepted envelope** (ถ้าวัดแล้ว volume เป็นของจริงและ 2 แนวบนไม่คุ้ม): ระบุ budget +
   counter + owner sign-off — ต้องเรียกว่า decision ไม่ใช่ "แก้แล้ว"

**Acceptance (E5):** churn ชุดเดิม + soak 24 h → `source_quota_shed`/`shed_overload`
ลดลงเทียบ baseline, `minifilter.dropped=0`, ring 0, readiness ไม่ผ่อน, pin ว่าของที่ควรเข้าไม่ถูกทิ้ง

---

## 7. Distribution (4 ข้อ) ภายใต้โมเดลเครื่องเดียว

### D1. EV + attestation/HLK — ยังอยู่นอกเครื่องนี้ (blocked)

- ต้องมีนิติบุคคล + EV cert (HSM/token) + Partner Center + HLK ที่มี **target แยกจาก
  controller** → เครื่องเดียวทำไม่ได้จริง (และ Kali เป็น Linux ใช้เป็น target ไม่ได้)
- สิ่งที่เตรียมได้ตอนนี้: checklist, CI step, และ `signtool verify /pa` สำหรับ test cert
- **ห้าม** เรียก test-signed driver ว่า production-signed

### D2. Installer 6.0.0 — คงไว้ใน v1.1 batch

- version `5.0.0` ฝังใน `src/control/state_machine.zig`, `handler_registry.zig`
  (version JSON), `src/main.zig` (banner), `src/forensic/*` และ cargo package
- แนะนำ: คง `5.0.0` สำหรับ v2.0.0 แล้ว bump `6.0.0` **ครั้งเดียว** รวม v1.1 build
  (เลี่ยง soak เพิ่ม); ถ้า bump ตอนนี้ = build + re-sign + soak ใหม่
- Acceptance: ทุก surface ตรงกัน; ไม่มี installer ที่ label สูงกว่า binary

### D3 + D4. Production rebuild + in-place reinstall (ทำได้บนเครื่องนี้)

1. backup runtime + drivers + configs (hash ทั้งหมด)
2. build จาก clean checkout → เทียบ hash กับ `SHA256SUMS` ของ release (ถ้าไม่ตรง ให้
   บันทึกสาเหตุ เช่น path/timestamp embedding — ไม่ใช่แก้ให้ตรง)
3. uninstall ด้วย uninstaller ที่มี (`aegis-installer-5.0.0-current.exe`, 6,130,207 B)
4. reinstall จาก installer เดียวกัน → ตรวจ hash ของทุกไฟล์ที่ติดตั้ง
5. `aegisctl status` 7/7, `queue` ปกติ, canary smoke จาก Kali 1 ครั้ง
6. reboot → ตรวจ service start ordering / driver load / ไม่มี artifact ค้าง
7. uninstall ซ้ำเพื่อพิสูจน์ idempotence แล้วติดตั้งกลับ

**ข้อจำกัดที่ต้องบันทึก (ไม่ใช่ปิดเงียบ):** นี่ไม่ใช่ clean-machine boot model —
เครื่องนี้มี toolchain/Npcap/test-cert อยู่แล้ว; ถ้าต้องการหลักฐาน clean machine
ต้องกลับไปใช้ Win11 VM (ISO พร้อม) ซึ่งอยู่นอกแผนนี้และต้องขออนุมัติใหม่

---

## 8. ลำดับที่แนะนำ (dependency + window)

```
Phase 0  (ไม่แตะ release, ไม่ต้อง window)
  ├─ ADR-0012 create-once measurement บนเครื่องนี้      → DONE (ปิดแล้ว)
  └─ CAPTURE-DUP config experiment (Dot11Support=0)     → ปิดได้หรือได้ตัวเลข

Phase 1  (ต้องอนุมัติ maintenance window)
  ├─ EVI-G2: lab build + canary จาก Kali + documented block + rollback
  └─ D3+D4: in-place reinstall + reboot + smoke

Phase 2  (v1.1 source batch, build เดียว + soak 24 h)
  ├─ RULE-LAYER-SCOPE-001
  ├─ QLOSS ETW delete filter + consumer throughput
  ├─ CAPTURE-DUP Nose dedup (ถ้า config ไม่หาย)
  └─ D2 version bump 6.0.0
       → build → tests → soak 24 h → re-sign → release ใหม่

Phase 3  (distribution, ภายนอก)
  └─ D1 EV + HLK/attestation → E7
```

---

## 9. สิ่งที่ต้องได้จากเจ้าของ (rev.2)

1. **อนุมัติ maintenance window บนเครื่องนี้** สำหรับ EVI-G2 (มีช่วงที่ inbound
   ถูกบล็อกที่ port เดียว) และ D3+D4 (uninstall/reinstall + reboot)
2. **อนุมัติการสตาร์ท Kali** จาก snapshot และใช้ host-only `192.168.126.10`
3. **ตัดสินใจ QLOSS**: counted filter + throughput หรือ accepted envelope
4. **ยอมรับข้อจำกัด** ของ in-place reinstall (ไม่ใช่ clean machine)
5. **อนุมัติ v1.1 build/soak/re-sign** รอบใหม่ (Phase 2)
6. **EV cert + Partner Center** สำหรับ D1 (เมื่อพร้อม)

---

## 10. กติกาหลักฐานของแผนนี้

- ทุกข้อต้องมี entry ใน `EVIDENCE_INDEX.json` พร้อม `level` จริง
- ห้ามอ้าง E5 จาก E2/E3; ห้ามอ้าง PASS จาก run ที่ไม่ได้รัน
- ทุก patch ที่แตะ `SOURCE_PATHS` ต้องมี soak 24 h ใหม่และ release ใหม่
- `release/T20-final/9ebee9b`, tag `v2.0.0`, `SHA256SUMS` ต้องไม่ถูกแก้
- lab binary / lab driver ต้องไม่ถูกทิ้งไว้บนเครื่องหลังจบ window (hash rollback ต้องผ่าน)
- ถ้าปิดไม่ได้เพราะข้อจำกัดภายนอก ให้บันทึกเป็น blocked พร้อมเหตุผล ไม่ใช่ปิดแบบไม่มีหลักฐาน

---

## 11. rev.3 amendment — G2 ถูกปิดเพราะ scope retire (2026-11-17)

**ผลจริงของ window (ไม่ใช่ผลตามแผน §3):**

1. lab daemon `F805F4DC...` + v2 signed lab policy (`71d93534...`, key_id 42,
   envelope VALID) ทำงาน: `GATE=open`, `POLICY_VALID=True`, `TIER3_ENFORCING=True`
2. canary payload (SQLi) จาก Kali `192.168.126.10` → host `192.168.126.1:443`
   **match policy 3 จริง** (audit `policy=3`, `rule=2107512682`)
3. แต่ `decision=escalate` — direct FFI probe ของ `aegis_pep.dll` ที่ติดตั้งให้
   `reason=8`, `filter_id=0` ทั้ง block และ quarantine (reason 8 =
   detection-only, host effect retired by product scope, issue #25)
4. จึงไม่มี filter id: ขั้น direction verify / duplicate filter / unblock /
   reachability canary **รันไม่ได้และไม่ได้รัน**
5. restore ผ่านครบ: daemon `7955A6E3...`, PEP `362B069A...`, driver `06CC8E23...`,
   policies `B7224FA0...`, sig/trust absent, env `AEGIS_LOSS_BUDGET=3500`,
   firewall 0, `WFP_PROVIDER_FILTERS=0`, gate closed, detection-only

**สถานะ:** `EVI-G2-PEP-CACHE-001-LAB-20261023` = CLOSED (superseded) ที่ E5,
evidence `G2-ENFORCEMENT-RETIRED-E5-20261117`,
รายละเอียด `analysis/current-head/G2-ENFORCEMENT-RETIRED-20261117.md`

**ผลต่อแผน:** Phase 1 ไม่มีงาน EVI-G2 เหลือ; เหลือ D3+D4 (in-place
uninstall/reinstall) ใน window ถัดไป — และ Phase 2 (v1.1 source batch) ไม่ต้องมี
งาน enforcement ใด ๆ เพราะไม่อยู่ใน product scope

**Stop-the-line ที่พบและแก้แล้ว:** rev.2 นับ G2 เป็น gap ที่ยังเปิด ซึ่งเป็น
เอกสารขัดกับ `AUTHORITY_MAP.json` (issue #25 ปิดแล้ว) — แก้ที่เอกสารเท่านั้น
ไม่แตะ source/driver/PEP/release
