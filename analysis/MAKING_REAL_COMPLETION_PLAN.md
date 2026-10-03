# AEGIS NIDS Windows — “ทำให้เป็นจริงตามที่อ้างไว้” Completion Plan

**Repository:** `D:\NIDs_Windows`  
**HEAD:** `42f95c0a00f526c06a6e9a3d856b6af66c51e683`, branch `main`, working tree dirty  
**เมื่อ:** 2026-10-03 (ช่วงหลัง deploy `aegis_nids.exe` ใหม่แล้ว)  
**โหมดหลัก:** elevated สำหรับขั้นที่แตะ service / driver / WFP / registry / file ใน `C:\Program Files\AEGIS NIDS`; non-elevated สำหรับไฟล์ใน repo และสอบถามสถานะ  

## 1. จุดเริ่มต้นจริงตอนนี้ (จาก host probe ล่าสุด)

### 1.1 สิ่งที่ “เป็นจริงแล้ว” หลังจากผ่านรอบก่อน
- [x] **config resolution:** `src/core/runtime_paths.zig` / `src/daemon.zig` / `src/pipeline/rule_loader.zig` แก้ให้แก้จากตำแหน่ง exe ไม่ใช่ cwd แล้ว — รันจาก `C:\Windows\System32` ได้ `loaded 22 rules` / `loaded 6 policies` และถ้าบันเดิลขาด config จะ `refuse to start`
- [x] **deploy binary:** `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe` ปัจจุบันคือ ReleaseFast build ตอนนั้น; SHA ตรงกับ `zig-out/bin/aegis_nids.exe` ใน repo (เท่ากัน)
- [x] **api/reporting honesty:** control_api ปัจจุบัน expose `rules_loaded`/`policies_loaded` จาก daemon แล้ว; `aegisctl status --component brain` ไม่หลอกว่า RUNNING
- [x] **enforcement posture:** `aegisctl enforce status` → `mode=detection-only, prevention_gate=closed, tier3_enforcing=false, host_effect_capable=false` (ไม่อ้าง host effect ที่ไม่มี)
- [x] **integrity channels (repo ในเครื่อง):**
  - `tools/truth.py verify` → `TRUTH_VALID`
  - `tools/release_engineering.py --verify` → `OK 516 artifacts` (source_commit=42f95c0)
  - `tools/create_manifest.py --verify` → `manifest_drift_fixed PASS / core_restored_per_request PASS`
- [x] **tests:** `tests/runtime + security + release` → 300 passed / 4 skipped (เมื่อไฟล์ไม่เปลี่ยนเพิ่ม)

### 1.2 สิ่งที่ยัง “ไม่จริง” บน host นี้ (จาก probe ล่าสุด)
- [ ] **WFP stale host effect:** มีกฎ Windows Firewall ที่ตั้งชื่อ AEGIS ค้างจำนวนมาก — จากหลักฐาน non-elevated ล่าสุดมี **73 กฎ** ที่ match “AEGIS” (รวมถึงกฎชื่อ `AEGIS_BLOCK_10.0.0.99` หลายกฎ)  
  ⚠️ **ยืนยันไม่ได้ว่า filterId 7023741 / 7088032 / 7041677 ยังอยู่หรือหายแล้ว** ในรอบนี้ เพราะ `netsh wfp show state` เขียน XML ไม่ได้โดยไม่ elevated; เรามีแต่กฎ firewall ระดับผู้ใช้เท่านั้น
- [ ] **driver provenance / signing:** `AegisWfp` รันจาก `System32\drivers\aegis_wfp.sys`; ในรอบก่อนมีเครื่องหมายว่า test-signed / BCD testsigning Yes / exe+dll NotSigned — ยังต้องยืนยันใหม่
- [ ] **service lifecycle:** ทั้ง `AegisNids` และ `AegisWfp` ยัง `DEMAND_START` + `sc qfailure` ว่าง (no recovery) — ยืนยันจาก state ปัจจุบัน; ไม่มี restart-on-failure
- [ ] **ETW honesty:** health ปัจจุบันบอก `etw_ready=true` แต่ `etw.running_sessions_matching_aegis = []` จาก probe ล่าสุด — ยังต้องดูว่า session จริงมีหรือไม่ หรือ field นี้にすぎุโรป็ยังเป็น “claim vs reality”
- [ ] **legacy install ซ้ำ:** `C:\Program Files\AEGIS` ยังอยู่ (11 files) — ยืนยันจาก probe ล่าสุด
- [ ] **driver service ซ้ำ:** มี service `aegis_wfp` (Stopped) + `AegisWfp` (Running) โ RM နှစ်ตัว
- [ ] **data plane / brain / aggregator / dashboard ยังไม่มี process:** ไม่มี listener 9999/9200, ไม่มี brain UDP, ไม่มี nose/aggregator ตาม probe ล่าสุด — นี่เป็น omitted-by-design ใน scope นี้หรือไม่ ต้องชี้แจง

## 2. เป้าหมาย “ครบ 100%” ในความหมายที่วัดได้ (acceptance)

เมื่อทำครบ หมายถึงวัดได้จาก **ทั้งหมดต่อไปนี้** บน host นี้:

1. **Control daemon (AegisNids) พร้อมใช้งานจริง:** `health` → `state=RUNNING`, `degraded=false`, `rules_loaded=22`, `policies_loaded=6`, worker ทุกตัว `ready=true`; `aegisctl readiness` → `ready=true, overall_gate=true`
2. **Posture ไม่อ้างขึ้นเอง:** `enforce status` → `mode=detection-only`, `prevention_gate=closed`, `tier3_enforcing=false`, `host_effect_capable=false`, `host_effect_confirmed=false`
3. **Removal of unowned stale host effect:** ไม่มีกฎ/filter AEGIS ค้างที่ไม่มี owner/process ปัจจุบันอ้างอิง — อย่างน้อยที่สุด ต้อง **capture & ล้างส่วนที่ proven ว่า stale** พร้อม before/after
4. **Driver provenance & signing:** driver `.sys` ที่โหลด้อยู่ must มี provenance ชัดเจนใน manifest และสถานะ signing ต้องระบุให้ได้ว่าใช่ test-signed หรือ production-signed; อย่างน้อยต้องไม่เพี้ยนจากที่ audit บอก
5. **Service lifecycle ทนนอน/รีบูร์ท:** `AegisNids` (และ `AegisWfp` ตามนโยบาย) มี `start= auto` + recovery actions; ไม่มี entry ซ้ำ; ไม่มี legacy install ที่ทำให้สับสน
6. **ETW claim ตรงจริง:** ถ้าบอก `etw_ready` ต้องมี session จริง หรือ field ต้องเปลี่ยนให้ซื่อสัตย์ตามความเป็นจริง
7. **Manifest/Truth ครบ:** `build_manifest.json` ครอบ artifact ที่ deploy จริง, `truth.py` ผ่าน, `release_engineering --verify` ผ่าน
8. **Tests ครบ:** suite ที่เกี่ยวข้องเขียวตามกติกาของ repo

**scope ที่ไม่ถือว่า “ครบ” ใน round นี้โดยอัตโนมัติ:** การเปิด data plane สมบูรณ์ (nose/brain/aggregator/dashboard + capture consumer จริง) — ถ้ายังไม่มี ให้ตีเส้นให้ชัดว่าเรื่องนี้อยู่ใน scope เดียวกันหรือเป็นคapai อีกชั้น

## 3. ลำดับงาน (plan)

### 3.1 ก่อน elevated — จัดหลักฐานและยืนยันความคุ้มครองปัจจุบัน (non-elevated)
- [x] run probe อีกครั้งล่าสุด: `python tools/audit_kernel_runtime.py --out admin-evidence/final-probe.json` → ทำแล้ว `admin-evidence/final-probe-20261004.json` (25KB, non-elevated, service RUNNING)
- [x] service config ปัจจุบัน: `AegisNids DEMAND_START` + no recovery, `AegisWfp DEMAND_START`, service `aegis_wfp` ซ้ำ STOPPED มีจริง — ยังไม่เปลี่ยนใดๆ ตามคำสั่ง
- [x] ยืนยันไฟล์ deploy ปัจจุบัน: installed exe `C5E0…` ≠ repo exe `A716…` → binary ที่รันอยู่เก่ากว่า HEAD ต้อง deploy ใหม่แบบ elevated
- [x] driver provenance เบื้องต้น: loaded `1213…` ≠ bundle `D58E…` (case B), Authenticode `Valid`, testsigning ดูไม่ได้แบบ non-elevated → เก็บใน `admin-evidence/driver-provenance-20261004.json`
- [x] legacy install: `C:\Program Files\AEGIS` 11 files เก็บรายการแล้ว ไม่ลบ
- [ ] run WFP stale evidence capture non-elevated: `powershell -ExecutionPolicy Bypass -File scripts/wfp_stale_evidence.ps1`

### 3.2 elevated — กำจัด host effect ค้าง (ก่อนเปลี่ยน service/driver) — ต้องขออนุญาตทีละคำสั่ง
- [ ] **ก่อนล้าง:** จับหลักฐาน WFP แบบ elevated ครั้งแรก: 
  - `netsh wfp show state file=<elevated-writable-path>\wfp_before.xml` (ต้อง elevated จึงจะเขียน XML ได้)
  - จากนั้น parse `wfp_before.xml` หา filterId 7023741, 7088032, 7041677, และกฎ AEGIS ทั้งหมด → เก็บใน evidence
- [ ] ล้าง filter WFP ค้าง (ถ้ายังอยู่) ด้วย elevated:
  - `netsh wfp delete filter filterid=7023741`
  - `netsh wfp delete filter filterid=7088032` (ถ้ามาจริงเป็น WFP filter; ถ้าเป็น Windows Firewall rule ให้ลบด้วย `Remove-NetFirewallRule`)
  - ลบกฎ `AEGIS_BLOCK_10.0.0.99` ทั้งหมดด้วย: `Remove-NetFirewallRule -DisplayName 'AEGIS_BLOCK_10.0.0.99'` (หรือลบตาม GUID หากมี
  - ตรวจสอบด้วย `Get-NetFirewallRule -DisplayName 'AEGIS*'` ว่าเหลือกฎค้างอยู่ไหม
- [ ] **หลังล้าง:** จับหลักฐาน WFP แบบ elevated อีกครั้ง: `netsh wfp show state file=<path>\wfp_after.xml` + parse + สรุปว่า filterId เป้าหมายหายจริง + device `/\.AegisWfpDevice` ยัง open ได้หรือไม่
- [ ] เก็บหลักฐาน netsh stdout/stderr ทั้งก่อน/หลังไว้ใน evidence พร้อม timestamp

### 3.3 elevated — ปรับ service lifecycle + ทำความสะอาดส่วนซ้ำ (ต้องขออนุญาตทีละคำสั่ง)
- [ ] **service start type + recovery (AegisNids):**
  - `sc config AegisNids start= auto` (หมายเหตุ: ต้องมีเว้นวรรคหลัง `start=`)
  - `sc failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000`
- [ ] **driver (AegisWfp) lifecycle** (ตามนโยบายเดียวกัน):
  - `sc config AegisWfp start= demand` หรือ `auto` ตามนโยบาย (ต้องชี้แจง); และ recovery actions เหมือนกันถ้าเหมาะสมกับ driver
- [ ] **ลบ entry ซ้ำ:**
  - ยืนยันชื่อ service ที่ซ้ำก่อนลบ: `sc query aegis_wfp` (ตัว Stopped)
  - `sc delete aegis_wfp` (อย่าลบ `AegisWfp` ที่กำลังรัน; ใช้ชื่อตัวหยุดเท่านั้น)
- [ ] **ล้าง legacy install:**
  - ตรวจสอบ `C:\Program Files\AEGIS` ว่ามีอะไรบ้าง (probe ล่าสุดบอก 11 files)
  - ถ้ายืนยันได้ว่าไม่ใช่ของใช้งานจริง: `Remove-Item -Recurse -Force 'C:\Program Files\AEGIS'`
  - เก็บหลักฐานรายการก่อนลบ + ยืนยันหลังลบ
- [ ] หลังเปลี่ยน service: `sc query AegisNids` + `sc qc AegisNids` + `sc qfailure AegisNids` เพื่อยืนยัน after state

### 3.4 elevated — ยืนยัน driver provenance/signing (แล้วตัดสินใจแบบปิด)
- [ ] `bcdedit | findstr /i "testsigning"` → บันทึกค่าปัจจุบัน
- [ ] `Get-AuthenticodeSignature` ของไฟล์ driverที่โหลดอยู่ (`System32\drivers\aegis_wfp.sys`) และของไฟล์ใน bundle `C:\Program Files\AEGIS NIDS\drivers\aegis_wfp.sys` → เก็บ Status + SignerCert
- [ ] เปรียบเทียบ hash ทั้ง 3 ทาง:
  - driver ที่โหลดจริง (`System32\drivers\aegis_wfp.sys`)
  - bundle copy (`C:\Program Files\AEGIS NIDS\drivers\aegis_wfp.sys`)
  - repo `build/x64/wfp/aegis_wfp.sys` + `drivers/wfp_callout/aegis_wfp.sys`
- [ ] ตัดสินจากหลักฐานว่า:
  - กรณี A: ตัวที่โหลดอยู่คือ test-signed → บันทึกเป็น limitation टि production-readiness; ไม่แก้ signature ใน round นี้หากยังไม่มี cert production
  - กรณี B: ตัวที่โหลดอยู่ไม่ตรงกับ repo → ต้องตัดสินใจว่าจะ sync ไฟล์ driver หรือระบุให้ชัดว่าตรงไหนคือผู้ให้บริการจริง

### 3.5 code/honesty ระดับที่อาจยังเหลือ (ถ้ายังไม่ทำ)
- [ ] **ETW:** ตรวจสอบว่า field `etw_ready` ใน source/control handler อาจ report `true` โดยไม่มี session จริง — ต้องยืนยันว่า:
  - หรือทำ session จริง (ถ้า prerequisites พร้อม)
  - หรือแก้ประสงค์ของ field/reporting ให้ตรงความจริง (scale back claim)
- [x] **enforcement.status contract:** ตรวจสอบแล้วตรง contract HEAD ทั้ง `prevention_gate`, `host_effect_capable`, `host_effect_confirmed`, `enforcement_mode` — live snapshot `closed`/`detection-only`/`false` ไม่มี contract error; `detection-only` ตอน gate closed คือค่าที่ gate ยอมรับ (`scripts/project2_runtime_gate.ps1:52`)
- [ ] **manifest coverage:** ตรวจสอบว่า `build_manifest.json` ครอบ artifact ที่ deploy แล้วจริงๆ รวมทั้ง `.sys` ที่โหลดและ `.dll` ที่ไปกับ runtime — จาก probe ล่าสุดไฟล์ใน `runtime/` มี 12 files; ต้องดูว่าทั้งหมดถูก manifest รับรองหรือไม่

## 4. สิ่งที่ explicitly NOT ใน scope ของ round นี้ (ตีเส้นชัด)
- [ ] การเปิด data plane สมบูรณ์ (nose/aggregator/dashboard/brain + listener 9999/9200) — หากยังไม่รัน ก็ไม่ใช่ failure ของ round นี้ หากเราตกลงกันว่า scope อยู่ที่ “core daemon + host effect honesty + lifecycle + provenance”
- [ ] การสร้าง cert chain production (เรื่อง certs ใน `admin-evidence/certificates/` ยังเป็น invalid-chain) — เป็นเรื่องแยกต่างหาก
- [ ] การเปลี่ยนด้าน WFP level-2 rule semantics หรือ policy semantics — เราทำแค่ cleanup stale effect
- [ ] การ commit/push — ไม่ทำโดยไม่ขอ

## 5. หลักฐานที่จะต้องเหลือไว้ (evidence packaging)
เมื่อจบ ต้องมีใน `admin-evidence/` อย่างน้อย:
- `final-probe.json` — probe ครั้งสุดท้ายหลังทำทุกอย่าง
- `wfp-stale-evidence-<ts>/result.json` — หลักฐานกฎ AEGIS ค้าง (non-elevated)
- `wfp-cleanup-<ts>/`:
  - `wfp_before.xml` + parse summary
  - `wfp_after.xml` + parse summary
  - `service_before.txt` / `service_after.txt`
  - `driver_signing_before.txt` / `driver_signing_after.txt`
- `result.json` ของ deploy เดิมยังเก็บไว้ (`deploy-20261003-224045/result.json`) — เป็นจุดเริ่มต้นหลังการ deploy
- สรุปผลลัพธ์สุดท้ายในรูปของ report นี้ (หรือรายงานแยกต่างหาก)

## 6. การตัดสินใจที่ต้องถามก่อนทำ elevated
1. **WFP cleanup:** ยืนยันว่าล้าง filterId 7023741, 7088032 และกฎ `AEGIS_BLOCK_10.0.0.99` ทั้งหมดได้ — รวมถึงการลบ persistent filter ด้วย netsh (มีความเสี่ยงน้อยแต่ต้อง elevated)
2. **driver lifecycle:** `AegisWfp` จะตั้ง start= ใด (demand หรือ auto) และ recovery actions แบบไหน
3. **driver signing:** ถ้ายัง test-signedอยู่ จะยอมรับเป็น limitation บันทึกไว้ หรือมีแผนผลิต cert จริง
4. **ETW claim:** จะแก้ field/reporting หรือทำ session จริง
5. **legacy install:** ยืนยันลบ `C:\Program Files\AEGIS` ได้
6. **scope data plane:** ยืนยันว่า “ไม่มี nose/brain/aggregator/dashboard” ในรอบนี้เป็น OK (คือไม่นับเป็น failure)

เมื่อได้คำตอบ ก็ทำตามขั้น elevated ทีละคำสั่งพร้อมบันทึกหลักฐาน แล้ว report ผลลัพธ์จริง หนึ่งเดียวที่ “ครบ 100%” คือ เมื่อหลักฐานพูดว่า:
- health/enforcement ซื่อสัตย์และ rules 22,
- stale host effect ถูกล้างพร้อม before/after,
- service/driver lifecycle + provenance จัดการได้ตามที่ตกลง,
- integrity channels เขียวทั้งหมด

คำถามก่อนเริ่ม: 6 ข้อด้านบน ตอบเป็นรายขอได้เลยครับ
