# AEGIS NIDS — Kernel/Service Runtime Audit (2026-10-02)

**Repository:** `D:\NIDs_Windows`
**HEAD:** `42f95c0a00f526c06a6e9a3d856b6af66c51e683` (2026-10-01T18:13:57+07:00), branch `main`, working tree dirty
**โหมดการตรวจ:** read-only — ไม่ start/stop service, ไม่ลบ/เพิ่ม WFP filter, ไม่แก้ registry, ไม่แก้ไฟล์ที่ติดตั้ง
**หลักฐานดิบ:**
- `admin-evidence/kernel-runtime-audit-normal.json` (รันแบบ user ธรรมดา)
- `admin-evidence/kernel-runtime-audit-admin.json` (รัน elevated, ชุดแรก)
- `admin-evidence/kernel-runtime-audit-admin2.json` (รัน elevated + WFP state/minifilter/binary markers/cwd)
- `admin-evidence/wfp_state.xml` (netsh wfp show state, 10.2 MB, 19,677 items, 131 รายการที่ label มี aegis)
- probe ใช้ซ้ำได้: `tools/audit_kernel_runtime.py`

---

## 1. ข้อสรุปผู้บริหาร (ตรงไปตรงมา)

บนเครื่องนี้ **มี kernel-level path จริงและโหลดอยู่จริง** แต่ยังไม่ใช่ "kernel-level IDS ที่ทำงานครบวง":

| ชั้น | สถานะจริง | หลักฐาน |
|---|---|---|
| WFP kernel driver | **RUNNING** (`AegisWfp`), โหลดจาก `System32\drivers\aegis_wfp.sys` | `sc query AegisWfp` |
| Kernel capture hook | **มี** callout filter `INBOUND_TRANSPORT_V4` (terminating) + callout registered | filterId 7041677, callout "AEGIS NIDS Network Capture" |
| Control daemon | **RUNNING** (LocalSystem, PID 21976, cwd=`C:\WINDOWS\system32`) | `tasklist`, psutil cwd |
| Rules ในหัว engine | **0 rules** จาก 22 rules ที่ติดตั้ง | `metrics.snapshot.rules_loaded=0`, `rules.list` |
| Packet acquisition | **หยุด** — Nose ไม่เชื่อม, brain/aggregator ไม่รัน | `go_nose_not_ready`, no listener 9999/9200 |
| ETW | **ไม่มี session** แต่ health อ้าง `etw_ready=true` | `logman query -ets` empty |
| Residual kernel block | **มี 2 block ค้าง** (หนึ่ง persistent, block 8.8.8.8:80) | WFP state filterId 7023741, 7088032 |
| Binary ที่รัน | release `6.0.0` (2026-09-16) — **ไม่ใช่ HEAD build** | sha256 643e7655… ≠ zig-out 98ef3143… |
| Driver ที่รัน | `build/x64/wfp/aegis_wfp.sys` **test-signed** + `testsigning Yes` | Authenticode CN=AEGIS NIDS Test Signing |

พูดสั้น ๆ: **หัวใจ kernel ทำงาน แต่สมอง (rules) ว่าง ข้อมูลเข้าไม่ได้ และมี host effect ค้างที่ไม่ถูกล้าง** — ต้องแก้ config/deploy path ก่อนจึงจะเรียกว่า IDS ที่ใช้งานได้

---

## 2. แผนผังความสัมพันธ์ที่พบจริง

```text
Windows SCM
  ├── AegisNids (WIN32_OWN_PROCESS, LocalSystem, DEMAND_START, no recovery actions)
  │     └── "C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe"   [6.0.0, 2026-09-16, UNSIGNED]
  │           ├── cwd = C:\WINDOWS\system32  →  หา "configs/Rules.json" ไม่เจอ  →  rules_loaded=0
  │           ├── control pipe \\.\pipe\aegis_control (single instance, default DACL)
  │           ├── in-process: aegis_pep.dll, aegis_ipc.dll (bridge), aegis_etw_helper.dll, aegis_fim_helper.dll
  │           └── AegisWfp block path (IOCTL) ──► persistent WFP filter "AEGIS WFP TCP Port Proof Filter"
  └── AegisWfp (KERNEL_DRIVER, DEMAND_START)
        └── \??\C:\WINDOWS\System32\drivers\aegis_wfp.sys  [= repo build/x64/wfp/aegis_wfp.sys, test-signed]
              ├── device \\.\AegisWfpDevice   (admin เท่านั้นที่เปิดได้; \\.\AegisWfp ไม่มี → WinError 2)
              ├── callout "AEGIS NIDS Network Capture" (registered)
              ├── filter 7041677 AEGIS Inbound Transport V4 Capture  (INBOUND_TRANSPORT_V4, CALLOUT_TERMINATING, non-persistent)
              ├── filter 7023741 AEGIS WFP TCP Port Proof Filter     (ALE_AUTH_CONNECT_V4, BLOCK, PERSISTENT, 8.8.8.8:80/TCP)
              └── filter 7088032 AEGIS_BLOCK_10.0.0.99               (INBOUND_ICMP_ERROR_V4, BLOCK, provider=MPSSVC_WF)

legacy ซ้ำซ้อน:
  ├── C:\Program Files\AEGIS\aegis_nids.exe            [2026-09-07, v5, ไม่ได้รัน, ยังมี uninstall.exe]
  ├── service entry "aegis_wfp" (Stopped) ชี้ไฟล์เดียวกับ AegisWfp
  └── bundle driver "C:\Program Files\AEGIS NIDS\drivers\aegis_wfp.sys" [d58e2eef…, 11,640 B] ≠ ตัวที่โหลดจริง

ขาดจากระบบทั้งหมด: nose (Go), brain (Python, UDP 9999), aggregator (9200), dashboard — ไม่มี process/ listener
```

---

## 3. Findings เรียงตามความรุนแรง

### F1 — P0: service รันด้วย rules 0 ตัว และ build จาก HEAD จะ start ไม่ขึ้น
- `metrics.snapshot` → `rules_loaded=0`, `detections=0`, `blocks=0`; `rules.list` → `{"rules_loaded":0,"engine":"aho_corasick"}`; ขณะที่ `C:\Program Files\AEGIS NIDS\configs\Rules.json` มี **22 rules** (มี R0056 "SQL Injection (Auth Bypass)", action Drop)
- root cause: [src/daemon.zig](src/daemon.zig) ใช้ `std.fs.cwd().openFile("configs/Rules.json")` → เทียบกับ **cwd ของ process** ซึ่ง service = `C:\WINDOWS\system32` (ยืนยันด้วย psutil) ไม่ใช่ install dir
- [src/platform/win32_service.zig](src/platform/win32_service.zig) `serviceMain` → `daemon.runDaemon()` ไม่มี `SetCurrentDirectory` หรือ image-relative resolution
- HEAD source **fail-closed**: `diag.err("detection engine has 0 rules — refusing to start"); return error.RulesUnavailable;` → ถ้า deploy binary จาก HEAD แบบนี้ service จะ **ไม่ start** (crash/ไม่ขึ้น) จนกว่าจะแก้ config resolution
- deployed binary (2026-09-16) ยังรันต่อได้ด้วย rules ว่าง → "แอบสำเร็จ" (silent empty ruleset)
- ผลกระทบ: ไม่มี detection เลย; enforcement mode "active" ไม่มีความหมาย

### F2 — P0: host effect ค้างใน kernel (stale block filters) — ยังไม่ถูกล้าง
พบใน WFP state (ไม่ใช่แค่ชื่อ):
- `AEGIS WFP TCP Port Proof Filter`, filterId **7023741**, layer `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, action **FWP_ACTION_BLOCK**, flags **FWPM_FILTER_FLAG_PERSISTENT**, conditions = remote `8.8.8.8` / port `80` / protocol `6` (TCP)
  - ต้นทาง: [drivers/wfp_callout/aegis_wfp.c:299,309](drivers/wfp_callout/aegis_wfp.c#L299) (`filter.displayData.name = L"AEGIS WFP TCP Port Proof Filter"`, `filter.flags = FWPM_FILTER_FLAG_PERSISTENT`)
  - **persistent → รอด reboot** และไม่ผูก provider/owner
- `AEGIS_BLOCK_10.0.0.99`, filterId **7088032**, layer `INBOUND_ICMP_ERROR_V4`, action **BLOCK**, provider `FWPM_PROVIDER_MPSSVC_WF`, condition remote `10.0.0.99` — คือ Windows Firewall rule ที่ตั้งชื่อตาม AEGIS (description อ้าง Tier-2 Rule R0056)
- `AEGIS Inbound Transport V4 Capture`, filterId 7041677, `INBOUND_TRANSPORT_V4`, `FWP_ACTION_CALLOUT_TERMINATING` (non-persistent) + callout "AEGIS NIDS Network Capture" (REGISTERED) — นี่คือ hook ตรวจจับจริง
- 120 รายการชื่อ `aegis-nids` / `aegis-dashboard` / `aegis-aggregator` = per-app rules ของ Windows Firewall ที่เกิดจากการรัน binary เหล่านั้น (ไม่ใช่ WFP filter ของ AEGIS แต่เป็นร่องรอย host state)
- ไม่มี providerKey ของ AEGIS บน filter ที่ driver สร้าง → ไม่มี ownership/reconciliation; unblock ต้องใช้ `g_FilterId` ในหน่วยความจำ driver ซึ่ง **หายเมื่อ driver/service restart** (ตรงกับข้อค้นพบเดิมใน [analysis/L4_WFP_ROOT_CAUSE_2026-09-21.md:39](analysis/L4_WFP_ROOT_CAUSE_2026-09-21.md#L39))
- ผลกระทบ: เครื่องนี้มี traffic ถูก block โดยไม่มีเจ้าของที่ตรวจสอบได้ — ขัดหลัก receipt-driven truth และ "no hidden host effect"

### F3 — P0: build-runtime mismatch (สิ่งที่รัน ≠ HEAD)
| artifact | รันบนเครื่อง | repo (HEAD build) | หมายเหตุ |
|---|---|---|---|
| aegis_nids.exe | 643e7655… (3,514,880 B, 2026-09-16) | 98ef3143… (3,639,808 B, 2026-10-01) | deployed = `release/aegis-nids-windows-6.0.0-20260916_223148` |
| aegis_pep.dll | ea7e24b8… | 405ad930… | ต่างกัน |
| aegis_wfp.sys (โหลดจริง) | 1213604e… (28,048 B, test-signed) | `build/x64/wfp/aegis_wfp.sys` = 1213604e… | provenance ปิด: ตัวที่รันคือ WDK build + `scripts/wfp_sign.ps1` |
| aegis_wfp.sys (ใน bundle) | d58e2eef… (11,640 B) | `drivers/wfp_callout/aegis_wfp.sys` = d58e2eef… | bundle ไม่ตรงกับตัวที่โหลด |
- `build_manifest.json` (516 artifacts, source_commit 42f95c0) **ไม่มี** `zig-out/bin/aegis_nids.exe` และ `target/release/aegis_pep.dll` → manifest ไม่ครอบ primary runtime
- `C:\Program Files\AEGIS` (2026-09-07) ยังอยู่ = duplicate install/legacy authority

### F4 — P1: kernel driver พึ่ง test signing (ยังไม่ production-ready)
- `bcdedit`: **`testsigning Yes`**, `hypervisorlaunchtype Off`
- `Get-AuthenticodeSignature` ของ driver: Valid แต่ signer = **`CN=AEGIS NIDS Test Signing`** (self-signed per [scripts/wfp_sign.ps1](scripts/wfp_sign.ps1))
- exe/dll ใน install dir: **NotSigned** ทั้งคู่
- ผลกระทบ: เครื่องปลายทางทั่วไป (testsigning off) จะโหลด driver ไม่ได้; release ต้องมี EV/WHQL signing + manifest ระบุ .sys

### F5 — P1: คำกล่าวอ้างของ runtime ไม่ตรงสภาพจริง (claim vs reality)
- `system.health`: `state=RUNNING`, `degraded=true`, `capabilities.wfp=true`, `workers.*=true`, `failure_mask=0`
  - แต่ `go` DEGRADED (`go_nose_not_ready`), `cpp` DEGRADED (`windows_telemetry_not_ready`), `etw_ready=true` ขณะที่ไม่มี ETW session (`logman query -ets` ว่าง; source ใช้ชื่อ session `AEGIS_NIDS` ที่ [src/windows/etw_realtime.zig:986](src/windows/etw_realtime.zig#L986))
- `enforcement.status` ตอบ `{"tier3":"READY","tier3_enforcing":true,"pep_available":true,"enforcement_mode":"active"}` — **ไม่มี** `prevention_gate` / `host_effect_capable` ตาม contract ที่ tests ของ HEAD คาด (`tests/runtime/test_operator_contracts.py:72`) → deployed contract เก่ากว่า HEAD
- `metrics`: events_processed 5,999 (เพิ่ม ~2/วิ) แต่ `packets_captured=0`, `flows_active=1`, `nose_connected=false` → event มาจาก in-process source ไม่ใช่ network data-plane; provenance ต้องระบุให้ได้
- `federation.status` → null (ยังไม่ implement)

### F6 — P1: control pipe ยังใช้ default DACL (privileged IPC boundary ไม่ได้ออกแบบ)
- SDDL ที่อ่านได้จริง: `O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BA)(A;;FR;;;WD)(A;;FR;;;AN)`
- user ธรรมดาเปิดแบบ read+write ไม่ได้ → `CreateFileW` **WinError 5**; admin เปิดได้ (server pid 21976)
- เพราะ protocol ต้อง *write request* เข้า pipe, `FA` เฉพาะ SYSTEM/Administrators ⇒ operation CLI ต้อง elevated เท่านั้น; role-based SDDL ที่เอกสารวางไว้ยังไม่ถูก implement (สอดคล้อง [analysis/current-head/03-runtime-lifecycle.md:130](analysis/current-head/03-runtime-lifecycle.md#L130))

### F7 — P1: lifecycle/ops ไม่ทน restart
- `sc qc`: ทั้ง `AegisNids` และ `AegisWfp` เป็น **DEMAND_START** → ไม่ start เองหลัง reboot
- `sc qfailure`: ไม่มี recovery action ทั้งคู่ → crash แล้วไม่ถูก restart
- ไม่มี auto-start + ไม่มี supervision = IDS หยุดเงียบ

### F8 — P2: duplicate/legacy artifacts บนเครื่อง
- install เก่า `C:\Program Files\AEGIS` (2026-09-07) + `uninstall.exe` ของเดิม
- driver service สองรายการชี้ไฟล์เดียวกัน: `aegis_wfp` (Stopped) และ `AegisWfp` (Running)

### F9 — P2: data plane ขาดทั้งวง
- ไม่มี process `nose`/`brain`/`aggregator`/`dashboard`; ไม่มี listener 9999 (brain) / 9200 (aggregator)
- UDP HEALTH probe ไป 9999 → `ConnectionResetError [WinError 10054]`
- kernel capture filter (7041677) มีอยู่ แต่ไม่มี consumer ปลายทาง

### F10 — P2: device ACL
- `\\.\AegisWfpDevice`: user ธรรมดาเปิดไม่ได้ (WinError 5 ทั้ง GENERIC_READ และ no-access) — ดีในมุม boundary
- admin เปิดได้แม้ไม่ขอ access ใด ๆ → device ไม่มี restrictive SDDL (ตรงกับข้อสังเกตใน [analysis/current-head/06-pep-wfp-native.md](analysis/current-head/06-pep-wfp-native.md))
- `\\.\AegisWfp` ไม่มีจริง (WinError 2) → สรุปฝั่ง user space ต้องใช้ `AegisWfpDevice` เท่านั้น (ชื่อนี้ถูกต้อง)
- ไม่มี AEGIS minifilter โหลด (`fltmc` ว่างจาก AEGIS)

---

## 4. ตารางหลักฐานสำคัญ (สำหรับ audit trail)

```text
PIPE      O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BA)(A;;FR;;;WD)(A;;FR;;;AN)   server_pid=21976
SERVICE   AegisNids  RUNNING  LocalSystem  DEMAND_START  "C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe"
DRIVER    AegisWfp   RUNNING  KERNEL_DRIVER  \??\C:\WINDOWS\System32\drivers\aegis_wfp.sys
HASHES    deployed exe 643e7655 (3514880)  |  HEAD zig-out exe 98ef3143 (3639808)
          loaded sys 1213604e (28048)      |  bundle sys d58e2eef (11640)
SIGNING   driver Valid/TestSigning           |  exe+dll NotSigned      |  BCD testsigning Yes
HEALTH    state RUNNING degraded=true  wfp=true etw_ready=true failure_mask=0
METRICS   rules_loaded=0 packets=0 events_processed=5999 detections=0 blocks=0
FORENSIC  verify ok records=6000
WFP       7041677 CALLOUT_TERMINATING INBOUND_TRANSPORT_V4 (non-persistent)
          7023741 BLOCK ALE_AUTH_CONNECT_V4 PERSISTENT 8.8.8.8:80/TCP
          7088032 BLOCK INBOUND_ICMP_ERROR_V4 10.0.0.99 (provider MPSSVC_WF)
ETW       logman -ets: ไม่มี session; providers: ไม่พบชื่อ aegis
PROCESS   cwd=C:\WINDOWS\system32 (root cause ของ F1)
```

---

## 5. ลำดับการแก้ (ยังไม่ได้ลงมือ — ต้องขออนุมัติทีละขั้น)

**P0-A: ล้าง host effect ค้าง (ต้อง admin, ทำตอน maintenance window)**
1. `netsh wfp delete filter filterid=7023741` (หรือ FwpmFilterDeleteById0 ผ่าน driver)
2. `Remove-NetFirewallRule -DisplayName 'AEGIS_BLOCK_10.0.0.99'` (ตรวจก่อนด้วย `Get-NetFirewallRule -DisplayName 'AEGIS_BLOCK*'`)
3. เก็บ `netsh wfp show state` after + ยืนยันว่า filter 7023741/7088032 หาย และ device ยังทำงาน
4. เพิ่มเครื่องมือ enumeration/cleanup สำหรับ stale AEGIS filters (ปัจจุบัน **ไม่มี** cleanup path ใน repo)

**P0-B: แก้ config resolution ให้ไม่ผูก cwd**
- เปลี่ยน `src/daemon.zig` / `src/pipeline/rule_loader.zig` ให้ resolve จาก **image directory** (`GetModuleFileNameW` → dirname) หรือชี้ผ่าน service args/registry; คง fail-closed เมื่อ 0 rules
- เพิ่ม test: service-like cwd (`C:\Windows\System32`) ต้องยังโหลด rules ได้

**P1-A: deploy HEAD build จริง**
- ใช้ `zig-out/bin/aegis_nids.exe` (98ef3143…) + `target/release/aegis_pep.dll` (405ad930…) + helpers ที่ตรงกัน; อัปเดต bundle `manifest.json` ให้ digest ตรง binary ที่จะรัน

**P1-B: driver production signing + manifest**
- EV/WHQL signing, ปิด testsigning, ระบุ `.sys` digest ใน manifest; ยืนยันว่าโหลดได้บนเครื่อง testsigning=off

**P1-C: service lifecycle**
- `sc config AegisNids start= auto` + `sc failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000`
- ทำเช่นเดียวกันกับ `AegisWfp` (อย่างน้อย start= demand→auto ตามนโยบาย)
- ลบ entry ซ้ำ `aegis_wfp` และ install เก่า `C:\Program Files\AEGIS`

**P2-A: pipe SDDL + role boundary**
- กำหนด SDDL ที่ให้ operate/read เฉพาะกลุ่ม operator ที่พิสูจน์ได้; impersonate caller เพื่อตัดสิน role (ไม่ใช้ token ของ daemon)

**P2-B: readiness/contract ให้ตรงจริง**
- `etw_ready` ต้องสะท้อน session จริง; ลบ optimistic flag
- `enforcement.status` เพิ่ม `prevention_gate`/`host_effect_capable` ตาม contract HEAD
- ระบุ provenance ของ `events_processed` เมื่อ nose ไม่เชื่อม

**P2-C: เปิด data plane ครบวง**
- supervisor เดียวคุม nose/brain/aggregator; health ต้อง DEGRADED ตามจริงเมื่อขาด consumer

---

## 6. ข้อจำกัดของการตรวจรอบนี้

- ไม่ได้ start/stop/restart service หรือ driver; ไม่ได้ทดสอบ block/unblock ใหม่ (ไม่สร้าง host effect เพิ่ม)
- ไม่ได้ลบ filter/rule ใด ๆ — รายการใน §5 เป็นข้อเสนอ
- ETW provider อาจลงทะเบียนด้วย GUID โดยไม่มีชื่อ aegis ใน logman; รอบนี้ยืนยันเฉพาะ "ไม่มี session รัน"
- WFP state parse จาก `netsh wfp show state` (snapshot 14:41:25Z) — filter ID เหล่านี้อาจเปลี่ยนได้หากมี process อื่น mutate WFP
- deployed binary เป็น build 2026-09-16: พฤติกรรม fail-open ต่อ rules ว่างเป็นข้อสันนิษฐานจากหลักฐาน (strings + ค่าที่วัดได้) ไม่ได้ disassemble ยืนยัน
