# แผนความสมบูรณ์: Kernel-level Network IDS (AEGIS NIDS Windows)

> **สถานะปัจจุบัน (2026-11-02):** ผลิตภัณฑ์คือ **Kernel-level IDS (detection/evidence only)**.
> WFP เป็น observe-only sensor, Rust PEP เป็น assessment-only และ production
> ไม่มี reachable host-effect path; lab gate เป็น build แยกและไม่ใช่ผลิตภัณฑ์.
> เนื้อหา §1 และ Phase 3 ด้านล่างเป็นบันทึกประวัติศาสตร์จากการประเมินก่อน pivot.
> Source of truth คือ code ที่ HEAD ปัจจุบัน ไม่ใช่ข้อความเก่าในเอกสารนี้.

สถานะฐาน: `64df058` — pytest 727, zig suite, truth, release 539/539, audit 100% (ดู EVIDENCE_INDEX.json EVT-091–099)

## 1. ผลออดิต: ระบบวันนี้คืออะไร

**ความจริงหลัก: ระบบปัจจุบันคือ user-mode NIDS ที่กิน kernel telemetry — ไม่ใช่ kernel-mode NIDS**

| ชั้น | ความจริง (หลักฐาน) |
|---|---|
| Packet acquisition | Npcap (third-party kernel driver) ผ่าน Go Nose — พิสูจน์ live แล้ว 43,835 pkts/15s |
| Host telemetry | ETW kernel providers (Process/File/Registry) บริโภคจาก user-mode — GUID/gates/probe เสร็จ, เหลือ live proof |
| Enforcement | User-mode WFP ผ่าน `aegis_wfp_user.dll` (fwpuclnt) ที่ Rust PEP โหลดตอนรัน (`rust-src/lib.rs:324`) — ห้าม kernel path โดยตรง (GAP-011 ปิดแล้ว) |
| Own WFP callout driver | มีแค่ source (`drivers/wfp_callout/`) — CMake ปฏิเสธ build โดยออกแบบ (`BUILD_KERNEL_DRIVER` ตายตัว) ไม่มี WDK authority |
| Minifilter (FIM ระดับ kernel) | มีแค่ source (`drivers/minifilter/`) ยังไม่ build/test |
| `.sys`/`.cer`/`.pdb` ใน `drivers/` | ไฟล์ local untracked (tracked จริงมีแค่ source + `.inf`) — ไม่มี provenance อย่าอ้างเป็น artifact |
| Policy/Brain/PEP/Forensics/Control | ครบ + verified (trust chain, receipt Zig, supervisor join 7/7, DEFCON) |

ข้อยุติความหมายคำว่า complete มี 2 แบบ: (A) สมบูรณ์แบบ user-mode + kernel telemetry (ไม่ต้อง cert ไม่ต้อง lab ใหญ่) กับ (B) โปรแกรม kernel-driver เต็มรูป (หลายเดือน + EV cert + HLK + lab แยก) แผนนี้ทำ A ให้จบก่อนเสมอ แล้วค่อยตัดสิน B

## 2. แผนเป็นเฟส

### Phase 1 — ปิด execution gap (operator shell ธรรมดา, ไม่ต้อง elevation)
1. `zig build` + `zig build test` เต็มรอบหลัง LIT-FREE fix (ยังไม่เคยเขียวเต็มรอบ)
2. `cargo test`, nose `go test`, brain pytest ยืนยันหลังเปลี่ยนล่าสุด
3. MSVC build `aegis_etw_helper` + host run: GUID ถูก start ได้, GUID ปลอมได้ rc -6 ไม่มี session (ปิด GAP-012 b5)
4. `--manifest` บน scratch copy → diff กับชุด 539 → ตัดสินใจ drop junk (ปิด GAP-008 b2) แล้ว clean-checkout `--verify` (ปิด b3)
- เกณฑ์ผ่าน: gates เดิมทั้งหมด + EVT บันทึกผลรัน

### Phase 2 — Live proof แบบ observe-only (ต้อง elevation, ทำบน workstation ได้)
1. Redeploy `aegis_nids.exe` + helper → restart `AegisNids` → forensic ring ต้องมี source=10 ใน 60 วินาที (ปิด GAP-012 b4, GAP-009 ส่วน ETW)
2. FIM watches ระดับ System32/SysWOW64 + registry proof (ปิด GAP-009 ส่วนที่เหลือ)
- ปลอดภัยบน workstation: ETW session กับ FIM watch ไม่ mutate อะไร

### Phase 3 — Isolated lab เท่านั้น (mutating + driver)
1. WFP BLOCK proof บน lab (ห้ามบน workstation จริง)
2. ตัดสิน quarantine semantics ก่อน แล้ว implement Rust quarantine-enforce ตาม spec EVT-098 R1 + proof บน lab
3. ตั้ง test-signing lab สำหรับ driver (testsign + `AegisTest.cer` ใช้ได้เฉพาะ lab)
- เกณฑ์ผ่าน: block/quarantine receipts ครบวงจรถึง Zig verify (EVT-094 เปิดทางไว้แล้ว)

### Phase 4 — Owner decisions
1. Quarantine semantics: DECIDED per-flow — implemented (EVT-112), caller wiring done (EVT-113)
2. เอา `g_confirmed_quarantines` เข้า DEFCON ladder: DECIDED รวมแบบ saturate — implemented
3. Go/no-go โปรแกรม kernel-driver: **DEFERRED อย่างเป็นทางการ (EVT-114)** — จบที่ user-mode + telemetry; กลับคำได้เมื่อมีงบ/เวลา/lab (ดู Phase 5)

### Phase 5 — โปรแกรม kernel-driver (DEFERRED — ยังไม่อนุมัติ, เก็บ spec ไว้เฉย ๆ)
1. ตั้ง WDK authority + wiring build (แทนการ refuse ใน CMake)
2. Test-signing → HLK → EV cert (production โหลด driver ไม่ได้ถ้าไม่มี)
3. Version pinning + minifilter ต่อให้จบ + lab proofs
4. ประเมินเวลาเป็นเดือน ไม่ใช่วัน

## 3. ตารางครบรายด้าน (หลังแผนนี้)

| ด้าน | Phase ที่ปิด |
|---|---|
| Backend (daemon/pipeline/ETW) | Phase 1+2 |
| Frontend (CLI/TS/dashboard/web) | ปิดแล้ว (ไม่มีงานค้างที่รู้จัก) |
| Database | ไม่มี subsystem นี้ (ring + NDJSON) — ไม่ต้องทำ |
| Security (trust/PEP/receipt/crypto) | Phase 1 (proof) + Phase 3 (quarantine-enforce) |
| External (Npcap/WFP/SIEM/federation) | Phase 2 (observe) + Phase 3 (mutating/lab) |
| Kernel driver (own callout/minifilter) | DEFERRED อย่างเป็นทางการ (EVT-114) — จบที่ user-mode + telemetry |

## 4. สิ่งที่ห้ามทำ
- Implement/แก้ enforcement หรือ driver แบบ blind (ไม่มี build/test) — ผิด stop-the-line
- Block proof หรือ driver install บน business workstation (lab เท่านั้น)
- อ้างว่า kernel-mode สมบูรณ์ทั้งที่ driver ยังไม่ build — อ้างได้แค่ kernel telemetry

## 6. สถานะล่าสุด — Minifilter "Slice A" สำเร็จ (EVT-230, 2026-10-18, E5)

minifilter ของเราเอง (drivers/minifilter/) หลุดจากสถานะ source-only แล้ว: build + sign (test cert) + load
บนโฮสต์จริง (altitude 370000, 6 instances), pull-model comm port (\AegisMinifilterPort), reader hardened
(1 MiB ring / 256 KiB pulls / 50 ms idle) — dropped=0 ตลอดภายใต้โหลดจริง (ก่อน hardening ~18%),
และพิสูจน์เนื้อหาแบบ byte เป๊ะ: สร้าง marker แล้วเจอใน forensic ring ด้วย forensics.list --payload-prefix
ตรง path จริงสอง volume (C:/D:, payload_len = DOS+21 เป๊ะ). observe-only — ไม่แตะ enforcement.
หลักฐาน: EVIDENCE_INDEX EVT-230 + admin-evidence/evt230-minifilter-slice-a-20261017/ (probe dump,
closeout note, operator blocks). รายละเอียดสไลซ์: drivers/minifilter + src/capture/minifilter_reader.zig
+ queue.stats minifilter block (aegisctl queue) + scripts/wdk_build_minifilter.ps1 /
minifilter_sign.ps1 / minifilter_service.ps1

สิ่งที่เหลือ (นอกสไลซ์นี้):

1. Production code signing (EV cert / HLK) — ปัจจุบัน test-signed เท่านั้น (โหลดได้เฉพาะเครื่องที่เปิด test-signing)
2. Enforcement activation (Slice C) — ไม่จำเป็นตามข้อกำหนด; ระบบเป็น detection-only
   (Slice B + CMake BUILD_KERNEL_DRIVER wiring ปิดแล้ว — ดู §7)

## 7. สถานะล่าสุด — WFP payload copy "Slice B" สำเร็จ (EVT-231, 2026-10-18, E5)

WFP callout ของเราเอง copy payload ดิบแบบ bounded ได้แล้ว: record = 48 B header + payload ตามที่
layer ส่งมา (≤ 4096 B, ไม่ parse L7, ไม่ reassemble), READ_EVENTS คืนเฉพาะ whole record, counter ครบ
(EventsWritten/Drops/BytesWritten/BytesRead) — พิสูจน์สองชั้นบนโฮสต์จริง (driver AD23EFB9, test cert):
kernel probe (daemon หยุด): 5 marker records payload_length=180 B byte-exact marker ที่ offset 0,
drops_delta=0, bytes_written_delta=9641 = drained_bytes เป๊ะ (48+payload ครบทุก record);
live chain: forensics.list --payload-prefix AEGIS matched=4 payload_len=180 source=wfp_sensor verified=true
(precheck ก่อนยิง marker = 0 → ยืนยัน causality). ข้อค้นพบ layout: บน loopback ทาง inbound transport
ส่งข้อมูลเริ่มที่ transport payload (ไม่รวม UDP header) — สัญญา copy คือ "ตรงตามที่ส่งมา ไม่สมมติ layout"
แล้ว CMake BUILD_KERNEL_DRIVER=ON delegate ไป scripts/wdk_build_production.ps1 (default OFF เดิม;
sign/deploy ยังเป็นขั้นแยกโดยเจตนา). observe-only — ไม่แตะ enforcement.
หลักฐาน: EVIDENCE_INDEX EVT-231 + admin-evidence/evt231-wfp-payload-copy-20261018/ (operator block,
probe, run2/run3 dump, live proof, closeout note) รายละเอียดสไลซ์: drivers/wfp_callout (aegis_wfp.h/.c/
aegis_wfp_callout.c) + src/capture/wfp_telemetry.zig (comment) + scripts/run_wfp_l4_observe_only_proof.ps1
+ tests/wfp/test_evt231_wfp_payload_copy.py + CMakeLists.txt

## 8. สถานะล่าสุด — Kernel payload → Detection พิสูจน์ครบวง (EVT-232, 2026-10-18, E5)

ต่อจาก Slice B: พิสูจน์ว่า bytes ที่ kernel copy มาจุด detection จริง — ครบวง kernel → rule → audit
โดยไม่ต้อง elevation. ชุดพิสูจน์ evt232-proof.ps1 (parameterized ด้วย -Tag) ยิง 6 UDP (42 B) + 3 TCP (46 B)
loopback ที่มี pattern `' OR 1=1` ผ่าน callout ที่ deploy อยู่จริง (daemon ไม่ต้องหยุด): forensic ring
precheck=0 → post=9, ทั้ง 9 source_name=wfp_sensor (kernel copy) + rule_id=2107512682 (= hash ของ R0056),
`forensic search --field rule --value R0056` คืน event_ids ชุดเดียวกัน 9/9, verified=true integrity=ok;
audit log 9 แถว signature_match (rule=2107512682, policy=block policy_id=3, enforcement_status=observed,
host_effect_confirmed=false); queue capture_wfp 91,428 → 91,487 (+59 รวม TCP control segments, drops คงที่
1,520); detections +1392 (counter ปน ambient ของ host — causality ยึดที่ event-id anchors), blocks_delta=0
(detection-only คงสภาพทั้ง 2 รัน). พบเพิ่ม: (1) delivery ที่ INBOUND_TRANSPORT_V4 ของ TCP ก็เริ่มที่ transport
payload เช่นเดียวกับ UDP — contract "as delivered, no layout assumption" ครอบคลุม TCP แล้ว; (2) runtime matcher
ใช้เฉพาะ rule_id + match_pattern (payload-only ตาม observe-only contract — target_ports/target_protocols ไม่ถูก
consult ที่จุด match); (3) มี lab source พื้นหลัง (loopback TCP sport 49374) ยิง R0056 เป็นช่วง ๆ อยู่ก่อนแล้ว —
เก็บ profile ไว้ในหลักฐาน (run1/log-rule-2107512682.ndjson, 127 แถว) จึงยึด causality ที่ prefix-scoped
pre/post + event-id overlap ไม่ใช่ global counter.
หลักฐาน: EVIDENCE_INDEX EVT-232 + admin-evidence/evt232-kernel-payload-detection-20261018/ (evt232-proof.ps1,
run1/ = exploratory + kit-final run 2, audit rows, log profile, events tail). ไม่มีการเปลี่ยน product code
(evidence-only round — ไฟล์ tracked ที่แก้: แผนนี้ + EVIDENCE_INDEX).

คงเหลือ (ไม่เปลี่ยนจาก §6/§7): production code signing (EV cert / HLK), real-NIC proof, IPv6/outbound decision,
Slice C (enforcement) decision — ระบบยัง detection-only ตามเดิม


## 9. Operator console - Kernel sensor view (WEB-002, 2026-10-18, E5)

?????? EVT-232: ??????????? "Kernel Sensors" ?? web dashboard (tools/aegisctl/web_dashboard/app.py) ??? telemetry ???
kernel path ????????????? UI ???? - observe-only, ?????? runtime/driver/daemon:

- snapshot (tick 3s/SSE) ????????????????????????? `kernel.sensors` - counters ??? queue.stats ??? snapshot ???????????
  (wfp callout, minifilter, kernel ingress pushed/dropped, queue depth) ????? control call ????? (payload ~28 KB)
- record pages ??????? GET /api/kernel (schema aegis.kernel.v1) + cache ???? server 60s: forensics.list ??? canonical
  source (1 wfp_sensor, 14 file_sensor) ?????? ~4s (retained-window scan + hash-chain verify) ????????????? tick 3s;
  page size 800 / 256KB = ????? page ??? daemon ??? (~770 records) - wfp window ???? complete (truncated=false,
  ??? newest), minifilter ????????????? label truncated ???????
- UI: ?????????? 2 sensors + ingress counters; ????? record newest-first (seq/event/rule/payload length/verified)
  ????? matched/ring/integrity/truncated ?????? daemon ???; rule hash (FNV-1a) map ???????? rule id ???? client
  ????????????????? (?????????????????? rule_loader.zig); ??????? payload bytes (ring ?????? payload text)

???????: admin-evidence/web002-kernel-sensor-view-20261018/ (web002-live-proof.ps1; run1/ = exploratory,
run 2 canonical PASS: wfp page 84/84 truncated=false, marker overlap 9/9 ???? 6 UDP + 3 TCP, rule hash 2107512682 = R0056,
integrity ok verified_all, cold 6601 ms vs hot 79 ms cache hit, snapshot sensors-only has_feeds=false, audit 9 rows,
blocks 0; DOM capture kernel-panel-capture.html + dom-kernel-state.json). ??????????: tools/aegisctl/web_dashboard/app.py +
tests/tools/test_web_dashboard.py (8 pins ????) + EVIDENCE_INDEX + ??????

## 10. Deployment refresh — installer พา kernel drivers ไปด้วย (DEPLOY-120, 2026-10-18, E3)

สืบเนื่องจาก EVT-232/WEB-002: ตัวติดตั้งที่ generate จริง (tools/installer.py → makensis) ยังไม่ครอบ kernel sensors —
ไม่มี minifilter, ไม่มี service registration ของทั้งสอง driver, ไม่ log สถานะ signature, และชี้ source ของ WFP ไปที่
สำเนาเก่า `drivers\wfp_callout\aegis_wfp.sys` (EC4A5683, ก่อน EVT-231) แทน build output จริง `build\x64\wfp\aegis_wfp.sys`
(AD23EFB9 = ตัวที่ deploy อยู่และพิสูจน์แล้ว) → fresh install ได้ driver เก่าและได้ kernel telemetry ไม่ครบ. รอบนี้ปิด:

- source ของทั้งสอง driver ชี้ canonical WDK output (build\x64\wfp + build\x64\minifilter, `/nonfatal`); generate
  annotate presence ต่อ driver และ WARN เมื่อ output หาย (ไม่ fail-closed — installer ยังประกอบได้)
- Install section เพิ่มบล็อก drivers (guarded ด้วย LogicLib `${If} ${FileExists}`): teardown ก่อน (fltmc unload →
  sc stop/delete — driver ที่โหลดอยู่แทนที่ไฟล์ไม่ได้), copy ไป System32\drivers, log สถานะ signature
  (AEGIS_DRIVER_SIG_WFP/FIM), แล้ว `sc create` เหมือนสคริปต์ที่พิสูจน์แล้วเป๊ะ — AegisWfp type=kernel start=demand;
  AegisMinifilter type=filesys start=demand + DisplayName + altitude 370000 ทั้ง service key และ
  Instances\DefaultInstance (WriteReg* ไม่ recreate key — บทเรียน EVT-230); payload ไม่มี driver = skip แบบ honest
- Start section: `sc start AegisWfp` → `fltmc load AegisMinifilter` (fallback sc start) → `sc start AegisNids`
  (drivers ก่อน daemon); Uninstall: unload/delete services + ลบสำเนา System32 (ไม่ DeleteRegKey SCM key)
- `find_makensis()`: PATH ก่อน แล้วค่อย %ProgramFiles(x86)%\NSIS — `--package` บิลด์ได้บน host นี้ (ก่อนหน้านี้ fail-closed)

หลักฐาน (E3 — ยังไม่รัน install บน host เพราะต้อง elevation; operator block อยู่ใน closeout): บิลด์ EXE จริงด้วย
makensis v3.12 (aegis_setup AAE7C060… size 7,404,405 B), 7z extract เทียบ SHA-256 4 ทางต่อ driver (packaged ==
build output == System32 ที่ deploy จริง: wfp AD23EFB9…83AEEAF / minifilter 082F6A43…F6909A5), signature Valid
ทั้งคู่ (CN=AEGIS Test Signer), registry parity กับ services ที่ RUNNING จริงครบ 7/7 ช่อง ต่อ service, gates 28/28.
ไฟล์ที่แก้: tools/installer.py + tests/release/test_installer_template.py (+11 pins) + docs/DEPLOYMENT.md +
แผนนี้ + EVIDENCE_INDEX + maps

คงเหลือ (ไม่เปลี่ยน): production code signing (EV cert/HLK), real-NIC proof, IPv6/outbound decision, Slice C
(enforcement) decision, host install drill ของ installer นี้ (E5, elevation) — ระบบยัง detection-only

## 11. Real-NIC ingress + ขอบเขต IPv6/outbound — NIC-001 (2026-10-18, E5)

ปิดคำถาม "kernel จับ payload จริงบนการ์ดจริงไหม": agent-run (non-elevated) บน production host
(daemon AegisNids + driver AegisWfp รันอยู่, base HEAD 8cd4837) ขับ DNS responses จริงผ่าน Wi-Fi
Killer AX1650i (@192.168.1.39) แล้วพิสูจน์ครบวง:

- **ขาเข้า v4 (kernel L7)**: responses 6/6 echo marker กลับผ่านการ์ดจริง และเข้า forensic ring
  เป็น record wfp_sensor rule R0056 (2107512682) ครบทุก ID — S1..S6 → event_ids
  5471356/57, 5471696-99 (attribution: payload_prefix ตาม DNS-ID ∩ rule search ∩ payload_len ตรง),
  integrity ok, audit rows 10 แถว
- **acquisition mirror**: egress 600 → capture_npcap +600 / capture_wfp +17; loopback 600 →
  npcap +1 / wfp +600 (ตรงข้ามกันเป๊ะ); probe บน Wi-Fi 189 packets; blocks delta 0
- **ขอบเขต v6/outbound (วัดจริง ไม่ใช่ assumption)**: kernel = v4-only (v6 marker 2/2 ตอบผ่าน wire
  แต่ record 0 — callout ผูก FWPM_LAYER_INBOUND_TRANSPORT_V4), outbound ไม่มี kernel L7 (egress
  marker 0 match), ฝั่ง acquisition: burst 300 → adapter TX +304 / pipe read +311 / submitted +3 /
  dropped +308 / npcap +0 — ฝั่ง capture/encode ถูก (nose binary emit v2 frames 1:1: 200/200 dst6 ตรง)
  แต่ frame ถูกทิ้งเงียบที่ queue gate

**บั๊ก silent event loss ที่พบ (STOP-THE-LINE)**: decode v2 ให้ `event.version=2` + sidecars (ตาม
contract ที่ pin ไว้ + tests/contracts/test_ipv6_wire_v2.py) แต่ `canonical.validate` pin `version == 1`
→ `pushDecodedFrame` คืน false → reader นับ frames_dropped เงียบ (rejected=0, ไม่มี log) — live สะสม
dropped=2,749,221 (87.7% ของ frames read). Repro บน HEAD: nic001-v6queue-repro.zig (zig test,
All 98 passed). ต้องเป็น slice แยก (V6-QUEUE-DROP) + operator redeploy จึงเปลี่ยน behavior จริง

- หลักฐาน: admin-evidence/nic001-real-nic-ingress-20261018/ (nic001-proof.py run3 official PASS 20/20;
  nic001-result.json, nic001-run.log, audit rows; run1/ + run2/ = ประวัติ; closeout มี operator block)
- หมายเหตุเชิงปฏิบัติ: forensic ring = 4096 records รวมทุก source (src/forensic/forensics_engine.zig)
  → per-tag search ต้องทำภายในไม่กี่วินาทีหลัง traffic (บทเรียนจาก run2)
- ตัดสินใจขอบเขต: คง kernel scope = IPv4 inbound (O3) + ยังไม่ทำ O1 (kernel v6) / O2 (nose payload);
  งานถัดไป = ซ่อม queue drop (O0) แล้ว operator redeploy
- ไฟล์: แผนนี้ + EVIDENCE_INDEX + maps (evidence-only — ไม่แตะ product code)
- คงเหลือ: production code signing (EV cert/HLK), Slice C (enforcement) decision, ซ่อม v6 queue + redeploy

## 12. ซ่อม V6-QUEUE-DROP - IPv6 ถูกทิ้งเงียบที่ queue gate (2026-10-18, E2)

ปิดบั๊ก STOP-THE-LINE ที่ NIC-001 พบ: เฟรม IPv6 (wire v2) ถูกอ่านเข้าสู่ pipeline แล้วทิ้งเงียบ
ที่ queue (วัดจริง 2,749,221 เฟรม = 87.7% ของ frames read) — ต้นเหตุคือ `pushDecodedFrame`
เรียก `canonical.validate` ซึ่ง pin `event.version == EVENT_VERSION (1)` แต่ v2 decode ตาม
contract (pinned โดย canonical tests + tests/contracts/test_ipv6_wire_v2.py) ให้ version == 2
→ push คืน false → reader นับ frames_dropped เงียบ (ไม่มี log, rejected = 0)

TDD แดง → เขียว (transcripts ใน admin-evidence/v6queue-drop-20261018/):
- regression: "wire-decoded v2 frame survives the queue gate" เดินเส้นทางจริง
  serializeV2 → deserializeDispatch → pushDecodedFrame → popEvent; pin acceptance + sidecars
  + u32 identity + kind (dns_response)
- negative: "decoded-frame gate rejects shapes no codec can emit" — fail-closed (v2 ไร้ sidecars /
  v1 มี sidecars / sidecar ข้างเดียว / magic เสีย)
- fixture เดิมของ v2 sidecar test แก้ให้เป็น shape จริงของ wire (version 2 + sidecars ครบ)
- RED: 97 passed; 3 failed (ตามคาด) → GREEN: All 100 tests passed; postfix driver พิสูจน์ flip
  (ก่อน fix push=false, หลัง fix push=true โดย `validate` ตัว strict ยัง false ตามเดิม)

Patch: เพิ่ม `validateDecodedFrame` ใน `src/contract/canonical_event.zig` (shape-strict: v1 = version 1
+ sidecars ว่าง; v2 = version 2 + sidecars ครบทั้งคู่; shape ผสม = reject) และสลับ
`pushDecodedFrame` (src/pipeline/event_queue.zig) ให้ใช้ตัวนี้ — `validate` เดิมยังเป็น strict ABI
gate (ไม่แตะ) และ wire contract ไม่เปลี่ยน; เพิ่มหัวข้อ Queue acceptance ใน wire_v2.md

- หลักฐาน: focused zig test All 100 passed; zig build test rc=0; zig build rc=0;
  pytest 916 passed / 2 skipped; release_engineering --refresh-digests + --verify OK (612 artifacts);
  truth verify TRUTH_VALID
- ยังไม่ครบ live (E2): daemon ที่รันอยู่เป็น binary เดิม — operator ต้อง redeploy (elevated block ใน
  closeout) แล้วรันสคริปต์ v6queue-drop-live-verify.py (ใน kit) เพื่อปิด E5
- ไฟล์: src/contract/canonical_event.zig, src/pipeline/event_queue.zig, shared/protocol/wire_v2.md,
  แผนนี้, EVIDENCE_INDEX + maps
- คงเหลือ: operator redeploy + live verify (E5), production signing (EV cert/HLK), Slice C decision

## 13. Slice C (Enforcement Activation) - Decision Brief (2026-10-18; ตัดสินใจแล้ว 2026-10-30: ออกจาก scope — ผลิตภัณฑ์คือ Kernel NIDS)

ข้อกำหนดปัจจุบัน: production เป็น detection-only; Slice C "ไม่จำเป็น" - ส่วนนี้สรุปสถานะที่ยืนยันแล้ว
และทางเลือกไว้ให้ตัดสินใจได้ทันทีโดยไม่ต้อง recon ใหม่

### 13.1 สถานะที่ยืนยันวันนี้ (HEAD 641d91c)

- live `enforcement.status` (ผ่าน control plane, non-elevated): tier3 READY, pep_available true,
  provider_ready true, shield_loaded true, tier3_enforcing false, host_effect_capable false,
  prevention_gate "closed", receipt_required true, enforcement_mode "detection-only"
  -> PEP พร้อม แต่ประตู host mutation ปิดสนิทโดยออกแบบ
- โค้ด: `g_prevention_gate_open = false` (src/pipeline/runtime_state.zig:20); คอมเมนต์กำกับ
  "Host mutation remains disabled until the isolated WFP proof opens this gate. Provider readiness
  alone must never change it."; audit pin (บรรทัด 65-84) ระบุ "nothing in-tree can open it -
  no store to g_prevention_gate_open exists" -> ไม่มี build option / env / handler ใดเปิด gate ได้
- projection: host_effect_capable := provider_ready และ gate_open (src/control/handler_registry.zig:1533);
  enforcement_mode เป็น "enforcing" เฉพาะเมื่อ gate_open และ provider_ready (บรรทัด 1538)
  ตามสัญญา "Project 2 observe-only": provider พร้อมอย่างเดียวห้ามรายงานว่า enforcing
- control plane มีครบ: enforcement.status/simulate/verify/block/quarantine/unblock/two_person/approve
  (src/control/protocol.zig enforcement.*; ดู RB-012 References); block/quarantine ถูกปฏิเสธด้วย
  PREVENTION_GATE_CLOSED "blocking is disabled until controlled host-effect proof and receipt
  validation complete"
- พาธ enforcement (เมื่อ gate เปิด) ผ่าน Rust PEP เท่านั้น: pep_bindings.PepEnforcer (enforceFlow /
  enforceQuarantineFlow -> aegis_pep.dll -> WFP exact 3-tuple filter -> queryFilterResult read-back
  ต้อง MATCH -> EnforcementReceipt host_effect_confirmed:true -> ENFORCED) พร้อม cleanup discipline
  (read-back absent/mismatch -> unblockFilter + POSTCONDITION_FAILED/RECEIPT_INVALID;
  src/control/handler_registry.zig:1746-1806); Zig ไม่มี direct WFP mutation (src/policy/wfp_production.zig
  เป็น fail-closed boundary)
- เอกสารควบคุมเขียนครบแล้ว (ยังไม่ execute):
  - docs/WARDEN_CUTOVER_SPEC.md (EVT-153, E5): cutover เฉพาะ lab/VM; preconditions (VM snapshot,
    test-signed driver+provider HEAD เดียวกัน, forensic ring healthy); canary block โดย
    BLOCKED_CONFIRMED ต้องมี receipt + host postcondition เท่านั้น; soak 24h (zero PEP_UNVERIFIED,
    zero receipt mismatch, ring verify + replay); rollback drill <5 นาที; prod non-goals:
    ห้าม flip/re-install/re-sign/filter change - driver คง RUNNING (telemetry), gate คงปิด
  - RB-012 / RB-013 (lab proof; status NOT YET EXECUTED as of this 2026-10-18 decision brief; see §27 for the 2026-11-02 RB-013 lab-kit diagnostic proof), RB-016 (production trust, OPERATOR ACTION),
    RB-001 (IR)
  - .analysis/security.md: detection-only จนกว่า P0/Gate A-E ผ่านที่ HEAD ปัจจุบัน
  - configs/aegis.conf [ips]: QUARANTINED (observe-only)

### 13.2 ช่องว่างก่อน activate (เรียงตามลำดับที่ต้องปิด)

- G1 กลไก "เปิด prevention gate" สำหรับ lab ไม่มีใน-tree (มีแต่ pin ห้ามเปิด) -> ต้องมีกติกาเปิดแบบ
  lab-scoped + signed-off design review ก่อน (หมายเหตุในไฟล์ quarantined ของ driver: "DO NOT RESTORE
  WITHOUT A SIGNED-OFF DESIGN REVIEW") จึงค่อย implement สไลซ์เล็กที่เพิ่มกลไกนี้
- G2 ยังไม่เคย execute RB-012/RB-013 บน isolated VM -> E5 host-effect proof (receipt + filter จริง +
  traffic ตายจริง) และ soak 24h + rollback drill ยังขาด
- G3 production trust ยังไม่ตั้ง (RB-016: Ed25519 keypair offline + policies.sig.json +
  AEGIS_POLICY_ENFORCE_TRUSTED) - unsigned policy escalate เสมอ (fail-closed ที่ถูกต้อง แต่ยัง enforce ไม่ได้)
- G4 production signing (EV/HLK) ยังไม่ทำ - driver/instrument test-signed เท่านั้น
  G3/G4 = งาน operator; G1/G2 = งาน code + lab (ฝั่ง agent ทำได้หลังอนุมัติ)

### 13.3 ทางเลือก

- A) คง detection-only (ไม่ทำอะไรต่อ): ตรงข้อกำหนดปัจจุบัน, blocks delta คง 0, ไม่มีงานเพิ่ม
- B) Lab qualification only (Slice C-lab): ปิด G1 (กลไกเปิด gate lab-scoped หลัง design review) +
  ปิด G2 (execute WARDEN spec step 1-4 / RB-012 -> RB-013 บน isolated VM ที่ HEAD ปัจจุบัน) + เก็บ
  evidence kit -> production ไม่เปลี่ยนเลย (gate คงปิด)
- C) Production enforcement: ต้องมี B ผ่าน + G3 + G4 + operator อนุมัติ; WARDEN spec ห้าม flip บน
  production ก่อนมีหลักฐาน lab ที่ HEAD ปัจจุบัน -> ยังไม่เสนอให้ทำตอนนี้

### 13.4 ความเสี่ยงหลัก (ของ B) และการควบคุม

- false positive/self-lockout: จำกัด TEST-NET (203.0.113.10 / 192.0.2.10 ตาม spec), exact 3-tuple,
  two-person rule severity>=7, quota 100 block/s, rollback enforcement.unblock + drill <5 นาที
- lab ต้องเป็น VM snapshot + host-only network (RB-012: NEVER run on production)
- ห้าม cite in-memory block / log / exit code เป็น host-block proof - ต้องมี receipt + read-back +
  traffic effect + forensics (spec ย้ำ; .analysis/security.md:23)
- minifilter ต้องอยู่นอก cutover (Gate D ของตัวเอง); driver/service บน production ห้ามแตะ

### 13.5 หลักฐานเป้าหมาย (ถ้าเลือก B)

- E5: WFP BLOCK live proof (receipt ENFORCED, enforcement.verify MATCH, Test-NetConnection fail -> recover)
- E5/E6: soak 24h + rollback drill + forensic ring verify/replay
- kit: admin-evidence/sliceC-lab-<date>/ + EVI entries + บันทึกปิด slice ในแผนนี้ (§14) เมื่อจบ
- invariant: production blocks delta คง 0 ตลอด (B ไม่แตะ host ที่รันจริง)

### 13.6 คำแนะนำ

- ถ้ายังไม่มี use case enforcement: คง A - เอกสารนี้พร้อมใช้ทันทีเมื่อต้องการ
- ถ้าจะเดินหน้า: เริ่ม B เท่านั้น (lab-scoped; ไม่แตะ production) - C รอ B + G3 + G4 ครบก่อน

สถานะการตัดสินใจ: **ตัดสินแล้ว 2026-10-30 (ผู้ดำเนินการ/เจ้าของโปรเจ็ค) — เลือกทาง A ถาวรตามตัวตนของผลิตภัณฑ์**

> ผู้ดำเนินการยืนยันว่า AEGIS คือ **ระบบตรวจจับการบุกรุกระดับ kernel (Kernel NIDS)**
> ไม่ใช่ระบบป้องกันการบุกรุก (NIPS) — enforcement/prevention activation (ทาง B/C ของ
> section นี้) ออกจาก scope ของผลิตภัณฑ์โดยการตัดสินของเจ้าของ ไม่ใช่งานที่ "ค้างรอทำ"
> production คง detection-only ตามที่ gate ปิดอยู่แล้ว; Slice C-lab/G1-G4 ของ 13.2
> เหลือเป็นความสามารถในเชิงเทคนิคที่พร้อมใช้ถ้าวันหนึ่งเปลี่ยนใจ (เอกสารยังคงรายงาน
> ความจริงของโค้ดเดิม) แต่ไม่นับเป็น remaining work ของแผนอีกต่อไป
>
> ย้ำหลักการ truth ของโปรเจ็คตามที่เจ้าของกำกับ (2026-10-30): สถานะ "เป็นระบบ NIDS
> ระดับ kernel แล้วหรือยัง" พิสูจน์จาก **source code ทั้งหมดที่ HEAD ปัจจุบัน** เป็นหลัก
> (ตามลำดับ source-of-truth ของ AGENTS.md) เอกสารบางส่วนถูกแก้ทีหลังงาน backend/
> frontend จึงต้องอ่านคู่กับโค้ดเสมอ และการปรับเอกสารให้ตรงโค้ดเป็นงาน records ปกติ
> ไม่ใช่หลักฐานพฤติกรรมระบบ

### 13.7 เอกสาร Design Review ของกลไกเปิด gate (G1) - draft

- docs/SLICE_C_LAB_GATE_DESIGN.md (DRAFT, ตรวจที่ HEAD 0cc8bee): เสนอกลไก compile-time lab option
  (`lab-prevention-gate`, default false) เป็น master switch เดียวของ host mutation ทั้ง S1
  (pipeline/policy-driven ผ่าน pep.enforce) และ S2 (control plane) + S1 boundary hardening +
  test/evidence plan + คำถามเปิดรอ reviewer
- ข้อค้นของ draft: วันนี้ S1 ไม่ได้ถูกคุมด้วย prevention gate (guard มีแค่ trusted policy +
  PEP availability) - ถ้า trust ถูกตั้งบน prod โดยผิดพลาด S1 host-mutate ได้ขณะ projection บอก
  detection-only; draft เสนอปิดช่องนี้ด้วย gate เดียว (gate closed = ไม่มี host mutation จากทุก surface)
- สถานะ: รอ signed-off review (sign-off table ในเอกสาร) - ยังไม่ implement ใด ๆ;
  production ยัง detection-only เหมือนเดิม

## 14. Slice C-lab (G1): prevention gate master switch + lab opt-in - IMPLEMENTED (E2)

ฐาน HEAD b3fe986; patch เดียว (commit: SLICE-C-LAB) - ดู EVI entry "SLICE-C-LAB" + admin-evidence/sliceC-lab-gate-20261018/

- Patch: build.zig (-Dlab-prevention-gate default false + build_options เฉพาะ exe graph); runtime_state.openPreventionGateLab
  (writer เดียว, preconditions 4 ข้อ fail-closed, in-memory) + GateSource; policy_ir.isHostMutating; pep_bindings.
  hostEffectGuardVerdict (gate -> trust -> availability) + enforce(..., gate_open); event_processor ส่ง
  state.g_prevention_gate_open; handler_registry enforcement.status เพิ่ม "gate_source" (additive); daemon เปิดเฉพาะ lab build
- S1 hardening (ปิด G1 หลัก): gate closed => block/quarantine/rate_limit ไม่ถึง provider boundary แม้ trusted+available
  (ปิดช่อง trust-misconfig ที่ projection เคยโกหกได้); pass/log/alert/escalate คงเดิม byte-identical
- TDD: RED - pytest surface pins 5 failed -> GREEN 5 passed; zig build test rc=0 (2161 total, 1 skipped; รอบแรกเจอ perf flake
  RegistryWatchQueue ที่รู้จัก -> rerun เขียว); mutation-red (ปิด guard + ring precondition ชั่วคราว) => 2 เทสต์เป้าหมาย fail
  ตามชื่อ (verdict spec; lab preconditions); full pytest 921 passed / 2 skipped / 27 subtests
- Pins ใหม่: tests/security/test_prevention_gate_surface.py (5) + unit ใหม่ 5 (verdict spec, closed-gate block path,
  lab preconditions x2, isHostMutating) + boot pin อัปเดตเป็น single-writer contract
- Default build = zero behavior change: ไม่มี caller ของ openPreventionGateLab ใน non-lab build; production ไม่ redeploy
  ในสไลซ์นี้; blocks delta คง 0
- ยังเปิด: G2 (execute RB-012 -> RB-013 บน isolated lab VM ด้วย lab build - operator), external security review ของ design,
  operator redeploy daemon (ค้างจาก V6-QUEUE-DROP)
- เอกสาร: docs/SLICE_C_LAB_GATE_DESIGN.md -> APPROVED/IMPLEMENTED + §6.1 + §8.1; RB-012 prerequisite เพิ่ม lab build line
- post-commit artifact rehearsal (E1, commit SLICE-C-LAB-ART): binary default ไม่มี literal เฉพาะของ gate opener แม้แต่ตัวเดียว (comptime flag ตัดโค้ดทั้งชุด) ขณะที่ lab build มีครบ; runtime strings อยู่ทั้งสอง build; live ยืนยันยังรัน binary เก่า (ไม่มี gate_source) - ไม่มี deploy ในสไลซ์นี้
- runbook precision สำหรับ E5: RB-012 step 1 require เพิ่ม gate_source:"lab-build-optin"; RB-013 ระบุ closed-gate answer ที่ reason เริ่ม prevention_gate_closed; operator tool post-redeploy-gate-check.py เพิ่มใน kit
- runbook precision 2 - elevation: ขั้นที่ mutate (RB-012: two-person/approve/block/rollback; RB-013: approve/quarantine/unblock) เป็น privileged-only (pipe role = client token elevation) จึงต้องรันจาก elevated shell; พิสูจน์กับ live แล้วแบบ deny-only (unelevated block/two_person -> AUTH_DENIED ก่อนถึง handler; verify=operate ผ่าน; kit: raw-role-probe.txt) - RB-012/RB-013/checklist ระบุครบ
## 15. Slice BRAIN-FASTPATH-FIX: คืนชีพ Tier-2 Case-2 pre-filter - IMPLEMENTED (E2/E4-local)

ฐาน HEAD dba2d75; patch เดียว (commit: BRAIN-FASTPATH-FIX) - ดู EVI entry "BRAIN-FASTPATH-FIX" + รายงาน deep scan ใน admin-evidence/deep-scan-20261019/

- ปิด P0 จาก deep scan: บล็อก "Cython Fast-Path Pre-filter" ของ brain/windows_brain.py เรียก scan_nop_sled /
  scan_shellcode_markers / detect_repeated_byte ที่ไม่ถูกนิยามที่ไหนเลย (aegis_hotspot.pyx เดิม retired,
  API แทนคือ aegis_brain_cython) => บนโฮสต์ที่มี accelerator compile อยู่ (production มี fast_scan.pyd)
  ทุก event Case-2 ("Forwarded: No Tier-1 Match") โยน NameError เข้า generic handler -> นับ [ERROR]
  และข้าม run_regex_scan ของ event นั้น => Tier-2 ตาบอดกับ event ที่ส่งต่อมา;
  บนโฮสต์ที่ไม่มี module บล็อกถูกข้าม => detection นี้ไม่เคยทำงานที่ไหนเลย
- แก้: 3 detectors ย้ายมาอยู่ที่ aegis_brain_cython.bridge เป็น pure Python (C acceleration เป็น follow-up
  ของ fast_scan.pyx) + mirrors ที่ import fallback ของ windows_brain.py + ปลด gate `if CYTHON_AVAILABLE`
  ของบล็อก pre-filter: detection ต้องไม่ขึ้นกับสถานะ compile ของ accelerator (build/runtime parity);
  return shapes ตรง call sites เดิม ((found,run,offset) / [(name,offset)] / (found,byte,run,offset)) และ semantics ตรง pyx เดิม
- TDD: RED = unit 6 fail (AttributeError) + behavioral fail โดยเห็น `[ERROR] name 'scan_nop_sled' is not defined`
  จาก brain process จริง -> GREEN = 7 passed (tests/brain/test_cython_prefilter.py ใหม่: 6 unit + 1 subprocess loopback
  พายโลด 250 ไบต์ชนะ CYTHON-003 ตรวจทั้ง stdout และ tmp logs/anomalous.json); tests/brain ทั้งหมด 50 passed
- Hygiene: เทสต์เขียน logs/anomalous.json ลง cwd ชั่วคราว (tmp_path) ไม่แตะ tree; spawn child ด้วย -u ให้เห็น match print ขณะรัน
- พฤติกรรมหลังแก้: pre-filter รันทุก build (accelerator = ความเร็วเท่านั้น), regex scan ไม่ถูกข้าม, ไม่มี enforcement ใหม่
- ยังเปิด: C acceleration ของ 3 detectors (ถ้าต้องการ perf), prod redeploy daemon (ค้างเดิมจาก V6-QUEUE-DROP), G2 lab (operator)

## 16. Slice POLICY-EVAL-FULL: policy evaluation เต็มรูปแบบของ live config - IMPLEMENTED (E2)

ฐาน HEAD d8a2064; patch เดียว (commit: POLICY-EVAL-FULL) - ดู EVI entry "POLICY-EVAL-FULL" + admin-evidence/policy-eval-full-20261019/

- ปิด P1 จาก deep scan (re-verified กับ source จริงก่อนแก้): loader ของ configs/policies.json เดิมเป็น inline ใน daemon.zig
  (326-471) ป้อน PolicySet ให้ event_processor.zig:211 - มี defect เงียบ 6 ชั้น: parse แค่ clauses[0].predicates[0]
  (multi-clause OR / multi-predicate AND ถูกตัด), gte -> gt, field/op ที่ไม่รู้จัก -> .kind/.eq, in -> .eq,
  ไม่ parse value_str เลย (match จาก JSON = pattern ว่าง = true ทุก event ที่ field นั้นมีค่า), @intCast id/ttl/value
  ติดลบ/overflow = panic/UB, condition หาย -> kind eq 0 (EventKind เริ่มที่ 1) = never-match เงียบ
- ผลจริงของ bug วันนี้: rule 1 "severity gte 6 / block" พลาด severity == 6 (critical, EventSeverity critical=6)
- evaluator (policy_ir.zig): Op +gte/+lte (ต่อท้าย enum ค่าเดิมไม่ขยับ), Predicate +value_list (in = membership จริง;
  ว่าง = single-value แบบ rule 5), field-domain dispatch: string fields {sni,dns_name,http_uri,http_host} เทียบ value_str,
  ที่เหลือ numeric เทียบ value_int - op ข้ามโดเมน / pattern ว่าง / string หาย = false เสมอ (ไม่มี true โดยบังเอิญ);
  deinit คืน value_list (เฉพาะ len>0)
- loader: extract เป็น policy_ir.loadPolicySetFromJson(allocator, bytes) -> LoadedPolicySet { ps, doc, report }
  (doc คงอายุ value_str; std.json.parseFromSlice duplicate string จริง - พิสูจน์ด้วย clobber-input + test pin);
  parse ครบทุก clause/predicate (cap 8x8), field 13 ตัว + op 9 ตัวครบ, value_str + "values":[...], POL-PRIO-070
  priority เดิม, validate id/ttl/value ขอบเขต (ไม่ @intCast ระเบิด), entry เสีย reject + นับ + reason keyword -
  set ไม่พัง, ไม่ reshape เงียบ; daemon เรียก loader ตัวเดียว (diff 10+/124-)
- policy_plane: compile path ตั้ง ir.signature = 0 (เดิมยัด SHA-256 8 bytes ลงฟิลด์ที่ doc เขียนว่า Ed25519;
  fingerprint ไม่ใช่ signature - ตัวจริงคือ policy_signing.zig Ed25519 ที่ต่อสาย daemon TRUST-WIRE-082 +
  policy.verify) + แก้ doc comment/header; test เปลี่ยนเป็น pin signature == 0; matches_any: pin single-value
  equality + comment (ไม่มี producer ส่ง list payload; reachable เฉพาะ policy simulate observe-only) - list semantics รอ contract decision
- TDD: RED - evaluator 6 fail runtime (0P/6F, red-01) -> GREEN 26/26; loader compile-RED (function ไม่มีอยู่, red-02 -
  จุดนี้คือเหตุผลที่ extract ออกมาให้ testable) -> GREEN 37/37; policy_plane signature pin RED ที่บรรทัด 580 (red-04)
  -> GREEN 62/62; real-config evidence runner: 6 loaded / 0 rejected / critical(6) -> rule 1 block (green-04)
- Gates: zig build exe rc=0; full zig suite 2182 passed / 1 skipped / 0 failed (rerun; รอบแรกเจอ perf flake
  RegistryWatchQueue ที่รู้จัก -> เขียว); full pytest 928 passed / 2 skipped / 27 subtests (frozen wire contract เขียว;
  รอบแรก 4 fails = digest drift ของ 3 ไฟล์ที่แก้ fresh_deploy preflight/t17 verify จับ -> --refresh-digests 612/612 แล้วเขียว)
- Hygiene: temp zig runner ที่วางใน src/ ชั่วคราวถูก pin tests/security/test_zig_test_scope.py จับทันที (test-bearing file
  ไม่มี proven execution edge) - ลบและ rerun scope เขียว; ยืนยันว่า hygiene pin ทำงานจริง
- พฤติกรรมเปลี่ยน: matched_policy ของ event severity==6 เข้า rule 1 (block) ก่อน - ตรง intent ของ config; enforcement
  ไม่ขยับ (gate/trust/PEP เดิม, production ยัง detection-only, blocks delta 0); live daemon ยังเป็น binary เก่า (redeploy ค้าง)
## 17. Slice STALE-DOC-SWEEP: truth docs ตรงกับ source จริง - IMPLEMENTED (E1)

ฐาน HEAD 67ff30e; patch เดียว (commit: STALE-DOC-SWEEP) - ดู EVI entry "STALE-DOC-SWEEP" + admin-evidence/stale-doc-sweep-20261019/

- ปิด P2 จาก deep scan (docs เก่าไม่ตรง source; re-verified ทุกข้อกับ source จริงก่อนแก้; banner + targeted fix
  ไม่ rewrite - คงโครงที่ tests/runtime/test_component_matrix.py pin ไว้):
  docs/WFP_IOCTL_STATUS.md เดิม "tracking-only" -> "IMPLEMENTED (lab-gated)" (callout = copy-only fail-open
  observe path + IOCTL ครบ 5 ตัว READ/BLOCK_FLOW/STATS/UNBLOCK_FLOW/QUERY_FILTER; block = FWP_ACTION_BLOCK
  exact-flow filter ที่ FWPM_LAYER_ALE_AUTH_CONNECT_V4 + filter_id read-back; src/policy/wfp_ioctl.zig READ-ONLY
  ตาม PEP-001; bridge = src/windows/wfp_ioctl.c -> aegis_wfp_user.dll; enforcement authority = rust-src wfp_adapter
  ที่ fail-closed ESCALATE reason 4)
- docs/PEP_QUARANTINE_STATUS.md เดิม "deferred" -> "IMPLEMENTED (QUAR-RCPT-112)" (EVT-112 @82e9f4a; primitive =
  flow-block เดียวกับ block ทุกด่าน: capability 0x01 / severity >= 7 two-person / quota T3-QUOTA / adapter
  filter_id; control path: prevention gate -> enforceQuarantineFlow -> queryFilterResult read-back ->
  EnforcementReceipt, mismatch = POSTCONDITION_FAILED + cleanup)
- docs/CLI_COMMANDS.md: ถอด 5 commands ผี (api/backup/logs/restore/watchdog) + เติม 11 ที่ขาด (queue/snapshot/
  readiness/forensics/bridge/brain/components/graph/iptest/authority/help) -> ตรง parser จริง 33 commands;
  ชี้ package กักกัน tools/legacy/aegisctl_commands_quarantined/ (ไม่ wired)
- docs/DEPLOYMENT.md: build order canonical ตาม build_truth.json (zig / cargo / root cmake 3 DLL / bridge cmake 3 /
  go nose / shield / brain / go aggregator / egui dashboard / WDK 4 scripts / ts_policy advisory), release layout
  runtime\, sc create AegisNids + sc failure ตรง installer.py, rollback RB-005 ผ่าน tools/upgrade_rollback.py,
  troubleshooting ชี้ port 5000 (Flask web dashboard = ตัวจริง; egui dashboard ไม่มี HTTP server)
- docs/runtime/COMPONENT_MATRIX.md + LOCAL_RUNBOOK.md: ตัด axum/:8080 ที่ตายแล้ว (axum ถอน - Cargo.toml GAP-5);
  web view = python -m tools.aegisctl.web_dashboard.app port 5000 (DASHBOARD_PORT), terminal view =
  aegisctl dashboard --watch; egui aegis_dashboard.exe = local viewer ไม่มี HTTP
- .analysis/security.md + control.md: banner HISTORICAL (ตรวจที่ HEAD 46b93dc ราว 2026-09; findings บางส่วนถูกแก้/
  แทนแล้วโดย slice หลัง) + ตัดคำกล่าว "current HEAD"; ไม่แตะเนื้อเชิงประวัติศาสตร์
- CONTRACT_MAP.json: เพิ่ม supplementary contract WIRE_PROTOCOL_V2 (shared/protocol/wire_v2.md; magic 0x57455631
  "WEV1" + canonical event 0x41454731 "AEG1"; v2 = 16B header + 133B payload = 149B)
- tools/release_candidate.py: KNOWN_LIMITATIONS เลิกอ้าง core/ (authority = src/policy + rust-src; installer =
  tools/installer.py) + rollback doc ชี้ src/control/handler_registry.zig / src/platform/win32_pipe.zig;
  ค้างถึง slice RELEASE-TOOLING: assembler ยัง copy REPO/core/*.zig + cite core/policy_signing.zig (โค้ดยุค T20)
- EVI: เพิ่ม V6-FLOW-036 (E2 @bde1c2c) + V6-DETECT-037 (E2 @3bd965c) ปิดช่อง traceability ของ commit ที่ลงจริง
  (in-file pins มีครบแล้ว) + entry STALE-DOC-SWEEP (E1) + last_updated_at; summary E1 24->25, E2 118->120
- TDD: RED = tests/docs/test_stale_doc_sweep.py 9 failed (red-01.txt) -> GREEN = 9 passed (green-01.txt);
  focused 137 passed (focused-01.txt)
- Gates: zig build rc=0; full zig suite 2182 passed / 1 skipped / 0 failed (zig-suite-run.txt); full pytest
  (CI scope tests/ --ignore=tests/test_e2e.py) 930 passed / 2 skipped / 27 subtests (pytest-full.txt);
  release_engineering --verify 612/612 ตรง (--refresh-digests 1 ไฟล์: release_candidate.py - digest drift จาก
  release-note text ที่แก้); truth.py verify TRUTH_VALID (restamp หลัง commit)
- Hygiene: 9 pins ใหม่เป็น read-only guards (ห้ามเขียน tree); ไม่มี enforcement เปลี่ยน (production ยัง
  detection-only, blocks delta 0); EOL คงเดิมต่อไฟล์ (LF ยกเว้น CLI_COMMANDS.md / CONTRACT_MAP.json = CRLF)

## 18. Slice DEADCODE-QUARANTINE: dead code ถูกกักกันอย่างมีกลไก + HEALTH counters บอกความจริง - IMPLEMENTED (E2)

ฐาน HEAD ba7d926; patch เดียว (commit: DEADCODE-QUARANTINE) - ดู EVI entries "DEADCODE-QUARANTINE" + "CONTROL-HEALTH-HONESTY"
+ admin-evidence/deadcode-quarantine-20261019/

- ปิด P2 จาก deep scan (35 ไฟล์แตะไม่ถึงจากทุก build root / 2 scaffolds superseded / incidents.show alias ทิ้ง payload /
  bridge command fake-success / runtime.stop/restart ค้างตัดสินใจ / HEALTH counters ปลอม 0 สาม components) - detection-only
  ทั้งหมด ไม่แตะ enforcement (blocks delta 0); agent non-elevated ทั้งรอบ
- Closure pin (mechanized quarantine): tests/security/test_zig_test_scope.py เพิ่ม BUILD_ROOTS 6 ตัว (main/daemon/all_tests/
  fuzz_entry/perf_bench_main/integration_test_main) + QUARANTINED_UNREACHABLE 35 ไฟล์ (7 non-test + 28 test-path) + assert
  สองทิศ (registered ต้องยังตาย / ไฟล์ตายต้องถูก register = ห้าม rot เงียบ, ห้าม promote เงียบ); ตัดสินใจไม่ rename 35 ไฟล์
  (จะพัง 6+ pins/manifest) - กลไกกักกันคือ registry นี้ + status headers; เติม status header 2 ไฟล์ที่ยังขาด
  (capture/flow_types.zig, capture/npcap_test_live.zig; reliability.zig มี REL-SPEC-050 อยู่แล้ว)
- ลบ 2 scaffolds (git rm): control/health/runtime_health.zig.scaffold (แทนด้วย state_machine+handler_registry) +
  tests/integration/golden_path_ffi.zig.scaffold (แทนด้วย wire v2 tests); --refresh-digests drop entries ให้เอง
  (610 artifacts kept, 11 digests updated, dropped 2, source_commit=ba7d926) - ไม่มี pin/manifest อ้างชื่อเดิมเหลือ
- incidents.show = show-by-id จริง (เดิม alias ของ incidents.list ที่ทิ้ง payload -> client ขอ 1 ตัวได้ทั้งลิสต์):
  ต้องมี {"id":<u64>} ไม่งั้น INVALID_INPUT/REJECTED; miss = INCIDENT_NOT_FOUND/NOT_FOUND; lookup ผ่าน
  threat_tracker.snapshotIncidentById สแกนตารางเต็ม MAX_INCIDENTS=4096 ใต้ mutex (ไม่ใช้ view SNAPSHOT_CAP 64 -
  id ที่ valid นอก top-64 ต้องเจอ); ไม่ wire CLI (zero callers; doc table ยังจริง); 6 zig tests ใหม่ (2 tracker + 4 handler)
- bridge command exports fail-closed (production mock): aegis_bridge_send_command เดิมปริ้นต์ "Command sent: type=.."
  + return 0 ทั้งที่ส่งจริงที่ไหนไม่ได้เลย -> -2 + stderr rejection note; receive_command -2 + note เช่นกัน; pin ใหม่
  tests/security/test_forbidden_edges.py::test_bridge_command_transport_stays_fail_closed สแกนเฉพาะ code lines
  (comments เล่าประวัติได้) เป็น sibling ของ block/unblock fail-closed pin
- runtime.stop/restart = decision pin (ไม่ implement จนกว่าจะมี daemon supervisor ที่ signalled/joined/verified จริง;
  สอดคล้อง tests/runtime/test_harness_scaffold.py ที่ NotImplementedError by design): เพิ่ม 2 zig tests ปักพฤติกรรม
  NOT_IMPLEMENTED/UNAVAILABLE + honest-state notes 3 ข้อใน shared/protocol/control_protocol.md (runtime.start idempotent /
  stop-restart refuse / incidents.show payload+miss semantics)
- HEALTH counters บอกความจริง 3 components (เดิม hardcoded zeros -> supervisor แยกไม่ออกว่า loop ตายหรือไม่):
  nose headlessTelemetry (in = samples ที่ consume, out = beacons ที่ emit หลัง print, last_event_ms = age ของ sample;
  0 = none yet) ผ่าน buildHeadlessState (schema §4.1 เดิม); aggregator Collector atomics (ingested/parseErrors/
  lastIngestMs) + Stats() เข้า handleHealth (out_events/dropped คง 0 พร้อม comment pull-only/no-drop-path);
  mouth health_pipe (in = บรรทัด log ที่ tail, out = probe ที่ flush response, last_event_age_ms saturating 0="never");
  probe ตั้งใจไม่แตะ tail timestamp เพื่อให้ tail ค้างมองเห็นได้; errors/dropped คง 0 พร้อม comment จุดที่ไม่มีทางเดิน
- inventory.json + reference_map.json regenerated (ครั้งแรกนับจาก slice 1-3; snapshot catch-up: sizes/counts +
  ลบ scaffolds + เพิ่มไฟล์เทสต์ของ slice ก่อน; ไม่มี freshness gate แต่เดินตาม rebaseline rule); เจอ ghost ระหว่าง regen:
  nose/aegis-nose.exe~ (go build temp ค้างตั้งแต่ 2026-10-07; ลบไม่ได้ด้วย ACL/ล็อกของผู้ใช้ปัจจุบัน) -> ย้ายออกจาก tree
  ไป admin-evidence (gitignored) แล้ว regen จน 0 ghosts
- TDD: RED->GREEN ครบทุก workstream - bridge pin RED->GREEN; closure pin demo จับไฟล์ปลอมจริง (temp runner
  src/zz_deadcode_focus_tmp.zig ถูกฟ้องเป็น unregistered dead code -> ลบ -> เขียว); zig focused RED compile
  (undeclared snapshotIncidentById) + RED assertion (incidentsShow คืน list) -> GREEN 354/354; nose RED signature ->
  GREEN; aggregator RED c.Stats -> GREEN; mouth RED unresolved helpers -> GREEN 13 passed
- Gates: zig build rc=0; zig build test rc=0; go test+vet nose/aggregator rc=0; cargo test mouth 13 passed +
  cargo build --release rc=0; full pytest CI scope 933 passed / 2 skipped / 27 subtests; EVI 2 entries (E2) +
  summary E2 120->122, known_gaps 230; restamp 9 maps หลัง commit + truth.py verify TRUTH_VALID
- Hygiene/พฤติกรรม: temp runner ไม่ค้างใน src/ (closure pin บังคับ); EOL เดิมต่อไฟล์ (LF ยกเว้น CLI_COMMANDS.md /
  CONTRACT_MAP.json / plan = CRLF); ไม่มี enforcement เปลี่ยน; live daemon ยัง binary เก่า (redeploy ค้างตามเดิม)

## 19. Slice CI-GAPS: ปิดช่องว่าง CI จาก deep scan §9 - IMPLEMENTED (E2)

ฐาน HEAD a38f414; patch เดียว (commit: CI-GAPS) - ดู EVI entries "CI-GAPS" + "CI-AGGREGATOR-HTTP"
+ admin-evidence/ci-gaps-20261019/

- ปิด §9 gaps ทั้งหมด: brain/test_*.py ไม่เคยรันใน CI / aegis_brain_cython (accelerator ที่ production ship
  เป็น fast_scan.cp3xx-win_amd64.pyd) ไม่ถูก build+test / mouth + aegis_dashboard ไม่มี gate / drivers ไม่มี job /
  e2e ถูก ignore / aggregator HTTP แทบไม่มีเทสต์ / trivy non-blocking ยังไม่ถูกทบทวน; detection-only ไม่แตะ
  enforcement (blocks delta 0); agent non-elevated
- ci.yml jobs ใหม่: brain-tests (CANONICAL required: python -m pytest brain/ -q, py3.11 + requirements)
  + cython-build-test (CANONICAL required: build brain/aegis_brain_cython + test_fast_scan + Case-2 pre-filter pin
  ใน accelerated config) -> เพิ่มเข้า ci-matrix needs ทั้งคู่ เพื่อให้ check_results fail pipeline ได้จริง;
  mouth-build-test + dashboard-build-test (SUPPORT: cargo test + cargo build --release ตาม manifest จริง);
  drivers-wdk-build (manual-only workflow_dispatch ผ่าน scripts/build_drivers.bat จนกว่าจะเห็น hosted run เขียวก่อน
  ค่อย promote เป็น PR gate); trivy comment เพิ่มผล review (คง non-blocking เพราะยังไม่มี triage SLA)
- ci_coverage.json: cython-scan = required:true + note ใหม่ (เดิม note อ้าง "built inside python-tests" ซึ่งจริงเฉพาะ
  brain/cython T5b ไม่ใช่ accelerator); shield = job "shield-build" จริง (required:false เพราะ runtime โหลดแบบ
  fail-safe: ไม่มี DLL/symbol = verdict unknown พฤติกรรมเดิมทุกบิต ตาม src/policy/shield_screen.zig ไม่ใช่
  fail-closed); entries ใหม่ brain/mouth/aegis-dashboard/drivers/e2e (e2e = documented decision: legacy harness
  อ้าง bridge/aegis_bridge.exe ที่ canonical build ไม่ผลิต -> job จะได้แค่ skip เงียบ = green wash; canonical
  integration coverage = zig build test + tests/runtime phase-t + python-tests + brain-tests)
- pins: tests/release/test_ci_gates.py +6 (job contents ของ brain/cython/operator tools, drivers manual-only,
  required ทุกตัวต้องถึง needs ของ gate, coverage entries ต้องชี้ job จริงหรือมี note, matrix สะท้อนความจริงใหม่)
  เป็น text-scrape ล้วน zero new dependency (dev venv ไม่มี pyyaml - RED รอบแรกจับได้จึงเปลี่ยนวิธี)
- gating proof (E2): simulated toJSON(needs) ผ่าน tools/ci_coverage.py check_results - all-success=0,
  brain-failed=1, brain-absent=1, cython-cancelled=1, shield-failed=0 (SUPPORT non-fatal) ตรงตาม semantics
- local job-command proofs: py3.11 venv (Astral/CPython3.11.16 = Python เดียวกับ CI) brain suite 88 passed
  fallback config (accelerator absent) + build_ext cp311 rc=0 + test_fast_scan 27 + pre-filter 7 (accelerated);
  py3.14 ได้ทั้ง accelerated และ fallback (88/7 ทั้งคู่, ซ่อน pyd ชั่วคราวแล้ว restore); mouth 13 passed +
  release build rc=0; dashboard 8 passed + release build rc=0; drivers job รัน local ไม่ได้ (ไม่มี WDK)
  = เหตุผลของ manual-only
- aggregator HTTP: +8 handler tests ใน go/aggregator/main_test.go (root/alerts/critical/by-hash round-trip
  200-404-400/stats/sessions/session-id/purge 405-400-200) - pins ของ behavior ที่ถูกอยู่แล้ว (GREEN first run
  ไม่มี RED; defect drive เดิมคือ /api/health ใน slice DEADCODE-QUARANTINE) + go vet clean
- Gates: pins RED->GREEN (5 fail -> 9 passed); ci_coverage exit 0 (optional gap เดียว = e2e->); full pytest
  CI scope 939 passed / 2 skipped / 27 subtests; zig build rc=0; release_engineering --refresh-digests 610/610
  (source_commit=a38f414); EVI 2 entries (E2) + summary E2 122->124, known_gaps 232; restamp 9 maps หลัง commit +
  truth.py verify TRUTH_VALID
- Hygiene: cython build regenerate tracked fast_scan.c ใน working copy (restore แล้ว; CI ephemeral + job นี้ไม่มี
  digest gate และ python-tests ที่มี digest gate ไม่ build module นี้); ลบ pyd cp311 ที่ venv สร้างทิ้ง;
  ไม่มี enforcement เปลี่ยน; live daemon ยัง binary เก่า (redeploy ค้างตามเดิม)

## 20. Slice RELEASE-TOOLING: pipeline release ตรง bundle จริง - IMPLEMENTED (E2)

ฐาน HEAD e1ff552; patch เดียว (commit: RELEASE-TOOLING) - ดู EVI entry "RELEASE-TOOLING"
+ admin-evidence/release-tooling-20261019/

- ปิด §7 จาก deep scan (re-verify ทุกข้อกับ source จริงที่ HEAD ก่อนแก้) + carryover จาก §17
  (release_candidate): verify_release.ps1 เดิม verify layout ที่ตายแล้ว (aegis-nids-v*.zip / bin\aegis_nids.exe /
  release-manifest.json / src\release_info.zig ซึ่งไม่มีอยู่จริง) -> เขียนใหม่เป็น read-only verifier ของ bundle
  ปัจจุบัน (aegis-nids-windows-*, manifest.json artifacts SHA256+length, required set, canonical_rules)
  ไม่มี Expand/Compress/New/Remove-Item/Set-Location เลย (ปักด้วย pin)
- release_package.ps1 = deprecation tombstone แบบ fail-closed (exit 1 + ชี้ package_release.ps1 /
  verify_release.ps1); ตัด body 2.x ทั้งหมด - ตัวเก่าดูได้ใน git history + สำเนา frozen ใต้
  release/T20-final/46b93dc/scripts/
- install_aegis.ps1 parity กับ NSIS path (tools/installer.py + docs/DEPLOYMENT.md): #Requires -RunAsAdministrator,
  BundleRoot optional (ให้ -Rollback/-Uninstall รันเดี่ยวได้ โดยมี check "required for install"), hash-verify
  ทุก artifact ก่อนแตะระบบ (ของเดิม - คงไว้), +Authenticode status gate (Valid ผ่าน / NotSigned + NotTrusted =
  warn จนกว่าจะมี EV cert/HLK / อื่นๆ รวม HashMismatch = fail closed), +register AegisNids (sc query guard,
  auto-start, description, failure restart/5000/restart/15000/restart/60000 ตรง NSIS), +sc start พร้อมเตือนถ้า
  LASTEXITCODE != 0, +-Uninstall (ลบ AegisNids + runtime/drivers/scripts + manifest.json/README.txt; AegisWfp
  ลบเฉพาะเมื่อ binPath อยู่ใต้ InstallRoot ไม่งั้นปล่อยไว้ + แจ้ง; คง configs ของ operator - parity NSIS uninstall)
- package_release.ps1: driver source เปลี่ยนเป็น build\x64\wfp\aegis_wfp.sys (canonical WDK output ตาม
  DEPLOY-120; drivers\wfp_callout\aegis_wfp.sys = pre-EVT-231 artifact ที่ installer pin ห้าม ship ซ้ำ) +
  bundle ship verify_release.ps1 ในตัว + README ใหม่ (verify/uninstall commands)
- tools/release_candidate.py: ตัด core/*.zig copy loop + empty core/ dir + cite core/policy_signing.zig ->
  src/policy/policy_signing.zig (authority จริงที่ daemon/handler_registry ใช้); docstring เลิกอ้าง
  release_package.ps1 (deprecated แล้ว)
- docs/DEPLOYMENT.md: แก้ให้ตรงความจริง - bundle ไม่เคยมี aegis-nose.exe (เดิมเขียนว่ามี); nose/minifilter =
  เนื้อหาฝั่ง NSIS installer path; +สรุปความสามารถ install_aegis (verify/signature/service/uninstall) และชี้
  verify_release.ps1
- TDD: RED = tests/release/test_release_tooling.py ใหม่ 10 failed / 1 passed (parse guard) -> GREEN = 11 passed;
  functional proof: verify_release.ps1 บน synthetic bundle (PASS -> tamper = SHA256 mismatch -> missing required
  file = FAIL; tree hash ไม่เปลี่ยน = read-only จริง) + บน bundle จริง 20261017 (9/9 artifacts, ทั้ง explicit
  -BundleRoot และ default discovery) + Parser::ParseFile clean ทั้ง 4 สคริปต์
- Gates: focused 89 passed (tests/release + stale-doc-sweep + operator-portable); full pytest CI scope 950 passed
  / 2 skipped / 27 subtests; zig build rc=0; release_engineering --verify เห็น drift 6 รายการตามคาด (5 ไฟล์ที่แก้ +
  runtime_manifest จาก restamp รอบก่อน) -> --refresh-digests 610/610 (source_commit=e1ff552) -> verify OK;
  EVI entry (E2) + summary E2 124->125, known_gaps 233; inventory regen 1699 ไฟล์ (+1 test ใหม่); validator 3 passed
- Hygiene: ไม่มี enforcement เปลี่ยน (blocks delta 0); agent non-elevated ทั้งรอบ - ไม่รัน installer จริง (pin เป็น
  structural + parse + synthetic); bundle tracked 20261017 คงเป็น frozen snapshot (สำเนา install_aegis.ps1 เก่า
  ใน bundle ไม่แก้); NSIS template ไม่แตะ (Authenticode runtime check ฝั่ง NSIS รอ signing gate G4 - บันทึกเป็น
  remaining); live daemon ยัง binary เก่า (redeploy ค้างตามเดิม)

## 21. Slice LEFTOVER-SWEEP: เศษ §3/§4 ที่เหลือ - ทุกจุดบอกความจริงตรงกับโค้ดจริง - IMPLEMENTED (E2)

ฐาน HEAD 7171e1f; patch เดียว (commit: LEFTOVER-SWEEP) - ดู EVI entry "LEFTOVER-SWEEP"
+ admin-evidence/leftover-sweep-20261019/

- ปิด 6 ข้อสุดท้ายจาก deep scan §3/§4 (re-verify ทุกข้อกับ source จริงที่ HEAD ก่อนแก้):
  (1) aegisctl policy enable/disable/reload = fail-closed จริงตาม capability matrix (guard ถูก pin ด้วย
  tests/runtime/test_gate_e.py) แต่ยังมี implementation ที่ไม่มีวันถูกเรียก + helper ตาย 3 ตัว
  (_state_file/_save_state/_query_control_safe) -> ลบออกทั้งหมด; USER_OPERATIONS_GUIDE.md เดิมโฆษณา
  คำสั่งที่ใช้ไม่ได้ -> แก้ให้ตรง (path จริง: configs/disabled_rules.json + rules reload; ระบุ exit code 4)
  (2) ts_policy dropped/winning_rule_indices เก็บ rule IDs ไม่ใช่ indices -> rename เป็น *_rule_ids +
  docstring บอกจริง (drop branch ว่างโดยโครงสร้าง: rule_id อยู่ใน sort key + duplicate id ถูก reject)
  (3) contract_freeze TEST_VECTORS: input="" ทั้ง 8 และไม่มีใครอ่าน .input -> ตัด field ทิ้ง + แยก
  verifyVectorTable() ตรวจ unique id/name + ครบ 4 vector types + non-empty; เพิ่ม test จับ duplicate จริง
  (F04 comment ชี้ executable suites ใน tests/contracts)
  (4) runtime_spine.zig header เดิมอ้าง "SINGLE runtime spine / authoritative registry" แต่ production
  ไม่โหลด (main.zig compose เอง; lifecycle.zig ถูก quarantine) -> เขียน header เป็น spec/proof-only +
  doc pin ห้าม main/daemon import (ปัก gap ตรงๆ; wiring = dedicated slice decision)
  (5) nose/ipc_reader.go (+ipc_reader_test.go): Bridge-era orphan, 0 non-test refs -> git rm
  (6) brain seam 10 โมดูล (acceptance_gates, canonical_event, core_routing, tier_routing,
  enforcement_pipeline, pep_request, pep_receipt, enforcement_receipt, policy_decision, forensic_evidence)
  ไม่ถึงจาก entrypoint production -> ติด SEAM-STATUS marker 10 ไฟล์ + pin import-graph ใหม่
  tests/brain/test_seam_disposition.py (closure(windows_brain.py) == module set - registry, สองทิศ)
- RED->GREEN ครบทุก workstream: 2F/9P -> 11P (stale-doc pins), 1F/2P -> 3P (seam pin),
  tsc 4 errors -> rc=0 + 76/76, zig focused undeclared verifyVectorTable -> 89/89;
  nose go build/test/vet rc=0; zig build rc=0
- zig build test 2190/2192: 1 fail = registered PERF-FLAKE (RegistryWatchQueue threshold 4807.3 vs
  floor 5000 ใต้โหลด build; warm rerun rc=0; perf path ไม่ถูกแตะโดย slice)
- full pytest CI scope 955P/2S/27 subtests (pre-refresh เจอ 5 digest-drift fails ใน tests/release
  ตามคาด -> refresh 608/608 dropped nose 2 entries -> verify OK, source_commit=7171e1f)
- inventory regen 1698 ไฟล์ (1699 -2 nose +1 test ใหม่); PHASE_0_TRUTH_REBUILD_REPORT.json refresh
  เป็น HEAD ปัจจุบัน (rebaseline side effect ตามแบบ 74864cd)
- Hygiene: ไม่แตะ enforcement (blocks delta 0); agent non-elevated ทั้งรอบ; ไม่ push;
  temp zig runner ถูกใช้เฉพาะ focused test แล้วลบก่อน commit

## 22. Slice REL-CLOSURE: Phase 9 re-scope (REL-001..004) + เศษ v-era สุดท้ายตรงกับ source - IMPLEMENTED (E2)

ฐาน HEAD 557b4ce; patch เดียว (commit: REL-CLOSURE) - ดู EVI entry "REL-CLOSURE"
+ admin-evidence/rel-closure-20261019/

- Phase 9 re-scope (re-verify ทุกข้อกับ source ที่ HEAD นี้ก่อนแก้): REL-001..004 = EVT-017..020
  (E2 @e6de1ae) ครอบ v5.0 PATCH-44/45 (src/forensic/release_manifest.zig + installer.zig) ซึ่งถูก
  อ้างจาก all_tests เท่านั้น -> คงเป็น spec reference และติด marker "SPEC-REFERENCE ONLY" +
  pin ห้าม main/daemon import (แบบเดียวกับ runtime_spine); ตัว implement จริงของแต่ละธีมถูกอ้างจาก
  entry เก่า: REL-001 = tools/release_engineering.py (digests/SBOM) + fresh_deploy preflight;
  REL-002 = tools/installer.py (NSIS manifest-driven + drivers) + verify_release.ps1 +
  install_aegis.ps1; REL-003 = installer upgrade-safety (EVT-221) + upgrade_rollback (RB-005);
  REL-004 = uninstall paths (configs preserved) + RB-004/RB-005 - Authenticode/HLK เหลือฝั่ง
  operator (G4)
- ปิดเศษ deep scan §3/§5/[S] สุดท้าย:
  (1) rust-src/lib.rs:63,2569 "Still unwired (no Zig caller)" = comment เก่า (จริง: wired ผ่าน
  src/policy/policy_signing.zig verifyViaRust -> sidecar envelope v1; key custody ยังตาม ADR-0005 Q3)
  -> แก้ comment ตรงความจริง + pin กันกลับมา
  (2) drivers/wfp_callout/aegis_minifilter.inf = T20-era leftover ผิดที่ (altitude แบบเก่า
  Parameters-DWORD ขณะที่ตัว canonical ใต้ drivers/minifilter ใช้ Instances-based) - 0 refs
  ปัจจุบัน รวมทั้ง installer -> git rm + pin "มีได้ที่เดียว"
  (3) compliance_reporter.zig = test-graph scaffold: 13/32 controls เป็น checkAlwaysTrue placeholder
  -> marker "TEST-GRAPH SCAFFOLD" + pin ห้าม production import (กัน compliance เคลมเท็จถ้ามีคน wire)
  (4) replay_integrity.zig ReplayComparison.compare() = 0 callers + คืน mismatches = undefined
  (deinit footgun) -> ลบ; compareAlloc เป็นทางเดียว + pin
- RED->GREEN: tests/docs/test_stale_doc_sweep.py +4 pins -> 4F/11P -> GREEN 15P;
  zig focused 114/114 (temp runner ลบก่อน commit); zig build rc=0; zig build test
  2190/2192 (1 = registered PERF-FLAKE RegistryWatchQueue 4895.1 vs floor 5000 ใต้โหลด; warm
  rerun rc=0); cargo check rc=0 (2 dead_code warnings เดิมของ aegis_pep); full pytest CI scope
  959P/2S/27 subtests; refresh-digests 608 kept / 6 updated (drivers tree ไม่อยู่ใน manifest อยู่แล้ว
  -> INF removal ไม่กระทบ digests) -> verify OK (source_commit=557b4ce)
- inventory regen 1697 ไฟล์ (1698 - INF); PHASE_0_TRUTH_REBUILD_REPORT.json refresh (head 557b4ce,
  valid; ไม่มี unresolved)
- Hygiene: ไม่แตะ enforcement (blocks delta 0); agent non-elevated ทั้งรอบ; ไม่ push; digest
  order = truth rebuild ก่อน refresh (runtime_manifest เป็น artifact)

## 23. Operator cutover: redeploy daemon dcb22a5 ขึ้น production สำเร็จ (2026-10-19 20:07) - EXECUTED (E5)

- operator (elevated) รัน Block A/B จาก `admin-evidence/operator-queue-20261019/`: staged `f223dcce…`
  hash-check ผ่าน -> backup live เป็น `.pre-dcb22a5` (`7cf8999a…`) -> Stop/swap/Start -> re-hash ตรง ->
  service RUNNING (Manual); Block B (non-elevated) เก็บ `after-*.txt` ครบ
- ก่อน cutover: gate-check FAIL (`no gate_source field: the OLD binary is still running`)
  แต่ v6 verify PASS อยู่แล้ว (306 submitted / 306 read)
- หลัง cutover: gate-check PASS `VERDICT: PASS - post-SLICE-C-LAB binary live; gate hard-closed; detection-only`
  (`gate_source:"closed"`, `prevention_gate:"closed"`, `host_effect_capable:false`); v6 live verify PASS
  (delta 476 submitted / 476 read / 0 dropped — counters รีเซ็ตที่ daemon restart ตามดีไซน์)
- status: RUNNING 7/7 subsystems, v5.0.0, PID 13796 (start 20:07:00); health: rules 23 / policies 6 /
  defcon HIGH(3) / nose_connected true / endpoint ownership CLEAR; nose PID 21568 (10/15) รอดจาก
  restart + reconnect เอง (frames ไหลเข้า daemon ใหม่)
- deltas ที่ยังไม่ active (optional): BRAIN-FASTPATH-FIX (brain PID 8944, 10/15 -> RB-017),
  nose/aggregator health-honesty counters (restart รอบถัดไป) — §6 ของ README ใน package
- rollback: `runtime\aegis_nids.exe.pre-dcb22a5` + `rollback\` ใน package (`7cf8999a…`) — ยังไม่ถูกใช้
- records: EVI `CUTOVER-DCB22A5` (E5) + entry UPDATEs (V6-QUEUE-DROP / SLICE-C-LAB / SLICE-C-LAB-ART)
  + postscripts ใน closeout ทุกไฟล์ที่ค้าง "redeploy pending" (supersede ครบ)
- hygiene: detection-only ตลอด (blocks delta 0); ไม่มี enforcement เปิด; agent non-elevated ทั้งรอบ; ไม่ push
- คิว operator คงเหลือ: G2 lab campaign (RB-012 -> RB-013; checklist @ `dcb22a5` — บันทึก SHA จริง),
  DEPLOY-120 installer host drill, RB-014/015/018/021, RB-016/017, G4 signing, external review, CI decision

## 24. Slice O2: Kernel outbound IPv4 capture - IMPLEMENTED (E2, host proof E5 PASS 2026-10-30)

> **สถานะ 2026-10-30 (host proof ปิดแล้ว):** outbound v4 capture พิสูจน์ครบวง
> **ring → daemon queue → authenticated forensic → CLI query** แล้วด้วย loopback probe
> (EVT `O2-OUTBOUND-FORENSIC-E5-20261030`). Candidate = O1 build ที่ source `24d8d81`
> (unsigned `A583B630…` rebuild ด้วย /Brepro ได้ hash เดิมเป๊ะ; sign เป็น `F63195B0…`,
> Authenticode Valid) + daemon ReleaseSafe `8B312864…` (build ใหม่ 14:57, pin ใน E5
> scripts ทั้งชุด). ลำดับพิสูจน์: หยุด Nose → takeover `kernel_fallback` (nose_absent) →
> ส่ง marker 51 ไบต์ `AEGIS-O2-DIRECTION-1192fcd3…` ไป loopback sink (ephemeral port
> 59607; server รับ marker ตรงเป๊ะ) → WFP rows 10→52 ระหว่าง takeover (361 หลัง
> handback), nose_frames_submitted 465→1254 พร้อม handback กลับ `npcap_primary` →
> payload-prefix query เจอ **2 records: outbound `direction=1` seq 97417 (payload_len 51,
> verified=true)** และ inbound duplicate `direction=0` seq 97418 ตามที่คาด → gate ปิด
> ทั้งก่อน/ระหว่าง/หลัง, forensic integrity ok ระหว่าง probe. Rollback คืน driver
> `49E65BB1…`, daemon `464E765B…`, services Running, gate closed, forensic verify ผ่าน.
> แปลว่า payload-offset fix (source `26513a2`) + O2 direction handoff ทำงานจริงบน host;
> ความล้มเหลวของรอบ 2026-10-26 (17:21 loopback เจอแต่ direction=0, 17:42 remote-sink
> หา payload ไม่เจอ) ปิดจากสาเหตุ driver ตอนนั้นยังไม่มี offset fix — ไม่ใช่ regression ใหม่.
> Loopback mode กลับมาใช้ได้เพราะหลักฐาน O1 E5 รอบเช้า (v4 loopback records
> `direction=1` + payload 14 ไบต์เต็ม) ยืนยันว่า outbound callback ยิงบน loopback จริง;
> scripts ทั้ง 5 ไฟล์ถูกอัปเดต pin + เปิด `-RemoteAddress/-RemotePort` เป็น optional
> (loopback = default, remote sink ยังใช้ได้เมื่อ VM online). Issue #24 ยังปิดอยู่
> (candidate คงอยู่ตลอด window). หลักฐาน:
> `admin-evidence/e5-host-proof-20261026/e5d-o2-offset-proof-20261030-150536.json`
> (+ functional/direction JSON + transcripts 3 ไฟล์).

ปิดช่อง "kernel L7 เห็นแค่ inbound" ที่ NIC-001 (§11) วัดไว้: driver เดิมมี callout
เดียวที่ `FWPM_LAYER_INBOUND_TRANSPORT_V4` ทำให้ detection ฝั่ง kernel ไม่เห็น
outbound payload (C2/exfil) เลย

- เพิ่ม callout ที่สองที่ `FWPM_LAYER_OUTBOUND_TRANSPORT_V4` (`AEGIS_OUTBOUND_CALLOUT_KEY`)
  พร้อม filter แบบ terminating + `PERMIT_IF_CALLOUT_UNREGISTERED` เหมือน inbound
- ใช้ record 48-byte เดิมและ ring เดียวกัน; `header.direction=1` เป็นตัวแยก
  (0=inbound) — ไม่มี ABI/wire change, ไม่แตะ enforcement
- inbound/outbound ใช้ emit helper ตัวเดียว (`AegisWfpEmitRecord`) เพื่อไม่ให้
  ring writer สองทางเบี่ยงกัน; acquire rundown ก่อน emit และ release หลัง emit
- teardown: ลบ outbound filter -> unregister outbound runtime -> ลบ BLM callout
  ทั้งสอง key -> ปิด engine; startup ล้มกลางทางเรียก `AegisWfpUnregisterCallout()`
  เพื่อไม่ให้เหลือคู่ callout ครึ่งเดียว
- Zig reader: `ParsedRecord.direction` อ่านจาก header และส่งเข้า
  `canonical_event.direction` (เดิมทิ้งค่าทำให้ outbound ถูกติดป้ายเป็น inbound)
- tests: `tests/wfp/test_kernel_bidirectional_capture.py` + อัปเดต pin ของ
  classify/rundown; `tests/wfp` 33 passed / 3 skipped (elevated host tests);
  `zig build` exit 0; `zig build test` exit 0 (มี benchmark `registry_trie`
  flaky หนึ่งรอบจากภาระเครื่อง แล้วผ่านเมื่อรันซ้ำ)
- O2 direction handoff (2026-10-26): พบว่า reader set direction ลงใน
  `CanonicalEvent` แต่ queue adapter ไม่พาไปต่อ; เพิ่ม in-memory sidecar ผ่าน
  queue และบันทึกลง forensic reserved metadata แบบ versioned (RecordHeader
  ยัง 144 B / slot 4 KB เท่าเดิม). `forensics.list/show/export` ส่ง
  `direction` เพิ่ม; record เก่า/producer ที่ไม่รู้ทิศทางได้ `null`. Targeted
  Zig tests 10/10 และ Python tests 11/11 ผ่าน; full `zig build test` ยังชน
  `RegistryWatchQueue` benchmark threshold สองรอบ (4,598.9 และ 4,202.2 ต่อ
  floor 5,000), ไม่ใช่ direction assertion. เป็น E2 เท่านั้น; host E5 ยังรอ.
- `zig build -Doptimize=ReleaseSafe` ผ่าน; candidate runtime `zig-out/bin/aegis_nids.exe` SHA-256
  `28E7DAD7D5FFDAFABF7A6EFDBA625BB1E516FC772EE32A9CC9B3F73931DA412A`.
  Live service ยังใช้ `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`
  SHA-256 `464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61`;
  candidate ยังไม่ได้ deploy. เตรียม runner
  `scripts/e5_o2_direction_verified.ps1` (AST parse PASS; ยังไม่ execute):
  preflight ปฏิเสธ daemon เก่าก่อนหยุด Nose, proof ใช้ loopback marker เท่านั้น,
  ต้องเห็น forensic `source=wfp_sensor`, `direction=1`, gate ปิด และ handback.
- E5D attempt (2026-10-26 16:08:28): runner หยุดที่ preflight ตามที่ออกแบบ
  เพราะ live daemon ยังเป็น hash `464E765B…` และไม่มี `direction`; ไม่มีการหยุด
  Nose หรือส่ง marker. Services ยัง RUNNING, prevention gate ยังปิด และ forensic
  verify เป็น `verified=true`. ผลนี้เป็น `BLOCKED_PRE_DEPLOYMENT`, ไม่ใช่ E5
  capture proof. เตรียม `scripts/e5_o2_deploy_candidate.ps1` สำหรับติดตั้ง
  candidate แบบ hash-pinned (`28E7DAD7…`) พร้อม backup/rollback; ต้องรันแบบ
  Administrator ก่อน แล้วจึงรัน `scripts/e5_o2_direction_verified.ps1` ซ้ำ.
- E5 deployment/readiness failure (2026-10-26 16:14): candidate
  `28E7DAD7…` เริ่มเป็น service process PID 28188 แต่ readiness query
  `forensics.list` ล้มเหลวและ deployment script rollback กลับ daemon เก่า
  `464E765B…`. WER `APPCRASH` exception `0x80000003`, offset
  `0x000000000009179a` เป็น process เก่าที่ถูก stop: faulting PID 11848 ตรงกับ
  daemon ก่อน deploy และ PE timestamp `0x6addf4cd` ตรงกับไบนารีเก่า. ยังไม่มี
  หลักฐานว่า candidate crash; สาเหตุ readiness query ยังไม่ทราบ. WER harvest มี
  `Report.wer` เท่านั้น ไม่มี `.dmp`/stack. หลัง rollback services RUNNING, Nose
  connected, prevention gate ปิด และ forensic verify ผ่าน. E5 runner รอบถัดไป
  หยุดที่ stale-runtime preflight. แยกวิเคราะห์ readiness failure และ old-daemon
  stop-time APPCRASH ตาม issue [#24](https://github.com/Supertee003/NIDs_Windows/issues/24);
  O2 host proof ยัง pending.
- Rollback E5 (2026-10-26 16:35:54): คืน daemon base `464E765B…` ด้วย backup
  ที่ hash ตรง; AegisNids/AegisWfp กลับ RUNNING, Nose connected และ counters
  เดิน, `prevention_gate=closed`, `host_effect_capable=false`, forensic verify
  ผ่าน. Candidate stability issue #24 ยังเปิด; ไม่ได้รัน direction capture proof.
- Deployment helper รอบ 16:29:49 ทำงานพร้อม transcript และ retry forensic-
  direction readiness สูงสุด 45 วินาที; probe ผ่านแต่ candidate service ออก
  ภายหลังด้วย 1067. เก็บ transcript ไว้และยังต้องหาสาเหตุ runtime exit ก่อน
  ใช้ candidate อีกครั้ง.
- E5 CDB diagnostic (2026-10-26 16:45:39): แนบ debugger กับ candidate PID
  3492 และจับ `RtlExitUserProcess` stack: `aegis_nids!abort` → `panicImpl` →
  `default_panic`; `symchk` ยืนยัน PDB ตรงกับ candidate และ map return address
  `0x00dff45d` กลับไปที่ `src/windows/etw_realtime.zig:1100` ภายใน
  `wrap`, จุดที่เรียก callback (`cb_fn(outer.callback_ctx.?, ...)`). Stack
  ยังไม่บอกว่า panic จาก optional unwrap หรือภายใน `etwCallback`. เหตุการณ์
  SCM 7031 ที่ 16:45:45.728 เกิด ~1.2 วินาทีหลัง PID 3492 start จึงเป็นช่วง
  runtime แรก ไม่ใช่ shutdown.
  JSON field `exit_trace_captured_by_cdb=false` ผิดจาก script throw ก่อน parse
  marker แต่ CDB log มี `[O2EXIT] ntdll!RtlExitUserProcess` และ stack ครบ.
  rollback คืน base hash `464E765B…`, service RUNNING, gate ปิด, forensic verify
  ผ่าน; ไม่ได้ทำ O2 traffic proof. เป็น STOP-THE-LINE: ห้าม deploy candidate หรือ
  ทำ O2 probe ซ้ำจนกว่าจะได้ panic source/repro และแก้พร้อม verification; issue
  [#24](https://github.com/Supertee003/NIDs_Windows/issues/24) อัปเดตแล้ว;
  attribution `aegis_etw_helper!wrap+0x3fd` และคำว่า shutdown ใน note ก่อนหน้า
  เป็นการอ่านผิดและถูกถอน ตาม correction comments.
- Patch O2-ETW-CONTEXT-001 (DATA-001; target HEAD `1294da6`; final HEAD
  `15a677b`): เปลี่ยน
  `EtwSource.setCallback` ให้ไม่รับ callback context จาก caller และส่ง `EtwSource`
  pointer ที่ native helper ถืออยู่เข้า callback โดยตรง; `etwThread` จึงไม่ส่ง
  `undefined` อีก. FFI signature, event schema, detection, authority, driver และ
  prevention ไม่เปลี่ยน. เพิ่ม synthetic native-record regression test. Focused
  test ผ่าน Debug/ReleaseSafe 2/2, ETW module tests 107/107, ReleaseSafe build
  ผ่าน และ PDB ตรงกับ candidate SHA-256
  `E19370F598507FBC9A1194EA8182059B319DFAF76DFF4D3DE34814C57386B407`.
  Full `zig build test`: 2,224 ผ่าน, 1 skipped, 1 benchmark miss (`RegistryWatchQueue`
  4,684 vs floor 5,000). Candidate ยังไม่ติดตั้ง; E5 stability/capture proof pending.
  Runner `scripts/e5_o2_exit_diagnostic.ps1` pin candidate hash ใหม่และแก้การอ่าน
  marker เพื่อไม่ให้ JSON พลาด exit trace.
- E5 stability (2026-10-26 17:01:34): patched candidate `E19370F5…` ผ่าน
  direction readiness และคงอยู่ครบ 30 วินาที ไม่มี service-exit 7031 ระหว่าง
  window; CDB จับ `RtlExitUserProcess` หลังสคริปต์สั่ง stop เพื่อ rollback เท่านั้น.
  Rollback คืน base `464E765B…`, services กลับ RUNNING, prevention gate ปิดและ
  forensic verify ผ่าน. อัปเดต deploy/rollback runners และเพิ่ม hash pin ใน
  direction proof script. เตรียม `scripts/e5_o2_functional_proof.ps1` ให้รัน
  deploy → outbound proof → rollback และ post-rollback checks ในคำสั่งเดียว;
  proof ต้องเห็น matched `wfp_sensor` record
  `direction=1`, WFP rows เพิ่ม, Nose handback ที่ read/submitted counters เดินต่อ
  และ gate ปิด.
- Functional orchestrator run (2026-10-26 17:06:20): deploy candidate สำเร็จและ
  forensic readiness ผ่าน แต่ helper ของ orchestrator จับ stdout รวมกับ child
  exit code จึงหยุดก่อน direction proof. `finally` เรียก rollback และ log ยืนยัน
  `ROLLBACK_OK`; orchestrator JSON รายงาน rollback false จากบั๊กเดียวกัน. ตรวจ
  host แยกแล้ว base hash ถูกติดตั้ง, services RUNNING, gate ปิด และ forensic
  verify ผ่าน. แก้ subprocess runner เป็น `Start-Process -Wait -PassThru`;
  dry-run ยืนยัน exit code 0/7 ถูกแยกถูกต้อง.
- Outbound E5 attempt (2026-10-26 17:10): takeover ไป kernel fallback, marker ถึง
  loopback server, WFP rows เพิ่ม 4→49 และ handback กลับ Npcap พร้อม Nose read /
  submitted counters เดิน. แต่ไม่พบ forensic marker record ที่ source=1 และ
  direction=1; gate จึง FAIL. Orchestrator result ไม่มี direction exit code เพราะ
  `Start-Process -Wait` รอ child tree รวม Nose ที่ยังรันหลัง handback; direction
  script JSON มีผล probe จริง. Rollback สำเร็จ, base hash กลับ, services RUNNING,
  prevention gate ปิด, forensic verify ผ่าน. แก้ wait ให้รอเฉพาะ PowerShell process
  และปรับ probe ให้ query marker โดยไม่กรอง source พร้อมบันทึก WFP rows ก่อน query.
  O2 capture proof ยัง pending จนกว่าจะระบุได้ว่า record attribution/payload หาย
  ตรงจุดใดและรอบถัดไปพบ `direction=1`.
- E5 รอบ 17:21 (2026-10-26) ใช้ query marker แบบไม่กรอง source แล้ว: พบ
  forensic record ที่ยืนยัน hash chain ได้ (`wfp_sensor`, payload 51 B, seq 20393)
  แต่ `direction=0`; takeover, WFP rows 18→72, handback และ Nose counters ผ่าน.
  Source inspection ยืนยัน driver ที่ติดตั้ง hash `49E65BB1…` ตรงกับ O2 signed
  candidate และมี callback แยก inbound (`direction=0`) / outbound (`direction=1`).
  Probe ปัจจุบันเชื่อม TCP ไป loopback listener บนเครื่องเดียวกัน จึงพิสูจน์เพียง
  inbound record ที่เห็น ไม่ใช่ outbound capture. Rollback กลับ base daemon
  `464E765B…` ผ่าน, services RUNNING, prevention gate ปิด, forensic verify ผ่าน.
  ไม่มีหลักฐาน ABI/driver contract mismatch และยังไม่แก้ source/driver; เปลี่ยน
  probe ขั้นต่อไปให้ใช้ controlled remote endpoint และจับคู่ marker/tuple กับ
  `direction=1`. O2 E5 gate ยังคง FAIL; ดู evidence
  `O2-OUTBOUND-LOOPBACK-INBOUND-ONLY-PARTIAL-E5-20261026-172112`.
- ปรับ `scripts/e5_o2_direction_verified.ps1` และ orchestrator ให้รับ
  `-RemoteAddress` / `-RemotePort` สำหรับ controlled TCP sink แล้ว; ก่อนรันให้
  เลือกเครื่องปลายทางที่ผู้ใช้ควบคุมและยืนยันว่ามี listener รับ connection. ไม่ส่ง
  marker ไป public third-party endpoint. ยังไม่ได้รัน host proof รอบใหม่.
- E5 remote-sink รอบ 17:42: Windows VM `192.168.126.20:47821` รับ marker
  `AEGIS-O2-DIRECTION-0195cf3b9374463a92ecf458a4fb367c` ตรงกับที่ส่ง; takeover,
  WFP rows 0→6, handback/Nose counters และ rollback ผ่าน. แต่ query forensics แบบ
  payload-prefix ได้ 0 records; จึงยังพิสูจน์ outbound capture ไม่ได้. JSON แสดง
  `marker_sent_to_remote=true`; console ยังพิมพ์ field loopback เก่าจึงขึ้น
  `marker=False` (แก้ script แล้ว). ขั้นถัดไปตรวจว่าข้อมูลขาออกหายที่ payload
  offset/truncation หรือ ring-to-forensics; gate ยังคง FAIL. ดู
  `O2-REMOTE-SINK-OUTBOUND-FORENSIC-MISS-E5-20261026-174241`.
- Patch `O2-OUTBOUND-PAYLOAD-OFFSET-001` (DATA-001; target `15a677b`, final
  source commit `26513a2`) แก้ contract mismatch: inbound transport buffer เริ่ม
  ที่ payload ส่วน outbound เริ่มที่ TCP/UDP header. Shared pure-C helper ตรวจ
  TCP data offset / UDP length แล้วคัดลอกเฉพาะ payload; scratch window เพิ่ม
  สูงสุด 60 B เพื่อเก็บ TCP options ระหว่าง gather และอ่าน header ภายใต้ ring lock
  เดียวกัน. Record ยังคง 48 B, IOCTL/authority ไม่เปลี่ยน, malformed/unsupported
  outbound เป็น header-only และยัง permit. WFP tests 42 passed/3 skipped; WDK
  build PASS, unsigned hash `E0C368C1…`. `truth.py verify` PASS หลัง commit และ
  `tools/rebuild_truth.py` rebaseline maps. E5 ยังรอ elevated operator proof;
  ใช้ VM sink ที่ `192.168.126.20:47821` และรัน
  `scripts/e5_o2_payload_offset_proof.ps1 -RemoteAddress 192.168.126.20 -RemotePort 47821`.
  Wrapper sign/deploys candidate, รัน functional proof และคืน driver เดิมใน finally;
  gate ต้องปิดและ rollback/forensic verification ผ่าน.
  — **ดำเนินการแล้ว 2026-10-30: PASS แบบ loopback mode** (VM sink offline; หลักฐาน O1
  E5 ยืนยัน outbound callback ยิงบน loopback จริง) กับ candidate ปัจจุบัน `A583B630…` +
  daemon `8B312864…`; ดูบล็อกสถานะด้านบนและ EVT `O2-OUTBOUND-FORENSIC-E5-20261030`.
- current unsigned payload-offset build: ถูกแทนที่ด้วย O1 build ที่ source `24d8d81`
  (รวม payload-offset fix): `build/x64/wfp/aegis_wfp.sys` 44,544 B
  SHA-256 `A583B630BCE55C7FBDE6B29B59657BABD0BD00910151F9257147F20DDE96732C`
  (WDK /Brepro rebuild 30-10 ได้ hash เดิม; signed `F63195B0…`; พิสูจน์บน host แล้ว
  วันนี้ แล้ว rollback — host driver ยังคง hash `49E65BB1…`).
- ~~ยังไม่ปิด: host proof ของ outbound capture (E5) และ O1 (kernel IPv6)~~
  **ปิดครบแล้ว 2026-10-30**: O2 host proof = EVT `O2-OUTBOUND-FORENSIC-E5-20261030`
  (ดูบล็อกสถานะด้านบน); O1 = EVT `O1-V6-SIDECAR-E5-20261030` (section 26).
- อัปเดต live state (2026-10-26): E5-A สลับ driver จาก `95C7…` เป็น O2 signed
  candidate `49E65BB12B4FC164F0B0C255AC75CDFA096F17AC77B056586BF16891FCDABE8C`
  (unsigned build `7EDE4DCD…`), signature Valid; AegisWfp และ AegisNids กลับมา
  RUNNING. หลักฐานนี้ยืนยันการติดตั้ง/เริ่มบริการเท่านั้น ไม่ยืนยัน outbound capture;
  probe เดิมใช้ parser แบบ fixed 48-byte stride จึงไม่นับเป็น functional proof.


## 25. Slice ACQ-ARB: network acquisition arbitration (Npcap vs WFP kernel) - IMPLEMENTED (E2, host switch E5 PASS)

ปิดข้อ DP-10 (สอง sensor family เป็น ingress พร้อมกัน = duplicate semantics):
ก่อน slice นี้ WFP telemetry submit ทุก row เข้า pipeline พร้อมกับ Nose/Npcap
ทำให้ event identity ซ้ำ, flow packet/byte นับซ้ำ และ rate rule เห็นซ้ำ

- `src/capture/source_arbiter.zig` เป็นผู้ตัดสินเจ้าของ ingress แต่เพียงผู้เดียว
  (pure decision + unit tests, ไม่แตะ device handle / enforcement):
  - `npcap_primary` = Nose connected+ready -> Nose submit, kernel ring ยังถูก
    drain แต่ row ถูกนับ `g_wfp_shadow_rows` และไม่ submit
  - `kernel_fallback` = Nose absent หรือ Nose submitted counter นิ่ง >= `STALL_MS`
    (10s) ขณะที่ kernel ยังเห็น row -> kernel submit ทั้ง inbound/outbound
  - `split_lab` = `AEGIS_CAPTURE_SPLIT=1` opt-in เฉพาะ interface ที่พิสูจน์แล้วว่า
    disjoint (lab); default ปิด
  - `none` = ไม่มี source; รายงานตรง ไม่แกล้งเป็น primary
- takeover ต้องมีหลักฐานสองอย่างพร้อมกัน: มี kernel row ขณะ Nose counter นิ่ง
  และนิ่งครบ 10s — network idle เปล่า ๆ ไม่ทำให้ mode กระพริบ; Nose กลับมา
  ส่ง frame เมื่อไร arbiter จะ stand down ก่อน submit record ถัดไป (overlap
  สูงสุดคือ record ที่ in flight อยู่แล้ว)
- `wfp_telemetry.zig` ถาม arbiter ต่อ record; shadow path ยัง advance ring
  ตามปกติ (ไม่ให้ ring 2 MB overflow) แต่ไม่เรียก `submitRecord`
- control plane: `queue.stats.wfp` เพิ่ม `mode`, `reason`, `shadow_rows`,
  `kernel_owned`; `aegisctl queue` แสดง mode/reason/shadow และบอกเมื่อ kernel
  เป็นเจ้าของ ingress (ไม่ใช่ "row หาย")
- tests: Zig unit suite ของ arbiter (state, stall rule, idle no-flap, resume
  stand-down, split opt-in) + `tests/wfp/test_capture_source_arbitration.py`
  (static pins) + `tests/tools/test_aegisctl_queue.py` (render)
- Host proof E5: **PASS** — harness `scripts/e5_arbiter_swap_verified.ps1` verified
  `npcap_primary → kernel_fallback → npcap_primary`; Nose frame read/submitted
  เพิ่มขึ้นและ WFP shadow rows เพิ่มขึ้นหลัง handback. Prevention gate ปิดและ
  `host_effect_capable=false` ทั้งก่อน/หลัง. หลักฐานเดิมที่ล้มเหลวเพราะขาด
  `-capture` ยังเก็บเป็น E5 PARTIAL แยกไว้. O1 (kernel IPv6) ยังรอการตัดสินใจ
  record identity.

## 26. O1 (Kernel IPv6) - record-header v2 (ตัดสินใจแล้ว: ทาง A; steps 1-3 landed 2026-10-29, step 4 E5 PASS 2026-10-30)

> **สถานะ 2026-10-30 (ปิดครบ 5 ขั้น):** O1 ใช้ **ทาง A (sidecar-in-payload)** และพิสูจน์ครบแล้ว:
> - steps 1-3 ที่ source commit `24d8d81` (decoder + driver v6 pairs + pins; rebaseline `f1302f5`;
>   EVT `O1-V6-SIDECAR-E2-20261029`, E2_count=139). WDK build เขียว (`aegis_wfp.sys` SHA-256
>   `A583B630…DE96732C`, C_ASSERT 48 เขียว), zig build test RC=0 (+6 O1 unit tests),
>   pytest 1025 passed / 0 failed (+5 static pins), truth TRUTH_VALID.
> - **ขั้น 4 (host E5) PASS 2026-10-30 12:27** — elevated run `scripts/c1_e5_sidecar_proof.ps1`
>   (hash pin + test-sign + auto-rollback): unsigned candidate `A583B630…` → signed
>   `F63195B0…` (45,968 B, signer CN=AEGIS NIDS Test Signing) ติดตั้งและรันจริง; อ่าน ring
>   ด้วย GENERIC_READ เท่านั้น (GET_STATS/READ_EVENTS): 894,306 ไบต์/14 reads, 858 records,
>   0 drops, 0 trailing. **812 v6 records** มี flags bit0 + payload_length ≥ 32, **33 records
>   probe-attributed** (TCP6 `::1` และ TCP6 host link-local `fe80::fad7:f941:3f9d:195c%24`
>   ทั้ง inbound layer 2 และ outbound layer 3); ICMPv6 proto 58 ก็เห็นใน ring (outbound 32 /
>   inbound 72 ไบต์ = sidecar 32 + ICMPv6 40), identity prefix
>   `{20010FB1:99, FE800000:16, 20010FB0:666, 26064700:4, 00000000:27}`; identity mismatch 0,
>   short claim 0, oversize claim 0. **46 v4 records** ยังรูปเดิม (flags clear, 16 attributed
>   จาก `127.0.0.1` regression). Rollback: driver กลับ `49E65BB1…`, daemon `464E765B…`,
>   gate closed, forensics verified=true/integrity=ok, services Running.
> - บั๊กที่เจอระหว่างทำหลักฐาน (แก้ในสคริปต์ ไม่ใช่ production): PS 5.1 `@($List[object])`
>   โยน `Argument types do not match` → `.ToArray()`; driver `READ_EVENTS` คืน batch สั้นที่
>   ขอบ record → drain วนจน `bytes == 0` (ไม่หยุดที่ `< 65536`).
> - หลักฐาน: `admin-evidence/c1-e5-20261029/c1-e5-sidecar-result-20261030-122702.json` (+`.log`);
>   attempt ที่ล้ม 2 ครั้ง (`…121927`, `…122311`) เก็บไว้เป็นประวัติของบั๊กข้างต้น.
>   EVT: `O1-V6-SIDECAR-E5-20261030`. ขั้น 5: source ไม่เปลี่ยน (script อยู่ใต้ `scripts/` ซึ่ง
>   ไม่ใช่ SOURCE_PATHS) maps จึงคงที่ `24d8d81`; ไม่แตะ build_manifest (ชุด artifact คงเดิม
>   616/616 — script เป็น evidence tooling ที่ติดตามใน git + EVT).
> ส่วนเนื้อหาด้านล่างคงไว้เป็น decision brief เดิม (บันทึกวันตัดสินใจ).

สถานะต้นทางที่ยืนยันแล้ว (ไม่เดา):
- kernel capture = v4-only (NIC-001 §11 วัดจริง: v6 marker ตอบผ่าน wire แต่ record 0 — callout
  ผูก INBOUND/OUTBOUND_TRANSPORT_V4 เท่านั้น)
- ring record = header 48 ไบต์ (`AEGIS_EVENT_HEADER`) + payload แปรผัน; consumer advance
  48+payload_length เสมอ; C_ASSERT pin 48 พร้อมคำสั่ง "Do not shrink" (EVT-213)
- Nose ปล่อย wire v2 frame ครบแล้ว (NIC-001: 200/200 dst6 ตรง) และ V6-QUEUE-DROP (§12) ทำให้
  pipeline รับ v2 frame ไม่ทิ้งเงียบ — เส้นทาง consumer ด้าน npcap พร้อมสำหรับ v6 ตั้งแต่วันนั้น
- การตัดสินแบบของ ADR-0006 (ฟอเรนซิก): "no layout break" เท่านั้น — O1 ใช้
  หลักเดียวกันได้ถ้าทางเลือกยังเปิดให้ทำ

### ทางเลือก header/identity (ต้องเลือกก่อนเขียนโค้ด 1 ไบต์)

- **ทาง A - แนะนำ: sidecar-in-payload (ไม่แตะ header)**
  - `flags` bit0 = "v6 sidecar นำหน้า payload": payload เริ่มด้วย src16 (16 ไบต์) + dst16 (16
    ไบต์) แล้วตามด้วย payload จริง (payload_length รวมทั้งหมด); u32 IP fields เก็บ prefix
    4 ไบต์แรกให้ตรงกับ sidecar (สัญญา IpMismatch ของ canon มีอยู่แล้ว)
  - ABI/สตรายด์/ring stats/minifilter ไม่เปลี่ยน; งานนี้ไม่แตะ shared wire codec (แปลว่า
    ไม่โดนกฎ one-schema-N-codecs เพราะ kernel ring record กับ wire frame คนละสัญญา)
  - decoder ด้าน Zig (`wfp_telemetry.zig`/ParsedRecord) อ่าน sidecar 32 ไบต์
    ส่งเข้า src_ipv6/dst_ipv6 ของ canonical; acceptance = sidecars ครบทั้งคู่เท่านั้น
- **ทาง B: header v2 จริง (stride 48→72/80)** เกิดเฉพาะเมื่อ (ก) ต้องการจะขยาย identity เพิ่ม
  ตอนนั้น (ท้าย v6 interface-id), (ข) ต้องเปิด enforcement v6 โดยเอา identity
  เข้า ioctl เดียวกัน — นี่คือ ABI break + dual-read; ถ้าเลือกทางนี้ต้องมี ADR
  แยก + คิว dual window ของ decoder ทุกภาษา; ข้อเสนอเบื้องต้นวันนี้ = ทาง A

### งานด้าน driver (ครบคู่เมื่อดำเนินงาน)

- เพิ่ม callout V6 สองชั้น: `FWPM_LAYER_INBOUND_TRANSPORT_V6` +
  `FWPM_LAYER_OUTBOUND_TRANSPORT_V6`; key/runtime-id/capture-filter ครบคู่แบบ
  outbound v4 เดิม; emit helper ตัวเดียว (`AegisWfpEmitRecord`) ให้ v4/v6 ใช้ร่วมกัน;
  teardown unregister ครบคู่ทั้ง v4/v6 (ห้ามเหลือครึ่ง)
- เงื่อนไข fail-open เท่านั้น (capture); enforcement v6 ไม่อยู่ในขอบเขต O1 (Slice C
  ยังคงปิดตามปกติ)

### คิวการทำงาน (หลังผู้ตัดสินใจเลือกทาง)

1. zig unit test ก่อน (แดง): header parse + sidecar ครบ/ไม่ครบ + pin ทิศทาง v6 rows
2. driver: รับ V6 callouts + sidecar emit + C_ASSERT เดิม 48 ยังคงเขียว (Zig build + WDK build)
3. zig reader: decode sidecar -> canonical sidecars; negative = sidecar ครึ่งเดียว reject ให้เขียว
4. host proof E5 บน lab (เทคนิค driver-swap แบบ g2-dupfilter-20261025d: candidate hash pin
   + backup + rollback verify) แล้ว probe: DNSv6/ICMPv6 marker จับได้จริงบน ring และ
   queue.stats เห็น event v6 ผลลัพธ์ detection (ไม่แตะ enforcement)
   — **ดำเนินการแล้ว 2026-10-30: PASS** (858 records, 812 v6, 33 probe-attributed, v4 regression
   46/16, zero defects, rollback verified; ดูบล็อกสถานะด้านบน)
5. rebaseline: plan/FLOW_MAP/CONTRACT_MAP/EVIDENCE_INDEX + ปิดหัวข้อ O1 ในแผนหลัก
   — **ดำเนินการแล้ว:** source คงที่ `24d8d81` (script ไม่อยู่ใน SOURCE_PATHS), EVT
   `O1-V6-SIDECAR-E5-20261030` บันทึกแล้ว, build_manifest adopt proof script

### เกณฑ์จบงาน (completion gate)

- record v6 ผ่าน pipeline ถึง canonical sidecars ครบ โดย ABI header 48 ไม่ถูกแตะ และ v4 path
  regression suite ยังเขียวทั้งชุด
- host E5: v6 marker traffic จับได้ + v4 rows ยังถูกต้องเดิม + shadow/arbiter ยังรายงานชัดตามเดิมทั้งคู่
- ไม่แตะ enforcement/PEP; `blocks delta 0` ยังคงสถานะตาม §13

### ความเสี่ยง/ขอบเขตที่ต้องรัด
- guard ของ decoder: payload_length >= 32 เสมอเมื่อ bit0 flags เปิด (ป้องกัน payload
  สั้นกว่า sidecar); ring 2 MB ยังบัญชีขนาดจริงตาม advance rule เดิม
- deploy driver ครั้งนี้ = สลับ candidate (test-signed ตามขั้นปัจจุบัน); เตรียม rollback hash pin เสมอ


## 27. RB-013 persisted diagnostic lab-kit E5 (2026-11-02) - G2-RB013-LOG CLOSED

> **สถานะ:** ปิดเฉพาะช่องว่าง observability ของ RB-013 ด้วย lab kit รุ่นก่อน HEAD
> ปัจจุบัน ไม่ใช่ current-source E5 และไม่เปลี่ยนสถานะ detection-only ของ production.

- PATCH-ID: `RB013-LOG-E5-20261102`; FLOW: `DATA-001 / RB-013`.
- สภาพแวดล้อม: Win11 lab VM `192.168.126.20` (isolated VMnet1), host `192.168.126.1`,
  lab build `zig build -Dlab-prevention-gate=true`; canary เดียว เวลา
  `2026-11-02T00:17:47-08:00` (host `15:17:47+07:00`).
- Kit ที่ติดตั้ง: daemon `86D4DD77...`, PEP `C7F20079...`, bridge `9D5D7D46...`,
  signed driver `8A2B3F12...` (เซ็นบน host ด้วย `CN=AEGIS Test Signer`,
  thumbprint `60B05537...`; guest ตรวจ `Valid Signature verified.`),
  lab policy `DB67B1B5...`.
- ผล: listener ได้ `ACCEPT 2026-11-02T00:17:47 192.168.126.1:60477`; diagnostic log
  `...\logs\aegis-daemon-diagnostic.log` (11,895,220 bytes, SHA-256
  `AC5CA4D6...`) มี 8 บรรทัดที่ epoch `1793607472` = `00:17:52-08:00`:
  `pep=quarantine confirmed=true filter_id=77892` 4 บรรทัด และ
  `action=QUARANTINED_CONFIRMED rule=0 policy_id=3 filter_id=77892` 4 บรรทัด.
- บรรทัดนี้ถูก emit หลัง `verifyEnforcementReceipt` ผ่านเท่านั้น
  (`src/policy/action_dispatcher.zig` ที่ `24d8d81`) จึงเป็น receipt-verified
  quarantine branch ไม่ใช่ request echo. ช่องว่าง `G2-RB013-LOG-20261023` ปิด.
- Restore: `RESTORE_OK=True`; baseline `E19C/617F/EF9B/AD23/B722` ตรงทั้งหมด;
  `AegisWfp`/`AegisNids` Running; `prevention_gate=closed`,
  `tier3_enforcing=false`, `enforcement_mode=detection-only`; lab payload ถูกลบ.
- ข้อจำกัด: ไม่ได้ยิง canary ที่สอง จึงไม่ได้ re-prove blocking effect;
  ไม่ได้เก็บ `metrics_after`; ไม่ได้ enumerate WFP filter หลัง restore
  (ถือว่าถูกลบตาม unload cleanup ของ `AegisWfp`); ไม่มี source commit ฝังใน
  binary. ขนาด daemon `9,731,584` ตรงกับ build ใหม่ของ `24d8d81` แต่ hash
  ไม่ตรง จึงไม่อ้าง bit-identical reproduction. Kit ไม่มี `AEGIS_NOSE_IFACE`
  ของ `53737e8` จึงเป็นรุ่นก่อน HEAD.
- หลักฐาน: `admin-evidence/rb013-log-e5-20261030/closeout.md`,
  `evidence-20261102/collect2.json`, `diag-hits.txt`,
  `guest-run-current-20261102.log`, `host-canary.json`, `listener.log`,
  `enforce-status-lab.json`, `enforce-status-restored.json`,
  `metrics-before.json`, `EVIDENCE_INDEX.json` entry `RB013-LOG-E5-20261102`.
- ยังเปิด: `E5-CURRENT-RUNTIME-MISMATCH` (current-source deployment + rollback)
  และ `IDS-XDR-005-WIRING-OPEN` (scope decision แยก).
- UPDATE 2026-11-05: `IDS-XDR-005-WIRING-OPEN` is CLOSED at E5
  (`EVIDENCE_INDEX.json#XDR-005-E5-20261105`); `E5-CURRENT-RUNTIME-MISMATCH`
  was CLOSED on 2026-11-04 by `RB-021-CANARY-F7C626D-20261104`. Broader
  supervised Windows E5/kernel qualification remains open; this RB013 record
  is historical.
