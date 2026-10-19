# แผนความสมบูรณ์: Kernel-level Network IDS (AEGIS NIDS Windows)

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

## 13. Slice C (Enforcement Activation) - Decision Brief (2026-10-18, รอการตัดสินใจ)

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
  - RB-012 / RB-013 (lab proof; status NOT YET EXECUTED), RB-016 (production trust, OPERATOR ACTION),
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

สถานะการตัดสินใจ: PENDING (รอ operator/user)

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

