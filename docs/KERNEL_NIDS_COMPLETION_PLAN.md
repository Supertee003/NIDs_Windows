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
