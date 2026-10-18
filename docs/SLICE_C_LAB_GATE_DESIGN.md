# Slice C Lab Gate - Design Review (DRAFT)

**สถานะ:** DRAFT - ต้องมี SIGNED-OFF REVIEW ก่อน implement ใด ๆ (ห้าม implement จากเอกสารนี้โดยตรง)
**ขอบเขต:** LAB ONLY - production ต้องคง detection-only (WARDEN_CUTOVER_SPEC) เอกสารนี้ไม่ได้อนุญาตให้เปิด gate บน production
**ที่มา:** แผน §13 (Slice C decision brief) ช่องว่าง G1/G2; docs/WARDEN_CUTOVER_SPEC.md; RB-012/RB-013; .analysis/security.md
**HEAD ที่ตรวจ:** 0cc8bee (2026-10-18)

---

## 1. ข้อเท็จจริงปัจจุบัน (ยืนยันจาก source)

คำถามกลาง: "อะไรบังคับ host mutation ได้จริง และอะไรกันมันไว้" - วันนี้มี 2 entry points

**S1 - pipeline (policy-driven, ต่อ event):**
- src/pipeline/event_processor.zig:226-258: policy match -> `pep_enf.enforce(ev, pol, pid, caps, req_id)` (call site เดียวของ enforce)
- guards ใน src/policy/pep_bindings.zig:139-153: (1) `requiresTrustedAuthorization(action) && !p.trusted` -> `escalate`; (2) `!available` -> `escalate`; แล้วจึงเรียก `aegis_pep_enforce` เข้า Rust PEP
- host effect เกิดใน Rust PEP (`aegis_pep` cdylib จาก rust-src/lib.rs) - grep ไม่พบ posture/gate check ฝั่ง Rust => Rust เชื่อ caller
- receipt -> `dispatchWithReceipt` (src/policy/action_dispatcher.zig:102-151) verify same-decision + tuple read-back -> นับ `g_confirmed_blocks` + forensic
- **S1 ไม่ขึ้นกับ prevention gate เลย** - ตัวเปิด S1 คือ "trusted policy" (`AEGIS_POLICY_ENFORCE_TRUSTED=1` + sidecar valid; src/daemon.zig:485-501) + PEP available

**S2 - control plane (manual):**
- `enforcement.block/quarantine` (src/control/handler_registry.zig:1740-1806): privileged role -> gate check (`PREVENTION_GATE_CLOSED`) -> `enforceFlow/enforceQuarantineFlow` -> read-back + receipt -> ENFORCED
- gate: `g_prevention_gate_open` (src/pipeline/runtime_state.zig:18-20) = false และไม่มี writer ใน-tree (pin test บรรทัด 65-84: "nothing in-tree can open it")

**Projection:** `enforcement.status` (src/control/handler_registry.zig:1518-1540): `host_effect_capable := provider_ready && gate_open`; `enforcement_mode = "enforcing"` เฉพาะ `gate_open && provider_ready`

**ช่องว่างความสอดคล้อง (เหตุผลหลักของ design นี้):** เพราะ S1 ไม่ขึ้นกับ gate - ถ้ามี trusted policy บน production (misconfig) S1 สามารถ host-mutate ได้ ขณะที่ projection ยังบอก detection-only / `host_effect_capable:false` => projection โกหก และ WARDEN spec ห้าม "filter changes" บน production

**เป้าหมายของ design:** **gate = master switch เดียวของ host mutation ทุก surface** => gate closed <-> ไม่มี host mutation ใด ๆ จาก S1/S2 และ projection เป็นจริงเสมอ

---

## 2. กลไกที่เสนอ (RECOMMENDED)

1. **Compile-time build option** `lab-prevention-gate` (default **false**) ใน build.zig - release/prod build ไม่ส่ง option นี้; ไม่มี env var / config / control verb ใดเปิด gate ได้ (คงหลัก "hard-closed by construction"; กัน runtime misconfig ทั้งหมด)
2. **Daemon init เท่านั้น (init-only):** หลัง Tier-3 init + PEP init + forensic ring init ก่อน pipeline threads เริ่ม: ถ้า compile-time true และ preconditions ครบ -> เปิดผ่านฟังก์ชันเดียว `openPreventionGateLab(...)`
   - preconditions: `pep_available` && `provider_ready()` && tier3 READY && forensic ring != null
   - ไม่ครบ -> คงปิด + log เหตุผล (fail-closed)
   - เป็นการเปิดในหน่วยความจำเท่านั้น (in-memory) - restart = ปิด; ไม่มี persistence
3. **Open record (provenance + evidence):** `diag.critical "LAB PREVENTION GATE OPEN"` + เขียน evidence log (ndjson) ครั้งเดียว + เก็บ `gate_source = .lab_build_optin` + แสดงใน `enforcement.status` เป็นฟิลด์ additive `"gate_source":"closed"|"lab-build-optin"`
4. **S1 boundary hardening:** เพิ่มพารามิเตอร์ `gate_open: bool` ให้ `pep_bindings.enforce(...)` -> `if (!gate_open) return .escalate;`
   - เหตุผล: เป็น choke point เดียวของ S1 (fail-closed ที่ขอบเขต authority แบบเดียวกับ trust/availability guard ที่มีอยู่แล้ว)
   - ห้าม `@import` pipeline/runtime_state ใน pep_bindings เพราะเกิด import cycle: pep_bindings <- runtime_manifest <- forensic_pipeline <- runtime_state (ตรวจแล้ว) จึงใช้พารามิเตอร์แทน
   - call site เดียว (event_processor) ส่ง `state.g_prevention_gate_open`
   - ทางเลือกสำรอง (ถ้า reviewer ไม่รับพารามิเตอร์): เช็คที่ call site + source-scan pin
5. **S2 คงเดิม** (มี gate check อยู่แล้ว) + เพิ่ม pin: call sites ของ `enforceFlow/enforceQuarantineFlow` ต้องมี gate check นำหน้า (assert รายชื่อ call sites ที่รู้จัก)
6. **Default = zero behavior change:** prod build (option false) ให้ผลเหมือนเดิมทุก path - S1 เป็น escalate เพราะ gate closed (ใน deployment จริงเดิม escalate เพราะ trust off อยู่แล้ว; ตอนนี้กันได้แม้ trust ถูกตั้งผิด), S2 ยัง `PREVENTION_GATE_CLOSED`, เพิ่มเฉพาะฟิลด์ `gate_source:"closed"` (additive)

---

## 3. สิ่งที่ต้องแก้ (implementation outline - หลัง sign-off เท่านั้น)

- `build.zig`: เพิ่ม option + ส่งเข้า module `build_options` ให้ exe และ test target (ปัจจุบันมี addOptions เฉพาะ `core_test_configs`)
- `src/pipeline/runtime_state.zig`: คง var เดิม; เพิ่ม `gate_source` + `openPreventionGateLab()` (writer เดียว); อัปเดต pin test จาก "no store exists" เป็น "writer เดียว, เปิดได้เฉพาะ lab build ที่ผ่าน preconditions"
- `src/daemon.zig`: call site เดียวหลัง init (ตาม §2.2) ผ่าน `@import("build_options")`
- `src/policy/pep_bindings.zig`: พารามิเตอร์ `gate_open` + guard; อัปเดต unit tests ที่เรียก `enforce()`
- `src/control/handler_registry.zig`: `enforcementStatus` เพิ่มฟิลด์ `gate_source`
- tests ใหม่: (a) unit: gate param false -> escalate แม้ trusted+available; true -> เดินต่อเข้า trust/availability logic; (b) source-scan: assignment ของ `g_prevention_gate_open` มีเฉพาะใน runtime_state (writer เดียว) นอกนั้นอ่านเท่านั้น; (c) release pin: ข้อความ `lab-prevention-gate` ต้องไม่ปรากฏใน scripts/release*, CI configs, installers
- docs: RB-012 อัปเดต prerequisite "เปิด gate ได้อย่างไร" (lab build); WARDEN spec อ้างกลไกนี้; แผน §13.7

---

## 4. Test / Evidence plan

- E2: unit + pins ข้างบน (ต้องเดินใน patch เดียวกับ code)
- E5: RB-012 (manual block ผ่าน S2) + RB-013 (quarantine) บน isolated VM จาก lab build ที่ HEAD เดียวกัน - ต้องได้ receipt ENFORCED + `enforcement.verify` MATCH + traffic effect + rollback
- E5/E6: WARDEN steps - canary attack ผ่าน S1 (trusted policy + Kali kit) -> `BLOCKED_CONFIRMED` เฉพาะมี receipt; soak 24h (zero `PEP_UNVERIFIED`, zero receipt mismatch); rollback drill <5 นาที (restart ด้วย non-lab build + `enforcement.unblock` เคลียร์ filters)
- kit: `admin-evidence/sliceC-lab-<date>/` + EVI entries; invariant: production ยัง blocks delta 0 และ prod binary รายงาน `gate_source:"closed"`

---

## 5. ความเสี่ยง + การควบคุม

| ความเสี่ยง | การควบคุม |
|---|---|
| lab flag หลุดเข้า release/CI | default false + release pin (§3c) + audit build recipe |
| เปิด gate โดยไม่ตั้งใจบน prod | ไม่มี runtime input (env/config/verb) + init-only + เฉพาะ lab build |
| trust misconfig เปิด S1 บน prod | S1 gate param (ปิดโดย default) - defence in depth |
| lab ยิงผิด targets | TEST-NET เท่านั้น (203.0.113.10 / 192.0.2.10) + snapshot + two-person + rollback drill (RB-012/WARDEN) |
| schema drift `enforcement.status` | additive field + อัปเดต pins ใน patch เดียว |
| "เปิดแล้วลืม" | in-memory only (restart = ปิด) + `gate_source` มองเห็นได้ + evidence record |

---

## 6. คำถามเปิดสำหรับ reviewer (ต้องตอบก่อน approve)

1. S1 hardening: รับพารามิเตอร์ `gate_open` ใน `enforce()` (แนะนำ) หรือเช็คที่ call site แทน?
2. ลำดับ guard ใน `enforce()`: gate check ก่อนหรือหลัง trust check? (แนะนำ: gate ก่อน - gate closed = escalate เสมอไม่ว่า trust ใด)
3. ฟิลด์ projection: `gate_source` ("closed"|"lab-build-optin") เพียงพอไหม หรือควรเพิ่มสถานะ trust (`policy_trust`) ให้ projection ตรงกับ S1 จริงด้วย?
4. ระดับหลักฐานตอนเปิด: `diag.critical` + evidence line พอไหม หรือต้องมี forensic record ด้วย?
5. preconditions: ต้องเพิ่ม "trusted policy verified" เป็นเงื่อนไขเปิดไหม? (แนะนำ: ไม่บังคับ - trust เป็นเงื่อนไขต่อ action ของ S1 อยู่แล้ว แต่บันทึกสถานะ trust ตอนเปิดไว้ใน open record)

---

## 7. Non-goals

- ไม่มีกลไกเปิด gate บน production (ไม่มี env / CLI / control verb)
- ไม่แตะ Rust PEP, driver (aegis_wfp.c), minifilter, quarantine comm
- ไม่มี persistence ของ gate state (in-memory เท่านั้น)
- ไม่เปลี่ยน wire contract อื่น; การเปลี่ยน `enforcement.status` เป็น additive + อัปเดต pins

---

## 8. Sign-off

| บทบาท | ชื่อ | วันที่ | ผล |
|---|---|---|---|
| Operator/User | | | |
| Security review | | | |
| Implementer | | | |
