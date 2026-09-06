# AEGIS Gate Reports (G2→G20)

ต่อเนื่องจาก `docs/BASELINE_20260906.md` — บันทึกผลตรวจ/พิสูจน์ราย gate
สถานะใช้คำศัพท์ Rule 3: REAL / MOCK / SCAFFOLD / UNIT-VERIFIED / HOST-VERIFIED / PRODUCTION-VERIFIED

## G2 — Canonical Event Contract ✅ UNIT-VERIFIED (commit d4b6350)

- ตรวจ `core/canonical_event.zig`: magic/version/struct_size validation, atomic event ID,
  explicit field-by-field wire encoding (109B payload) — ครบตาม STEP 2 rules
- Gap ที่พบและแก้: host/process identity + confidence ไม่เป็นทางการ → formalize
  reserved-area layout เป็น contract (RES_OFF_*, node_id, confidence) + EventSource
  additive (npcap=9, host_telemetry=10, ml=11, federation=12)
- Proof: 21/21 tests + full suite 4269/4269 (3 env WFP step failures จาก baseline คงเดิม)
- เหลือ: provenance chain ยังเป็น context_flags ระดับ bit — เพียงพอสำหรับ v1

## G3 — Runtime Spine ✅ UNIT-VERIFIED

- init order ใน `core/lifecycle.zig` ถูกต้อง: forensic → fabric → sensors →
  detection → correlation → threat intel → brain → policy → PEP → forensics;
  production profile skip test modules (replay/e2e/perf/canary/fault/ips_sim)
- `core/runtime_spine.zig`: ModuleCategory production/tool classification,
  verifyLifecyclePattern, verifyWorkerModel, GoldenPathTracer (per-stage trace)
- Proof: 21/21 tests รวม "G3 Exit Gate: Golden Path trace" ผ่าน
- Dispatcher (`core/dispatcher.zig`): processEvent + EventFate + PipelineStats มีอยู่จริง

## G4 — Event Fabric Accounting ✅ UNIT-VERIFIED

- ตรวจ `core/nose_contract.zig`: SubmitResult มีเหตุผลครบ (accepted/rejected/
  dropped_at_source/dropped_by_fabric/not_initialized) แต่ facade เดิมนับแค่
  submit/pop/drop รวม — ไม่มี per-reason metrics
- แก้: `core/event_fabric.zig` เพิ่ม `Accounting` snapshot (submitted, accepted,
  rejected, dropped_by_fabric, not_initialized) + `identityHolds()` ตรวจ identity
  `input = processed + dropped + rejected + failed` ทุกครั้ง
- Proof: 55/55 event_fabric tests รวม identity test ผ่าน (accept/reject/uninit ผสม)

## G5 — Flow / Stateful Runtime ✅ UNIT-VERIFIED (audit)

- `core/flow_engine.zig`: MAX_FLOWS = 65536 (bounded), evictIdle() + sweep()
  มีจริง; ownership ชัดเจนผ่าน FlowEngine struct
- ยังไม่ measure eviction latency/high-watermark จริง → G16 ต้อง benchmark

## G6 — Detection ✅ UNIT-VERIFIED (audit)

- `core/detection_engine.zig`: ทุก detector คืน `Evidence` (verdict, confidence,
  rule_id, event_id) — ไม่มี enforcement call ใน detection path ตาม authority rules
- ครอบคลุม network events; host detection อยู่ที่ host_telemetry (G11 ต่อ)

## G7 — Correlation / Entity Model ✅ UNIT-VERIFIED (audit)

- `core/correlation_engine.zig`: EntityType (source_ip/dest_ip/session/user),
  EntityKey, CorrelationAlert มี `triggering_event_id` → trace
  Incident → Evidence → Event IDs ได้ตาม exit gate

## G8 — Threat Intel ✅ UNIT-VERIFIED (audit)

- `core/threat_intel.zig`: lookup/evidence เท่านั้น (IpMatch: severity, category,
  confidence, source attribution), bounded 4096 entries, ไม่มี enforcement API
- Brain/RAG: ตาม lifecycle เป็น advisor + fail-soft context, ไม่มี enforce path


## G9 — Policy Security Gate ✅ UNIT-VERIFIED (commit หลังจากนี้)

- พบ stub เดิม (`policy_plane.zig:281`): signature = SHA-256 fingerprint ไม่มี Ed25519
- **แก้แล้ว:** `core/policy_signing.zig` (additive, ไม่แก้ policy_plane) —
  sign/verify จริงด้วย `std.crypto.sign.Ed25519`, canonical digest ครอบ
  magic/version/rule_count/hash/policy_version/expiry, key_id + trusted key
  table + rollback tracker (highest accepted version)
- Verification: VALID / TAMPERED / INVALID_SIGNATURE / UNKNOWN_KEY /
  EXPIRED_POLICY / ROLLBACK ครบตาม report §9
- Proof (exit gates ครบ): 1-byte policy flip → fail, 1-byte signature flip →
  INVALID_SIGNATURE, unknown key → UNKNOWN_KEY, expired → EXPIRED_POLICY,
  v10 แล้ว v9 → ROLLBACK; ทดสอบผ่านทั้งหมด, ผูกเข้า `build.zig` test list แล้ว
- เหลือสำหรับ production: key management/persistence ของ highest version
  (G17 installer/config preservation)
