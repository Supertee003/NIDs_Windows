# AEGIS Windows NIDS/IPS — Deep Audit 04: Detection, Policy, Forensics และ Incident Pipeline

**ขอบเขตและวิธีการ.** รายงานนี้ตรวจ source-of-truth ใน repository `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows` โดยใช้ `git ls-files` เป็น inventory และอ่าน implementation/test จริง ไม่ใช้ handoff เป็นหลักฐานแทนโค้ด ไม่รัน controlled host block และไม่เปลี่ยนระบบภายนอก. ตรวจทั้งหมด **304 tracked paths** ในกลุ่ม brain/shield/mouth, detection/analysis/policy, forensic/xdr, config/ts_policy/shared และ tests ที่อยู่ใน inventory; `src/analysis`, `src/forensics`, `src/incident`, `src/telemetry` ไม่มี directory tracked จริง ขณะที่ implementation forensics อยู่ที่ **`src/forensic` (singular)**. Zig tests ไม่ได้รันเพราะ sandbox ไม่มี `zig` executable.

## Executive summary

ระบบมีเจตนาสถาปัตยกรรมที่แยก detection → decision → PEP และมีหลักฐานบางส่วนของ bounded evidence, advisory-only Brain/RAG/Shield, CRC/SHA-256 record integrity, replay comparison และ Ed25519 API. อย่างไรก็ตาม **ยังไม่มีหลักฐานเพียงพอให้เรียก production-ready**. จุดเสี่ยงสูงสุดคือ (1) dispatcher เลือก allow/default allow และ PEP no-op เมื่อ dependency ไม่พร้อม ซึ่งเป็น fail-open, (2) active policy path ไม่ได้บังคับ signed PolicyIR/TrustStore และยังใช้ heuristic decision ที่ไม่มี policy provenance, (3) TS/Zig/Python canonical serialization ใช้คนละ byte stream, และ (4) signature matcher พลาด failure/suffix outputs. สิ่งเหล่านี้กระทบทั้งการป้องกันจริงและความน่าเชื่อถือของ forensic/incident record.

## Architecture and call/data/control flow

**Ingress/input.** Event Fabric ส่ง `CanonicalEvent` ให้ `src/policy/dispatcher.zig:drainQueueTimed()` ซึ่ง pop event, ตรวจ queue TTL แล้วเรียก `processFlow`/pipeline. Python `brain/windows_brain.py` เป็น process แยก รับ UDP ที่ `127.0.0.1:9999`, โหลด `configs/Rules.json`, สแกน regex ผ่าน Python/Cython และควรส่ง policy-neutral detection metadata กลับไป; ใน clean checkout dependency `brain/detection_scan.py` ไม่ถูก track.

**Detection boundary.** `detection_integration` เรียก `DetectionEngine.analyze`: built-in rule/block/severity/flow detectors คืน bounded `EvidenceList` สูงสุด 16 รายการ. `VerdictAggregator` รวม max verdict/confidence และอาจ escalate. Correlation, threat-intel และ RAG เป็น enrichment/evidence producers; RAG มี explicit no-block contract แต่ Brain ใช้ context คำนวณ score. Brain returns `BrainAdvice` ไม่มี WFP handle/blocked IP จึงเป็น advisory ใน data model แต่ `PolicyEngine` รับ advice และให้ priority `escalate_to_block` สูงสุด.

**Decision/policy boundary.** `src/policy/policy_engine.zig` ผลิต `EnforcementDecision` จาก Brain/TI/correlation/verdict; ไม่มี input signed PolicyIR/trust metadata. `policy_plane`/TS compiler/signing/trust store เป็นอีกสายหนึ่งที่มี tests แต่ไม่ถูกเรียกใน active dispatcher. `pep_bindings.zig` มี intended FFI contract และ trusted check แต่ dispatcher ใช้ `src/core/rust_pep.zig` ผ่าน `rust_pep_integration`, ซึ่งเป็น local safety model: localhost/private/critical-infra reject/defer และ block จริงจบที่ `host_effect_unavailable/failed`.

**Process/language/privilege boundaries.** Python/Cython และ Shield Rust (`shield/src/lib.rs`, `pep.rs`) เป็น advisory/no direct enforcement; MOUTH เป็น UI/health monitor. Zig dispatcher เป็น orchestrator และควรเป็น unprivileged planner. Rust PEP/Windows provider เป็น intended privilege boundary แต่ source ที่ตรวจมี simulation/no-op paths and no validated host receipt in the active integration. `action_dispatcher.zig` เองเพียง log/federate/forensic callback ไม่แตะ WFP.

**Outputs.** ผลลัพธ์คือ decision + PEP result, in-memory `ForensicsEngine` ring, optional `ForensicRing` CRC/SHA-256 chain, NDJSON logger/payload artifact, XDR incident/CEF export และ replay comparison. XDR/fabric มี incident/entity models แยกกันและยังไม่มีหลักฐานว่าถูก link ใน active dispatcher ทุก event. Forensics integration singleton log หลัง PEP แต่ไม่มี lock/atomic transaction และไม่บันทึก RAG context ใน `PipelineResult` เต็มรูปแบบ.

**Accounting.** Fate ledger มี enum และ `fatesBalanced()` แต่ processed ถูก increment เมื่อ stages หาย/PEP no-op ในหลาย path และ `g_total_failed/g_total_archived` ไม่ใช่ output ของทุก failure; จึงไม่ควรถือว่า accounting เป็น evidence ของ security outcome.

## Critical findings

### 1. C1 [Fail-open เมื่อ policy/PEP ไม่พร้อม]: `src/policy/dispatcher.zig:490-531,534-585` และ duplicate `src/policy/dispatcher_phase_b.zig:347-385,387-433` เลือก `.allow/default_allow` เมื่อ policy ไม่ initialized และสร้างผล PEP `.no_op` + `actual_action=.allow` เมื่อ PEP ไม่ initialized (`src/tests/integration/rust_pep_integration.zig:45-73`). ดังนั้น malicious/critical event ยังเดินต่อโดยไม่ถูกปฏิเสธ/กักไว้; test ยืนยัน behavior นี้เอง (`src/tests/integration/policy_integration.zig` และ `rust_pep_integration.zig:123-138`). นี่ขัด fail-closed และทำให้ telemetry `processed` ถูกนับแม้ enforcement ไม่เกิด.
### 2. C2 [Policy authority ไม่ใช่ signed source-of-truth]: runtime path ใช้ heuristic `src/policy/policy_engine.zig:126-223` ซึ่งตัดสิน block จาก Brain/TI/correlation/verdict โดยไม่รับ `PolicyIR`, `SignedPolicy`, `TrustStore` หรือ verification result; `policy_plane.zig:224-286` และ `policy_signing.zig:127-167,420-461` เป็น additive/test path ที่ไม่ได้เชื่อมเข้ากับ dispatcher. แม้ `policy_ir.zig:81-88` ระบุ privileged action ต้อง trusted แต่ active `EnforcementDecision` ไม่มี trust metadata และ runtime PEP ที่ dispatcher เรียกคือ simulation `src/core/rust_pep.zig:122-203`, ไม่ใช่ `pep_bindings.PepEnforcer` ที่ตรวจ `p.trusted` (`src/policy/pep_bindings.zig:98-134`). หาก host-effect provider ถูกเปิดภายหลัง action ที่ไม่ได้มาจาก signed policy จะข้าม authority gate.
### 3. C3 [Signature/canonical serialization ข้ามภาษาไม่ compatible]: TS ใช้ JSON canonical bytes/typed-value FNV (`ts_policy/src/compiler.ts:268-305,376-390`); Zig compiler ใช้ `std.mem.asBytes(&rule)` ซึ่งมี slice pointers และตั้ง `ir.signature=hash` เป็น SHA-256 fingerprint ไม่ใช่ Ed25519 (`src/policy/policy_plane.zig:267-287`); Zig signer ยังใช้ raw struct bytes (`src/policy/policy_signing.zig:92-99`) ขณะที่ Python test ยอมรับว่า TS/Python กับ Zig ใช้คนละ byte stream (`tests/policy_signing/test_t7_signed_policy.py:48-59`). จึงไม่มีหลักฐานว่า policy ที่ compile/sign ใน TS จะ verify ใน Zig ได้จริง; policy authenticity boundary ใช้งานไม่ได้ตามที่อ้าง.
### 4. C4 [Detection false negative จาก Aho–Corasick]: `src/detection/signature_engine.zig:100-136` ไม่ merge failure-state outputs และ `match/matchFirst` (`:145-187`) อ่านเฉพาะ output ของ current state ไม่เดิน failure chain. Pattern ที่เป็น suffix/overlap จึงหาย เช่น `he` เมื่อพบ `she`; test เพียง `matches.len >= 2` ไม่ตรวจครบทุก rule (`:206-218`). `State.depth` เป็น `u8` (`:42-48`) ทำให้ pattern ยาวเกิน 255 overflow และ `output_count` เป็น `u8` ทำให้ output ร่วม state เกิน 255 ผิดพลาด. นี่เป็น correctness/security defect ที่ทำให้ signature หลบการตรวจได้.

## Important findings

### 1. I1 [Decision ไม่ผูก event identity อย่างเข้ม]: `src/policy/policy_engine.zig:126-222` รับ `event` แต่ทิ้งด้วย `_ = event` และใช้ `av.event_id`; ไม่มีตรวจว่า `av`, TI, alert และ Brain มี event_id เดียวกัน. การผสม evidence ข้าม event/thread สามารถเปลี่ยน action ได้. `forensics_engine.zig:123-156` บันทึกค่าเหล่านี้โดยไม่ validate identity.
### 2. I2 [Singleton/global state ไม่ปลอดภัยต่อ concurrency]: `src/policy/dispatcher.zig:76-88,203`, integration facades (`src/tests/integration/detection_integration.zig:16-21`, `brain_integration.zig:14-18`, `forensics_integration.zig:15-17`) และ engine counters หลายตัวเป็น plain mutable globals/counters ไม่มี mutex/atomics. `policy_engine.zig:116-120`, `brain_engine.zig:85-88`, `forensics_engine.zig:89-94` จึงมี lost updates/ข้อมูลระหว่าง shutdown และ process event พร้อมกัน.
### 3. I3 [ThreatTracker map race และ duplicate incident]: `src/detection/threat_tracker.zig:124-156` เรียก `AutoHashMap.getOrPut` โดยไม่ถือ `self.mutex`; mutex ครอบเฉพาะการสร้าง incident หลังอ่าน `incident_id` แล้ว และไม่มี double-check หลัง lock. concurrent flow จึง data-race และอาจสร้าง incident ซ้ำสำหรับ flow เดียว.
### 4. I4 [XDR window/layer semantics ไม่ถูกบังคับ]: `src/xdr/xdr_engine.zig:77-113` ตรวจ required layers แค่ network+host แม้ rule 3002 ต้อง identity, ไม่ใช้ `rule.window_sec` เลย และสะสม score/trigger ซ้ำทุก event; score `u16` อาจ overflow. ผล alert จึงไม่ deterministic ตามกติกาใน config.
### 5. I5 [XDR fabric อ้างว่า dispatch PEP ทั้งที่ไม่ได้ dispatch]: `src/xdr/xdr_incident_fabric.zig:195-213` ตั้ง `dispatched_to_pep = d.isEnforcement()` เพียงจาก action ไม่ได้เรียก PEP หรือรับ receipt. นี่ทำให้ incident evidence อาจรายงาน host action ที่ไม่เกิดจริง; integration XDR (`src/tests/integration/xdr_harden_integration.zig:37-43`) ยังเพิ่ม `total_incidents` แม้ `processRecord` เพียง update incident เดิม.
### 6. I6 [ForensicsEngine recent() panic/garbled slice เมื่อ ring wrap]: `src/forensic/forensics_engine.zig:187-194` คืน `self.ring[start..start+actual_n]` โดยมี comment เองว่าใช้ไม่ได้เมื่อ wrap; หลังเกิน 4096 records start+n อาจเกิน array boundary. test `:351-362` ทดสอบเฉพาะ 5 records ไม่ทดสอบ wrap + recent.
### 7. I7 [ForensicsEngine และ XDR ไม่ lock]: `src/forensic/forensics_engine.zig:100-200` ไม่มี mutex รอบ log/get/recent/reset; `src/xdr/xdr_harden.zig:208-351` ก็ไม่มี synchronization และเมื่อเต็ม reset `incident_count=0` (`:231-236`) ทำให้ข้อมูล incident เดิมหายโดยไม่มี dropped/overwrite evidence. `xdr_correlator.zig:163-170` คืน pointer หลัง unlock ทำให้ reader ถือ pointer ขณะ writer เปลี่ยนข้อมูล.
### 8. I8 [Forensic hash chain เป็น in-memory/ring-local เท่านั้น]: `src/forensic/forensic_pipeline.zig:301-330` ข้าม chain-link check สำหรับ oldest retained record และไม่มี external anchor/signature; หลัง wrap จึงพิสูจน์ได้เพียง record ที่เหลือ ไม่พิสูจน์การลบ/เปลี่ยนช่วงก่อนหน้า. `initMemory` (`:70-73`) ไม่ validate size ให้เป็น multiple/ไม่น้อยกว่า `RECORD_BYTES`; ขนาดผิดอาจทำ `appendWrapped` เขียน slice `0..RECORD_BYTES` เกิน buffer.
### 9. I9 [Replay fail-soft กลบ absence]: `src/tests/integration/replay_integration.zig:65-105` คืน `no_diff` เมื่อ replay engine ไม่ initialized แทน `unavailable/error`; caller จึงอาจสรุปว่า replay ตรงกันทั้งที่ไม่ได้ replay. `src/forensic/replay_engine.zig:168-231` เปรียบเทียบ PipelineResult ที่ถูกสร้างจาก caller ไม่ได้อ่าน event/forensic sequence หรือ rerun detector/policy จริง.
### 10. I10 [Policy compiler/IR semantic defects]: `src/policy/policy_plane.zig:145-160` ไม่ตรวจ `condition_count<=4` ก่อน index array; `.time_window` ถูก `continue` จึงไม่ match เวลาเลย; `.matches_any` ถูกลดรูปเป็น equality (`:95-103`). `src/policy/policy_ir.zig:133-174` `.in` ก็เป็น equality. `configs/policies.json:9-20` ใช้ severity 6 ทั้งที่ canonical detector severity อยู่ 0-3 และไม่มี loader ที่เชื่อมไฟล์นี้เข้ากับ active `PolicyEngine`.
### 11. I11 [Config/rule source ซ้ำและ action vocabulary ไม่เป็น authority เดียว]: `config/Rules.json` กับ `configs/Rules.json` มี duplicate rule sets; Python ใช้ `configs/Rules.json` (`brain/windows_brain.py:115-139`) ขณะที่ `configs/policies.json` มี policy อีกชุด และ Zig signature engine มี `RuleAction` อีก enum (`src/detection/signature_engine.zig:18-24`). ไม่มีหลักฐาน schema/version/signature check เดียวก่อนใช้ rules.
### 12. I12 [PII/secrets/forensic retention]: `src/forensic/forensic_log.zig:226-236,267-305,389-419` เขียน source IP, session ID, rule/extra และ `capturePayload` เก็บ full raw payload ใน `logs\payloads`, ใช้ชื่อจากเพียง 64 บิตแรกของ SHA-256 (`:399-415`), ไม่มี ACL/retention/encryption/secret redaction. `src/policy/trust_store.zig:41-53` เก็บ key material ใน heap (แม้ wipe ตอน deinit) และ key generation เป็น mock random 32-byte placeholder (`:95-104`), ไม่ใช่ CNG/HSM evidence.
### 13. I13 [Forensic/trace linkage validation ไม่พอ]: `src/forensic/decision_trace.zig:87-103` บังคับเพียงลำดับ link แต่ไม่ตรวจ ref IDs ว่า event/policy/verdict/evidence เป็น causal เดียวกัน; `SecurityDecisionTrace.validate` ตรวจแค่ magic/version (`:356-358`) และ `setPepDecision` map unknown ordinal เป็น logged_only (`:374-383`). `src/forensic/forensics_engine.zig:66-73` เก็บ `policy_rule`/PEP status แต่ไม่มี receipt/trace ID เต็มรูปแบบ.
### 14. I14 [XDR entity/incident correlation มี identity poisoning และ capacity silent loss]: `src/xdr/xdr_incident_fabric.zig:151-168,216-237` merge incident ด้วย entity string อย่างเดียว ไม่มี time window/normalization/authentication; attacker ที่ควบคุม key สามารถรวมเหตุการณ์ต่างกัน. เต็ม `MAX_INCIDENTS` คืน 0 แบบ fail-soft (`:156`) โดยไม่มี error/metric ให้ caller บังคับทบทวน.
### 15. I15 [CEF/log serialization injection และ partial write]: `src/xdr/xdr_harden.zig:173-195` ใส่ `incident.summary` ตรง ๆ ใน CEF โดยไม่ escape `|`, `=`, newline; `src/forensic/forensic_log.zig:309-323` ใช้ `WriteFile` แล้วตรวจเพียง return code ไม่ตรวจ `bytes_written == written.len`. Log/CEF downstream จึงอาจ parse ผิดหรือถูก log injection.
### 16. I16 [Python brain clean-checkout/reliability]: `brain/windows_brain.py:63-65,269-291` import `brain.detection_scan` ซึ่งมีอยู่ใน working tree แต่ไม่อยู่ใน `git ls-files` inventory (และมี `detection_result` dependency ด้วย). clean checkout ตาม repository source-of-truth จะได้ `scan_to_detection_result=None`/unavailable; ทั้งที่ startup ยังทำงานแบบ degraded. `request_enforcement_via_pep` (`:162-185`) เป็น stub คืน FAILED เสมอ จึงไม่มี production enforcement evidence.
### 17. I17 [MOUTH/Shield ไม่ใช่ enforcement evidence]: `shield/src/lib.rs:18-23` และ `shield/src/pep.rs:19-24` เป็น advisory scanner; auth token เพียง non-empty/not `REPLACE_ME` (`:10-17`) ไม่ใช่ cryptographic authentication. `mouth/windows_sec_monitor.rs:24-243` ทำ health named pipe แบบ detached threadและรับ content โดยไม่ parse/auth request. ไม่ควรนับเป็น privilege boundary หรือ PEP implementation.
### 18. I18 [Threat intel/RAG state consistency]: `src/detection/rag_intelligence.zig:109-168,191-198` lock query/update แต่ `getStats` อ่าน `db_count` โดยไม่ lock; `src/detection/threat_intel.zig:169-196` `AutoHashMap` ไม่มี synchronization และ counters plain u64. การ feed ingestion พร้อม lookup อาจ race/ทำให้ evidence provenance/statistics ไม่สอดคล้อง.
### 19. I19 [Evidence aggregation assumptions]: `src/detection/verdict_aggregator.zig:86-120` นับ `agreeing` จากจำนวน evidence ที่ verdict เท่ากัน ไม่ใช่ distinct detector IDs และ average confidence รวม benign evidence; detector เดิมที่ emit ซ้ำจึงทำให้ escalation ถึง threshold ได้. ไม่มี test duplicate detector ID หรือ adversarial mixed-confidence set.

## Test/evidence gaps

- ยังรัน Zig unit/integration tests ไม่ได้ใน sandbox เพราะ `zig` executable ไม่มีอยู่ (`zig: command not found`); จึงไม่มีผล pass/fail runtime ของ source นี้ มีเพียง static code/test review.
- ไม่มี test ที่พิสูจน์ end-to-end ว่า TS `compile/seal` -> serialized artifact -> Zig `verifyPolicyWithStore` ใช้ canonical bytes เดียวกัน; test Python ระบุชัดว่าคนละ stream และเป็น offline auditor เท่านั้น.
- ไม่มี test ที่ policy/PEP unavailable ต้อง reject/quarantine หรือหยุด pipeline; tests ปัจจุบัน assert `.allow/default_allow` และ `.no_op` เมื่อไม่ initialized ซึ่งล็อก fail-open behavior.
- ไม่มี integration test ที่ยืนยัน host-effect receipt จริง, provider identity/filter ownership, cleanup/unblock, restart persistence หรือ privilege ACL; `RustPep` ระบุ host effect unavailable และ map in-memory ไม่ใช่ WFP proof.
- signature tests ขาด suffix/failure-output, >255-byte pattern, >255 outputs ต่อ state, malformed/large input และ bounded memory/latency. fuzz entrypoint เป็น deterministic loop 1,000 inputs ไม่ใช่ fuzz harness และไม่ assert semantic coverage.
- ไม่มี concurrent tests สำหรับ PolicyEngine/dispatcher singletons, ForensicsEngine, XDR harden/fabric และ ThreatTracker map access; มี concurrency tests เฉพาะ `ForensicRing` ที่มี mutex.
- forensics/replay tests ไม่ครอบคลุม `ForensicsEngine.recent()` หลัง wrap, sequence ที่ถูก overwrite, replay unavailable/error distinction, replay จาก canonical event จริง และ tamper/chain persistence across restart.
- `src/tests/policy/action_dispatcher.zig` เป็นเพียง import-cleanly test; หลาย proof/security tests ตรวจ source strings/manifest ไม่ได้ execute cross-process boundaries หรือ validate actual serialized wire/receipt.
- ไม่มี policy/config reload atomicity test ที่สลับ rules ระหว่าง evaluate; ไม่มี signature, expiry, rollback, schema and provenance check ของ `config/Rules.json`/`configs/policies.json` ใน active runtime.
- ไม่มี PII/secret retention test, access-control test, redaction test, full-payload size quota หรือ collision testสำหรับ `capturePayload`; ไม่มี durable external anchor สำหรับ hash chain.

## Recommended actions (priority order)

1. P0: เปลี่ยนทุก unavailable/error path ใน dispatcher ให้เป็น explicit `failed/rejected/deferred` และไม่เรียก action/allow; ห้ามนับ processed หาก policy/PEP/forensics required stage ไม่ครบ. ส่ง error + event_id ไป forensic และสร้าง negative tests policy/PEP down.
2. P0: ทำ signed-policy gate เป็น active path เดียว: load canonical serialized IR, verify Ed25519/trust store/expiry/rollback/schema ก่อน activate, atomically swap immutable policy snapshot; ให้ `PolicyEngine.evaluate` รับ policy version/digest/trust state และ PEP ปฏิเสธทุก privileged request ที่ไม่มี verified metadata.
3. P0: กำหนด canonical wire format เดียวสำหรับ TS/Zig/Python (length-delimited fields, no raw pointers), สร้าง golden vectors และ independent verification; ลบ `signature=hash` และ raw `asBytes(&rule)` จาก authority path, ใช้ Ed25519 เท่านั้น.
4. P0: แก้ Aho–Corasick ให้รายงาน outputs ของ failure ancestors (หรือ output links), เปลี่ยน depth/metadata เป็น u32/usize, ตรวจ overflow/capacity และเพิ่ม tests ครบ suffix/overlap/long pattern/high fan-in.
5. P1: เพิ่ม event identity envelope/hash ให้ evidence, av, alerts, TI, Brain, policy, PEP และ forensic; reject mixed IDs. เพิ่ม immutable generation/version ใน config reload และ lock/atomic snapshot ทุก singleton.
6. P1: ใส่ mutex/ownership model ให้ ThreatTracker map+incident creation (double-check หลัง lock), ForensicsEngine, XDR engines และ counters; คืน copy/snapshot ไม่ใช่ pointer หลัง unlock; เพิ่ม stress tests/TSAN-equivalent race review.
7. P1: แก้ XDR layer/window/score semantics, dedupe trigger, incident TTL และ explicit `dispatch` API ที่รับ/ตรวจ `EnforcementReceipt`; `dispatched_to_pep` ต้อง true ได้เมื่อ receipt validated เท่านั้น. เพิ่ม dropped/overwrite counters.
8. P1: แก้ forensic ring validation/serialization: enforce capacity multiple of record size, monotonic logical indexes, safe wrapped `recent`/read, durable append/checkpoint and external signed anchor; distinguish unavailable from no_diff in replay.
9. P1: ลด PII/payload risk: default hash-only, redact IP/session/user where not required, encrypt/ACL payload artifacts, full 256-bit collision-safe naming, size quotas, retention/deletion audit and verify partial writes/CEF escaping.
10. P1: จัด repository ให้ clean checkout build ได้: track `brain/detection_scan.py` และ `brain/detection_result.py` หรือแก้ imports; compile/test matrix ต้อง build Zig/Rust/Python/Cython paths ไม่พึ่ง untracked working-tree files.
11. P2: รวม `config/Rules.json`, `configs/Rules.json`, `configs/policies.json` เป็น signed versioned source เดียว; validate severity/action enums and schema at load; remove unreachable thresholds and document precedence.
12. P2: ขยาย tests จาก static proof เป็น local integration tests: failure injection, process restart, receipt mismatch, replay/tamper, cross-language golden vectors, concurrent stress, resource cleanup, secret redaction and controlled (non-host-mutating) simulated enforcement.

## Static evidence and notable positive controls

- `detection_engine.zig` จำกัด evidence/detector capacity; detector returns metadata ไม่ใช่ enforcement handle.
- RAG (`src/detection/rag_engine.zig`) ระบุ fail-soft และไม่มี action field; Shadow decision forcibly clears `candidate_enforce` (`src/policy/shadow_decision.zig:93-108`).
- `pep_bindings.zig` ตรวจ unknown response ordinal และคืน escalate เมื่อ DLL unavailable/error (`:98-134`); แนวคิดนี้ควรถูกย้ายมาเป็น active dispatcher contract ไม่ใช่ปล่อยให้ integration facade แปลงเป็น no-op.
- `ForensicRing` มี mutex, snapshot copy, CRC และ per-record SHA-256 (`src/forensic/forensic_pipeline.zig:18-28,260-330`) และมี concurrent append tests; แต่ยังไม่แก้ external anchoring/size validation.
- TS policy source ไม่มี direct child-process/network/firewall import ตาม AST tests แต่เป็นเพียง no-enforcement claim ไม่ใช่ proof ของ signed runtime activation.

## Files reviewed (tracked inventory)

จำนวนไฟล์ตาม `git ls-files`: **304**. รายการเต็ม:

```text
brain/__init__.py
brain/aegis_brain_cython/README.md
brain/aegis_brain_cython/__init__.py
brain/aegis_brain_cython/bridge.py
brain/aegis_brain_cython/fast_scan.pyx
brain/aegis_brain_cython/setup.py
brain/aegis_brain_cython/test_fast_scan.py
brain/cython/__init__.py
brain/cython/_py_fallback.py
brain/cython/aegis_hotspot.pxd
brain/cython/aegis_hotspot.pyx
brain/cython/cython_regex_scan.pyx
brain/cython/setup.py
brain/windows_brain.py
config/Rules.json
config/deployment_profile.example.json
configs/Rules.json
configs/Rules.json.before-reload-test
configs/aegis.conf
configs/canary_tests.json
configs/cluster.example.json
configs/policies.json
configs/runtime.json
configs/schema.json
configs/siem_config.json
configs/test/cluster_config.json
configs/test/etw_realtime_config.json
configs/test/federation_bench_config.json
configs/test/federation_config.json
configs/test/federation_tcp_config.json
configs/test/federation_tls_config.json
configs/test/host_correlator_config.json
configs/test/host_telemetry_config.json
configs/test/host_telemetry_detectors_config.json
configs/test/host_telemetry_mock_config.json
configs/test/host_telemetry_scenarios_config.json
configs/test/injection_detector_config.json
configs/test/integration_test_config.json
configs/test/perf_benchmark_config.json
configs/test/registry_trie_config.json
configs/test/windows_adapters_config.json
mouth/.gitignore
mouth/Cargo.lock
mouth/Cargo.toml
mouth/README_DEPLOY.txt
mouth/build_mouth.bat
mouth/windows_sec_monitor.rs
shared/__init__.py
shared/abi/pep_abi.md
shared/abi/runtime_abi.md
shared/aegis_bridge_ctypes.py
shared/errors/error_codes.md
shared/event/canonical_event.md
shared/policy/policy_ir.md
shared/protocol/control_protocol.md
shared/protocol/protocol.md
shared/protocol/protocol_version.json
shared/protocol/versioning.md
shared/protocol/wire_v1.h
shared/protocol/wire_v1.md
shared/runtime/components.json
shared/schema/canonical_event_v1.h
shared/version/version.md
shared/wire/golden_path_ffi.py
shared/wire/wire_codec.h
shared/wire/wire_codec.py
shield/Cargo.toml
shield/src/lib.rs
shield/src/pep.rs
src/detection/anomaly_detector.zig
src/detection/correlation_engine.zig
src/detection/correlator.zig
src/detection/detection_engine.zig
src/detection/detection_interface.zig
src/detection/injection_detector.zig
src/detection/ml_detector.zig
src/detection/proto_anomaly.zig
src/detection/rag_engine.zig
src/detection/rag_intelligence.zig
src/detection/signature_engine.zig
src/detection/threat_intel.zig
src/detection/threat_tracker.zig
src/detection/verdict_aggregator.zig
src/forensic/abi_contract.zig
src/forensic/decision_trace.zig
src/forensic/evidence_record.zig
src/forensic/forensic_log.zig
src/forensic/forensic_pipeline.zig
src/forensic/forensics_engine.zig
src/forensic/installer.zig
src/forensic/integration_contract.zig
src/forensic/policy_contract.zig
src/forensic/provenance.zig
src/forensic/python_contract.zig
src/forensic/release_gate.zig
src/forensic/release_manifest.zig
src/forensic/replay_engine.zig
src/forensic/replay_integrity.zig
src/forensic/replay_verifier.zig
src/forensic/replayable_security.zig
src/forensic/siem_forwarder.zig
src/policy/action_dispatcher.zig
src/policy/control_ipc.zig
src/policy/dispatcher.zig
src/policy/dispatcher_phase_b.zig
src/policy/pep_bindings.zig
src/policy/policy_contract.zig
src/policy/policy_engine.zig
src/policy/policy_ir.zig
src/policy/policy_plane.zig
src/policy/policy_signing.zig
src/policy/shadow_decision.zig
src/policy/tier3_state.zig
src/policy/trust_store.zig
src/policy/wfp_ioctl.zig
src/policy/wfp_production.zig
src/tests/capture/flow_table.zig
src/tests/capture/npcap_adapter.zig
src/tests/capture/packet_decoder.zig
src/tests/capture/proto/parsers.zig
src/tests/capture/stream_reassembly.zig
src/tests/cli/cluster_cli.zig
src/tests/cli/etw_realtime_cli.zig
src/tests/cli/federation_bench_cli.zig
src/tests/cli/federation_cli.zig
src/tests/cli/federation_tcp_cli.zig
src/tests/cli/federation_tls_cli.zig
src/tests/cli/host_telemetry_cli.zig
src/tests/cli/host_telemetry_detectors_cli.zig
src/tests/cli/host_telemetry_mock_cli.zig
src/tests/cli/host_telemetry_scenarios_cli.zig
src/tests/cli/injection_detector_cli.zig
src/tests/cli/integration_test_cli.zig
src/tests/cli/ml_test_cli.zig
src/tests/cli/nose_pipe_e2e_cli.zig
src/tests/cli/perf_benchmark_cli.zig
src/tests/cli/registry_trie_cli.zig
src/tests/cli/windows_adapters_cli.zig
src/tests/cli_imports.zig
src/tests/contract/event.zig
src/tests/contract/runtime_manifest.zig
src/tests/core/bisect_a.zig
src/tests/core/bisect_b.zig
src/tests/core/core_configs.zig
src/tests/core/core_modules.zig
src/tests/core/diagnostics.zig
src/tests/core/memory_pool.zig
src/tests/detection/anomaly_detector.zig
src/tests/detection/correlator.zig
src/tests/detection/proto_anomaly.zig
src/tests/detection/signature_engine.zig
src/tests/detection/threat_tracker.zig
src/tests/federation/aggregator.zig
src/tests/federation/cluster_coord.zig
src/tests/federation/node_registry.zig
src/tests/forensic/abi_contract.zig
src/tests/forensic/decision_trace.zig
src/tests/forensic/evidence_record.zig
src/tests/forensic/forensic_pipeline.zig
src/tests/forensic/installer.zig
src/tests/forensic/integration_contract.zig
src/tests/forensic/policy_contract.zig
src/tests/forensic/provenance.zig
src/tests/forensic/python_contract.zig
src/tests/forensic/release_gate.zig
src/tests/forensic/release_manifest.zig
src/tests/forensic/replay_engine.zig
src/tests/forensic/replay_integrity.zig
src/tests/forensic/replay_verifier.zig
src/tests/forensic/test_fault.zig
src/tests/forensic/test_integration.zig
src/tests/forensic/test_release.zig
src/tests/forensic/test_unit.zig
src/tests/fuzz_main.zig
src/tests/integration/brain_integration.zig
src/tests/integration/concurrency_harden_integration.zig
src/tests/integration/correlation_integration.zig
src/tests/integration/detection_integration.zig
src/tests/integration/e2e_harness_integration.zig
src/tests/integration/fault_injection_integration.zig
src/tests/integration/flow_integration.zig
src/tests/integration/forensics_integration.zig
src/tests/integration/golden_path_e3.zig
src/tests/integration/golden_path_ffi.zig
src/tests/integration/hids_integration.zig
src/tests/integration/ips_canary_integration.zig
src/tests/integration/ips_simulation_integration.zig
src/tests/integration/nose_integration.zig
src/tests/integration/performance_integration.zig
src/tests/integration/policy_integration.zig
src/tests/integration/policy_plane_integration.zig
src/tests/integration/rag_integration.zig
src/tests/integration/release_engineering_integration.zig
src/tests/integration/replay_integration.zig
src/tests/integration/rust_pep_integration.zig
src/tests/integration/threat_intel_integration.zig
src/tests/integration/xdr_harden_integration.zig
src/tests/policy/action_dispatcher.zig
src/tests/policy/pep_bindings.zig
src/tests/policy/policy_ir.zig
src/tests/policy/trust_store.zig
src/tests/proofs/audit_trail_proof.zig
src/tests/proofs/brain_proof.zig
src/tests/proofs/compliance_proof.zig
src/tests/proofs/config_reload_proof.zig
src/tests/proofs/correlation_proof.zig
src/tests/proofs/detection_fabric_proof.zig
src/tests/proofs/documentation_proof.zig
src/tests/proofs/final_integration_proof.zig
src/tests/proofs/flow_state_proof.zig
src/tests/proofs/forensic_replay_proof.zig
src/tests/proofs/health_monitoring_proof.zig
src/tests/proofs/intelligence_proof.zig
src/tests/proofs/pep_enforcement_proof.zig
src/tests/proofs/performance_tuning_proof.zig
src/tests/proofs/policy_plane_proof.zig
src/tests/proofs/siem_integration_proof.zig
src/tests/proofs/telemetry_export_proof.zig
src/tests/reliability/fault_injection.zig
src/tests/reliability/latency_histogram.zig
src/tests/reliability/security_check.zig
src/tests/reliability/watchdog.zig
src/tests/stubs/etw_helper_stub.c
src/tests/stubs/fim_helper_stub.c
src/tests/windows/etw_realtime.zig
src/tests/windows/fim.zig
src/tests/windows/host_telemetry.zig
src/tests/windows/injection_detector.zig
src/tests/windows/registry_monitor.zig
src/tests/xdr/xdr_engine.zig
src/xdr/xdr_correlator.zig
src/xdr/xdr_engine.zig
src/xdr/xdr_harden.zig
src/xdr/xdr_incident_fabric.zig
src/xdr/xdr_incident_graph.zig
tests/__init__.py
tests/adapters/test_t9_windows_adapters.py
tests/aegis_mouth_test.py
tests/aegis_nose_test.py
tests/contracts/event_vectors/event_vectors/README.md
tests/contracts/event_vectors/event_vectors/event_v1_001.bin
tests/contracts/event_vectors/event_vectors/event_v1_002.bin
tests/contracts/event_vectors/event_vectors/event_v1_003.bin
tests/contracts/event_vectors/event_vectors/event_v1_004.bin
tests/contracts/event_vectors/event_vectors/event_v1_005.bin
tests/contracts/event_vectors/event_vectors/golden_vectors.json
tests/contracts/event_vectors/event_vectors/vectors_metadata.json
tests/contracts/event_vectors/generate_test_vectors.py
tests/cython/PROFILE_REPORT.md
tests/cython/profile_brain_hotspot.py
tests/cython/test_cython_benchmark.py
tests/cython/test_cython_correctness.py
tests/cython/test_cython_no_policy_path.py
tests/cython/test_cython_profile.py
tests/e2e/test_t14_windows_golden_path.py
tests/federation/test_t13_federation_tls.py
tests/forensics/test_t12_forensics_replay.py
tests/host_telemetry/test_t10_single_source.py
tests/ips/test_t18_ips_canary_xdr.py
tests/pep/test_t8_rust_pep.py
tests/policy_signing/test_t7_signed_policy.py
tests/release/test_t17_perf_ci_installer.py
tests/reliability/test_t15_reliability_config.py
tests/runtime/README.md
tests/runtime/__init__.py
tests/runtime/conftest.py
tests/runtime/test_aegisctl.py
tests/runtime/test_component_matrix.py
tests/runtime/test_gate_d.py
tests/runtime/test_gate_e.py
tests/runtime/test_gate_f.py
tests/runtime/test_golden_path.py
tests/runtime/test_harness_integration.py
tests/runtime/test_harness_scaffold.py
tests/runtime/test_health.py
tests/runtime/test_restart.py
tests/runtime/test_states.py
tests/runtime/test_timeouts.py
tests/runtime/test_version.py
tests/runtime/test_wire.py
tests/security/test_t16_security_hardening.py
tests/security/test_t19_decision_trace_shadow_replay_review.py
tests/test_e2e.py
tests/test_golden_path.py
tests/tests/contracts/canonical_event.bin
tests/tests/contracts/test_vectors.json
tests/tests/contracts/wire_event.bin
tests/typescript/test_06_typescript_policy.py
tests/vectors/event_vectors.py
tests/wfp/test_t11_wfp_enforcement.py
tests/wfp/test_t11_windows_host.py
ts_policy/package-lock.json
ts_policy/package.json
ts_policy/src/compiler.ts
ts_policy/src/index.ts
ts_policy/src/seal.ts
ts_policy/src/types.ts
ts_policy/tests/compiler.test.ts
ts_policy/tests/cross_language_contract.test.ts
ts_policy/tests/no_enforcement.test.ts
ts_policy/tests/no_post_seal_mutation.test.ts
ts_policy/tests/seal.test.ts
ts_policy/tests/typed_values.test.ts
ts_policy/tsconfig.json
```

- Missing scope directory: `src/analysis`
- Missing scope directory: `src/forensics`
- Missing scope directory: `src/incident`
- Missing scope directory: `src/telemetry`
- Present alternate directory: `src/forensic` (singular), reviewed above.
