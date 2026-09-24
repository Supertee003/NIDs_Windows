# AEGIS Windows-native NIDS/IPS — Brain, Detection, Policy และ Policy-Loading Review

**Review type:** senior production/security review แบบ read-only ต่อ source code และ generated truth

**Repository:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`

**ตรวจ HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`

**ขอบเขต:** `brain/`, `brain/cython/`, `src/detection/`, `src/policy/`, policy-related parts of `src/pipeline/`, `ts_policy/`, `configs/policies.json`, policy fixtures, Python/Cython/TypeScript tests, policy loading/reload code, and references needed to classify active versus support/legacy paths.

**คำตัดสิน:** ยัง **ไม่ production-ready** และไม่ควรเปิด prevention จากเส้นทางนี้จนกว่าจะปิด stop-the-line findings ด้านล่าง ระบบมี safety containment บางส่วนที่ถูกต้อง เช่น Python alert-only adapter และ PEP-unavailable → `ESCALATE`, แต่ active daemon path ยังรับ policy JSON ที่ unsigned ได้โดยตรง, ยอมรับ unknown action เป็น `pass`, ไม่ผูก expiry/TTL/version/digest เข้ากับ runtime decision, และสร้างข้อความที่อ้างว่า WFP enforcement สำเร็จโดยไม่มี receipt หรือ host-effect postcondition.

> หลักการที่ใช้ตลอดรายงานนี้คือ **detection result ไม่ใช่ policy decision, policy decision ไม่ใช่ PEP authorization, PEP response ไม่ใช่ WFP host effect, และมีเพียง validated `EnforcementReceipt` เท่านั้นที่อนุญาตให้ claim ว่า host ถูก block**.

## 1. Scope และวิธีตรวจ

ตรวจ source ณ HEAD ที่ระบุด้วย `git rev-parse HEAD`; อ่าน source, test, fixture, config, runtime/build references และเอกสาร handoff/README เพื่อใช้จัดประเภท path เท่านั้น เมื่อเอกสารขัดกับ source หรือ call graph ให้ source และ runtime wiring มี priority สูงกว่าเอกสาร. ไม่มีการแก้ source หรือ generated truth ใด ๆ; ไฟล์รายงานนี้เป็น artifact ที่ผู้ร้องขอระบุให้เขียน.

การจัดประเภทมีสี่กลุ่ม:

| กลุ่ม | เกณฑ์ที่ใช้ในรายงานนี้ | ตัวอย่าง |
|---|---|---|
| **Active production candidate** | ถูกเรียกจาก daemon entry หรือส่ง object เข้า active pipeline โดยตรวจ call site ได้ | `src/daemon.zig` policy JSON loader, `src/pipeline/event_processor.zig`, `src/policy/policy_ir.zig`, `src/policy/pep_bindings.zig` |
| **Support/optional path** | มี implementation และอาจถูกโหลดเป็น bridge/เครื่องมือ แต่ยังไม่ใช่ authority หลักหรือไม่มี evidence ว่าทำงานบน host ปัจจุบัน | `brain/windows_brain.py`, `brain/cython/`, `ts_policy/`, `src/policy/policy_signing.zig` |
| **Tooling/test path** | compiler, fixture, unit/proof tests หรือ static architecture checks | `ts_policy/src/*`, `ts_policy/tests/*`, `src/tests/policy/*`, `tests/policy_signing/*` |
| **Legacy/parallel path** | source มี logic แต่ active daemon ใช้คนละ path หรือมี comments ระบุว่าไม่ใช่ production authority | `src/core/nids_analyze.zig`, `src/policy/policy_engine.zig`, `src/policy/policy_contract.zig` บางส่วน |

สิ่งที่ต้องรันบน Windows, elevated token, Rust/Zig native linker, หรือ VMware lab ไม่ได้ถือว่าผ่านจากการมีไฟล์หรือ test source. ผลที่ยังไม่ได้รันจะระบุเป็น **UNVERIFIED**.

## 2. Active call graph ที่ตรวจได้จาก source

### 2.1 Detection และ policy path ของ daemon

เส้นทางที่ active จาก source คือ:

```text
src/main.zig / Windows service entry
  -> daemon.runDaemon
       -> initialize Aho-Corasick
       -> load configs/Rules.json
            -> rule_loader.loadRulesInto
                 -> AhoCorasick.addPattern/build
       -> load configs/policies.json
            -> std.json.parseFromSlice
            -> ad-hoc string-to-enum/condition mapping
            -> policy.PolicySet.add
       -> PepEnforcer.init
       -> processor.pipelineLoop
            -> processEvent
                 -> flow lookup
                 -> Aho-Corasick match / upstream rule_id
                 -> anomaly detector
                 -> threat tracker
                 -> policy.PolicySet.evaluate
                 -> PepEnforcer.enforce
                 -> ActionDispatcher.dispatch
                 -> decision trace / audit log
                 -> forensic_ring.append
```

หลักฐานสำคัญคือ daemon โหลด detection rules ที่ `src/daemon.zig:155-177` และโหลด policy set จาก `configs/policies.json` ที่ `src/daemon.zig:179-298` [1]. Worker ส่ง `&ps` เข้า `processor.pipelineLoop` ที่ `src/daemon.zig:383-386` [1]. `processEvent` เรียง detection → policy → PEP → dispatch → forensic ที่ `src/pipeline/event_processor.zig:73-200` [2].

Active `PolicySet` อยู่ใน `src/policy/policy_ir.zig`, ไม่ใช่ TypeScript Policy IR. `PolicySet.evaluate()` คืน **policy แรกที่ match** ที่ `src/policy/policy_ir.zig:78-109`; ไม่มี priority sorting, metadata verification หรือ time check [3].

### 2.2 Detection boundary

`processEvent` ใช้ `g_active_ac` global และ `qe.payload` เพื่อหา signature ที่ `src/pipeline/event_processor.zig:73-104` [2]. Detection result ถูกเก็บเป็น `ev.rule_id` และเปลี่ยน kind เป็น `signature_match`; นี่เป็น detection metadata ไม่ใช่ authorization.

Python brain มี seam ที่ถูกต้องกว่าในเชิง authority: `DetectionResult.from_regex_match()` ทิ้ง action จาก rule และเก็บเฉพาะ rule/severity/reason ที่ `brain/detection_result.py:74-115` [4]. `decide_alert_only()` ยอมให้ผลเป็นเพียง `ALERT` หรือ `ALLOW` และ reject privileged action ที่ `brain/policy_decision.py:20-71` [5]. นี่สอดคล้องกับ invariant ว่า detection แนะนำได้ แต่ไม่ enforce.

อย่างไรก็ตาม `src/policy/policy_engine.zig` เป็น parallel planner ที่นำ `brain.BrainAdvice` ไปเลือก `.block` ที่ `src/policy/policy_engine.zig:126-223` [6]. Source นี้ไม่ใช่ object ที่ `event_processor` ส่งให้ PEP ใน active path ปัจจุบัน ซึ่งใช้ `policy.PolicySet` จาก `policy_ir.zig`. จึงต้องไม่สรุปว่า Python brain เป็นผู้ authorize; แต่ต้องปิด semantic duplication เพื่อไม่ให้ caller อื่นเลือก path ผิด.

### 2.3 PEP และ host-effect boundary

`PepEnforcer.enforce()` ที่ `src/policy/pep_bindings.zig:79-105` ปฏิบัติถูกบางส่วน: ถ้า DLL ไม่มี จะคืน `.escalate` ไม่ใช่ `.allow`; ถ้า FFI return code ไม่ใช่ศูนย์ก็คืน `.escalate` [7]. นี่เป็น fail-closed containment ที่ควรรักษา.

แต่ response ABI มีเพียง `decision`, `reason`, `quota_remaining`, `signed_by` ที่ `src/policy/pep_bindings.zig:46-51`; ไม่มี `filter_id`, provider postcondition, host-effect confirmation, receipt version, trace/audit linkage [7]. หลัง FFI return, code ทำ `@enumFromInt(resp.decision)` ที่บรรทัด 104 โดยไม่ตรวจว่า byte อยู่ใน enum range [7]. ค่าผิดรูปจาก DLL จึงอาจทำให้ runtime trap/ล้มเหลวหรือเกิด ABI semantic corruption แทนที่จะได้ explicit `ENFORCEMENT_FAILED`.

`ActionDispatcher.dispatch()` ไม่ได้ตรวจ receipt. สำหรับ `.block` มันเขียน `PEP validated block; WFP enforcement executed by Rust PEP` ที่ `src/policy/action_dispatcher.zig:63-73` [8]. นี่เป็น **host-block claim ที่เกินหลักฐาน**: `PepDecision.block` แปลเพียงว่า PEP ส่ง decision กลับมา; source path นี้ไม่มี provider response ที่ยืนยัน filter หรือ host postcondition. `src/policy/wfp_production.zig:16-20` ยังคืน `.unavailable` เป็น implementation ที่ fail-closed และเป็นหลักฐานตรงข้ามกับข้อความ “WFP enforcement executed” [9].

## 3. File-level observations

### 3.1 `configs/policies.json` และ active loader

`configs/policies.json` มีเพียง `id`, `name`, `description`, `condition`, `action`, `severity`, `ttl_sec`; ไม่มี magic, schema version, policy revision, digest, key id, Ed25519 signature, signer, issued-at หรือ expiry envelope [10]. Config ปัจจุบันมี action `block`, `alert`, `rate_limit`, `log` และ `ttl_sec` หลายค่า [10].

Loader ใน `src/daemon.zig:196-230` parse JSON แล้ว map action ดังนี้:

```text
block       -> .block
alert       -> .alert
rate_limit  -> .rate_limit
quarantine  -> .quarantine
log         -> .log
escalate    -> .escalate
anything else -> .pass
```

การ map ค่าที่ไม่รู้จักเป็น `.pass` คือ **unknown-action acceptance** และมีผลเชิง fail-open เพราะ `PepEnforcer.mapAction()` map `.pass` เป็น PEP allow ที่ `src/policy/pep_bindings.zig:118-126` [7]. A typo เช่น `"blok"` จึงไม่ถูก reject และอาจลด policy จาก block เป็น allow. นี่เป็น Severity **CRITICAL**.

Loader ยังรับ rule ที่ไม่มีเงื่อนไขเป็นค่า default kind/0, unknown field เป็น `.kind`, unknown operator เป็น `.eq`, และ `gte` ถูกแปลงเป็น `.gt` ที่ `src/daemon.zig:240-264` [1]. ดังนั้น `severity >= 6` ใน config ไม่เท่ากับ `gte` จริงเมื่อ severity เท่ากับ 6. Loader อ่านเพียง clause แรกและ predicate แรก (`src/daemon.zig:245-269`) แม้ schema ใน JSON อนุญาต array; predicates/clauses ที่เหลือถูกละทิ้ง. นี่เป็น semantic drift ระหว่าง authoring truth กับ runtime truth และ Severity **HIGH**.

`ttl_sec` ถูกเก็บลง `Policy.ttl_sec` ที่ `src/daemon.zig:236-238,281-287` แต่ `PolicySet.evaluate()` ที่ `src/policy/policy_ir.zig:104-109` ไม่อ่านเวลาและไม่กรอง expired policy [3]. ค่า TTL ใน config จึงเป็นข้อมูลที่ดูเหมือนมี expiry แต่ไม่มี runtime effect. Severity **HIGH**.

Loader ไม่ตรวจ duplicate policy ID, maximum count, required semantic fields, policy set digest หรือ signature. Missing file/parse error ทำให้ daemon log warning แล้วเดินหน้าด้วย policy set ว่างที่ `src/daemon.zig:184-214`; นั่นคือ detection ยังเดินต่อ แต่ operator ต้องได้รับสถานะ policy-unavailable ที่ชัดเจน ไม่ใช่เพียง counter เป็นศูนย์.

### 3.2 Active `PolicySet` และ action semantics

`src/policy/policy_ir.zig:18-26` กำหนด action ordinal เป็น:

```text
pass=0, log=1, alert=2, rate_limit=3, block=4, quarantine=5, escalate=6
```

`PolicySet.evaluate()` คืน policy แรกที่ match และไม่มี priority/rollback/expiry ที่ `src/policy/policy_ir.zig:78-109` [3]. Empty condition ทำให้ `evalCondition()` คืน true ตาม `src/policy/policy_ir.zig:120-125`; clause ที่ไม่มี predicates เองคืน false ที่บรรทัด 127-132. นโยบายที่ malformed แล้วถูกเติม default predicate จึงมี behavior ที่ไม่ได้มาจาก author intent.

Action vocabulary/ordinal ไม่ได้เป็นชุดเดียวกับทุก module:

| Contract | action set/ordinal ที่ source กำหนด | ผลกระทบ |
|---|---|---|
| Active `policy_ir.Action` | `pass=0, log=1, alert=2, rate_limit=3, block=4, quarantine=5, escalate=6` | ใช้โหลด `policies.json` และส่ง `requested_action` เข้า PEP |
| `policy_contract.PolicyDecision` | `allow=0, alert=1, block=2, rate_limit=3, quarantine=4, log_only=5` | มี mapping อีกชุดใน legacy/support contract |
| `policy_plane.PolicyActionDef` | `allow=0, alert=1, block=2, quarantine=3, rate_limit=4, log_only=5` | TypeScript IR support/tooling contract |
| `pep_bindings.PepDecision` | `allow=0, block=1, rate_limit=2, quarantine=3, escalate=4, drop=5` | PEP response contract |

การใช้ `@intFromEnum(p.action)` ใน `src/policy/pep_bindings.zig:86-96` [7] จึงปลอดภัยได้ก็ต่อเมื่อ Rust ABI ใช้ **active `policy_ir.Action`** จริง. Source ยังไม่มี generated enum/fixture ที่บังคับให้ทั้งสาม policy sets และ PEP ABI ใช้ vocabulary เดียวกัน. การที่ comments เขียนว่า ordinals match ไม่ใช่ proof. Severity **HIGH** จนกว่าจะมี cross-language golden vector และ Rust-side ABI test.

### 3.3 Policy signing, version และ schema

มี implementation Ed25519 ที่ดีในเชิง unit-level อยู่ใน `src/policy/policy_signing.zig`. `SignedPolicy` มี `key_id`, `policy_version`, `expiry_ms`, signer และ 64-byte signature ที่ `src/policy/policy_signing.zig:46-60`; `verifyPolicy()` ตรวจ trusted key, expiry, rollback, IR validity และ Ed25519 ที่ `src/policy/policy_signing.zig:125-167` [11]. `verifyPolicyWithStore()` เพิ่ม trust-store/revocation/rollback-floor semantics.

แต่ไฟล์เดียวกันระบุชัดว่าเป็น additive module ที่ caller “opt in” (`src/policy/policy_signing.zig:1-5`). Active `src/daemon.zig` loader ของ `configs/policies.json` ไม่สร้าง `SignedPolicy`, ไม่เรียก `verifyPolicy()` หรือ `verifyPolicyWithStore()`, และไม่ใช้ trust store ก่อน `ps.add()` [1][11]. ดังนั้น **มี verifier ไม่เท่ากับ active runtime บังคับ signature**.

TypeScript policy plane ยังไม่ใช่ signature authority:

* `ts_policy/src/compiler.ts` ตั้ง `signature: 0` จนกว่าจะ sign ใน tier ถัดไป; tests ยืนยันว่า IR compile result เป็น unsigned ที่ `ts_policy/tests/compiler.test.ts:120-127` [12].
* `ts_policy/src/seal.ts:74-79` ระบุเองว่า seal เป็น SHA-256 HMAC ที่ใช้ padded signer string และ “NOT a replacement for Ed25519”; implementation ใช้ `createHmac("sha256", signer)` ที่ `ts_policy/src/seal.ts:101-106` [13]. `signer` เป็น identifier ที่ถูกส่งเข้า function ไม่ใช่ trust-store key และ `verifySeal()` ตรวจเพียง padded signer, expiry, version และ HMAC ที่ `ts_policy/src/seal.ts:147-172` [13]. นี่ไม่ใช่ mandatory public-key authenticity ของ production policy.


`signer` เป็น identifier ที่ถูกส่งเข้า function ไม่ใช่ trust-store key และ `verifySeal()` ตรวจเพียง padded signer, expiry, version และ HMAC ที่ `ts_policy/src/seal.ts:147-172` [13]. นี่ไม่ใช่ mandatory public-key authenticity ของ production policy.

จึงพบ **unsigned/weakly-authenticated acceptance** สองชั้น: TypeScript compiler ผลิต `signature=0`; active Zig JSON loader ไม่ตรวจ envelope ใด ๆ; และ TypeScript HMAC seal ไม่ได้ถูกส่งเข้า active daemon. แม้ Ed25519 verifier จะผ่าน unit-level tests แต่ policy ที่ active อยู่ยังไม่ผ่าน verifier. Severity **CRITICAL**.

### 3.4 Runtime digest, version, expiry และ rollback propagation

`PolicyMetadata` ใน `src/policy/policy_contract.zig:20-41` มี `revision`, `digest`, signer และ lifetime แต่ active `policy_ir.Policy` มีเพียง id/name/condition/action/severity/ttl ที่ `src/policy/policy_ir.zig:69-76` [3]. ไม่มี conversion ที่สร้าง `PolicyMetadata` จาก `configs/policies.json`.

ใน active event path มีหลักฐานของการสูญเสีย identity โดยตรง:

* `event_processor` บันทึก `decision_trace.setPolicy(pol.id, 1)` ที่ `src/pipeline/event_processor.zig:144-150`; policy version ถูก hard-code เป็น `1` และไม่มี digest [2].
* `PepContext` มี `policy_version` ที่ `src/policy/pep_bindings.zig:26-31` แต่ initializer ที่บรรทัด 96 ไม่กำหนดค่า จึงใช้ default `0` [7].
* forensic append ที่ `src/pipeline/event_processor.zig:198-200` ส่ง policy ID และ PEP decision แต่ไม่ส่ง policy digest, revision, signer, expiry หรือ schema version [2].

จึงไม่สามารถพิสูจน์ย้อนหลังได้ว่า decision และ PEP request ใช้ policy bytes ชุดใด. Rollback floor ของ `policy_signing.zig` ไม่ได้รับ input จาก active loader. Severity **HIGH** และเป็น forensic/replay contract defect.

### 3.5 Reload behavior และ atomicity

`src/pipeline/rule_loader.zig:22-129` reload ได้เฉพาะ `configs/Rules.json`; มันสร้าง Aho-Corasick ชุดใหม่และ swap `state.g_active_ac` แต่ไม่โหลด `configs/policies.json`, ไม่ verify policy metadata และไม่ update policy digest/version [14]. `src/daemon.zig` โหลด `policies.json` เพียงครั้งเดียวตอน startup ที่บรรทัด 179-298 [1]. ดังนั้น rules reload ไม่ได้ reload policy plane.

Python Brain ก็ watch `Rules.json` mtime ใน `brain/windows_brain.py:452-467` แต่ recompile เฉพาะ Tier-2 regex engine; ไม่มี policy envelope verification หรือ policy digest publication [15]. การ reload detector อาจทำให้ detector truth เปลี่ยนโดยไม่มี policy-set revision ที่ผูกกัน. Active policy reload แบบ atomic, generation-bound และ rollback-aware ยังไม่มี. Severity **HIGH**.

การเก็บ old automata ไม่ทำลายทันทีที่ `rule_loader.zig:115-126` ช่วยหลีกเลี่ยง use-after-free แต่ source ระบุว่าจะ retain จน daemon lifetime; ยังไม่มี bounded retired-generation policy หรือ metric. นี่เป็น resource/lifecycle concern ระดับ **MEDIUM**, ไม่ใช่หลักฐานว่า reload policy ปลอดภัย.

### 3.6 Python/Cython fallback, binary safety และ timeout

`brain/cython/__init__.py:20-34` พยายาม import `cython_regex_scan`; ถ้าล้มเหลวจะ broad-catch แล้วเลือก `_py_fallback` [16]. นี่ทำให้ Brain ยังทำงานได้เมื่อ extension ไม่มี แต่ก็ทำให้ incompatible/stale `.pyd` ถูกลดระดับเป็น fallback โดยไม่มี startup gate ที่บังคับ parity evidence.

`brain/cython/_py_fallback.py:25-94` และ `brain/cython/cython_regex_scan.pyx:43-136` มีโครงสร้าง parallel-array, regex compile, severity default และ first-match loop ใกล้เคียงกัน [17][18]. ทั้งสองรับ `str` ไม่ใช่ raw bytes. ก่อนเรียก Cython หรือ fallback, `windows_brain.run_regex_scan()` ทำ `safe_payload = str(payload)[:MAX_PAYLOAD_SIZE]` ที่ `brain/windows_brain.py:261-290` [15]. ถ้า caller ส่ง `bytes`, Python จะกลายเป็นข้อความ representation เช่น `"b'...\\x00...'"`; regex จะ match representation ไม่ใช่ byte stream จริง. Embedded NUL และ non-UTF-8 payload จึงมี semantic drift จาก packet bytes. Severity **HIGH** สำหรับ NIDS binary safety.

มี `brain/aegis_brain_cython/fast_scan.pyx` และ test ที่ครอบคลุม bytes/embedded NUL ใน support path แต่ `windows_brain.py` ไม่ได้ import module นี้. การมี `.pyd` หรือ generated `.c` ไม่ได้พิสูจน์ว่า module ถูก build ถูก Python ABI หรือถูกเลือกใน production. Windows build/loader verification ยัง **UNVERIFIED**.

Python enforcement wrapper ตั้ง `subprocess.run(..., timeout=10)` ที่ `brain/windows_brain.py:187-205` และ timeout จะคืน `DEFERRED` [15]. `apply_firewall_block()` แสดงข้อความ `ACCEPTED by Rust PEP` เมื่อ process exit code เป็นศูนย์ที่ `brain/windows_brain.py:208-230`, แต่ไม่ได้ parse/validate `EnforcementReceipt`, filter identity หรือ host postcondition. จึงห้ามใช้ boolean return เป็น host-block truth.

Active Zig-to-PEP FFI ไม่มี timeout หรือ cancellation/deadline รอบ `aegis_pep_enforce()` ที่ `src/policy/pep_bindings.zig:54,79-105` [7]. การตอบสนองค้างของ DLL ไม่ถูกแปลงเป็น bounded `UNAVAILABLE`/`FAILED`. Exact Windows timing behavior ยัง **UNVERIFIED**.

## 4. Contract และ authority impact

### 4.1 สิ่งที่ถูกต้องและควรรักษา

Python `DetectionResult` ไม่ copy action ไปเป็น privileged decision; `decide_alert_only()` จำกัด output เป็น `ALLOW`/`ALERT`; Cython source ไม่มี WFP/PEP/subprocess path ใน regex module; และ PEP unavailable/error ถูกแปลงเป็น `.escalate` ไม่ใช่ `.allow`. สิ่งเหล่านี้เคารพ invariant ว่า detection/policy/UI ห้าม claim host block และ Rust PEP เป็น enforcement authority เดียว.

### 4.2 สิ่งที่ยังทำลาย authority contract

Active policy parser ทำหน้าที่ compile และตีความ authorization เองโดยไม่มี signed Policy IR boundary. Unknown action ถูกเปลี่ยนเป็น `pass`; unknown operator/field ถูกเปลี่ยนเป็นค่า default; TTL ถูกเก็บแต่ไม่บังคับ; PEP request ส่ง ordinal/action แต่ไม่ส่ง verified policy identity; dispatcher logs a block claim จาก PEP decision โดยไม่ต้องมี receipt. ผลรวมคือ detection, policy, PEP และ WFP states ถูกยุบเข้าด้วยกันใน log และอาจทำให้ UI/operator เข้าใจว่า block เกิดขึ้นแล้วทั้งที่ host effect ยังไม่พิสูจน์.

### 4.3 Semantic drift ที่ต้องถือเป็น contract break

มีอย่างน้อยสาม policy representations ที่ไม่ใช่ ABI เดียวกัน: runtime JSON `Policy`, Zig `PolicyIR/PolicyActionDef`, และ TypeScript `PolicyIR`. Runtime JSON ใช้ string action และ clause/predicate object; TS ใช้ numeric enums, typed values และ sorted rules; active Zig loader อ่านเฉพาะ first clause/first predicate และไม่ใช้ TS compiled IR. Signature fields ก็ไม่สอดคล้องกัน: TS compile ใส่ zero, TS seal ใช้ HMAC, Zig signing ใช้ Ed25519, active loader ใช้ไม่มีทั้งสอง. จึงไม่ควรเรียก `ts_policy` output ว่า active production policy artifact จนกว่าจะมี canonical wire envelope และ loader เดียว.

## 5. Concrete defects และ severity

| ID | Severity | Defect และหลักฐาน | ผลกระทบ |
|---|---|---|---|
| BP-01 | **CRITICAL / stop-the-line** | Active `daemon.zig` อ่าน `configs/policies.json` แล้ว `ps.add()` โดยไม่สร้างหรือ verify `SignedPolicy`; `policy_signing.zig` เป็น opt-in additive module | unsigned, expired, unknown-key และ rollback policy สามารถเข้าสู่ active `PolicySet` ได้ |
| BP-02 | **CRITICAL / stop-the-line** | Unknown action ที่ `daemon.zig:228-230` map เป็น `.pass`; PEP map `.pass -> allow` | typo/malformed action เปลี่ยน intended block เป็น allow |
| BP-03 | **HIGH** | `ttl_sec` ถูกเก็บแต่ `PolicySet.evaluate()` ไม่ตรวจเวลา | expired policy ยังคง match ต่อไป |
| BP-04 | **HIGH** | `gte -> gt`, unknown operator -> `eq`, unknown field -> `kind`, first clause/predicate เท่านั้น | runtime behavior ไม่เท่ากับ authored/configured semantics |
| BP-05 | **HIGH / stop-the-line for host claim** | dispatcher logs “WFP enforcement executed” จาก PEP decision; ไม่มี receipt/filter/postcondition | host block อาจถูกอ้างโดยไม่มี proof |
| BP-06 | **HIGH** | `setPolicy(pol.id, 1)` hard-code version; PEP `policy_version` default 0; forensic append lacks digest/version/signer | runtime digest propagation, replay และ rollback audit ใช้ไม่ได้ |
| BP-07 | **HIGH** | `str(payload)` ก่อน scanning; Cython/fallback รับ text ขณะที่ network payload เป็น bytes | embedded NUL/non-UTF8 scan ไม่เท่ากับ intended bytes |
| BP-08 | **HIGH** | Policy reload ไม่มี; only `Rules.json` detector reloads | detector/policy generations อาจ diverge |
| BP-09 | **HIGH** | `@enumFromInt(resp.decision)` without range validation | malformed DLL response อาจ trap หรือ corrupt semantic status |
| BP-10 | **MEDIUM** | Optional Cython import broad-catches any error; generated `.pyd`/`.c` not proof of active compatible module | stale/incompatible binary silently changes implementation |
| BP-11 | **MEDIUM** | Python `ACCEPTED`/`DEFERRED` wrapper returns process-level status without receipt; active PEP call has no deadline | timeout/ambiguous provider state can be reported incorrectly or hang |

## 6. Tests and proofs: present versus missing

Python tests cover detection result validation, alert-only policy behavior, PEP request shape, receipt validation, and forensic identity. Cython tests cover correctness and a separate bytes-oriented support path. Zig tests cover Ed25519 signing, tamper, unknown key, expiry and rollback. TypeScript tests cover enum values, deterministic compiler output, `signature=0` for compiled IR, HMAC seal, expiry/rollback return values, and no-enforcement source scanning.

These tests establish component properties, but do **not** prove that the active daemon loader invokes them. The missing link is `daemon -> signed envelope verification -> active PolicySet -> PEP request -> receipt`.

### 6.1 Observed execution status

* `python3 -m pytest -q brain tests/cython tests/policy_signing` was **UNVERIFIED/blocked** because this sandbox has no `pytest` module (`No module named pytest`).
* `cd ts_policy && npm test` was attempted but all six suites failed before test execution because installed `node_modules` contains the Windows `@esbuild/win32-x64` binary while the sandbox is Linux. This is an environment/package-reproducibility failure, not a semantic pass/fail result.
* Zig/Rust/Cython native build and Windows host tests were not run in this Linux sandbox. They remain **UNVERIFIED**.
* No elevated Windows WFP proof, VMware isolation proof, provider filter identity, cleanup proof, or lifecycle recovery after host effect was available. These remain **UNVERIFIED** and closed.

### 6.2 Missing negative and integration proofs

Required tests not proven on the active path are: active rejection of unsigned, unknown-key, revoked-key, bad-signature, bad-magic/version, expired, not-yet-valid and rollback artifacts; rejection rather than normalization of unknown action/field/operator; duplicate-ID and multi-clause preservation; TypeScript/Zig/Rust canonical digest and ordinal golden vectors; exact expiry-boundary behavior; verified policy reload with last-known-good retention and digest propagation; arbitrary bytes/embedded NUL/non-UTF8 parity against the exact selected Cython module; out-of-range PEP response rejection; receipt validation; and bounded timeout behavior when PEP/provider hangs.

The project also lacks a proof that only a receipt with `status=ENFORCED`, `host_effect_confirmed=true`, nonzero `filter_id`, request/event/trace/audit IDs and supported receipt version can reach `BLOCKED_CONFIRMED` or any UI claim.

## 7. Prioritized fixes

### P0 — keep prevention closed

1. Replace direct JSON loading with one canonical signed policy envelope. At the daemon boundary verify magic/schema/version, canonical bytes, Ed25519 signature against a trust store, key status, issued-at, expiry and persistent rollback floor. Reject every failure; never substitute empty policy or `.pass` for malformed input.
2. Remove unknown-action/field/operator fallback. Use explicit parse errors and fail closed. Define one generated action/condition registry used by TypeScript, Zig, Rust and fixtures.
3. Replace the PEP response/dispatcher log path with a structured validated `EnforcementReceipt`. Validate response range, request ID, policy digest/version, provider identity, filter ID, host-effect confirmation and receipt version before any enforcement claim.

### P1 — converge semantics and evidence

4. Choose one Policy IR and canonical serialization. Make `ts_policy` compile to that envelope, make Zig decode/verify it, and make Rust PEP consume the same digest/version. Isolate parallel policy engines until ownership is explicit.
5. Add policy ID, revision, digest, signer/key ID, schema version and expiry to active Policy, PepRequest, decision trace, forensic record and receipt. Eliminate hard-coded version `1` and default PEP version `0`.
6. Implement atomic verified policy reload, separate from detection-rule reload. On failed reload retain the last verified generation and expose failure plus active digest. Persist rollback floor.
7. Preserve bytes at detection boundary. Use length-delimited bytes API or one explicit documented decoding step before both paths. Do not use `str(bytes)` for packet inspection.

### P2 — operational hardening

8. Add bounded deadlines/cancellation around PEP/provider calls. Timeout and ambiguous response must become non-enforcing failure.
9. Add Windows ABI/build verification for Python version, architecture, `.pyd` signature/hash and import path. Health must expose selected implementation and active policy generation.
10. Retire or label `policy_engine.zig`, `policy_contract.zig`, legacy `nids_analyze.zig`, and unconnected TypeScript/HMAC paths. Add a build-graph check that fails when a second policy authority is linked into production target.

## 8. Exact Windows-only verification commands

The following commands must run on Windows; results are **UNVERIFIED** until executed and archived against this HEAD. Host-effect commands require an isolated VMware VMnet and elevated PowerShell.

### 8.1 Build and language tests

```powershell
Set-Location -Path 'D:\NIDs_Windows'
git rev-parse HEAD
git status --short
zig build
zig build test
python -m pytest -q brain tests\cython tests\policy_signing tests\typescript
Set-Location -Path 'D:\NIDs_Windows\ts_policy'
Remove-Item -Recurse -Force .\node_modules -ErrorAction SilentlyContinue
npm ci
npm test
```

### 8.2 Active-path and binary checks

```powershell
Set-Location -Path 'D:\NIDs_Windows'
git grep -n -E 'policies\.json|verifyPolicy|verifyPolicyWithStore|PolicySet\.evaluate|setPolicy|policy_version|policy_digest|host_effect_confirmed|EnforcementReceipt'
Get-FileHash .\configs\policies.json -Algorithm SHA256
Get-FileHash .\configs\Rules.json -Algorithm SHA256
Get-ChildItem .\brain -Recurse -Include *.pyd,*.dll | Get-FileHash -Algorithm SHA256
python -c "import brain.windows_brain as b; print('cython=', b.CYTHON_REGEX_AVAILABLE, 'module=', b._cython_scan.__module__ if b.CYTHON_REGEX_AVAILABLE else 'fallback')"
```

Record commit, OS build, Python version, architecture, selected module path and package hashes. A `.pyd` existing on disk is not readiness evidence.

### 8.3 Read-only host preflight

In one elevated window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig build run
```

In a second elevated window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_host_production_preflight.ps1' `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

Expected safe state before proven host effect is `runtime_state=RUNNING`, `pep_ready=true`, `tier3_ready=true`, `workers_ready=true`, `forensic_verified=true`, `host_effect_capable=false`, `overall_gate=false`, `production_attested=false`, `attack_attempted=false`, and `enforcement_attempted=false`. A timeout is failed preflight, not readiness evidence.

### 8.4 Isolated VMware WFP proof

Confirm the guest addresses rather than assuming them. The handoff example is host `192.168.126.1`, Kali `192.168.126.10`, disposable Windows target `192.168.126.20`, host-only VMnet1.

```powershell
Set-Location -Path 'D:\NIDs_Windows'
Get-NetIPConfiguration
Get-NetAdapter
Test-NetConnection 192.168.126.20 -Port 8080
python .\tools\aegisctl.py health
python .\tools\aegisctl.py block 192.168.126.20 --rule-id 3 --reason 'isolated WFP proof'
python .\tools\aegisctl.py health
Get-NetFirewallRule -DisplayName 'AEGIS*' | Format-List *
python .\tools\aegisctl.py unblock 192.168.126.20
Test-NetConnection 192.168.126.20 -Port 8080
Get-NetFirewallRule -DisplayName 'AEGIS*' | Format-List *
```

This is a pass only when receipt status is `ENFORCED`, `host_effect_confirmed=true`, filter ID and all request/event/trace/audit IDs are linked, Kali observes the block, cleanup removes the owned filter, reachability returns, and a new runtime generation has no stale filter. Until this executes, host effect is **UNVERIFIED** and prevention remains closed.

## 9. Conclusion

The project has a credible separation-of-concerns direction, but the active policy path has not converged with its signing, schema and evidence contracts. The strongest immediate risk is not that Python directly calls WFP; the Python seam is mostly advisory. The stronger risk is that the active Zig daemon independently interprets unsigned JSON, silently normalizes unknown values, ignores expiry, hard-codes policy version, and allows a dispatcher log to stand in for an enforcement receipt.

The safe product state at this HEAD is **detection/alert-only or explicitly degraded**, with Rust PEP and WFP host-effect gates closed. Do not announce production readiness from unit tests, source presence, generated `.pyd`/DLL files, a successful JSON parse, a PEP decision, or a UI/log message.

## References

[1]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/daemon.zig "AEGIS daemon initialization and active policy loading"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/event_processor.zig "AEGIS active detection-to-policy-to-PEP pipeline"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/policy_ir.zig "AEGIS active PolicySet, action enum, and evaluator"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/detection_result.py "Python canonical detection result boundary"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/policy_decision.py "Python alert-only policy adapter"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/policy_engine.zig "Parallel Zig policy planner using BrainAdvice"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/pep_bindings.zig "Zig Rust PEP FFI bindings and request/response ABI"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/action_dispatcher.zig "Action dispatcher and enforcement log claims"
[9]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/wfp_production.zig "Fail-closed WFP production boundary"
[10]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/configs/policies.json "Active unsigned JSON policy configuration"
[11]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/policy_signing.zig "Additive Ed25519 policy signing and trust-store verifier"
[12]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/ts_policy/src/compiler.ts "TypeScript policy compiler and unsigned IR output"
[13]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/ts_policy/src/seal.ts "TypeScript HMAC seal and local verification"
[14]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/rule_loader.zig "Detection rule reload implementation"
[15]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/windows_brain.py "Python Brain scan, optional Cython path, hot reload, and PEP request wrapper"
[16]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/cython/__init__.py "Cython optional import and fallback selection"
[17]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/cython/_py_fallback.py "Pure Python regex fallback"
[18]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/brain/cython/cython_regex_scan.pyx "Cython regex scan implementation"
[19]: file:///home/ubuntu/upload/AEGISComprehensiveDevelopmentAnalysisandProductionHandoff.md "AEGIS comprehensive development and production handoff"
[20]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/README.md "AEGIS repository status and authority invariants"
