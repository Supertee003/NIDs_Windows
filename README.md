# AEGIS NIDS Windows

> **สถานะสำคัญ:** AEGIS อยู่ในช่วง **architecture convergence และ safety containment** ระบบมี source code ครบหลายส่วน แต่ยังไม่ควรอ้างว่าเป็น production-ready prevention system จนกว่าจะผ่าน runtime, contract, security, Windows-host และ release gates ในเอกสารนี้

AEGIS คือระบบ Windows-native Network Intrusion Detection and Response ที่รวมการรับข้อมูลเครือข่ายและ host telemetry, การตรวจจับ, การประเมิน policy, การบังคับใช้บน Windows, การควบคุมโดย operator และ forensic evidence ไว้ในโครงการเดียว

อย่างไรก็ตาม **code ที่มีอยู่ไม่เท่ากับระบบที่พิสูจน์แล้ว** README นี้จึงแยกคำว่า *มี implementation*, *ถูกเรียกใช้ใน runtime*, *ผ่าน integration* และ *ผ่าน production verification* ออกจากกันอย่างชัดเจน

---

## 1. อ่านเอกสารนี้อย่างไร

เอกสารนี้ใช้คำว่า **Current implementation** สำหรับสิ่งที่พบใน source tree และ call path ที่ตรวจได้ ส่วน **Target architecture** หมายถึงสถาปัตยกรรมที่โครงการต้อง converge ไปให้ถึง ไม่ใช่หลักฐานว่าระบบปัจจุบันทำงานครบแล้ว

เมื่อเอกสารขัดแย้งกับ runtime หรือ source code ให้ใช้ลำดับความน่าเชื่อถือต่อไปนี้:

1. พฤติกรรม runtime ที่สังเกตได้จริง
2. source code ณ current HEAD
3. build configuration และ link graph
4. machine-readable truth artifacts ที่ตรวจว่าไม่ stale แล้ว
5. test และ evidence ที่ผูกกับ current HEAD
6. เอกสาร architecture และรายงานเก่า

ห้ามใช้ README นี้แทนการตรวจสอบ runtime, ABI หรือ security boundary

---

## 2. สถานะปัจจุบันโดยสรุป

### 2.1 สิ่งที่มีอยู่ในโครงการ

โครงการมี implementation หลายกลุ่ม ได้แก่ Zig runtime, Go packet acquisition, C/C++ Windows adapters, Rust policy enforcement components, Python Brain, TypeScript policy authoring, forensic/replay modules, control tooling, installer และ CI/release tooling

โค้ดเหล่านี้มีคุณค่าในฐานะ implementation และ research baseline แต่หลายส่วนยังมี contract, lifecycle, authority และ packaging ที่ไม่รวมเป็นเส้นทาง production เดียวกัน

### 2.2 สิ่งที่ยังไม่พิสูจน์

จากการตรวจ source-level architecture พบว่ายังไม่ควรประกาศสิ่งต่อไปนี้เป็น production fact:

- มี runtime spine เพียงชุดเดียว
- มี canonical event contract เพียงชุดเดียว
- มี Policy IR เพียงชุดเดียว
- Rust PEP เป็น enforcement authority เพียงหนึ่งเดียวในระดับ ABI และ kernel boundary
- start/stop/restart ควบคุม worker จริงและมี postcondition
- health/status สะท้อน dependency และ worker liveness จริง
- Go Nose → detector → policy → PEP → WFP → forensics เป็น golden path ที่ทำงานครบ
- forensic replay ใช้ historical input, policy, context และ binary ที่ตรงกับเหตุการณ์เดิม
- installer, signature, rollback และ clean install ผ่าน release verification

### 2.3 โหมดการใช้งานที่ปลอดภัยในช่วง convergence

จนกว่าจะปิด stop-the-line risks ระบบควรจำกัดเป็น **detection-only หรือ degraded mode** และต้องแสดงสถานะนี้ใน health, CLI, audit และ evidence อย่างชัดเจน

ห้ามตีความ `ALLOW` ว่า enforcement สำเร็จ หาก PEP, WFP adapter, driver หรือ privileged dependency ไม่พร้อม

---

## 3. Architecture ที่ประกาศกับเส้นทางที่ตรวจพบว่ารันจริง

### 3.1 Target architecture

สถาปัตยกรรมเป้าหมายคือระบบที่มี authority เดียวในแต่ละ boundary:

```text
Operator / automation
        |
Authenticated control endpoint
        |
Supervisor and runtime state owner
        |
        +--> One ingress owner
        |      +--> Go Nose
        |      +--> ETW / FIM / Registry
        |      +--> isolated compatibility sources
        |
        +--> Canonical event and evidence transport
        |      +--> unique event identity
        |      +--> bounded payload/reference
        |      +--> backpressure and drop ledger
        |
        +--> Detection and correlation
        |
        +--> One canonical Policy IR
        |      +--> signed policy artifact
        |      +--> schema/version validation
        |
        +--> Authenticated Rust PEP broker
        |      +--> authorization
        |      +--> explicit allow/deny/unavailable/failed
        |      +--> Windows enforcement adapters
        |
        +--> Durable forensic evidence
               +--> decision trace
               +--> audit chain
               +--> observe-only replay
               +--> export/aggregation
```

### 3.2 Runtime path ที่ตรวจพบในปัจจุบัน

เส้นทางที่มีหลักฐานจาก source ว่าเป็น active daemon path มีลักษณะดังนี้:

```text
Windows service entry
  -> src/main.zig
  -> platform/win32_service.mainEntry
  -> daemon.runDaemon
       -> initialize runtime state
       -> start legacy capture path
       -> start pipeline/event_processor
       -> start Go Nose pipe reader
       -> start ETW/FIM/registry worker paths
       -> start control path
       -> append records to in-memory forensic ring
```

ในขณะเดียวกัน โครงการยังมี `reliability/lifecycle.zig`, `src/contract/event_fabric.zig` และ `src/policy/dispatcher.zig` ซึ่งมี lifecycle, ingress และ dispatcher logic อีกชุดหนึ่ง แต่ยังต้องตัดสินใจว่าจะทำให้เป็น runtime authority หรือ retire/isolate อย่างเป็นทางการ

**กฎปัจจุบัน:** ห้ามอ้างว่า Event Fabric หรือ dispatcher เป็น production golden path จนกว่าจะมี call-graph และ end-to-end evidence ยืนยันว่าถูกเรียกจาก production entrypoint

### 3.3 ปัญหาเชิงสถาปัตยกรรมที่ต้องปิดก่อน feature expansion

| Boundary | สถานะที่ต้องถือเป็นจริงในปัจจุบัน |
|---|---|
| Runtime | มี runtime path ซ้อนกัน ต้องเลือก owner เดียว |
| Ingress | มี producer หลายตัวและ queue ต้องพิสูจน์ MPSC/backpressure |
| Event | มีหลาย schema และหลาย size/offset definition |
| Policy | มี Policy IR และ action mapping หลายชุด |
| Enforcement | มี path ที่ bypass Rust PEP |
| Lifecycle | บาง handler เปลี่ยน state โดยไม่ควบคุม worker จริง |
| Health | ยังไม่รวม dependency, worker heartbeat, queue pressure และ enforcement state ครบ |
| Control | มี top-level CLI และ modular command surface ที่ไม่สอดคล้องกัน |
| Evidence | หลาย artifact stale และยังไม่มี E4/E6/E7 ที่ผูกกับ release ปัจจุบัน |
| Release | installer, signing, clean install และ rollback ยังต้องพิสูจน์บน Windows จริง |

---

## 4. Ownership และ security authority

### 4.1 Target ownership

| ส่วน | Owner ที่ต้องการ | สิ่งที่ owner ห้ามทำ |
|---|---|---|
| Runtime spine | Zig | ห้ามเป็น privileged enforcement authority |
| Packet acquisition | Go Nose | ห้ามตัดสิน policy หรือ mutate Windows security state |
| Native host telemetry | C/C++ adapters | ห้ามตัดสิน policyหรือ bypass PEP |
| Intelligence | Python Brain | recommend, explain, enrich ได้ แต่ห้าม authorize/enforce/WFP |
| Policy authoring | TypeScript | สร้างและตรวจ policy ได้ แต่ห้าม enforce |
| Policy authorization | Rust PEP | เป็น authority เดียวสำหรับ privileged action |
| Windows mutation | PEP-backed adapter/driver broker | ห้ามเปิด direct mutation path ให้ bridge หรือ client ทั่วไป |
| Evidence | Runtime/forensic authority | ต้องเก็บ finalized decision ไม่ใช่เพียง intent |

### 4.2 Stop-the-line security gates

ห้ามเปิด prevention หรือ privileged production deployment จนกว่าจะปิดประเด็นต่อไปนี้:

1. Direct `netsh` หรือ direct firewall mutation จาก C++/Python/bridge ต้องถูกลบหรือเปลี่ยนเป็น authenticated request ไปยัง Rust PEP
2. WFP device และ mutating IOCTL ต้องมี restrictive SDDL และตรวจ caller identity ที่ boundary จริง
3. PEP failure, missing DLL, missing driver และ WFP adapter failure ต้องไม่ถูกแปลงเป็น `ALLOW`
4. Caller PID, role และ capability ต้องไม่ถูกเชื่อจากค่าที่ caller ส่งมาเองโดยไม่มี OS identity binding
5. Policy signature ต้องเป็น mandatory Ed25519 verification ไม่ใช่ digest ที่ caller สร้างใหม่ได้
6. DLL/driver loading ต้องใช้ trusted absolute path, signature/hash verification และ ACL-protected installation directory
7. Audit และ rollback ต้องผูกกับ request, authenticated caller, policy digest, PEP result, adapter result และ filter ownership
8. Standard-user และ low-integrity Windows tests ต้องพิสูจน์ว่าไม่สามารถ mutate privileged state ได้

---

## 5. Canonical contracts ที่ต้องมีเพียงชุดเดียว

### 5.1 Canonical event

เป้าหมายคือ fixed wire format ที่มี schema ID, version และขนาดชัดเจน โดยไม่ส่ง natural-aligned in-memory struct ข้ามภาษาโดยตรง

Canonical event ต้องรักษาอย่างน้อย:

- event identity ที่ unique ข้าม source และ restart
- source และ source instance
- wall-clock timestamp
- monotonic timestamp
- protocol and endpoint metadata
- detection and policy fields
- bounded payload หรือ evidence reference
- schema/version information
- reserved/extension rules ที่ decoder ทุกภาษาตีความเหมือนกัน

ทุกภาษาและทุก adapter ต้องใช้ generated offsets และ golden vectors เดียวกัน

### 5.2 Policy IR

ต้องเลือก Policy IR authority เพียงหนึ่งชุด แล้วกำหนด:

- magic และ version เดียว
- action ordinal เดียว
- condition/operator registry เดียว
- canonical byte encoding
- signature envelope
- expiry และ rollback semantics
- schema migration rules
- rejection behavior เมื่อ schema/action ไม่รู้จัก

ห้าม cast enum ระหว่าง module ที่กำหนดค่าไม่เหมือนกัน และห้ามใช้ชื่อเดียวกันกับ struct คนละ ABI โดยไม่มี schema ID

### 5.3 Error และ status

Transport status, authorization status, enforcement result และ policy decision ต้องเป็นคนละ field

อย่างน้อยต้องแยก:

```text
ALLOW
DENY
ENFORCEMENT_UNAVAILABLE
ENFORCEMENT_FAILED
AUTHORIZATION_DENIED
INVALID_REQUEST
POSTCONDITION_FAILED
NOT_IMPLEMENTED
```

ห้าม map error หรือ dependency unavailable เป็น `ALLOW`

### 5.4 ABI ownership

ทุก pointer/buffer ABI ต้องระบุ:

- caller/callee ownership
- alignment
- input/output length
- total capacity หรือ element capacity
- lifetime
- release function
- error representation
- symbol/version handshake

ต้องมี ABI conformance harness ที่รันกับ DLL/CDylib จริง ไม่ใช่เฉพาะ unit test ของแต่ละ module

---

## 6. Control plane และ health contract

### 6.1 Control plane เป้าหมาย

ควรมี CLI/client เพียงหนึ่งชุดที่สื่อสารกับ authenticated control endpoint เดียว:

```text
CLI/client
  -> ACL + authenticated caller identity
  -> versioned envelope
  -> nonce/request ID/deadline
  -> authorization
  -> handler
  -> real state mutation
  -> postcondition verification
  -> durable audit
  -> structured result + exit code
```

คำสั่ง mutation ต้องไม่เขียน local JSON หรือ local cache แล้วรายงานว่าสำเร็จ หาก daemon ไม่ตอบรับและ postcondition ยังไม่ผ่าน

### 6.2 Health source of truth

Health reducer ต้องรวมข้อมูลจริงจาก:

- lifecycle state
- supervisor state
- worker readiness และ heartbeat
- Go Nose connectivity
- ETW/FIM/Registry liveness
- queue depth และ drop ledger
- PEP/WFP availability
- watchdog state
- stale last-event threshold
- audit/evidence persistence

`RUNNING` ใช้ได้เมื่อ dependency ที่จำเป็นพร้อมจริงเท่านั้น

### 6.3 Lifecycle state machine

สถานะที่แนะนำ:

```text
STOPPED
STARTING
READY
RUNNING
DEGRADED
FAILED
RECOVERING
STOPPING
```

แต่ละ transition ต้องมี owner เดียว, deadline, acknowledgement และ evidence ของ postcondition

---

## 7. Evidence, forensics และ replay

Forensic record ที่เสร็จสมบูรณ์ต้องเชื่อมโยงได้ดังนี้:

```text
EVENT_ID
  -> DETECTION_ID
  -> INCIDENT_ID
  -> POLICY_ID / POLICY_DIGEST
  -> PEP_REQUEST_ID
  -> ENFORCEMENT_ID / FILTER_ID
  -> ACTION_RESULT
  -> AUDIT_ID
  -> FORENSIC_SEQUENCE
  -> HASH-CHAIN SEGMENT
  -> REPLAY RESULT
```

Evidence ต้องผูกกับ:

- source commit และ dirty-tree state
- binary/dependency/toolchain digest
- runtime manifest
- ruleset และ policy signature
- host identity และ Windows environment
- raw event หรือ evidence reference
- complete decision result
- adapter and rollback result

Replay ต้องเป็น **observe-only** และต้องโหลด historical event, rules, policy, context และ build identity ที่ตรงกับ evidence เดิม การเปรียบเทียบผลที่ caller ป้อนเองไม่ถือเป็น deterministic replay proof

---

## 8. Roadmap ที่ปรับปรุงแล้ว

### Phase 0 — Safety containment

ปิด direct enforcement bypass, แยก enforcement unavailable ออกจาก allow, จำกัดระบบเป็น detection-only/degraded และสร้าง current-head attestation

**Exit gate:** static authority lint ผ่าน, standard-user/device negative tests ผ่าน และ PEP failure ไม่คืน allow

### Phase 1 — Runtime ownership and ingress correctness

เลือก runtime spine เดียว สร้าง supervisor เดียว แก้ worker ownership, cancellation, join, startup barrier, queue และ event identity

**Exit gate:** start/stop/restart ไม่มี hang, queue saturation reconcile ได้ และ event ID เดียวกันตั้งแต่ source ถึง forensic

### Phase 2 — Contract and policy freeze

รวม event, Policy IR, error codes และ PEP ABI เป็น contract เดียว พร้อม generated bindings, offsets, vectors และ canonical policy bytes

**Exit gate:** Go/Zig/C/C++/Rust/Python/TypeScript ให้ผล byte-level และ semantic-level ตรงกัน

### Phase 3 — Detection and enforcement vertical paths

ทำ Go Nose → detector → forensic detection-only slice ก่อน จากนั้นทำ signed block → PEP → WFP broker slice

**Exit gate:** มี event ID, decision, policy digest, PEP result, adapter result และ forensic record ครบใน Windows test

### Phase 4 — Control, forensics and recovery

รวม CLI/client, authenticated pipe, deadline/replay protection, real postconditions, durable audit, replay และ filter ownership

**Exit gate:** ทุก mutation มี independently verified postcondition และทุก error path มี audit

### Phase 5 — Release assurance

ทำ artifact graph, signing, secure loader, SBOM/provenance, clean-room install, upgrade, rollback, uninstall/reinstall และ independent E7 review

**Exit gate:** evidence current-head ครบ, release package reproducible และ Windows clean-room verification ผ่าน

---

## 9. First three vertical slices

### Slice 1 — Go Nose to detection-only forensics

```text
Go Nose
  -> authenticated pipe
  -> canonical event
  -> bounded ingress
  -> detector
  -> finalized forensic record
```

ต้องรักษา event ID, payload/evidence reference, source metadata และ accepted/dropped ledger ให้ครบ โดยยังไม่เปิด firewall mutation

### Slice 2 — Signed block through Rust PEP

```text
Signed policy fixture
  -> canonical bytes
  -> Ed25519 verification
  -> authenticated PEP request
  -> WFP broker
  -> explicit result
  -> audit/forensic record
```

ต้องพิสูจน์ว่า unsigned, expired, wrong-key, rollback และ adapter unavailable ไม่ถูกแปลงเป็น allow

### Slice 3 — Authenticated lifecycle and truthful health

```text
CLI/client
  -> ACL/SID/token verification
  -> deadline/nonce
  -> supervisor transition
  -> worker acknowledgement
  -> health reducer
  -> audit/postcondition
```

ต้องพิสูจน์ว่า unauthorized client ถูก reject, stuck client ไม่ block ระบบ และ `RUNNING` ไม่เกิดเมื่อ required dependency หายหรือ stalled

---

## 10. Repository map

```text
NIDs_Windows/
├── src/                    # Zig runtime, contracts, pipeline, policy, forensics, reliability
├── rust-src/               # Rust PEP and security boundary
├── nose/                   # Go packet acquisition
├── bridge/                 # C++ bridge and adapter targets
├── src/windows/            # Native Windows adapters
├── drivers/                # Windows kernel driver sources
├── brain/                  # Python intelligence layer
├── ts_policy/              # TypeScript policy authoring/compiler
├── go/aggregator/          # Optional/support aggregation sidecar
├── tools/                  # CLI, truth, evidence, release and installer tooling
├── scripts/                # Operational scripts; not automatically the canonical CLI
├── configs/                # Rules, policies and runtime configuration
├── shared/                 # Shared schemas, ABI documents and wire helpers
├── docs/                   # Architecture decisions, contracts and runbooks
├── AGENTS.md               # Development workflow and stop-the-line rules
├── AI_CONTEXT.md           # Machine-generated context; must be current-head verified
├── SYSTEM_MAP.json         # Component map; must be current-head verified
├── FLOW_MAP.json           # Flow map; must be current-head verified
├── AUTHORITY_MAP.json      # Authority map; must be current-head verified
├── CONTRACT_MAP.json       # Contract registry; must be current-head verified
├── EVIDENCE_INDEX.json     # Evidence registry; must be current-head verified
├── build_truth.json        # Build graph; must be current-head verified
├── runtime_manifest.json   # Runtime manifest; must be current-head verified
└── inventory.json          # File inventory
```

---

## 11. Current-head workflow

ก่อนแก้ source ทุกครั้งให้บันทึก baseline:

```powershell
git rev-parse HEAD
git branch --show-current
git status --short
git log -1 --oneline
git ls-files
```

จากนั้นตรวจ truth artifacts:

```powershell
python tools/truth.py verify
```

หาก artifact ใดมี SHA ไม่ตรงกับ `git rev-parse HEAD` ให้ถือว่า **STALE** และห้ามใช้เป็น current truth จนกว่าจะ regenerate ใหม่

ทุก patch ต้องระบุ:

```text
PATCH-ID
FLOW-ID
TARGET HEAD
TARGET FILES/SYMBOLS
IN-SCOPE / OUT-OF-SCOPE
CONTRACT IMPACT
ABI IMPACT
AUTHORITY IMPACT
STATE IMPACT
TEST IMPACT
EVIDENCE IMPACT
```

ทุก patch ต้องส่งมอบ:

```text
FINAL HEAD
FILES CHANGED
OLD FLOW → NEW FLOW
INVARIANT
BUILD RESULT
TEST RESULT
WINDOWS RESULT
EVIDENCE LEVEL
EVIDENCE ARTIFACTS
ROLLBACK
REMAINING RISK
OPEN BLOCKERS
COMPLETION GATE
```

---

## 12. Build และ test baseline

คำสั่งด้านล่างเป็น baseline ที่ต้องตรวจสอบกับ current build configuration ก่อนใช้เป็น release command:

```powershell
# Zig runtime
zig build
zig build test

# Rust components
cargo test --release
cargo build --release

# C/C++ adapters
cmake -B build -S .
cmake --build build --config Release

# Go acquisition
cd nose
go test ./...
go build -o aegis-nose.exe .
cd ..

# TypeScript policy authoring
cd ts_policy
npm run typecheck
npm run test:all
cd ..

# Python tests
python -m pytest tests/ -v --ignore=tests/test_e2e.py
```

การที่ unit test ผ่านยังไม่หมายถึง system integration หรือ Windows enforcement ผ่าน ต้องใช้ evidence level ที่เหมาะสมกับ claim

---

## 13. Evidence levels

| Level | ความหมาย |
|---|---|
| E0 | Design/source review หรือยังไม่มี execution proof |
| E1 | Static inspection และ contract checks |
| E2 | Unit/module test |
| E3 | Deterministic component integration |
| E4 | Windows component integration |
| E5 | End-to-end system simulation |
| E6 | Clean-room production simulation |
| E7 | Independent release verification |

ห้ามยกระดับ claim จาก E1/E2 ไปเป็น E4/E5/E7 โดยไม่มีหลักฐานระดับนั้นจริง

---

## 14. Definition of production readiness

AEGIS จะถือว่าเหมาะกับ prevention production ได้เมื่อผ่านเงื่อนไขทั้งหมดต่อไปนี้:

- มี runtime owner เพียงหนึ่งเดียว
- มี ingress และ event identity authority เพียงหนึ่งเดียว
- มี event, policy, error และ PEP contracts ที่ generated และตรงกันทุกภาษา
- ไม่มี direct firewall/WFP mutation path นอก authenticated PEP broker
- PEP failure เป็น explicit failure/unavailable และ enforcement mode fail-closed ตาม policy
- lifecycle และ health สะท้อน worker/dependency state จริง
- Go Nose ถึง detector, policy, PEP, WFP และ forensic record ใน Windows E4/E5 test
- forensic evidence ผูกกับ event, decision, policy, PEP, action และ build identity
- replay เป็น observe-only และ reproducible ด้วย historical context
- installer, driver, DLL และ release package มี signature/provenance ที่ตรวจได้
- clean install, upgrade, rollback, uninstall และ recovery ผ่านบน Windows clean-room host
- current-head truth artifacts และ evidence ไม่ stale
- มี E0–E7 evidence matrix ครบตาม release claim

---

## 15. Related documents

- `AGENTS.md` — contribution workflow, source-of-truth hierarchy และ stop-the-line rules
- `AI_CONTEXT.md` — machine-generated context; ต้อง verify current HEAD ก่อนใช้
- `AUTHORITY_MAP.json` — declared ownership และ security authority
- `CONTRACT_MAP.json` — declared cross-language contracts; ต้องตรวจเทียบ source
- `EVIDENCE_INDEX.json` — evidence registry และ verification levels
- `docs/architecture/` — architecture decisions และ contracts
- `tools/truth.py` — truth artifact verification
- `tools/release_engineering.py` — release artifact and manifest tooling
- `tools/installer.py` — installer generation tooling

## References

[1]: AGENTS.md "AEGIS development workflow and stop-the-line rules"
[2]: AI_CONTEXT.md "Machine-generated AEGIS context"
[3]: AUTHORITY_MAP.json "Declared authority boundaries"
[4]: CONTRACT_MAP.json "Declared cross-language contracts"
[5]: EVIDENCE_INDEX.json "Evidence index and verification levels"
[6]: docs/architecture/ "AEGIS architecture and contract documents"
[7]: tools/truth.py "Truth artifact verification tool"
[8]: tools/release_engineering.py "Release engineering and artifact manifest tool"
