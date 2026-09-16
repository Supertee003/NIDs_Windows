# AEGIS NIDS Windows — Roadmap จากสถานะปัจจุบันสู่ระบบสมบูรณ์

**ฉบับ:** 1.0  
**วันที่วิเคราะห์:** 16 กันยายน 2026  
**ขอบเขต:** Architecture convergence, Windows runtime, policy/enforcement, portability, WSL2 attack lab และ production release

## บทสรุปผู้บริหาร

AEGIS อยู่ในช่วงท้ายของ **Phase 1: Runtime Authority** และมีความคืบหน้าใกล้เส้นชัยของ source-level convergence แล้ว ผลทดสอบล่าสุดยืนยันว่า Gate D, Gate E, Gate F, T16 security hardening และ release artifact verification ผ่านทั้งหมด โดยมี `90 passed` ใน targeted regression suite และ `339/339` artifacts มี digest ตรงกับ manifest

สิ่งที่ยังทำให้ระบบไม่ควรประกาศว่า production-complete คือ **core live lifecycle บน Windows ยังไม่ผ่านหนึ่งรายการ** ระบบ binary ถูกสร้างได้ แต่ test ไม่สามารถเปิด health pipe ของ core และรอ state `RUNNING` ภายใน 5 วินาทีได้ ผลล่าสุดคือ `1 failed, 3 passed` ใน `test_harness_integration.py` นอกจากนี้ WFP host enforcement ต้องทดสอบบนเครื่อง Windows ที่มี PEP DLL และ WFP driver ติดตั้งจริง การที่ test นี้ skip เมื่อไม่ได้เปิด `AEGIS_RUN_WFP_HOST_TESTS=1` เป็นพฤติกรรมที่ถูกต้อง ไม่ควรแก้ด้วยการบังคับให้ PEP คืน `BLOCK` เมื่อ driver ไม่พร้อม

เป้าหมายสุดท้ายจึงไม่ใช่เพียงทำให้ pytest เป็นสีเขียว แต่ต้องพิสูจน์เส้นทางใช้งานจริงดังนี้:

```text
ติดตั้ง
  -> เลือก host profile และ adapter
  -> start bridge
  -> start core/supervisor
  -> acquire Wi-Fi/LAN/ETW/FIM/Registry
  -> canonical event
  -> detection and correlation
  -> policy decision
  -> Rust PEP authorization
  -> WFP enforcement หรือ fail-closed unavailable
  -> forensic trace
  -> operator observe/export
  -> safe stop/update/rollback
```

## สถานะที่ยืนยันแล้ว

| พื้นที่ | สถานะ | หลักฐานล่าสุด |
|---|---|---|
| Rules command center | ผ่าน | Rules CRUD และ Gate D ผ่าน |
| Ruleset | ผ่าน | 22 rules, `VALID: 22 rules checked` |
| Policy lifecycle | ผ่าน | Gate E ผ่าน |
| Block/enforce/quarantine command contract | ผ่าน | Gate F ผ่าน |
| Security hardening T16 | ผ่าน | `8 passed` |
| Release artifact provenance | ผ่าน | `339 artifacts`, digest verification ผ่าน |
| Shield Rust path | ผ่านระดับ source contract | มี crate, Cargo.lock, checked `CStr`, advisory-only boundary |
| Rust PEP authority | ผ่านระดับ static/invariant tests | T8/T11 structural tests ผ่าน |
| Golden path identifier integrity | ผ่านระดับ contract | T14 ผ่าน |
| Forensics and replay contract | ผ่านระดับ contract | T12 ผ่าน |
| Federation/TLS contract | ผ่านระดับ contract | T13 ผ่าน |
| Reliability/config contract | ผ่านระดับ contract | T15 ผ่าน |
| Core live lifecycle | **ยังไม่ผ่าน** | core health pipe ไม่ตอบใน 5 วินาที |
| WFP host enforcement | ต้องยืนยันบน host ที่มี driver | ไม่ใช่ sandbox/source-only gate |

## ความหมายของคำว่า “ระบบเสร็จสมบูรณ์”

AEGIS จะประกาศ production-complete ได้เมื่อเงื่อนไขต่อไปนี้ผ่านพร้อมกัน:

1. **Runtime authority เดียว:** Windows service/console entrypoint เดียวเรียก `daemon.runDaemon()` และ `RuntimeSupervisor` เป็นเจ้าของ worker, stop signal, join และ lifecycle postcondition
2. **Enforcement authority เดียว:** ทุก privileged decision ไปผ่าน Rust PEP และ WFP adapter ที่ Rust PEP เรียก ไม่มี C++, Python, TypeScript, CLI หรือ Shield path ใด mutate firewall โดยตรง
3. **Canonical contracts เดียว:** event, policy IR, PEP ABI, health, control IPC และ forensic trace มี schema/version เดียว และทุกภาษาใช้ contract เดียวกัน
4. **Portable deployment:** เครื่องใหม่เลือก Wi-Fi, LAN, VPN, virtual adapter, Npcap, WFP, ETW หรือ replay ผ่าน deployment profile โดยไม่แก้ source code
5. **Operator workflow ครบ:** ติดตั้ง, preflight, build, start, health, rules CRUD, observe, investigate, canary, stop, update และ rollback ทำได้จากเอกสารและ command center ที่เป็นทางการ
6. **Evidence ครบ:** ทุก test มี test id, commit, artifact digest, environment, command, output, decision trace และผล pass/fail ที่ตรวจซ้ำได้
7. **Windows host proof:** core lifecycle ผ่าน, PEP/WFP block/unblock ผ่านบน test-signed host, adapter selection ผ่านทั้ง Wi-Fi และ LAN และ WSL2 lab golden path ผ่าน

## Phase 1 — ปิด core live lifecycle

### ปัญหาปัจจุบัน

ผลล่าสุด:

```text
Bridge lifecycle: PASS
Brain lifecycle: PASS
Core lifecycle: FAIL
```

Core binary มีอยู่จริง แต่ health probe ที่ `\\.\pipe\aegis_control` ไม่ตอบกลับ ภายใน test output ไม่มี stdout ที่ช่วยวินิจฉัย ดังนั้นต้องแยกสาเหตุเป็นลำดับ:

1. process exit ก่อนสร้าง pipe
2. missing DLL หรือ import library ทำให้ process ไม่เริ่ม
3. security self-check คืน failure
4. `aegis_pep.dll` หรือ bridge dependency ไม่พร้อม
5. core อยู่ใน `DEGRADED` แต่ control pipe ไม่เปิด
6. pipe ACL หรือ endpoint ชื่อไม่ตรง
7. working directory ทำให้หา `configs/Rules.json`, `config/deployment_profile.json` หรือ DLL ไม่พบ

### งานที่ต้องทำ

เพิ่ม startup diagnostics ที่ไม่เปิดเผย secret:

- exit code และ process lifetime ใน harness output
- `GetLastError` จาก pipe creation
- resolved executable directory
- resolved config directory
- PEP load state
- bridge load state
- security self-check category ที่ fail
- control pipe creation state

แก้แล้วใน source ระดับหนึ่ง: `win32_service.mainEntry()` จะ fallback ไป console daemon เมื่อ service dispatcher probe ไม่สำเร็จ แทนการ exit เงียบ แต่ต้อง rebuild binary แล้วทดสอบบน Windows อีกครั้ง

### Exit criteria

```text
python -m pytest tests/runtime/test_harness_integration.py -v
4 passed
```

และ health response ของ core ต้องมีอย่างน้อย:

```json
{
  "component": "core",
  "state": "RUNNING",
  "deps": [{"name": "bridge", "state": "RUNNING"}],
  "workers": {
    "pipeline_ready": true,
    "failure_reasons": []
  }
}
```

`DEGRADED` ต้องเป็นผลที่ยอมรับได้เฉพาะกรณีที่ test กำหนดไว้ชัดเจน เช่น PEP หรือ WFP dependency ไม่พร้อม แต่ health pipe ต้องตอบเสมอเพื่อให้ operator เห็นความจริง

## Phase 2 — Freeze canonical contracts

ทำสัญญา versioned contracts ให้เสร็จในทุกภาษา:

| Contract | Canonical owner | ต้องตรวจ |
|---|---|---|
| Event | Zig canonical event | field order, required fields, bounded payload, event id |
| Policy | TypeScript authoring + Zig Policy IR | digest, version, severity/action vocabulary |
| PEP ABI | `rust-src/lib.rs` + Zig bindings | `repr(C)`, offsets, sizes, reserved/version fields |
| Health | Zig runtime health | states, workers, failure mask, uptime, counters |
| Control IPC | Zig pipe protocol | role, caller, request id, nonce, timeout, replay protection |
| Forensics | Zig forensic trace | ordered chain, immutable append, replay atoms |
| Rules | `config/Rules.json` | schema version, unique IDs, pattern validity, scope |

เพิ่ม schema fixtures ที่ทุกภาษาต้องอ่านและเขียนผ่าน เช่น:

```text
contracts/fixtures/event/*.json
contracts/fixtures/pep/*.json
contracts/fixtures/health/*.json
contracts/fixtures/forensic/*.json
```

Exit criteria คือ cross-language round-trip test ผ่าน และ ABI layout test ผ่านบน x86_64 Windows release build

## Phase 3 — Runtime portability and adapter selection

Deployment ต้องใช้ profile แทน hard-coded host assumptions ไฟล์ต้นแบบอยู่ที่ `config/deployment_profile.example.json`

### Required behavior

- `interface_selector.mode=auto` เลือก adapter ที่ใช้งานได้
- สามารถเลือก Ethernet หรือ Wi-Fi ด้วย description, MAC หรือ index
- exclude loopback หรือ virtual adapters ได้
- Npcap ใช้สำหรับ packet capture
- WFP ใช้สำหรับ flow/enforcement integration
- ETW ใช้สำหรับ process/kernel telemetry
- replay ใช้สำหรับ deterministic offline test
- fallback ต้องรายงานเหตุผลใน health
- provider failure ต้องไม่เปลี่ยน enforcement เป็น allow

### Tests ที่ต้องเพิ่ม

1. mock adapter inventory มี Wi-Fi และ Ethernet
2. auto selection เลือก adapter ตาม policy
3. explicit selection เลือก MAC ที่กำหนด
4. unavailable provider เข้าสู่ degraded พร้อม reason
5. replay mode ทำงานได้โดยไม่ต้องมี live NIC
6. LAN และ Wi-Fi produce canonical event schema เดียวกัน

## Phase 4 — Rules and policy productization

Ruleset ปัจจุบันมี 22 rules และครอบคลุม L4/L7, kernel file/process และ named pipe แล้ว ขั้นต่อไปคือทำให้ rules เป็น product configuration ที่ปลอดภัย:

- มี JSON schema ที่เป็นทางการ
- validate regex ก่อน commit
- reject duplicate `rule_id`
- มี rule scope เช่น source, destination, adapter, protocol และ port
- มี severity/action vocabulary ที่ปิดชุด
- มี rule revision และ policy version
- มี author, created_at, expires_at และ change reason
- มี dry-run compilation สำหรับ Zig AC และ Python regex
- มี rollback ของ ruleset
- มี audit record ทุก add/update/delete
- มี signature verification ก่อน enable production policy

Command center ควรมี surface ต่อไปนี้:

```text
rules list
rules show --id ID
rules validate
rules add --rule-json JSON
rules update --id ID --rule-json JSON
rules delete --id ID
policy list
policy show --id ID
policy enable --id ID
policy disable --id ID
policy reload
```

CRUD สำเร็จแล้วใน CLI แต่ต้องเชื่อม production path ให้ reload ผ่าน control IPC, validate ใน Zig, compile tiers และทำ atomic policy swap โดยไม่ให้ CLI เขียน enforcement state โดยตรง

## Phase 5 — End-to-end detection and enforcement

ต้องทำ golden-path evidence จาก input เดียวให้ครบ:

```text
WSL2/LAN/Wi-Fi input
 -> Go Nose or host adapter
 -> canonical event
 -> Zig flow/detection
 -> Cython/Python Tier-2 when applicable
 -> correlation/incident
 -> policy decision
 -> Rust PEP authorization
 -> WFP adapter
 -> response
 -> forensic trace
```

สำหรับทุก decision ต้องเก็บ:

```text
event_id
incident_id
policy_id
policy_version
request_id
pep_decision
enforcement_result
forensic_id
```

ต้องมี matrix อย่างน้อย:

| Action | PEP ready | WFP ready | Expected |
|---|---:|---:|---|
| Alert | yes | no | alert/audit |
| Block | yes | yes | block + evidence |
| Block | yes | no | unavailable/escalate, never false success |
| Quarantine | yes | yes | authorized quarantine |
| Quarantine | no | yes | reject/escalate |
| Any privileged action | no | any | fail closed |

## Phase 6 — WSL2 attack laboratory

WSL2 ใช้เป็น controlled attacker ไม่ใช่ production simulator ที่ยิง payload อันตรายแบบไม่จำกัด

### Topology

```text
WSL2 attacker
  -> isolated virtual/LAN path
  -> Windows AEGIS host
  -> Npcap/WFP/ETW
  -> canonical pipeline
  -> Rust PEP
```

### Test sequence

1. interface and route discovery
2. benign connectivity check
3. local disposable HTTP service
4. SQL injection marker
5. command injection marker
6. XSS marker
7. path traversal marker
8. bounded ICMP/SYN/XMAS reconnaissance marker
9. harmless file rename and process marker
10. replay comparison
11. canary block with expiry and rollback

ห้ามใช้ malware จริง, credential theft, ransomware หรือ uncontrolled flood ใน host test การทดสอบต้องมี scope, rate limit, expiry และ cleanup

### Exit criteria

ทุก scenario ต้องมี:

- expected rule matched
- expected severity/action
- event and request identifiers preserved
- PEP decision recorded
- WFP result recorded or explicit unavailable
- forensic trace exported
- rollback verified

## Phase 7 — Forensics, replay and evidence

ทำให้ forensic evidence เป็นหลักฐาน release ไม่ใช่เพียง log:

- append-only hash chain
- decision trace ordered chain
- event/policy/context/binary provenance
- replay uses historical input and policy version
- replay never enforces
- difference reason identifies changed atom
- export JSON and CSV
- evidence index links test, commit and artifacts
- clock and timezone recorded

สร้าง evidence bundle ต่อ run:

```text
evidence/<run-id>/
  environment.json
  command.txt
  test-output.txt
  health-before.json
  health-after.json
  decision-trace.ndjson
  forensic-export.json
  artifact-digests.json
  result.json
```

## Phase 8 — Operator product and appliance workflow

ระบบควรมี one-command workflow ที่ไม่ทำให้ผู้ใช้ต้องรู้รายละเอียดทั้ง 7 ภาษา:

```text
preflight
install/build
profile validate
start
status
health
events
forensic export
rules/policy management
canary run
stop
snapshot
rollback
```

CLI ต้องรายงาน actionable errors เช่น:

```text
CORE_NOT_RUNNING
PEP_UNAVAILABLE
WFP_DRIVER_MISSING
ADAPTER_NOT_FOUND
RULESET_INVALID
CONTROL_PIPE_UNAVAILABLE
```

แต่ละ error ต้องมีสาเหตุ, ผลกระทบ, คำสั่งตรวจสอบ และวิธี recovery ที่ไม่ทำให้ operator เข้าใจผิดว่า enforcement สำเร็จ

## Phase 9 — Release, installer and update safety

Release pipeline ต้องสร้าง:

- Windows binaries
- Shield DLL
- Rust PEP DLL
- native helpers
- Go binaries
- Python/Cython package
- TypeScript policy artifacts
- deployment profile template
- signed rules/policy package
- SBOM
- build manifest
- artifact digests
- installer
- rollback snapshot

Release gates:

1. clean checkout build
2. all toolchain versions pinned
3. all required artifacts exist
4. digest verification passes
5. static authority checks pass
6. unit and integration tests pass
7. Windows lifecycle tests pass
8. WFP host tests pass on approved test host
9. install/uninstall/upgrade/rollback pass
10. evidence bundle is complete

## Phase 10 — Final production acceptance

### Required test result

```text
full pytest: 0 failed
expected skips only
Zig unit tests: all pass
Rust PEP tests: all pass
Shield tests: all pass
C/C++ build and tests: all pass
Go tests: all pass
TypeScript typecheck/test: all pass
Windows live lifecycle: all pass
WFP host block/unblock: pass on approved driver host
WSL2 lab scenarios: all pass
release verify: all artifacts match
```

### Required operational demonstration

A reviewer must be able to clone or install the release on a clean Windows host, select a LAN or Wi-Fi adapter through the profile, start the system, see health, add or disable a rule, generate a bounded lab event from WSL2, observe the decision, export evidence, stop the runtime, and restore the previous release without editing source code.

### No-go conditions

Do not declare production complete when any of the following is true:

- core lifecycle has no health response
- WFP driver is missing but UI says block succeeded
- rules can bypass validation or audit
- Shield can authorize privileged action
- two runtime owners can start the same workers
- manifest digest is stale
- replay can enforce
- installer loses config or evidence
- Wi-Fi works but LAN requires source changes
- WSL2 test has no cleanup and scope control

## Immediate next actions

1. Rebuild core with the repository's supported build invocation. The previous command `zig build -Doptimize=ReleaseSafe` returned `invalid option`; run `zig build -h` and use the option exposed by the current build graph rather than assuming the flag name.
2. Capture core process exit code, stderr, resolved DLL/config paths and pipe creation result during `test_harness_integration.py`.
3. Confirm that `aegis_control` is created before worker readiness becomes degraded.
4. Rerun the core lifecycle test until it reaches a truthful `RUNNING` response.
5. Run the full suite with WFP host gate disabled and record expected skips.
6. On a dedicated administrator/test-signed Windows host, build/install the WFP driver and run the explicit block/unblock host test.
7. Add adapter-selection tests for both Wi-Fi and Ethernet.
8. Add end-to-end WSL2 evidence bundle tests.
9. Execute clean-install, upgrade, rollback and uninstall tests.
10. Freeze current truth artifacts and publish the final release evidence bundle.

## Definition of done

The project is finished when AEGIS behaves like a portable security appliance rather than a collection of language runtimes: one supported installation path, one operator command center, one runtime owner, one canonical policy and event contract, one Rust PEP enforcement authority, selectable capture providers, truthful health, deterministic evidence, safe WSL2 validation, and a release that can be installed, verified, updated and rolled back on another Windows machine.

## References

[1]: README.md "AEGIS NIDS Windows current architecture and truth-oriented status"

[2]: docs/runtime/LOCAL_RUNBOOK.md "AEGIS local operator runbook"

[3]: docs/USER_OPERATIONS_GUIDE.md "AEGIS user operations guide"

[4]: docs/PORTABLE_DEPLOYMENT_AND_WSL2_TESTING.md "Portable deployment and WSL2 testing runbook"

[5]: build_manifest.json "AEGIS release build manifest and artifact digests"

[6]: tests/runtime/test_harness_integration.py "Windows component lifecycle integration tests"

[7]: tests/wfp/test_t11_windows_host.py "Rust PEP to WFP Windows host test"
