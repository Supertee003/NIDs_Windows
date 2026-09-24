# AEGIS Production Handoff

**Project:** AEGIS Windows-native NIDS/IPS  
**Handoff date:** 2026-09-22  
**Audience:** Future Manus agents, developers, reviewers, QA engineers, release operators, and security engineers  
**Document status:** Authoritative continuation brief for the current engineering state  
**Repository root:** `D:\NIDs_Windows` on the Windows development host  
**Current safety posture:** Detection and observe-only operation; prevention gate closed

> **Important:** This handoff is designed to prevent a future agent from confusing source implementation with verified runtime capability. The next agent must use this document together with the current source tree, current build manifest, current runtime health, and current proof output. Historical notes are evidence of previous work, not proof for the current build.

---

## 1. Executive conclusion

AEGIS is a Windows-native network intrusion detection and response platform with a multi-language implementation. Its intended production architecture separates sensor observation, event normalization, detection, policy decision, privileged authorization, Windows host effect, forensic evidence, lifecycle ownership, and operator presentation.

The project has reached an **engineering-complete foundation**. The following areas have meaningful implementation and partial verification: the Zig runtime owner, Go Nose ingress, WFP kernel telemetry, control-plane health, forensic recording, Rule-22 synthetic qualification, FIM proof-root readiness, contract validation, and read-only operator surfaces.

The project is **not yet accepted as a production IPS**. The remaining work is primarily host-level and release-level verification. Backend code, frontend code, and unit tests are necessary but not sufficient. A security product becomes production-ready only when the current Windows build demonstrates correct cross-language ABI behavior, real sensor observations, controlled reversible host effects, receipt-backed postconditions, cleanup, restart recovery, signing, packaging, and rollback.

The correct overall path is:

```text
Current-source provenance
  -> cross-language contract freeze
  -> Windows build and ABI validation
  -> real sensor observation proofs
  -> Rule-22 real qualification
  -> controlled WFP host-effect proof
  -> receipt and cleanup verification
  -> failure/restart/recovery testing
  -> signing and packaging
  -> production acceptance
```

The prevention gate must remain closed until the controlled WFP proof and its cleanup/recovery evidence are accepted.

---

## 2. Direct answer to the production question

The assumption that “backend, frontend, and tests are complete, therefore production is complete” is **not sufficient** for AEGIS.

For an ordinary web application, backend and frontend tests may cover most of the product surface. A Windows NIDS/IPS has additional trust boundaries that cannot be validated by application tests alone:

1. The running process must be the current build, not an older installed daemon.
2. The driver must be the intended binary and must satisfy Windows signing policy.
3. Kernel telemetry must cross the device and IOCTL boundary correctly.
4. Real network and file sensors must create normalized events.
5. Cross-language structures must have identical sizes, offsets, endianness, and enum values.
6. A policy decision must not be confused with a host effect.
7. A WFP effect must be verified on the host after the provider returns.
8. Cleanup must remove the exact filter recorded in the receipt.
9. Restart and crash recovery must not leave stale filters, processes, pipes, or corrupted evidence.
10. The installer, manifest, artifact hashes, signing, upgrade, and rollback must be verified.

Therefore, the project needs both **production-grade documentation and contracts now** and **production acceptance evidence before enabling IPS**.

---

## 3. Current ground truth

### 3.1 Completed or substantially completed

| Area | Current state | Evidence interpretation |
|---|---|---|
| Zig daemon ownership | Implemented | Runtime owner is intended to be `src/daemon.zig` and the current Zig daemon path |
| Runtime readiness | Implemented | Worker readiness and failure state are represented in health |
| Control plane | Implemented | Read-only status, health, simulate, verify, and fail-closed mutation paths exist |
| Go Nose ingress | Implemented | Canonical frames can enter through `\\.\pipe\aegis_nose` |
| WFP kernel telemetry | Observe-only path verified in the isolated lab | Kernel ring and user-mode readback were demonstrated; this is not a block proof |
| Forensic pipeline | Implemented | Events and evidence can be recorded and verified within the runtime generation |
| Rule-22 synthetic qualification | Passed | Synthetic fixture matching is not real-sensor or IPS evidence |
| FIM proof root | Implemented | `AEGIS_FIM_PROOF_ROOT` allows safe testing without changing system directories |
| FIM normalization source | Implemented in current source path | Real Windows proof is still required |
| Operator contract v1 | Added | Python contract and health tests passed in the sandbox |
| Web dashboard | Read-only surface implemented | It must consume backend truth and must not become a second supervisor |
| Native dashboard semantics | Receipt-aware projection implemented | A policy `BLOCK` label alone cannot be displayed as confirmed blocking |
| README and documentation | Production-oriented | Documentation does not substitute for host acceptance |

### 3.2 Not accepted yet

| Area | Status | Required next evidence |
|---|---|---|
| Current Windows build | Pending in the current session | Build and run from `D:\NIDs_Windows` |
| FIM real sensor proof | Pending | Real `ReadDirectoryChangesW` event through normalization and forensic path |
| ETW real coverage | Pending | Real event capture and normalized evidence |
| Registry real coverage | Pending | Real event capture and normalized evidence |
| Rule-22 real qualification | Pending | Sensor event, rule match, correlation, and evidence per rule/profile |
| EnforcementReceipt host postcondition | Pending | Valid receipt after actual provider effect and verification |
| WFP controlled block | Not started/accepted | Isolated reversible block proof |
| Exact cleanup | Pending | Remove exact receipt filter and verify traffic recovery |
| Crash/restart recovery | Pending | No stale filter, process, pipe, or evidence inconsistency |
| Production signing | Pending | Driver, binaries, policies, and release manifest verification |
| Clean install/upgrade/rollback | Pending | Installer and release acceptance |

### 3.3 Current safety invariant

```text
prevention_gate       = closed
tier3_enforcing       = false
host_effect_capable   = false
receipt_required      = true
```

A provider being present or ready does not prove that a host effect occurred.

---

## 4. Architecture overview

### 4.1 Production reference architecture

```text
Operator / automation
        |
Authenticated control endpoint
        |
Zig daemon: runtime owner, supervisor, state, queues, health
        |
        +--> Packet ingress path
        |      +--> Npcap
        |      +--> Go Nose
        |      +--> CanonicalEvent frame
        |      +--> \\.\pipe\aegis_nose
        |
        +--> Kernel WFP telemetry path
        |      +--> WFP callout
        |      +--> kernel ring buffer
        |      +--> \\.\AegisWfpDevice
        |      +--> read-only IOCTL event readback
        |
        +--> Host telemetry paths
        |      +--> ETW
        |      +--> ReadDirectoryChangesW/FIM
        |      +--> Registry notifications
        |
        +--> Normalized event queue
        |      +--> identity
        |      +--> bounded payload
        |      +--> backpressure/drop ledger
        |
        +--> Detection and correlation
        |      +--> Rule-22 rules
        |      +--> Python/Cython analysis
        |      +--> incident context
        |
        +--> Policy authority
        |      +--> canonical policy action
        |      +--> severity and scope
        |      +--> policy version and signature
        |
        +--> Rust PEP authorization
        |      +--> capability checks
        |      +--> freshness/replay checks
        |      +--> explicit allow/deny/unavailable/failed
        |
        +--> WFP effect provider
        |      +--> guarded filter operation
        |      +--> host postcondition readback
        |      +--> exact cleanup
        |
        +--> Forensics and operator views
               +--> event and audit identities
               +--> receipt validation
               +--> CLI
               +--> web dashboard
               +--> native dashboard
```

### 4.2 Authority boundaries

| Component | May do | Must not do |
|---|---|---|
| WFP kernel callout | Observe classification-layer activity and maintain kernel ring state | Decide policy or bypass user-mode authorization |
| Go Nose | Capture/decode packets and serialize canonical frames | Call WFP, authorize a block, or claim host effect |
| C/C++ adapters | Expose bounded Windows ABI/provider interfaces | Become an independent policy authority |
| Zig daemon | Own lifecycle, queues, runtime state, control, health, and orchestration | Mutate WFP outside the authorized PEP path |
| Detection engine | Match rules and produce evidence | Produce final `BLOCKED_CONFIRMED` or call WFP |
| Policy layer | Select intended action from evidence and context | Claim that the action was applied |
| Rust PEP | Authorize, deny, or reject privileged requests | Claim host effect without postcondition evidence |
| WFP user adapter | Apply the provider-level operation requested through the authorized path | Accept direct calls from untrusted layers |
| Forensic pipeline | Append, verify, link, and export evidence | Hide unavailable, failed, or cleaned-up actions |
| Python/CLI | Request control operations and display authoritative responses | Start a second supervisor or bypass the daemon |
| Web/native dashboard | Present health, events, incidents, and receipts | Infer a block from a policy label or log line |

The essential distinction is:

```text
Detection result
  != policy decision
  != PEP authorization
  != WFP provider response
  != verified host postcondition
```

Only a validated `EnforcementReceipt v1` may support `BLOCKED_CONFIRMED`.

---

## 5. End-to-end operation

### 5.1 Who, what, where, how, when, why

Every event and incident must be explainable through these questions:

| Question | Required answer | Typical evidence |
|---|---|---|
| **Who?** | Which sensor, process, runtime generation, policy authority, provider, or operator handled the record? | source, PID, runtime generation, role, provider identity |
| **What?** | What activity occurred, which rule matched, and which decision resulted? | event type, payload metadata, rule ID, severity, policy action |
| **Where?** | Which host, interface, IP, port, file, process, pipe, or filter scope was involved? | source/destination addresses, interface, path, process, filter ID |
| **How?** | Which sensor and contract carried the data, and which components transformed it? | sensor path, contract version, pipe, policy version, PEP/provider result |
| **When?** | When was it observed, processed, decided, applied, verified, and cleaned up? | event, monotonic, request, audit, postcondition, cleanup timestamps |
| **Why?** | Why was it classified, allowed, rejected, deferred, failed, or escalated? | rule reason, policy reason, denial code, provider reason, failure evidence |

### 5.2 Packet ingress path

```text
Selected Windows interface
  -> Npcap
  -> Go Nose packet decode
  -> 4-byte little-endian length + CanonicalEvent payload
  -> \\.\pipe\aegis_nose
  -> Zig pipe reader
  -> queue and runtime context
  -> detection/correlation
  -> policy input
  -> forensic record
```

This path is distinct from the WFP kernel telemetry path.

### 5.3 WFP kernel telemetry path

```text
Network activity at a WFP classification layer
  -> kernel callout
  -> kernel ring buffer
  -> \\.\AegisWfpDevice
  -> read-only IOCTL
  -> user-mode WFP adapter
  -> normalized event
  -> Zig pipeline
  -> forensic record
```

The observe-only proof must use read-only access and must not call block or unblock control codes.

### 5.4 FIM path

```text
File create/modify/delete/rename
  -> ReadDirectoryChangesW
  -> FILE_NOTIFY_INFORMATION
  -> Zig parser and UTF-16/path validation
  -> normalized FimEvent
  -> IpcEvent bounded path payload
  -> Rule-22 match
  -> forensic evidence
```

`AEGIS_FIM_PROOF_ROOT` selects a disposable test root. The proof must not modify `System32` or another production directory.

### 5.5 Enforcement path

```text
DetectionResult
  -> policy evaluation
  -> BLOCK_REQUESTED
  -> Rust PEP validation
  -> guarded WFP provider request
  -> host postcondition verification
  -> EnforcementReceipt v1
  -> forensic/audit linkage
  -> operator display
```

The controlled proof is not accepted unless traffic behavior, provider state, receipt fields, forensic linkage, cleanup, and recovery all agree.

---

## 6. Cross-language contracts

### 6.1 Contract review method

Every contract must be analyzed in five dimensions:

1. Definition: where the type or schema is declared.
2. Serialization: how it is encoded on a wire, pipe, file, or FFI boundary.
3. Validation: which side rejects malformed or incompatible input.
4. Authority: which component is allowed to make decisions from it.
5. Evidence: how use of the contract is recorded and verified.

### 6.2 CanonicalEvent and IpcEvent

Known contract facts from the current project context:

```text
CanonicalEvent wire payload = 109 bytes
IpcEvent internal representation = 96 bytes
WFP event header = 44 bytes
Go Nose frame = 4-byte length prefix + canonical payload
```

These sizes must be checked from the current source and build artifacts. They must not be copied blindly into a new implementation.

`CanonicalEvent` and `IpcEvent` are not interchangeable. A conversion boundary must preserve event identity, timestamp semantics, network metadata, rule identity, payload bounds, policy status, and forensic linkage. If a field is intentionally dropped, that loss must be explicit and observable.

### 6.3 Action namespaces

Policy actions and PEP response decisions are separate namespaces. The current operator contract records:

```text
PolicyAction.BLOCK = 2
PepDecision.BLOCK = 1
```

These values must not be compared directly. A provider-specific action value must be mapped through an explicit contract layer.

### 6.4 EnforcementReceipt v1

A confirmed receipt requires, at minimum:

```text
version = supported version
status = enforced
host_effect_confirmed = true
request_id != 0
event_id != 0
trace_id != 0
audit_id != 0
filter_id != 0
provider is present
```

The following states must never produce a confirmed block:

```text
simulated
pending
failed
unavailable
provider_ready without postcondition
policy BLOCK without receipt
```

### 6.5 Health semantics

The following fields have distinct meanings:

```text
runtime state
worker readiness
pep_ready
provider_ready
host_effect_capable
tier3_ready
tier3_enforcing
prevention_gate
forensic integrity
```

A system may have `pep_ready=true` while remaining `host_effect_capable=false`. A system may have a provider present while the prevention gate remains closed.

---

## 7. Backend source map

### 7.1 Zig runtime

Start analysis here:

```text
src/main.zig
src/daemon.zig
src/control/
src/pipeline/
src/core/
src/platform/
```

Verify:

- one runtime owner;
- one stop signal and reverse-order join;
- bounded worker startup barrier;
- readiness only after real initialization;
- failure masks and failure reasons;
- control pipe ownership;
- queue backpressure and drop metrics;
- no stale daemon generation is treated as current;
- blocking Windows APIs have a proven shutdown path.

### 7.2 WFP driver and user adapter

Start analysis here:

```text
drivers/wfp_callout/aegis_wfp.c
drivers/wfp_callout/aegis_wfp_callout.c
drivers/wfp_callout/aegis_wfp_comm.c
src/windows/wfp_ioctl.c
scripts/run_wfp_l4_observe_only_proof.ps1
```

The driver is a kernel sensor/provider boundary. Verify device name, IOCTL codes, packed header sizes, ring buffer behavior, read/write access, service path, signature, and cleanup behavior. The observe-only proof must not be interpreted as an IPS proof.

### 7.3 Go Nose

Start analysis here:

```text
nose/
nose/golden_path_ffi.go
nose/inject.go
src/capture/nose_pipe_reader.zig
```

Verify adapter selection, packet decode, BPF behavior, canonical frame serialization, length prefix, reconnect behavior, counters, monotonic IDs, duplicate handling, and pipe ownership. Nose is an ingress sensor, not a policy authority.

### 7.4 FIM

Start analysis here:

```text
src/windows/fim_native.c
src/windows/fim.zig
src/windows/windows_adapters.zig
src/pipeline/telemetry_threads.zig
scripts/run_fim_real_observe_only_proof.ps1
```

Verify `ReadDirectoryChangesW` buffer handling, record chaining, UTF-16 conversion, relative path normalization, action mapping, bounded payloads, timestamps, proof-root selection, queue submission, and forensic linkage.

### 7.5 ETW and Registry

Start analysis here:

```text
src/windows/etw_realtime.zig
src/windows/registry_monitor.zig
src/pipeline/telemetry_threads.zig
```

A `READY` worker is not equivalent to a real sensor proof. Capture a real event, normalize it, match or correlate it, and verify the evidence chain.

### 7.6 Rust PEP and Shield

Start analysis here:

```text
shield/
rust-src/
src/core/rust_pep.zig
src/policy/pep_bindings.zig
src/policy/enforcement_receipt.zig
```

Verify FFI layout, calling convention, ownership, error mapping, capability checks, request freshness, replay handling, action mapping, provider readiness, receipt fields, and explicit unavailable/failed states.

### 7.7 Python/Cython detection

Start analysis here:

```text
brain/
brain/cython/
src/detection/
tests/cython/
```

Python fallback and Cython fast path must produce the same `DetectionResult`. Test binary payloads, embedded NUL, truncation, oversized input, invalid encoding, timeout behavior, and fallback behavior.

### 7.8 Policy and TypeScript

Start analysis here:

```text
ts_policy/
src/policy/
configs/
contracts/
```

Policy authoring may validate, compile, sign, version, and package policy. It must not directly enforce a Windows host effect. Zig and Rust must validate policy again at their boundaries.

---

## 8. Frontend and operator surface

### 8.1 CLI

Primary operator commands include:

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py status --json
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
python tools\aegisctl.py metrics
python tools\aegisctl.py incidents
python tools\aegisctl.py events count
python tools\aegisctl.py events tail
python tools\aegisctl.py rules list
python tools\aegisctl.py rules validate
```

The CLI must remain a thin client. It should display control-plane truth and not create an independent lifecycle or policy authority.

### 8.2 Web dashboard

The read-only Python dashboard exposes:

```text
/
/api/snapshot
/api/status
/api/incidents
/api/receipt
/health
/rules
/stream
/health/check
```

It must use the same semantic projection as the CLI. It must not turn a policy label into `BLOCKED_CONFIRMED` and must not mutate WFP.

### 8.3 Native dashboard

The Rust/native dashboard is an operator presentation layer. It may display alerts, health, incidents, and validated receipts. It must not become a second runtime owner or infer host effect from a log line.

### 8.4 Operator evidence rule

Every incident view should support this chain:

```text
event_id
  -> rule_id and detection evidence
  -> incident context
  -> policy decision
  -> request_id and trace_id
  -> PEP/provider response
  -> filter_id and host postcondition
  -> audit_id and forensic record
```

A missing link means the record may remain valid detection evidence, but it cannot be displayed as confirmed enforcement.

---

## 9. Test and evidence inventory

### 9.1 Tests already passed in the sandbox

The current sandbox validation included:

```text
28 Python tests passed
Python syntax validation passed
Operator contract JSON validation passed
README and changed-file diff checks passed
Web dashboard route smoke test passed
```

These results validate Python contracts and presentation logic. They do not replace Windows, Zig, Rust, C/C++, driver, or host-effect acceptance.

### 9.2 Existing proof categories

| Proof | What it proves | What it does not prove |
|---|---|---|
| Rule matching observe-only | Fixtures match configured rules | Real sensor path or host effect |
| Control receipt probe | Read-only routes and invalid mutation fail closed | Real WFP block |
| WFP observe-only | Driver/device/ring readback and kernel observation | Rule enforcement or host block |
| FIM real observe-only | Real file notification and normalized path | Production-wide FIM coverage or host response |
| Health probe | Runtime/dependency/readiness state | Correctness of every event path |
| Forensic verification | Record integrity and linkage within the generation | Cross-restart durable storage unless separately proven |
| Controlled IPS proof | Real reversible host effect and cleanup | General production safety without hardening/release gates |

### 9.3 Test evidence requirements

Every proof record should contain:

```text
source commit or build ID
artifact hashes
daemon path and PID
driver path, service name, and hash
OS/build and toolchain versions
network topology and interface
ruleset/policy digest
prevention-gate state
baseline counters
operation performed
observed result
forensic/audit identifiers
cleanup result
final health result
```

---

## 10. Remaining work to reach Production

### Phase A: Current-build Windows validation

Run from the Windows host using the current repository root:

```powershell
Set-Location D:\NIDs_Windows
.\scripts\build_all.bat
python tools\release_engineering.py --manifest
python tools\release_engineering.py --verify
python tools\aegisctl.py rules validate
```

Then verify process provenance:

```powershell
Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'" |
  Select-Object ProcessId,ExecutablePath,CommandLine
Get-FileHash .\zig-out\bin\aegis_nids.exe -Algorithm SHA256
```

Acceptance requires no stale installed daemon and no required component skipped by the build.

### Phase B: Contract and ABI freeze

Complete:

- cross-language action ordinal tests;
- CanonicalEvent size, offset, and endian tests;
- IpcEvent conversion tests;
- WFP header ABI tests;
- malformed frame rejection tests;
- receipt v1 serialization and validation tests;
- policy version and signature tests;
- health schema tests;
- duplicate and non-monotonic event identity tests.

### Phase C: Real sensor proof

Complete, in order:

1. WFP read-only proof with a benign VMnet1 flow.
2. FIM real proof with `AEGIS_FIM_PROOF_ROOT`.
3. ETW real event coverage.
4. Registry real event coverage.
5. Forensic linkage for each real sensor.
6. Rule-22 real qualification matrix update.

### Phase D: Rule-22 qualification

For every rule, record:

```text
rule ID
severity
synthetic fixture result
real sensor source
benign trigger or replay input
normalized event
correlation result
policy decision
expected operator state
forensic record
whether controlled response is allowed
cleanup/recovery requirement
```

Synthetic success is not real-sensor success. Real-sensor success is not host-effect success.

### Phase E: Controlled WFP proof

Use a disposable Windows target VM and a host-only network. The representative lab is:

```text
Kali attacker VM       192.168.126.10
Windows target VM      192.168.126.20
Windows host           192.168.126.1
```

The proof must use a benign, bounded, reversible flow. It must demonstrate:

```text
rule match
  -> policy decision
  -> PEP authorization
  -> WFP filter installation
  -> traffic behavior changes
  -> host postcondition verified
  -> receipt emitted
  -> forensic linkage
  -> exact filter cleanup
  -> traffic recovery
  -> restart/recovery clean state
```

Do not run this on a business workstation or against a host that is not explicitly authorized.

### Phase F: Hardening and release

Complete:

- driver signing or approved isolated test-signing record;
- binary and DLL signing;
- policy/ruleset signing;
- named-pipe and service ACL review;
- least-privilege review;
- clean install;
- upgrade;
- downgrade or rollback;
- uninstall;
- stale process cleanup;
- stale pipe cleanup;
- stale WFP filter cleanup;
- crash recovery;
- restart recovery;
- release manifest and hashes;
- known limitations;
- incident response and rollback runbook;
- final acceptance record.

---

## 11. Safe operating procedure

### Observe-only startup

```powershell
Set-Location D:\NIDs_Windows
python tools\aegisctl.py status
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
python scripts\run_control_receipt_probe.py
```

Expected safe state:

```text
state                 = RUNNING or DEGRADED with explanation
prevention_gate       = closed
tier3_enforcing       = false
host_effect_capable   = false
receipt_required      = true
```

### WFP observe-only proof

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_wfp_l4_observe_only_proof.ps1 `
  -GenerateBenignProbe `
  -RequireEvent
```

The proof must show read-only access, event readback, and no forbidden block/unblock operation.

### FIM observe-only proof

```powershell
$proofRoot = Join-Path $PWD "test-fixtures\fim-proof"
New-Item -ItemType Directory -Force $proofRoot | Out-Null
$env:AEGIS_FIM_PROOF_ROOT = $proofRoot
```

Restart the current daemon, create a benign file change inside the proof root, and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_fim_real_observe_only_proof.ps1
Remove-Item Env:AEGIS_FIM_PROOF_ROOT -ErrorAction SilentlyContinue
```

### Safe network lab testing

Use only disposable systems and bounded traffic:

```bash
nc -vz -w 5 192.168.126.20 49152
nmap -sT -Pn -p 49152 --max-retries 1 --host-timeout 10s 192.168.126.20
```

Do not use credential theft, ransomware, destructive payloads, uncontrolled flood commands, or exploit chains. A test must be authorized, bounded, reversible, and recorded.

---

## 12. Failure modes and interpretation

### Wrong daemon path

If the process path is under `C:\Program Files\AEGIS` while the test expects `D:\NIDs_Windows\zig-out\bin\aegis_nids.exe`, stop and correct provenance before interpreting any result.

### Named pipe busy

`ERROR_PIPE_BUSY` indicates pipe ownership contention or a stale runtime. Do not start a second daemon to bypass it. Identify the owner, stop the stale generation, verify pipe release, and retry.

### Driver signature error

A Windows driver signature failure is a deployment failure. Do not interpret an old loaded driver as evidence for the current source. Verify service state, installed path, and SHA256.

### Degraded health

`DEGRADED` is an explicit safety state. Inspect worker failure reasons, provider readiness, FIM readiness, data-plane counters, and forensic integrity. Do not silently upgrade degraded state to production enforcement.

### No WFP event

First verify interface/topology, driver state, device path, traffic direction, callout layer, ring buffer state, read access, and current driver hash. A successful TCP connection alone does not prove that AEGIS captured an event.

### No FIM event

Verify that the daemon restarted after setting `AEGIS_FIM_PROOF_ROOT`, the path is within the configured watch root, the native helper is ready, the change occurred after watcher startup, and the raw notification buffer was parsed successfully.

---

## 13. Definition of Done

AEGIS may be called production-ready only when all required boxes are true:

```text
[ ] Current source/build/runtime provenance verified
[ ] Required build components report OK with no required SKIP
[ ] Cross-language action and ABI contracts frozen
[ ] CanonicalEvent/IpcEvent conversion verified
[ ] WFP observe-only proof passed on the current driver
[ ] FIM real proof passed on the current daemon
[ ] ETW and Registry real coverage verified or explicitly excluded
[ ] All 22 rules pass synthetic qualification
[ ] Required rules pass real sensor qualification
[ ] EnforcementReceipt v1 is emitted and validated
[ ] Controlled WFP block proof passed in an isolated target VM
[ ] Host postcondition verified independently
[ ] Exact filter cleanup verified
[ ] Traffic recovery verified
[ ] Crash and restart recovery verified
[ ] No stale process, pipe, filter, or evidence inconsistency
[ ] Driver and binaries signed according to the release profile
[ ] Clean install verified
[ ] Upgrade and rollback verified
[ ] Release manifest and hashes verified
[ ] CLI, web, and native views show the same semantic state
[ ] Production acceptance report approved
```

---

## 14. Instructions for the next AI agent

The next agent must follow this order and must not skip directly to IPS:

1. Read this handoff, the current `README.md`, the operator acceptance note, the contract JSON, and the local runbook.
2. Inspect `git status` and identify uncommitted changes before modifying files.
3. Re-scan the current source rather than trusting historical summaries.
4. Confirm the current Windows build and process provenance.
5. Run read-only health and contract probes.
6. Complete FIM real proof and WFP observe-only proof.
7. Update the qualification matrix with evidence, not assumptions.
8. Resolve any contract or ABI drift before controlled enforcement.
9. Keep `prevention_gate=closed` until a user-approved isolated proof plan is fully prepared.
10. Before any host-effect operation, present the exact target, flow, policy, expected effect, receipt fields, cleanup plan, and recovery plan for explicit confirmation.
11. After the proof, verify the host postcondition, receipt, forensic linkage, cleanup, and recovery independently.
12. Update this handoff with command output, artifact hashes, dates, and the exact current status.

The next agent must never infer that a component is production-ready because:

```text
its source file exists
its worker says READY
its provider says READY
its policy says BLOCK
its frontend displays BLOCK
its unit test passes
```

Those facts are necessary but not sufficient.

---

## 15. Final handoff statement

AEGIS is ready for the next development phase: **current-build Windows validation, real FIM proof, WFP observe-only regression, contract/ABI freeze, and Rule-22 real sensor qualification**.

It is not yet ready for production IPS deployment. The correct next milestone is not to open blocking immediately. The correct next milestone is to produce a reproducible evidence bundle proving that the current build observes real events, preserves identity and forensic linkage, remains fail-closed, and can later apply and remove one controlled WFP effect without leaving stale state.

The final production claim must be earned by evidence:

```text
Observed
  -> normalized
  -> detected
  -> decided
  -> authorized
  -> applied
  -> verified
  -> recorded
  -> cleaned up
  -> recovered
```

Until every required link is proven, AEGIS remains a production-oriented NIDS foundation with controlled IPS development, not a production prevention appliance.

---

## References

[1]: README.md "AEGIS NIDS for Windows Official README"
[2]: docs/P0_P2_OPERATOR_ACCEPTANCE.md "AEGIS P0–P2 Operator Acceptance"
[3]: docs/runtime/LOCAL_RUNBOOK.md "AEGIS Local Runbook"
[4]: docs/architecture/CONTRACTS.md "AEGIS Authoritative Contracts"
[5]: contracts/operator_contract_v1.json "AEGIS Operator Contract v1"
[6]: docs/USER_OPERATIONS_GUIDE.md "AEGIS User Operations Guide"
