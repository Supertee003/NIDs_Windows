# AEGIS Comprehensive Development Analysis and Production Handoff

**Project:** AEGIS Windows-native NIDS/IPS  
**Date:** 2026-09-20  
**Audience:** Project owner, Manus agents, developers, reviewers, and future maintenance sessions  
**Document role:** Operational source-analysis and development handoff

---

## 1. Executive conclusion

AEGIS is a multi-language Windows-native network intrusion detection and prevention system. Its intended architecture separates observation, analysis, policy authority, host enforcement, evidence, lifecycle control, and operator presentation. This separation is the central security property of the project.

The project has already reached a meaningful data-plane and lifecycle milestone. The observed path from Go Nose through the named pipe into the Zig runtime and forensic ring has passed controlled observe-only evidence. Lifecycle recovery has also passed with a new process generation and a verified forensic ring. Rust PEP readiness is represented separately from WFP provider readiness, and the system remains fail-closed while host effect is not proven.

The project is **not yet Production-ready**. The missing proof is not merely a build or unit-test result. Production acceptance requires a Windows host-level WFP proof in an isolated VMware lab. That proof must show a real reversible host effect, an authoritative `EnforcementReceipt`, forensic linkage, cleanup, and successful recovery without stale filters or stale runtime ownership.

The correct development strategy is therefore:

```text
Truth and contracts
  -> runtime/lifecycle convergence
  -> canonical data plane
  -> detection and policy convergence
  -> PEP authority
  -> WFP provider
  -> isolated host-effect proof
  -> rollback and recovery
  -> operator/UI acceptance
  -> packaging and release acceptance
```

No component may skip its authority boundary in order to make a demonstration appear successful.

---

## 2. Non-negotiable architectural invariants

### 2.1 One runtime owner

The Zig daemon is the runtime owner. It owns lifecycle state, worker startup, readiness, stop signals, join order, control protocol, queue coordination, and authoritative health.

Normal start, stop, restart, and recovery must converge on the daemon control plane. The CLI, dashboard, installer, or UI must not become a second runtime supervisor. Process inspection may be used for diagnostics, but it must not be promoted to operational truth when the daemon control pipe is unavailable.

### 2.2 One enforcement authority

Rust PEP is the sole authority that may authorize a privileged enforcement action. WFP is the host-effect provider controlled through that authority. Detection, Python, Cython, TypeScript, Go Nose, Zig policy orchestration, CLI, and Mouth may request, classify, display, or record, but none may independently mutate host filtering state.

The following distinction must remain explicit:

```text
Detection result       != policy decision
Policy decision        != PEP authorization
PEP authorization      != WFP host effect
WFP response           != verified postcondition
EnforcementReceipt     = only valid claim when all required fields verify
```

### 2.3 Detection cannot block

Detection produces a typed `DetectionResult`. It can identify a pattern, confidence, severity, rule, context, and evidence. It cannot decide that the host must block traffic.

Policy maps detection and context to an intended action. Rust PEP verifies whether that action is authorized. WFP performs the host effect. A detector must never call WFP or produce a final `BLOCKED` state.

### 2.4 Mouth is receipt-driven

Mouth and all operator-facing views must display host blocking only from an authenticated and validated `EnforcementReceipt`. A log line, policy decision, or PEP response without host-effect confirmation is insufficient.

The minimum success condition is equivalent to:

```text
receipt.status == ENFORCED
receipt.host_effect_confirmed == true
receipt.filter_id != 0
receipt.request_id != 0
receipt.event_id != 0
receipt.trace_id != 0
receipt.audit_id != 0
receipt.version == supported version
```

### 2.5 Health must describe reality

A live daemon response is runtime truth. A process scan or stale PID file is diagnostic information only. If the control daemon is unavailable, the API must return a degraded diagnostic payload with `runtime_available=false`; it must not claim that an unrelated process is the healthy runtime.

`DEGRADED` is not the same as `FAILED`. It means the runtime is operating while one or more capabilities are unavailable. In the current design, Rust PEP can be ready while WFP remains unavailable. This is an expected degraded state, not a reason to falsely mark Tier-3 as stopped.

---

## 3. Current system architecture

| Layer | Main technology | Responsibility | Must not do |
|---|---|---|---|
| Runtime hub | Zig | Daemon, lifecycle, control, queues, orchestration, health, forensic coordination | Mutate WFP outside PEP boundary |
| Network ingress, Nose | Go | Npcap capture, packet decoding, CanonicalEvent serialization, named-pipe delivery | Decide block or call WFP |
| Native adapters | C/C++ | Windows adapter boundaries such as ETW, FIM, and native provider interfaces | Become a second policy authority |
| PEP and shield | Rust | Privileged authorization, capability checks, enforcement request boundary, receipt production | Claim host effect without postcondition |
| Detection and intelligence | Python/Cython | Regex, fast scan, analytics, enrichment, context, fallback implementation | Authorize or execute block |
| Policy authoring | TypeScript | Validate, compile, sign, version, and package policy | Directly enforce policy |
| Evidence | Zig/Python support plus forensic contracts | Append, verify, replay, trace, audit, provenance | Hide failed or unavailable actions |
| Mouth/UI | Rust and dashboard tooling | Display health, alerts, receipts, operator state | Infer `BLOCKED` from logs or decisions |
| Operator tooling | Python/PowerShell | Control requests, diagnostics, proofs, reports | Bypass daemon authority in normal operation |

The source tree contains both current paths and historical/legacy paths. A future agent must never assume that file presence means production ownership. Ownership must be confirmed from the current build graph, runtime entrypoint, and contract references.

---

## 4. End-to-end data flow

### 4.1 Network observation path

The intended network path is:

```text
Wi-Fi / LAN / VMware VMnet
  -> Npcap
  -> Go Nose capture
  -> packet decode and normalization
  -> CanonicalEvent v1
  -> 4-byte little-endian frame length
  -> 109-byte canonical payload
  -> \\.\pipe\aegis_nose
  -> Zig Nose pipe reader
  -> event queue / Event Fabric
  -> detection orchestration
  -> correlation and threat context
  -> policy input
  -> audit and forensic evidence
```

The known wire shape is:

```text
4-byte length prefix + 109-byte payload = 113-byte frame
```

The CanonicalEvent contract currently identifies a magic value, schema version, struct-size marker, event identity, timestamps, network metadata, event type, severity, rule identity, payload length/hash, policy action, enforcement status, impact, context flags, and reserved extension space. This contract must be frozen through fixtures rather than inferred separately by every language.

### 4.2 Policy and enforcement path

The privileged path is:

```text
DetectionResult
  -> policy evaluation
  -> PolicyDecision
  -> Rust PEP authorization
  -> WFP request
  -> provider response
  -> host-effect observation
  -> EnforcementReceipt
  -> forensic linkage
  -> Mouth/operator display
```

The pipeline must distinguish at least these outcomes:

```text
ALLOW
ALERT
ESCALATE
BLOCK_REQUESTED
ENFORCEMENT_UNAVAILABLE
ENFORCEMENT_FAILED
BLOCKED_CONFIRMED
ROLLED_BACK
```

Only the last state is permitted to appear as a confirmed host block, and only when the receipt validates.

### 4.3 Lifecycle path

The lifecycle path is:

```text
operator request
  -> authorized control client
  -> named control pipe
  -> Zig handler registry
  -> state-machine transition
  -> worker stop/start or restart
  -> readiness barrier
  -> authoritative health
  -> postcondition and audit
```

The old daemon must finish and release the control pipe before an external owner starts. The recovery script therefore checks the old PID, control-pipe release, new PID generation, Rust PEP readiness, worker readiness, and forensic integrity of the new process generation.

---

## 5. Contract inventory and analysis method

Every contract must be examined in five dimensions:

1. **Definition:** Where is the type or schema declared?
2. **Serialization:** How is it encoded on the wire or in a file?
3. **Validation:** Which side rejects malformed or incompatible data?
4. **Authority:** Which component is allowed to make decisions from it?
5. **Evidence:** How is the use of the contract recorded and verified?

### 5.1 CanonicalEvent

Relevant source areas include:

```text
src/contract/canonical_event.zig
src/contract/event.zig
src/contract/wire_event.zig
shared/event/
shared/wire/
nose/golden_path_ffi.go
contracts/fixtures/
```

Required checks include field offsets, total size, endianness, enum ordinal values, version behavior, reserved fields, IPv4/IPv6 semantics, timestamp semantics, malformed-frame rejection, and round-trip behavior across Go and Zig.

Known historical risks include multiple event models, event ID ownership drift, conflicting struct-size constants, different event-type names, and different payload hash assumptions. These must be resolved by one generated or frozen fixture set.

### 5.2 IPC event

`IpcEvent` is an internal 96-byte representation and must not be silently substituted for the 109-byte wire CanonicalEvent. The conversion boundary must be explicit and tested. A smaller internal structure is valid only if it preserves the required identity and evidence fields or records the loss explicitly.

### 5.3 Producer identity

Cross-restart event identity must not rely on a process-local counter alone. A safe identity model includes producer identity, runtime generation, producer epoch, and local event sequence, or it delegates global sequence allocation to the Zig ingress authority.

Duplicate, collision, and non-monotonic identity are different failures and must have different metrics and evidence. Retrying a frame without an idempotency contract may produce duplicate side effects.

### 5.4 Policy contract

Relevant areas include:

```text
src/policy/
shared/policy/
ts_policy/
configs/policies.json
contracts/fixtures/pep/
```

The policy contract must define action vocabulary, severity, rule identity, policy version, signature, expiry, scope, change reason, and rollback behavior. TypeScript may author and validate policy, but Zig and Rust must independently validate the received representation at their boundaries.

### 5.5 EnforcementReceipt

The current receipt contract distinguishes status from host effect. A receipt is successful only when it has an enforced status and `host_effect_confirmed=true`. It also requires request and event identity, trace and audit linkage for forensic completeness, and a supported version.

A receipt with status `simulated`, `pending`, `failed`, or `unavailable` must never produce a UI state of confirmed block.

### 5.6 Health contract

The health payload must include runtime state, subsystem states, worker readiness, counters, data-plane metrics, Rust Shield state, Tier-3 state, WFP/provider state, and forensic/authority indicators where applicable.

The following fields have different meanings and must not be collapsed:

```text
rust_shield.pep_ready
rust_shield.provider_ready
rust_shield.host_effect_capable
tier3.ready
tier3.dependency_ready
tier3.provider_ready
overall_gate
```

### 5.7 Forensic contract

Forensic evidence must be appendable, integrity-verifiable, replayable where supported, and linked to event ID, request ID, policy ID/version, decision, receipt, filter identity, trace ID, audit ID, runtime generation, and cleanup result.

The current forensic ring is process-local bounded evidence. A clean restart may reset its record count. It must not reset the requirement that the new generation verifies its own integrity.

---

## 6. Backend development analysis

### 6.1 Zig runtime and daemon

Start analysis at:

```text
src/main.zig
src/daemon.zig
src/control/
src/pipeline/
src/core/
src/platform/
```

Confirm that `src/main.zig` and `daemon.runDaemon()` define the real production entrypoint. Trace worker creation, readiness flags, stop signals, join order, error masks, and control-pipe shutdown behavior. Confirm that every thread or worker has a bounded stop path and a join path.

Pay special attention to Windows blocking APIs. A blocking named-pipe accept or read may prevent the daemon from returning after a stop request. The implementation must use bounded polling, cancellation, a wake-up mechanism, or a close operation that is proven to release the blocking call.

The runtime must expose enough diagnostics to answer:

```text
Which generation is running?
Which workers started?
Which worker failed?
Which pipe owns the runtime?
Which readiness barrier is incomplete?
Which queue counters changed?
Which shutdown step is waiting?
```

### 6.2 Go Nose

Start analysis at:

```text
nose/main.go
nose/golden_path_ffi.go
nose/inject.go
src/capture/nose_pipe_reader.zig
src/capture/npcap_*.zig
```

Verify adapter selection, BPF behavior, packet decode, event normalization, serialization, pipe framing, reconnect behavior, counters, and error handling.

Nose is a sensor and ingress component. It must not contain a hidden policy authority. It must not call WFP. It must not state that a packet was blocked. If it classifies a signature locally for performance, that classification must become input to the canonical detection pipeline rather than a privileged action.

### 6.3 Python and Cython brain

Start analysis at:

```text
brain/
brain/cython/
brain/aegis_brain_cython/
src/detection/
tests/cython/
```

The Cython path and Python fallback must return the same `DetectionResult` semantics. Binary payloads must be length-aware; C string functions that stop at an embedded NUL must not be used for arbitrary network payloads.

Test both paths with identical vectors. Include ASCII, binary, embedded NUL, truncated input, oversized input, invalid encoding, regex timeout behavior, and fallback behavior. A performance optimization is valid only if it preserves the same authority and output contract.

### 6.4 Rust PEP and Shield

Start analysis at:

```text
rust-src/lib.rs
rust-src/shield/
shield/src/
src/core/rust_pep.zig
src/policy/pep_bindings.zig
```

Check ABI layout, calling convention, ownership, error mapping, capability checks, request freshness, replay handling, signed policy state, quotas, and provider response mapping.

A PEP response such as `accepted` is not enough to claim that a host filter exists. The Rust boundary must either return a receipt with verifiable provider identity and postcondition or return an unavailable/failed result.

### 6.5 C/C++ native adapters

Start analysis at:

```text
bridge/
drivers/
src/windows/
target/helpers/
build/
```

Map each native adapter to its ABI, DLL or SYS artifact, import library, required privilege, device name, IOCTL, and health signal. Confirm that a service name, binary path, device symbolic link, and userspace endpoint match exactly.

The previously found WFP device-name risk illustrates why this is necessary: service documentation referenced `\\.\AegisWfp` while the userspace contract referenced `\\.\AegisWfpDevice`. Such a mismatch can leave the service running while the provider remains unusable.

### 6.6 TypeScript policy authoring

Start analysis at:

```text
ts_policy/src/
ts_policy/tests/
configs/policies.json
```

Trace policy input, schema validation, compilation, signing, versioning, output artifacts, reload behavior, and rollback. Ensure the policy compiler cannot emit an action or enum that Zig/Rust interpret differently. The signed and loaded policy digest must appear in decision evidence.

### 6.7 Forensic backend

Start analysis at:

```text
src/forensic/
shared/runtime/
tests/forensics/
```

Confirm append ordering, hash-chain or integrity semantics, process-generation behavior, replay, export, failure behavior, and cleanup evidence. A forensic write failure must not be hidden merely because enforcement succeeded.

---

## 7. Frontend and operator development analysis

### 7.1 Mouth

The Rust Mouth component is not an independent security authority. Analyze:

```text
mouth/
rust-src/
scripts/aegis_console*.py
```

The UI should consume structured health, detection results, policy decisions, receipts, and forensic evidence. It should not infer status from free-form logs when a typed field exists.

Required display distinctions include:

```text
OBSERVED
ALERTED
POLICY_BLOCK_REQUESTED
AUTHORIZATION_DENIED
ENFORCEMENT_UNAVAILABLE
ENFORCEMENT_FAILED
BLOCKED_CONFIRMED
ROLLED_BACK
```

The UI must show why a system is degraded. It must not hide WFP unavailability behind a green PEP status. It must show runtime generation and stale-data warnings when the control daemon is unavailable.

### 7.2 Dashboard and operator scripts

Analyze:

```text
aegis_dashboard/
scripts/Dashboard.py
scripts/aegis_console.py
scripts/aegis_console_pro.py
scripts/aegis_status.py
scripts/aegis_metrics.py
```

For every page or command, record its source of truth. A health card must use the health API. An enforcement card must use a validated receipt. A forensic card must use the verification endpoint. A process list may be shown as diagnostics but cannot override daemon state.

### 7.3 Operator control flows

Every mutating operation must include authorization, request ID, state transition, postcondition, audit record, and a safe failure. The UI should disable or clearly gate actions when the runtime is unavailable or the provider is not ready.

A UI button labelled `Block` does not prove that block succeeded. It only creates a request. The confirmation must come from the receipt and host-effect postcondition.

---

## 8. Phase roadmap from initial truth to Production

### Phase 0 — Truth and change control

Regenerate inventory, reference maps, runtime manifest, build manifest, evidence index, and authority maps from current source. Verify every referenced path. Distinguish canonical, support, optional, and legacy files. Never manually edit hashes or manifests when generators exist.

**Exit:** truth verification passes, no stale commit or missing path, generated artifacts match current HEAD.

### Phase 1 — Core live lifecycle

Make the core start reliably, create control and health endpoints, expose degraded reasons, and prevent silent exits. Verify startup paths, DLL resolution, pipe ACLs, worker readiness, and shutdown.

**Exit:** health responds within timeout, runtime starts with degraded dependencies, and no worker blocks shutdown indefinitely.

### Phase 2 — Control and lifecycle convergence

Make Zig the operational authority. Normal CLI and UI lifecycle operations use the versioned control protocol. Force termination remains an emergency path with explicit warning and audit.

**Exit:** normal lifecycle does not rely on process killing; every mutation has authorization and postcondition.

### Phase 3 — Contract and ABI freeze

Freeze CanonicalEvent, IPC event, Policy IR, PEP ABI, health, forensic, control, and receipt contracts. Generate or maintain shared fixtures. Add negative vectors.

**Exit:** Go, Zig, Rust, Python, and TypeScript agree on size, offsets, enums, errors, and malformed-input behavior.

### Phase 4 — Canonical acquisition and data plane

Prove one event from capture to forensic record. Add exactly-once identity semantics, backpressure behavior, rejection counters, and event-generation continuity.

**Exit:** synthetic and benign VMware traffic produce correct event deltas and forensic records without duplicate or non-monotonic identity errors.

### Phase 5 — Detection and policy productization

Unify Cython and Python detection output. Validate rules, policy signatures, duplicate IDs, expiry, revision, scope, and atomic reload. Include policy version and digest in decisions.

**Exit:** invalid or unsigned policy is rejected; valid policy can be loaded and rolled back atomically.

### Phase 6 — Enforcement and fail-closed behavior

Route every enforcement request through Rust PEP. Separate decision, authorization, provider response, receipt, and postcondition. Implement failure and rollback paths.

**Exit:** WFP unavailable never produces success or confirmed block. A real isolated block/unblock proof passes.

### Phase 7 — Adapter and deployment convergence

Build and package Npcap, ETW, FIM, WFP, C++ helpers, Rust DLLs, configuration, signatures, and runtime directories. Verify service names, DLL dependencies, device names, import libraries, and architecture.

**Exit:** clean Windows installation and uninstall are repeatable and truth artifacts are generated.

### Phase 8 — Lifecycle and recovery acceptance

Stop the daemon orderly, wait for old process exit and pipe release, start a new owner, verify new PID/generation, workers, PEP state, forensic integrity, and closed gate.

**Current evidence:** lifecycle proof has passed with a valid new forensic generation while enforcement remained closed.

### Phase 9 — Tier-3 and WFP readiness separation

Ensure Rust PEP/Tier-3 readiness is independent from WFP provider readiness. Report `READY` PEP with `provider_ready=false` when appropriate. Treat artifact presence as diagnostic only.

**Current evidence:** source-level separation and regression coverage are present. Windows host preflight still needs to be executed successfully from a working terminal.

### Phase 10 — VMware isolated lab and host-effect proof

Use VMnet1 host-only network. Keep Kali and the Windows 11 target isolated. First run read-only and observe-only proofs. Only after the exact target and cleanup plan are confirmed may an authorized host-effect proof be run.

**Exit:** target is reachable before block, blocked during proof, reachable after cleanup, receipt and forensic linkage verify, and no stale filter remains.

### Phase 11 — Operator and frontend acceptance

Verify that Mouth, dashboard, CLI, and reports display the same structured truth. Confirm that no UI path reports `BLOCKED` from a decision alone. Test degraded, failed, unavailable, denied, enforced, rolled-back, and stale-runtime states.

**Exit:** operator views are receipt-driven and consistent across interfaces.

### Phase 12 — Release and production acceptance

Rebuild truth artifacts, run clean build and tests, verify package contents and signatures, install on a clean Windows host, execute smoke tests, execute lifecycle recovery, execute isolated enforcement proof, and archive all evidence.

**Exit:** release gate is signed by evidence, not by a source flag or UI status.

---

## 9. Current VMware lab status

The reported Windows host interfaces are:

```text
VMware VMnet1       192.168.126.1/24  host-only candidate
VMware VMnet8       192.168.5.1/24    NAT; exclude from first proof
Wi-Fi               192.168.1.33/24   physical network; exclude from isolated proof
vEthernet Default   172.28.112.1/20   WSL/Hyper-V; exclude from first proof
```

The recommended isolated topology is:

```text
Windows AEGIS host  192.168.126.1
Kali attacker       192.168.126.10
Windows 11 target   192.168.126.20
VMware network       VMnet1 host-only
```

This allocation must be confirmed from the guest operating systems and VMware configuration. The preflight script now validates the expected CIDR and reports whether the lab subnet is found.

The first traffic proof must be benign and observe-only. It should use a disposable test service on the Windows 11 target. NAT, bridged, Wi-Fi, production gateway, real DNS, and unrelated private networks must not be part of the first host-effect proof.

---

## 10. Host production preflight

The current host preflight is read-only. It checks runtime, workers, truth/configuration files, forensic verification, and closed gate. It has bounded health and forensic query timeouts so an unavailable named pipe cannot create an indefinite command hang.

Run it only from a working elevated PowerShell on the Windows host:

```powershell
Set-Location -Path 'D:\NIDs_Windows'

zig build
zig build test
python -m pytest `
  tests\runtime\test_health.py `
  tests\runtime\test_lifecycle_authority.py `
  tests\runtime\test_rust_shield_lifecycle.py `
  -q
```

Start the runtime in one window:

```powershell
zig build run
```

Run the preflight in another elevated window:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_host_production_preflight.ps1' `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

A healthy preflight should report:

```text
runtime_state          = RUNNING
pep_ready              = true
tier3_ready            = true
workers_ready          = true
paths_ready            = true
forensic_verified      = true
host_effect_capable    = false
overall_gate            = false
production_attested    = false
attack_attempted       = false
enforcement_attempted  = false
```

A timeout is a failed preflight, not evidence of readiness.

---

## 11. Test and evidence strategy

### 11.1 Test layers

Use the following order:

1. Pure contract tests for layout, enums, validation, and receipt semantics.
2. Language-level tests for Go, Zig, Rust, Python, Cython, and TypeScript components.
3. Cross-language golden vectors.
4. Runtime integration tests for pipes, queues, lifecycle, and health.
5. Observe-only data-plane proof.
6. PEP decision proof without host effect.
7. Isolated WFP host-effect proof.
8. Cleanup and rollback proof.
9. Lifecycle recovery after enforcement.
10. Clean-install and package acceptance.

A higher layer cannot compensate for a failed lower contract. A successful unit test cannot prove a Windows host effect.

### 11.2 Evidence record for every proof

Every proof artifact should record:

```text
test ID
current commit
source tree or package digest
OS and architecture
runtime generation
command line
configuration/profile
health before
health after
input event identity
policy ID and version
PEP decision
provider response
filter identity
receipt
forensic record identity
cleanup result
rollback result
final gate state
```

Do not manually edit evidence hashes or manifests. Use the project generators and then verify the generated output.

### 11.3 Failure interpretation

A failed proof should identify the first violated postcondition. Do not convert a failure into a warning only to continue the next phase. Keep the enforcement gate closed and preserve logs, health snapshots, and forensic evidence for diagnosis.

---

## 12. Production WFP proof requirements

The WFP proof requires an exact user-confirmed target and cleanup plan because it changes host filtering state. The safe lab sequence is:

```text
precondition: target service is reachable
  -> PEP authorizes exact request
  -> WFP provider creates filter
  -> provider returns filter identity
  -> receipt records the action
  -> Kali verifies target is blocked
  -> forensic linkage verifies
  -> filter is removed
  -> Kali verifies target is reachable again
  -> no stale filter remains
```

The proof must not use the Windows host's primary Wi-Fi address, the VMware gateway, a production service, localhost, or an unconfirmed private address. It must use the disposable Windows 11 target in the isolated VMnet after reachability and capture have been proven.

The proof must fail closed when:

```text
PEP is unavailable
WFP is unavailable
provider response is ambiguous
filter identity is missing
host postcondition is not observed
receipt is invalid
cleanup fails
forensic linkage fails
```

Only after the complete proof passes may `host_effect_capable` become true for that tested provider state. Even then, production acceptance still requires package, lifecycle, operator, rollback, and clean-host verification.

---

## 13. Backend and frontend completion checklist

### Backend

- [ ] Zig runtime is the single lifecycle owner.
- [ ] All workers have readiness and bounded shutdown behavior.
- [ ] Control pipe authorization derives from Windows token/elevation correctly.
- [ ] Health does not use stale PID fallback as runtime truth.
- [ ] CanonicalEvent and IPC event conversions are explicit.
- [ ] Cross-restart producer identity is stable and tested.
- [ ] Go Nose emits only canonical ingress data.
- [ ] Cython and Python detection results are semantically identical.
- [ ] Policy compiler, validator, signer, and loader agree on enums and versions.
- [ ] Rust PEP is the only privileged enforcement authority.
- [ ] WFP device/service/IOCTL names are consistent.
- [ ] EnforcementReceipt is required for confirmed block.
- [ ] Forensic records link input, decision, receipt, provider, and cleanup.
- [ ] Replay and integrity verification work on a new process generation.
- [ ] Build, package, install, uninstall, and rollback are reproducible.

### Frontend and operator surfaces

- [ ] Mouth consumes structured health and receipts.
- [ ] Dashboard does not calculate enforcement truth from logs.
- [ ] `DEGRADED`, `FAILED`, `UNAVAILABLE`, `DENIED`, `ENFORCED`, and `ROLLED_BACK` are distinct.
- [ ] UI displays provider unavailability without claiming a block.
- [ ] UI shows receipt identity and forensic linkage.
- [ ] UI warns when the control daemon is unavailable.
- [ ] UI actions use versioned control requests and show postconditions.
- [ ] Operator reports include exact command, environment, and evidence links.
- [ ] No normal UI path kills processes or edits generated manifests.

---

## 14. Instructions for a second Manus agent

The next agent should begin by reading this report and then inspect the current source. It must not assume historical reports are current truth. The current source, build graph, live daemon health, and fresh generated artifacts have priority.

The agent should work in this order:

1. Check git status and identify source changes without modifying unrelated work.
2. Read the current build graph and runtime entrypoint.
3. Read the contract files before changing implementation.
4. Trace one selected flow end-to-end rather than editing many unrelated components.
5. Add or update a focused test before changing behavior.
6. Preserve authority boundaries.
7. Run the narrowest relevant test locally.
8. Request Windows-side commands when Zig, WFP, Npcap, or elevated service state cannot be verified in the sandbox.
9. Record evidence in a dated report.
10. Never declare Production-ready until host-effect, cleanup, lifecycle recovery, and package acceptance all pass.

When a result is unavailable, report it as unavailable. Do not infer it from a file existing, a DLL loading, or a UI label.

---

## 15. Current status summary

| Area | Current status | Interpretation |
|---|---|---|
| Architecture baseline | Established | Current source must remain authoritative |
| Canonical ingress path | Observe-only evidence passed | Does not prove WFP effect |
| Lifecycle recovery | Passed in prior Windows evidence | Must be rerun after material changes |
| Tier-3/PEP separation | Implemented and tested at source level | Provider readiness remains separate |
| VMware lab | Kali and Windows 11 prepared | Use VMnet1 host-only first |
| Host production preflight | Prepared with bounded timeouts | Must be executed from working elevated PowerShell |
| WFP provider | Not fully attested | Requires Windows service/device evidence |
| Host-effect proof | Not executed | Requires exact confirmed payload |
| Overall enforcement gate | Closed | Correct current state |
| Production-ready claim | Not allowed | Missing host-effect and release evidence |

---

## 16. Final production definition

For this project, Production-ready means more than “the program builds” and more than “the UI is running.” It means that a clean Windows installation can start the runtime, expose truthful health, capture supported interfaces, process canonical events, run validated policy, authorize privileged actions through Rust PEP, apply host effect through WFP, produce a verifiable receipt, retain forensic evidence, roll back the effect, recover after restart, and present the same truth consistently in CLI, dashboard, and Mouth.

The final claim must be supported by reproducible artifacts. If WFP cannot be loaded or the host effect cannot be observed, the correct product state is a safe degraded/alert-only deployment, not Production-ready IPS.

## References

[1]: https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page "Microsoft Windows Filtering Platform documentation"

[2]: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea "Microsoft CreateFile documentation"

[3]: https://docs.vmware.com/ "VMware documentation"
