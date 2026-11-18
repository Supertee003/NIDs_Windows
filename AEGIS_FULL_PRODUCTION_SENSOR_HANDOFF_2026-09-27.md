# AEGIS Full Production and Victim Sensor Handoff

**Project:** AEGIS Windows-native NIDS with Rust PEP/WFP enforcement capability  
**Date:** 2026-09-27  
**Status:** Advanced pre-production; runtime readiness exists, but live network ingress and real host-effect proof are not complete  
**Purpose:** Give the next developer or Manus agent a complete architectural, recovery, development, validation, packaging, and Victim-installation plan.

---

## 1. Executive decision

AEGIS should continue as a **host-based, kernel-assisted NIDS with optional local WFP enforcement**, not as a transparent inline network IPS.

The current VMware topology is suitable for development and proof:

```text
Kali attacker 192.168.126.10
        |
        | VMware VMnet1 host-only network
        |
AEGIS NIDS host 192.168.126.1
        |
Victim VM 192.168.126.20
```

The AEGIS host can observe traffic that reaches its own Npcap adapter. It cannot automatically observe all traffic between Kali and a separate Victim merely because both systems exist on the same host-only network. To protect the Victim, the sensor must be installed on the Victim, traffic must traverse the sensor's interface, or the lab must be redesigned as an inline/bridge/TAP/SPAN topology.

The selected product direction is therefore:

> **Install the AEGIS sensor on the Victim for local detection and optional local WFP enforcement; keep the central AEGIS runtime/NIDS host for development, correlation, evidence, and operator control.**

This avoids claiming that a host-only observer can protect a different VM's traffic when the packets do not traverse the observer.

---

## 2. Current status and honest boundary

### 2.1 What is validated

- Zig runtime source and build are available.
- Rust PEP is the sole intended enforcement authority.
- WFP driver/service has been installed and previously observed running.
- Administrator lifecycle recovery proof passed.
- WFP read-only preflight passed with PEP/provider/host-effect capability true.
- Rust dashboard unit test passed and release build succeeded.
- Python security/runtime regression passed with `267 passed` in the latest recorded run.
- Go Nose source compile blocker in `nose/model.go` was fixed.
- Go Nose `go test ./...` passed after that fix.
- Fresh `dist\\nose_dashboard.exe` was built from current source.
- Go Nose selected VMware VMnet1 Npcap device and connected to `\\.\pipe\aegis_nose`.
- The control plane returned live health, metrics, snapshot, and authority responses.

### 2.2 What is not validated yet

- A real Kali packet has not yet been proven to produce a non-zero Nose capture/frame counter in the latest evidence.
- `nose_frames_read` and `nose_frames_submitted` were still zero in the latest attached result.
- No current-head real enforcement request has been sent after the WFP direction semantic finding.
- No receipt has been validated with real host-effect confirmation.
- No victim-installed sensor package has been produced and installed.
- No production signing/trust chain has been established; existing test signing is not production trust.
- No final release hash manifest has been frozen after all current source changes.

The attached health result with `nose_connected=true` is a readiness result, not a complete NIDS proof:

```text
nose_connected=true
nose_frames_read=0
nose_frames_submitted=0
packets_captured=0
blocks=0
```

---

## 3. Architecture and authority map

### 3.1 Data plane

```text
Npcap adapter
  -> Go Nose capture
  -> packet decode
  -> CanonicalEvent v1
  -> 4-byte little-endian length + 109-byte payload
  -> \\.\pipe\aegis_nose
  -> Zig Nose pipe reader
  -> canonical validation
  -> event fabric / queue
  -> detection engine
  -> correlation/context
  -> policy evaluation
  -> forensic append
```

The expected wire frame is:

```text
4-byte LE length prefix (109)
+ 109-byte CanonicalEvent payload
= 113 bytes total
```

### 3.2 Control and enforcement plane

```text
CLI / dashboard / operator request
  -> control named pipe
  -> Zig handler registry
  -> request validation
  -> Rust PEP
  -> WFP provider/driver
  -> provider read-back
  -> EnforcementReceipt
  -> forensic linkage
  -> dashboard/Mouth display
```

### 3.3 Authority rules

| Component | May do | Must never do |
|---|---|---|
| Go Nose | Capture, decode, serialize, deliver | Decide or enforce blocks |
| Zig core | Runtime ownership, queue, orchestration, detection routing, control boundary | Bypass Rust PEP for privileged mutation |
| Python/Cython brain | Deep inspection, enrichment, request generation | Call WFP/netsh or claim block |
| TypeScript policy | Author, validate, sign, version policy | Mutate host filtering state |
| Rust PEP | Final authorization and receipt authority | Claim host effect without provider/read-back proof |
| WFP driver | Apply provider-level host effect | Become policy authority |
| Dashboard/Mouth | Display authoritative state | Infer block from logs or intent |
| CLI/PowerShell | Diagnostics and authorized requests | Become a second runtime owner |

The central invariant is:

```text
Detection != policy decision
Policy decision != PEP authorization
PEP authorization != WFP effect
WFP response != verified postcondition
Valid EnforcementReceipt == only accepted host-block claim
```

---

## 4. Product model: central host plus Victim sensor

### 4.1 Recommended deployment modes

#### Mode A — Victim-local sensor, recommended

Install the AEGIS sensor on the Windows Victim. It captures traffic on the Victim's own interfaces and can enforce local WFP policy. The central NIDS host receives telemetry and evidence through an authenticated control/telemetry channel when that integration is implemented.

Advantages:

- observes traffic that actually reaches the Victim;
- can block at the Victim's local host boundary;
- does not require VMware bridging or a transparent network appliance;
- maps directly to the current WFP design.

#### Mode B — Separate passive observer

Keep AEGIS on `192.168.126.1` and mirror traffic to it through SPAN/TAP or a VMware network design that sends a copy of relevant traffic to the observer. This is detection-only unless the observer is also inline or has a coordinated enforcement path on the protected host.

#### Mode C — Inline gateway/bridge

Place AEGIS between attacker and Victim, or use a transparent bridge with the sensor in the forwarding path. This is a different product architecture and should not be claimed from the current host-local WFP implementation.

### 4.2 Scope of the current project

The current project is best described as:

> **Windows-native host NIDS with kernel-assisted telemetry and receipt-driven local WFP enforcement, with a Go/Npcap acquisition front end and a Rust PEP authority.**

It is not yet:

- a full L2-L7 inline IPS;
- a transparent network firewall;
- a universal SPAN/TAP collector;
- a decryption engine;
- a guaranteed detector of traffic that never reaches the sensor host.

---

## 5. Recovery-to-normal plan

Execute the separate recovery document first:

[Recovery Handoff — Return to Normal](AEGIS_RECOVERY_HANDOFF_RETURN_TO_NORMAL_2026-09-27.md)

The recovery sequence is:

```text
Stop stale owners
  -> start one elevated Zig core
  -> verify health and WFP readiness
  -> start one fresh Go Nose on VMnet1
  -> generate Kali lab traffic
  -> verify non-zero captured/read/submitted frames
  -> verify forensic integrity
  -> only then begin enforcement proof
```

The normal-state gate must contain one evidence set in which:

```text
runtime_state=RUNNING
state=RUNNING
degraded=false
pep_ready=true
provider_ready=true
host_effect_capable=true
workers_ready=true
nose_connected=true
nose_frames_read>0
nose_frames_submitted>0
nose_frames_rejected=0
nose_pipe_errors=0
```

---

## 6. Development phases to production

### Phase 0 — Repository and build authority

1. Identify the active runtime entrypoint from `build.zig`, `src/main.zig`, and `src/daemon.zig`.
2. Identify the active Go Nose artifact from `nose/main.go`, not from an arbitrary stale executable.
3. Remove or clearly label historical binaries and duplicate PEP/shield paths.
4. Freeze one build output directory and one artifact manifest.
5. Record source commit, compiler versions, WDK version, Rust toolchain, Go version, Python version, and policy version.
6. Require all release builds to write a machine-readable manifest with SHA-256 hashes.

Acceptance:

```text
A clean checkout can rebuild the core, PEP DLL, driver, Nose, dashboard, and optional Mouth from documented commands.
```

### Phase 1 — Runtime truth and lifecycle

1. Keep Zig as the only runtime owner.
2. Ensure every worker has a readiness flag and failure reason.
3. Distinguish `runtime_state`, dependency state, worker readiness, and external process state.
4. Expose `nose_connected` separately from `nose_reader_ready`.
5. Expose Go Nose process health separately from core reader health.
6. Make control-pipe retry bounded and fail closed.
7. Prove orderly stop, join, pipe release, restart, and new process generation.
8. Ensure a stale PID/log cannot promote a stopped system to `RUNNING`.
9. Ensure a non-elevated daemon reports WFP unavailable rather than pretending it is ready.

Acceptance:

- lifecycle recovery proof passes;
- all workers join;
- no duplicate control-pipe owner remains;
- forensic generation integrity is verified after restart;
- health output is authoritative and internally consistent.

### Phase 2 — Canonical Nose data plane

1. Freeze the CanonicalEvent schema and wire fixture.
2. Verify Go field offsets and Zig field offsets.
3. Verify length prefix, payload size, endianness, enum values, timestamp meaning, and hash semantics.
4. Test short writes and short reads.
5. Test client disconnect/reconnect.
6. Test duplicate event IDs and non-monotonic IDs.
7. Define producer generation/epoch semantics for restart.
8. Add a live capture acceptance test using VMware VMnet1.
9. Keep Go Nose acquisition-only.
10. Prevent direct Zig Npcap capture from running concurrently with Go Nose.

Acceptance:

```text
Kali traffic -> Npcap -> Go Nose -> pipe -> Zig -> queue
```

must produce a non-zero, correctly validated frame count with no rejected frames or duplicate identities.

### Phase 3 — Detection and brain integration

1. Confirm Python and Cython return the same typed `DetectionResult`.
2. Test binary payloads, embedded NULs, truncation, invalid encoding, oversized payloads, and regex timeout.
3. Keep detection separate from policy and enforcement.
4. Route all enforcement requests through the control/PEP path.
5. Do not let Nose or brain call WFP.
6. Add detection evidence with event ID, rule ID, policy version, confidence, and trace identity.
7. Confirm the frontend differentiates `DETECTED`, `ALERTED`, `PEP_REJECTED`, and `ENFORCED`.

Acceptance:

- a real or controlled event is detected;
- the event is linked to forensic evidence;
- no detector can mutate host state;
- PEP remains the only privileged authority.

### Phase 4 — PEP/WFP closure

1. Freeze the request ABI across Zig, Rust, and C.
2. Validate exact IP, port, protocol, direction, policy ID, request ID, event ID, trace ID, and audit ID.
3. Add provider read-back.
4. Create a complete receipt only after read-back confirms the filter.
5. Use the receipt's `filter_id` for cleanup.
6. Reject stale, duplicated, malformed, unsigned, expired, or scope-invalid requests.
7. Make provider-unavailable state fail closed.
8. Add idempotency behavior for retries.
9. Correct the direction semantic before inbound proof.

Important unresolved issue:

> The current WFP implementation uses `FWPM_LAYER_ALE_AUTH_CONNECT_V4` with remote address/port conditions. That is an outbound-connect semantic. It does not inherently prove that Kali inbound traffic to a Victim listener is blocked. The inbound proof requires `ALE_AUTH_RECV_ACCEPT_V4` or an explicitly documented outbound proof.

Acceptance:

```text
request -> PEP authorization -> direction-correct WFP filter
-> provider read-back -> valid receipt -> observed reachability change
-> forensic linkage -> exact rollback
```

### Phase 5 — Frontend and operator surfaces

1. Make dashboard a read-through client of `health`, `metrics`, `snapshot`, forensic verification, and receipt state.
2. Never create authoritative state in the UI.
3. Never call WFP or firewall APIs from the UI.
4. Display stale/reconnecting/degraded states.
5. Display live Nose counters and capture adapter identity.
6. Show receipt IDs and forensic links for confirmed blocks.
7. Show `HOST_EFFECT_CONFIRMED` only after receipt validation.
8. Make Mouth receipt-driven as well.
9. Add operator actions only after backend contract tests pass.

Acceptance:

A stopped, degraded, disconnected, or unverified backend must be visibly represented as such.

### Phase 6 — Victim sensor productization

1. Define sensor package contents.
2. Separate sensor-only runtime from central operator/dashboard components.
3. Give the sensor a local control plane and optional authenticated telemetry channel.
4. Install the WFP driver with a real signing/trust plan.
5. Register a Windows service with least privilege and controlled recovery.
6. Capture the Victim's actual network adapters.
7. Bind local WFP filters to the correct direction and local/remote tuple semantics.
8. Add health reporting for service, driver, PEP, WFP provider, Nose, queue, and policy trust.
9. Add uninstall and rollback that remove filters, service state, driver state, and temporary files.
10. Produce a signed installer or documented administrator deployment procedure.

Acceptance:

A fresh Victim can be installed, started, health-checked, tested, rolled back, and uninstalled without manual source-tree assumptions.

---

## 7. WFP host-effect proof plan

### 7.1 Preconditions

Do not begin until:

- Administrator runtime health is `RUNNING`;
- PEP/provider/host-effect readiness is true;
- Go Nose live ingress has produced frames;
- target service is disposable and isolated;
- WFP direction semantics are correct for the chosen test;
- a baseline connection succeeds.

### 7.2 Inbound Victim proof

For the selected topology:

```text
Kali 192.168.126.10 -> Victim 192.168.126.20:8080
```

The Victim must run a known disposable listener. Record:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen
```

From Kali:

```bash
curl --connect-timeout 3 http://192.168.126.20:8080/
```

The baseline must succeed before enforcement.

The enforcement request must explicitly identify:

```text
remote/source address: 192.168.126.10
local/destination address: 192.168.126.20
protocol: TCP
port: 8080
direction: inbound
TTL: disposable, for example 30 seconds
policy identity/version
request/event/trace/audit identities
```

The WFP provider must use a receive-accept/inbound-compatible layer or a proven equivalent. A successful API response at an outbound layer is not sufficient.

### 7.3 Required receipt

A valid host-block receipt requires all relevant fields, including:

```text
status = ENFORCED
host_effect_confirmed = true
filter_id != 0
request_id != 0
event_id != 0
trace_id != 0
audit_id != 0
policy identity/version valid
direction valid
provider read-back successful
forensic linkage verified
```

### 7.4 Required postconditions

1. Connection succeeds before block.
2. Request is accepted by Rust PEP.
3. WFP provider read-back finds the filter.
4. Receipt is complete and authenticated.
5. Connection fails or times out during the TTL.
6. Forensic record links event, decision, receipt, filter, and trace.
7. Cleanup removes the exact `filter_id`.
8. Post-cleanup connection succeeds again.
9. No stale filter remains.
10. Metrics and dashboard show the result from the receipt, not from a guessed counter.

### 7.5 Failure interpretation

| Result | Meaning |
|---|---|
| PEP rejects | Authorization or contract failure; no host effect expected |
| Provider unavailable | Fail closed; no block claim |
| Receipt pending/failed | No confirmed block |
| Filter exists but reachability unchanged | Host-effect proof failed or tuple/direction wrong |
| Reachability changes but no complete receipt | Evidence integrity failure; do not claim production success |
| Cleanup fails | Production gate fails; remove stale state before retry |

---

## 8. Victim sensor installation design

### 8.1 Proposed sensor package

```text
AEGIS-Sensor-Victim-x64/
  installer/
    install_sensor.ps1
    uninstall_sensor.ps1
    repair_sensor.ps1
  bin/
    aegis_nids.exe
    nose_dashboard.exe or aegis_sensor.exe
    aegis_pep.dll
    aegis_wfp.sys
    sensor_health.exe
  config/
    sensor.json
    policies.json
    Rules.json
    trust-store/
  contracts/
    canonical_event.schema.json
    enforcement_receipt.schema.json
    health.schema.json
  scripts/
    preflight.ps1
    smoke_test.ps1
    rollback.ps1
  manifests/
    release.json
    hashes.sha256
    signer.json
  logs/
```

The final product should use a dedicated sensor binary name rather than exposing the development dashboard binary as the production sensor. The sensor may reuse the Go capture library, but its runtime mode must be headless and service-oriented.

### 8.2 Victim installation preflight

Before installation:

```powershell
$ErrorActionPreference='Stop'
whoami /groups | Select-String 'Administrators'
Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption,Version,OSArchitecture
Get-Service npcap -ErrorAction SilentlyContinue
Get-NetAdapter | Where-Object Status -eq 'Up' |
  Select-Object Name,InterfaceDescription,Status
```

Verify:

- Windows x64 supported;
- Administrator installation token;
- Npcap installed in the required mode;
- at least one intended network adapter is up;
- no conflicting old AEGIS service or WFP filter exists;
- disk/log directories are available;
- policy/trust artifacts match the release manifest;
- driver signing/trust requirements are satisfied.

### 8.3 Sensor startup order

```text
Driver/service prerequisite
  -> local runtime owner
  -> PEP capability check
  -> WFP provider check
  -> Nose/Npcap capture
  -> local control pipe
  -> health READY
  -> telemetry channel to central host (optional)
```

The sensor must not start in enforcement mode if PEP, policy trust, WFP provider, or receipt persistence is unavailable. It may start in observe-only mode only if the operator explicitly sees that mode in health.

### 8.4 Victim-local health contract

The Victim sensor health must report:

```text
installation_version
runtime_generation
runtime_state
service_state
policy_version
policy_signature_valid
pep_ready
provider_ready
host_effect_capable
nose_reader_ready
nose_connected
capture_adapter
frames_read
frames_submitted
frames_rejected
pipe_errors
duplicate_event_ids
non_monotonic_event_ids
forensic_integrity
last_event_time
last_receipt_time
```

### 8.5 Sensor uninstall/rollback

Uninstall must:

1. disable enforcement requests;
2. remove active filters by validated receipt/filter ID;
3. verify no active AEGIS filters remain;
4. stop the sensor service and join workers;
5. release control and Nose pipes;
6. remove the driver service only if this package owns it;
7. preserve or export forensic evidence according to retention policy;
8. remove temporary logs/config only after export policy is satisfied;
9. record uninstall result.

---

## 9. Testing strategy

### 9.1 Unit and contract tests

Run per language:

```powershell
zig build
zig build test
cargo test --manifest-path Cargo.toml
cargo test --manifest-path aegis_dashboard\Cargo.toml
Set-Location nose
 go test ./...
Set-Location ..
python -m pytest tests/security tests/runtime -q --disable-warnings
```

Add/retain tests for:

- health schema and state transitions;
- receipt validation and stale receipt rejection;
- policy signature/version/expiry;
- canonical event serialization;
- 109-byte payload and 113-byte frame;
- partial pipe reads/writes;
- duplicate and non-monotonic IDs;
- provider unavailable fail-closed behavior;
- WFP direction and local/remote tuple semantics;
- lifecycle stop/restart;
- dashboard severity normalization;
- brain version and startup behavior;
- Nose adapter selection.

### 9.2 Integration tests

#### Ingress integration

```text
fixture or live packet
 -> Go serializer
 -> named pipe
 -> Zig reader
 -> event fabric
 -> metrics/forensics
```

#### Detection integration

```text
known lab pattern
 -> Nose event
 -> detection result
 -> policy decision
 -> forensic event
```

#### Enforcement integration

```text
approved request
 -> Rust PEP
 -> WFP provider
 -> read-back
 -> receipt
 -> reachability change
 -> rollback
```

### 9.3 Host lab tests

Maintain separate profiles:

- `observe_only_ingress`
- `victim_local_detection`
- `inbound_wfp_block`
- `outbound_wfp_block`
- `rollback_and_recovery`
- `provider_unavailable_fail_closed`
- `stale_receipt_rejection`

Never merge evidence from different profiles into one claim.

### 9.4 Attack validation boundaries

Only test systems owned and isolated by the project owner. Use bounded reconnaissance and disposable services. Record source/destination, time, interface, command, expected result, actual result, and evidence path. Do not turn an uncontrolled attack into a production gate.

---

## 10. Release and evidence requirements

Every release candidate must include:

```text
source commit
compiler/toolchain versions
OS/WDK version
policy version and signature
artifact SHA-256 manifest
driver SHA-256
PEP DLL SHA-256
core SHA-256
Nose/sensor SHA-256
dashboard SHA-256
install/uninstall transcript
unit/integration test summary
lifecycle proof
Nose ingress proof
WFP host-effect proof
rollback proof
forensic verification
known limitations
```

Evidence must be timestamped and immutable enough to distinguish:

- stale evidence;
- synthetic observe-only evidence;
- readiness evidence;
- live packet evidence;
- real host-effect evidence.

Recommended evidence naming:

```text
admin-evidence/
  release-<version>-hashes.json
  gate-runtime-health.json
  gate-lifecycle-recovery.json
  gate-nose-live-ingress.json
  gate-detection.json
  gate-wfp-inbound-block.json
  gate-wfp-rollback.json
  gate-forensic-verify.json
```

---

## 11. Definition of Production Complete

AEGIS is production-complete for the current product scope only when:

1. A clean build reproduces all required artifacts.
2. One runtime owner controls lifecycle and health.
3. The Victim sensor installs and uninstalls reproducibly.
4. Go Nose captures the Victim's real interface.
5. Canonical events pass across the pipe with no contract errors.
6. Detection and policy evidence are linked.
7. Rust PEP is the only enforcement authority.
8. WFP direction semantics match the claimed traffic direction.
9. Provider read-back confirms the filter.
10. The complete receipt validates.
11. Traffic behavior changes on the intended host and tuple.
12. Cleanup uses the exact receipt/filter identity.
13. Traffic recovers after rollback.
14. Provider or policy failure fails closed.
15. Dashboard and Mouth display only receipt-driven host effect.
16. Lifecycle recovery passes after enforcement cleanup.
17. Release hashes, signatures, and evidence are frozen.
18. Known limitations are documented honestly.

Until these are complete, the correct label remains:

> **Advanced pre-production / enforcement-ready, not fully production-attested.**

---

## 12. Recommended next-session order

The next developer should not start with new kernel detection features. Use this order:

```text
1. Complete recovery-to-normal handoff.
2. Generate real Kali traffic and obtain non-zero Nose frame counters.
3. Fix any adapter, VMnet, pipe, or canonical-frame defect.
4. Add a health distinction between Nose reader readiness and external Nose process health.
5. Rebuild and hash all current artifacts.
6. Audit/fix inbound WFP direction semantics.
7. Run baseline -> block -> read-back -> receipt -> reachability -> rollback proof.
8. Complete lifecycle recovery after rollback.
9. Package sensor-only Victim build.
10. Install on Victim VM and repeat local sensor proof.
11. Harden dashboard/Mouth against stale/unverified state.
12. Freeze production release evidence.
13. Only then consider kernel-assisted detection expansion.
```

The next agent must preserve the central principle:

> **Backend truth and evidence quality are more important than adding features.**
