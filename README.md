# AEGIS NIDS for Windows

AEGIS is a production-oriented Windows-native network intrusion detection and response platform. It combines kernel-assisted network telemetry, host telemetry, rule matching, policy evaluation, operator control, and forensic evidence in one supervised runtime.

> **Release status:** The repository is maintained with production-grade contracts, authority boundaries, runbooks, and acceptance gates. The current release is approved for development, qualification, and observe-only operation. Production IPS blocking remains **not accepted** until the isolated Windows host-effect proof, receipt validation, cleanup, signing, rollback, and recovery gates are complete.

This README is the official entry point for developers, reviewers, lab operators, and release operators. It describes the production reference architecture, the current verified path, the required deployment controls, and the acceptance evidence needed before an IPS release can be promoted. It distinguishes source implementation from active runtime capability and from production acceptance.

## What AEGIS does

The current runtime is designed around explicit authority boundaries:

```text
Network / host activity
        |
        +--> WFP, ETW, FIM, Registry and Go Nose sensors
        |
        +--> Zig daemon and canonical event pipeline
        |
        +--> Detection, correlation and Rule-22 qualification
        |
        +--> Policy decision
        |
        +--> Rust PEP authority
        |
        +--> WFP host effect provider
        |
        +--> Forensic record, audit trail and operator views
```

The Zig daemon is the runtime owner. Rust PEP is the only component allowed to authorize privileged enforcement. The user-mode WFP adapter and kernel WFP callout are effect-provider layers; their low-level IOCTL functions must be reached only through the authorized runtime path and must not be called directly by Python, Go, TypeScript, dashboards, or detection code. Those components may observe, analyze, request, or display state, but they must not independently mutate Windows filtering state.

A policy action named `BLOCK` is not evidence that a host block occurred. A confirmed block requires a valid `EnforcementReceipt` with a verified host postcondition.

## How to read the architecture

The architecture is easiest to understand as a sequence of **observation, normalization, detection, decision, authorization, effect, evidence, and presentation**. Each stage has one responsibility and a strict boundary. A later stage may reject an earlier result; it may not silently upgrade an earlier result.

### End-to-end event lifecycle

```text
1. Observe
   WFP / ETW / FIM / Registry / Go Nose observe activity
          |
2. Normalize
   Convert source-specific data into CanonicalEvent or IpcEvent
          |
3. Ingest
   Zig daemon assigns runtime context, queues the event, and applies backpressure
          |
4. Detect
   Rule engine and Brain produce evidence, rule ID, confidence, and severity
          |
5. Correlate
   Events are related to flows, files, processes, hosts, sessions, or incidents
          |
6. Decide
   Policy authority maps evidence to ALLOW, ALERT, ESCALATE, or BLOCK_REQUESTED
          |
7. Authorize
   Rust PEP validates capability, policy, target, expiry, and request freshness
          |
8. Apply effect
   WFP may apply a reversible host effect only when the prevention gate is open
          |
9. Verify
   The runtime checks the host postcondition and creates EnforcementReceipt v1
          |
10. Remember and present
    Forensic/audit records are written; CLI and dashboards display the result
```

The current supported path stops safely after steps 1–6 for observe-only operation. Steps 7–9 are present as guarded enforcement boundaries, but the prevention gate remains closed until the isolated WFP proof is accepted.

### What each layer is allowed to claim

| Layer | It may claim | It must not claim |
|---|---|---|
| Sensor | Activity was observed or a notification was received | The activity was malicious or blocked |
| Normalizer | A valid canonical event was produced | That a policy decision was authorized |
| Detector | A rule matched and evidence was produced | That the host was changed |
| Policy | An intended action was selected | That WFP applied the action |
| Rust PEP | The request was authorized, denied, or unavailable | A host effect without provider evidence |
| WFP provider | A filter operation was attempted or returned | A verified postcondition without read-back/verification |
| Forensics | What the system observed and decided | A failed action was successful |
| CLI/dashboard | What the authoritative backend attested | A `BLOCK` label is a confirmed block |

### Network event paths

AEGIS has two network observation paths. They are related at the pipeline and evidence layers, but they are not the same transport and must not be represented as one chain.

The **packet-ingress path** is:

```text
Packet on a selected Windows interface
  -> Npcap capture
  -> Go Nose decode and event serialization
  -> 4-byte frame length + CanonicalEvent payload
  -> \\.\pipe\aegis_nose
  -> Zig Nose reader and event queue
  -> rule matching, correlation, and forensic append
  -> policy decision and optional guarded PEP request
```

The **kernel WFP telemetry path** is:

```text
Network activity at a WFP classification layer
  -> WFP kernel callout
  -> kernel ring buffer
  -> \\.\AegisWfpDevice
  -> read-only IOCTL event readback
  -> Zig/user-mode WFP adapter
  -> canonical pipeline and forensic append
```

The Go component is an ingress sensor. It does not own policy and does not call WFP. The WFP driver is a kernel telemetry provider and is not the policy authority. The Zig daemon owns the receiving paths, runtime state, event correlation, and control boundary. Rust PEP is the only component allowed to authorize a privileged host effect. This separation prevents a capture component or low-level adapter from becoming an unreviewed enforcement authority.

### FIM event path

For file integrity monitoring, the path is:

```text
File change under the configured watch root
  -> ReadDirectoryChangesW in the native helper
  -> FILE_NOTIFY_INFORMATION record
  -> Zig normalization of action, relative path, and timestamp
  -> IpcEvent with bounded path payload
  -> Rule-22 matching and forensic record
  -> operator display
```

The `AEGIS_FIM_PROOF_ROOT` environment variable selects a disposable directory for testing. It is intentionally opt-in so that a proof does not mutate or monitor Windows system directories unnecessarily.

### Enforcement lifecycle

The enforcement path has four different meanings that must not be collapsed:

```text
PolicyDecision
  != PEP authorization
  != WFP provider response
  != verified host postcondition
```

Only the final state may be displayed as `BLOCKED_CONFIRMED`, and only when `EnforcementReceipt v1` validates. A receipt is valid for a confirmed block only when it contains a non-zero request ID, event ID, trace ID, audit ID, and filter ID; identifies the provider; reports `status=enforced`; and sets `host_effect_confirmed=true`.

If a dependency is missing, the system reports `DEGRADED`, `ENFORCEMENT_UNAVAILABLE`, or `ENFORCEMENT_FAILED`. It must not convert that condition into `ALLOW` or into a false success message. Cleanup is a separate operation and must verify removal of the exact filter recorded in the receipt.

### Runtime and control lifecycle

The Zig daemon is the single runtime owner:

```text
Operator command
  -> authenticated control pipe
  -> Zig handler registry
  -> daemon-owned state transition
  -> worker readiness or failure
  -> authoritative health response
  -> audit record
```

The CLI and dashboards are clients of this control plane. They do not start a second worker set, decide runtime health from a stale PID, or bypass the daemon to mutate WFP. A process scan may help diagnose a problem, but it is not runtime truth when the control endpoint is unavailable.

### How to investigate one incident

An operator should follow one identifier chain rather than reading isolated log lines:

```text
event_id
  -> rule_id and detection evidence
  -> incident/correlation context
  -> policy decision
  -> request_id and trace_id
  -> PEP/provider result
  -> filter_id and host postcondition
  -> audit_id and forensic record
```

If any link is missing, the incident may still be useful as detection evidence, but it must not be presented as a confirmed enforcement event. This identifier chain is also the basis for replay, cleanup, and post-incident review.

### The five-question model: who, what, where, how, and why

Every AEGIS event should be understandable through the same operational questions. The questions are not a replacement for the event contract; they are a practical way to read the contract and the evidence together.

| Question | What the operator must be able to answer | AEGIS evidence |
|---|---|---|
| **Who?** | Which sensor, process, runtime generation, policy authority, or operator produced or handled the record? | `source`, producer identity, process ID, runtime generation, operator role, signer/provider identity |
| **What?** | What activity was observed, which rule matched, and which decision was produced? | event type, payload metadata, `rule_id`, detection evidence, severity, policy decision |
| **Where?** | Which host, interface, file path, flow, process, pipe, or target was involved? | source/destination IP and port, interface, FIM path, process identity, target, filter scope |
| **How?** | Which sensor and contract carried the event, and which components transformed or authorized it? | sensor path, CanonicalEvent/IpcEvent version, pipe, policy version, PEP result, provider result |
| **When?** | When was the activity observed, processed, decided, applied, verified, or cleaned up? | event timestamp, monotonic timestamp, request timestamp, audit timestamp, postcondition and cleanup time |
| **Why?** | Why did the system classify, escalate, allow, reject, defer, or fail the action? | rule reason, confidence, policy reason, denial/unavailable code, receipt reason, failure evidence |

For example, a complete observe-only network record should answer the following in one investigation:

```text
Who?
  Go Nose observed the packet; the Zig daemon owned ingestion; no privileged
  enforcement authority was invoked.

What?
  A TCP connection was observed and Rule Rxxxx produced detection evidence.

Where?
  The event came from 192.168.126.10 and targeted the selected Windows
  interface or destination 192.168.126.20:49152.

How?
  WFP/Npcap observation was normalized into a canonical event and delivered
  through the AEGIS ingress path to the rule engine and forensic ring.

When?
  The event, processing, audit, and forensic timestamps identify the order of
  observation and handling.

Why?
  The rule matched its configured evidence. The result remains OBSERVED or
  ALERT because the prevention gate is closed and no host effect was verified.
```

A complete FIM record follows the same model. It identifies the FIM helper and Zig worker as the actors, the file action as the activity, the proof root and relative file path as the location, `ReadDirectoryChangesW` and the normalization contract as the method, and the timestamp chain as the chronology. The rule reason explains why the event was qualified. It must still remain an observation until a separate, authorized, and verified enforcement path exists.

The **why** field is especially important for failure handling. A record that says only `BLOCK` is incomplete. A useful record says whether the system observed a rule match, selected a policy action, denied the request, found the provider unavailable, applied a filter, verified the host postcondition, or cleaned up the exact filter. This prevents operators and downstream systems from confusing intent with effect.

## Supported operating modes

| Mode | Purpose | Host mutation |
|---|---|---:|
| **Synthetic qualification** | Verify rule definitions against deterministic fixtures | No |
| **Observe-only** | Observe WFP, FIM, ETW, and ingress events on a real Windows host | No |
| **Degraded detection** | Continue safe telemetry when an optional or privileged dependency is unavailable | No |
| **Controlled IPS proof** | Isolated lab validation of a reversible WFP effect | Not enabled by default |
| **Production IPS** | Future release target | **Not yet accepted** |

Do not use the current repository as a production blocking appliance. The prevention gate must remain closed until the project publishes a completed host-effect acceptance record.

### Capability and evidence status

Production release decisions use evidence, not the presence of source files. The following matrix is the current release interpretation:

| Capability | Source implementation | Active runtime path | Observe proof | Host-effect proof |
|---|---:|---:|---:|---:|
| WFP kernel telemetry | Yes | Yes | Passed on isolated lab path | Not accepted |
| Go Nose canonical ingress | Yes | Yes | Passed through the control/forensic path | Not applicable |
| FIM real notifications | Yes | Yes | Proof and normalization in progress | Not applicable |
| ETW and Registry adapters | Yes | Worker paths present | Coverage must be verified per host profile | Not applicable |
| Rule-22 synthetic qualification | Yes | Yes | Passed for the qualification fixtures | Not applicable |
| EnforcementReceipt v1 validation | Yes | Guarded | Structural tests passed | Host postcondition pending |
| WFP block and cleanup | Yes, guarded | Gate closed | Not applicable | Not accepted |

`Yes` in the source column means that code exists. It does not mean that the capability is enabled, verified on the current build, or accepted for production. A release may be promoted only when the corresponding runtime and evidence columns satisfy the release gate.

## Repository structure

| Path | Responsibility |
|---|---|
| `src/` | Zig runtime, control plane, pipeline, policy boundary, forensic coordination, and Windows adapters |
| `drivers/` | WFP kernel callout and communication code |
| `rust-src/`, `shield/`, or Rust PEP build paths | Privileged policy enforcement boundary and native security helpers |
| `nose/` | Go network ingress and canonical event delivery |
| `brain/` | Python/Cython detection and analytical support |
| `ts_policy/` | TypeScript policy authoring and validation |
| `tools/aegisctl/` | Python operator API, CLI, contract helpers, and web dashboard |
| `aegis_dashboard/` | Optional Rust/egui Windows operator dashboard |
| `scripts/` | Build, install, proof, verification, and release automation |
| `configs/` | Rules and deployment configuration |
| `contracts/` | Machine-readable cross-language and operator contract fixtures |
| `docs/` | Architecture, runbooks, acceptance gates, and operational references |

## Requirements

### Supported host

The supported build and runtime target is a **64-bit Windows 10 or Windows 11 host** with administrator access. Kernel-driver and WFP tests must run on an isolated test machine or disposable virtual machine. Do not install an experimental driver on a business workstation.

### Required build tools

Install the following tools before building from source:

| Component | Minimum | Purpose |
|---|---:|---|
| Zig | 0.13.0 | Core daemon and Zig tests |
| Rust | 1.75 or current stable MSVC toolchain | PEP, Shield, and native dashboard components |
| Go | 1.22+ | Go Nose and related ingress components |
| Python | 3.11+ | CLI, Brain, proof scripts, and tests |
| CMake | 3.27+ | Native helper and bridge builds |
| Visual Studio 2022 | MSVC C++ workload | C/C++ compilation and Windows ABI support |
| Windows SDK and WDK | Matching installed SDK | WFP kernel driver and Windows headers/libraries |
| Git | Current | Source retrieval and versioned provenance |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7 | Build, service, and proof scripts |

Install the **Desktop development with C++** workload in Visual Studio. The WDK must provide kernel headers, `ntoskrnl.lib`, and WFP libraries. A driver that is only compiled but not correctly signed is not a valid runtime artifact.

### Optional runtime and lab tools

Install these only when the corresponding capability is required:

- **Npcap and the Npcap SDK** for live packet capture through Go Nose.
- **Node.js 20+** for TypeScript policy tooling, if that part of the policy workflow is built locally.
- **VMware Workstation/Player** or another hypervisor for the isolated lab.
- **Kali Linux** as an optional traffic-generation and reconnaissance VM.
- A second disposable Windows VM as the preferred AEGIS target for host-effect testing.

The recommended lab network is a host-only VMware network such as VMnet1. A representative topology is:

```text
Kali attacker VM       192.168.126.10
Windows target VM      192.168.126.20
Windows development host / optional target  192.168.126.1
```

Use a separate target VM when possible. Attacking the development host itself is less reproducible and increases operational risk.

## Obtain the source

```powershell
git clone <repository-url> AEGIS-NIDS
Set-Location .\AEGIS-NIDS
```

If the repository is delivered as an archive, verify the archive checksum and record the source commit before building. All build, test, installer, and release paths must use the same repository root. Do not mix binaries from `Program Files`, an old release bundle, and the current checkout.

## First-time setup

Open an **elevated PowerShell** only when a step requires administrator access. Keep ordinary source inspection and unit tests unprivileged.

Check the toolchain:

```powershell
zig version
rustc --version
cargo --version
go version
python --version
cmake --version
```

Create the runtime directories used by the local runbook:

```powershell
New-Item -ItemType Directory -Force `
  logs\pids, logs\runtime, logs\health, logs\build, pid | Out-Null
```

Create a deployment profile from the example and edit only host-specific values:

```powershell
Copy-Item config\deployment_profile.example.json config\deployment_profile.json
```

Do not place secrets, private policy signing keys, or production credentials in the repository.

## Build from source

Build from the repository root:

```powershell
.\scripts\build_all.bat
```

The build normally covers the native helpers, Zig daemon, Rust components, Go ingress, and Python/Cython support. The script can report `SKIP` when a toolchain is absent; `SKIP` is not a successful production build. For a complete release, every required component must report `OK`, and no required artifact may be missing. If a step reports `FAIL` or an expected component reports `SKIP`, stop and resolve that condition before starting the runtime.

Run the repository verification commands:

```powershell
python tools\release_engineering.py --manifest
python tools\release_engineering.py --verify
python tools\aegisctl.py rules validate
```

The exact artifact names can change between release profiles. The authoritative artifact manifest and the current build output must agree. The release manifest is authoritative for the Go Nose filename; do not infer readiness from an old filename or from a stale `dist`, `build`, or `target` directory. At minimum, verify the current daemon path:

```powershell
Get-Item .\zig-out\bin\aegis_nids.exe
Get-FileHash .\zig-out\bin\aegis_nids.exe -Algorithm SHA256
```

The running process must later point to this current build, not to an older executable under `C:\Program Files\AEGIS`.

## Start and verify detection-only mode

Start the current daemon using the project’s documented service or development start procedure. Do not start multiple copies. The Zig daemon must own the control pipe and worker lifecycle.

Verify the runtime through the control plane:

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
```

A healthy observe-only system should expose the state of the runtime, worker readiness, data-plane counters, forensic status, WFP capability, FIM readiness, and the prevention gate. The expected safe posture is:

```text
prevention_gate       = closed
tier3_enforcing       = false
host_effect_capable   = false
receipt_required      = true
```

`provider_ready=true` does not mean that traffic was blocked. It means that a provider dependency is present or attested. Only a validated receipt can claim a confirmed host effect.

## Use the operator interfaces

### CLI

The CLI is the most reliable interface for engineering and automation:

```powershell
python tools\aegisctl.py status --json
python tools\aegisctl.py health --json
python tools\aegisctl.py metrics
python tools\aegisctl.py rules list
python tools\aegisctl.py rules validate
python tools\aegisctl.py events count
python tools\aegisctl.py events tail
python tools\aegisctl.py incidents
```

Use the JSON forms in automation. Human-readable forms are intended for operators during a lab session.

### Web dashboard

The optional read-only dashboard is started from the repository root:

```powershell
$env:DASHBOARD_PORT = "5000"
python -m tools.aegisctl.web_dashboard.app
```

Open `http://127.0.0.1:5000/` locally. The dashboard exposes a unified snapshot, health, rules, incidents, and read-only server-sent updates. It must not be treated as a second runtime supervisor.

### Native dashboard

`aegis_dashboard` is an optional Windows-native operator view. It displays evidence and runtime state but must not infer a host block from an event label. Build and run it only after the current Rust toolchain and daemon contract have been verified.

## Safe testing workflow

### 1. Synthetic Rule-22 qualification

Start with deterministic fixtures. This verifies rule matching without requiring an attack and without changing host state:

```powershell
python scripts\run_rule_matching_observe_only.py
```

A successful result means that the configured rule matches its synthetic fixture. It does **not** prove that a real sensor produced the event or that IPS enforcement works.

### 2. Control-plane fail-closed probe

Run the read-only and invalid-mutation probe:

```powershell
python scripts\run_control_receipt_probe.py
```

The expected result is that read-only routes work and invalid mutation requests are rejected without an enforcement receipt or WFP host effect.

### 3. Real WFP observe-only proof

Use the project proof script in read-only mode:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_wfp_l4_observe_only_proof.ps1 `
  -GenerateBenignProbe `
  -RequireEvent
```

This proof must use read access to the device and must not call block or unblock control codes. It validates kernel-to-user observation and ring readback. It is not an IPS blocking proof.

### 4. Real FIM observe-only proof

Use a disposable proof directory rather than modifying Windows system directories:

```powershell
$proofRoot = Join-Path $PWD "test-fixtures\fim-proof"
New-Item -ItemType Directory -Force $proofRoot | Out-Null
$env:AEGIS_FIM_PROOF_ROOT = $proofRoot
```

Restart the current daemon so the environment variable is read by the FIM worker. Create a benign file change inside the proof root and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_fim_real_observe_only_proof.ps1
```

The proof must show the current daemon path, the configured proof root, a real file notification, normalized FIM metadata, a forensic record, and no host mutation. Remove the environment variable after the test:

```powershell
Remove-Item Env:AEGIS_FIM_PROOF_ROOT -ErrorAction SilentlyContinue
```

### 5. Generate benign lab traffic

From the Kali VM, use only traffic directed at the isolated lab target. Examples include a TCP connectivity check or a bounded port scan against a disposable listener:

```bash
nc -vz -w 5 192.168.126.20 49152
nmap -sT -Pn -p 49152 --max-retries 1 --host-timeout 10s 192.168.126.20
```

Record the attacker address, target address, interface, ruleset digest, runtime version, and prevention-gate state before each test. Correlate the WFP event, normalized canonical event, matched rule, alert, and forensic record.

Do not run credential theft tools, ransomware, destructive payloads, uncontrolled floods, or exploit chains against any host. A safe NIDS qualification test should be bounded, reversible, and limited to systems you own or are explicitly authorized to test.

## Rule-22 qualification model

Rule-22 qualification has three separate acceptance levels:

1. **Synthetic match:** the fixture matches the configured rule.
2. **Real sensor observation:** a WFP, FIM, ETW, registry, or ingress event is captured and normalized.
3. **Controlled response:** a policy decision is linked to a valid receipt and a verified reversible host postcondition.

Passing level 1 does not imply passing levels 2 or 3. The current project focus is to complete real sensor observation before enabling controlled IPS proof.

## Troubleshooting and provenance

### The wrong daemon is running

Inspect the running process:

```powershell
Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'" |
  Select-Object ProcessId, ExecutablePath, CommandLine
```

Stop stale development or installed copies before starting the current build. A result from an old executable is not evidence for the current source tree.

### Named pipe is busy

`ERROR_PIPE_BUSY` usually means another client or stale daemon owns a pipe instance. Use the authoritative daemon lifecycle procedure. Do not start a second daemon to bypass the error. Retry read-only queries only after the owner has released the pipe.

### WFP driver does not start

Check service state, loaded path, and the installed driver hash:

```powershell
Get-CimInstance Win32_SystemDriver -Filter "Name='AegisWfp'" |
  Format-List Name,State,Status,Started,PathName
Get-FileHash C:\Windows\System32\drivers\aegis_wfp.sys -Algorithm SHA256
```

A signature error, a stale installed driver, or a `Stop Pending` state must be resolved before interpreting telemetry results. Do not bypass Windows driver-signing protections on a production host.

### The system reports degraded

`DEGRADED` is an explicit safety state. Inspect `health --json` for worker failure reasons, data-plane counters, PEP readiness, WFP provider readiness, FIM readiness, and forensic integrity. The correct response is to fix the missing dependency or remain in detection-only mode, not to assume that enforcement succeeded.

## Production-readiness gates

AEGIS should not be marketed or deployed as production IPS until all of the following are complete on the current build:

- One authoritative runtime owner is verified after clean install and restart.
- Canonical event and policy contracts pass cross-language tests.
- WFP observe-only telemetry is reproducible on the supported Windows versions.
- FIM events are normalized and linked to Rule-22 evidence.
- EnforcementReceipt v1 contains request, event, trace, audit, provider, filter, and host-postcondition fields.
- A controlled block proof shows a real reversible WFP effect.
- Cleanup removes the exact receipt filter and is independently verified.
- Restart and recovery leave no stale process, filter, pipe, or forensic inconsistency.
- Driver, binaries, configuration, and policy artifacts are signed or verified according to the release profile.
- A clean installation, rollback, and release-manifest verification pass.

Until then, the correct product statement is **Windows-native NIDS with observe-only and controlled-lab IPS development**, not production prevention.

## Documentation map

- [User operations guide](docs/USER_OPERATIONS_GUIDE.md)
- [Local runbook](docs/runtime/LOCAL_RUNBOOK.md)
- [Canonical contracts](docs/architecture/CONTRACTS.md)
- [Architecture truth](docs/architecture/ARCHITECTURE-TRUTH.md)
- [Authority matrix](docs/architecture/authority-matrix.md)
- [WFP IOCTL status](docs/WFP_IOCTL_STATUS.md)
- [P0–P2 operator acceptance](docs/P0_P2_OPERATOR_ACCEPTANCE.md)
- [Production handoff](docs/AEGIS_PRODUCTION_HANDOFF_2026-09-22.md)
- [Operator contract v1](contracts/operator_contract_v1.json)

## References

[1]: docs/runtime/LOCAL_RUNBOOK.md "AEGIS Local Runbook"
[2]: docs/USER_OPERATIONS_GUIDE.md "AEGIS User Operations Guide"
[3]: docs/architecture/CONTRACTS.md "AEGIS Authoritative Contracts"
[4]: docs/architecture/authority-matrix.md "AEGIS Authority Matrix"
[5]: docs/P0_P2_OPERATOR_ACCEPTANCE.md "AEGIS P0–P2 Operator Acceptance"
