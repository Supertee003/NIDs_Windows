# AEGIS Production Handoff

**Project:** AEGIS Windows-native NIDS/IPS  
**Baseline commit:** `46b93dc`  
**Date:** 2026-09-23  
**Mode:** Observe-only / qualification  
**Prevention gate:** `CLOSED`  
**Host mutation:** Not executed in the current qualification cycle

## 1. Executive status

AEGIS has a runtime-complete release candidate for qualification. The RC assembles and verifies successfully, starts from the RC directory, reports healthy Zig/C++/Rust/Nose components, and has demonstrated real WFP read-only telemetry and Npcap attribution from Kali to the Windows host.

The project is **not yet production-ready as an IPS**. The remaining blocker is enforcement evidence. The current Rust PEP and WFP path can request an exact-flow filter and can remove a filter by its exact `filter_id`, but the system does not yet have a fully verified provider-backed `EnforcementReceipt v1`, an independently sufficient host postcondition read-back, or a proven post-cleanup state. Do not open the prevention gate until those conditions are complete.

## 2. Verified achievements

### Release candidate and provenance

Latest RC result:

```text
RC PASS: D:\NIDs_Windows\release\T20-final\46b93dc (230 files, 9ea6de3749215f10)
RC VERIFY PASS: D:\NIDs_Windows\release\T20-final\46b93dc
```

The RC now contains `tools/upgrade_rollback.py`. The running PEP artifact was previously verified inside the RC tree:

```text
tier3.artifact_path = D:\NIDs_Windows\release\T20-final\46b93dc\zig-out\bin\aegis_pep.dll
```

### Runtime qualification

The latest healthy RC runs verified:

```text
state                 = RUNNING
runtime_state         = RUNNING
degraded              = false
cpp                   = RUNNING
nose_connected        = true
ETW/FIM/Registry      = READY
provider_ready        = true
```

The successful Nose run showed no duplicate or non-monotonic event IDs. A successful L7 host-only run attributed traffic from Kali `192.168.126.10` to Windows host `192.168.126.1` through Npcap, Go Nose, and the Zig pipeline.

### WFP observe-only proof

The real host proof passed with:

```text
driver_service          = AegisWfp
access                  = GENERIC_READ
requested controls      = GET_STATS, READ_EVENTS
forbidden controls      = BLOCK_FLOW, UNBLOCK_FLOW
complete event frames   = 286
trailing event bytes    = 0
```

This proves sensor read capability. It does not prove that a host block can be installed, verified, and removed safely.

### Control-plane fail-closed proof

The safe control probe passed:

```text
CONTROL_RECEIPT_PROBE_RESULT {"failures": [], "passed": true}
```

Observed behavior:

```text
enforcement.status   = OK
enforcement.simulate  = OK
enforcement.verify   = UNAVAILABLE / DEGRADED
enforcement.block     = rejected for invalid payload
enforcement.unblock   = rejected for filter_id=0
prevention_gate       = closed
```

The probe proves rejection of invalid mutation requests. It does not prove a valid enforcement request.

## 3. Architecture summary

```text
WFP / ETW / FIM / Npcap / Named Pipe
                |
                v
       Go Nose and sensor adapters
                |
                v
       Zig canonical event pipeline
                |
                v
       Python Brain and policy logic
                |
                v
        Rust PEP authority
                |
                v
        WFP exact-flow provider
                |
                v
  receipt, audit, forensic, postcondition
```

The Rust PEP is the sole intended enforcement authority. Zig must not call privileged WFP block or unblock transport directly. The C bridge is a transport boundary, not a second policy authority.

## 4. Backend status

| Component | Current result | Remaining production work |
|---|---|---|
| Zig core | Runtime qualified | Preserve readiness barriers and fail-closed behavior |
| Go Nose | Real Npcap attribution and exactly-once counters | Stress, restart, and sustained-loss evidence |
| Python Brain | Runs in RC qualification | Remove wrapper-lock risk and pin deployment dependencies |
| Rust PEP | Provider-ready; exact cleanup path exists | Complete receipt and query ABI |
| WFP driver | Read-only telemetry proven; block path exists | Exact provider read-back and restart-safe ownership |
| C user bridge | Flow ABI reviewed | Compile and test query export on Windows |
| Control plane | Named pipe and audit IDs work | Implement verified block/verify/cleanup lifecycle |
| Forensics | Observation evidence works | Link event, receipt, audit, and cleanup records |
| Release tooling | RC PASS/VERIFY PASS | Rebuild after each ABI change |

## 5. EnforcementReceipt v1 requirements

The contract in `src/policy/enforcement_receipt.zig` requires a confirmed receipt to contain:

```text
receipt_version          = 1
request_id               != 0
event_id                 != 0
policy_id                != 0
decision                  = block
status                   = enforced
provider                 != empty
filter_id                != 0
host_effect_confirmed    = true
trace_id                 != 0
audit_id                 != 0
```

A non-zero `filter_id` alone is not sufficient. The provider must be queried by that exact ID and the result must match the requested destination IP, port, and protocol.

Approved isolated proof scope:

```text
Kali source:       192.168.126.10
Windows host:      192.168.126.1
Destination:       TCP/49153
Policy ID:         0xE901
Severity:          lowest proof severity
```

## 6. Read-back implementation status

The following query work was started in the source tree and is **not yet compiled with Windows/WDK**:

```text
drivers/wfp_callout/aegis_wfp.h
  IOCTL_AEGIS_QUERY_FILTER and query/state structs

drivers/wfp_callout/aegis_wfp.c
  query dispatch, tracked tuple fields, read-only query handler

src/windows/wfp_ioctl.c
  user-mode query structs, ABI assertions, query export

rust-src/lib.rs
  FilterState, adapter query symbol, aegis_pep_query_filter export

src/policy/pep_bindings.zig
  PepFilterState, queryFilter(), ABI layout test
```

Important limitation: the first implementation reads the driver-owned active filter state. It must still be verified against actual WFP provider enumeration semantics. Because the filter is currently marked persistent while identity is held in globals, driver restart behavior must be resolved before calling this a production-grade postcondition.

A previous attempted edit to `src/control/handler_registry.zig` for `enforcement.verify` was interrupted. Treat it as unimplemented until `git diff`, Zig compilation, and control-probe output confirm otherwise.

## 7. Rollback status

The RC rollback tool was corrected to distinguish required and optional paths. Latest reported snapshot:

```json
{
  "entries_copied": 3,
  "entries_missing": 0,
  "optional_entries_missing": 5,
  "required_entries": 1,
  "optional_entries": 7
}
```

This means the required configuration baseline is present. Optional signing, trust, certificate, audit, and forensic artifacts must not be fabricated merely to make the count zero.

This snapshot is a configuration/data baseline. It is not a WFP filter rollback proof. WFP proof requires a separate filter pre-state, receipt, post-block query, exact cleanup, and post-cleanup query.

## 8. Frontend and operator surface

The dashboard and CLI must display control-plane truth. They must not infer a host block from a policy action, detection log, or provider readiness alone.

Required UI states:

| State | Required meaning |
|---|---|
| `DETECTION_ONLY` | Sensors and detection work; host effect is unavailable |
| `PROVIDER_READY_GATE_CLOSED` | Provider is ready, but blocking is still disabled |
| `ENFORCEMENT_PROOF_ACTIVE` | A scoped proof window is active with expiry |
| `ENFORCED` | A validated receipt and matching postcondition exist |
| `ROLLBACK_PENDING` | Cleanup was requested but not yet verified |
| `ROLLED_BACK` | Exact filter removal and absence query succeeded |
| `DEGRADED` | Required control or evidence is unavailable |

Frontend work required:

1. Add a receipt panel containing receipt version, filter ID, provider, trace ID, audit ID, policy ID, and exact tuple.
2. Add a postcondition panel showing `present`, provider status, and tuple match.
3. Add a cleanup panel showing the original filter ID and post-cleanup result.
4. Display gate state separately from provider readiness.
5. Show RC executable and DLL provenance.
6. Prevent stale `ENFORCED` state when the control daemon is unavailable.
7. Add rule evidence filtering that distinguishes synthetic matches from real-sensor matches.
8. Export linked event, forensic, audit, receipt, and cleanup evidence.

## 9. Required backend implementation order

1. Compile and validate the new query ABI across kernel driver, C bridge, Rust, and Zig.
2. Decide whether proof filters are dynamic or persistent. If persistent, implement restart-safe ownership and enumeration; otherwise use a dynamic proof session with deterministic cleanup.
3. Extend PEP/Zig data so the control handler can construct a complete receipt.
4. Implement `enforcement.verify` using exact `filter_id` and exact tuple comparison.
5. Add scoped proof-gate lifecycle with automatic expiry.
6. Use only receipt `filter_id` for cleanup.
7. Query again and require `present=false` after cleanup.
8. Link receipt, audit, trace, event, forensic, and pre/post filter evidence.
9. Rebuild the RC and verify all checksums.
10. Only then execute the approved isolated host proof.

## 10. Test plan

Run on the Windows host after each change:

```powershell
Set-Location D:\NIDs_Windows
python -m pytest tests\runtime\test_operator_contracts.py -q
python -m pytest tests\runtime\test_health.py -q
python -m pytest tests\pep\test_t8_rust_pep.py -q
python -m pytest tests\wfp\test_t11_wfp_enforcement.py -q
python tools\aegisctl.py rules validate
zig build test -Doptimize=Debug
```

Use the WDK build for the driver:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\wdk_build_production.ps1
```

Do not run the old direct ctypes host test as the production proof if it uses the legacy `aegis_pep_unblock_ip` symbol. The authoritative proof must use the control plane and exact receipt filter ID.

Safe control probe:

```powershell
Set-Location D:\NIDs_Windows\release\T20-final\46b93dc
python scripts\run_control_receipt_probe.py
```

Safe WFP observe-only proof:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\run_wfp_hostonly_observe_only.ps1 `
  -ExpectedKaliIp 192.168.126.10 `
  -ListenPort 49153 `
  -WaitSeconds 30
```

## 11. Approved isolated proof sequence

Only after the backend query, receipt, verify, gate, and cleanup tests pass:

```text
1. Stop stale AEGIS wrappers and processes.
2. Start only the verified RC.
3. Capture health and filter pre-state.
4. Prepare the proof scope and rollback evidence.
5. Open an expiring proof gate.
6. Send one exact-flow block request through control plane to Rust PEP.
7. Require complete EnforcementReceipt v1.
8. Query by receipt.filter_id and verify exact tuple.
9. Send one benign Kali probe.
10. Verify the expected host postcondition.
11. Unblock using only receipt.filter_id.
12. Query the same ID and require present=false.
13. Close the gate.
14. Export evidence and verify the RC/runtime state.
```

If any step fails, stop. Do not use IP-only cleanup and do not issue a broad firewall reset.

## 12. 22-rule evidence matrix

Synthetic qualification already passed for all 22 rule definitions. Production evidence must add these fields for every rule:

```text
rule ID
schema/semantic validation
synthetic match
real sensor source
source event ID
pipeline correlation
forensic record
observe-only evidence path
enforcement proof status
final qualification state
```

A synthetic match is not a real-sensor match. A policy decision is not a host effect. A rule cannot be production-ready until its evidence type is explicit.

## 13. Production cut-over gates

| Gate | Current state |
|---|---|
| RC assembly and checksum verification | PASS |
| RC executable/DLL provenance | PASS in latest healthy run |
| WFP/ETW/FIM/Nose observation | PASS for qualification |
| 22-rule synthetic validation | PASS |
| 22-rule real-sensor matrix | Incomplete |
| Rust PEP authority isolation | HELD |
| EnforcementReceipt v1 | Incomplete |
| Exact WFP read-back | In progress; not Windows-compiled |
| Host block postcondition | Not executed |
| Exact filter cleanup proof | Not executed |
| Post-cleanup absence proof | Not executed |
| Config rollback baseline | PASS with optional absences documented |
| Driver/policy/release signing | Not evidenced as production-complete |
| Monitoring and stale-state handling | Incomplete |
| Scoped proof-gate lifecycle | Incomplete |
| Production approval | Not granted |

## 14. Next-session commands

Start in source root and inspect the unfinished ABI work:

```powershell
Set-Location D:\NIDs_Windows
git status --short
Select-String -Path src\control\handler_registry.zig `
  -Pattern "queryFilter|POSTCONDITION_FAILED|provider-backed EnforcementReceipt"
rg -n "QUERY_FILTER|query_filter|PepFilterState|FilterState|g_BlockedPort|g_BlockedProtocol" `
  drivers/wfp_callout src/windows rust-src src/policy/pep_bindings.zig
```

Then run the compile/test gates. If the query ABI fails to compile, revert only that query change set and redesign it atomically. Do not bypass the gate or call the C bridge directly from an ad-hoc script.

## 15. Final handoff state

```text
Runtime qualification       = strong PASS
RC packaging                = PASS
Observe-only WFP            = PASS
Authority isolation         = PASS
Config rollback baseline    = PASS
Exact block path            = exists but unproven
Read-back ABI               = started, not Windows/WDK compiled
EnforcementReceipt v1       = incomplete
Host postcondition          = not executed
Cleanup proof               = not executed
Production IPS              = not approved
Prevention gate             = CLOSED
```

> The next milestone is one isolated, reversible block-and-rollback proof that produces a complete, independently verifiable receipt. It is not simply opening the blocking gate.

## References

[1]: ../src/policy/enforcement_receipt.zig "AEGIS EnforcementReceipt v1 contract"
[2]: ../src/control/protocol.zig "AEGIS control protocol"
[3]: ../src/control/handler_registry.zig "AEGIS control handlers"
[4]: ../rust-src/lib.rs "AEGIS Rust PEP and WFP adapter"
[5]: ../drivers/wfp_callout/aegis_wfp.h "AEGIS WFP driver ABI"
[6]: ../drivers/wfp_callout/aegis_wfp.c "AEGIS WFP driver implementation"
[7]: ../src/windows/wfp_ioctl.c "AEGIS user-mode WFP IOCTL bridge"
[8]: ../src/policy/pep_bindings.zig "AEGIS Zig PEP bindings"
[9]: ../scripts/run_control_receipt_probe.py "AEGIS fail-closed control probe"
[10]: ../scripts/run_wfp_hostonly_observe_only.ps1 "AEGIS WFP observe-only proof"
[11]: ../tools/release_candidate.py "AEGIS RC assembler"
[12]: ../tools/upgrade_rollback.py "AEGIS rollback tool"
[13]: ../scripts/run_aegis.bat "AEGIS runtime launcher"
[14]: PRODUCTION_PATH.md "AEGIS production roadmap"
[15]: ../docs/platform/p4-enforcement-contract.md "AEGIS enforcement platform contract"
[16]: ../release/T20-final/46b93dc/ROLLBACK.md "Current RC rollback notes"
[17]: ../configs/Rules.json "Current 22-rule source"
[18]: ../tools/aegisctl/web_dashboard/app.py "Read-only AEGIS dashboard"
[19]: ../tools/aegisctl/api/control_api.py "AEGIS control API"
[20]: ../tests/wfp/test_t11_windows_host.py "Windows WFP host test contract"

> Internal repository paths above are relative to this report location.
