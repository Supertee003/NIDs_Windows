# AEGIS Phase 9 — Tier-3 Readiness Report

**Date:** 2026-09-19  
**Scope:** Tier-3 authority readiness, WFP provider separation, lifecycle regression, and Phase 10 entry gate.

## Executive conclusion

Phase 9 source-level readiness work is complete. The current authority model is now explicit: Rust PEP/payload screening is the Tier-3 authority, while WFP is a separate host-effect provider. A ready PEP must not be reported as `STOPPED` merely because WFP is unavailable. Conversely, PEP readiness must never be interpreted as proof that a host block occurred.

The runtime remains intentionally fail-closed until a WFP provider and host-effect postcondition are attested.

## Verified changes

The daemon now marks the Tier-3 subsystem ready when the Rust PEP is available. The former coupling to `bridge_init.allActive()` was removed from this decision because that aggregate also requires WFP, C++ IPC, and UDP Brain. Provider readiness and host-effect capability remain separate health fields.

The control API now recognizes both the current `aegis_pep.dll` artifact name and the legacy `sec_monitor.dll` name. Disk presence remains diagnostic only; it does not attest dependency loading, provider readiness, or host effect.

A regression test now asserts the required separation:

| Assertion | Required value |
|---|---:|
| Tier-3 PEP ready | `true` |
| Tier-3 dependency ready | `true` |
| WFP provider ready | `false` when WFP is unavailable |
| Tier-3 host-effect capable | `false` when WFP is unavailable |
| Rust Shield PEP ready | `true` |
| Rust Shield provider ready | `false` when WFP is unavailable |
| Overall state | `DEGRADED` |

Python syntax validation passed with `py_compile`. Full Zig and pytest execution requires the Windows development environment because the sandbox does not contain the project Zig toolchain or pytest installation.

## Lifecycle evidence

The latest lifecycle recovery proof passed after the readiness separation change. The observed result was:

```json
{
  "passed": true,
  "stopped_state": "DEGRADED",
  "restarted_state": "DEGRADED",
  "rust_shield_state": "READY",
  "overall_gate": false,
  "host_effect_capable": false,
  "forensic_generation_valid": true,
  "forensic": {
    "integrity": "ok",
    "verified": true
  }
}
```

The forensic record count reset across process generations is accepted because the current forensic ring is process-local. Integrity and verification of the new generation remain mandatory.

## Phase 10 entry gate

Phase 10 may begin only after the Windows elevated checks confirm the WFP service/device contract. The following conditions are mandatory:

1. The Rust PEP is ready.
2. The WFP provider is independently observable as ready.
3. `host_effect_capable` is not promoted by configuration or artifact presence.
4. The isolated proof uses a designated test target and records precondition, requested action, provider response, and postcondition.
5. The proof verifies the actual host effect and then verifies cleanup/unblock.
6. A failed or ambiguous postcondition produces a non-passing proof and leaves the enforcement gate closed.

No production-ready claim is allowed before the host-effect postcondition is proven.

## Windows verification commands

Run from an elevated PowerShell after rebuilding the current sources:

```powershell
Set-Location -Path 'D:\NIDs_Windows'

zig build
zig build test
python -m pytest tests\runtime\test_health.py tests\runtime\test_lifecycle_authority.py -q
```

Start the owner in one window:

```powershell
zig build run
```

Inspect runtime readiness from another window:

```powershell
$h = python tools\aegisctl.py health --json | ConvertFrom-Json
$h | Select-Object state, runtime_state, tier3, rust_shield, capabilities
```

Inspect the WFP registration and device prerequisites without changing them:

```powershell
sc.exe query aegis_wfp
Get-Service | Where-Object {
    $_.Name -match 'aegis|wfp|npcap' -or
    $_.DisplayName -match 'aegis|wfp|npcap'
} | Select-Object Name, DisplayName, Status, StartType

Get-ChildItem -Path 'D:\NIDs_Windows' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'aegis_wfp|wfp.*sys|aegis_pep|sec_monitor' } |
    Select-Object FullName, Length, LastWriteTime
```

Expected pre-Phase-10 state while WFP is unavailable:

```text
Tier-3 PEP authority  = READY
WFP provider          = UNAVAILABLE
host_effect_capable   = false
overall_gate           = false
state                 = DEGRADED
```

## Files changed

- `src/daemon.zig` — separates Tier-3 PEP readiness from WFP provider readiness.
- `tools/aegisctl/api/control_api.py` — discovers current and legacy Tier-3 artifact names without treating disk presence as readiness.
- `tests/runtime/test_health.py` — adds the Tier-3/WFP authority-boundary regression test.
- `scripts/run_lifecycle_recovery_proof.ps1` — accepts process-local forensic generation reset while requiring new-generation integrity.

## Final status

Phase 8 lifecycle/recovery acceptance remains passed. Phase 9 source and contract work is complete. Phase 10 is gated on Windows elevated WFP/device verification and an isolated, reversible host-effect proof.


## Phase 10 preparation update

A read-only preflight script has been added at `scripts/run_wfp_phase10_preflight.ps1`. It checks administrator context, `AegisWfp` service registration/state, live PEP/Tier-3 health, provider readiness, and gate state. It never submits a block, installs a filter, changes a service, or claims host-effect capability from artifact presence.

A contract mismatch was also corrected in `scripts/wfp_service.ps1`: the documented userspace device endpoint is now `\\.\AegisWfpDevice`, matching `src/policy/wfp_ioctl.zig`. The service status message now references `IOCTL_AEGIS_GET_STATS (0x00126008)`, matching the Zig IOCTL constant. Phase 10 must still verify that the kernel driver's actual symbolic link is the same endpoint before any host-effect proof.

Run the preflight from elevated PowerShell while the daemon is running:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\scripts\run_wfp_phase10_preflight.ps1'
```

A passing preflight means only that the PEP/Tier-3 authority is live and the gate remains safely closed. It is not a WFP host-effect proof. The preflight must report `enforcement_attempted=false`.
