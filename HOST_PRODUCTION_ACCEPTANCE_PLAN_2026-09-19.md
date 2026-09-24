# AEGIS Host Production Acceptance Plan

**Date:** 2026-09-19  
**Scope:** Windows Host runtime readiness before VMware attack and WFP host-effect proof.

## Decision

The two VMware guests are prepared and can communicate on the isolated lab network. The next work should validate the AEGIS host itself before any attack traffic is generated. This phase is a read-only production preflight. It verifies the runtime, worker readiness, forensic integrity, required truth artifacts, and fail-closed enforcement state.

This phase does not declare the system production-ready. That declaration requires an isolated WFP host-effect proof, a cleanup proof, and lifecycle recovery after the provider has been exercised.

## Required host conditions

The Windows host must run the current build from `D:\NIDs_Windows`. The daemon must be the single runtime owner. The health response must show a running runtime, ready Rust PEP, ready Tier-3 pipeline, and all required workers. The forensic chain must verify successfully.

The enforcement gate must remain closed during this preflight:

```text
overall_gate         = false
host_effect_capable  = false
production_attested  = false
```

A closed gate is expected until a real WFP provider postcondition is proven.

## Preflight script

Run from an elevated PowerShell while `zig build run` is active:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_host_production_preflight.ps1'
```

The script checks live health, required worker flags, required truth/configuration artifacts, forensic verification, and gate closure. It does not install or stop a driver, generate traffic, submit an enforcement action, or alter policy.

## Windows validation sequence

Run the following in order:

```powershell
Set-Location -Path 'D:\NIDs_Windows'

zig build
if ($LASTEXITCODE -ne 0) { throw 'zig build failed' }

zig build test
if ($LASTEXITCODE -ne 0) { throw 'zig tests failed' }

python -m pytest `
  tests\runtime\test_health.py `
  tests\runtime\test_lifecycle_authority.py `
  tests\runtime\test_rust_shield_lifecycle.py `
  -q
if ($LASTEXITCODE -ne 0) { throw 'Python runtime tests failed' }
```

Start the owner in a separate window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig build run
```

Run host preflight from another elevated window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_host_production_preflight.ps1'
```

Then run lifecycle recovery acceptance:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_lifecycle_recovery_proof.ps1' `
  -WaitSeconds 180
```

## Acceptance interpretation

A passing host preflight means the host is ready for the next lab stage. It does not prove WFP host effect. A failure must be corrected before observe-only traffic or enforcement testing proceeds.

The host is not production-attested until all of the following are available:

- valid build and unit-test results;
- live runtime and worker readiness;
- valid forensic integrity before and after restart;
- successful observe-only VMware traffic proof;
- Rust PEP authorization evidence;
- WFP provider response with filter identity;
- observed block postcondition from the isolated target path;
- cleanup and unblock postcondition;
- receipt and forensic linkage;
- recovery without stale filters or stale pipe ownership.

## Current boundary

The VMware guests may be used for topology and benign reachability checks after the host preflight passes. The WFP block proof remains gated on an exact user-confirmed target, protocol, port, duration, and cleanup procedure. No production-ready claim is permitted before those postconditions are recorded.

## References

[1]: https://docs.vmware.com/ "VMware documentation"
