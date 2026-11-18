# WFP-READINESS-REFRESH-001 — live provider status projection

**Status:** E2 + bounded E5 provider/readiness verification PASS; RB-021 canary remains open
**Patch commit:** `318a10a95b7922851562aad27f389c2ab9f4fdac`
**Target HEAD:** `f39a02975f31abffaf0e77cdec38e2c6ffd9a72a`
**Build source commit:** `318a10a95b7922851562aad27f389c2ab9f4fdac`

## Patch contract

- **PATCH-ID:** WFP-READINESS-REFRESH-001
- **FLOW-ID:** RB-021 / PEP provider readiness and health projection
- **TARGET FILES:** `src/core/bridge_init.zig`, `src/control/handler_registry.zig`
- **TARGET SYMBOLS:** `bridge_init.status`, `bridge_init.allActive`, `bridge_init.getState`, `bridge_init.printStatus`, `handlers.health`
- **IN SCOPE:** Refresh read-only WFP provider attestation for status snapshots and calculate the health bridge predicate from the same snapshot.
- **OUT OF SCOPE:** WFP driver/ABI changes, detector/capture behavior, prevention activation, queue-loss policy.
- **CONTRACT IMPACT:** `capabilities.wfp` is now a live provider-attestation projection rather than a startup-only cached bit. JSON schema remains unchanged.
- **ABI IMPACT:** None.
- **AUTHORITY IMPACT:** None. Rust PEP remains the sole authority; prevention gate remains closed and production is detection-only.
- **STATE IMPACT:** Bridge status is sampled once for each health response; transient provider failures are visible on subsequent samples. Queue/loss readiness continues to gate overall health.
- **TEST IMPACT:** Regression covers startup false→live true and true→false state projection. Full Zig test and build pass at E2.
- **EVIDENCE IMPACT:** E2 component evidence recorded. Current-source Windows redeploy/health comparison is still pending.

## Evidence and result

The live red loop before the patch returned `(health.wfp, enforce.provider_ready, health.wfp) = (false, true, false)` for daemon PID 16116. Source review showed both surfaces call the same Rust `aegis_pep_provider_ready()` export, while health consumed `g_state.wfp_ioctl` captured only during bridge initialization.

The patch makes `status()` project the current provider probe into a local `BridgeState`; it does not mutate shared global bridge flags. The health handler derives both `wfp` and `bridge_ready` from that one snapshot. `allActive()` and status diagnostics use the same live projection. No prevention gate or host-effect path was changed.

- Targeted `zig test src/core/bridge_init.zig`: 5 passed, 0 failed.
- Full `zig build test --summary all`: 2,062 passed, 10 skipped, 0 failed.
- `zig build`: PASS (`ReleaseSafe x86_64-windows`).
- `zig fmt` and `git diff --check`: PASS for changed source.
- `python tools/truth.py verify`: TRUTH_VALID after source-map rebaseline.
- **Windows result:** pending redeploy. No canary traffic sent.

## Patch completion record

- **FINAL HEAD:** `318a10a95b7922851562aad27f389c2ab9f4fdac` (source commit)
- **FILES CHANGED:** 2 source files
- **OLD FLOW → NEW FLOW:** startup-cached provider bit → fresh Rust attestation → one immutable bridge snapshot → matching health capability and bridge predicate
- **INVARIANT:** Provider readiness fields within one health response derive from one provider probe; readiness does not imply host-effect capability.
- **BUILD RESULT:** PASS
- **TEST RESULT:** E2 PASS (2,062 passed, 10 skipped)
- **WINDOWS RESULT:** Current-source package installed; daemon and build SHA-256 match; WFP health/enforce/health sequence was `(true, true, true)`; elevated RB-021 preflight passed all 16 checks. Overall health remains DEGRADED from attributed ETW/FIM quota sheds and minifilter loss.
- **EVIDENCE LEVEL:** E2 + bounded E5 provider/status verification; no RB-021 canary or overall E5 qualification
- **EVIDENCE ARTIFACTS:** this report; `STOPLINE-WFP-READINESS-001-20261109.md`; local-only `admin-evidence/wfp-readiness-refresh-001-20261109/postinstall-verification-e5.json`
- **ROLLBACK:** `git revert 318a10a`
- **REMAINING RISK:** A live probe may be temporarily unavailable; overall health must remain DEGRADED when loss counters are nonzero. Per-request retries can attempt adapter loading when provider is absent. Current live health remains DEGRADED because queue and minifilter loss counters are nonzero.
- **OPEN BLOCKERS:** #25 authority reconciliation; #29 telemetry quota/ring loss; #30 service lifecycle; E5 and Phase 6–9 gates.
- **COMPLETION GATE:** PASS for the E2 + bounded E5 provider-status slice; RB-021 detection canary, issue #29 loss resolution, and overall runtime acceptance remain OPEN.
