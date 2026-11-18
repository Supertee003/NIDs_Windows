# STOP-LINE: WFP provider readiness diverges across runtime surfaces

**Observed:** 2026-11-09 (Windows victim host, current-source deployment window)
**Runtime image:** `AEGIS-NIDS-5.0.0-6b728b8-20261109.exe`
**Repository HEAD:** `8f7c84d84a50f189491f82df18f5d0c3ac24c7bc` (build source `6b728b87e580aa7c1c09eb711087cb32d1b1324f`)
**Classification:** STOP-THE-LINE — driver/provider contract and telemetry loss require reconciliation
**Disposition:** No canary traffic sent; prevention gate remains closed; no source code changed.

## Evidence captured

- `sc.exe query AegisWfp`: kernel driver service reports `RUNNING`.
- `sc.exe qc AegisWfp`: image path is `\??\C:\WINDOWS\System32\drivers\aegis_wfp.sys`.
- Driver image SHA-256: `F63195B02C87A99A442A34CCF7025F18431C5E1FACAB804D5050029FFFA21F63`.
- `aegisctl health --json`: daemon is `DEGRADED`; `capabilities.wfp=false`; Rust PEP says `provider_capable=false`, `provider_ready=false`, `wfp=UNAVAILABLE`.
- `aegisctl enforce status`: `provider_ready=true`, `tier3=READY`, detection-only, prevention gate closed, host-effect capability false.
- `aegisctl queue --json`: queue `state=ok`, `mode=npcap_primary`, `kernel_owned=false`, `rows=0`, `shadow_rows=67887`, `reads=555`.
- At about 228 seconds uptime, health showed `queue_dropped_total=19127`, `minifilter_ring_dropped=30842`, `minifilter_pipeline_dropped=1666`; Nose showed 5267 frames read/submitted, zero drops/rejections/errors, and no duplicate/non-monotonic event IDs.
- A repeated read at about 396 seconds uptime reproduced `health.wfp=false` → `enforce status.provider_ready=true` → `health.wfp=false`. The queue reported `dropped_total=29876` (`capture_etw=28210`, `capture_fim=1666`), `source_quota_shed=29876`, `shed_overload=0`, depth 0, peak depth 9836; the minifilter ring counter remained 30842. Thus these queue drops are attributed quota sheds, not evidence of unclassified silent drops. Nose was still connected with 11311 frames read/submitted and zero Nose drop/reject/error or duplicate/non-monotonic IDs.
- Source inspection: `bridge_init.initWfpIoctl()` snapshots `pep_bindings.providerAttested()` into `capabilities.wfp` at startup; CLI projections also derive provider readiness from that capability. `enforce status` obtains provider readiness through a separate probe. This explains the separate reporting paths but does not establish which probe is correct or whether the driver is providing the expected contract.

## Why this blocks the canary

The service being `RUNNING` is not proof that the Rust PEP device attestation and runtime capability are healthy. The CLI readiness surfaces disagree, the Npcap queue reports no kernel-owned rows, and data-loss counters continue to rise while the daemon is degraded. Sending a detection canary now would produce ambiguous evidence and could obscure the telemetry-loss/driver-contract defect.

## Required follow-up

1. Reconcile provider attestation sources and define one authoritative, time-consistent health contract across daemon health, `enforce status`, queue diagnostics, and driver/device state.
2. Determine why this package's startup `providerAttested()` is false while the separate `enforce status` probe returns true. Capture the Rust DLL/device-open error path and kernel device/IOCTL diagnostics without opening the prevention gate.
3. Explain the queue's `kernel_owned=false` / `rows=0` / `shadow_rows>0` values against the actual AegisWfp driver contract; validate expected image hash, loaded image, device path, and IOCTL readback.
4. Attribute the minifilter/queue loss deltas and define whether they are expected overload, stale counters, or silent loss. Do not reset or hide counters to make readiness green.
5. Once all surfaces agree and readiness is genuinely healthy, rerun current-source preflight, then execute the bounded RB-021 canary and record event attribution/forensic verification.

## Patch contract (investigation record only)

- **PATCH-ID:** STOPLINE-WFP-READINESS-001
- **FLOW-ID:** RB-021 / PEP provider readiness and telemetry status
- **TARGET HEAD:** `8f7c84d84a50f189491f82df18f5d0c3ac24c7bc`
- **TARGET FILES:** this record and current phase/evidence records only
- **IN SCOPE:** preserve observed live evidence and block ambiguous canary qualification
- **OUT OF SCOPE:** source implementation, driver changes, prevention activation, VM changes
- **CONTRACT / ABI / AUTHORITY / STATE IMPACT:** none; no code changed
- **TEST IMPACT:** none; observation only
- **EVIDENCE IMPACT:** E5 runtime observation; not a canary or qualification pass
- **ROLLBACK:** remove this investigation record and its index/phase references if evidence is superseded with provenance
- **REMAINING RISK:** provider readiness disagreement and telemetry loss unresolved
- **OPEN BLOCKERS:** existing issue #25 authority reconciliation, #29 telemetry loss, #30 lifecycle, plus this stop-line finding
- **COMPLETION GATE:** FAIL for RB-021 canary; continue only after provider/driver state is reconciled
