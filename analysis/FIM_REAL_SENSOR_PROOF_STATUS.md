# AEGIS Real FIM Observe-Only Proof Status

## Current finding

The Windows FIM native helper uses `ReadDirectoryChangesW` and the runtime worker polls its raw notification buffer. The worker currently wraps that buffer in an `IpcEvent` with `kind=fim_change` and `source=capture_fim`, then sends it to the pipeline queue. This is a real sensor path, but it is not yet a fully normalized `FimEvent`/canonical file-event adapter: the raw `FILE_NOTIFY_INFORMATION` payload is carried as detector payload.

## Safe proof change

`src/pipeline/telemetry_threads.zig` now supports the opt-in environment variable `AEGIS_FIM_PROOF_ROOT`. When set, the daemon watches only that operator-selected directory. When unset, the existing production defaults remain `C:\Windows\System32` and `C:\Windows\SysWOW64`. This prevents the proof from modifying Windows system directories.

## Proof runner

Use `scripts/run_fim_real_observe_only_proof.ps1` only after rebuilding and restarting the daemon with the same `AEGIS_FIM_PROOF_ROOT` value. The runner creates one benign marker file, waits, verifies the marker, and never calls WFP, PEP, block, or unblock operations. Its `passed=true` result proves fixture creation only; it must not be treated as proof that the daemon matched a rule.

## Acceptance gate still required

The real sensor proof is complete only when daemon evidence shows all of the following for the marker event: `source=capture_fim`, `kind=fim_change`, pipeline processed delta at least one, forensic record delta at least one, and no enforcement/host-effect delta. A later adapter step should parse `FILE_NOTIFY_INFORMATION` into `FimEvent` and expose the filename/action as structured metadata before claiming Rule-22 matching coverage for file rules.

## Host procedure

```powershell
$root = "$env:TEMP\aegis-fim-proof"
$env:AEGIS_FIM_PROOF_ROOT = $root
# Rebuild and restart the development daemon from this same environment.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_fim_real_observe_only_proof.ps1 -ProofRoot $root
```

The current phase is therefore **real FIM ingress prepared, safe fixture path added, canonical structured parsing and evidence correlation still pending**.
