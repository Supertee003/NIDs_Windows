# AEGIS Phase 8–10 Runtime Runbook

## Phase 8: lifecycle/recovery

Start the daemon from an elevated PowerShell using `zig build run`. In a second elevated PowerShell, verify health and forensic integrity. Run `scripts/run_lifecycle_recovery_proof.ps1` with a bounded wait. The accepted post-restart state is Rust Shield `READY`, all required workers ready, forensic verification true, and `overall_gate=false` while WFP or Tier-3 is unavailable.

The proof must not interpret a textual `stop` acknowledgement as a health result. It must query health and readiness after the command. A denied stop is an authorization result and does not constitute a lifecycle proof.

## Phase 9: Tier-3 readiness

Do not infer readiness from a DLL existing on disk. Verify artifact presence, dependency loading, provider readiness, health response, timeout behavior, and failure recovery separately. A missing or failed dependency must produce `tier3.ready=false`, `provider_ready=false`, and `host_effect_capable=false`.

## Phase 10: WFP host-effect proof

This phase is gated. It may start only after Rust Shield provider readiness and Tier-3 prerequisites are independently verified. A successful action must produce a provider identifier, a host postcondition, and an `ENFORCED` receipt with `host_effect_confirmed=true`. Without all three, the result is not enforcement.

No runtime proof in this runbook should bypass the control plane, use direct firewall commands, or convert a policy request into a host-effect claim.
