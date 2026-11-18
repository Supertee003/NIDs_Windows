# WARDEN cutover spec — receipt-gated enforcement, LAB ONLY (EVT-153)

## Verified production state (2026-10-10, this host)

- `aegiswfp` kernel driver service: RUNNING (`sc.exe query aegiswfp`).
- Daemon `enforcement.status`: `tier3 READY`, `pep_available true`,
  `provider_ready true`, but `tier3_enforcing false`,
  `host_effect_capable false`, `enforcement_mode "detection-only"`,
  `prevention_gate "closed"`, `receipt_required true`.
- `runtime_manifest.json` note: detection-only until a provider-owned,
  receipt-producing WFP adapter is connected; no host block is claimed.
- Security reviews (`.analysis/security.md`) require detection-only until
  P0/Gate A–E pass on a Windows host at current HEAD.

Conclusion: the provider path is READY but the enforcing cutover is
unproven. Flipping it on the production host is forbidden by this spec.

## Cutover preconditions (lab/VM only)

1. Lab VM snapshot taken; host isolated from production traffic.
2. Test-signed driver + user-mode provider from the SAME HEAD
   (`drivers/wfp_callout/`, `src/windows/wfp_ioctl.c`,
   `src/policy/wfp_production.zig`).
3. Forensic ring healthy (`forensics.verify` passes) so every canary
   block lands in evidence.

## Cutover steps (lab)

1. Enable receipt-gated enforcement in lab config (never `configs/`
   on prod): provider must return a validated `EnforcementReceipt`
   per block; without a receipt the decision stays observe-only
   (fail-closed, same rule as prod).
2. Fire a canary block against lab attack traffic (pair with the Kali
   kit: `scripts/kali_attacks/*`); assert postcondition per block:
   `BLOCKED_CONFIRMED` appears ONLY with receipt + host postcondition
   (filter hit + connection actually dead), recorded in forensics.
3. Soak 24h lab: zero `PEP_UNVERIFIED` escalations, zero receipt
   mismatches, ring verifies end-to-end, replay reproduces.
4. Rollback drill: restore detection-only + `host_effect_capable=false`
   in under 5 minutes, with evidence intact.

## Confirmation gate (all must hold)

- `enforcement_mode` reports enforcing ONLY in lab, with receipts.
- No in-memory `.block`, log line, or exit code is ever cited as a
  host-block proof (see `.analysis/security.md:23`).
- Minifilter (`drivers/minifilter/`, currently quarantined) stays OUT
  of the cutover until its own Gate D evidence exists.

## Non-goals on the production host

No enforcement flip, no driver reinstall/re-sign, no filter changes.
Prod keeps: driver RUNNING (telemetry path), gate closed, receipts
required. Revisit only with lab gate evidence at current HEAD.
