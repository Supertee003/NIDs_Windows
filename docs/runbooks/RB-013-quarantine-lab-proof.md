# RB-013: Quarantine Positive-Path Proof (Isolated Lab VM ONLY)

> **HISTORICAL/LAB REFERENCE — OUT OF PRODUCT SCOPE.** This document is
> retained for provenance and must never be treated as a production feature
> or activation roadmap for the detection-only Kernel NIDS.

> **NEVER run on production.** Quarantine is a host-effect decision
> executed through the WFP flow-block primitive. Same isolation and
> target rules as RB-012 (host-only lab network, TEST-NET targets only).

## Objective

Prove a quarantine decision end to end: severity-gated request ->
two-person approval -> `DECISION_QUARANTINE` with `filter_id` ->
receipt capture (Zig mirror) -> read-back verification -> rollback.
The acceptance criterion is the receipt's `decision` field reading
`quarantine` (not `block`), because the two decisions share the WFP
primitive and only the receipt distinguishes them.

## Prerequisites

- RB-012 steps 1-3 complete (open gate, provider ready, signed-policy
  trust, two-person rule ON). Quarantine requires the same posture plus
  severity >= 7 (the two-person gate ignores lower severities).
- Elevated shell for the mutating steps (3 and 6): `approve`,
  `quarantine` and `unblock` are privileged-only control verbs — the
  role comes from the client token elevation (same rule as RB-012).
- Target: TEST-NET only (`203.0.113.10` preferred; never production).

## Steps

1. **Confirm posture**: `enforce status` shows open gate, provider
   ready, host-effect capable (RB-012 step 1). Confirm two-person is
   still ON.

2. **Request quarantine** (severity 8-10 so the two-person gate
   engages) through the quarantine verb (the CLI `quarantine add` verb
   is list-only by Gate-E pin and does nothing). First project the
   posture (read-only, must answer honestly):
   ```
   python tools/aegisctl.py enforce simulate --action quarantine --severity 8
   ```
   On an open gate with provider ready, expect `outcome:"would_request"`
   (on a closed gate: `outcome:"allow"` with `reason` starting
   `prevention_gate_closed;` — that answer is correct, not a failure;
   open the gate per RB-012).

3. **Issue + approve with ceremony identity** (same workable ceremony
   as RB-012 step 4 — the daemon's control counter races at 1000+/s,
   so identity travels in the payload):
   ```powershell
   python -c "import sys; sys.path.insert(0,'D:/NIDs_Windows/tools'); from aegisctl.api.control_api import query_control; print(query_control('enforcement.approve', {'request_id': 92001})); print(query_control('enforcement.quarantine', {'dst_ip': 3405803786, 'dst_port': 443, 'protocol': 6, 'policy_id': 3, 'event_id': 9002, 'trace_id': 9002, 'severity': 9, 'request_id': 92001}))"
   ```
   Use a fresh nonzero ceremony id per attempt (one-shot approvals).

4. **Confirm the decision field**: the returned receipt must read
   `"decision":"quarantine"` with non-zero `filter_id`. A receipt
   reading `"decision":"block"` is a valid ENFORCEMENT proof but NOT a
   quarantine proof — record which one happened (both outcomes are
   evidence; only mislabeling is failure).

5. **Confirm Zig-mirror capture**: the daemon logs show the quarantine
   receipt captured (`QUARANTINED_CONFIRMED`, `g_confirmed_quarantines`
   incremented). Without a receipt the outcome stays best-effort and
   the counter is untouched by design.

6. **Verify + rollback**: `enforcement.verify` with the receipt tuple
   (RB-012 step 5, expect MATCH), then `enforcement.unblock`
   `{"filter_id"}` (RB-012 rollback, expect ROLLED_BACK/ABSENT).
   Quarantine filters have no separate release verb — `filter_id`
   addressed unblock is the only cleanup identity.

## Verification

- Receipt `decision:"quarantine"`, `filter_id` non-zero,
  `host_effect_confirmed:true`, full v1 receipt fields.
- `enforcement.verify` MATCH on the receipt tuple.
- Mirror counter incremented (QUARANTINED_CONFIRMED observed).
- Rollback ROLLED_BACK/ABSENT; traffic test as in RB-012 step 6.

## Rollback

Same as RB-012 (filter-addressed unblock). IP-only unblock is
receipt-unaware and rejected for proof.

## Notes

- Quota (100/sec/source) is SHARED between block and quarantine;
  exhaustion escalates, never allows.
- RB-001's "quarantine DEFERRED" note is stale: the two-person gate,
  adapter execution, quota sharing, and Zig receipt mirror all landed
  (EVT-112/113); this runbook is the lab proof that was deferred, not
  the implementation.
- First-match note: keep severity >= 7 or the gate never engages and
  the runbook degrades to a block proof — label it as such.

## References

- Rust gates: `rust-src/lib.rs` (two-person, quota, DECISION_QUARANTINE,
  adapter, receipts).
- Zig mirror: `src/policy/pep_bindings.zig` (enforceQuarantineFlow,
  receipt capture), `src/policy/action_dispatcher.zig` (confirmation).
- Control verbs: `src/control/handler_registry.zig`
  (simulate/approve/verify/unblock); CLI pins:
  `tests/security/test_cli_mutation_gate.py`.
