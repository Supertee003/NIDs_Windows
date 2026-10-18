# RB-012: WFP BLOCK Live Proof (Isolated Lab VM ONLY)

> **NEVER run on production.** This runbook performs real host-effect
> enforcement (WFP flow-block). Lab VM must be isolated (host-only
> network), and targets are restricted to documentation ranges below.
> A mistaken target on a production host is a self-inflicted outage.

## Objective

Prove end-to-end that a `block` decision becomes a live WFP filter:
request -> two-person approval (severity-gated) -> ENFORCED receipt ->
read-back verification -> rollback. Every step names its postcondition;
anything else is not proof.

## Prerequisites

- Lab VM with the AEGIS service installed from a release build.
- Prevention gate OPEN and provider ready (see step 1). Default posture
  is detection-only; that is correct everywhere except this runbook.
  Gate open comes ONLY from a lab-qualification build
  (`zig build -Dlab-prevention-gate=true`, see
  docs/SLICE_C_LAB_GATE_DESIGN.md): default/production builds have no
  code path that can open it, and the gate re-closes on restart.
- Signed policy trust established (step 2). Unsigned policy can never
  enforce (fail-closed by construction).
- Target: a TEST-NET address that answers no production role. Sanctioned:
  `203.0.113.10` (TEST-NET-3 canary), `192.0.2.10` (TEST-NET-1 WFP
  proof). Never production peers, never the lab gateway.

## Steps

1. **Confirm enforcement posture** (read-only):
   ```
   python tools/aegisctl.py enforce status
   ```
   Require: `prevention_gate:"open"`, `gate_source:"lab-build-optin"`,
   `provider_ready:true`, `host_effect_capable:true`,
   `enforcement_mode:"provider-attested-enforcement-enabled"`.
   Anything else: STOP (posture is detection-only; see step 2).

2. **Establish signed-policy trust** (one-time per policy file):
   - Set `AEGIS_POLICY_ENFORCE_TRUSTED=1` in the service environment.
   - Produce `configs/policies.sig.json` over the exact
     `configs/policies.json` bytes with a trusted anchor
     (`configs/policy_trust.json` or `AEGIS_POLICY_PUBKEY`).
   - Verify: `python tools/aegisctl.py policy verify` must report
     top-level `verified:true` (enforcement envelope).
   - Restart the service so the daemon loads the trusted set.

3. **Enable the two-person rule** (severity >= 7 requires approval):
   ```
   python tools/aegisctl.py enforce two-person on
   ```
   Expect `{"two_person_rule":true,"postcondition":"SET"}`.

4. **Issue the block** through the control plane (the CLI `block add`
   verb is intentionally list-only and does nothing — Gate-E pin).
   The two-person match keys on an operator-chosen ceremony identity
   (the daemon's control counter is shared with pipeline audit entries
   at 1000+/s and cannot be predicted — approve-then-hit is unwinnable,
   so identity travels in the payload instead):
   ```powershell
   python -c "import sys; sys.path.insert(0,'D:/NIDs_Windows/tools'); from aegisctl.api.control_api import query_control; print(query_control('enforcement.approve', {'request_id': 91001})); print(query_control('enforcement.block', {'dst_ip': 3405803786, 'dst_port': 443, 'protocol': 6, 'policy_id': 3, 'event_id': 9001, 'trace_id': 9001, 'severity': 9, 'request_id': 91001}))"
   ```
   (`dst_ip` is the u32 integer: 203.0.113.10 = 3405803786. Use any
   fresh nonzero ceremony id per attempt; approvals are one-shot and
   an id never authorizes twice.)
   Expect `{"approved":true,"postcondition":"RECORDED"}` from the first
   call and the ENFORCED receipt (see Verification) from the second.
   The daemon mints no identity of its own here: approve(X), then a
   block carrying request_id=X, at any pace — the approval sits pending
   until the matching block consumes it. If the block answers
   ESCALATE reason 2, the approval did not match (wrong id or already
   consumed): pick a fresh id and repeat steps 4-5 together.

5. **Verify the live filter** (postcondition, not vibes — there is no
   CLI verb for this; call the control plane directly):
   ```powershell
   python -c "import sys; sys.path.insert(0,'D:/NIDs_Windows/tools'); from aegisctl.api.control_api import query_control; print(query_control('enforcement.verify', {'filter_id': <filter_id>, 'dst_ip': <u32>, 'dst_port': 443, 'protocol': 6}))"
   ```
   Require `{"verified":true,"present":true,"postcondition":"MATCH"}`
   with the exact tuple echoed back.

6. **Prove traffic effect**: from the lab VM,
   `Test-NetConnection 203.0.113.10 -Port 443` must fail while the
   filter is present (and succeed after step 7).

## Verification

- Receipt: `status:"ENFORCED"`, `decision:"block"`, `provider:"wfp"`,
  `host_effect_confirmed:true`, `receipt_version:1`,
  `request_id/event_id/policy_id/filter_id/trace_id/audit_id` all > 0.
- Read-back: `enforcement.verify` returns MATCH (step 5).
- Traffic: blocked during, reachable after rollback (step 6/7).
- Record all IDs + filter ID + receipt version (operator release
  §10.7: a `BLOCK` without them is `BLOCK_REQUESTED`, never `BLOCKED`).

## Rollback

```
enforcement.unblock {"filter_id": <filter_id>}
```
Require `{"status":"ROLLED_BACK","present":false,"postcondition":"ABSENT"}`.
Still present: `CLEANUP_POSTCONDITION_FAILED/ROLLBACK_PENDING` — do not
leave the lab; escalate with the filter ID. Never use IP-only unblock
for proof (receipt-unaware).

## Notes

- `block add/remove`, `enforce enable/disable/push` stay refused by
  Gate-E pins even in the lab (CLI never touches the PEP).
- Quota: 100 blocks/sec/source shared with quarantine; exhaustion
  escalates, never allows.
- RB-001's "WFP tracking-only" note is stale post-Phase-8: provider
  reports READY with live filters on an open gate.

## References

- Control contract: `src/control/protocol.zig` (enforcement.* 800-806),
  handlers `src/control/handler_registry.zig` (status/simulate/verify/
  block/unblock/two_person/approve).
- Trust gating: `src/daemon.zig` (policy load), `src/policy/pep_bindings.zig`
  (trusted path), `rust-src/lib.rs` (two-person, quota, receipts).
- Receipt validity gate: `tools/aegisctl/api/control_api.py`
  (is_valid_enforcement_receipt).
- Pinned CLI behavior: `tests/security/test_cli_mutation_gate.py`.
