# PEP Quarantine Status: IMPLEMENTED (QUAR-RCPT-112)

Updated 2026-10-19. Supersedes the earlier "deferred" status.

## Current state

Quarantine is implemented and executes through the Rust PEP as a per-flow
traffic constraint. No separate filter class exists below the PEP: the
primitive is the same WFP flow-block used by `block`, and the quarantine
semantics travel in the returned decision/receipt (`DECISION_QUARANTINE`),
which the Zig verifier keys on.

Where it lives (verified at this HEAD):

- `rust-src/lib.rs` - `ACTION_QUARANTINE` clears the same bars as block:
  capability bit `0x01`, the severity >= 7 two-person approval gate, the
  shared per-source quota window (T3-QUOTA), and adapter execution that
  mints a `filter_id`. If the WFP adapter is absent the decision fails
  closed to `DECISION_ESCALATE` (reason 4). Evidence: EVI `EVT-112`
  (landed `82e9f4a`, "per-flow quarantine enforced"), with Rust pins
  `pep_quarantine_no_capability_returns_escalate_with_reason`,
  `pep_quarantine_without_adapter_fails_closed_no_filter` and
  `high_severity_quarantine_without_approval_escalates_for_approval`.
- `src/policy/pep_bindings.zig` - `enforceQuarantineFlow(...)` mirrors the
  block entry point and fails closed without a provider (pinned by
  `QUAR-RCPT-112: enforceQuarantineFlow fails closed without provider`).
- `src/control/handler_registry.zig` - the control-plane quarantine
  request path: prevention-gate check first (`PREVENTION_GATE_CLOSED`
  while the gate is closed), then `enforceQuarantineFlow`, then an
  exact-filter read-back (`queryFilterResult`); a mismatched or absent
  filter is cleaned up and rejected as `POSTCONDITION_FAILED`, and only
  then is an `EnforcementReceipt` minted.

## What gates quarantine live (by design)

- Prevention gate: closed in every default/production build
  (`-Dlab-prevention-gate` off); the lab opening requires the RB-012 /
  RB-013 sequence on an isolated lab VM.
- Live production daemon currently runs detection-only (operator redeploy
  pending); `blocks delta 0`.
- Drivers are test-signed until production signing (EV certificate / HLK).

## History

The previous version of this file described quarantine as "deferred"
(enqueued for retry, never executed) and pointed at proof/test files
under the removed `core` tree. That description stopped being true when
QUAR-RCPT-112 landed (EVT-112): quarantine now executes through the same
WFP flow-block path, gated exactly like block.
