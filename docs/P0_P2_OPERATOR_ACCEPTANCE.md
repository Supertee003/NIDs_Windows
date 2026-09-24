# AEGIS P0–P2 Operator Acceptance

## P0 contract freeze

The operator contract is defined in `contracts/operator_contract_v1.json`. Policy actions and PEP response decisions are separate namespaces. The canonical policy value for `BLOCK` is `2`; the PEP response value for `BLOCK` is `1`. A provider-specific action value must never be compared directly with a policy action value.

`EnforcementReceipt` version 1 is the only source that may produce `BLOCKED_CONFIRMED` in an operator view. A valid confirmed receipt requires an enforced status, confirmed host effect, non-zero request/event/trace/audit/filter identities, and a provider name. `READY`, `provider_ready`, or a policy action alone is not a confirmed host block.

## P1 operator projection

`tools/aegisctl/contracts.py` provides the shared projection used by the web dashboard. The projection exposes `OBSERVE_ONLY` while the prevention gate is closed, even if a provider is present. Incident records are normalized without inventing enforcement state.

The backend remains authoritative: web, CLI, and native views must consume the Zig control response or a forensic record. They must not mutate WFP or infer blocking from a log line.

## P2 web surface

`tools/aegisctl/web_dashboard/app.py` now exposes `/api/snapshot`, `/api/status`, `/api/incidents`, `/stream`, `/health`, `/rules`, and `/health/check`. These endpoints are read-only and share one snapshot projection.

The native dashboard now counts a block only when a complete receipt is present. A policy/event label alone is never counted as a confirmed host effect.

## Validation boundary

Python contract and health tests pass in the sandbox. Windows acceptance is still required for real FIM mutation under `AEGIS_FIM_PROOF_ROOT`, real VMnet1 WFP observation, cross-language build/ABI tests, and the eventual controlled host-effect proof. The prevention gate remains closed.
