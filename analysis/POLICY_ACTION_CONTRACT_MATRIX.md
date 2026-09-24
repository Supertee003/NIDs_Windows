# AEGIS Policy Action Contract Matrix

## Finding

The repository contains more than one action vocabulary. The canonical event and policy-engine path use one ordinal set, while the legacy `policy_ir.zig` and Rust PEP request constants use another set. This must be resolved before any Rules 22 block proof.

## Observed definitions

| Authority or file | ALLOW/PASS | ALERT | BLOCK | QUARANTINE | RATE_LIMIT | LOG_ONLY | Additional |
|---|---:|---:|---:|---:|---:|---:|---|
| `ts_policy/src/types.ts:87-94` | 0 | 1 | 2 | 3 | 4 | 5 | authoring contract |
| `src/contract/canonical_event.zig:260-267` | 0 | 1 | 2 | 3 | 4 | 5 | canonical event contract |
| `src/policy/policy_contract.zig:47-63` | 0 | 1 | 2 | 3 | 4 | 5 | converts to canonical action |
| `src/policy/policy_engine.zig:27-34` | 0 | 1 | 2 | 3 | 4 | 5 | says it matches canonical |
| `src/policy/policy_ir.zig:18-26` | 0 (`pass`) | 2 | 4 | 5 | 3 | 1 (`log`) | legacy IR; also has `escalate=6` |
| `rust-src/lib.rs:198-205` | 0 (`pass`) | 2 (`alert`) | 4 | 5 | 3 | 1 (`log`) | Rust PEP request ABI |

## Interpretation

The intended canonical action set appears to be the six-value set used by TypeScript, `CanonicalEvent`, `policy_contract.zig`, and `policy_engine.zig`:

```text
ALLOW      = 0
ALERT      = 1
BLOCK      = 2
QUARANTINE = 3
RATE_LIMIT = 4
LOG_ONLY   = 5
```

The `policy_ir.zig` and Rust PEP values are not numerically compatible with that set. Their values may be a separate legacy/internal ABI, but the boundary is not currently expressed as a versioned conversion contract. Passing a canonical action directly into either legacy/Rust ordinal domain would be unsafe.

## Decision required before block proof

1. Keep the canonical action values above as the Rules 22 decision authority.
2. Add an explicit, named conversion at the PEP boundary from canonical policy action to Rust request action; do not rely on numeric equality.
3. Version and test the conversion with golden vectors for all six actions.
4. Mark `policy_ir.zig` legacy actions as non-authoritative until its loader and conversion path are confirmed.
5. Add a per-rule mapping from `configs/Rules.json` rule ID to canonical policy ID/action. The six generic entries in `configs/policies.json` are not sufficient for individual Rule qualification.

## Current safety status

The prevention gate remains closed. No action ordinal should be changed in-place until the active loader path is verified, because changing an enum can alter existing detection behavior. The next implementation patch should be an explicit conversion plus tests, not a global renumbering.

## Acceptance criteria

A Rules 22 block candidate may proceed only when:

- TypeScript emits the canonical action value.
- Zig decision evaluation preserves the canonical action.
- Zig-to-Rust conversion is explicit and tested.
- Rust receives the intended request action.
- A block decision cannot be produced from an unsigned or unmapped Rule.
- The resulting receipt records the Rule ID and canonical action.
