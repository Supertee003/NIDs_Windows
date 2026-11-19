# POLICY-MUTATE-001 — Patch Record (E2)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | POLICY-MUTATE-001 |
| FLOW-ID | CONTROL-001 (control verb → evidence verdict) |
| TARGET HEAD | `683ff20` |
| FINAL HEAD | this commit |
| TARGET FILES | `src/control/protocol.zig`, `src/pipeline/runtime_state.zig`, `src/pipeline/event_processor.zig`, `src/control/handler_registry.zig`, `src/daemon.zig`, `tools/aegisctl.py`, `shared/protocol/control_protocol.md`, `docs/USER_OPERATIONS_GUIDE.md`, `docs/OPERATOR_COMMAND_MAP.md`, `docs/AEGIS_Command_Capability_Matrix.md`, `tests/tools/test_policy_mutate.py`, 3 inverted test modules |
| TARGET SYMBOLS | `Command.policy_enable/disable/reload`, `g_policy_evaluation_enabled`, `g_live_policy_set`, `effectivePolicySet`, `publishPolicySet`, `freeRetiredPolicySets`, `policyEnable/Disable/Reload`, `_policy_mutation` |
| IN-SCOPE | privileged evidence-verdict gate, honest live-set swap, read-back postconditions, CLI verbs, contract docs |
| OUT-OF-SCOPE | detection match, severity, forensic record shape, PEP branch, host effects, CanonicalEvent wire/codec, signed-IR promotion, E5 |
| CONTRACT IMPACT | three new `PRIVILEGED` / `is_mutation` / `has_postcondition` commands (604–606); no wire change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | control-plane only; no enforcement or host authority moves; still detection-only |
| STATE IMPACT | one atomic bool, one atomic pointer, a mutex-guarded retired list, one generation counter; all process-local |
| TEST IMPACT | 3 Zig tests + 8 CLI E2 tests + 3 inverted legacy pins |
| EVIDENCE IMPACT | E2 entry `POLICY-MUTATE-001-E2-20261119`; no E5 claim |

## Old flow → New flow

`policy enable/disable/reload → CLI returns _unavailable (exit 4), no daemon path, disabled_rules.json suggested as a substitute`
→
`policy enable/disable → privileged control verb → atomic evidence-verdict gate (read-back postcondition); policy.reload → read configs/policies.json → parse immutable set → atomic pointer swap → generation bump → CLI verifies status + postcondition + count`

## Invariant

`state.effectivePolicySet(ps)` returns null only when the evidence gate is OFF. The rule-match condition (`matched_rule_id != 0`, host-source exclusion) stays OUTSIDE the gate; the PEP branch is below it and unchanged. Published sets are immutable; a swap never mutates a live set. Retired sets are freed only at shutdown after `supervisor.shutdown()` has joined every worker (LIFO defer). Reload with zero loadable policies keeps the previous set and fails closed. No `disabled_rules.json` or other local write is performed by the mutation verbs.

## Verification

- `zig fmt` PASS; `zig build test --summary all` PASS (2131/2142, 11 skipped, 0 failed)
- `python -m pytest tests/tools/test_policy_mutate.py tests/runtime/test_gate_e.py tests/tools/test_operator_honesty.py tests/docs/test_stale_doc_sweep.py -q` 35 passed, 9 subtests passed

## Evidence level

E2. No E5: no claim that a live installed daemon executed these verbs. The old signed candidate's soak ended in a documented terminal FAIL; this source is outside that window.

## Rollback

Revert this commit. The gate defaults to ON and `g_live_policy_set` to null, so removing the code restores the original direct `ps.evaluate` call and the fail-closed CLI verbs.

## Remaining risk / blockers

- Live-set swap lifetime relies on the shutdown-only free after thread joins; a future worker spawned outside `RuntimeSupervisor` would break that assumption (static pin added).
- Reload mirrors the startup trust opt-in; an unverified envelope leaves the new set untrusted rather than refusing it (identical to startup behaviour, observe-only).
- No E5 host proof until a new signed candidate is installed and the owner names a fresh soak window.

## Completion gate

Zig + targeted E2 suites PASS, no wire change, no detection gating, no host effect, no local state write — **PASS (E2)**.
