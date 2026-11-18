# ACTION-SPACES-001 — four action enums, three numberings, one of them swapped

**Created:** 2026-11-14
**Build source:** this patch touches `src/tests/proofs/pep_enforcement_proof.zig`
(`zig build` and `zig build test` exit 0)
**Level:** E2 (8 pins) + E1 for the transposition itself

---

## 1. What was found

Reading every declaration of an "action" ordinal in the tree:

| Declaration | Ordinals |
|---|---|
| `src/contract/canonical_event.zig` `PolicyAction` | allow0 alert1 **block2 quarantine3 rate_limit4** log_only5 |
| `src/forensic/policy_contract.zig` `PolicyAction` | identical (its own test pins it) |
| `src/policy/policy_engine.zig` `EnforcementAction` | identical |
| `src/tests/proofs/pep_enforcement_proof.zig` `EnforcementAction` | allow0 alert1 block2 **rate_limit3 quarantine4** log_only5 |
| `src/policy/policy_ir.zig` `Action` | pass0 log1 alert2 rate_limit3 **block4** quarantine5 escalate6 |
| `rust-src/lib.rs` `ACTION_*` | identical to `policy_ir.Action` |

Two findings:

1. **The proof harness transposed quarantine and rate_limit.** Its enum claims to
   mirror the enforcement vocabulary, sits in `u8` fields of structs the proof
   compares, and its output is evidence — yet it numbered the two restricted
   actions the other way round from every module it exists to prove.
   `src/policy/policy_contract.zig` even has a test named "quarantine and
   rate_limit are not interchangeable". Nothing executed wrongly because the
   proof only compared tags, but a declared ordinal space that disagrees with the
   contract is exactly the kind of thing a later `@intFromEnum` inherits.
2. **The FFI action space was declared nowhere.** `policy_ir.Action` (seven
   values, `BLOCK = 4`) is the `requested_action` ABI the Rust PEP receives
   (`pep_bindings.zig`: "requested_action uses the policy.Action ABI, not
   PepDecision"), and Rust mirrors it exactly — but `contracts/operator_contract_v1.json`
   documented only two of the three spaces, so a reader comparing "policy action"
   BLOCK against the FFI would find 2 against 4 with no document saying why.

## 2. What changed

- `src/tests/proofs/pep_enforcement_proof.zig`: enum renumbered to
  `quarantine = 3, rate_limit = 4` with a comment naming the four modules that
  share the space and the existing "never swap" test. Comments and ordinals only;
  `zig build` and `zig build test` exit 0.
- `contracts/operator_contract_v1.json`: new `pep_request_action_ordinals`
  (PASS0 LOG1 ALERT2 RATE_LIMIT3 BLOCK4 QUARANTINE5 ESCALATE6) plus
  `pep_request_action_note` stating that three spaces exist and none may be
  compared with another — "convert, never cast".
- `tests/contracts/test_action_spaces.py` (8 pins):
  - every declaration of the canonical space (four files) equals
    `policy_action_ordinals`;
  - `policy_ir.Action` and Rust `ACTION_*` equal `pep_request_action_ordinals`;
  - the two spaces still collide if compared by ordinal (frozen 4 = QUARANTINE is
    FFI 4 = BLOCK; frozen 2 = BLOCK is FFI 2 = ALERT) — the pins assert the
    collision exists so the note stays true;
  - no `.zig` file casts an action into a canonical `policy_action` byte
    (`policy_action = @intFromEnum(...)`, `@enumFromInt(... .action)`);
  - the named converter in `src/policy/policy_contract.zig` still exists and still
    goes through `intToEnum` rather than a cast.

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/contracts/test_action_spaces.py tests/contracts/test_operator_contract.py` | 16 passed |
| `zig build` | exit 0 |
| `zig build test` | exit 0 |
| mutation: restore the transposed proof enum | 1 failed (`test_canonical_action_space_is_identical_everywhere[src/tests/proofs/pep_enforcement_proof.zig]`) |
| restored | 8 passed |

## 4. Limitations

1. **E2.** The proof harness was not run against a live PEP; only its declared
   ordinal space was corrected.
2. **The ban is syntactic.** It catches the two cast shapes that exist in the
   codebase today (`policy_action = @intFromEnum(...)`, `@enumFromInt(... .action)`);
   a cast through an intermediate variable would pass.
3. **`policy_ir.Action` legitimately differs.** It is not wrong — it is a
   different ABI with `pass` and `escalate`. This patch documents it; it does not
   unify it, and unifying it would be a wire change with its own evidence.
4. **`ACTION_*` in Rust is asserted equal to the contract, not to `policy_ir.Action`
   directly** — the contract is the middle term by design (three-way agreement:
   contract ↔ Zig, contract ↔ Rust).
