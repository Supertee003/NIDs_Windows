# CONTRACT-OPERATOR-001 — a contract with no reader, and a stale claimant inside it

**Created:** 2026-11-14
**Build source:** `069356b` -> this patch touches `src/forensic/integration_contract.zig`
so the build source moves with the commit (`zig build` and `zig build test` exit 0)
**Level:** E2 (8 pins) + E1 for the enum mismatch itself

---

## 1. What was wrong

`contracts/operator_contract_v1.json` declares the two ordinal spaces an operator
compares, plus the rule that motivates the file:

> `PolicyAction` and `PepDecision` are different namespaces; their BLOCK values
> must not be compared directly.

**Nothing in the repository read it.** `git grep` found the file only in
`README.md`, two design docs and the generated maps — no code, no test. So the
two numbers it declares could drift from the enums and nobody would notice. Two
had:

| Space | Contract says | Code said |
|---|---|---|
| `policy_action_ordinals` | ALLOW 0, ALERT 1, BLOCK 2, QUARANTINE 3, RATE_LIMIT 4, LOG_ONLY 5 | matches in `src/contract/canonical_event.zig` **and** `src/forensic/policy_contract.zig` |
| `pep_decision_ordinals` | ALLOW 0, BLOCK 1, RATE_LIMIT 2, QUARANTINE 3, **ESCALATE 4**, **DROP 5** | `src/policy/pep_bindings.zig` has six; `rust-src/lib.rs` `DECISION_*` has six; **`src/forensic/integration_contract.zig` had four** |

The forensic copy of `PepDecision` stopped at `quarantine = 3`. Its own inline
test checked exactly the four shared ordinals, so `zig build test` was green
while the two Zig enums disagreed about the two values the assessment path
actually returns (`pep_bindings.zig` returns `.escalate` when the PEP is
unavailable, and guards on `.drop`). Any code taking a `u8` decision from Rust
and matching it against the forensic enum had no member for 4 or 5.

Second unread file in the same sweep: `shared/protocol/protocol_version.json`.
Its `version`, `magic`, `header_size`, `max_payload`, `canonical_event_magic` and
`canonical_event_version` are all hard-coded in `shared/wire/wire_codec.py`
(`WIRE_VERSION`, `WIRE_MAGIC`, `WIRE_HEADER_SIZE`, `WIRE_MAX_PAYLOAD`,
`EVENT_MAGIC`, `EVENT_VERSION`). They agree today; nothing kept them agreeing.

## 2. What changed

- `src/forensic/integration_contract.zig`: `PepDecision` now declares all six
  ordinals with a comment naming `src/policy/pep_bindings.zig` as the live
  authority and stating that the values must not be renumbered. The existing
  inline test keeps checking the four it checked before; the new Python pin is
  what compares the full space.
- `tests/contracts/test_operator_contract.py` (8 pins):
  - `policy_action_ordinals` equals `PolicyAction` in both Zig definitions;
  - `pep_decision_ordinals` equals `PepDecision` in both Zig files and agrees
    with the Rust `DECISION_*` constants, and Rust still declares
    `escalate`/`drop` (the reason the contract lists them);
  - `PolicyAction.BLOCK != PepDecision.BLOCK` — the file's own rule, enforced,
    so a comparison-by-ordinal bug cannot be introduced without deleting a test;
  - the enforcement-receipt requirement list is non-empty and still versioned;
  - `shared/protocol/protocol_version.json` equals the six `wire_codec.py`
    constants;
  - every un-fixtured contract file (`contracts/operator_contract_v1.json`,
    `shared/protocol/protocol_version.json`, `shared/runtime/components.json`)
    is named by some code or test in the working tree — the census that would
    have caught the original problem.

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/contracts/test_operator_contract.py` | 8 passed |
| `zig build` | exit 0 |
| `zig build test` | exit 0 |
| ordinal comparison | policy BLOCK = 2, pep BLOCK = 1 (the contract's rule holds) |

The mutation that this pin would have caught is the historical one: before this
patch the forensic enum had four members, so `test_pep_decisions_match_every_implementation`
fails against it.

## 4. Limitations

1. **This is the contract's first reader, not a runtime check.** The daemon does
   not consult `operator_contract_v1.json`; the pin makes the JSON true, not
   load-bearing.
2. **`ACTION_*` in `rust-src/lib.rs` is a third space.** It declares
   PASS 0, LOG 1, ALERT 2, RATE_LIMIT 3, BLOCK 4, QUARANTINE 5, ESCALATE 6 and a
   comment calls them "policy-action ordinals from src/policy/policy_ir.zig" —
   which is a *different* numbering from the frozen `PolicyAction` (ALERT 1,
   BLOCK 2). It is used internally by the PEP request path, so it is not a bug
   per se, but the operator contract does not mention it and this patch does not
   claim it is consistent. That is the next question in this area.
3. **The census matches file names, not imports.** A comment naming the file
   counts as a reader. It answers "does anything know this file exists", not
   "is it validated" — the other seven pins do that for the two files here.
4. **`shared/runtime/components.json` passed the census on an existing reader**
   (`scripts/doc_checker.py`, `tests/runtime/test_aegisctl.py`); this patch did
   not audit its content.
