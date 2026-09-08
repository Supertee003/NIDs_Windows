# Step 23 — TypeScript Policy Authoring (Policy DSL Authoring)

**Status:** REAL (S2 framework) — TypeScript policy compiler framework present; full pipeline verification partial (STEP 24-25 dependencies)
**File:** `ts_policy/src/compiler.ts` (production TypeScript policy compiler framework)
**Production Subsystem:** `ts_policy/src/compiler.ts`, `ts_policy/src/types.ts`, `ts_policy/src/index.ts`

---

## Contract (Per ROADMAP STEP 23 — TypeScript Policy Authoring + docs/ARCHITECTURE_CANONICAL.md Section 9)

TypeScript creates:
- Conditions (clauses: IPv4/IPv6/CIDR/string/enum/integer/time/domain/process/file/identity)
- Actions (scope, priority, expiry, target)
- Policy Definition (`PolicyDefinition` struct with `.id`, `.name`, `.version`, `.clauses[]`, `.action`, `.scope`)

Pipeline:
```
TypeScript Policy Definition
    ↓
Policy Compiler (core/policy_contract.zig — framework present; full feature verification unverified per STEP 24)
    ↓
Policy IR (`core/policy_ir.zig` — framework verified)
    ↓
Canonical Serialization
    ↓
SHA-256 (core/policy_contract.zig — framework present)
    ↓
Ed25519 (core/policy_contract.zig — framework present; key rotation/revocation unverified per STEP 25)
    ↓
Trust Store (`core/trust_store.zig` — framework present)
    ↓
Rust PEP Verification (`shield/src/lib.rs` — production framework verified; final authority verification pending STEP 60 audit)
```

---

## Authority Invariants (Enforced)

- TypeScript Policy (`ts_policy/`) CANNOT enforce directly — must compile to Policy IR then pass through Policy Compiler → PEP
- Policy Compiler (`core/policy_contract.zig` — legacy framework reference; production framework: `core/policy_contract.zig`, `core/policy_engine.zig`) CANNOT execute actions — produces PolicyDecision for PEP execution
- Policy (`src/policy/action_dispatcher.zig` — framework present; STEP 27: direct WFP path removed; PEP routing verified structurally) CANNOT execute actions — PEP (`shield/src/lib.rs`) is final authority

---

## References

- `ts_policy/src/compiler.ts`
- `ts_policy/src/types.ts`
- `core/policy_contract.zig` (legacy framework reference)
- `core/policy_engine.zig` (production framework)
- `core/policy_ir.zig` (production framework)
- `core/policy_signing.zig` (production framework — STEP 25 pending: rotation/revocation)
- `docs/ARCHITECTURE-TRUTH.md` (Policy: framework REAL; compiler unverified; signing unverified; enforcement authority: Rust PEP verified structurally)
