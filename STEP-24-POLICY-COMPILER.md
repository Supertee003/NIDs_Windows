# Step 24 — Policy Compiler (DSL Compiler — IPv4/IPv6/CIDR/String/Enum/Time/Process/File/Identity)

**Status:** S2 (Implemented — framework present; full feature verification unverified)
**Files:** `core/policy_contract.zig` (legacy framework reference), `core/policy_engine.zig` (production framework), `core/policy_ir.zig` (production), `core/policy_contract.zig` (production compiler framework — note: same name, different from legacy reference; must distinguish by directory context)
**Production Subsystem:** `core/policy_contract.zig` + `core/policy_engine.zig` (production framework; full feature verification pending)

---

## Contract (Per ROADMAP STEP 24)

Policy compiler supports:
- IPv4 / IPv6 / CIDR
- String / Enum / Integer / Time / Domain
- Process / File / Identity
- Deterministic ordering: priority → specificity → rule_id → version
- Hot reload: read → parse → validate → compile → atomic swap → audit

---

## Production Status

- `core/policy_contract.zig`: Policy Compiler framework (legacy; superseded by production `core/policy_engine.zig` framework; kept for contract/reference only per user request)
- `core/policy_engine.zig`: Policy engine framework (production framework; full feature verification unverified — Step 24 dependency: full compiler feature set verification)
- `core/policy_ir.zig`: Policy Intermediate Representation (production framework; verified structurally)
- `core/policy_contract.zig` (production compiler framework — same file name as legacy reference but different content; the legacy reference is preserved in git history; the production version is tracked under `core/`)

Note: The production compiler framework (`core/policy_contract.zig`) and the production engine framework (`core/policy_engine.zig`) are distinct modules. The compiler produces Policy IR; the engine consumes it.

---

## References

- `core/policy_contract.zig`
- `core/policy_engine.zig`
- `core/policy_ir.zig`
- `core/policy_contract.zig` (production compiler framework — distinct from legacy reference)
- `docs/ARCHITECTURE-TRUTH.md` (Policy: framework REAL; compiler unverified)
