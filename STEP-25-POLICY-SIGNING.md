# Step 25 — Policy Signing (SHA-256 + Ed25519 + Key Lifecycle + Trust Store)

**Status:** S2 (Implemented — framework present; key rotation/revocation/expiry/rollback/provisioning unverified)
**File:** `core/policy_signing.zig` (production framework; tracked; user's original development)
**Production Subsystem:** `core/policy_signing.zig` (same file — framework exists; verification missing per STEP 60 security audit)

---

## Contract (Per ROADMAP STEP 25 — Policy Signing Pipeline)

Pipeline must be verified:
```
Policy IR
    ↓
Canonical Serialization
    ↓
SHA-256
    ↓
Ed25519
    ↓
Key ID
    ↓
Trust Store
    ↓
Rust Verify (shield/src/lib.rs — production Rust PEP)
```

Additional requirements (per Step 6 architecture truth notes):
- Key rotation (framework present; rotation procedure unverified)
- Revocation (framework present; revocation procedure unverified)
- Expiry (framework present; expiry verification unverified)
- Provisioning (framework present; provisioning procedure unverified)
- Persistent rollback floor (STEP 52 — recovery unverified; rollback verification unverified per STEP 52)

---

## Production Status

- Framework present (`core/policy_signing.zig` — 29,731 lines; tracked per user request)
- SHA-256 framework present (part of `core/policy_contract.zig` compiler + `core/policy_signing.zig`)
- Ed25519 framework present (`core/policy_contract.zig` — crypto framework present)
- Key lifecycle (`core/trust_store.zig` — framework present; rotation/revocation/provisioning unverified)
- Trust store (`core/trust_store.zig` — framework present)
- Rust Verify (`shield/src/lib.rs` — production framework verified; audit dimensions unverified per STEP 60)
- Policy rollback floor (`core/policy_contract.zig` — rollback framework present; rollback verification unverified per STEP 52)

---

## References

- `core/policy_signing.zig`
- `core/trust_store.zig`
- `docs/ARCHITECTURE-TRUTH.md` (Policy Signing: framework REAL; rotation/revocation/provisioning/rollback unverified)
- `docs/ARCHITECTURE-TRUTH.md` (Rollback: framework STUB — rollback verification pending STEP 52)
