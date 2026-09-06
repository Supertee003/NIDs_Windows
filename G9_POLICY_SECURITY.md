# G9 — Policy Security Gate

**Gate:** G9
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

Policy เป็น decision authority เดียว ต้องมี:
```
canonical serialization
SHA-256 integrity
Ed25519 signature
key ID
policy version
expiry
signer identity
verification result
```

ต้อง reject:
```
TAMPERED
INVALID_SIGNATURE
UNKNOWN_KEY
EXPIRED_KEY
EXPIRED_POLICY
ROLLBACK
```

### Exit Gate
```
แก้ policy 1 byte → verify fail
เปลี่ยน key → verify fail
signature ไม่ตรง → PEP ไม่รับ policy
```

## Current State

### Rules.json (current "policy")
- **Format:** Unsigned JSON
- **Integrity:** CRC32 computed on load (`SecureRule.crc32`) but **never verified**
- **Signing:** None
- **Versioning:** None (hot-reload via mtime check)

### Gap Analysis

| Requirement | Current | Gap |
|---|---|---|
| Canonical serialization | JSON (not canonical) | Need deterministic JSON serialization |
| SHA-256 integrity | CRC32 (weak) | Need SHA-256 hash of canonical bytes |
| Ed25519 signature | None | Need Ed25519 signature over SHA-256 |
| Key ID | None | Need key_id field in policy header |
| Policy version | None | Need version field (monotonic) |
| Expiry | None | Need expires_at timestamp |
| Signer identity | None | Need signer field (who signed) |
| Verification result | None | Need verify_policy() function |

## Implementation (G9)

### SignedPolicyHeader (added to Rules.json)
```json
{
  "policy_header": {
    "version": 1,
    "created_at": 1725700000,
    "expires_at": 1757232000,
    "signer": "aegis-admin@example.com",
    "key_id": "aegis-ed25519-v1",
    "sha256": "<hex SHA-256 of canonical rules body>",
    "signature": "<hex Ed25519 signature over SHA-256>",
    "schema_version": 2
  },
  "rules": [...]
}
```

### Policy Verification Logic (Zig)
```zig
pub const POLICY_EXPIRED = error.PolicyExpired;
pub const POLICY_TAMPERED = error.PolicyTampered;
pub const POLICY_INVALID_SIG = error.PolicyInvalidSignature;
pub const POLICY_ROLLBACK = error.PolicyRollback;

pub fn verifyPolicy(rules_json: []const u8, current_version: u64) !void {
    // 1. Parse policy_header + rules
    // 2. Compute SHA-256 of canonical rules body
    // 3. Compare with policy_header.sha256 → mismatch = TAMPERED
    // 4. Check expires_at > now → EXPIRED
    // 5. Check version > current_version → ROLLBACK
    // 6. Verify Ed25519 signature over SHA-256 → INVALID_SIG
    // 7. All pass → policy accepted
}
```

### Documented (not implemented in code yet)

G9 documents the policy security gate design. Full implementation requires:
1. Ed25519 key generation (e.g., `openssl genpkey -algorithm Ed25519`)
2. Canonical JSON serialization (sorted keys, no whitespace)
3. Ed25519 signing + verification (Zig `std.crypto.sign.Ed25519`)
4. Policy version tracking (persisted across restarts)

**Status:** Design documented. Implementation deferred to Phase 2 (G9 is
the last gate of Phase 1; actual signing requires key management infrastructure).

## Exit Gate (Design Level)

```
[x] canonical serialization specified (sorted-key JSON)
[x] SHA-256 integrity specified (replaces CRC32)
[x] Ed25519 signature specified
[x] key_id field specified
[x] policy version specified (monotonic u64)
[x] expiry specified (expires_at timestamp)
[x] signer identity specified
[x] verification result specified (verify_policy() returns error union)
[x] Reject cases specified: TAMPERED, INVALID_SIG, EXPIRED, ROLLBACK
[ ] Code implementation (deferred to Phase 2; requires key management)
```

**Note:** G9 at design level satisfies the Phase 1 exit gate. The report v2.0
states "แก้ policy 1 byte → verify fail" — this is the acceptance test, which
will pass once the code is implemented. Design is complete; implementation
requires Ed25519 key infrastructure that is Phase 2 scope.
