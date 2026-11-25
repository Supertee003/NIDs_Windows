# AEGIS Canonical Policy Bytes v1 — `POLICY_CANONICAL_BYTES_V1`

## Status: ACTIVE contract for NEW canonical-byte proofs (2026-11-26)

This document defines one versioned, fixed-width, cross-language byte stream
for representation-B policy rules (`ts_policy/` ↔
`src/policy/policy_plane.zig`). It is **additive**. Legacy hashes and the
ADR-0005 exact-file Ed25519 sidecar are unchanged and are explicitly NOT
described by this format.

## Purpose

The legacy implementations disagree on purpose:

- `ts_policy/src/compiler.ts::canonicalRuleBytes` uses `\x1f`-joined UTF-8.
- `src/policy/policy_plane.zig::PolicyCompiler` hashes raw struct bytes.
- `src/policy/policy_signing.zig::canonicalDigest` hashes a LE header followed
  by pointer-bearing `std.mem.asBytes(&rule)` bytes.
- `tests/policy_signing/test_t7_signed_policy.py` uses JSON-canonical rule
  bytes.
- `ts_policy/src/seal.ts::canonicalIRBytes` uses newline/`|`/`=`-joined text.

Those functions remain byte-identical in this patch. This document introduces
a single new format that Python, TypeScript, Zig and Rust can all reproduce
from the same vector manifest.

## Encoding rules

All integers are **unsigned or signed little-endian**, with fixed widths.
All strings are **UTF-8 bytes** with a 4-byte LE byte-length prefix. There are
no delimiters, so NUL, newline, `\x1f`, Unicode and empty strings are
unambiguous. No struct padding, pointer, float, locale, or JSON key ordering
is involved.

Limits (values outside these limits MUST be rejected, never truncated):

| Item | Limit |
|---|---|
| string byte length (`name`, `description`) | `0..256` |
| rules in a set / signature pre-image | `1..64` |
| conditions per rule | `0..4` |
| `ConditionType` ordinal | `0..8` |
| `ConditionOperator` ordinal | `0..5` |
| `PolicyActionDef` ordinal | `0..5` |
| `enabled` | `0` or `1` |
| `id`, `ir_hash`, `value`, `value2` | `0..2^64-1` as applicable |
| `policy_version`, `ir_magic` | `0..2^32-1` |
| `expiry_ms` | `-2^63..2^63-1` |

### 1. Single rule — `PC01RULE`

```
offset  size  field
0       8     magic = ASCII "PC01RULE"
8       2     format_version = 1 (u16 LE)
10      2     flags = 0 (u16 LE)
12      4     id (u32 LE)
16      1     priority (u8)
17      1     action ordinal (u8)
18      1     enabled: 0 | 1 (u8)
19      1     condition_count (u8)
20      4     name_len (u32 LE)
24      N     name UTF-8 bytes
24+N    4     description_len (u32 LE)
28+N    M     description UTF-8 bytes
28+N+M  ...   conditions, in declared order:
              field u8, operator u8, value u64 LE, value2 u64 LE
```

`condition_count` MUST equal the number of encoded conditions. A present
value2 is always encoded (zero when unused), so every condition consumes 18
bytes.

### 2. Rule-set digest pre-image — `PC01SETS`

```
0       8     magic = ASCII "PC01SETS"
8       2     format_version = 1
10      2     flags = 0
12      4     rule_count (u32 LE)
16      ...   canonicalRuleBytesV1(rule) for each rule, in supplied order
```

`policy_rule_set_digest_v1` is `SHA-256(PC01SETS pre-image)`. This is the
versioned replacement pre-image for the compiler rule-set fingerprint; the
legacy compiler hash is not changed by this contract.

### 3. Signed-policy digest pre-image — `PC01SIGN`

```
0       8     magic = ASCII "PC01SIGN"
8       2     format_version = 1
10      2     flags = 0
12      4     ir.magic (u32 LE)
16      2     ir.version (u16 LE)
18      2     rule_count (u16 LE)
20      8     ir.hash (u64 LE)
28      4     policy_version (u32 LE)
32      8     expiry_ms (i64 LE)
40      ...   canonicalRuleBytesV1(rule) for each rule, in supplied order
```

`canonical_signature_digest_v1` is `SHA-256(PC01SIGN pre-image)`. This is the
versioned replacement pre-image for the disputed
`policy_signing.canonicalDigest`; the legacy function remains untouched.

## Ordinal tables (representation B)

- `ConditionType`: `SRC_IP=0, DST_IP=1, SRC_PORT=2, DST_PORT=3, PROTOCOL=4,
  RULE_ID=5, VERDICT=6, THREAT_INTEL_SEVERITY=7, TIME_WINDOW=8`.
- `ConditionOperator`: `EQUALS=0, NOT_EQUALS=1, GREATER_THAN=2, LESS_THAN=3,
  IN_RANGE=4, MATCHES_ANY=5`.
- `PolicyActionDef`: `ALLOW=0, ALERT=1, BLOCK=2, QUARANTINE=3, RATE_LIMIT=4,
  LOG_ONLY=5`.

These are the same ordinals pinned by `shared/policy/policy_ir.md` and
`ts_policy/tests/cross_language_contract.test.ts`. Representation A
(`src/policy/policy_ir.zig`) has different action semantics and is not encoded
here.

## Shared vectors

`shared/vectors/policy_canonical_v1.json` is the single source of test vectors.
It is produced by `python tools/generate_policy_canonical_vectors.py --write`
and consumed read-only by:

- `brain/policy_canonical_v1.py` / `tests/policy_signing/test_canonical_policy_bytes_v1.py`
- `ts_policy/src/canonical_policy_bytes_v1.ts` / `ts_policy/tests/canonical_policy_bytes_v1.test.ts`
- `src/policy/policy_canonical_v1.zig` (inline tests)
- `rust-src/policy_canonical_v1.rs` (inline tests)

Vectors cover delimiters, NUL, newline, Unicode, maximum string length,
`u64 = 2^53`, `u64 = 2^64-1`, multi-rule ordering, rule-set digest and
signed-policy digest.

## Authority and migration note

This format carries evidence only. No component gains enforcement authority
from it. It is not a signature scheme and does not replace ADR-0005's
exact-file sidecar. Migration of legacy hashes to V1 is a separate, reviewed
change because it would alter published hashes and signatures.
