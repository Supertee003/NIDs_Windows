# CONTRACT-05: Policy IR (Intermediate Representation)

**Contract ID:** POLICY_IR
**Status:** ACTIVE (two live representations — see Schema below; the old
single `Version: 5.0 / FROZEN` stamp was stale and is retired by this edit)
**Languages:** TypeScript, Zig, Rust

## Purpose

Defines the policy intermediate representation format.
TypeScript compiles policy DSL → Policy IR.
Zig evaluates Policy IR against events.
Rust PEP validates policy signatures.

## Schema — representation A: daemon JSON loader (`src/policy/policy_ir.zig`)

The tables below are verified against the loader structs (Predicate /
Clause / Condition / Policy / EvalContext in `policy_ir.zig:54-154`).
This is the ONLY format the daemon JSON loader accepts into PolicySet.

### Action (u8)
```
pass        = 0
log         = 1
alert       = 2
rate_limit  = 3
block       = 4
quarantine  = 5
escalate    = 6
```

### FieldKind (u8)
```
kind        = 0
severity    = 1
source      = 2
src_ip      = 3
dst_ip      = 4
src_port    = 5
dst_port    = 6
protocol    = 7
sni         = 8
dns_name    = 9
http_uri    = 10
http_host   = 11
rule_id     = 12
```

### Op (u8)
```
eq          = 0
ne          = 1
match       = 2
nomatch     = 3
lt          = 4
gt          = 5
in          = 6
```

### Predicate
```zig
pub const Predicate = struct {
    field: FieldKind,
    op: Op,
    value_int: u64,
    value_str: []const u8,
};
```

### Clause (AND of predicates)
```zig
pub const Clause = struct {
    predicates: []Predicate,
};
```

### Condition (OR of clauses)
```zig
pub const Condition = struct {
    clauses: []const Clause,
};
```

### Policy
```zig
pub const Policy = struct {
    id: u32,
    name: []const u8,
    condition: Condition,
    action: Action,
    severity: u8,
    ttl_sec: u32,
    priority: u32 = 0,   // POL-PRIO-070: file order kept unless declared
    trusted: bool = false, // TRUST-WIRE-082: privileged actions need trust
};
```

## Schema — representation B: compiler/plane IR (`src/policy/policy_plane.zig` + `ts_policy/`)

Emitted by the TS compiler, evaluated by the plane, mirrored byte-value-exact
(TS `types.ts` ↔ Zig `policy_plane.zig`, pinned by
`ts_policy/tests/cross_language_contract.test.ts` + golden
`ts_policy/tests/fixtures/policy_ir_002.json` shared with the Zig loader).
Magic `POL1` (`0x504F4C31`), IR version 1.

### ConditionType (u8): SRC_IP=0, DST_IP=1, SRC_PORT=2, DST_PORT=3, PROTOCOL=4, RULE_ID=5, VERDICT=6, THREAT_INTEL_SEVERITY=7, TIME_WINDOW=8
### ConditionOperator (u8): EQUALS=0, NOT_EQUALS=1, GREATER_THAN=2, LESS_THAN=3, IN_RANGE=4, MATCHES_ANY=5
### PolicyActionDef (u8): ALLOW=0, ALERT=1, BLOCK=2, QUARANTINE=3, RATE_LIMIT=4, LOG_ONLY=5
### PolicyCondition: field + operator + value u64 (+ value2 u64 upper bound for IN_RANGE)

## How A and B relate

The TS compiler emits representation B; the daemon enforces from
representation A loaded out of `configs/policies.json` (PolicySet). The
compiled IR additionally runs as a verify-only mirror (T3-TSIR-025 — never
replaces the PolicySet, never touches enforcement authority).

### EvalContext
```zig
pub const EvalContext = struct {
    ev: *const IpcEvent,  // or CanonicalEvent
    sni: ?[]const u8,
    dns_name: ?[]const u8,
    http_uri: ?[]const u8,
    http_host: ?[]const u8,
};
```

## Evaluation Flow

```
TypeScript Policy DSL
    │
    ▼
Policy Compiler (TypeScript)
    │
    ▼
Policy IR (JSON → Zig PolicySet)
    │
    ▼
Zig Policy Evaluator
    │
    ├── For each Policy in PolicySet:
    │   ├── Evaluate Condition against EvalContext
    │   ├── If match: return Policy (action + severity)
    │   └── If no match: continue
    │
    ▼
Policy match → PepRequest → Rust PEP
```

## Signing

- Policy IR is signed with Ed25519
- Signature covers: policy_id + condition + action + severity
- Rust PEP verifies signature before enforcement
- Trust store manages key lifecycle

## Invariants

- Each plane has exactly one format (loader schema for PolicySet, compiler schema for the IR mirror) — no ad-hoc policy structs on either side
- Policies are signed (Ed25519) and verified by Rust PEP
- Policy evaluation is deterministic (same input → same output)
- Policy TTL prevents stale policy enforcement
- No component may create policies at runtime (only compile-time)

## References

- `src/policy/policy_ir.zig` - Zig loader implementation (representation A)
- `src/policy/policy_plane.zig` - Zig plane implementation (representation B)
- `ts_policy/tests/fixtures/policy_ir_002.json` - golden IR shared with the Zig loader
- `ts_policy/tests/cross_language_contract.test.ts` - TS/Zig value-parity pins
- `ts_policy/src/` - TypeScript compiler
- `rust-src/lib.rs` - Rust signature verification
- `CONTRACT_MAP.json` - Contract registry
