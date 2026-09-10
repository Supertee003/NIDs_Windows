# CONTRACT-05: Policy IR (Intermediate Representation)

**Contract ID:** POLICY_IR
**Version:** 5.0
**Status:** FROZEN
**Languages:** TypeScript, Zig, Rust

## Purpose

Defines the policy intermediate representation format.
TypeScript compiles policy DSL → Policy IR.
Zig evaluates Policy IR against events.
Rust PEP validates policy signatures.

## Schema

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
    value_str: [64]u8,
};
```

### Clause (AND of predicates)
```zig
pub const Clause = struct {
    predicates: []const Predicate,
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
    name: [64]u8,
    condition: Condition,
    action: Action,
    severity: u8,
    ttl_sec: u32,
};
```

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

- Policy IR is the ONLY policy format (no ad-hoc policy structs)
- Policies are signed (Ed25519) and verified by Rust PEP
- Policy evaluation is deterministic (same input → same output)
- Policy TTL prevents stale policy enforcement
- No component may create policies at runtime (only compile-time)

## References

- `src/policy/policy_ir.zig` - Zig implementation
- `ts_policy/src/` - TypeScript compiler
- `rust-src/lib.rs` - Rust signature verification
- `CONTRACT_MAP.json` - Contract registry
