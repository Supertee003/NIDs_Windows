# CONTRACT-02: PEP ABI (Policy Enforcement Point)

**Contract ID:** PEP_ABI
**Version:** 1.0
**Status:** FROZEN
**Languages:** Zig, Rust

## Purpose

Defines the boundary between Zig Runtime and Rust PEP.
Zig sends PEP requests; Rust validates, authorizes, and returns decisions.
Rust is the FINAL security authority - no bypass allowed.

## Request/Response Types

### PepDecision (u8)
```
allow       = 0
block       = 1
rate_limit  = 2
quarantine  = 3
escalate    = 4
drop        = 5
```

### PepContext (24 bytes)
```c
typedef struct {
    uint32_t caller_pid;
    uint32_t caller_capability_mask;
    uint64_t request_id;
    uint32_t reserved;
} AegisPepContext;
```

### PepRequest (64 bytes)
```c
typedef struct {
    uint8_t  decision_kind;    // EventKind (what action is being requested)
    uint64_t flow_id;          // Flow correlation ID
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t policy_id;        // Which policy triggered this
    uint8_t  severity;
    AegisPepContext ctx;
} AegisPepRequest;
```

### PepResponse (16 bytes)
```c
typedef struct {
    uint8_t  decision;         // PepDecision enum
    uint32_t reason;           // Reason code
    uint32_t quota_remaining;  // Rate-limit quota
    uint32_t signed_by;        // KeyId prefix (Ed25519)
} AegisPepResponse;
```

## FFI Functions

```c
// Initialize PEP (call once at startup)
int aegis_pep_init(void);

// Shutdown PEP (call once at shutdown)
void aegis_pep_shutdown(void);

// Enforce a policy decision (main entry point)
int aegis_pep_enforce(
    const AegisPepRequest* req,
    AegisPepResponse* resp
);

// Query remaining rate-limit quota for an IP
uint32_t aegis_pep_quota_remaining(uint32_t src_ip);
```

## Authorization Flow

```
Zig Runtime
    │
    ▼
PepRequest (event + policy + context)
    │
    ▼
Rust PEP
    │
    ├── Validate request (signature, freshness, replay)
    ├── Check policy authority (is this policy signed by trusted key?)
    ├── Check capability mask (is caller authorized?)
    ├── Check rate-limit quota
    ├── Apply two-person rule (if high severity)
    │
    ▼
PepResponse (decision + reason + quota + signature)
    │
    ▼
Zig Runtime
    │
    ▼
Action Dispatcher (block via WFP, quarantine, escalate, etc.)
```

## Invariants

- PepRequest is 64 bytes (extern struct, no padding)
- PepResponse is 16 bytes (extern struct, no padding)
- Rust PEP is the ONLY final enforcement authority
- No component may bypass PEP for privileged actions
- PEP responses are signed (Ed25519) for audit trail
- Quota is per-source-IP, decremented on rate_limit decisions

## References

- `src/policy/pep_bindings.zig` - Zig-side FFI bindings
- `rust-src/lib.rs` - Rust-side implementation
- `CONTRACT_MAP.json` - Contract registry
