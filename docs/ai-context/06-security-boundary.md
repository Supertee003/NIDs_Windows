# 06 - Security Boundary

## Rust PEP is the Final Enforcement Authority

No bypass allowed.

## PEP Validation (before execution)

Rust validates:
- policy
- version
- signature
- target
- action
- authorization
- expiry

## PEP Results (7 statuses, never single success flag)

- EXECUTED
- FAILED
- DENIED
- DEFERRED
- NOT_APPLICABLE
- UNSUPPORTED
- TIMEOUT

## Forbidden Actions

| Component | Forbidden Action |
|-----------|-----------------|
| Detection | Call PEP directly |
| Detection | Decide enforcement |
| Brain | Execute block/quarantine/kill-process |
| Policy | Execute directly (must go through Rust PEP) |
| Any language | Bypass Rust PEP |

## Policy Plane Security

Policy signing is NOT production-ready until:
- real cryptographic signature
- key handling
- verification
- version
- expiry
- rollback

are exercised in the real runtime path.

## Human Review Required

AI-generated code must receive human review when changing:
- drivers
- FFI
- ABI
- IPC
- policy
- PEP
- privilege operations
- cryptographic verification
- event persistence

AI may implement. Human must approve security semantics.
