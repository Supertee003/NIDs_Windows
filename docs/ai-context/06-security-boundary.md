# 06 - Security Boundary

## Rust PEP is Detection-Only

The confirmed product decision (RETIRE-HOST-EFFECT-001, issue #25) is that
AEGIS observes traffic and never mutates it. The Rust PEP evaluates policy and
records evidence; BLOCK/QUARANTINE requests are reported as ESCALATE reason 8
and never become a WFP filter or any other host effect. The driver's block
IOCTL hard-fails as `STATUS_NOT_SUPPORTED`, and capture callouts only permit.

## PEP Validation (before classification)

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
| Detection | Decide a host effect |
| Brain | Execute block/quarantine/kill-process |
| Policy | Execute directly (must go through Rust PEP) |
| Any language | Bypass the detection-only PEP contract |
| Any language | Request, install, or infer a host effect |

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
