# AEGIS System Flow Overview

## System purpose

AEGIS is a Windows-native NIDS/IPS composed of several language runtimes. The system observes network and host activity, normalizes it into bounded event contracts, detects and correlates incidents, evaluates policy, requests privileged authorization through Rust PEP, and presents only evidence-backed state to operators.

The most important safety distinction is:

```text
sensor observation
  != detection result
  != policy decision
  != PEP authorization
  != provider response
  != verified host postcondition
```

Only the final state, backed by a valid `EnforcementReceipt v1`, may be presented as confirmed enforcement. The current system intentionally keeps the prevention gate closed.

## End-to-end control flow

```text
Windows sensors / packet ingress
        |
        v
Go Nose, WFP telemetry, ETW, FIM, Registry
        |
        v
Canonical event contracts and bounded queues
        |
        v
Zig runtime owner: lifecycle, workers, health, backpressure, control
        |
        v
Python/Cython detection and correlation
        |
        v
Policy plane: TypeScript authoring -> policy IR -> validation/signature
        |
        v
Zig policy boundary -> Rust PEP authorization
        |
        +--> advisory / allow / escalate / unavailable
        |
        +--> guarded provider request
                    |
                    v
              WFP provider boundary
                    |
                    v
              host postcondition readback
                    |
                    v
              EnforcementReceipt v1
                    |
                    v
              forensic linkage and operator projection
```

## Language and component responsibilities

| Language | Main responsibility | Contract boundary | Must not do |
|---|---|---|---|
| Zig | Runtime owner, worker lifecycle, queues, health, control pipe, policy orchestration | CanonicalEvent, IpcEvent, runtime health, receipt projection | Bypass Rust PEP to mutate WFP |
| Go | Nose packet capture/decode and canonical frame production | Named pipe frame: length prefix plus canonical payload | Decide policy or call WFP |
| Rust | PEP authorization, capability checks, signature verification, provider adapter, advisory Shield | C ABI, PEP request/response, exact filter identity | Claim host effect without postcondition evidence |
| C/C++ | Windows native adapters and kernel/user WFP boundary | Packed IOCTL structs, device handle, ring buffer, native helper ABI | Become a second policy authority |
| Python | Detection fallback, CLI/control API, operator tools, analysis integration | Control pipe JSON, detection result, operator snapshot | Infer host effect or directly mutate firewall |
| Cython | Detection fast path | Must produce equivalent result to Python fallback | Implement a separate policy or enforcement path |
| TypeScript | Policy authoring/compiler/sealing | Policy IR and cross-language enum/schema contract | Apply host effects |
| PowerShell/BAT | Build, proof, diagnostics, packaging | Evidence files and command exit status | Be treated as the runtime authority |

## Eight-group relationship

### Group 1 — Zig runtime

This is the execution owner. It starts workers, establishes readiness, owns stop signals, routes events, records failures, and exposes control/health state. A successful Zig unit test proves compilation and local invariants only; runtime acceptance requires process provenance, readiness, clean shutdown, and restart recovery.

### Group 2 — WFP driver and user adapter

The kernel driver observes classification activity and stores bounded event frames in a ring. The user adapter reads the device through IOCTL. The provider mutation surface is intentionally behind Rust PEP. The observe-only proof may open the device read-only and call `GET_STATS`/`READ_EVENTS`; it must not be interpreted as a block proof.

### Group 3 — Go Nose

Nose captures packets, decodes them, and writes canonical frames to the named pipe. The important proofs are frame size, length prefix, reconnect, monotonic identity, duplicate behavior, drop counters, and correct ownership of the pipe. Nose is an ingress sensor, not a policy component.

### Group 4 — FIM

The native helper receives `ReadDirectoryChangesW` records. Zig validates record chaining, action mapping, UTF-16LE/path bounds, and proof-root restrictions. A temporary marker file proves only that a fixture was created. Full acceptance requires daemon counters, canonical event provenance, rule matching, forensic record, and no host enforcement.

### Group 5 — ETW and Registry

These sensors produce host telemetry that must be normalized and correlated. A `READY` state or a matching log line is not sufficient real-sensor evidence. Acceptance requires a real event, normalized event identity, correlation, and forensic linkage.

### Group 6 — Rust PEP and Shield

Rust PEP is the only privileged authorization authority. It validates capabilities, action namespace, policy/signature inputs, provider availability, and exact cleanup identity. Shield is advisory and may escalate to the canonical policy path; it must never authorize or apply a host effect.

### Group 7 — Python/Cython detection

The Python fallback and Cython fast path must return equivalent detection results. The tests must cover binary payloads, embedded NUL, truncation, oversized input, invalid encoding, timeouts, and fallback. Detection output is evidence, not an enforcement receipt.

### Group 8 — Policy and TypeScript

TypeScript authors and compiles typed policy IR, validates enum/schema values, seals policy state, and does not enforce. Zig and Rust validate again at their boundaries. A signed policy proves policy authenticity, not that a host effect occurred.

## Current evidence interpretation

The latest Host output demonstrates strong progress in unit and contract layers:

- Zig runtime tests passed.
- WFP observe-only readback passed.
- FIM observe-only fixture passed.
- Host telemetry and health tests passed.
- Rust PEP and Shield passed after the Shield FFI correction.
- Python/Cython and detection tests passed in the non-overlapped portion of the log.
- TypeScript typecheck, safety, and contract tests passed.

The same output cannot yet be used as a single aggregate result because its log contains overlapping sections and multiple final counters. The corrected runner now uses a lock and unique output directory; a clean single-process rerun is required.

## Release acceptance boundary

The system may proceed with observe-only development, contract hardening, and real telemetry proofs. It must not enable production IPS until all of the following are evidenced from the current build:

1. Rust PEP returns a complete `EnforcementReceipt v1` only after provider postcondition verification.
2. The exact receipt `filter_id` is used for cleanup.
3. Traffic behavior changes as expected in an isolated reversible lab.
4. Cleanup restores traffic and removes the exact filter.
5. Crash/restart recovery leaves no stale filter, process, pipe, or evidence inconsistency.
6. Driver and binaries are signed, hashed, and provenance-linked.
7. Installation, upgrade, rollback, and prevention-gate transitions are verified.

## References

[1]: /home/ubuntu/upload/AEGISProductionHandoff.md "AEGIS Production Handoff"
[2]: analysis/EIGHT_GROUP_STATUS.md "Eight-group status"
[3]: analysis/EIGHT_GROUP_RUN_FINDINGS_20260922.md "Run findings"
[4]: contracts/operator_contract_v1.json "Operator contract v1"
[5]: docs/architecture/CONTRACTS.md "Architecture contracts"
