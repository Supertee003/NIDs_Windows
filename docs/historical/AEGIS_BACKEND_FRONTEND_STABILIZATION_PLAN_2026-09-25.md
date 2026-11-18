# AEGIS Backend Stabilization and Frontend Delivery Plan

## Objective

The immediate objective is to complete and stabilize the existing Kernel-assisted NIDS with WFP enforcement capability before expanding kernel-mode detection. Backend behavior must become the single source of truth for runtime state, metrics, authorization, enforcement receipts, forensic linkage, and recovery. The frontend must remain a thin operator surface that reads authoritative backend state and never becomes a second policy or enforcement authority.

## Current baseline

The repository already contains the Zig runtime spine, Go Nose ingress, Rust PEP, WFP provider boundary, control protocol, forensic chain, dashboard source, and Mouth operator monitor. The latest qualification remains observe-only: synthetic rule qualification is passing, while the prevention gate remains closed until current-head WFP host-effect evidence is produced.

## Delivery phases

### Phase 1 — Backend truth and contract stabilization

The first phase will normalize `system.health`, `metrics.snapshot`, `enforcement.status`, `forensics.verify`, and lifecycle responses. The daemon remains authoritative; PID files, log files, executable presence, and UI state are diagnostic only. Health must distinguish runtime readiness, PEP readiness, provider readiness, enforcement capability, and confirmed host effect. Metrics must originate from live runtime counters and preserve exactly-once identifiers.

Acceptance requires a stable JSON schema, explicit degraded and fail-closed states, truthful worker readiness, bounded control-pipe retries, and no optimistic promotion from diagnostic data to `RUNNING` or `ENFORCED`.

### Phase 2 — PEP/WFP backend closure

All privileged mutations must follow the single route `control request → Zig boundary → Rust PEP → WFP provider → provider read-back → EnforcementReceipt → forensic linkage`. IP-only compatibility mutation remains unavailable. A valid block requires an exact destination IP, port, protocol, policy identity, request identity, provider status, non-zero filter ID, and a successful postcondition query. Unblock must use the filter ID from the validated receipt.

Acceptance requires duplicate-request behavior, stale-receipt rejection, provider-unavailable fail-closed behavior, exact cleanup, and receipt-to-forensic linkage.

### Phase 3 — Runtime lifecycle and release hardening

The backend will be tested for single-owner startup, readiness, graceful stop/join, stale pipe recovery, provider loss, driver recovery, backpressure, and restart behavior. Build manifests, binary hashes, driver hashes, source commit, and policy trust-store version must be synchronized after the final rebuild. Temporary probes and stale evidence must not be treated as release evidence.

Acceptance requires clean rebuild verification, lifecycle recovery evidence, negative authorization tests, and a reproducible release candidate.

### Phase 4 — Frontend delivery

The dashboard and Mouth will consume the backend contract without direct WFP access or independent state mutation. The dashboard will provide runtime overview, sensor status, detection feed, metrics, forensic integrity, and receipt-driven enforcement status. The UI must distinguish `DETECTED`, `ALERTED`, `PEP_REJECTED`, `ENFORCED`, and `HOST_EFFECT_CONFIRMED`. It must never display `ENFORCED` from an action label, log line, or process exit alone.

Read-only views will be delivered first. Privileged operator actions will be enabled only after the backend receipt and authorization contracts pass. The frontend must show stale-data timestamps, reconnect state, degraded state, and fail-closed state.

## Immediate implementation slice

The first implementation slice fixes dashboard severity normalization so `Critical`, `critical`, and other case variants produce identical counters and DEFCON behavior. The slice also adds a regression test for this invariant. This is intentionally low-risk and does not change enforcement behavior.

The next slice will add backend contract tests for health and metrics normalization, followed by current-head WFP controlled proof. Kernel detection expansion remains paused until these gates are closed.

## Definition of done

The backend is stable when health and metrics are live and truthful, all privileged actions pass through Rust PEP, WFP effects are receipt-driven and read back from the provider, cleanup is exact, provider failure is fail-closed, lifecycle recovery is proven, and release artifacts match one source commit.

The frontend is ready when it is a thin client of those contracts, does not mutate WFP directly, does not create authoritative state, handles unavailable and stale data explicitly, and links every displayed enforcement result to a valid receipt and forensic record.

## Explicit non-goals for this phase

No new kernel detection surface will be added yet. No frontend shortcut will call `netsh`, local firewall APIs, direct WFP IOCTL mutation, or an in-memory enforcement map. No synthetic fixture will be promoted to host-effect proof.

## Gate order

1. Backend health and metrics truth.
2. PEP/WFP receipt and exact cleanup.
3. Lifecycle, recovery, and release verification.
4. Read-only frontend views.
5. Privileged frontend actions after backend proof.
6. Resume kernel detection expansion.

## Current decision

AEGIS remains in observe-only mode until the current-head controlled WFP proof and recovery evidence pass. The plan deliberately prioritizes correctness and evidence quality over adding more detection features.

## References

[1]: PRODUCTION_COMPLETION_RUNBOOK_2026-09-20.md "AEGIS Production Completion Runbook"
[2]: analysis/PRODUCTION_PATH.md "AEGIS Production Path"
[3]: AUTHORITY_MAP.json "AEGIS Authority Map"
[4]: FLOW_MAP.json "AEGIS Flow Map"
[5]: EVIDENCE_INDEX.json "AEGIS Evidence Index"

