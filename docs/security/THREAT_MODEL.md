# Threat model — assets, boundaries, controls and residual risk

> Scope: `v1.1` detection-only / observe-only product (`docs/SCOPE.md`).
> This is a **model of the recorded design**, not a penetration-test result and not
> evidence of a fresh host run. It changes no authority or gate. Status source:
> [`release/release-status.json`](../../release/release-status.json).

## Assets

| Asset | Why it matters |
|---|---|
| Raw network/host telemetry (Npcap, WFP, ETW, FIM, Registry) | Input to every detection; corruption or loss produces false negatives |
| Canonical event and wire frames (`v1`/`v2`/`v3`) | Cross-language contract; malformed frames must be rejected, not silently truncated |
| Rule catalog and golden vectors | Detection identity; unauthorized edits change what "detected" means |
| Policy decisions and Rust PEP assessment | Evidence authority only; must never become a host effect in this release |
| Forensic hash chain and evidence receipts | Investigation trail; must be verifiable and attributable |
| Control API / operator surfaces | Read-mostly observation and diagnostics; privileged IPC exposure is a STOP-THE-LINE trigger |
| Release signature trust anchor | Owner-held private key; public anchor is the only in-tree material |
| Host runtime and installed binaries | Must remain the pinned current-source build during any qualification window |

## Threat actors

| Actor | Capability | Relevant to this product |
|---|---|---|
| Passive network observer | Reads traffic | Can observe, not alter, telemetry |
| Active network attacker | Injects/mutates traffic | Malformed frames, oversized payloads, replay-like patterns |
| Unprivileged local user | Runs processes, accesses user-mode IPC | Attempts to reach operator/control surfaces |
| Privileged local administrator / OS controller | Can load drivers, stop services, alter host state | **Above this product's trust boundary** — see residual risk |
| Supply-chain / build attacker | Alters source, toolchain or release tree | Targets golden vectors, signatures and provenance |
| Malicious or careless operator | Has legitimate control access | Can misread stale UI as live truth or mishandle a soak window |

## Attack surfaces and trust boundaries

| Boundary | Crossing | Validation that must exist |
|---|---|---|
| External network → Npcap capture | Raw packets | Captured length vs original length; BPF must not drop required traffic |
| Go Nose → Zig daemon (named pipe) | 4-byte LE length-prefixed frame | Exact per-version length, version, reserved bits, CRC, payload limit; reject and count, never silent truncation |
| Kernel adapters → user runtime | WFP/ETW/FIM/Registry events | IOCTL buffer length, IRQL constraints, ownership and cleanup on unload |
| Zig runtime → Rust PEP | Policy request / assessment | Schema and capability validation; deterministic evaluation; no host-effect authority |
| Control API → operator surfaces | Snapshot / command | Nonce/replay/freshness on active control; single authority; no second runtime |
| Analytics/UI → operator | Processed events | Explicit stale-data and disconnect display; no old data presented as real-time |
| Release pipeline → repository | SHA256SUMS + Ed25519 signature | Owner anchor check, commit-contains-runtime, artifact digest verification |
| Host operator → soak window | Finalizer and restore | Exactly one SYSTEM finalizer per window, serialized, no concurrent restore |

## Threat scenarios → controls → residual risk

| Scenario | Control in the recorded design | Residual risk |
|---|---|---|
| Malformed or oversized frame | Exact-length decoder, version rejection, `nose_frames_rejected` counter | Current-source full host matrix not re-measured; E2-level proof only |
| Telemetry loss / queue full | Bounded queue with observable shedding and drop counters; not silent loss | Drops can still occur under load; see the real soak FAIL counters |
| Replayed control command | Version/freshness/single-use nonce at the source | Narrow E5 proof only, not a full matrix result |
| Policy says `BLOCK` | Detection-only PEP, `prevention_gate=closed`, `host_effect_capable=false` | Lab-only mutation code remains historical; production path has no reachable creation path (source reading, E1) |
| Evidence tampering | Hash chain and integrity verification | **Tamper-evident, not tamper-proof**; verification detects change, it does not prevent it |
| Stale dashboard shown as live | Health snapshot and disconnect/stale display rules | Misinterpretation remains possible; operators must read the health model |
| Compromised build/release | Owner-held key, signed SHA256SUMS, provenance manifests | Signature authenticates bytes, not security validation of every artifact |
| Privileged administrator alters host | Out of scope by design | **Unavoidable**: an OS-level controller is above the trust boundary; no product control can defend against it |
| Overlapping soak finalizers | Owner serialization requirement (issue #55) | Real prior incident: stale finalizer swapped a live window's runtime; gate still OPEN |

## Residual-risk summary

1. Detection coverage is catalogued and partially proved, not fully host-qualified; R2003 has only a narrow E5 re-measurement.
2. No production host enforcement exists by design; prevention claims are out of scope.
3. Evidence integrity is tamper-evident, not tamper-proof.
4. Full current-source Windows E5, soak, driver lifecycle and E7 remain unproven.
5. A privileged host administrator is outside the trust boundary and cannot be constrained by this product.

Related: [`docs/SCOPE.md`](../SCOPE.md) · [`docs/runtime/HEALTH_MODEL.md`](../runtime/HEALTH_MODEL.md) ·
[`docs/runtime/QUEUE_SEMANTICS.md`](../runtime/QUEUE_SEMANTICS.md) ·
[`docs/gates/RELEASE_TRUST_ANCHOR.md`](../gates/RELEASE_TRUST_ANCHOR.md).
