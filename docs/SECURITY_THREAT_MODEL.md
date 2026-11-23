# Security Threat Model — AEGIS NIDS Windows

> Scope: the detection-only production runtime described in `README.md`, `SYSTEM_MAP.json`,
> `FLOW_MAP.json`, and `AUTHORITY_MAP.json` at build source `a53eda8`.
> This is a design-level threat model, not a penetration test result. Controls are listed with the
> layer that owns them; where a control is only partially implemented, it is marked as such.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| CanonicalEvent stream | The single normalized truth feeding detection and forensics |
| Runtime state (Zig daemon) | One authoritative owner; duplicate owners cause duplicate detection and stale authority |
| Control plane (`\\.\pipe\aegis_control`) | Authenticated operator channel; a false "success" here is dangerous |
| Forensic records and hash chain | The evidence that an event really happened; integrity is the product's value |
| Detection rules and policy artifacts | Changing these changes what the system reports |
| WFP / ETW / FIM / Registry telemetry | Source fidelity; corrupted telemetry produces false findings |
| Go Nose ingress (`\\.\pipe\aegis_nose`) | Boundary between packet capture and the runtime |
| Release signing material and trust anchor | Identity of the shipped build (trust anchor unchanged) |

---

## 2. Threat actors

| Actor | Capability | Relevant concern |
|---|---|---|
| Unprivileged local process | Can open local pipes/ports | IPC spoofing, event injection, unauthorized control requests |
| Malicious process on host | Can generate network/host activity | Detection evasion, event flooding, rule bypass |
| Malware with user privileges | Can tamper with user-writable files | Log/record tampering, config drift |
| Compromised sensor (Go Nose / adapter) | Can submit fabricated events | False positives, forensic pollution |
| Compromised operator account | Can issue valid-looking control requests | Unauthorized queries/commands within the control contract |
| Malicious administrator (kernel influence) | Can load/unload drivers, edit anything | Out of what a user-mode NIDS can defend; system must be **tamper-evident**, not "tamper-proof" |

---

## 3. Threats and controls

| Threat | Control | Owner / notes |
|---|---|---|
| IPC spoofing / unauthorized control request | Authenticated control plane; daemon-owned snapshot; no second runtime authority | Zig control plane; see `SECURITY_BOUNDARIES.md` for pipe details |
| Event injection from a sensor | Schema validation, length-prefixed framing, runtime-owned queue | Normalizer + runtime |
| Malformed / oversized IPC message | Bounded framing and explicit rejection path | Codecs + runtime; exact limits in contract docs |
| Duplicate / replayed events | Exactly-once counters (`duplicate_event_ids`, `nose_non_monotonic_event_ids`) reported by health | Data-plane counters; see `tests/` |
| Queue exhaustion / resource abuse | Bounded queue with observable shedding on full (drop-on-full, **not** blocking-producer backpressure); `shed_overload` and drop counters exposed to health | Zig runtime; is intentionally observable, not silent |
| Detection bypass | 23 rules across multiple layers; negative controls used for L4 proof | Detection engine; honest coverage stated in `DETECTION_VALIDATION.md` |
| Forensic record tampering | Hash-chain integrity verification plus `forensic verify` CLI | Forensics; **tamper-evident**, not tamper-proof |
| Release binary substitution | Ed25519 signature over `SHA256SUMS`; 674/674 manifest verification; pinned trust anchor | Release engineering |
| Privilege escalation via enforcement | No host-effect authority: prevention gate closed, block IOCTL unsupported, no AEGIS filter installed | Rust PEP + WFP adapter; `RETIRE-HOST-EFFECT-001` |
| Driver failure / unload | Explicit `UNAVAILABLE`/`DEGRADED` state rather than false success | Health and failure model |
| Stale authority / duplicate daemon | Single runtime owner; control pipe ownership checked; never start a second daemon | `AGENTS.md` + runbooks |
| Control daemon unavailable | No unauthorized fallback authority; local logs are diagnostic only | README "Unified Command Control Center" |

---

## 4. Trust boundaries

1. **Kernel → user** — WFP callout/ring → adapter → CanonicalEvent. Kernel telemetry is evidence, not authority.
2. **Process → process (IPC)** — Go Nose / CLI / dashboard → Zig control pipe. The Zig daemon is the authority; callers are not.
3. **Language boundary** — Zig hub ← Go/C/C++/Rust/Python/TypeScript spokes. Cross-language contracts are tested, not assumed.
4. **Operator → runtime** — dashboard and CLI render daemon-owned snapshots. They never create runtime state.
5. **Build → release** — signed manifest and pinned trust anchor establish build identity.

---

## 5. What the model deliberately does not claim

- It does not claim protection against a malicious kernel-mode administrator.
- It does not claim that a `BLOCK` policy label equals a host block.
- It does not claim tamper-proof logging. Records are **tamper-evident** via hash-chain verification.
- It does not claim all 23 rules are live-proven. Only stated evidence levels apply.
- It does not claim field/production fleet deployment. E7 in this repository means release
  signing/rebuild.

---

*See also: [Security boundaries](architecture/SECURITY_BOUNDARIES.md) ·
[Failure matrix](OPERATIONAL_FAILURE_MATRIX.md) · [Security policy](../SECURITY.md)*
