# Security Threat Model — AEGIS NIDS Windows

> Scope: the detection-only production runtime described in `README.md`, `SYSTEM_MAP.json`,
> `FLOW_MAP.json`, and `AUTHORITY_MAP.json` at current build source `7822f4c`.
> This is a design-level threat model, not a penetration test result. Controls are listed with the
> layer that owns them; where a control is only partially implemented, it is marked as such.
>
> The earlier scope records at `a26c573` and `43a8bcc` are HISTORICAL; they are not the current
> build source.
>
> Evidence scope (2026-11-25): E3 and a narrow elevated canonical-pipe E4/E5 proof at
> `43a8bcc` are HISTORICAL at that source. At `7822f4c` E2 unit proof and a narrow private-pipe
> `-inject` E3 exact-delta proof are current; E4/E5 remain **NOT_PROVEN** until owner-run
> elevated re-proof. No proof here establishes full current-head
> Windows E5 / kernel IDS qualification, which remains `NOT_PROVEN`
> (`runtime_manifest.json:535`). See `docs/evidence/PROVENANCE.md`.

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
| IPC spoofing / unauthorized control request | Daemon-owned snapshot and role/ACL checks in the control contract; active nonce/replay is **not enforced** on the production path | `src/control/protocol.zig:296-297` only declares `issued_at_ms`/`nonce`; the replay-protected module `src/policy/control_ipc.zig` is test-only (`src/all_tests.zig:107`). Treat replay defense as an open gap, not a closed control. |
| Event injection from a sensor | Schema validation, length-prefixed framing, runtime-owned queue | Normalizer + runtime |
| Malformed / oversized IPC message | Bounded framing and explicit rejection path | Codecs + runtime; exact limits in contract docs |
| Duplicate / replayed events | Exactly-once counters (`duplicate_event_ids`, `nose_non_monotonic_event_ids`) reported by health | Data-plane counters; see `tests/` |
| Queue exhaustion / resource abuse | Bounded queue with observable shedding on full (drop-on-full, **not** blocking-producer backpressure); `shed_overload` and drop counters exposed to health | Zig runtime; is intentionally observable, not silent |
| Detection bypass / visibility gap | 23 rules across multiple layers; L4 negative controls are HISTORICAL proof. C6 source admits VLAN/QinQ and walks common IPv6 extension headers, but no host measurement of the new path exists; L7 sees plaintext bytes only | Source-level changes at `7822f4c` (BPF `vlan or ip or ip6` in `nose/capture.go`; bounded two-tag VLAN unwrap and IPv6 extension walk in `src/capture/packet_decoder.zig`) are E2-only; detection efficacy at `7822f4c` is NOT_PROVEN. LIM-1 remains open |
| Forensic record tampering | Hash-chain integrity verification plus `forensic verify` CLI | Forensics; **tamper-evident**, not tamper-proof. Replay is integrity-only, not live pipeline re-execution (`src/control/handler_registry.zig:1943`) |
| Release binary substitution | Ed25519 signature over `SHA256SUMS`; 674/674 artifact hashes verified against **one** signature; pinned trust anchor | Release engineering; 674 is a hash count, not a signature count |
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

## 6. Open gaps at current build source `7822f4c`

These are source-observed gaps, not host-effect claims. C6 changed capture source at `7822f4c`;
its unit tests are E2 only, and no host measurement of the new path exists. They are the boundary
of the controls in §3.

| Gap | Source fact | Status |
|---|---|---|
| Active control nonce/replay | `src/control/protocol.zig:296-297` declares `nonce` and `issued_at_ms`; no production handler consumes them. The replay-protected request module is only imported by `src/all_tests.zig:107`. | **OPEN** — declared, not enforced (untouched by C6) |
| VLAN / QinQ visibility | C6 sets BPF `vlan or ip or ip6` in `nose/capture.go` and unwraps up to two tags (802.1Q + 802.1ad) in `src/capture/packet_decoder.zig`, pinned by Zig tests. | **SOURCE-FIXED / E2 ONLY** — tagged frames not host-proven at `7822f4c` |
| IPv6 extension headers | C6 walks Hop-by-Hop, Routing, Destination Options, Fragment and AH with an 8-hop fail-closed bound in `src/capture/packet_decoder.zig`; ESP and No-Next-Header stop the walk. Go keeps the full v2 tail (`nose/capture.go:299-322`). | **SOURCE-FIXED / E2 ONLY** — no host proof at `7822f4c` |
| Event identity / time | C6 stamps `monotonic_ns` from a process-relative origin (`monotonicNowNS`), so the field now matches its schema meaning. `eventSequence` remains process-local and the Zig reader still comments on restart boundaries (`src/capture/nose_pipe_reader.zig:285,379`). | **PARTIAL** — cross-process monotonic identity still not proven |
| Capture shutdown | C6 returns capture errors to `main` instead of `os.Exit` in the goroutine, gives collectors and the live-talkers loop a stop channel, and uses bounded send/timer selects. | **SOURCE-FIXED / E2 ONLY** — bounded shutdown not host-proven |
| Detection matrix at `7822f4c` | E5/E6 rows were measured at `f4cde3c`; E3/E4/E5 at `43a8bcc` are HISTORICAL and cover the `-inject` lifecycle only. | **NOT RE-MEASURED / NOT_PROVEN** — see `docs/portfolio/DETECTION_MATRIX_CURRENT.md` |

None of these gaps authorizes a host effect, changes a rule or wire field, or creates a MITRE
mapping. The remaining OPEN items (active nonce/replay, cross-process identity) require further
source work and fresh E3/E4/E5 proof.

---

*See also: [Security boundaries](architecture/SECURITY_BOUNDARIES.md) ·
[Failure matrix](OPERATIONAL_FAILURE_MATRIX.md) · [Security policy](../SECURITY.md)*
