# Security Threat Model — AEGIS NIDS Windows

> Scope: the detection-only production runtime described in `README.md`, `SYSTEM_MAP.json`,
> `FLOW_MAP.json`, and `AUTHORITY_MAP.json` at current build source `aa3b7b0`.
> This is a design-level threat model, not a penetration test result. Controls are listed with the
> layer that owns them; where a control is only partially implemented, it is marked as such.
>
> The earlier scope records at `a26c573`, `43a8bcc`, `7822f4c`, `493648f`, `4bc8244` and
> `f1f89c1` are HISTORICAL; they are not the current build source.
>
> Evidence scope (updated 2026-11-26): E3 and a narrow elevated canonical-pipe E4/E5 proof at
> `43a8bcc` are HISTORICAL at that source. E2 unit proof, narrow private-pipe E3 and owner-run
> elevated canonical-pipe E4/E5 `-inject` exact-delta proofs with a verified host restore at
> `7822f4c` were current at that source and are now HISTORICAL relative to `aa3b7b0`. S1/S2/S3/S4
> added source-level producer, replay, identity and canonical-policy bytes at E2 only. No proof
> here establishes full current-head
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
| IPC spoofing / unauthorized control request | Daemon-owned snapshot and role/ACL checks; active v2 enforces `protocol_version=2`, ±60 s freshness and a single-use nonce at dispatch | `src/control/handler_registry.zig:184-215` and `src/control/replay_guard.zig:11-21,65-81`; the 1024-entry ring is process-local, so restart resets it and eviction can reuse a nonce. Narrow E5 covers exact in-process replay; no durable or keyed guarantee is claimed. |
| Event injection from a sensor | Schema validation, length-prefixed framing, runtime-owned queue | Normalizer + runtime |
| Malformed / oversized IPC message | Bounded framing and explicit rejection path | Codecs + runtime; exact limits in contract docs |
| Duplicate / replayed events | Exactly-once counters (`duplicate_event_ids`, `nose_non_monotonic_event_ids`) reported by health | Data-plane counters; see `tests/` |
| Queue exhaustion / resource abuse | Bounded queue with observable shedding on full (drop-on-full, **not** blocking-producer backpressure); `shed_overload` and drop counters exposed to health | Zig runtime; is intentionally observable, not silent |
| Detection bypass / visibility gap | 23 rules across multiple layers; most L4 negative controls are HISTORICAL proof. C6 source admits VLAN/QinQ on Ethernet and walks common IPv6 extension headers; L7 sees plaintext bytes only | BPF `vlan or ip or ip6` from `7822f4c` remains for Ethernet; `aa3b7b0` uses `ip or ip6` on the exact DLT_NULL loopback selector after a real host failure proved the strict filter aborted capture there. R9006 has a narrow E6 PASS at `aa3b7b0`; full efficacy and VLAN/QinQ on loopback are not claimed. LIM-1 remains open |
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

## 6. Open gaps at current build source `aa3b7b0`

These are source-observed gaps, not host-effect claims. C6 changed capture source at `7822f4c`
(now HISTORICAL) and S1/S2/S3/S4 added source-level producers, replay, identity and canonical
policy bytes. S2 replay denial and S3 durable identity now have narrow E5 host proof at
`aa3b7b0`. The canonical pipe-reader shutdown and S1's R2003 producer now have narrow E5 host
proof at this source; VLAN/IPv6 host visibility remains E2-only. The gaps that cannot be
physically proven here are recorded as `CLOSED as documented gap` in
`analysis/current-head/REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md` — that is a status-page
disposition, not an evidence promotion. They are the boundary of the controls in §3.

| Gap | Source fact | Status |
|---|---|---|
| Active control nonce/replay | S2 `4bc8244` enforces `protocol_version=2`, 32-hex nonce, ±60 s freshness and a bounded process-local replay ring in the active Zig control handler; the Python builder is `tools/aegisctl/envelope.py`. | **PASS narrow E5 at `aa3b7b0`** — exact replay denial on the rebuilt daemon (`REPLAY_DENIED`); see `analysis/current-head/S2S3-HOST-PROOF-E5-AA3B7B0-20261126.md` |
| VLAN / QinQ visibility | C6 sets BPF `vlan or ip or ip6` in `nose/capture.go` and unwraps up to two tags (802.1Q + 802.1ad) in `src/capture/packet_decoder.zig`, pinned by Zig tests. | **SOURCE-FIXED / E2 ONLY** — tagged frames not host-proven at `aa3b7b0` |
| IPv6 extension headers | C6 walks Hop-by-Hop, Routing, Destination Options, Fragment and AH with an 8-hop fail-closed bound in `src/capture/packet_decoder.zig`; ESP and No-Next-Header stop the walk. Go keeps the full v2 tail (`nose/capture.go:299-322`). | **SOURCE-FIXED / E2 ONLY** — no host proof at `aa3b7b0` |
| Event identity / time | S3 `f1f89c1` adds durable per-interface v3 provenance (`capture_sequence`, `producer_epoch`, `producer_generation`, `interface_id`) from Go Nose with duplicate/regression refusal at Zig ingress; C6 `monotonic_ns` semantics remain. | **PASS narrow E5 at `aa3b7b0`** — generation `5→6`, sequence `736→1324`, zero duplicate/regression/invalid rows |
| Canonical pipe-reader shutdown | C6 bounds the pipe reader's send/timer selects and records exact framing/drop counters. | **PASS narrow E5 at `aa3b7b0`** — `-inject` exact deltas, harness SHA-256 `55306B0A…710B3`, verified restore; see `analysis/current-head/PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126.md`. The **Go `capture.go` adapter** on a physical NIC remains E2-only / `CLOSED as documented gap` |
| R2003 `CommandLine` producer | S1 `493648f` recovers `ProcessCommandLineInformation` as AEGT TLV kind 2 on the existing consumer path. | **PASS narrow E5 at `aa3b7b0`** — one verified `rule_id=2485705370` row with two independent negative controls and verified restore; see `analysis/current-head/R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md` |
| Detection matrix at `aa3b7b0` | Full matrix rows were measured at `f4cde3c`; E3/E4/E5 at `43a8bcc` and narrow E3/E4/E5 at `7822f4c` are HISTORICAL relative to the current source. | R9006 **PASS narrow E6** and R2003 **PASS narrow E5** at `aa3b7b0`; full 23-rule matrix **NOT RE-MEASURED / NOT_PROVEN** — `CLOSED as documented gap`, see `docs/portfolio/DETECTION_MATRIX_CURRENT.md` |

None of these gaps authorizes a host effect, changes a rule or wire field, or creates a MITRE
mapping. The nonce/replay, durable-identity, pipe-reader shutdown and R2003 producer gaps have
narrow E5 proof at the current source. The full 23-rule matrix, coverage-guided fuzzing,
VLAN/IPv6 host visibility, Go capture-adapter shutdown, driver/kernel lifecycle, E7 and clean
install/uninstall remain `NOT_RUN`/`NOT_PROVEN` and are `CLOSED as documented gap` — no gate,
level, result or `status_basis` was promoted. The only OPEN item is a fresh 24 h soak at
`aa3b7b0`. See `analysis/current-head/REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md` and
`analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`.

---

*See also: [Security boundaries](architecture/SECURITY_BOUNDARIES.md) ·
[Failure matrix](OPERATIONAL_FAILURE_MATRIX.md) · [Security policy](../SECURITY.md)*
