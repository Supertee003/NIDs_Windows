# Security Boundaries and Privilege Separation

> Verified against current source at build source `a53eda8`. This is a design/boundary document,
> not a penetration test. **Do not use `CONTRACT_MAP.json` CONTRACT-04 as current control-plane
> truth** — it still describes the frozen v1 IPC; the active path is v2 source code cited below.
> Related: [Threat model](../SECURITY_THREAT_MODEL.md), [Security policy](../../SECURITY.md),
> [Failure matrix](../OPERATIONAL_FAILURE_MATRIX.md).

---

## 1. Boundary map

```text
 KERNEL MODE
 ┌──────────────────────────────────────────────────────────────┐
 │ WFP callout: classify() → bounded L4 payload → ring buffer  │
 │ IOCTL read-only telemetry; BLOCK_FLOW refused NOT_SUPPORTED │
 └───────────────────────┬──────────────────────────────────────┘
                         │ device IOCTL (observe only)
 ────────────────────────│────────────── trust boundary ────────
                         ▼
 USER MODE — acquisition spokes (no verdict authority)
 ┌──────────────────────┐   ┌──────────────────────────────────┐
 │ Go Nose / Npcap      │   │ C/C++ WFP / ETW / FIM / Registry │
 │ length-prefixed pipe │   │ adapters → CanonicalEvent        │
 └──────────┬───────────┘   └────────────────┬─────────────────┘
            └──────────┬──────────────────────┘
                       ▼
 USER MODE — single runtime authority
 ┌──────────────────────────────────────────────────────────────┐
 │ Zig daemon: ingestion → queue → detection → correlation     │
 │             → Rust PEP (evidence only) → forensic records   │
 │ control plane: \\.\pipe\aegis_control (message mode, 1 inst)│
 └──────────┬───────────────────────────────┬───────────────────┘
            ▼                               ▼
   CLI / web dashboard              logs + hash chain
   (render daemon snapshot)         (tamper-evident)
```

## 2. Kernel boundary — WFP telemetry

Source: `drivers/wfp_callout/aegis_wfp_callout.c:7-14`, `aegis_wfp.c:923-932`,
`aegis_wfp.h:102-111`, `aegis_wfp.inf:1-4`.

| Question | Verified answer |
|---|---|
| Does the callout block traffic? | **No.** `classify()` is explicitly fail-open; it copies a bounded L4 payload into the ring |
| Is enforcement reachable? | **No.** `IOCTL_AEGIS_BLOCK_FLOW` (0x801) is refused with `STATUS_NOT_SUPPORTED`. The legacy handler stays for ABI stability but is unreachable |
| IOCTLs present | `READ_EVENTS` 0x800 (read), `BLOCK_FLOW` 0x801 (refused), `GET_STATS` 0x802, `UNBLOCK_FLOW` 0x803 (cleanup of pre-existing AEGIS filter only), `QUERY_FILTER` 0x804 |
| Partial record handling | `READ_EVENTS` copies whole records; a record that would not fit is neither consumed nor emitted |
| Payload limit | `AEGIS_MAX_PAYLOAD_SIZE = 4096` bytes; no TCP reassembly; TLS bodies stay ciphertext; inbound WFP has no TCP-flags evidence |
| Driver signing | WDK/VS2022 build, **test signing** required in source/INF. Production/EV/HLK signing and Microsoft attestation are not implemented and are out of scope |
| Current lab binding | `wfp.kernel_owned=false`, `mode=npcap_primary` in the live snapshot — WFP is available but is not the primary packet source on this host |

**Do not claim:** "verified on WFP" from the code-level scope document, or E5 proof for the newest
WFP source changes (`EVIDENCE_INDEX.json:180` says no WDK build, no E5, no soak for that source).

## 3. IPC boundary — control plane

Source: `src/platform/win32_pipe.zig`, `src/control/protocol.zig`,
`src/control/handler_registry.zig`, `tools/aegisctl/client.py`.

| Property | Implementation |
|---|---|
| Endpoint | `\\.\pipe\aegis_control` (`win32_pipe.zig:17`) |
| Framing | Message mode + message read mode + wait; one JSON request and one JSON response per connection (`win32_pipe.zig:21-24`) |
| Single owner | `CONTROL_PIPE_MAX_INSTANCES = 1` — a stale core cannot answer alongside a new one (`win32_pipe.zig:29-33`) |
| DACL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)` — SYSTEM, Administrators, Authenticated Users; **no Everyone ACE** (`win32_pipe.zig:66-79`) |
| Fail-closed setup | If the security descriptor cannot be built, endpoint creation is refused with `ControlPipeSecurityFailed` (`win32_pipe.zig:228-240`) |
| Caller role | Derived from `ImpersonateNamedPipeClient` → `OpenThreadToken` → `TokenElevation`. Elevated = `.privileged`, otherwise `.operate`. The JSON caller never supplies a role (`win32_pipe.zig:137-180`) |
| Authorization | Per-command dispatch checks the token-derived role against the command contract (`handler_registry.zig:183-205`); every mutation requires an elevated caller |
| Client PID | Best-effort via `GetNamedPipeClientProcessId`; unavailable PID is warned, not promoted to authority |
| Active protocol | **v2 JSON**, 33 dotted commands + aliases (`shared/protocol/control_protocol.md:106-117`) |
| **Replay / freshness** | **NOT IMPLEMENTED on active v2.** `Envelope` declares `nonce`/`issued_at_ms` (`protocol.zig:286-298`) but dispatch reads only `command` and `payload`; the v1 `(request_id, nonce)` table is in inactive `src/policy/control_ipc.zig` (`CONTROL-AUTH-001-20261110.md:67-71`) |

### What an unprivileged local process can do

An `Authenticated Users` token can connect and send commands. The second gate is per-command
authorization: reads/queries are available at `.operate`, mutations require `.privileged`, and even
a privileged command cannot authorize a host effect because no such path exists. A failed
authentication returns `AUTH_UNAVAILABLE` / `UNAUTHORIZED`.

**Do not claim** nonce/freshness/replay protection, and **do not** treat the stale v1
`CONTRACT_MAP.json` entry (which claims freshness/replay and `rules.reload` at `OPERATE`) as
current behavior.

## 4. Language and authority boundaries

| Component | Privilege / role | Authority it does **not** have |
|---|---|---|
| WFP kernel callout | Kernel, telemetry only | No packet modification, no **reachable** host-effect creation path (the legacy block handler and persistent-filter recovery are disclosed in the source audit) |
| Zig daemon | User, **single runtime owner** | No host effects; cannot be duplicated |
| Go Nose | User, acquisition | No rule file, no pattern matcher, no verdict; acquisition-authored verdicts are stripped at Zig ingress |
| C/C++ adapters | User/native, acquisition | No policy decision |
| Rust PEP | User, detection-only policy + crypto | No host-effect authority, no WFP mutation, no detection logic |
| Python brain / CLI | User, analytics + tooling | No privileged OS calls, no enforcement |
| TypeScript | Authoring/compiler | No runtime presence |

## 5. Operator boundary

CLI and web dashboard consume the daemon-owned snapshot; they never create runtime state. Process
scans are diagnostic only and are not promoted to truth while the control daemon is available.
A `BLOCK` policy label is **intent**: it is rendered as `observed` with
`host_effect_confirmed=false` unless a verified receipt proves a host postcondition — which this
product cannot produce.

## 6. Evidence boundary

Forensic records are 4 KiB slots with CRC32 plus SHA-256 chain links (prev/current hash). The chain
verifier checks CRC, per-record hash, and linkage between retained records; linkage for the oldest
retained record is skipped because its predecessor may have been overwritten
(`src/forensic/forensic_pipeline.zig:636-665`). Ring overwrite is disclosed through `retained`,
`overwritten`, and `oldest_record_seq`.

`forensics.replay` performs **integrity-only observe replay**: it re-verifies CRC and the hash
chain, re-exports the source range, and explicitly does **not** re-execute detection/policy/PEP.
`events_replayed` stays `0` and `pass` stays `false` until a deterministic harness exists
(`src/control/handler_registry.zig:1902-1943`). Call that "integrity verification", not
"detection replay matched".

## 7. Claim guardrail for interviews

Safe to say: *fail-open WFP telemetry, no host-effect IOCTL, message-mode named pipe with a
restrictive DACL and token-derived per-command authorization, single runtime owner, tamper-evident
hash-chained records, detection-only PEP.*

Never say: *production IPS, WFP blocking, EV/HLK-signed driver, replay re-executed detection,
nonce/replay-protected IPC, tamper-proof logging, or confirmed host blocks.*
