# AEGIS Current-HEAD Forensics and Security Review

**Review scope:** `src/forensic/`, `shared/runtime/`, evidence generators, `src/tests/forensic/`, fuzz targets, security tests, authority review, audit/logging, hash chains, export/replay/verification, and cleanup records.

**Repository:** `NIDs_Windows`

**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`

**Review mode:** Read-only source, build-graph, and test-activation review. No source file or generated truth artifact was changed. The only deliverable created by this review is this report.

## 1. Executive conclusion

AEGIS has a useful set of forensic, replay, hash-chain, and authority-oriented modules, but the current production call path does not satisfy the required evidence invariant. The active Zig daemon records a bounded in-memory `ForensicRing`; it does not persist a finalized evidence record that links **event, decision, policy digest, PEP request, provider/filter, receipt, audit, runtime generation, and cleanup**. A successful PEP decision is therefore not a complete forensic success claim.

The repository must remain **detection-only or explicitly degraded** for prevention claims. A source-level receipt contract exists, but the active pipeline neither constructs nor validates an `EnforcementReceipt`, does not record provider or filter identity, and does not record a postcondition or cleanup result. Windows host effect, elevated behavior, named-pipe ACL behavior, driver/provider behavior, clean restart, and cleanup were not executable in this Linux sandbox and are **UNVERIFIED**.

Replay is not currently a deterministic observe-only production feature. The control handler returns a success-shaped placeholder with zero events, the proof replay copies stored outcomes rather than re-running historical input, and the general replay APIs compare caller-supplied `PipelineResult` values. The replay contract also exposes an `enforce` mode and the control protocol marks replay as a mutation. This is incompatible with the requirement that replay be observe-only and deterministic.

The most important stop-the-line issues are:

1. **Active forensic records are incomplete and volatile.** `src/pipeline/event_processor.zig:198-200` appends directly to `ForensicRing` after the PEP decision, but the record format has no trace ID, PEP request ID, policy digest, provider, filter ID, receipt, runtime generation, or cleanup result. The ring is freed on daemon shutdown (`src/daemon.zig:137-140`).
2. **The apparent forensic/export/replay API is partly placeholder or support code.** `src/control/handler_registry.zig:445-466` returns `not_implemented`, `exported=true`, and `replayed=true` without showing or exporting records or running replay.
3. **The active PEP boundary produces no authoritative receipt or host-effect proof.** `rust-src/lib.rs:404-426` returns an action decision after a provider call, but no filter identity, provider response identity, postcondition, audit ID, or signed receipt is returned. The Zig wrapper maps an unchecked response byte into an enum (`src/policy/pep_bindings.zig:98-105`).
4. **Replay can be treated as mutation and has a dangerous mode.** `src/forensic/replay_verifier.zig:22-27` defines `enforce`; `src/control/protocol.zig:220-221` marks replay as mutation with a postcondition; the handler itself does not enforce observe-only semantics.
5. **Truth artifacts are stale and the relevant Python test suite did not execute in this sandbox.** `python tools/truth.py verify --json` reported stale `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `build_manifest.json`, and `AI_CONTEXT.md`. `pytest` was unavailable, and no Zig or Windows execution was available.

## 2. Scope and method

The review started from `README.md`, the handoff, Git HEAD, and the current build graph. Source and build configuration were given priority over declarations in reports and manifests. The active executable is identified from `build.zig`, which creates `aegis_nids` from `src/main.zig`; the daemon path was then traced into the event queue, Go Nose pipe reader, event processor, PEP wrapper, dispatcher, and forensic ring. The review separately classified modules named by the runtime spine, test aggregators, proof modules, Python structural tests, and generated truth artifacts.

The following observations were made from current source. Windows-only actions, elevated execution, WFP/driver behavior, named-pipe ACL behavior, and VMware host effect were not inferred from file presence. They are reported as **UNVERIFIED**.

`python3 tools/truth.py verify --json` was run against this HEAD. It returned `valid: false` because several generated artifacts carry another commit. Direct invocation of the Python test functions showed structural passes and material failures in T12: the declared golden path does not contain the required forensics/replay stages, the manifest shape lacks the expected `modules` key, and authority invariants are empty. The T19 test module could not import because `pytest` is not installed. No source or generated truth file was repaired.

## 3. Active call graph and ownership

### 3.1 Active production path

```text
build.zig
  -> src/main.zig
     -> platform/win32_service.mainEntry()
        -> daemon.runDaemon()
           -> security_check.SecurityCheck.run()
           -> runtime state/capability initialization
           -> forensic.ForensicRing.initMemory(64 MiB)
           -> bridge and worker startup
           -> pipeline.event_processor.pipelineLoop()
           -> capture.nose_pipe_reader.runPipeReaderLoop()
              -> canonical.deserializeFromBytes()
              -> pipeline.event_queue.pushCanonicalEvent()
           -> event_processor.processEvent()
              -> detection/policy evaluation
              -> pep.PepEnforcer.enforce()
              -> ActionDispatcher.dispatch()
              -> forensic_ring.append()
           -> platform.win32_pipe control server
              -> handler_registry dispatch
              -> forensics.verify calls ring.verifyHashChain()
```

The concrete production entrypoint and worker setup are in `src/main.zig:20-35` and `src/daemon.zig:85-140,353-496`. The daemon does import and initialize `src/forensic/forensic_pipeline.zig`. It does **not** initialize `src/forensic/forensic_log.zig`, `src/forensic/forensics_engine.zig`, `src/tests/integration/forensics_integration.zig`, or the replay verifier in the active path.

The Go Nose reader deliberately validates a fixed 109-byte frame and submits it to `pushCanonicalEvent` (`src/capture/nose_pipe_reader.zig:245-300`). That call does not provide original payload bytes. `pushCanonicalEvent` therefore queues an empty payload (`src/pipeline/event_queue.zig:62-70`), while the event metadata may still state a non-zero payload length/hash. The active forensic append uses the bounded queue payload, not a verified payload reference (`src/pipeline/event_processor.zig:198-200`).

### 3.2 Support, tooling, proof, and legacy paths

| Classification | Paths | Review consequence |
|---|---|---|
| Active production | `build.zig`, `src/main.zig`, `src/daemon.zig`, `src/pipeline/event_processor.zig`, `src/pipeline/event_queue.zig`, `src/capture/nose_pipe_reader.zig`, `src/forensic/forensic_pipeline.zig`, `src/control/*`, `rust-src/lib.rs` | These paths determine current runtime claims. |
| Support or alternate implementation | `src/forensic/forensic_log.zig`, `src/forensic/forensics_engine.zig`, `src/tests/integration/forensics_integration.zig`, `src/tests/integration/replay_integration.zig`, `src/forensic/siem_forwarder.zig`, `src/forensic/replayable_security.zig` | Presence does not prove daemon ownership or production activation. |
| Tooling/proof/test | `src/tests/proofs/*`, `src/tests/forensic/*`, `tests/forensics/*`, `tests/security/*`, `src/fuzz_entry.zig`, `src/tests/fuzz_main.zig` | These provide source or component evidence only unless run and tied to this HEAD. |
| Declared but not proven as active | `src/contract/runtime_spine.zig` production module list, `runtime_manifest.json` golden path | The declarations conflict with the actual daemon call graph and current Python test expectations. |
| Legacy | `src/forensic/forensics_engine.zig` is a separate result/ring design; older core paths are separately marked legacy in repository architecture records | Must not be used to upgrade active-path claims. |

`src/contract/runtime_spine.zig:88-118` lists `forensic_log`, `forensics_integration`, and replay-related modules, but those registrations are declarative. The active daemon uses a different `ForensicRing` implementation. `runtime_manifest.json:85-107` currently lacks the declared forensic/replay golden path expected by T12, and its schema also lacks the `modules` object expected by the tests. This is a source/build-truth divergence, not evidence that either path is correct.

## 4. File-level observations

### 4.1 `src/forensic/forensic_pipeline.zig`: active ring integrity and durability

`ForensicRing` stores fixed 4096-byte records in a process-local byte ring (`src/forensic/forensic_pipeline.zig:34-70`). Append is mutex-protected and computes a SHA-256 record hash plus CRC (`:88-121,218-256`). Snapshot reads are copied under the mutex (`:260-267`), which is a sound local concurrency boundary. The test suite includes corruption, wrap, sequence, and concurrent append/read cases (`:342-702`).

However, the format is not sufficient for a successful enforcement claim. `RecordHeader` contains event ID, rule ID, policy ID, PEP decision, audit ID, record sequence, and hashes (`:39-54`), but does not contain a policy digest, policy version, detection/incident ID, PEP request ID, trace ID, provider, filter ID, receipt version/status, host-effect observation, runtime generation, source producer epoch, cleanup request/result, or binary/context identity. `appendReceipt` exists (`:123-147`) but is not used from the active event processor and its fields are not serialized into the active record.

The ring is **in-memory only**. `daemon.runDaemon` allocates it and releases it on process exit (`src/daemon.zig:134-140`). A clean restart therefore loses all prior records and resets sequence state. Hashing detects changes to retained bytes; it does not provide durable retention, an external anchor, signer identity, or proof that overwritten records existed. On wrap, `verifyHashChain` intentionally skips the link from the first retained record to its overwritten predecessor (`forensic_pipeline.zig:301-330`). This is acceptable as a bounded-ring integrity rule only if the loss and boundary are durably recorded. They are not.

`initMemory` accepts arbitrary sizes, including zero or a size smaller than `RECORD_BYTES` (`:70-74`). `append` and `appendWrapped` then use modulo and fixed slices (`:99-103,158-164`), so an invalid configuration can panic or fail before returning a controlled error. There is no test for zero, non-multiple, or one-record-minus-one-byte storage. `recordCount()` returns total writes rather than retained record count (`:84-86`), which can surprise export/replay consumers and can wrap after a long-lived process.

`verifyHashChain` holds the ring mutex while scanning every retained record and recomputing CRC/SHA-256 (`:306-330`). At the configured 64 MiB ring this is a large synchronous operation on the control thread. Repeated authorized verification requests can create latency and producer starvation. `ReplayVerifier.exportRecords` reads `recordCount()` without the ring lock and then locks once per record (`src/forensic/replay_verifier.zig:142-165`), so concurrent appends can produce a logically inconsistent source range even though individual snapshots are memory-safe.

### 4.2 Active event ordering and process generation

The event processor performs PEP and dispatch, then appends the forensic record (`src/pipeline/event_processor.zig:152-200`). It writes a human-readable diagnostic line before the append (`:175-196`), but the diagnostic line is not the authenticated evidence record. The stack `SecurityDecisionTrace` is populated for detection, policy, PEP, and audit (`:53-55,132-178`), but it is neither finalized nor persisted, and it does not prove that all required links were present.

`runtime_state.zig:77-87` uses plain process-local counters for forensic records, audit IDs, PEP request IDs, and trace IDs. There is no runtime-generation field. `src/capture/nose_pipe_reader.zig:227-234` explicitly resets the strict monotonicity comparison at each producer connection because Go Nose uses a process-local sequence. The source comment identifies cross-generation identity continuity as a separate task. Consequently, an event ID, audit ID, PEP request ID, or trace ID can repeat after restart or reconnect, and the active forensic record cannot disambiguate the generations.

The queue has a producer mutex and a serialized consumer mutex (`src/pipeline/event_queue.zig:22-51,155-166`), which addresses the documented reservation race. It is bounded and increments a drop counter when full. It does not persist a drop ledger into the forensic chain, and it does not tie a dropped event to a generation or source connection. The ordering proved by the ring is consumer append order, not necessarily capture timestamp order or a total order across all adapters.

### 4.3 `src/forensic/forensics_engine.zig`: alternate result ring

`ForensicsEngine` records a rich `PipelineResult` containing verdict, correlation, threat-intel, brain, policy, and PEP status (`src/forensic/forensics_engine.zig:37-73`). It has a bounded 4096-entry in-memory ring (`:31,89-100`) and per-process sequence IDs (`:123-170`). This is useful component code but is not the ring allocated by the active daemon. Its `PipelineResult` still lacks policy digest, PEP request ID, receipt/provider/filter identity, runtime generation, and cleanup. Its `recent()` returns an internal slice and incorrectly documents that callers must handle wrap (`:187-193`), while the function itself can return an out-of-bounds slice when the selected range crosses the physical end of the ring. No active call site was found in `daemon.runDaemon`.

### 4.4 Logging and audit durability

`src/forensic/forensic_log.zig` is a separate NDJSON logger. It opens `logs\\aegis_core.ndjson` and flushes only critical/error events (`:39-113,242-323`). It is not initialized by the active daemon shown in `daemon.zig`, and it has no hash chain, signed checkpoint, receipt linkage, policy digest, runtime generation, or cleanup linkage. It does not check that `WriteFile` wrote the complete buffer (`:311-317`). Rotation ignores rename errors and does not implement the declared age policy (`:146-203`); `LOG_MAX_AGE_S` is defined but not used to rotate by age.

The logger's unsynchronized `g_initialized` check can race with `shutdown` (`:244-250` versus `:95-113`). `capturePayload` writes unlimited caller-provided bytes into a relative `logs\\payloads` directory and uses only the first 64 bits of SHA-256 in the filename (`:389-419`). A prefix collision conflates different payloads, there is no file ACL or encryption setup, and any create/write failure is treated as an existing payload filename (`:411-417`). This can falsely report capture success and can create disk-exhaustion risk.

`src/control/audit.zig` is a 4096-entry memory ring (`:22-42`). It records command, role, caller PID, result, latency, and payload length, but not authenticated token/SID, policy digest, PEP request, provider/filter, receipt, trace, generation, or cleanup. Despite the module comment, the module itself has no durable file append or hash chain (`:1-5`). `recent()` returns a slice after unlocking (`:44-54`), and `toJson()` unlocks before copying entries (`:56-76`); concurrent recording can mutate the returned/read entries while they are being consumed. The ring evicts old audit decisions without a durable eviction marker.

`handler_registry.dispatch` audits an authorization denial and the final handler result (`src/control/handler_registry.zig:179-223`), but parse errors, missing commands, unknown commands, and missing handlers return through `sendError` without an audit entry (`:150-201`). More seriously, `forensics.export` and `forensics.replay` return success-shaped values even though their handlers are placeholders (`:461-466`). Those successful audit records would document an operation that did not occur.

### 4.5 Evidence records, provenance, and cleanup

`src/forensic/evidence_record.zig` provides a fixed 1024-byte `EvidenceRecord` and a SHA-256 self-hash (`:31-70,165-197`). It includes HEAD, environment strings, test profile, event/flow/audit IDs, and artifact hash. It does not include policy digest, PEP request, provider/filter, receipt, runtime generation, cleanup, or rollback. `validate()` checks only magic and version (`:101-103`); callers must separately invoke integrity checks. Setters silently truncate and do not add an explicit length field or rejection signal (`:105-163`). `EvidenceChain` is an unbounded `ArrayList` with no mutex or durable storage (`:211-251`).

`src/forensic/provenance.zig` models a complete chain (`:18-64`) and storage lifecycle (`:70-134`), but `ProvenanceTracker.register` accepts incomplete chains and only records a 64-bit Wyhash provenance summary (`:248-259`). The audit log is bounded and evicts the oldest entry with `orderedRemove(0)` (`:182-223`), which is O(n), and its integrity check only compares timestamps. There is no cryptographic chain for these audit entries, no persistence, and no automatic retire/archive/purge implementation. `verifyAll()` returns false for any purged lifecycle (`:290-297`), so the model cannot represent a completed purge as a valid lifecycle state.

Cleanup is not linked to any active enforcement record. The Rust ABI exposes `aegis_pep_unblock_ip` (`src/policy/pep_bindings.zig:53-58,112-115`), but the active processor does not create an ownership record or call it as part of a receipt/cleanup workflow. The active ring has no cleanup field. The installer/recovery types in `src/forensic/installer.zig` are declarations and bounded test structures, not proof that Windows filters, services, drivers, files, or evidence are cleaned and verified.

### 4.6 Replay, export, and verification

The replay implementation is split across multiple non-equivalent paths:

* `src/forensic/replay_engine.zig:168-231` compares two caller-supplied `PipelineResult` values. It does not load the historical event, historical policy bytes/digest, context, executable identity, or original provider/receipt. Its comparison is useful as a pure diff helper, not deterministic replay.
* `src/forensic/replayable_security.zig:114-155` accepts a caller-supplied new outcome and attributes differences to caller-supplied atom version numbers. It does not perform the detection or policy evaluation itself.
* `src/tests/proofs/forensic_replay_proof.zig:717-730` explicitly simulates replay by returning the stored verdict/action. The source comments state that production would re-run the pipeline, but the proof does not do so.
* `src/forensic/replay_verifier.zig:142-243` exports retained raw slots, verifies per-record CRC/hash, and accepts caller-supplied `recordReplayResult` values (`:192-216`). It never invokes the detector/policy/PEP pipeline. `finalize()` requires at least one caller-supplied result and no mismatches (`:228-233`), not a proof that historical input was actually replayed.
* `src/forensic/replay_verifier.zig:22-27` exposes `ReplayMode.enforce`. A dangerous mode in a replay contract is contrary to the required invariant unless the type and all entrypoints make it unrepresentable in production.
* `src/forensic/replay_integrity.zig:121-170` has two comparison APIs. `compare()` only compares the common prefix and reports `match=true` when the prefix matches, even if lengths differ; `compareAlloc()` separately handles length mismatch. Consumers can therefore select an unsound comparison method.
* `src/forensic/replay_integrity.zig:38-72` retains one 32-byte hash per packet in an unbounded `ArrayList`; replay input size is not bounded by a maximum packet count or byte budget.

The control plane makes the mismatch externally visible. `src/control/protocol.zig:216-221` declares replay as privileged, a mutation, and requiring a postcondition. `src/control/handler_registry.zig:465-466` returns `{"replayed":true,"events":0}` without consuming a source range, enforcing an observe-only context, producing a replay hash, or recording a result. Thus a caller can receive a successful replay claim with no replay.

The export handler is equally non-functional: `forensicsExport` returns a path string without reading the ring, writing NDJSON, hashing the export, applying redaction, or recording a source range (`handler_registry.zig:461-463`). The proof redaction implementation in `src/tests/proofs/forensic_replay_proof.zig:501-598` has a documented dangling-slice problem in `redact()`, and its `verifyRedaction()` sets `rule_preserved = true` even though `RedactedRecord` contains no rule field (`:664-668`). This is a proof-quality defect, not evidence of safe export.

### 4.7 Sensitive data and SIEM export

The active `ForensicRing` retains raw bounded payload bytes in memory. The separate payload capture path writes full payloads to disk without a size limit, ACL setup, encryption, or retention/secure-delete proof. Source IP, ports, session IDs, event IDs, rules, and payload lengths are available in unredacted internal records. The NDJSON logger does not provide an authenticated redaction boundary.

`src/forensic/siem_forwarder.zig` is an additive support path, not active daemon evidence. Its NDJSON, CEF, and syslog formatters interpolate attacker-controlled strings without JSON/CEF/syslog escaping (`:380-437`). HTTP returns true even when individual requests fail or return a non-OK status (`:257-305`), so forwarding statistics can claim success while records are lost. Batch size, retry count, retry delay, destination, and endpoint are externally configurable without hard bounds (`:91-103`), and the singleton has no synchronization (`:461-505`). UDP/syslog has no authenticity or confidentiality guarantee. These are export attack-surface gaps even if the forwarder remains disabled by default.

### 4.8 Authority review and PEP impact

`src/core/authority_review.zig:81-99` is a data comparison helper, not a source authority lint. Its fail-closed claim is incorrect for incomplete observations: `out.authoritative = out.passing == out.count` makes an empty or short `observed` slice authoritative. It also trusts the caller to supply the observation rows and does not inspect the actual build graph or loaded providers. The current repository has no `tools/authority_lint.py` executable path matching the requested authority-lint role; the available Python security tests are source-structure checks.

The Rust PEP correctly maps missing PEP and non-zero FFI return to a non-enforcing escalation in the Zig wrapper (`src/policy/pep_bindings.zig:79-105`). This containment is positive but does not prove host enforcement. In `rust-src/lib.rs:340-426`:

* `caller_pid` is accepted but not checked against OS caller identity; the capability mask is caller-provided at the ABI boundary.
* `request_id` is not checked for freshness or replay in `aegis_pep_enforce`.
* `signed_by` remains zero and the response contains no receipt, provider identity, filter identity, or postcondition.
* `aegis_pep_unblock_ip` ignores `caller_pid` and `request_id` (`:430-451`).
* The WFP DLL is loaded through relative search candidates (`:230-245`) without an absolute trusted installation path or signature/hash verification. This leaves a DLL search/hijack risk until Windows loader policy and ACLs are proven.
* `PepEnforcer.enforce` uses `@enumFromInt(resp.decision)` without rejecting unknown response values (`pep_bindings.zig:98-105`). A malformed or incompatible provider response can become a runtime safety failure rather than a controlled denial.
* The quota state is read but no block count is added in the shown enforcement path (`rust-src/lib.rs:295-315,350-425`), so the stated quota protection is not demonstrated by this path.

`src/forensic/policy_contract.zig:251-299` itself documents TypeScript/Zig condition ordinal and magic mismatches. A successful claim cannot contain a trustworthy policy digest until policy bytes, signature, version, and cross-language action/condition encoding are frozen and recorded at the PEP boundary.

## 5. Contract and authority impact

The required successful-claim invariant can be assessed against the active `ForensicRing` record and the active event processor as follows:

| Required link | Current active evidence | Assessment |
|---|---|---|
| Event identity | `IpcEvent.event_id` is copied into `RecordHeader.ev_id`; Go Nose preserves frame ID | **Partial.** IDs are process/producer-local across restart and connection boundaries. |
| Decision | `pep_decision` byte is stored | **Partial.** It is an action byte, not a validated receipt or complete enforcement result. |
| Policy digest/version | Only `policy_id` is stored; no digest | **Missing.** `policy_id` alone is not immutable policy identity. |
| PEP request | `g_pep_request_id` exists in runtime state but is not stored in the active record | **Missing.** |
| Provider/filter | No fields in `RecordHeader`; Rust response has no such identity | **Missing.** |
| Receipt | `appendReceipt` exists but is not called; no receipt is created in `processEvent` | **Missing.** |
| Audit | A process-local `audit_id` is stored and a diagnostic is emitted | **Partial.** No durable/authenticated chain and no full request/receipt linkage. |
| Trace | Stack trace is populated but not persisted | **Missing for evidence.** |
| Runtime generation | No generation field in runtime state or record | **Missing.** |
| Cleanup/rollback | No active cleanup result or ownership record | **Missing.** |
| Replay | Placeholder or caller-supplied comparison paths | **Not proven.** |

The authority invariant remains conceptually correct—Zig owns runtime lifecycle and Rust PEP is intended to be the sole enforcement authority—but the evidence boundary does not enforce that distinction. A detector/policy action or PEP decision can still be represented as a block-like forensic byte without a verified `EnforcementReceipt`. The UI and operator surfaces must therefore remain receipt-negative for confirmed blocking until the active record and control paths are corrected.

## 6. Concrete defects and severity

| ID | Severity | Defect | Evidence |
|---|---|---|---|
| F-01 | **Critical / stop-the-line** | Active forensic record cannot prove a successful claim because policy digest, PEP request, provider/filter, receipt, trace, generation, and cleanup are absent. | `src/forensic/forensic_pipeline.zig:39-54`; `src/pipeline/event_processor.zig:152-200` |
| F-02 | **Critical / stop-the-line** | Forensics are process-local and lost at restart; IDs reset without generation binding. | `src/daemon.zig:134-140`; `src/pipeline/runtime_state.zig:77-87`; `src/forensic/forensics_engine.zig:89-100` |
| F-03 | **Critical / stop-the-line** | Export and replay handlers return success-shaped placeholders without performing the operation. | `src/control/handler_registry.zig:445-466` |
| F-04 | **Critical / stop-the-line** | Replay is not guaranteed observe-only and exposes `enforce`; protocol labels replay as mutation. | `src/forensic/replay_verifier.zig:22-27`; `src/control/protocol.zig:216-221` |
| F-05 | **High** | PEP response has no receipt, provider/filter identity, postcondition, or cleanup ownership; relative DLL loading is untrusted until Windows proof. | `rust-src/lib.rs:205-285,404-451` |
| F-06 | **High** | Authority review accepts empty or partial observations as authoritative. | `src/core/authority_review.zig:86-97` |
| F-07 | **High** | Named-pipe stop can hang on blocking `ReadFile` after a client sends a partial frame; create retries ignore stop for up to 60 seconds. | `src/capture/nose_pipe_reader.zig:97-126,129-140,190-216` |
| F-08 | **High** | Active event evidence loses or fails to verify payload bytes: Go Nose supplies metadata-only 109-byte events, while the queue and ring use actual queued payload bytes. | `src/capture/nose_pipe_reader.zig:265-299`; `src/pipeline/event_queue.zig:62-103`; `src/pipeline/event_processor.zig:198-200` |
| F-09 | **High** | Control audit is volatile, not hash-chained/durable, exposes unsafe post-unlock slices, and does not audit all parse/dispatch failures. | `src/control/audit.zig:24-76`; `src/control/handler_registry.zig:150-223` |
| F-10 | **High** | `ForensicRing.initMemory` accepts zero/small/non-record-sized storage and can panic in modulo/fixed-slice operations. | `src/forensic/forensic_pipeline.zig:70-74,99-103,158-164` |
| F-11 | **Medium-High** | `ReplayComparison.compare()` can report a matching common prefix when replay lengths differ; replay hash/result inputs are caller supplied. | `src/forensic/replay_integrity.zig:121-137`; `src/forensic/replay_verifier.zig:192-243` |
| F-12 | **Medium-High** | Full payload capture has no bounded size or ACL, uses a 64-bit filename prefix, and reports success on arbitrary create/write failures. | `src/forensic/forensic_log.zig:389-419` |
| F-13 | **Medium** | NDJSON/CEF/syslog export lacks field escaping and bounded retry/batch controls; HTTP non-OK responses can be counted as successful forwarding. | `src/forensic/siem_forwarder.zig:91-103,257-305,380-437` |
| F-14 | **Medium** | Forensic audit/provenance helper uses timestamp-only integrity and a non-cryptographic 64-bit provenance summary; incomplete chains are accepted. | `src/forensic/provenance.zig:18-64,182-223,248-297` |
| F-15 | **Medium** | `forensics_engine.recent()` can return an invalid slice across a ring wrap and is not the active ring anyway. | `src/forensic/forensics_engine.zig:187-193` |
| F-16 | **Medium** | The Rust-side policy-signature function exists, but current PEP enforcement does not show mandatory signature/digest binding in the request or receipt. | `rust-src/lib.rs:21-54,340-426`; `src/policy/pep_bindings.zig:26-44` |
| F-17 | **Medium** | Fuzz target is a deterministic 1000-iteration executable, not a coverage-guided or bounded forensic/replay parser fuzz target. | `src/fuzz_entry.zig:1-5`; `src/tests/fuzz_main.zig:6-32`; `build.zig:162-171` |
| F-18 | **Medium** | Generated truth artifacts are stale, and manifest/test schema disagreement prevents current-head evidence from being trusted. | `tools/truth.py:32-53,98-190`; `runtime_manifest.json:1-137`; observed verifier output |

## 7. Missing tests and proofs

The following proofs are required before any prevention or production forensic claim can be considered:

1. **Current-head truth:** regenerate truth artifacts from this exact HEAD using the project generators, then run strict verification. The current stale artifacts must not be manually edited.
2. **Active-path integration:** inject one canonical Go Nose event and capture the exact active `ForensicRing` record. Assert that event ID, detection, policy bytes/digest, PEP request, decision, receipt, audit, trace, generation, provider/filter, postcondition, and cleanup are all present and mutually equal.
3. **Durable restart proof:** append evidence, flush/commit it, stop the daemon, start a new generation, verify the old chain and the new generation anchor, and prove no IDs collide without generation qualification.
4. **Hash-chain adversarial proof:** alter bytes, CRC, current hash, previous hash, record sequence, retained boundary, and externally stored checkpoint. Verify that all alterations fail and that ring overwrite is explicitly reported as evidence loss rather than silently accepted.
5. **Receipt proof:** test enforced, failed, unavailable, pending, simulated, rolled-back, missing-filter, provider-ambiguous, and host-postcondition-failed outcomes. Only a validated receipt may yield a confirmed block.
6. **PEP identity proof:** on Windows, bind caller PID/SID/token and capability to OS identity at the privileged boundary. Test a standard-user, low-integrity, wrong-PID, stale-request, replayed-request, and unknown-response case.
7. **Replay proof:** replay a stored historical event through the detector and policy evaluator using frozen historical rules, policy bytes/signature/digest, context, runtime/build identity, and deterministic clocks. The replay API must not expose a live enforcement path. Compare complete output lengths and all required fields.
8. **Export proof:** export exactly a verified source range, include source/head/generation/hash metadata, apply bounded redaction before leaving the host, escape all output formats, and verify exported hash plus record count.
9. **Audit durability proof:** verify append ordering, hash chain, flush/atomic rename, crash recovery, partial write handling, retention/eviction evidence, and concurrent readers/writers.
10. **Cleanup proof:** create a real isolated filter, record ownership and filter ID, remove it, observe reachability restored, verify no stale filter remains, and append cleanup success/failure to the same evidence chain.
11. **Pipe cancellation proof:** hold a client connection with a partial header/body and issue stop/restart. Assert bounded return and joined worker on Windows.
12. **Fuzz proof:** fuzz canonical frames, ring records, CRC/hash fields, NDJSON lines, replay exports, redaction, policy digests, and PEP responses with hard allocation/time budgets.
13. **Source/build authority lint:** fail CI if a non-PEP component imports or calls host mutation APIs; fail CI if a production module is only declared in a manifest but absent from the transitive build graph; fail CI if replay/export handlers return placeholders.

## 8. Prioritized fixes

### P0 — Keep prevention closed

Remove the success-shaped export/replay handlers or make them return `NOT_IMPLEMENTED` with an audited failure until real implementations exist. Remove `ReplayMode.enforce` from production-facing types and mark replay commands read-only. Ensure `BLOCKED_CONFIRMED` is impossible without a validated receipt with provider/filter/postcondition evidence. Do not use the current ring record as proof of host block.

### P1 — Define one durable finalized evidence contract

Extend the active record or introduce a finalized evidence envelope containing: schema/version, runtime generation, event identity plus producer epoch, detection/incident IDs, canonical policy bytes digest and signature identity, PEP request ID, authenticated caller identity, PEP decision, provider identity, filter ID, host-effect observation, receipt version/status, trace ID, audit ID, forensic sequence, source commit/binary/dependency digest, cleanup/rollback result, redaction state, and previous/current hash. Make the active event processor write this record after the provider postcondition and write explicit failure records when evidence persistence fails.

### P1 — Make durability and chain anchoring real

Choose one production persistence design. Use append-only framed records with length, checksum, cryptographic hash chain, durable checkpoints, crash recovery, restrictive ACLs, and explicit rotation/retention evidence. Do not call an in-memory ring or an unanchored FNV chain tamper-proof. Make every overwrite, drop, failed flush, and purge an auditable event.

### P1 — Make replay deterministic and observe-only

Replay must read a verified historical source, reconstruct historical input, load the exact historical policy/rules/context/build identity, use deterministic time/randomness, invoke detection and policy only, and emit a separate replay record. The type system and control contract should not permit live PEP/WFP calls. Require equal source counts and complete output comparison. Do not accept caller-supplied replay outcomes as proof.

### P1 — Close the Windows PEP boundary

Return an authoritative receipt or explicit failure from Rust. Bind caller capability to a Windows token/SID rather than caller-provided values. Validate request freshness and replay. Load provider DLLs from an absolute ACL-protected path with signature/hash verification. Return provider/filter identity and verify the host postcondition. Add authenticated cleanup and rollback with ownership checks.

### P2 — Fix concurrency, bounds, and sensitive data handling

Validate ring size before allocation. Add bounded replay bytes/records and export batches. Replace unlocked audit slices with copied snapshots. Make pipe reads overlapped/cancellable or close-wakeable and bound startup retries by the stop signal. Add full-write checks, secure file ACLs, payload size limits, collision-resistant names, error propagation, and format escaping. Keep raw payload retention disabled unless an explicit encrypted/ACL-protected evidence policy permits it.

### P2 — Replace declarative authority review with executable lint

Require exactly `CLAUSE_COUNT` observations, reject empty/short input, and make the lint inspect the current source/build graph. Add negative tests for missing rows, extra rows, stale manifests, direct mutation symbols, placeholder handlers, and mismatched policy ordinals. Regenerate all truth artifacts only through the generator and verify their HEAD binding.

## 9. Exact Windows-only verification commands

The following commands are required on a Windows 11 host with the stated toolchains. They were **not run here**. Run in an isolated disposable lab, with elevation only where the command requires it.

### 9.1 Current-head and strict truth gate

```powershell
Set-Location -Path 'D:\NIDs_Windows'
git rev-parse HEAD
git status --short
python tools\truth.py verify --strict
python tools\truth.py verify --strict --json
```

The expected HEAD is `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`. Any stale or missing truth artifact is a failed gate.

### 9.2 Build and component tests

```powershell
zig version
zig build
zig build test
zig build fuzz

cargo test --manifest-path rust-src\Cargo.toml --release
cargo build --manifest-path rust-src\Cargo.toml --release

cmake -B build -S .
cmake --build build --config Release

Set-Location nose
go test ./...
go build -o aegis-nose.exe .
Set-Location ..

Set-Location ts_policy
npm run typecheck
npm run test:all
Set-Location ..

python -m pytest tests\forensics tests\security -q
```

The fuzz command is only a build/launch baseline. It is not a substitute for a coverage-guided fuzz campaign against forensic/replay parsers.

### 9.3 Artifact signature, ACL, and dependency checks

```powershell
Get-AuthenticodeSignature .\zig-out\bin\aegis_nids.exe | Format-List
Get-AuthenticodeSignature .\target\release\aegis_pep.dll | Format-List
Get-AuthenticodeSignature .\build\Release\aegis_wfp_user.dll | Format-List
Get-FileHash .\zig-out\bin\aegis_nids.exe -Algorithm SHA256
Get-FileHash .\target\release\aegis_pep.dll -Algorithm SHA256
Get-Acl .\logs | Format-List
Get-Acl .\logs\payloads | Format-List
Get-Acl .\target\release | Format-List
where.exe dumpbin
& dumpbin /DEPENDENTS .\zig-out\bin\aegis_nids.exe
& dumpbin /EXPORTS .\target\release\aegis_pep.dll
```

The evidence must show absolute trusted load paths, expected signatures/hashes, restrictive ACLs, and no unexpected writable directory in the DLL search path.

### 9.4 Service, driver, provider, and pipe preflight

```powershell
Get-Service | Where-Object { $_.Name -match 'aegis|wfp' } | Format-Table -Auto
sc.exe query type= service state= all | Select-String -Pattern 'AEGIS|aegis|WFP|wfp'
fltmc filters
fltmc instances
Get-NetFirewallProfile | Format-List
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object DisplayName -match 'AEGIS|aegis' | Format-List
Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'" | Select-Object ProcessId,ExecutablePath,CreationDate
Get-CimInstance Win32_Process -Filter "Name='aegis-nose.exe'" | Select-Object ProcessId,ExecutablePath,CreationDate
Get-ChildItem \\.\pipe\ | Where-Object Name -match 'aegis' | Format-Table Name
```

A file or service being present is not readiness evidence. The provider must answer the exact ABI and expose an authoritative filter identity.

### 9.5 Runtime and forensic verification

In one elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig build run
```

In a second elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
.\scripts\aegis.ps1 health
.\scripts\aegis.ps1 forensic verify
.\scripts\aegis.ps1 forensic list
.\scripts\aegis.ps1 forensic show --json
.\scripts\aegis.ps1 forensic export --json
.\scripts\aegis.ps1 forensic replay --json
```

The expected result is that `forensic show`, `export`, and `replay` return real record/range data, not `not_implemented`, `exported=true` without a file, or `replayed=true` with zero events. Replay must report observe-only mode and must not create or modify a WFP filter.

### 9.6 Cancellation and generation proof

```powershell
$old = Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'"
$old | Select-Object ProcessId,CreationDate,ExecutablePath
# Hold a Go Nose connection open with a partial frame from a controlled test client.
# Then request orderly shutdown through the authenticated control plane:
.\scripts\aegis.ps1 stop
Wait-Process -Id $old.ProcessId -Timeout 10
Get-ChildItem \\.\pipe\ | Where-Object Name -match 'aegis_(control|nose)'
zig build run
$new = Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'"
$new | Select-Object ProcessId,CreationDate,ExecutablePath
.\scripts\aegis.ps1 health --json
.\scripts\aegis.ps1 forensic verify --json
```

The old process must exit within the bounded deadline, both pipe handles must be released, the new process must have a distinct generation identity, and old/new evidence must not collide on bare event, audit, PEP, or trace IDs.

### 9.7 Isolated WFP effect and cleanup proof

Run only after the Windows preflight passes and the target is confirmed as the disposable VMnet1 target. Do not use Wi-Fi, NAT, the host gateway, localhost, or a production service.

On the target VM:

```powershell
Get-NetTCPConnection -State Listen
Test-NetConnection -ComputerName 192.168.126.20 -Port 8080
```

On the attacker VM, record the same reachability baseline. On the AEGIS host, capture pre-state:

```powershell
netsh wfp show filters file=C:\Temp\aegis-wfp-before.xml
Get-NetFirewallRule -PolicyStore ActiveStore | Export-Clixml C:\Temp\aegis-firewall-before.xml
```

Submit one exact authorized PEP request through the authenticated control plane, then collect:

```powershell
.\scripts\aegis.ps1 enforcement status --json
.\scripts\aegis.ps1 forensic verify --json
netsh wfp show filters file=C:\Temp\aegis-wfp-during.xml
```

The claim is valid only if the receipt has `status=ENFORCED`, `host_effect_confirmed=true`, non-zero request/event/trace/audit/filter IDs, a provider identity, and a matching forensic record. After cleanup, remove the exact owned filter through the authorized rollback path and verify:

```powershell
.\scripts\aegis.ps1 enforcement rollback --json
Test-NetConnection -ComputerName 192.168.126.20 -Port 8080
netsh wfp show filters file=C:\Temp\aegis-wfp-after.xml
Get-NetFirewallRule -PolicyStore ActiveStore | Export-Clixml C:\Temp\aegis-firewall-after.xml
.\scripts\aegis.ps1 forensic verify --json
```

Reachability must be restored, the receipt and cleanup record must be linked to the same event/request/filter ownership, and the after-state must contain no stale filter. If any step is unavailable, ambiguous, or not independently observed, the enforcement gate remains closed.

## 10. Review disposition

Current disposition: **NOT PRODUCTION-READY; prevention claim blocked.** The source contains valuable component tests and several correct containment intentions, especially the distinction between PEP availability and an allow decision. Those intentions do not replace an active, durable, receipt-linked evidence path or a Windows host-effect proof. The next accepted milestone is a current-head, observe-only vertical slice with a durable finalized record and deterministic replay; only after that should an isolated WFP effect and cleanup proof be attempted.

## References

[1]: README.md "AEGIS repository README and source-of-truth hierarchy"
[2]: /home/ubuntu/upload/AEGISComprehensiveDevelopmentAnalysisandProductionHandoff.md "AEGIS comprehensive development and production handoff"
[3]: runtime_manifest.json "Current runtime manifest at reviewed HEAD"
[4]: build.zig "Current Zig build graph"
[5]: tools/truth.py "Current-head truth artifact verifier"
[6]: src/forensic/forensic_pipeline.zig "Active bounded forensic ring implementation"
[7]: src/forensic/replay_verifier.zig "Replay export and verification implementation"
[8]: src/control/handler_registry.zig "Control command handlers and audit dispatch"
[9]: rust-src/lib.rs "Rust PEP FFI and provider boundary"
[10]: src/pipeline/event_processor.zig "Active detection, PEP, dispatch, and forensic append path"
[11]: src/capture/nose_pipe_reader.zig "Active Go Nose named-pipe ingress"
[12]: src/core/authority_review.zig "Authority checklist and review helper"
[13]: src/control/audit.zig "Control-plane in-memory audit log"
[14]: src/forensic/forensic_log.zig "Separate NDJSON forensic logger"
[15]: src/forensic/provenance.zig "Provenance and storage lifecycle helper"
[16]: src/tests/proofs/forensic_replay_proof.zig "Proof-only forensic replay and redaction module"
[17]: src/forensic/siem_forwarder.zig "Support SIEM export module"
[18]: src/tests/fuzz_main.zig "Current deterministic fuzz executable"
[19]: src/tests/security/test_t16_security_hardening.py "Structural security hardening tests"
[20]: src/tests/security/test_t19_decision_trace_shadow_replay_review.py "Structural decision-trace and replay review tests"
