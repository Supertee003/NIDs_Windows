# AEGIS Windows-native NIDS/IPS — Data Plane and Detection Review

**Review ID:** `AEGIS-CURRENT-HEAD-04`  
**Repository:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`  
**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review mode:** Read-only source/build-graph review. No source file, generated truth artifact, fixture, or build output was modified.  
**Conclusion:** The repository contains a credible observe-only design and substantial unit-test material, but the current production path is not proven as one canonical data plane. Several source-level defects can reject every Go Nose frame, lose payload visibility, duplicate ingress identities, hang shutdown, or record a block intent without a verifiable host-effect receipt. **Production-ready prevention must not be claimed.**

## 1. Scope and method

This review is limited to `nose/`, `src/capture/`, `src/detection/`, `src/pipeline/`, `src/contract/event_fabric.zig`, injector-related paths, Go tests, Zig tests, and golden-path fixtures. The review also inspected the executable build graph, the Windows service entrypoint, imports from the active daemon, generated manifests where they describe reachability, and the handoff/README only as lower-priority context.

The evidence order was: current source at the pinned HEAD, `build.zig` and imports, test registration, then manifests and documents. A symbol was treated as **active production** only when it is reachable from `src/main.zig` through `platform/win32_service.mainEntry` and `daemon.runDaemon()`. A file that exists, is imported by an aggregator test, or is named in a manifest was not treated as runtime proof. Windows, elevated, Npcap, and VMware execution could not be performed in this Linux sandbox; those results are **UNVERIFIED**, not inferred.

The available sandbox did not provide `zig`, `go`, or a Windows host. Therefore this report records static findings and exact Windows verification commands, but it does not convert a source-level test or fixture into an execution claim.

## 2. Executive assessment

The real executable root is `build.zig` → `src/main.zig`; `src/main.zig` dispatches to the Windows service/foreground path, and `win32_service.mainEntry()` calls `daemon.runDaemon()`.[1] The active Windows daemon starts a pipeline worker, a legacy Python sensor pipe, the Go Nose named-pipe reader, ETW, FIM, and Registry workers.[2] It explicitly does **not** start the direct Zig Npcap capture thread. Consequently, Go Nose live capture is a separately launched process (`nose -capture`), not a child of the Zig production entrypoint.[3]

The intended active network path is therefore only partially reachable from the production entrypoint:

```text
AEGIS executable
  -> src/main.zig
  -> win32_service.mainEntry
  -> daemon.runDaemon
       -> pipelineLoop
       -> Go Nose pipe server: \\.\pipe\aegis_nose
            -> event_queue.pushCanonicalEvent
       -> legacy sensor server: \\.\pipe\aegis_sensor_pipe
            -> event_queue.pushEvent
       -> ETW/FIM/Registry
            -> event_queue.pushEvent
```

The Npcap capture process is external:

```text
nose.exe -capture
  -> gopacket/pcap.FindAllDevs
  -> firstUpDevice or -iface
  -> pcap.OpenLive + BPF "ip or ip6"
  -> Go CanonicalEvent
  -> FrameWriter
  -> \\.\pipe\aegis_nose
```

This distinction matters operationally. A healthy Zig daemon does not prove that Npcap is running, that the Go producer is connected, or that a packet can reach the detector. Conversely, starting a Nose process does not prove the daemon is the consumer that owns the pipe.

The most urgent source-level defect is a wire-header contract mismatch. Go writes `DefaultDevStructSize = 128` into the 109-byte wire payload, while the Zig canonical model sets `struct_size` from `@sizeOf(CanonicalEvent)` and rejects any value that differs from that value.[4] The fixtures declare `struct_size = 109`.[5] The sender and receiver are not tied to one generated constant. Until a Windows/Zig build proves the compiled size and the frame round trip, the Go-to-Zig path must be treated as **not proven and likely rejected**.

## 3. Active call graph and authority boundaries

### 3.1 Reachable production graph

| Stage | Reachable source and symbol | Finding | Authority classification |
|---|---|---|---|
| Process entry | `src/main.zig:20-35`, `main()` | Dispatches to the SCM/foreground service entry. | **Active production** |
| Service/console dispatch | `src/platform/win32_service.zig:94-126`, `mainEntry()` | Calls `daemon.runDaemon()` for both service and console mode. | **Active production** |
| Runtime owner | `src/daemon.zig:85`, `runDaemon()` | Owns initialization, worker creation, control server, and supervisor joins. | **Active production** |
| Detection pipeline | `src/pipeline/event_processor.zig:205-252`, `pipelineLoop()` | Pops only from `src/pipeline/event_queue.zig`; does not pop from `event_fabric.zig`. | **Active production** |
| Go ingress | `src/daemon.zig:400-405` → `nose_pipe_reader.runPipeReaderLoop()` | Reads `CanonicalEvent` frames and calls `pipeline_queue.pushCanonicalEvent()`. | **Active production when external Go producer is present** |
| Legacy sensor ingress | `src/daemon.zig:375-381` → `core/nids_capture.capture_packets()` | Reads `aegis_sensor_pipe`, creates a separate 96-byte `IpcEvent`, and calls `pushEvent()`. | **Active production** |
| Direct Zig Npcap | `src/pipeline/packet_callback.zig:87-120`, `captureThread()` | Implemented and testable, but daemon comments explicitly disable it. | **Support/diagnostic, not active production** |
| Go live capture | `nose/main.go:94-107`, `runCapture()` | Runs only when an operator separately invokes `nose -capture`. | **External operational path** |
| Event Fabric facade | `src/contract/event_fabric.zig:1-16` | Imported by lifecycle/dispatcher support code, but the active Nose reader bypasses it. | **Support/legacy authority candidate** |
| Correlation alternatives | `src/detection/correlator.zig`, `correlation_engine.zig` | Unit-tested modules exist, but no import/call from the active `event_processor` path was found. | **Support/legacy** |

The active processor imports `event.IpcEvent`, the signature engine, anomaly detector, threat tracker, policy IR, PEP bindings, forensic ring, action dispatcher, and the active queue.[6] It does not import `detection_interface.DetectionManager`, `detection_engine.DetectionEngine`, `correlator.Correlator`, or `correlation_engine.CorrelationEngine`. The repository therefore has multiple detection/correlation models, but only one subset is reachable from the current daemon call graph.

### 3.2 Runtime owner and hidden blocking authority

`RuntimeSupervisor.requestStop()` only sets `g_stop_requested` and asks the bridge layer to shut down; `shutdown()` then joins the workers in reverse order.[7] The Go pipe reader uses synchronous `ConnectNamedPipe(server, null)` and synchronous `ReadFile` through `readExact()`.[8] No `CancelSynchronousIo`, `CancelIoEx`, cross-thread pipe close, or overlapped I/O cancellation is present in this reader. Setting an atomic flag cannot interrupt a thread already blocked in `ConnectNamedPipe` or `ReadFile`.

The Go writer also contradicts its own non-blocking claim. `NewFrameWriter()` synchronously calls `ensureConnected()`, and `dialPipe()` calls `os.OpenFile()` on a Windows named pipe. The source comment acknowledges that this maps to a `PIPE_WAIT` open.[9] `FrameWriter.Send()` holds a mutex while writing the complete frame with `writeAll()`, with no deadline, overlapped I/O, bounded queue, or cancellation. A slow or stuck consumer can therefore become the blocking authority for the capture goroutine.

This is not merely a performance concern. It can prevent the daemon from completing a stop/restart postcondition, and it makes “drop rather than block” a claim that is not proven by the implementation.

## 4. File-level observations

### 4.1 Npcap and adapter selection

The Go path calls `pcap.FindAllDevs()` and auto-selects the first device with addresses whose name/description does not contain several virtual or unwanted labels, including VMware, Hyper-V, Bluetooth, Wi-Fi Direct, TeamViewer, Loopback, and Npcap Loopback.[10] If no such device exists, it falls back to the first addressed device and then the first listed device. This is heuristic, not route-aware and not tied to the VMware VMnet1 proof topology. An operator can pass `-iface`, but the source does not bind the selected device to a verified adapter GUID, expected CIDR, or test target.

The Go capture opens the selected adapter with `pcap.OpenLive(iface, 65535, false, 1s)` and installs the read-only BPF filter `ip or ip6`.[11] It does not capture ARP or other non-IP frames. That may be acceptable for the scoped IP detection slice, but it must be stated in the coverage contract rather than treated as general packet acquisition.

The separate Zig `NpcapAdapter` dynamically tries absolute `Npcap\wpcap.dll`, `wpcap.dll`, and loader-search-path candidates, validates required symbols, enumerates devices, skips virtual/unsupported descriptions, and selects an up/running non-loopback device.[12] Its selection logic is not the active daemon path because `daemon.runDaemon()` explicitly disables `captureThread()` to prevent two network event streams.[2] The existence of a valid DLL or successful adapter unit test is therefore not proof that production capture is active.

### 4.2 Packet decode and normalization

Go normalization creates one event per gopacket packet, assigns `SourceNpcapSensor`, maps IPv4 addresses and TCP/UDP ports, and uses the first four bytes of each IPv6 address as the 32-bit identity.[13] The Zig callback and `packet_decoder.zig` use similar reduced IPv6 identity behavior. This is a deterministic lossy mapping: distinct IPv6 endpoints can collide before detection, correlation, policy, or evidence. The canonical 109-byte model has no full 128-bit source/destination address field, so this is a contract limitation, not just a parser detail.

`packet_decoder.decodeIpv4()` checks for a minimum IPv4 header and validates that IHL is not below the base header, but it does not verify the IP version, total length, or that the complete IHL lies within the captured frame before deriving the L4 offset.[14] TCP decoding derives the payload offset from the data-offset nibble without rejecting data offsets below the minimum TCP header length. The later bounds checks avoid some out-of-range reads, but malformed packets can be interpreted with an incorrect payload slice. Add explicit version, IHL, total-length, TCP data-offset, and captured-length invariants before treating decoder tests as parser hardening.

The active Go signature classifier searches `strings.Contains(string(payload), pattern)`.[15] Go strings are length-aware and do not terminate at an embedded NUL, but converting arbitrary binary application data to a text string still gives undefined detector semantics for invalid encodings, binary signatures, and normalization boundaries. The Zig queue has the more consequential data loss: `MAX_PAYLOAD_BYTES` is 1500, and `pushEvent()` copies only the first 1500 bytes.[16] The Go canonical path does not send raw payload bytes at all. `pushCanonicalEvent()` sets `ev.payload_len` from the wire metadata but passes an empty slice into `pushEvent()`, which resets the queued payload length to zero.[16] As a result, the active Zig Aho-Corasick stage cannot inspect Go Nose packet bytes. It can only carry the upstream `rule_id`/event type that Go may have assigned.

### 4.3 Canonical framing and validation

The intended frame is `u32 little-endian length + 109-byte payload`. The Zig reader enforces `frameLen == 109`, reads exactly 109 bytes, deserializes with explicit field reads, and validates magic, version, and struct size.[8] The Go writer emits the same nominal frame shape.[9]

The header marker is not actually one source of truth:

- Zig `canonical_event.zig:15-17` defines `EVENT_SCHEMA_SIZE` as `@sizeOf(CanonicalEvent)`.[4]
- Zig explicit serialization returns `WIRE_PAYLOAD_SIZE = 109`.[4]
- Go `nose/canonical.go:180-188` defines `EventWireSize = 109` but `DefaultDevStructSize = 128`.[17]
- Go serializes 128 into bytes `6:8`.[17]
- The fixture metadata expects `struct_size = 109`.[5]

The receiver's `deserializeFromBytes()` validates the received marker after decoding it.[4] This is a deterministic release blocker. The project cannot claim cross-language ingress until the compiled Zig layout and the wire marker are generated/frozen to one value and a Go-to-Zig byte-level test passes.

There is a second fixture-tool defect. `nose/golden_path_ffi.go:69-105` parses `EventID` from `b[0:8]`, although the canonical wire layout places event ID at `b[8:16]`.[18] This helper is not the active pipe reader, but it can report incorrect golden-vector semantics and must not be used as cross-language proof in its current form.

### 4.4 Pipe framing, reconnect, backpressure, and drop ledger

The Zig reader is byte-mode, single-instance, synchronous, and configured with a 256-frame input buffer.[8] It correctly loops in `readExact()` for short reads. It reconnects after a client disconnect by calling `DisconnectNamedPipe()` and looping back to `ConnectNamedPipe()`.

Malformed length handling is unsafe. Any length other than 109 enters a discard loop with a 256-byte stack buffer and no maximum discard bound.[8] A peer can send `0xFFFFFFFF`; the reader will attempt to consume that many bytes or remain blocked until disconnect. The correct behavior is to reject and close the client immediately when the advertised length exceeds a small protocol maximum.

The Go writer drops a frame when no connection exists or a write fails, increments a local `dropped` counter, and retries only on later sends.[9] It does not persist a drop record, return a typed delivery result, or transfer the drop reason to Zig. `runCapture()` ignores the return value from `Send()` and only copies the writer's local aggregate into a local TUI metric.[19] A frame can therefore be locally classified as dropped without a corresponding daemon drop-ledger record.

The Zig reader increments aggregate `frames_dropped` both for malformed frames and for queue rejection.[8] The active queue has only a generic `g_queue_drops` counter.[16] The richer reason-coded accounting in `src/contract/event_fabric.zig` is not on this active path: the reader calls `pipeline_queue.pushCanonicalEvent()`, not `event_fabric.submitEvent()` or `nose_contract.submitWireEvent()`.[8][20] Consequently, `QUEUE_FULL`, validation failure, producer disconnect, malformed length, and source-side write loss are not one authoritative ledger.

The active queue is also unsafe for the declared producer set. `pushEvent()` reads `g_queue_head`, writes the slot, and stores `head + 1` without a compare-and-swap or producer mutex.[16] The daemon can have the legacy sensor, Go reader, ETW, FIM, and Registry producers active at once.[2] A multi-producer race can overwrite a slot or lose an increment. The pop side has a mutex, but that does not make concurrent producers safe. `g_queue_drops` is a non-atomic global updated from worker contexts.

### 4.5 Event identity across restart and duplicate side effects

Go event identity is an atomic process-local counter declared at `nose/capture.go:41` and incremented at `eventFromPacket():187`.[13] It restarts at zero when the Go process restarts. The legacy sensor has another process-local counter, `g_pipe_event_id`, at `core/nids_capture.zig:18` and `:290`.[21] Zig's canonical model has a separate process-local `g_event_id_counter`.[4] These are independent identity authorities.

The reader detects equal or decreasing event IDs, increments diagnostic counters, and then accepts the event anyway.[8] It does not reject, deduplicate, attach producer epoch/generation, or carry an idempotency key into the policy/PEP/evidence stages. A retried frame or a reconnect replay can therefore run detection, policy evaluation, PEP request creation, action dispatch, audit logging, and forensic append again. Since the active event processor allocates a new PEP request ID and audit ID for each accepted copy, duplicate event side effects are not prevented by the downstream identifiers.[6]

The current evidence does not prove cross-restart continuity. It proves only that the system can notice duplicate/non-monotonic values after they arrive.

### 4.6 Detection, correlation, and policy semantics

The active processor performs flow-table lookup, optional Aho-Corasick matching, anomaly observation, threat tracking, policy evaluation, PEP enforcement, action dispatch, audit logging, and forensic append.[6] The flow key and threat tracker operate on the 96-byte `IpcEvent` representation, not the full canonical object. `pushCanonicalEvent()` copies only selected fields into that representation and drops the source, session ID, direction, layer, enforcement status, ruleset version, context semantics, and all raw payload bytes except a truncated 32-bit hash.[16]

The processor has multiple semantic problems:

1. `matched_rule_id` and an incident are each counted as a detection, and a matched policy is counted again as a detection (`event_processor.zig:80-83`, `:120-128`, `:165`). The detection metric therefore does not represent one well-defined event/result cardinality.
2. `g_pipeline_correlations` is declared in `runtime_state.zig`, but the active processor invokes `ThreatTracker.observeFlowThreat()` rather than the standalone `Correlator`/`CorrelationEngine`, and no active increment from a correlation result is visible. Correlation modules and active threat escalation are separate semantics.
3. The active processor assigns `policy_action` but does not use it (`:139-147`). It hard-codes policy trace version `1` because `Policy` has no version field (`:148-149`). The decision trace therefore cannot prove the loaded policy digest/version.
4. `detection_interface.zig` defines `DetectionResult` and a `Verdict.match_block` outcome, even though the project invariant says detection cannot block.[22] This interface is not on the active processor path, but it is a duplicate semantic model that can enable an authority breach if wired later without redesign.
5. The action dispatcher logs `"PEP validated block; WFP enforcement executed by Rust PEP"` for `.block` and writes a forensic event, but it receives only a `PepDecision`, not a validated `EnforcementReceipt` or host postcondition.[23]

The active path does call the Zig-side PEP binding once before dispatch, which is consistent with the intended single authorization boundary. It does **not** prove that Rust PEP authorized the exact request, that WFP created a filter, that the host effect was observed, or that cleanup succeeded.

### 4.7 Evidence handoff

The active processor appends a record with the event, queued payload, audit ID, policy ID, PEP decision ordinal, and severity.[6] The forensic ring append signature accepts those fields but not an `EnforcementReceipt`, provider/filter identity, host-effect confirmation, cleanup result, or policy digest.[24] The decision trace carries a PEP request ID, but the append call shown in the active processor does not pass the trace ID or request ID as explicit receipt-linked fields.

This is insufficient for the project’s receipt-driven claim. A log message or enum such as `.block` is not a host block. The active path must remain detection-only/degraded until the receipt and postcondition contract is wired through the final evidence record.

### 4.8 Injector-related scope

No tracked top-level `injectors/` directory is present at this HEAD. `src/windows/injection_detector.zig` and `src/tests/windows/injection_detector.zig` are detection/telemetry modules, not packet injectors. Their presence must not be interpreted as an injection or attack-generation proof. Any packet or attack generator under scripts/tooling is support/test tooling unless a current build and runtime call graph proves otherwise.

## 5. Contract and authority impact

| Contract/boundary | Current source reality | Impact |
|---|---|---|
| Runtime ownership | Zig daemon owns worker handles, but synchronous Go-pipe operations are not cancellation-safe. | A blocking ingress can prevent the single owner from completing stop/join. |
| Network ingress | Go Nose and legacy `aegis_sensor_pipe` are both daemon-started/operationally reachable. Direct Zig Npcap is disabled. | There are two active sensor families and two identity/normalization paths. |
| Canonical event | 109-byte explicit wire format, 96-byte internal `IpcEvent`, natural-aligned Zig size marker, Go marker 128, fixtures marker 109. | Cross-language acceptance is not proven; Go frames may be rejected. |
| Detection authority | Active processor uses AC/anomaly/threat tracker; alternate DetectionManager and correlation models remain. | Duplicate semantics and future authority drift risk. |
| Policy authority | Active processor calls PEP before dispatch. | Correct direction, but request/result/receipt evidence is incomplete. |
| Host enforcement claim | Dispatcher logs WFP execution from a PEP decision. | Violates receipt-driven truth if displayed as confirmed block. |
| Backpressure | Active queue is bounded but multi-producer push is not synchronized. | Loss and duplicate/overwrite behavior is not reliable under load. |
| Drop ledger | Rich Event Fabric accounting exists but active reader bypasses it; Go drops remain local. | No end-to-end accepted/rejected/dropped reconciliation. |
| Event identity | Go, legacy pipe sensor, and canonical helper each mint local counters; reader only observes anomalies. | Restart/retry can create duplicate side effects and non-monotonic evidence. |
| Evidence | Forensic append links event/audit/policy/PEP ordinal, not receipt/provider/filter/cleanup. | No valid `BLOCKED_CONFIRMED` evidence chain. |

## 6. Concrete defects and severity

Severity uses **Critical** for a stop-the-line correctness/security issue, **High** for a defect that can break the active path or invalidate a production claim, **Medium** for bounded but material correctness risk, and **Low** for non-blocking maintainability/test quality.

| ID | Severity | Defect | Evidence and consequence |
|---|---|---|---|
| DP-01 | **Critical** | Go/Zig struct-size marker is not one contract. | Go writes `128`; Zig validates against `@sizeOf(CanonicalEvent)`; fixtures state `109`.[4][5][17] The active Go frame can be rejected before queue submission. |
| DP-02 | **Critical** | Active evidence path can claim block without a receipt or host postcondition. | Processor calls PEP and dispatcher logs WFP execution, while forensic append accepts only decision/audit/policy/severity and no receipt/filter/postcondition.[6][23][24] Prevention must remain closed. |
| DP-03 | **High** | Pipe stop path can hang on synchronous `ConnectNamedPipe`/`ReadFile`. | `requestStop()` sets a flag and joins; reader blocks with null OVERLAPPED and no cancellation/close.[7][8] Restart and service stop are not proven bounded. |
| DP-04 | **High** | Go writer can block capture despite “never block” comments. | `NewFrameWriter()` opens a `PIPE_WAIT` endpoint synchronously; `Send()` holds a mutex over uncancellable `writeAll()`.[9] A full/slow consumer can stall packet acquisition. |
| DP-05 | **High** | Active queue is not safe for multiple producers. | `pushEvent()` has non-CAS head publication and no producer lock, while daemon starts multiple producers.[2][16] Events can overwrite or disappear under load. |
| DP-06 | **High** | Event ID is process-local and duplicate/non-monotonic values are accepted. | Go and legacy counters reset independently; reader logs anomalies but still submits.[8][13][21] Replay/retry can repeat PEP, audit, forensic, and external side effects. |
| DP-07 | **High** | Go Nose payloads are not available to active Zig payload detection. | `pushCanonicalEvent()` copies metadata but passes an empty payload; processor only invokes AC when `qe.payload_len > 0`.[6][16] Go’s local classifier is a second detection authority and not equivalent to raw-payload processing. |
| DP-08 | **High** | Active reader bypasses the richer Event Fabric/drop ledger. | Reader calls `pipeline_queue.pushCanonicalEvent()`; `event_fabric.zig` accounting is support-only for this path.[8][20] Source-side loss and queue loss cannot be reconciled end to end. |
| DP-09 | **High** | Malformed frame length can force unbounded discard/blocking. | Reader accepts any non-109 `u32` into a discard loop without a maximum before reconnect/close.[8] A malicious client can hold the ingress worker. |
| DP-10 | **High** | Two active sensor families use different event models and identity authorities. | Go canonical pipe and legacy `IpcEvent` sensor both feed `event_queue`; the legacy sensor is started by the daemon.[2][21] This creates duplicate semantics, source loss, and collision risk. |
| DP-11 | **Medium** | Golden FFI deserializer reads event ID from the wrong offset. | `golden_path_ffi.go:75` reads `b[0:8]` instead of `b[8:16]`.[18] Fixture-based semantic proof can be false even if the binary is correct. |
| DP-12 | **Medium** | IPv6 normalization truncates endpoint identity to 32 bits. | Go maps only the first four bytes of each IPv6 address.[13] Distinct endpoints can collide in flow, detection, policy, and evidence. |
| DP-13 | **Medium** | Packet decoder accepts insufficiently validated header lengths. | IPv4 version/total-length and TCP data-offset invariants are not fully checked before payload derivation.[14] Malformed traffic can produce incorrect detector input. |
| DP-14 | **Medium** | Detection, correlation, and policy vocabularies are duplicated. | `DetectionResult.match_block`, `detection_engine.Verdict`, `event.IpcEvent.EventKind`, canonical event types, threat tracker, and policy actions coexist; several are not on the active call graph.[6][22] Future wiring can violate “detection cannot block.” |
| DP-15 | **Medium** | Correlation/evidence metrics do not have one active semantic owner. | Active code uses `ThreatTracker`, while standalone correlator/engine modules are test/support paths; policy trace hard-codes version 1.[6][14] Incidents and policy evidence cannot be compared reliably across paths. |
| DP-16 | **Medium** | Local aggregate drop counters are not durable/idempotent. | Go writer returns raw bytes even after a drop and caller ignores the result; Zig counters are process-local and reason classes are not unified.[9][19][20] Recovery cannot prove which input was lost. |
| DP-17 | **Low** | Test comments and paths describe stale `core/` locations while source moved to `src/`. | `nose_pipe_e2e_cli.zig` usage refers to `core/nose_pipe_e2e_cli.zig`, whereas the tracked file is under `src/tests/cli/`.[25] This increases the chance of running the wrong proof or no proof. |

## 7. Missing tests and proofs

The following proofs are absent or not executable in this review environment:

1. **Byte-level Go → Zig acceptance at current HEAD.** The proof must assert the exact struct-size marker, all offsets, enum ordinals, and that the active reader submits one frame rather than rejecting it.
2. **Producer concurrency.** Flood `aegis_nose`, `aegis_sensor_pipe`, ETW, FIM, and Registry producers concurrently and reconcile sent, accepted, rejected, queue-full, malformed, and forensic counts. The current queue requires a race detector or deterministic multi-producer harness.
3. **Restart identity.** Capture before and after Go restart and Zig daemon restart. Verify producer ID, runtime generation, producer epoch, local sequence, dedup behavior, and no repeated PEP/audit/forensic side effects.
4. **Pipe cancellation.** Stop the daemon while blocked in `ConnectNamedPipe`, blocked in `ReadFile`, and blocked in a full writer. Assert process exit, pipe release, and worker join within a fixed deadline.
5. **Malformed length handling.** Send zero, one, 108, 110, 256, and `0xFFFFFFFF` length prefixes. The reader must reject/close promptly without reading an attacker-controlled discard length.
6. **Payload semantics.** Send ASCII, embedded NUL, invalid UTF-8, binary signatures, truncated packets, oversized packets, TCP data-offset edge cases, VLAN, IPv6 extension headers, and fragments. Compare Go and Zig detector inputs and results.
7. **Adapter selection.** On a Windows host with Wi-Fi, VMware VMnet1/VMnet8, Hyper-V, Npcap Loopback, and disabled adapters, record the selected Npcap device name/GUID, flags, CIDR, BPF, and first packet. Do not infer selection from a DLL file.
8. **Active correlation proof.** Demonstrate which correlation implementation is called from `runDaemon()` and connect its incident ID/evidence to the event ID and policy decision. Current source only proves standalone module tests for alternate correlators.
9. **Receipt/evidence handoff.** Produce a typed receipt with request ID, event ID, trace ID, audit ID, policy ID/version/digest, provider/filter ID, host-effect confirmation, and cleanup result. The active `ForensicRing.append` signature must carry or resolve every field.
10. **No host-block claim when unavailable.** With missing PEP, missing WFP provider, ambiguous adapter response, invalid receipt, or failed cleanup, prove that action state is `ENFORCEMENT_UNAVAILABLE`/`ENFORCEMENT_FAILED`, never `BLOCKED_CONFIRMED`.
11. **Cross-language fixture completion.** The Go helper explicitly marks C++ support as pending and Rust as TBD.[18] C++ and Rust must read the same five binary vectors, including event ID and struct-size fields, before claiming cross-language equivalence.
12. **Current-head execution.** `zig build`, `zig build test`, Go tests/build, and the Windows host preflight were not run here. Their result is **UNVERIFIED**.

## 8. Prioritized fixes

### P0 — Stop-the-line correctness and authority fixes

1. **Freeze one generated wire contract.** Choose the explicit 109-byte encoding as the wire authority. Generate Go/Zig/Rust/Python/C++ constants for magic, version, payload size, header offsets, enum ordinals, and the struct-size marker. Remove Go’s `128` marker and remove any receiver dependence on natural-aligned `@sizeOf` for wire validation. Add a byte-for-byte Go-to-Zig test using the checked-in vectors.
2. **Make Zig the only active ingress queue owner.** Choose either `event_fabric` or `event_queue`, not both. Route the Go reader and legacy sensor through one API. Replace the current multi-producer head publication with a proven MPSC queue or a bounded producer lock. Make every drop counter atomic and reason-coded.
3. **Define restart-safe identity.** Event identity should contain producer ID, runtime generation, producer epoch, and local sequence, or Zig must allocate the global ingress ID at acceptance. Duplicate frames must be rejected or idempotently acknowledged before policy/PEP/action/forensics.
4. **Close the receipt boundary.** Change the active PEP/action/evidence flow so only a validated `EnforcementReceipt` can produce an enforcement-confirmed state. A PEP decision alone must produce request/pending/unavailable/failed evidence, not a block claim. Add filter identity, provider response, postcondition, cleanup, trace, and audit linkage.
5. **Remove synchronous pipe authority.** Use overlapped named-pipe I/O with cancellation and deadlines on both server and client. On stop, cancel/close the handle before join. Bound writes, make backpressure explicit, and never hold a global capture mutex over an unbounded OS write.

### P1 — Data-plane correctness and semantic convergence

6. **Decide whether Go Nose is supervisor-managed.** Either have Zig launch and supervise a versioned Go producer with a readiness/heartbeat contract, or explicitly model it as an external required dependency. Health must distinguish `nose_process_running`, `pipe_connected`, `frames_read`, and `frames_submitted`.
7. **Eliminate the second active sensor path or give it a separate contract.** The legacy `aegis_sensor_pipe` should be retired, isolated as a test adapter, or converted to the same canonical wire contract and identity authority. It must not silently create 96-byte events while Go creates 109-byte events.
8. **Preserve payload/reference semantics.** Decide whether payload bytes are carried, bounded, or referenced by content-addressed evidence. Do not advertise full-payload detection when `pushCanonicalEvent()` passes an empty payload. Make binary matching length-aware and define invalid-encoding behavior.
9. **Select one detection/correlation API.** The active path should return a typed `DetectionResult` that cannot encode host enforcement, then a separate policy decision, then PEP authorization. Retire or quarantine duplicate `DetectionManager`, `detection_engine`, `correlator`, and `correlation_engine` models until one is authoritative.
10. **Harden decoders and IPv6 identity.** Validate every header length/version/fragment/extension invariant and preserve full IPv6 identity through the contract or use a collision-resistant endpoint reference.

### P2 — Proof and release assurance

11. Correct `golden_path_ffi.go` event-ID offsets and make the Go, Zig, Rust, C++, and Python fixture tests use the same binary files and expected field map.
12. Replace manifest/static golden-path assertions with an executable harness that starts the real daemon, injects a benign fixture through the real pipe, observes queue/detection/forensic deltas, and records the current commit.
13. Add Windows tests for Npcap device selection, named-pipe ACLs, stop deadlines, non-admin rejection, queue saturation, and recovery after a producer restart.
14. Archive evidence with runtime generation, producer identity, policy digest, receipt, filter identity, cleanup result, and final gate state. Do not use a passing unit test as host-effect evidence.

## 9. Exact Windows-only verification commands

The following commands are intentionally explicit. They must be run from a **working Windows PowerShell**, with elevation where noted. A timeout, missing toolchain, missing adapter, or missing DLL is a failed/unverified proof, not a pass.

### 9.1 Pin the source and verify the build graph

```powershell
Set-Location -Path 'D:\NIDs_Windows'

git rev-parse HEAD
# Expected: 46b93dcf9cca17b323ddff7a4c71e33e81c37fb5
git status --short
git ls-tree -r --name-only HEAD nose src/capture src/detection src/pipeline src/contract/event_fabric.zig src/tests tests | Select-String -Pattern 'nose|capture|detection|pipeline|event_fabric|golden|fixture|inject'

zig version
go version
python --version
zig build -Doptimize=ReleaseSafe
zig build test
Push-Location .\nose
go test ./...
go build -o ..\dist\aegis-nose.exe .
Pop-Location
```

### 9.2 Verify Npcap installation and adapter selection

Run in an elevated PowerShell. Do not substitute file existence for a live capture proof.

```powershell
Get-Service -Name npcap -ErrorAction Stop | Format-List Name,Status,StartType
Get-NetAdapter | Sort-Object ifIndex | Format-Table ifIndex,Name,InterfaceDescription,Status,MacAddress,LinkSpeed
Get-NetIPConfiguration | Format-List InterfaceAlias,InterfaceIndex,IPv4Address,IPv6Address

Push-Location .\nose
..\dist\aegis-nose.exe -list-devices 2>&1 | Tee-Object ..\analysis\current-head\nose-devices.txt
Pop-Location
```

For the isolated VMware proof, confirm the intended VMnet1 CIDR and pass the exact Npcap device name rather than relying on heuristic selection:

```powershell
$iface = '<EXACT_NPCAP_DEVICE_NAME_FROM_LIST_DEVICES>'
$pipe = '\\.\pipe\aegis_nose'
$iface
$pipe
```

### 9.3 Start the real Zig owner and independently start Go Nose

The Go process is external in the current source graph. Start it separately and record both logs.

```powershell
# Window 1: real Zig production entrypoint
Set-Location -Path 'D:\NIDs_Windows'
zig build run 2>&1 | Tee-Object .\analysis\current-head\zig-runtime.log
```

```powershell
# Window 2: external Go producer
Set-Location -Path 'D:\NIDs_Windows\nose'
..\dist\aegis-nose.exe -capture -iface '<EXACT_NPCAP_DEVICE_NAME>' -pipe '\\.\pipe\aegis_nose' 2>&1 |
  Tee-Object ..\analysis\current-head\nose-capture.log
```

In a third window, query structured health; do not infer health from process existence:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python .\tools\aegisctl.py health
python .\tools\aegisctl.py metrics snapshot
```

The output must separately show runtime state, `nose_ready`, pipe connectivity, frames read/submitted/dropped, queue depth, and worker failure reasons. A green PEP field without provider/host-effect capability is not a prevention proof.

### 9.4 Execute the named-pipe golden path

Use the tracked source path, not the stale `core/` path in the CLI comment.

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig run .\src\tests\cli\nose_pipe_e2e_cli.zig -- -seconds 10
```

For a deterministic frame test, run the Go unit/fixture tests and compare the emitted bytes to the checked-in vector hashes:

```powershell
Push-Location .\nose
go test -run 'TestCanonical|TestGolden|TestEventFromPacketSynthetic|TestSignatureClassifier' -v
Pop-Location

Get-FileHash .\tests\contracts\event_vectors\event_vectors\event_v1_001.bin -Algorithm SHA256
Get-FileHash .\tests\contracts\event_vectors\event_vectors\event_v1_002.bin -Algorithm SHA256
Get-FileHash .\tests\contracts\event_vectors\event_vectors\event_v1_003.bin -Algorithm SHA256
```

The current source must first be fixed so the expected `struct_size` is generated identically. Until then, a fixture read by Go alone is not an acceptance proof.

### 9.5 Verify stop/restart and blocking behavior

Measure the stop path while the reader is idle and while a client is connected. The process must exit within the selected deadline and release both named pipes.

```powershell
Set-Location -Path 'D:\NIDs_Windows'
$proc = Get-Process -Name aegis_nids -ErrorAction Stop
$sw = [Diagnostics.Stopwatch]::StartNew()
python .\tools\aegisctl.py stop
$proc.WaitForExit(5000)
$sw.Stop()
[pscustomobject]@{Exited=$proc.HasExited; StopMilliseconds=$sw.ElapsedMilliseconds}
if (-not $proc.HasExited) { throw 'STOP-TIMEOUT: blocked worker or pipe owner' }

Get-Process -Name aegis_nids -ErrorAction SilentlyContinue
Get-Process -Name aegis-nose -ErrorAction SilentlyContinue
```

Repeat with Go Nose started but no Zig consumer, and with the Zig reader connected but no frames. Any hang or stale pipe ownership is a failure of DP-03/DP-04.

### 9.6 Verify identity, duplicate, and drop accounting

Run two capture generations and intentionally replay one frame. The daemon must reject or idempotently acknowledge the replay before policy/PEP/action dispatch.

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python .\tools\aegisctl.py metrics snapshot | Tee-Object .\analysis\current-head\metrics-before.json
# Stop and restart the external Nose producer without changing the daemon.
# Then repeat one deterministic fixture frame and query metrics again.
python .\tools\aegisctl.py metrics snapshot | Tee-Object .\analysis\current-head\metrics-after-nose-restart.json
# Restart the Zig daemon and repeat the same frame.
python .\tools\aegisctl.py metrics snapshot | Tee-Object .\analysis\current-head\metrics-after-daemon-restart.json
```

Acceptance requires stable producer/generation identity, no duplicate side effects, and a reconciled drop ledger. A counter that merely reports `duplicate_event_ids` after accepting the frame is not sufficient.

### 9.7 Run the isolated VMware observe-only proof

This section is **UNVERIFIED until run on the designated Windows/Kali/Windows 11 VMnet1 lab**. Confirm the target and cleanup plan before any host mutation.

```powershell
# Elevated Windows host preflight; use the exact project path.
Set-Location -Path 'D:\NIDs_Windows'
zig build
zig build test
python -m pytest .\tests\runtime\test_health.py .\tests\runtime\test_restart.py .\tests\runtime\test_wire.py -q
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_host_production_preflight.ps1 `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

The first network proof must be benign and observe-only on VMnet1. Record the exact adapter, CIDR, runtime generation, Go event ID, queue counters, detector result, policy result, PEP result, forensic sequence, and final gate. Do not treat `event_v1_002.bin` or a policy action of `block` as evidence of a host block.

## 10. Final disposition

At current HEAD, the system should be treated as **detection-only or degraded**, with enforcement closed. The production entrypoint reaches the Zig runtime and a detector/policy/PEP call chain, but it does not prove that Go Npcap capture is started, that the 109-byte Go frame is accepted, that the multi-producer queue is lossless/safe, that identity survives restart, that the blocking path is bounded, or that a WFP host effect is confirmed and linked to evidence.

The correct next milestone is not a UI or packaging claim. It is a current-head, byte-level, Windows data-plane proof that fixes the contract marker, converges queue/identity/drop authority, interrupts pipe I/O on shutdown, and emits receipt-driven forensic evidence. Until those proofs pass, **AEGIS is not Production-ready IPS**.

## References

[1]: ../../build.zig "Zig build graph and executable/test roots"
[2]: ../../src/daemon.zig "Active daemon startup, worker graph, and disabled direct Zig Npcap path"
[3]: ../../nose/main.go "Go Nose entrypoint and externally selected capture mode"
[4]: ../../src/contract/canonical_event.zig "CanonicalEvent v1 model, validation, identity, and 109-byte encoding"
[5]: ../../tests/contracts/event_vectors/event_vectors/golden_vectors.json "Canonical event golden-vector field metadata"
[6]: ../../src/pipeline/event_processor.zig "Active detection, policy, PEP, audit, and forensic pipeline"
[7]: ../../src/daemon.zig "RuntimeSupervisor stop and join implementation"
[8]: ../../src/capture/nose_pipe_reader.zig "Active Go Nose named-pipe server, framing, validation, and queue handoff"
[9]: ../../nose/pipe_writer.go "Go Nose frame writer, reconnect, and drop behavior"
[10]: ../../nose/capture.go "Go Npcap device enumeration and heuristic adapter selection"
[11]: ../../nose/capture.go "Go Npcap open, BPF, and packet capture loop"
[12]: ../../src/capture/npcap_adapter.zig "Zig dynamic Npcap loader and adapter selection support path"
[13]: ../../nose/capture.go "Go packet-to-canonical normalization and process-local event sequence"
[14]: ../../src/capture/packet_decoder.zig "Zig Ethernet/IP/TCP/UDP decoder and payload derivation"
[15]: ../../nose/signature_classifier.go "Go Nose local signature classification"
[16]: ../../src/pipeline/event_queue.zig "Active bounded queue, canonical-to-IpcEvent conversion, and payload copy"
[17]: ../../nose/canonical.go "Go CanonicalEvent layout, serialization, and struct-size marker"
[18]: ../../nose/golden_path_ffi.go "Go golden-vector FFI helper and cross-language status comments"
[19]: ../../nose/capture.go "Go capture loop handling of FrameWriter results and local counters"
[20]: ../../src/contract/event_fabric.zig "Event Fabric facade and reason-coded accounting support path"
[21]: ../../src/core/nids_capture.zig "Daemon-started legacy sensor pipe and local IpcEvent identity"
[22]: ../../src/detection/detection_interface.zig "Alternate detection result/verdict interface"
[23]: ../../src/policy/action_dispatcher.zig "PEP decision dispatch and block logging"
[24]: ../../src/forensic/forensic_pipeline.zig "Forensic ring append fields and hash-chain record write"
[25]: ../../src/tests/cli/nose_pipe_e2e_cli.zig "Named-pipe E2E CLI and stale usage-path comment"
[26]: ../../src/platform/win32_service.zig "Windows SCM and foreground entrypoint dispatch"
[27]: ../../src/detection/correlator.zig "Standalone correlation module and unit tests"
[28]: ../../src/detection/correlation_engine.zig "Alternate incident/correlation engine"
[29]: ../../src/detection/detection_engine.zig "Alternate evidence/verdict detection engine"
[30]: ../../src/all_tests.zig "Zig unit-test aggregator and imported support modules"
[31]: ../../tests/e2e/test_t14_windows_golden_path.py "Manifest/static golden-path assertions"
[32]: ../../src/tests/integration/golden_path_e3.zig "Synthetic Zig event-to-forensic golden-path test"
[33]: ../../nose/canonical_test.go "Go canonical, packet, and signature-classifier tests"
[34]: ../../README.md "Project source-of-truth hierarchy and non-production status"
[35]: ../../AGENTS.md "Repository review and authority rules"
[36]: ../../home/ubuntu/upload/AEGISComprehensiveDevelopmentAnalysisandProductionHandoff.md "Operational handoff context and production gates"
##
