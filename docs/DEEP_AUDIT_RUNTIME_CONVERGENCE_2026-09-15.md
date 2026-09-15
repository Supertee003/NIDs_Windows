# AEGIS NIDS Deep Audit — Runtime Convergence

**Date:** 2026-09-15  
**Scope:** production entrypoint, capture paths, named pipes, Canonical Event contract, pipeline queue, health counters, and build graph.

## Executive conclusion

The project is not failing because of one Npcap call. It currently contains **multiple partially overlapping runtime architectures**. The daemon starts a legacy Python sensor pipe, a direct Zig Npcap capture thread, and a Go Nose canonical pipe reader at the same time. Only one of these should be the canonical acquisition path.

The current evidence proves that WFP, C++ bridge, UDP brain, Zig Npcap open, and Go-to-`aegis_nose` pipe connection can work independently. It does **not** yet prove a live packet traverses the Go Nose path into the detector queue. The correct next step is convergence and observability, not adding more sensors.

## 1. Production runtime graph

`build.zig` builds `src/main.zig`. `main.zig` dispatches into the Windows service/console entrypoint, which reaches `daemon.runDaemon()`.

`daemon.zig` currently starts all of the following:

| Runtime path | Source | Endpoint | Role | Assessment |
|---|---|---|---|---|
| Direct Zig Npcap | `pipeline/packet_callback.zig` → `capture/npcap_adapter.zig` | Npcap handle | Captures and pushes internal `IpcEvent` | Competing acquisition path |
| Legacy sensor pipe | `core/nids_capture.zig` | `\\.\\pipe\\aegis_sensor_pipe` | Python/script payloads to legacy analyzer | Legacy path still active |
| Go Nose canonical pipe | `capture/nose_pipe_reader.zig` | `\\.\\pipe\\aegis_nose` | Reads 4-byte length + 109-byte Canonical Event | Intended canonical path |
| ETW/FIM/registry | `pipeline/telemetry_threads.zig` | Native helpers | Host telemetry | Optional/degraded |

This is the main architectural source of confusion. The startup log simultaneously reports direct Npcap capture and Go Nose readiness, but health does not distinguish **process alive**, **adapter open**, **frames received**, and **events submitted**.

## 2. Confirmed structural problems

### 2.1 Three acquisition concepts remain active

`daemon.zig` imports `legacy_capture`, starts `legacy_capture.capture_packets`, starts `packet.captureThread`, and starts `nose_reader.runPipeReaderLoop`. The comments themselves label the first bridge as `Legacy` and the Go reader as `Canonical`, but both remain in the production path.

**Required decision:** make Go Nose → `aegis_nose` → Zig canonical reader the single production network-ingress path. Keep direct Zig Npcap only behind an explicit diagnostic/test mode, or remove it from the default daemon startup.

### 2.2 Pipe names are not the same contract

- `aegis_sensor_pipe` is the legacy Python/script pipe.
- `aegis_nose` is the canonical Go Nose pipe.

Earlier tests sent Go Nose to `aegis_sensor_pipe`, which could never reach `nose_pipe_reader.zig`. The current connection to `aegis_nose` is correct.

### 2.3 Canonical Event semantic enums are inconsistent

The Zig contract defines:

- `EventType.forward = 2` and `match_ = 1`;
- `PolicyAction.log_only = 5`.

Go currently defines:

- `TypeForward = 1`;
- `ActionLogOnly = 0`.

The 109-byte frame can pass magic/version/size validation while carrying the wrong event semantics. This violates the single event-model requirement even if byte length is correct.

### 2.4 Canonical Go deserializer had an offset bug

Go `Serialize()` writes the header at bytes `0..7` and `EventID` at `8..15`, while `Deserialize()` previously read `EventID` from `0..7`. This was fixed and a round-trip regression test was added, but the wider enum mismatch remains.

### 2.5 The Zig canonical reader is active despite stale documentation

`nose_pipe_reader.zig` says it is “not build.zig main target (deferred T3)”, but `daemon.zig` imports and starts it in the production daemon. The comment is false and should be corrected as part of convergence.

### 2.6 Health is lifecycle-oriented, not data-plane truthful

`runtime_state` has real pipeline counters and `g_last_event_ms`, but the health payload can report all seven subsystems `RUNNING` while `in_events=0`, `out_events=0`, and `last_event_ms=0`. A healthy process is not the same as a live data plane.

Health must expose at least:

- `nose_process_connected`;
- `nose_frames_received`;
- `nose_frames_rejected`;
- `nose_frames_submitted`;
- `pipeline_events_processed`;
- `capture_packets`;
- `capture_errors`;
- `last_event_ms`.

## 3. Why the packet symptom is misleading

The daemon log proves that the Zig direct Npcap handle opens and that Go can connect to `aegis_nose`. It does not prove that Go's pcap loop receives traffic. The Go capture loop was changed to direct `ReadPacketData()` so pcap read errors can no longer be hidden by `PacketSource.Packets()`.

The next run must distinguish:

1. `OpenLive` failure;
2. BPF filter failure;
3. read timeout;
4. non-timeout `ReadPacketData` error;
5. first packet received;
6. first 113-byte framed write;
7. Zig 109-byte frame read;
8. canonical validation;
9. queue submission;
10. pipeline processing.

To isolate the acquisition layer, Go Nose now has `-capture-probe`. It opens the selected Npcap interface for 15 seconds without BPF, packet decoding, CanonicalEvent serialization, or named-pipe delivery. A result of `packets=0` localizes the fault to interface/Npcap/host traffic; packets in probe but not in `-capture` localize it to BPF or decoding; packets in capture but no pipe frame localize it to serialization or writer.

## 4. Contract-first remediation order

### Phase A — freeze the production graph

1. Keep `aegis_nose` as the only network canonical pipe.
2. Disable direct Zig Npcap startup by default; add an explicit diagnostic flag if needed.
3. Disable or isolate `aegis_sensor_pipe` legacy server from the normal production run.
4. Rename stale comments and remove claims that the canonical reader is test-only.

### Phase B — freeze the wire contract

1. Correct Go enum values to exactly match `canonical_event.zig`.
2. Add Go tests for magic, version, struct size, event type, policy action, event ID, source, and all fixed offsets.
3. Add a cross-language test that sends one synthetic Go frame through the actual Zig reader and asserts the same event ID reaches `event_queue`.
4. Reject invalid magic/version/size in Go deserialization as well as Zig validation.

### Phase C — make data-plane health truthful

1. Add reader statistics to the control health response.
2. Separate `RUNNING` lifecycle from `DATA_PLANE_ACTIVE` readiness.
3. Set `last_event_ms` only after a queue event is accepted/processed.
4. Make `in_events` and `out_events` derive from the same canonical counters, not placeholder subsystem state.

### Phase D — live proof

Run one synthetic event first, then a live packet:

```text
Go synthetic CanonicalEvent
  -> 113-byte pipe frame
  -> Zig receives 109-byte payload
  -> validate
  -> pushCanonicalEvent
  -> event_queue
  -> event_processor
  -> forensic append
```

Only after this passes should live Npcap capture be used to prove the external acquisition layer.

## 5. Current status

The adapter probe on 2026-09-15 identified the concrete Npcap root cause. The previously used GUID `EEBC19C8-C7B1-426C-9FFC-ED2F36F99CAA` is `WAN Miniport (Network Monitor)` and produced `packets=0`. The real Wi-Fi adapter is `5FD31C6E-DE48-44CB-838E-14667A04DA4B`, described as `Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)`, and produced 13 raw packets in five seconds. Loopback also produced four packets, proving the Go/Npcap read path works.

The Zig and Go auto-selection filters were therefore tightened to skip WAN Miniport, Hyper-V, VMware, Bluetooth, Wi-Fi Direct, TeamViewer, and loopback descriptions. Zig also now preserves the selected device name in the adapter state instead of copying the original zero-filled config.

The control-plane health payload now exposes `data_plane.nose_connected`, `nose_frames_read`, `nose_frames_rejected`, `nose_frames_submitted`, `nose_frames_dropped`, and `nose_pipe_errors`, so a process can no longer be mistaken for an active canonical data plane.

The first live E2E reached `[NOSE PIPE] canonical event submitted: event_id=167`, proving Go Nose -> named pipe -> Zig deserializer -> `event_queue` works. The same run exposed an independent crash in the competing direct Zig Npcap path: `pcap_pkthdr` was declared with 64-bit timestamp fields, but Windows Npcap uses 32-bit C `long` fields for `timeval`; this shifted `caplen`/`len` and caused an integer-cast panic in `packetCallback`. The ABI was corrected to 32-bit `i32` timestamps, a checked timestamp conversion was added, and a 16-byte layout regression test was added.

The subsequent live run produced Go frames (`event_id=1..`) and Zig submissions (`event_id=759..761`) while an audit event showed another ID (`984`), confirming the duplicate direct Zig Npcap path was still active and interleaving events. `daemon.zig` now disables direct Zig Npcap in production; Go Nose is the sole canonical network ingress, while the direct adapter remains available only for focused tests/diagnostics.

The health contract now includes exactly-once observations: the latest Nose event ID, duplicate event-ID count, and non-monotonic event-ID count. These are checked at the canonical reader immediately before queue submission and exposed through both Zig health JSON and the Python control API.

The first metrics/forensics probe showed `nose_frames_submitted=99` but `packets_captured=0` and `records=0`. This was a reporting defect: the metrics handler counted only the disabled direct Zig Npcap adapter, while the forensic list handler incorrectly used detection count rather than forensic append count. The handlers now report canonical Nose submissions, pipeline events processed, and successful forensic ring appends separately.

The forensic verification handler no longer returns a constant success value. The daemon publishes the active `ForensicRing` through runtime state, and `forensics.verify` now calls `ForensicRing.verifyHashChain()` under the ring mutex and reports the actual verification result and record count.

The next security-path slice begins with the rule loader contract. The previous `configs/Rules.json` fixture contained no `match_pattern`, so the loader correctly reported zero active signatures despite the file containing a nominal test rule. The fixture now contains two explicit patterns (`GET` and `example.com`) so `rules_loaded` can be verified independently before testing detection and PEP enforcement.

The canonical detection boundary is now explicit: the frozen 109-byte event carries `rule_id`, `event_type`, severity, and payload reference, but not raw payload bytes. `event_processor` therefore accepts an upstream classifier's `signature_match + rule_id` metadata as the detection result and passes it to Policy IR/PEP without reinterpreting payload bytes. Raw signature matching remains a separate acquisition/classification responsibility; the Zig runtime remains the policy and enforcement path.

The Go Nose now loads the same `nids_rules[].match_pattern` fixture (or `AEGIS_RULES_PATH`) and, when an application payload matches, emits `event_type=match_`, the FNV-1a rule ID used by the Zig loader, and the canonical severity ordinal. This is classification metadata only; Go does not evaluate policy or enforce. The next Windows E2E assertion is `rules_loaded > 0`, followed by `detections > 0`, `blocks > 0` or an explicit PEP deny/allow decision, and matching forensic `rule_id` with a verified hash chain.

| Area | Status |
|---|---|
| WFP device | Working |
| C++ bridge load/export/init | Working |
| UDP brain | Working |
| Zig direct Npcap open | Working |
| Go Nose process and pipe connection | Working |
| Go packet delivery | Unproven; direct read diagnostics added |
| 109-byte frame size | Implemented |
| Go event ID round-trip | Fixed and regression test added |
| Go/Zig enum semantics | **Mismatch remains** |
| Single acquisition authority | **Not yet converged** |
| Health data-plane truth | **Incomplete** |
| End-to-end forensic proof | Pending |

## Decision

Do not add more detector, ETW, FIM, federation, or brain features yet. First converge the runtime to one network acquisition path and prove one synthetic 109-byte event end to end. The current project is larger than the target architecture because legacy, direct-capture, and canonical paths were all retained during successive development phases.
