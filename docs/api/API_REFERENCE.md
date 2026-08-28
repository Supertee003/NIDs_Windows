# AEGIS NIDS API Documentation (v3.0)

## Overview

This document covers all public APIs across the AEGIS NIDS pipeline (STEP 3-26).

## Table of Contents

1. [Event Fabric Runtime (STEP 3)](#event-fabric-runtime)
2. [Nose Integration (STEP 4)](#nose-integration)
3. [Flow Engine Integration (STEP 5)](#flow-engine-integration)
4. [Detection Fabric (STEP 6)](#detection-fabric)
5. [Correlation Layer (STEP 7)](#correlation-layer)
6. [RAG Intelligence (STEP 8)](#rag-intelligence)
7. [Policy Engine (STEP 9)](#policy-engine)
8. [Forensics Replay (STEP 10)](#forensics-replay)
9. [C++ Bridge Integration (STEP 17)](#cpp-bridge-integration)
10. [Rust Shield Integration (STEP 18)](#rust-shield-integration)
11. [Go Aggregator Integration (STEP 19)](#go-aggregator-integration)
12. [Python Brain Integration (STEP 20)](#python-brain-integration)
13. [Cython Acceleration (STEP 21)](#cython-acceleration)
14. [Metrics Export (STEP 22)](#metrics-export)

---

## Event Fabric Runtime

**Module:** `core/event_fabric.zig`
**Step:** 3

### Types

#### `Pressure` (enum u8)
- `low` — queue depth < 50%
- `medium` — queue depth 50%-80%
- `high` — queue depth > 80%
- `saturated` — queue full

#### `DropPolicy` (enum u8)
- `block_new` — reject new events when full (default)
- `drop_oldest` — evict oldest event, accept new
- `drop_lowest_priority` — evict lowest-priority event

#### `FabricConfig` (struct)
- `capacity_per_priority: usize = 256`
- `validate_on_submit: bool = true`
- `medium_threshold: f32 = 0.50`
- `high_threshold: f32 = 0.80`
- `drop_policy: DropPolicy = .block_new`

#### `FabricMetrics` (struct)
- `pending: usize` — total events in queue
- `pressure: Pressure` — current pressure level
- `total_accepted: u64` — lifetime accepted count
- `total_rejected: u64` — lifetime rejected count
- `total_dropped: u64` — lifetime dropped count
- `total_popped: u64` — lifetime popped count
- `last_pop_latency_ns: u64` — last event latency
- `max_pop_latency_ns: u64` — max observed latency

### Functions

#### `initFabric(allocator, config) !void`
Initialize the Event Fabric. Call once at startup.

#### `shutdownFabric(allocator) void`
Shutdown and free all resources.

#### `submitWithBackpressure(event) SubmitWithPressure`
Submit event with pressure signaling. Returns `{ accepted, pressure }`.

#### `submitEvent(event) bool`
Submit event (simple API). Returns true if accepted.

#### `popEvent() ?CanonicalEvent`
Pop next highest-priority event. Updates latency tracking.

#### `currentPressure() Pressure`
Query current pressure without submitting.

#### `getMetrics() FabricMetrics`
Get unified metrics snapshot.

---

## Nose Integration

**Module:** `core/nose_integration.zig`
**Step:** 4

### Types

#### `IntegratedSubmitResult` (enum)
- `accepted` — event enqueued
- `dropped_at_source` — sampling policy dropped event at sensor
- `dropped_by_fabric` — queue full after backoff
- `rejected` — validation failed
- `not_initialized` — fabric not initialized

#### `SamplingPolicy` (struct)
- `medium_low_drop_fraction: f32 = 0.50`
- `high_drop_low: bool = true`
- `saturated_drop_low_and_normal: bool = true`
- `saturated_high_backoff_ns: u64 = 1_000_000`
- `max_backoff_retries: u32 = 1`

Presets:
- `.default` — balanced
- `.aggressive` — more sampling
- `.permissive` — never drop at source

#### `SensorStats` (struct)
- `total_submits: u64`
- `accepted: u64`
- `dropped_at_source: u64`
- `dropped_by_fabric: u64`
- `backoff_retries: u64`
- `acceptRate() f32`

### Functions

#### `init(policy) void`
Initialize with sampling policy.

#### `submit(event) IntegratedSubmitResult`
Submit with adaptive sampling + backoff.

#### `getStats() SensorStats`
Get aggregate stats.

#### `getSensorStats(source) SensorStats`
Get per-sensor-type stats.

---

## Flow Engine Integration

**Module:** `core/flow_integration.zig`
**Step:** 5

### Types

#### `FlowContext` (struct, value type)
- `is_new_flow: bool`
- `is_host_event: bool`
- `key: FlowKey` — 5-tuple
- `packet_count: u64`
- `byte_count: u64`
- `risk_score: u8` (0-255)
- `session_id: u64`

### Functions

#### `init() void`
Initialize flow integration.

#### `processEvent(event) FlowContext`
Update FlowTable + return context snapshot.

#### `updateRiskScore(key, score) void`
Update flow risk score (called by detection layer).

#### `purgeExpired() usize`
Remove expired flows (60s timeout).

---

## Detection Fabric

**Module:** `core/detection_integration.zig`
**Step:** 6

### Types

#### `DetectionContext` (struct)
- `event: CanonicalEvent` — mutated with escalation flags
- `flow_context: FlowContext` — snapshot
- `verdict: Verdict` — no_match / match_alert / match_block
- `matched: bool`

#### `EscalationThresholds` (struct)
- `high_packet_count: u64 = 1000`
- `high_byte_count: u64 = 10_000_000`
- `high_risk_score: u8 = 200`

Presets: `.default()`, `.strict()`

### Functions

#### `processEvent(event, det_mgr, payload) DetectionContext`
Full detection pipeline:
1. Update flow state
2. Check escalation patterns
3. Run detectors (if det_mgr provided)
4. Update flow risk score on match

#### `escalateOnFlowPattern(event, fctx) ?Verdict`
Check flow patterns (beaconing, exfiltration, repeat offender).

---

## Correlation Layer

**Module:** `core/correlation_integration.zig`
**Step:** 7

### Types

#### `CorrelationResult` (struct)
- `linked_to_existing: bool`
- `incident_index: ?usize`
- `incident_event_count: u32`
- `incident_severity: u8`

### Functions

#### `submitDetectionContext(det_ctx) CorrelationResult`
Feed DetectionContext to XDR correlator.

#### `processEventWithCorrelation(event, det_mgr, payload)`
Combined pipeline: detection + correlation in one call.

---

## RAG Intelligence

**Module:** `core/rag_integration.zig`
**Step:** 8

### Functions

#### `enrichEvent(event) EnrichmentContext`
Query threat DB by source_ip. Mutates event:
- Sets `context_flags` (threat_intel/apt/botnet/high_confidence)
- Escalates severity (APT=critical, malicious=medium+)
- Updates flow risk_score

#### `processEventWithRAG(event, det_mgr, payload)`
Combined: RAG enrich + detection + correlation.

#### `addThreat(entry) bool`
Add threat intel entry at runtime.

---

## Policy Engine

**Module:** `core/policy_integration.zig`
**Step:** 9

### Types

#### `PolicyResult` (struct)
- `decision: PolicyDecision`
- `enforcement_result: EnforcementResult`
- `context: PolicyContext`
- `event: CanonicalEvent` (after enforcement)

#### `FullPipelineResult` (struct)
- `det_ctx: DetectionContext`
- `corr_result: CorrelationResult`
- `enrichment: EnrichmentContext`
- `policy_result: PolicyResult`

### Functions

#### `processEventFullPipeline(event, det_mgr, payload) FullPipelineResult`
**Main entry point** — runs the COMPLETE Golden Path:
1. RAG enrichment (STEP 8)
2. Flow update (STEP 5)
3. Detection escalation + detectors (STEP 6)
4. XDR correlation (STEP 7)
5. Policy evaluation (STEP 9)
6. PEP enforcement (STEP 9)

#### `evaluateAndEnforce(det_ctx, enrichment, corr_result) PolicyResult`
Evaluate policy + enforce PEP.

---

## Forensics Replay

**Module:** `core/forensics_integration.zig`
**Step:** 10

### Types

#### `PipelineRecord` (struct, 24 fields)
Captures full pipeline result per event: seq, timestamp, event_id, session_id, source_ip, event_type, severity, threat_intel_match, threat_category, confidence, verdict, detection_matched, incident_index, linked_to_existing, decision, enforcement_result, context_flags, flow_packet_count, flow_byte_count, flow_risk_score.

#### `ReplayFilter` (struct)
- `session_id: ?u64`
- `min_severity: u8`
- `threat_intel_only: bool`
- `decisions_only: bool`
- `since_ms: ?i64`
- `source_ip: ?u32`

### Functions

#### `logPipelineResult(result) void`
Log full pipeline result to ring buffer + disk NDJSON.

#### `query(filter) ReplayResult`
Query in-memory ring buffer (4096 entries).

#### `getRecord(seq) ?PipelineRecord`
Retrieve specific record by sequence number.

#### `getRecent(allocator, n) ![]PipelineRecord`
Get N most recent records (newest first, caller frees).

#### `buildTimeline(allocator, session_id, max) ![]TimelineEntry`
Reconstruct incident timeline for a session.

---

## C++ Bridge Integration

**Module:** `core/cpp_bridge_integration.zig`
**Step:** 17

### Functions

#### `canonicalToIpcEvent(event) IpcEvent`
Convert CanonicalEvent → C++ IpcEvent (48 bytes, explicit field-by-field).

#### `ipcEventToCanonical(ipc) CanonicalEvent`
Convert C++ IpcEvent → CanonicalEvent.

#### `submitToCppBridge(event) bool`
Convert + push to C++ IPC bridge.

#### `popFromCppBridge() ?CanonicalEvent`
Pop from C++ + convert back.

#### `parsePacketWithCpp(data) ?CanonicalEvent`
Use C++ PacketParser (zero-copy) on raw data.

---

## Rust Shield Integration

**Module:** `core/rust_shield_integration.zig`
**Step:** 18

### Types

#### `ShieldSeverity` (enum i32)
- `low = 0`, `medium = 1`, `high = 2`, `critical = 3`

### Functions

#### `scoreEvent(severity, confidence) i32`
Score event (0-100). Critical=100, High=75, Medium=50, Low=25.

#### `isThreat(score) bool`
Check if score >= threshold (default 50).

#### `shieldDetector(payload, ctx) DetectionResult`
Detector adapter for DetectionManager (tier3_behavioral).

#### `registerShieldDetector(dm) bool`
Register as tier-3 detector.

---

## Go Aggregator Integration

**Module:** `core/go_aggregator_integration.zig`
**Step:** 19

### Functions

#### `pushAlert(level, event, rule, src_ip, src_port, session_id) bool`
Push alert to Go aggregator (via NDJSON in production, stub in test).

#### `pushAlertFromEvent(event, level) bool`
Convenience for CanonicalEvent.

#### `getAlertCount() usize`
Query total alert count.

#### `getCriticalAlertCount() u64`
Query critical-only count.

#### `getSessionTimelineCount(session_id) u64`
Count events for a session.

---

## Python Brain Integration

**Module:** `core/python_brain_integration.zig`
**Step:** 20

### Types

#### `DefconLevel` (enum u8)
- `defcon1` (Critical) → `defcon5` (Normal)

#### `BrainResult` (struct)
- `matched: bool`
- `score: i32` (0-100, -1 = error)
- `severity: u8`
- `defcon: DefconLevel`

### Functions

#### `submitToBrain(payload, ctx) BrainResult`
Tier-2 regex deep inspection.

#### `getDefconLevel() DefconLevel`
Query current DEFCON level.

#### `brainDetector(payload, ctx) DetectionResult`
Detector adapter for DetectionManager (tier2_regex).

#### `registerBrainDetector(dm) bool`
Register as tier-2 detector.

---

## Cython Acceleration

**Module:** `core/cython_acceleration.zig`
**Step:** 21

### Functions

#### `fastScan(payload, patterns) ScanResult`
C-level substring matching (10 default patterns).

#### `fastScanDefault(payload) ScanResult`
Scan with built-in patterns (malware, suspicious, exploit, etc.).

#### `fastSeverityLookup(severity_str) CythonSeverity`
String → severity enum.

#### `cythonAcceleratedDetector(payload, ctx) DetectionResult`
Detector adapter using Cython scan.

#### `registerCythonDetector(dm) bool`
Register as tier-1.5 detector.

---

## Metrics Export

**Module:** `core/metrics_export.zig`
**Step:** 22

### Functions

#### `init() void`
Initialize metrics registry (64 slots max).

#### `registerCounter(name, help, value) bool`
Register a counter metric.

#### `registerGauge(name, help, value) bool`
Register a gauge metric.

#### `updateMetric(name, value) bool`
Update existing metric value.

#### `collectAllMetrics() void`
Gather metrics from ALL pipeline layers (STEP 3-21).

#### `exportPrometheus(buf) usize`
Export in Prometheus text format to buffer.

### Metric Naming Convention

All metrics use `aegis_` prefix:
- `aegis_fabric_*` — Event Fabric (STEP 3)
- `aegis_nose_*` — Nose Integration (STEP 4)
- `aegis_flow_*` — Flow Engine (STEP 5)
- `aegis_detection_*` — Detection (STEP 6)
- `aegis_correlation_*` — Correlation (STEP 7)
- `aegis_rag_*` — RAG Intelligence (STEP 8)
- `aegis_policy_*` — Policy Engine (STEP 9)
- `aegis_forensics_*` — Forensics (STEP 10)
- `aegis_version_*` — Release info (STEP 15)
