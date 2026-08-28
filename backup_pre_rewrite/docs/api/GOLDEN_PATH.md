# AEGIS NIDS — Golden Path API Flow

## Complete Pipeline (processEventFullPipeline)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    processEventFullPipeline(event, det_mgr, payload) │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 8: RAG Enrichment (rag_int.enrichEvent)   │
          │  - Query threat DB by source_ip                 │
          │  - Set context_flags (threat_intel/apt/botnet)  │
          │  - Escalate severity (APT=critical, malicious=med+) │
          │  - Update flow risk_score (+/- delta, capped)   │
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 5: Flow Update (flow_int.processEvent)     │
          │  - Upsert FlowTable by 5-tuple                  │
          │  - Return FlowContext snapshot (packet_count,    │
          │    byte_count, risk_score, session_id)           │
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 6: Detection Pipeline                       │
          │  - escalateOnFlowPattern (high packet/byte/risk) │
          │  - det_mgr.detect (run registered detectors)     │
          │    ├─ C++ Bridge detector (STEP 17)              │
          │    ├─ Rust Shield detector (STEP 18)             │
          │    ├─ Python Brain detector (STEP 20)            │
          │    └─ Cython Accelerated detector (STEP 21)      │
          │  - On match: updateRiskScore (annotate flow)    │
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 7: XDR Correlation                          │
          │  - submitDetectionContext (link by session_id)   │
          │  - Create or link to existing incident            │
          │  - Escalate incident severity                     │
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 9: Policy + PEP                             │
          │  - Build PolicyContext (DEFCON, threat_intel,     │
          │    correlation_count, risk_score)                 │
          │  - PolicyEngine.evaluate (rules + DEFCON override) │
          │  - PEP.enforce (wfp_ioctl.block_ip / alert / log) │
          │  - Mutate event with policy_action + enforcement   │
          └────────────────────────┬────────────────────────┘
                                   │
          ┌────────────────────────▼────────────────────────┐
          │  STEP 10: Forensics Logging                       │
          │  - logPipelineResult (24-field PipelineRecord)     │
          │  - Write to in-memory ring buffer (4096 entries)   │
          │  - Write to disk NDJSON (forensic_log.log)        │
          │  - Available for replay query (STEP 10 API)        │
          └───────────────────────────────────────────────────┘
```

## Detector Registration

```zig
// Register all multi-language detectors (STEP 17-21)
const dm = detection.DetectionManager.init();

// C++ Bridge (STEP 17) — packet parsing
_ = cpp_bridge.registerBridgeDetector(&dm); // if available

// Rust Shield (STEP 18) — behavioral analysis
rust_shield.init(50.0);
_ = rust_shield.registerShieldDetector(&dm);

// Python Brain (STEP 20) — regex deep inspection
python_brain.init("127.0.0.1", 9999);
_ = python_brain.registerBrainDetector(&dm);

// Cython Acceleration (STEP 21) — pattern matching
cython.init();
_ = cython.registerCythonDetector(&dm);

// Now dm.detect() runs all 4 detectors per event
```

## Pressure-Aware Sensor Submission (STEP 4)

```zig
// Sensor checks pressure before expensive sampling
const pressure = nose_int.currentPressure();
if (pressure == .saturated) {
    // Drop low-priority events at source
    return;
}

// Submit with backpressure awareness
const result = nose_int.submit(event);
switch (result) {
    .accepted => {},
    .dropped_at_source => { /* sampling policy decided */ },
    .dropped_by_fabric => { /* queue full after backoff */ },
    .rejected => { /* validation failed */ },
    .not_initialized => { /* fabric not ready */ },
}
```

## Forensics Replay Query (STEP 10)

```zig
// Query by session_id (incident investigation)
const result = forensics_int.query(.{
    .session_id = 42,
    .decisions_only = true,
});

// Get recent events (newest first)
const recent = try forensics_int.getRecent(allocator, 10);
defer allocator.free(recent);

// Build incident timeline
const timeline = try forensics_int.buildTimeline(allocator, 42, 100);
defer allocator.free(timeline);
```

## Metrics Export (STEP 22)

```zig
// Collect from all layers
metrics_export.init();
metrics_export.collectAllMetrics();

// Export in Prometheus format
var buf: [8192]u8 = undefined;
const written = metrics_export.exportPrometheus(&buf);
// buf[0..written] contains Prometheus text format
```
