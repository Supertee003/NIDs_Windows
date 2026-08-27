# AEGIS Event Flow (STEP 0 — Baseline Freeze)

## Golden Path (Current Implementation)

```
                    ┌──────────────────────────────────────────┐
                    │              SENSORS (Layer 1)             │
                    │                                          │
                    │  T2: Pipe Sensor (nids_capture.zig)     │
                    │  T3: WFP Sensor (windows_capture.zig)   │
                    │  T4: Minifilter (minifilter_reader.zig)  │
                    │  T5: Pipe Monitor (pipe_monitor.zig)     │
                    │  T6: HIDS Process (hids_process_monitor) │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │         NOSE CONTRACT (Layer 2)          │
                    │         nose_contract.zig                │
                    │                                          │
                    │  createEvent() → validate → submitEvent()│
                    │  (magic + version + struct_size check)   │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      PRIORITY QUEUE (Layer 3)            │
                    │      priority_queue.zig                  │
                    │                                          │
                    │  HIGH:   block, ip_blocked, rejected     │
                    │  NORMAL: match_, session_start, session_end│
                    │  LOW:    forward, ruleset_reload, startup│
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      EVENT FABRIC DRAIN (Layer 3.5)     │
                    │      eventFabricDrain() in nids_analyze  │
                    │                                          │
                    │  popEvent() → forensic_log (FABRIC_EVENT)│
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      DETECTION (Layer 4)                │
                    │      detection_interface.zig            │
                    │                                          │
                    │  DetectionManager.detect()               │
                    │  ├── Tier-1: AC Engine (existing)       │
                    │  ├── Tier-2: Regex (Python/Cython)      │
                    │  └── Tier-3: Rust Shield (behavioral)    │
                    │  → DetectionResult (verdict+rule_id)     │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      FLOW ENGINE (Layer 4.5)             │
                    │      flow_engine.zig                    │
                    │                                          │
                    │  FlowTable.upsert(FlowKey)              │
                    │  → FlowState (packet_count, risk_score) │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      CORRELATION (Layer 5)               │
                    │      xdr_correlator.zig                  │
                    │                                          │
                    │  XDRCorrelator.submitEvent()            │
                    │  → Incident (links by session_id)       │
                    │  → Severity escalation tracking          │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      THREAT INTELLIGENCE (Layer 6)       │
                    │      rag_intelligence.zig                │
                    │                                          │
                    │  RAGEngine.enrich(source_ip)             │
                    │  → EnrichmentResult (context_flags)      │
                    │  (does NOT make policy decisions)       │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      POLICY ENGINE (Layer 7)            │
                    │      policy_contract.zig                 │
                    │      policy_ir.zig                       │
                    │                                          │
                    │  PolicyEngine.evaluate(result, context)  │
                    │  → PolicyDecision (allow/alert/block)    │
                    │  (DEFCON-1 escalation override)          │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      PEP / ENFORCEMENT (Layer 8)        │
                    │      policy_contract.zig (PEP)           │
                    │                                          │
                    │  PEP.enforce(decision, event)            │
                    │  → wfp_ioctl.block_ip(source_ip)        │
                    │  → enforcement_status (1=ok, 2=failed)  │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      FORENSICS (Layer 9)                │
                    │      forensic_log.zig                   │
                    │                                          │
                    │  NDJSON: BLOCK/MATCH/FORWARD/POLICY_DEC  │
                    │  → logs/aegis_core.ndjson (rotated)     │
                    │  → logs/blocked_ips.json                │
                    │  → logs/payloads/<sha256>.bin           │
                    └──────────────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────┐
                    │      REPLAY (Layer 10)                  │
                    │      go/aggregator/                     │
                    │                                          │
                    │  fsnotify → NDJSON → dedup → timeline   │
                    │  REST API :9200 for dashboard/CLI       │
                    └──────────────────────────────────────────┘
```

## Parallel Paths

### Existing Detection Path (inspect_packet)
```
Sensor → inspect_packet() directly (legacy, pre-Blueprint)
  → AC Engine → pushTier1Match() → bridge_init.pushEvent() → C++ Bridge
  → bridge_init.sendToBrain() → UDP → Python Brain
  → forensic_log.logBlock() / logMatch() / logForward()
```

### Blueprint Event Fabric Path
```
Sensor → nose.submitEvent() → PriorityQueue → eventFabricDrain()
  → forensic_log.log(FABRIC_EVENT)
  (parallel to existing path — additive, not replacing)
```

## Event Lifecycle States (current)

```
CAPTURED (sensor creates event)
  ↓
VALIDATED (nose_contract.validate — magic+version check)
  ↓
QUEUED (PriorityQueue.push — HIGH/NORMAL/LOW)
  ↓
ANALYZED (DetectionManager.detect — verdict)
  ↓
CORRELATED (XDRCorrelator.submitEvent — incident)
  ↓
ENRICHED (RAGEngine.enrich — context_flags)
  ↓
POLICY_EVALUATED (PolicyEngine.evaluate — decision)
  ↓
ENFORCED (PEP.enforce — wfp_ioctl.block_ip)
  ↓
ARCHIVED (forensic_log — NDJSON + payload capture)
```

## Failure States (current)

```
REJECTED — nose_contract validation failed (wrong magic/version)
DROPPED — PriorityQueue full (overflow)
ERROR — DetectionManager error (fail-open: treat as no_match)
FAILED — PEP.enforce failed (WFP device not open)
TIMEOUT — Flow Engine expired (60s timeout)
```

## Data Flow Boundaries (for STEP 1+ changes)

| Boundary | Current | Target (v2.0 Plan) |
|----------|---------|---------------------|
| Sensor → Fabric | nose.submitEvent() ✅ | Same — enforce no bypass |
| Fabric → Detection | popEvent() → inspect_packet() (parallel) | Unified: popEvent() → DetectionManager.detect() |
| Detection → Correlation | Not wired in runtime | Wire: DetectionResult → XDRCorrelator |
| Correlation → RAG | Not wired in runtime | Wire: Incident → RAGEngine.enrich() |
| RAG → Policy | Not wired in runtime | Wire: EnrichmentResult → PolicyContext |
| Policy → PEP | Wired in inspect_packet() ✅ | Same — move to unified pipeline |
| PEP → Forensics | forensic_log.log() ✅ | Same + ForensicRecord model |
