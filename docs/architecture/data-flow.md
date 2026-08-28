# AEGIS NIDS — Data Flow (Rewrite v3.0)

## Golden Path (Rewrite Target)

```
SOURCE (WFP/Minifilter/Pipe/HIDS)
  ↓ capture + minimal metadata
NOSE
  ↓ timestamp + sequence + validation
CANONICAL EVENT
  ↓ explicit wire encoding (no memcpy)
EVENT FABRIC
  ↓ pressure-aware queue + backpressure
RUNTIME DISPATCHER
  ↓ pop event, route to pipeline
  ├──→ FLOW ENGINE
  │     ↓ upsertOrCreate() → FlowSnapshot
  │     ↓ flow context (packet_count, byte_count, risk_score)
  │
  ├──→ DETECTION
  │     ↓ Detector.scan() → Evidence[]
  │     ↓ NOT event mutation — evidence production
  │
  └──→ TELEMETRY (future)
        ↓ metrics collection

EVIDENCE[]
  ↓ aggregate by event_id
VERDICT
  ↓ BENIGN / OBSERVE / SUSPICIOUS / MALICIOUS / UNKNOWN / ERROR
  ↓ UNKNOWN != BENIGN, ERROR != BENIGN

CORRELATION
  ↓ link by entity graph (not just session_id)
  ↓ Entity: Host, Process, User, File, Flow, Session, IP, Domain, Pipe
  ↓ create/update Incident

INCIDENT
  ↓ events[] + entities[] + evidence[] + attack_chain[] + actions[]

THREAT INTELLIGENCE
  ↓ IP / Domain / Hash / IOC / Reputation lookup
  ↓ provenance: source, entry_id, version, confidence

BRAIN (Python/Cython)
  ↓ score + confidence + features + context + recommendation
  ↓ advisor only — NO direct enforcement

RAG (Retrieval-Augmented Generation)
  ↓ threat context, MITRE mapping, historical incidents, playbooks
  ↓ enrichment only — NO direct enforcement

VERDICT + CONTEXT
  ↓ PolicyEngine.evaluate()
  ↓ → EnforcementPlan (not direct action)

POLICY IR
  ↓ priority, severity, verdict, condition, action, enabled
  ↓ conflict resolution: priority → severity → deterministic tie breaker

ENFORCEMENT PLAN
  ↓ Rust PEP: validate (policy_version, signature, target, action, authorization, expiry)
  ↓ execute: WFP block / host action

ACTION
  ↓ EnforcementResult: SUCCESS / FAILED / NOT_APPLICABLE / UNSUPPORTED / SKIPPED / DENIED / TIMEOUT

FORENSICS
  ↓ audit context: event_id, detector_version, ruleset_version, intel_version, brain_version, policy_version, decision, action, result
  ↓ ring buffer (4096) + NDJSON (append-only, rotation)

REPLAY
  ↓ Recorded Event → Detection → Correlation → Policy Simulation
  ↓ "ruleset ใหม่จะตัดสิน event เก่าอย่างไร?"
```

## Key Changes from v2.0/v3.0

| From (v2.0/v3.0) | To (Rewrite) |
|-------------------|--------------|
| Detector mutates event | Detector emits Evidence |
| Detection = decision | Detection → Evidence → Verdict |
| Session correlation | Entity graph correlation |
| Flow pointer after unlock | Flow snapshot (value type) |
| lookup() then upsert() | upsertOrCreate() (atomic) |
| Policy + PEP in one call | Evaluate → Plan → Execute |
| Brain blocks directly | Brain advises (score + recommendation) |
| Linear FlowTable (array) | Hash-based flow store |
| Overwrite slot 0 when full | LRU/clock eviction |
| main() knows everything | Runtime owns lifecycle |
| Tests call functions | Tests exercise real pipeline |

## Data Ownership

```
┌─────────────────────────────────────────────────────┐
│ SENSOR LAYER                                        │
│  WFP → raw packet metadata                         │
│  Minifilter → file operation metadata              │
│  Pipe → payload data                               │
│  HIDS → process event metadata                     │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ NOSE LAYER                                          │
│  Timestamp (dual-clock: epoch_ms + monotonic_ns)    │
│  Sequence (atomic counter)                          │
│  Provenance (source enum)                           │
│  Validation (magic + version + struct_size)         │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ CANONICAL EVENT (single source of truth)            │
│  109 bytes wire format (explicit field-by-field)    │
│  Immutable after creation                           │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ EVENT FABRIC (runtime authority)                    │
│  Priority queue (HIGH/NORMAL/LOW)                   │
│  Pressure levels (low/medium/high/saturated)        │
│  Backpressure signaling                             │
│  Source sampling (drop at sensor, not at queue)     │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ RUNTIME DISPATCHER                                  │
│  Pop event from Fabric                              │
│  Route to: Flow → Detection → Correlation → Policy  │
│  Thread pool management                             │
│  Graceful shutdown                                  │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ EVIDENCE (NEW — detection output)                   │
│  event_id, detector_id, detector_version            │
│  rule_id, severity, confidence, reason, evidence_ref│
│  Multiple evidence per event → aggregated to Verdict│
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ VERDICT (NEW — aggregated detection result)         │
│  BENIGN / OBSERVE / SUSPICIOUS / MALICIOUS / UNKNOWN│
│  UNKNOWN != BENIGN (explicit uncertainty)           │
│  ERROR != BENIGN (explicit failure)                 │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌──────────────────────▼──────────────────────────────┐
│ POLICY (evaluate → plan → execute)                  │
│  Evaluate: Verdict + Context → EnforcementPlan      │
│  Plan: action, target, authorization, expiry        │
│  Execute: Rust PEP validates + enforces             │
└─────────────────────────────────────────────────────┘
```
