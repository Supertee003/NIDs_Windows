# Runtime Spine

**Status**: AUTHORITATIVE
**Source**: `docs/architecture/ARCHITECTURE_CANONICAL.md` Section 2

---

## Single Runtime Path

AEGIS has exactly **one** runtime spine. No competing paths are allowed.

```
SOURCE
  |
SENSOR (Nose - Go/C)
  |
CANONICAL EVENT (Zig - immutable)
  |
VALIDATION (Zig)
  |
EVENT FABRIC (Zig - priority queue)
  |
STATE / FLOW (Zig - atomic upsert, bounded)
  |
DETECTION (Zig - evidence producer, NOT enforcer)
  |
EVIDENCE (Zig - aggregated)
  |
VERDICT (Zig + Brain advisory - fail-soft)
  |
CORRELATION (Zig - entity graph, 9 types)
  |
INTELLIGENCE (Zig - Threat Intel + RAG, separate)
  |
POLICY (Zig - decides, NOT executes)
  |
ENFORCEMENT PLAN (Zig -> Rust)
  |
RUST PEP (Rust - validate, execute, defer)
  |
ACTION (Rust - block/alert/rate-limit)
  |
FORENSICS (Zig - immutable, hash-chained)
  |
REPLAY (Zig - deterministic regression)
```

---

## Authority

| Component | File | Role |
|-----------|------|------|
| Orchestrator | `core/dispatcher.zig` | Drains queue, calls stage functions |
| Lifecycle | `core/lifecycle.zig` | init() -> start() -> run() -> shutdown() |
| Main | `nids_main.zig` | Bootstrap only (no business logic) |

---

## Dispatcher Refactor Rule

If `processEvent()` becomes too large, it must call explicit stage functions:

```
processEvent()
  -> processFlow()
  -> processDetection()
  -> processVerdict()
  -> processCorrelation()
  -> processIntelligence()
  -> processPolicy()
  -> processEnforcement()
  -> processForensics()
```

**Goal**: Dispatcher = orchestrator, NOT a second monolith.

---

## Stage Details

### 1. Nose (OBSERVE)
- **Language**: Go (with C drivers)
- **Input**: Windows network/host telemetry
- **Output**: Raw events
- **Authority**: `nose/` directory

### 2. Canonical Event (NORMALIZE)
- **Language**: Zig
- **Input**: Raw events from Nose
- **Output**: Immutable CanonicalEvent
- **Authority**: `core/canonical_event.zig`
- **Rule**: Immutable after observation

### 3. Event Fabric (SCHEDULE)
- **Language**: Zig
- **Input**: CanonicalEvent
- **Output**: PrioritizedEvent (queue with backpressure)
- **Authority**: `core/event_fabric.zig`
- **States**: accepted, processed, source_dropped, queue_dropped, rejected, expired

### 4. Flow / State (STATE)
- **Language**: Zig
- **Input**: CanonicalEvent
- **Output**: FlowUpdate (FlowKey -> hash -> bucket -> FlowState)
- **Authority**: `core/flow_engine.zig`
- **Rule**: Atomic upsert, no mutable pointer after lock release, return snapshot

### 5. Detection (DETECT)
- **Language**: Zig
- **Input**: CanonicalEvent + Context
- **Output**: DetectionEvidence
- **Authority**: `core/detection_engine.zig`
- **Rule**: Evidence producer ONLY. Cannot call PEP. Cannot decide enforcement.

### 6. Verdict (DETECT)
- **Language**: Zig (with Brain advisory)
- **Input**: DetectionEvidence[]
- **Output**: AggregatedVerdict (6 states: benign/observe/suspicious/malicious/unknown/error)
- **Authority**: `core/verdict_aggregator.zig`
- **Rule**: UNKNOWN != BENIGN, ERROR != BENIGN

### 7. Correlation (CORRELATE)
- **Language**: Zig
- **Input**: Verdict + Flow + Entities
- **Output**: CorrelationAlert (entity graph)
- **Authority**: `core/correlation_engine.zig`
- **Entities**: Host, User, Process, File, Flow, Session, IP, Domain, Pipe (9 types)
- **Relationships**: Host->Process, Process->File, Process->Flow, Flow->IP, Process->User

### 8. Intelligence (INTELLIGENCE)
- **Language**: Zig (Threat Intel) + Python (Brain/RAG)
- **Input**: Event + Verdict + Correlation
- **Output**: ThreatIntelMatch + BrainAdvice + RAG context
- **Authority**: `core/threat_intel.zig`, `brain/`
- **Rule**: RAG enriches. RAG must NOT authorize enforcement.

### 9. Policy (DECIDE)
- **Language**: Zig
- **Input**: Event + Verdict + Alerts + TI + Advice
- **Output**: EnforcementDecision
- **Authority**: `core/policy_engine.zig`
- **Rule**: Decides, does NOT execute. Produces EnforcementPlan for Rust PEP.

### 10. Rust PEP (ENFORCE)
- **Language**: Rust
- **Input**: EnforcementPlan (validated: policy, version, signature, target, action, authorization, expiry)
- **Output**: EnforcementResult (7 statuses)
- **Authority**: `shield/` (Rust)
- **Rule**: Final enforcement authority. No bypass.

### 11. Forensics (REMEMBER)
- **Language**: Zig
- **Input**: All pipeline results (event, flow, evidence, verdict, correlation, TI, brain, policy, PEP, action)
- **Output**: ForensicRecord (immutable, hash-chained)
- **Authority**: `core/forensics_engine.zig`, `core/forensic_log.zig`
- **Versions**: schema, ruleset, detector, brain, intel, policy

### 12. Replay (REMEMBER)
- **Language**: Zig
- **Input**: Historical ForensicRecord + ruleset v1 + policy v1
- **Output**: ReplayResult (deterministic comparison)
- **Authority**: `core/replay_engine.zig`
- **Rule**: Same event + same versions = same result (deterministic)

---

## Priority Queue Model

Keep the priority model small:
- HIGH
- NORMAL
- LOW

Do not add many priority classes. Only introduce aging/weighted fairness after a starvation test demonstrates the need.

---

## Event Fabric States

```
accepted     -> event entered fabric
processed    -> event completed pipeline
source_dropped -> Nose dropped (intentional sampling)
queue_dropped  -> Fabric dropped (congestion)
rejected     -> validation failed
expired      -> timeout
```

**Sampling vs Queue overflow** (conceptually separate):
- NOSE = intentional sampling
- FABRIC = congestion handling

---

## Completion Criterion

The runtime spine is complete when:

```
ONE EVENT
  -> ONE CANONICAL MODEL
  -> ONE RUNTIME SPINE
  -> ONE STATE AUTHORITY
  -> ONE EVIDENCE MODEL
  -> ONE DECISION AUTHORITY
  -> ONE ENFORCEMENT AUTHORITY
  -> ONE FORENSIC TRACE
  -> ONE REPLAY PATH
```
