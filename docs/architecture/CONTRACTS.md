# Contracts

**Status**: AUTHORITATIVE
**Source**: `docs/architecture/ARCHITECTURE_CANONICAL.md` Section 6

---

## Contract Authority

Each contract has exactly **one** authoritative definition. No duplicates allowed.

---

## 1. CanonicalEvent

**Authority**: `core/canonical_event.zig`
**Position**: NORMALIZE
**Rule**: Immutable after observation

**Fields**:
- event_id (u64)
- timestamp (epoch_ms + monotonic_ns)
- source (sensor ID)
- src_ip, dst_ip, src_port, dst_port, protocol
- rule_id, severity, event_type
- session_id, payload_preview

**Forbidden**: Do not add decision state directly into the original event.

---

## 2. Wire/ABI

**Authority**: `core/wire_event.zig`
**Position**: TRANSPORT

**Requirements**:
- Fixed width
- Explicit endian
- Bounded length
- Version field
- Checksum
- No pointers
- No raw memory dump

**Rule**: Cross-language vectors are treated as contract tests (validated in CI).

---

## 3. DetectionEvidence

**Authority**: `core/detection_engine.zig`
**Position**: DETECT

**Fields**:
- detector_id
- rule_id
- verdict (6-state)
- confidence (0-100)
- description
- event_id (correlation)

**Rule**: Evidence producer ONLY. Detectors cannot call PEP. Detectors cannot decide enforcement.

---

## 4. AggregatedVerdict

**Authority**: `core/verdict_aggregator.zig`
**Position**: DETECT

**States** (6):
- BENIGN
- OBSERVE
- SUSPICIOUS
- MALICIOUS
- UNKNOWN
- ERROR

**Rule**: Do NOT equate UNKNOWN = BENIGN or ERROR = BENIGN.

---

## 5. CorrelationResult

**Authority**: `core/correlation_engine.zig`
**Position**: CORRELATE

**Entities** (9 types, LOCKED schema):
- Host
- User
- Process
- File
- Flow
- Session
- IP
- Domain
- Pipe

**Relationships** (8):
- Host -> Process
- Process -> File
- Process -> Flow
- Flow -> IP
- Process -> User
- Process -> Session
- Flow -> Session
- IP -> Domain

**Incident**: entities[] + events[] + evidence[] + attack_chain[] + time + relationships

---

## 6. ThreatContext

**Authority**: `core/threat_intel.zig`
**Position**: INTELLIGENCE

**Sources** (operational):
- IOC IP
- IOC Domain
- IOC Hash
- Reputation

**Rule**: Operational threat intel. Provenance tracked.

---

## 7. BrainAdvice

**Authority**: `core/brain_engine.zig` (Zig) + `brain/` (Python)
**Position**: INTELLIGENCE

**Fields** (advisory only):
- kind (keep/escalate/deescalate/insufficient_data)
- threat_score (0-100)
- recommended_verdict
- original_verdict
- confidence (0-100)
- explanation
- signal_detection, signal_correlation, signal_threat_intel, signal_flow_anomaly
- event_id

**Forbidden**: Brain must NOT execute block/quarantine/kill-process.

**Fail-soft**: When Brain is down, returns insufficient_data (system continues).

---

## 8. PolicyDecision

**Authority**: `core/policy_engine.zig`
**Position**: DECIDE

**Fields**:
- action (allow/alert/block/rate_limit/quarantine/log_only)
- rule (rule ID)
- confidence
- reason
- event_id
- brain_recommended_verdict
- original_verdict
- threat_score

**Rule**: Policy decides, does NOT execute. Produces EnforcementPlan for Rust PEP.

---

## 9. EnforcementPlan

**Authority**: `core/policy_engine.zig` -> Rust
**Position**: DECIDE -> ENFORCE

**Validated by Rust PEP before execution**:
- policy
- version
- signature
- target
- action
- authorization
- expiry

---

## 10. EnforcementResult

**Authority**: `core/rust_pep.zig` (Zig interface) + `shield/` (Rust impl)
**Position**: ENFORCE

**Statuses** (7, never single success flag):
- EXECUTED
- FAILED
- DENIED
- DEFERRED
- NOT_APPLICABLE
- UNSUPPORTED
- TIMEOUT

**Fields**:
- status
- reason
- requested_action
- actual_action
- blocked_ip
- event_id
- message

---

## 11. ForensicRecord

**Authority**: `core/forensics_engine.zig`
**Position**: REMEMBER

**Records entire decision trace**:
- source
- event
- flow
- evidence
- verdict
- correlation
- threat_intel
- brain
- policy
- decision
- pep
- action
- result

**Versions** (recorded per event):
- schema_version
- ruleset_version
- detector_version
- brain_version
- intel_version
- policy_version

**Rule**: Immutable, hash-chained, append-only. No edit/delete API.

---

## 12. AuditRecord

**Authority**: `core/audit_trail_proof.zig`
**Position**: REMEMBER

**Fields**:
- record_id (sequential)
- timestamp_ms
- action (11 types: config_reload, policy_change, manual_block_ip, etc.)
- outcome (success/failed/rejected/deferred)
- operator_id
- target
- detail
- record_hash (FNV-1a)
- prev_hash (chain of custody)

**Rule**: Tamper-evident. Hash chain verified by `verifyChain()`.

---

## Version Freeze

These versions are frozen separately and recorded per release:

| Version | Authority | Freeze Status |
|---------|-----------|---------------|
| Event Schema | `core/canonical_event.zig` | Frozen (G1) |
| Wire Protocol | `core/wire_event.zig` | Frozen (G1) |
| Policy IR | `core/policy_plane.zig` | Frozen (G9) |
| Detection Rule Set | `config/Rules.json` | Hot-reloadable (G12) |
| Policy Set | signed IR | Frozen + signed (G9) |

A code release records which versions it used (see `aegis.manifest.json`).

---

## Contract Test Vectors

Cross-language contract tests must validate:
1. Wire encoding/decoding round-trip
2. CanonicalEvent immutability
3. Evidence schema compliance
4. Verdict 6-state enum values
5. PolicyDecision -> EnforcementPlan mapping
6. EnforcementResult 7-status enum values
7. ForensicRecord schema version

These tests run in CI (Stage 7: Cross-language contract vectors).
