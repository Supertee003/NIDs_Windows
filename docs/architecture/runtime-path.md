# AEGIS NIDs Windows -- Runtime Path

**Status:** Locked by ADR-0001  
**Date:** 2026-09-02  

## Single Production Dispatch Path

```
[Entry Point: nids_main.zig]
    |
    v
[Lifecycle: lifecycle.zig]
    |-- initializes production subsystems in order:
    |   1.  forensic_log (logging first)
    |   2.  event_fabric (queue before sensors)
    |   3.  nose_contract (validation)
    |   4.  nose_integration (sampling)
    |   5.  flow_integration (flow tracking)
    |   6.  detection_integration (evidence)
    |   7.  dispatcher.initAggregator (verdict)
    |   8.  correlation_integration (context)
    |   9.  threat_intel_integration (enrichment)
    |   10. brain_integration (advisory)
    |   11. policy_integration (decision)
    |   12. rust_pep_integration (enforcement)
    |   13. forensics_integration (trace)
    |   14. replay_integration (read-only tool)
    |   15. e2e_harness_integration (TEST - P0.5: remove from prod)
    |   16. performance_integration (TEST - P0.5: remove from prod)
    |   17. ips_canary_integration (TEST - P0.5: remove from prod)
    |   18. xdr_harden_integration (SIEM export)
    |   19. release_engineering_integration (metrics)
    |   20. rag_integration (P0.1: NOT in dispatcher!)
    |
    v
[Dispatcher: dispatcher.zig]
    |-- processEvent() calls stages in order:
    |   1. Canonical event validation
    |   2. Flow update
    |   3. Detection evidence production
    |   4. Verdict aggregation
    |   5. Correlation
    |   6. Threat intel enrichment
    |   7. (MISSING: RAG context enrichment -- P0.1)
    |   8. Brain advice
    |   9. Policy decision
    |  10. Rust PEP enforcement
    |  11. Forensics recording
    |
    v
[Shutdown: lifecycle.zig shutdown()]
    |-- reverse order of initialization
```

## P0 Issues in Current Path

### P0.1: RAG missing from dispatcher
- **Status:** rag_integration is initialized in lifecycle (step 20)
  but dispatcher.processEvent() does NOT call RAG
- **Fix:** Add RAG stage between Threat Intel (6) and Brain (8)
- **Risk:** README claims RAG is runtime; code does not match

### P0.5: Test modules in production lifecycle
- **Status:** Steps 15-17 (e2e_harness, performance, ips_canary)
  are test/proof modules initialized in production lifecycle
- **Fix:** Separate into TestProfile; production lifecycle
  initializes only steps 1-14 + 18-20

### P0.6: nids_analyze.zig competes with dispatcher
- **Status:** nids_analyze.zig (2,237 lines) is imported by
  nids_main.zig and runs its own analysis pipeline
- **Fix:** Audit what nids_analyze.zig provides that dispatcher
  does not; migrate or remove

## Pipeline Context (Target)

```zig
pub const PipelineContext = struct {
    event: CanonicalEvent,
    flow: ?FlowUpdate,
    evidence: EvidenceSet,
    verdict: VerdictAggregate,
    correlation: CorrelationContext,
    threat_intel: ThreatIntelContext,
    rag: RagContext,           // P0.1: add this
    brain: BrainAdvice,
    policy: EnforcementDecision,
    pep: EnforcementResult,
    fate: EventFate,
    trace: DecisionTrace,
};
```

## Event Fate Accounting (Phase C target)

```
input = processed + source_dropped + fabric_dropped
      + rejected + expired + failed + archived
```
