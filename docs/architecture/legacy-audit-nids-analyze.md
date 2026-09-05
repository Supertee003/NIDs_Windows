# Phase B: Legacy Audit Report -- nids_analyze.zig vs dispatcher.zig

**Date:** 2026-09-02  
**Auditor:** Phase B  
**Status:** PENDING MIGRATION

## Summary

| Module | Lines | Role | Runtime Used? |
|---|---|---|---|
| dispatcher.zig | 404 (563 after Phase B) | Production orchestrator | YES (via lifecycle.zig) |
| nids_analyze.zig | 2,237 | Legacy analysis engine | YES (via nids_main.zig T1 thread) |

## Conflict Analysis

### What nids_analyze.zig provides:

1. **TCP listener** (port 12345) -- accepts TCP sensor events
2. **Named pipe listener** (`\\.\pipe\aegis_nids`) -- accepts pipe sensor events
3. **Aho-Corasick pattern matching** -- Tier-1 fast detection
4. **Rule loading** -- loads Rules.json and compiles patterns
5. **Rate limiting** -- per-IP connection rate limiting
6. **Defense logging** -- security configuration output
7. **Status reporter** -- bridge status reporting
8. **CTRL+C handler** -- signal handling

### What dispatcher.zig provides:

1. **Pipeline orchestration** -- Flow -> Detection -> Verdict -> Correlation
   -> Threat Intel -> RAG (Phase B) -> Brain -> Policy -> PEP -> Forensics
2. **Event Fabric integration** -- pops events from priority queue
3. **Verdict aggregation** -- multi-detector evidence aggregation
4. **Accounting** -- EventFate + PipelineStats (Phase B)

### Overlap

| Concern | nids_analyze.zig | dispatcher.zig | Resolution |
|---|---|---|---|
| Pattern matching | Yes (Aho-Corasick) | No (via detection_engine) | Migrate to detection_engine |
| Rule loading | Yes (reload_rules_atomic) | No | Move to detection_engine |
| TCP listener | Yes (tcp_listener) | No | Move to nose/ sensor |
| Pipe listener | Yes (pipe_listener) | No | Move to nose/ sensor |
| Rate limiting | Yes (checkIpRateLimit) | No | Move to flow_engine |
| Status reporter | Yes (bridgeStatusReporter) | No | Move to health_monitoring |
| Pipeline | No | Yes | dispatcher wins |

## Migration Plan (P0.6)

### Step 1: Move sensor listeners out of nids_analyze
- TCP listener -> nose/ (Go) or new core/sensor_tcp.zig
- Pipe listener -> nose/ (Go) or new core/sensor_pipe.zig

### Step 2: Move rule loading to detection_engine
- `reload_rules_atomic()` -> `detection_engine.reloadRules()`

### Step 3: Move rate limiting to flow_engine
- `checkIpRateLimit()` -> `flow_engine.checkRateLimit()`

### Step 4: Move status reporter to health_monitoring
- `bridgeStatusReporter()` -> health pipe server (already done in G35)

### Step 5: Remove nids_analyze.zig
- After all functionality is migrated, delete the file
- Update nids_main.zig to not spawn T1 thread

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| TCP/pipe listeners break | Medium | High | Test before removing |
| Rule loading changes | Low | Medium | detection_engine already has rules |
| Rate limiting regression | Medium | Medium | Benchmark before/after |
| Missing functionality | Low | High | Full audit before removal |

## Recommendation

**Do NOT remove nids_analyze.zig in Phase B.** Instead:

1. Mark it as `core/legacy/nids_analyze.zig` (or keep in place)
2. Add deprecation comment at top of file
3. Create migration tasks for each piece of functionality
4. Remove only after all consumers are migrated and tested

This follows the master plan rule: "Do not big rewrite before baseline."
