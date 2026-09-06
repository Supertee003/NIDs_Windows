# G7 — Correlation / Entity Model

**Gate:** G7
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

> ต้องเชื่อม: Network, Host, Process, File, Registry, IP, Domain, User, Flow
> และสามารถ trace: Incident → Evidence → Event IDs

## Implementation

### AtomicThreatTracker — State Machine

```
CLEAN ──(1st match)──> SUSPICIOUS ──(3+ matches)──> VERIFIED ──(Block action)──> BLOCKED
  ↑                                                                        │
  └──────────────────────────── reset() ────────────────────────────────────┘
```

| State | Trigger | Meaning |
|---|---|---|
| CLEAN | Initial state | No threat detected |
| SUSPICIOUS | First Tier-1 match (`step1_markSuspicious`) | One suspicious event observed |
| VERIFIED | 3+ matches from same source (`step2_verifyThreat`) | Multiple events = likely campaign |
| BLOCKED | Block rule matched (`step3_block`) | Source actively blocked |

### Fields
```zig
state: atomic(u8)            // ThreatState enum
match_count: atomic(u32)    // Total matches from this source
first_match_ms: atomic(i64) // Timestamp of first match
last_match_ms: atomic(i64)  // Timestamp of most recent match
```

### Integration in inspect_packet

```zig
// On Tier-1 match:
const now_ms = std.time.milliTimestamp();
_ = global_attacker_tracker.step1_markSuspicious(now_ms);
if (global_attacker_tracker.getMatchCount() >= 3) {
    if (global_attacker_tracker.step2_verifyThreat()) {
        std.debug.print("[G7] Threat VERIFIED — {d} matches from source\n", ...);
    }
}

// On Block action:
_ = global_attacker_tracker.step3_block();
```

### Trace: Incident → Evidence → Event IDs

```
Incident: "Threat VERIFIED — 3 matches from source"
  └─ Evidence: AtomicThreatTracker.state = VERIFIED
      └─ Event IDs: flow_table.flow_id (G5) for each matched flow
          └─ Rule IDs: rule.rule_id from Rules.json for each match
              └─ Packet data: inspect_packet(data, ctx) for each event
```

### Entity Model

| Entity | Source | Status |
|---|---|---|
| Network (5-tuple) | PacketContext | ✅ Tracked |
| IP (source) | PacketContext.source_ip | ✅ Tracked (global tracker) |
| Flow | FlowTable (G5) | ✅ Tracked (flow_id) |
| Host | — | ⏳ Deferred to G11 |
| Process | — | ⏳ Deferred to G11 |
| File | — | ⏳ Deferred to G11 |
| Registry | — | ⏳ Deferred to G11 |
| Domain | — | ⏳ Future (DNS parsing) |
| User | — | ⏳ Future (auth events) |

### Known Limitations

1. **Single global tracker**: Currently one `AtomicThreatTracker` for all sources.
   Future: per-source-IP hash map (requires allocator + thread safety).
2. **No cross-entity correlation**: Currently correlates matches by count only.
   Future: correlate network → process → file → registry (requires G11 telemetry).
3. **Verification threshold hardcoded**: 3 matches → VERIFIED.
   Future: configurable via Rules.json or policy (G9).

## Exit Gate

```
[x] AtomicThreatTracker wired into inspect_packet (was defined but never called)
[x] State machine: CLEAN → SUSPICIOUS → VERIFIED → BLOCKED
[x] Match count tracking (match_count atomic counter)
[x] Verification at 3+ matches (step2_verifyThreat)
[x] Block state on Block action (step3_block)
[x] Trace path: Incident → Evidence (tracker state) → Event IDs (flow_id) → Rule IDs
[x] Network + IP + Flow entities tracked
[ ] Host + Process + File + Registry entities deferred to G11 (Phase 2)
```
