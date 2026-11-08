# QLOSS-E5-STEADY-WINDOW-20261109

**Flow:** QLOSS-HEALTH-001 (ETW/FIM ingress -> bounded queue -> pipeline -> minifilter ring)  
**Runtime evidence:** Windows service runtime, read-only `queue.stats` snapshots 15 seconds apart  
**Build source:** `795246d7b4794b11c9b45e0b17a43c6cb219602a`  
**Evidence:** E5, limited to the observed window

## Result

- Queue depth: 271 -> 11; peak since service start: 9,234 / 16,384.
- 186,815 events were admitted during the 15-second interval (~12,454/s): ETW 106,781, FIM 79,808, Npcap 213, registry 12, host-net 1, WFP 0.
- Admission drops did not increase in this interval: all per-source drop deltas 0; `source_quota_shed` remained 25,649.
- Minifilter ring drops remained 10,906 and minifilter pipeline drops remained 1,277; no new loss accrued in this window.
- `forensic_append` p95 was 32,768 ns in the endpoint snapshot.

Raw snapshots and computed deltas are in `admin-evidence/qloss-steady-window-20261109/` (`before.json`, `after.json`, `summary.json`).

## Interpretation and limits

The consumer drained the small starting backlog while processing a high event rate, and no loss counters advanced in this sample. A separate adjacent 15-second sample earlier in this session recorded +1,247 ETW drops. These observations demonstrate burst-sensitive behavior, not a stable no-loss guarantee. The cumulative historic minifilter/queue loss remains visible and health remains degraded. No attacker canary, forced workload, event coalescing, or VM configuration change was performed. Issue #29 remains open.

**Next gate:** Capture multiple representative windows including an agreed workload, characterize burst arrivals/queue occupancy and per-source loss, then select a bounded admission or consumer-throughput change. Do not coalesce minifilter events until the producer identity contract passes its stop-line.
