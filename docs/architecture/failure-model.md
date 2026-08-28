# AEGIS NIDS — Failure Model (Rewrite v3.0)

## Failure Layers (8 layers, each with explicit handling)

### Layer 1: Sensor Failure
```
WFP driver not loaded
  → fabric.submitEvent returns false
  → sensor logs warning, continues trying
  → system runs in NIDS-only mode (no IPS)
```

### Layer 2: Nose Validation Failure
```
Event with wrong magic/version
  → nose.submit returns .rejected
  → event dropped, never enters fabric
  → rejection counter incremented
```

### Layer 3: Event Fabric Overflow
```
Queue full (saturated)
  → nose.submit returns .dropped_at_source (for LOW priority)
  → or .dropped_by_fabric (for HIGH priority after backoff)
  → pressure level reported to sensors
  → sensors can reduce sampling rate
```

### Layer 4: Detection Error
```
Detector panics or returns error
  → DetectionResult.errorResult() returned
  → fail-open: treated as no_match (not block)
  → error counter incremented
  → detector can be marked inactive
```

### Layer 5: Correlation Failure
```
XDR correlator table full (256 incidents)
  → submitEvent returns null (table full)
  → event still processed, just not correlated
  → system continues without correlation
```

### Layer 6: Policy/PEP Failure
```
WFP IOCTL fails (device not open)
  → PEP.enforce returns .failed
  → event marked enforcement_status=2 (failed)
  → policy decision still recorded in forensics
  → system runs in detection-only mode (no enforcement)
```

### Layer 7: Forensics Failure
```
Disk full / write error
  → forensic_log.log silently drops (no crash)
  → in-memory ring buffer still works
  → system continues with degraded forensics
```

### Layer 8: Cross-Language Failure
```
Python Brain unreachable (UDP timeout)
  → brain detector returns no_match
  → DEFCON stays at previous level
  → system continues without brain intelligence

Rust Shield unavailable (FFI link error)
  → shield detector returns no_match
  → system continues without behavioral analysis

Go Aggregator down (REST API fails)
  → alerts not aggregated
  → forensics log still written
  → system continues without alert aggregation
```

## Fault Injection States

| Fault | System State | Detection | Result |
|-------|-------------|-----------|--------|
| WFP down | DEGRADED | IOCTL returns false | NIDS-only mode |
| Driver down | DEGRADED | Device handle null | No kernel events |
| Queue full | RUNNING | Pressure = saturated | Source sampling active |
| Brain down | DEGRADED | UDP timeout | No brain intelligence |
| RAG down | DEGRADED | Lookup returns no match | No threat enrichment |
| Policy invalid | DEGRADED | Validation fails | Default action (allow) |
| IPC broken | DEGRADED | FFI call fails | Stub fallback |
| Rust shield down | DEGRADED | FFI link fails | No behavioral analysis |
| Disk full | DEGRADED | Write fails | Ring buffer only |
| Forensic logger down | DEGRADED | Log call fails | In-memory only |

## Fail-Open vs Fail-Closed

### Fail-Open (traffic continues)
- Detection error → no_match (not block)
- Brain unreachable → no brain input
- RAG down → no threat enrichment
- Correlation full → no correlation
- Forensics full → ring buffer only

### Fail-Closed (traffic blocked)
- DEFCON 1 → block all matches
- Policy rule: severity >= 3 + match_block → BLOCK
- APT threat intel match → severity escalation → BLOCK

### Principle
> Detection errors fail-open (better to miss than to false-positive block)
> Policy decisions fail-closed (when threat is confirmed, block)
> PEP enforcement failure is logged, not retried (don't block forever on broken WFP)

## Graceful Shutdown

```
1. Stop accepting new events (sensors stop)
2. Drain queue (process remaining events)
3. Flush forensics (write pending NDJSON)
4. Close file handles
5. Free memory
6. Exit clean (exit code 0)
```

### Timeout
- Drain timeout: 30 seconds
- If drain doesn't complete → force flush + exit (exit code 1)
