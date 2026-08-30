# RB-007: Performance Tuning (Queue Depth + Batching)

## Objective
Tune AEGIS NIDS performance by adjusting thread pool size, queue capacity, and batching parameters. This runbook covers diagnosing performance issues and applying tuning changes.

## Prerequisites
- AEGIS NIDS running with performance monitoring enabled
- Access to performance metrics (EPS, p99 latency, queue depth)
- Operator access to configuration

## Steps

1. **Capture current performance baseline**
   ```
   metrics = MetricsSnapshot{
       .total_events = ...,
       .queue_depth = ...,
       .max_queue_depth = ...,
       .latency_samples_us = ...,
   }
   eps = metrics.epsRate(window_start_ms)
   p99 = metrics.p99LatencyUs()
   ```
   - Record: current EPS, p99 latency, queue fill %
   - Identify the performance issue:
     - Low EPS (< expected throughput)
     - High p99 latency (> 10ms)
     - Queue nearly full (> 80%)

2. **Diagnose the bottleneck**
   - **Queue full (backpressure critical)**:
     - Detection/policy/PEP too slow
     - Need: larger queue OR faster processing OR more workers
   - **High latency (p99 > 10ms)**:
     - Batch timeout too long
     - Need: smaller batch timeout OR smaller batch size
   - **Low throughput (EPS low)**:
     - Batch size too small (too many flushes)
     - Need: larger batch size OR longer timeout

3. **Adjust thread pool (if CPU-bound)**
   ```
   config = ThreadPoolConfig{
       .worker_count = 8,  # increase from default 4
       .work_stealing = true,
       .stack_size = 64 * 1024,
   }
   validatePoolConfig(config)  # must return true
   ```
   - Default: 4 workers
   - Max: 32 workers (MAX_WORKER_COUNT)
   - Min stack: 4KB
   - Work-stealing: always enable (balances load)

4. **Adjust queue capacity (if memory available)**
   ```
   queue = BoundedQueue.init(2048)  # increase from default 1024
   ```
   - Default: 1024 capacity
   - Max: 65536 (MAX_QUEUE_CAPACITY)
   - Backpressure levels: normal (<50%), elevated (50-80%), high (80-95%), critical (>95%)
   - At "high": start dropping low-priority events
   - At "critical": reject new events

5. **Adjust batch size and timeout (throughput vs latency tradeoff)**
   ```
   batcher = Batcher.init(128, 5)  # batch_size=128, timeout=5ms
   ```
   - Default batch size: 64 (DEFAULT_BATCH_SIZE)
   - Max batch size: 256 (MAX_BATCH_SIZE)
   - Default timeout: 10ms (DEFAULT_BATCH_TIMEOUT_MS)
   - Larger batch = higher throughput, higher latency
   - Smaller timeout = lower latency, more flushes

6. **Apply changes (hot reload where possible)**
   - Thread pool: requires restart (cannot change worker count at runtime)
   - Queue capacity: requires restart (bounded queue size is fixed at init)
   - Batch size/timeout: can be hot-reloaded via config

7. **Verify performance improvement**
   - Capture new metrics after changes
   - Compare: EPS, p99 latency, queue fill %
   - Verify DEFCON level improved (e.g., guarded -> normal)

8. **Record changes in audit trail**
   - Audit trail records: action=config_reload, detail="performance tuning"
   - Include before/after metrics in the detail field

## Verification
- EPS increased (or maintained at expected level)
- p99 latency < 10ms (bounded by batch timeout)
- Queue fill % < 80% (backpressure not elevated+)
- DEFCON level: 5 (normal) or 4 (guarded at worst)
- No events dropped (total_dropped == 0)

## Rollback
If tuning makes performance worse:
1. Revert to previous configuration
2. Restart the system (for thread pool/queue changes)
3. Verify metrics return to baseline
4. Consider alternative tuning parameters

## Notes
- Thread pool: 4 workers (default), 32 max, work-stealing enabled
- Queue: 1024 capacity (default), 65536 max, 4 backpressure levels
- Batcher: 64 events/batch (default), 10ms timeout (default)
- p99 latency bounded by batch timeout (worst case: wait for timeout + processing)
- Backpressure prevents OOM (count never exceeds capacity)

## References
- G18: `core/performance_tuning_proof.zig` - Performance tuning proof
- G13: `core/health_monitoring_proof.zig` - Health monitoring (DEFCON rollup)
- G12: `core/config_reload_proof.zig` - Config reload (hot reload batcher params)
