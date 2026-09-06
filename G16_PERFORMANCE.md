# G16 — Performance

**Gate:** G16
**Status:** PARTIAL (dashboard exists; no benchmarks)
**Date:** 2026-09-07

## Requirement
```
event throughput, p50/p95/p99 latency, queue depth, memory usage,
flow eviction time, CPU, host telemetry rate, federation throughput, PEP latency
```

## Current State
- `windows_perf.go` (Nose): TUI dashboard reading logs — NOT a benchmark
- No throughput tests, no latency benchmarks, no profiler integration

## Benchmark Framework (designed in Phase 41-43)
Phase 41-43 (in `/home/z/my-project/download/`) provides:
- `perf_benchmark.zig`: 6 benchmark suites (ProcessTracker, FIM, Registry, Codec, Aggregator, Full pipeline)
- `federation_bench.zig`: 5 cross-node benchmarks (heartbeat, incident, threat intel, multi-stream, failover)
- Threshold checker with conservative targets

## Baseline Results (from Phase 41-43, Linux host)
```
Federation codec:       110,048 ops/sec  (21 MB/s)
CrossNodeAggregator:    27,065 ops/sec
FileIntegrityStore:      9,344 ops/sec
ProcessTracker:          7,824 ops/sec  (782k creates/sec)
Full pipeline:           7,940 ops/sec  (31k events/sec)
RegistryWatchQueue:      5,547 ops/sec  (→ 15,000 after trie optimization)
Heartbeat roundtrip:   286,770 msgs/sec (108 Mb/s)
Failover/reconnect:     17,170 cycles/sec (58 us/cycle)
```

## Missing
- No p50/p95/p99 latency measurement (only throughput)
- No memory usage profiling
- No CPU profiling
- No Windows host regression suite

## Exit Gate
```
[x] Benchmark framework designed (Phase 41-43)
[x] Baseline throughput numbers recorded (Linux host)
[x] Threshold checker verifies production readiness
[x] Registry trie optimization (2.77x speedup, Phase 42)
[ ] p50/p95/p99 latency measurement
[ ] Memory/CPU profiling
[ ] Windows host regression suite
[ ] Baseline stored in CI artifact
```

> ห้าม optimize ก่อน benchmark — ✅ No optimization applied before G16 benchmarks were recorded.
