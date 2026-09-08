# T17 (Steps 46-52) — Performance Benchmark Results

Windows host (x86_64) measurements recorded for the T17 Performance AC.
Host: local Windows build of the AEGIS NIDS source tree, `zig test`
Debug for correctness gates, `-O ReleaseFast` for benchmark numbers.

## Zig — event throughput / fabric / detection / dispatcher (perf_benchmark.zig)

`zig build-exe core/perf_benchmark_cli.zig -lc -O ReleaseFast` · `perf_benchmark_cli quick`

| Suite (ops/sec, 100 iters)            | ops/sec  | us/op    | threshold |
|----------------------------------------|----------|----------|-----------|
| ProcessTracker (100 creates)           |   20,200 |   49.51  | 1,000  PASS |
| FileIntegrityStore (50 baselines)      |  145,582 |    6.87  |   500  PASS |
| RegistryWatchQueue (100 enqueues)      |  100,857 |    9.92  | 5,000  PASS |
| Federation codec (10 encode+decode)    |1,049,318 |    0.95  | 10,000 PASS |
| CrossNodeAggregator (50 reports)       |  191,058 |    5.23  | 1,000  PASS |
| Full pipeline (4 events)               |   33,573 |   29.79  |   500  PASS |

All thresholds pass (production readiness for event ingestion).

## Zig — p50/p95/p99 latency (perf_benchmark_cli latency, 200 iters)

| Suite                              | p50    | p95    | p99    |
|------------------------------------|--------|--------|--------|
| ProcessTracker (100 creates)       | 35.7us | 57.5us | 75.3us |
| FileIntegrityStore (50 baselines)  |  6.7us | 12.9us | 25.4us |
| RegistryWatchQueue (100 enqueues)  |  9.3us |  9.4us |  9.4us |
| Federation codec (10 encode+decode)|  1.0us |  1.0us |  1.1us |
| CrossNodeAggregator (50 reports)   |  5.5us | 10.8us | 23.4us |
| Full pipeline (4 events)           | 29.7us | 30.0us | 31.7us |

Latency percentiles were added in T17 (`BenchResult.latency`,
`LatencyPercentiles.compute`, `BenchConfig.collectLatency`) — until this
ticket only aggregate throughput was measured.

## Go — capture / aggregator throughput / concurrency

Go capture (`nose`) and aggregator (`go/aggregator`) ship a Go test suite
with concurrency and throughput-adjacent coverage; CI job `go-build-test`
runs `go build ./... && go test ./...`.

## Python / Cython — brain feature extraction, numeric batch

- `tests/cython/test_cython_benchmark.py` — 2 tests pass (Cython fast-scan
  + numeric batch invariants).
- Brain RAG and Windows brain latency are measured via the runtime health
  metrics (events/sec, queue depth, p-latency) aggregated by
  `scripts/aegis_metrics.py` (T15 observability).

## Rust — PEP / enforcement latency

Enforcement decisions carry `request_id` + policy version and are the sole
enforcement path (T16); per-decision latency is recorded in the PEP trace.

## C++ — ETW / FIM registry latency

Native helper build in `c-native-build`; ETW/FIM observation timestamps
surface through host telemetry (`core/host_telemetry.zig`).

## TypeScript — policy compile/sim/control

`ts_policy` suite (`npm run test:all` in CI job `ts-policy-build`)
exercises compiler + seal signing + cross-language contract.

## Cross-language metrics envelope (per AC list)

Events/sec, latency p50/p95/p99, CPU, memory, queue depth and drop rate all
have a declared home:
- events/sec + queue depth + drop rate: `core/performance_harness.zig`,
  `core/performance_integration.zig` (20 tests)
- p50/p95/p99: `perf_benchmark.zig` latency mode (above)
- CPU/memory/queue/latency snapshot: `scripts/aegis_metrics.py` (T15)
- tuning authority: `core/performance_tuning_proof.zig` (33 tests)