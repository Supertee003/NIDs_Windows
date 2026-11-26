# Performance report — method, observed values, and what is not measured

> Scope: build source `4dd3393` (HISTORICAL at current source `aa3b7b0`). AEGIS-PLAN-012.
> This is a **methodology and status page** plus one real E2 microbenchmark run
> (section 1a). It is **not** a controlled fixed-rate network benchmark and
> promotes nothing to E5/E6/E7.

## 1. What exists

| Artifact | Content | Level |
|---|---|---|
| `docs/portfolio/OBSERVED_PERFORMANCE.md` | Point-in-time snapshot from the live daemon at `2026-11-23T14:19:12Z`, build source `a53eda8`: 63,609 s uptime, ~12.3 M cumulative events, zero loss/shed counters in the recorded soak window | Recorded observation, **not a controlled benchmark** |
| `docs/DEPLOYMENT.md`, `docs/runtime/TOOLCHAIN_INVENTORY.md` | Toolchain and build matrix | E1 |
| Historical soak record `SOAK-PASS-466A226-20261122` | 36.52 / 24.0 h PASS, `problems=[]`, zero loss/shed counters in that window | E5 at release identity, HISTORICAL at `4dd3393` |

The observed page states its own limits: counters are cumulative since daemon
start, there is no synthetic offered-load ceiling, and no fixed-rate load test
is claimed.

## 1a. Zig microbenchmark actually run at `4dd3393`

| Item | Value |
|---|---|
| Command | `zig build core-tools -Doptimize=ReleaseFast --cache-dir D:\aegis-tmp\plan_zig_cache --global-cache-dir D:\aegis-tmp\plan_zig_global`, then `zig-out\bin\aegis_perf_bench.exe quick` and `... latency` |
| Binary SHA-256 | `8829E03D841FF3F4BE12223226EBCD7FDE9313DF8D2F245FFE15703BD182A476` |
| Harness | `src/perf_bench_main.zig` → `src/core/perf_benchmark.zig`, config `configs/test/perf_benchmark_config.json` |
| Modes | `quick`: warmup 10, 100 iterations; `latency`: warmup 10, 200 iterations |
| Result | all 6 declared thresholds PASS in `quick`; exit 0 in both modes |

`quick` (ops/sec, 100 iters) — **current source**, distinct from the older
`docs/gates/T17_benchmark_results.md` values:

| Suite | ops/sec | us/op | threshold |
|---|---:|---:|---:|
| ProcessTracker (100 creates) | 23,587 | 42.40 | 1,000 PASS |
| FileIntegrityStore (50 baselines + observes) | 64,637 | 15.47 | 500 PASS |
| RegistryWatchQueue (100 enqueues) | 83,591 | 11.96 | 5,000 PASS |
| Federation codec (10 encode+decode) | 1,172,333 | 0.85 (223.6 MB/s) | 10,000 PASS |
| CrossNodeAggregator (50 reports) | 191,278 | 5.23 | 1,000 PASS |
| Full pipeline (4 events → incidents) | 42,123 | 23.74 | 500 PASS |

`latency` (200 iters):

| Suite | p50 | p95 | p99 |
|---|---:|---:|---:|
| ProcessTracker | 40.8us | 57.1us | 72.4us |
| FileIntegrityStore | 16.5us | 27.1us | 34.6us |
| RegistryWatchQueue | 13.1us | 19.0us | 31.4us |
| Federation codec | 1.0us | 1.0us | 1.0us |
| CrossNodeAggregator | 7.9us | 17.0us | 27.8us |
| Full pipeline | 24.0us | 28.4us | 35.6us |

**Level and limits:** this is an **E2 in-process microbenchmark** of Zig data
structures and the codec. It is not a packet-rate test, not Nose/queue/daemon
integration, not run on an isolated lab host, and does not establish a host
throughput ceiling. No network load generator, no offered-rate control, and no
negative control were part of this run. It does not change the fixed-rate row
in section 3.

## 2. Required method for a real controlled report

A future report that claims a throughput ceiling must publish all of:

1. **Build identity** — source commit, compiler versions, ReleaseSafe/ReleaseFast
   mode, candidate SHA-256, installed binary SHA-256.
2. **Host** — CPU, RAM, NIC/adapter, OS build, WFP mode, ring size, queue reserve.
3. **Load generator** — fixed rate, packet size mix, protocol mix, duration,
   source/destination isolation, and the exact command line.
4. **Measurement** — interval, sampling cadence, counters used, and how
   ring drops, pipeline drops, queue drops, and rejected frames are separated.
5. **Bottleneck** — which stage saturated first and the evidence for it.
6. **Result table** — offered rate, accepted rate, drop rate, p50/p95/p99
   latency, and the raw transcript SHA-256.
7. **Negative controls** — no traffic and no daemon runs with the same harness.

## 3. Current status

| Claim | Status at `4dd3393` |
|---|---|
| Controlled fixed-rate benchmark at current source | **NOT RUN** |
| 7M+ events synthetic ceiling | **NOT CLAIMED** |
| Historical 36.52 h soak | PASS at `a53eda8`, HISTORICAL |
| Observed cumulative counters | Recorded at `a53eda8`, not a current-source measurement |

No number in this page is promoted to E6/E7. Production remains observe-only.

## 4. Owner actions

Run a fixed-rate harness on the isolated lab host using the owner-run runbook,
then add an E5/E6 evidence entry with the raw transcript locator. Until then,
this page is the honest status source for AEGIS-PLAN-012.

---

See also: [`OBSERVED_PERFORMANCE.md`](OBSERVED_PERFORMANCE.md),
[`VERIFICATION_SUMMARY.md`](VERIFICATION_SUMMARY.md),
[`../evidence/PROVENANCE.md`](../evidence/PROVENANCE.md).
