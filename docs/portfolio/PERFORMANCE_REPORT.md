# Performance report — method, observed values, and what is not measured

> Scope: build source `4dd3393`. AEGIS-PLAN-012.
> This is a **methodology and status page**. It does not report a new benchmark
> run. All numbers below are recorded observations from existing artifacts.

## 1. What exists

| Artifact | Content | Level |
|---|---|---|
| `docs/portfolio/OBSERVED_PERFORMANCE.md` | Point-in-time snapshot from the live daemon at `2026-11-23T14:19:12Z`, build source `a53eda8`: 63,609 s uptime, ~12.3 M cumulative events, zero loss/shed counters in the recorded soak window | Recorded observation, **not a controlled benchmark** |
| `docs/DEPLOYMENT.md`, `docs/runtime/TOOLCHAIN_INVENTORY.md` | Toolchain and build matrix | E1 |
| Historical soak record `SOAK-PASS-466A226-20261122` | 36.52 / 24.0 h PASS, `problems=[]`, zero loss/shed counters in that window | E5 at release identity, HISTORICAL at `4dd3393` |

The observed page states its own limits: counters are cumulative since daemon
start, there is no synthetic offered-load ceiling, and no fixed-rate load test
is claimed.

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
