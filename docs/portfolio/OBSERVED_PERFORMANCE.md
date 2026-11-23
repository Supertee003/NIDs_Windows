# Observed runtime values on the lab host (honest limits)

> This is **not a controlled benchmark**. These are point-in-time values read from the live daemon
> snapshot (`GET /api/snapshot`, schema `aegis.operator.snapshot.v1`) on **2026-11-23T14:19:12Z**.
> Counters are cumulative since daemon start; they are not a fixed-rate load test. There is no
> synthetic offered-load ceiling claimed here. If you need one, run a fixed-rate harness and publish
> the environment, method, and bottleneck with it.

## Environment

| Item | Value |
|---|---|
| OS | Windows lab host, 64-bit |
| Runtime | AEGIS daemon, observe-only |
| Build source | `a53eda8` (ADR-0008 records-only model) |
| Acquisition | Go Nose on Killer Wi-Fi AX1650i, WFP in `npcap_primary` mode |
| Snapshot uptime | 63,609 s (~17 h 40 m) |
| Snapshot timestamp | 2026-11-23T14:19:12Z (epoch ms 1795443552982) |
| Release evidence | owner-run soak 36.52 / 24.0 h PASS, loss counters 0 **during that window** |

## Values actually observed

| Metric | Observed value | Source field |
|---|---|---|
| Events processed / forensic records | 12,302,739 / 12,302,739 | `metrics.events_processed`, `metrics.forensic_records` |
| Packets captured | 835,764 | `metrics.packets_captured` |
| Detections / anomalies | 5,134,401 / 136,269 | `metrics.detections`, `metrics.anomalies` |
| Active flows / rules loaded | 1,233 / 23 | `metrics.flows_active`, `metrics.rules_loaded` |
| CPU (process, sampled) | 28.68% (one core = 100%) | `health.resources.cpu_percent` |
| Private bytes / working set | 841,465,856 / 132,890,624 B | `health.resources.private_bytes`, `working_set_bytes` |
| Queue depth / peak / size | 254 / 6,028 / 16,384 | `queue.depth`, `depth_peak`, `queue_size` |
| Queue dropped / shed overload / quota shed / tail shed | 0 / 0 / 0 / 0 | `queue.*` |
| Minifilter pipeline dropped | 0 | `queue.minifilter_pipeline_dropped` |
| **Minifilter ring dropped** | **1,341,156** | `queue.minifilter.dropped` |
| `blocks` / `confirmed_blocks` / `confirmed_quarantines` | 0 / 0 / 0 | `metrics.*` |
| Alerts written / failed | 5,128,956 / **7,028** | `metrics.alert_file.*` |

Every value above came from the live API response at the timestamp shown. None of them is an
estimate or an extrapolated ceiling.

## Instrumented stage latency (from the same snapshot)

The daemon publishes per-stage counters, so capture-to-alert latency is measured rather than
guessed. Values are nanoseconds; `p50`/`p95`/`p99` are the useful figures because `mean` and `max`
are distorted by a single implausible `capture_to_decode` maximum of 51,520,002,152,200 ns
(~14.3 h), which is consistent with a boot-time clock/counter artifact rather than a real event
latency. **Do not quote that mean.**

| Stage | p50 | p95 | p99 |
|---|---:|---:|---:|
| capture_to_decode | 16,384 ns | 262,144 ns | 524,288 ns |
| decode_to_flow | 64 ns | 128 ns | 512 ns |
| flow_to_detection | 256 ns | 1,024 ns | 2,048 ns |
| detection_to_correlation | 64 ns | 256 ns | 1,024 ns |
| correlation_to_policy | 64 ns | 64 ns | 128 ns |
| policy_to_action | 64 ns | 64 ns | 128 ns |
| action_to_forensic | 16,384 ns | 16,384 ns | 32,768 ns |
| forensic_append | 16,384 ns | 16,384 ns | 32,768 ns |
| forensic_hash | 1 ns | 128 ns | 256 ns |
| receipt_issue | 1 ns | 64 ns | 64 ns |

Interpretation: in the hot path, detection/correlation/policy are sub-microsecond at p95; the
dominant cost is the forensic append (~16 µs p50). Those figures describe this host and this
counter window only.

## Important interpretation — read this before quoting any number

- The nonzero `minifilter_ring_dropped` (1,341,156) and `metrics.alert_file.failed` (7,028) are
  **real current lab-host observations**. They are reported here instead of hidden. The published
  v1.1 soak measured zero loss **during its specific 36.52 h window**; that is a different window
  and does not cancel these counters. Say: "the release soak window measured zero loss; this lab
  host currently shows ring drops and some alert-write failures that need investigation."
- Because those counters are nonzero, never claim "zero loss ever" for this host.
- `provider_ready`/`pep_ready` are capability states, not throughput or enforcement evidence.
- `wfp.kernel_owned=false`, `mode=npcap_primary` describe the current binding; kernel telemetry is
  available but is not the primary packet source on this host.
- The dashboard's `DEGRADED` badge reflects a control-pipe responder detail while subsystems
  report `RUNNING`; it is not a performance number. See [Failure matrix](../OPERATIONAL_FAILURE_MATRIX.md).

## What is deliberately not claimed

| Claim | Why it is absent |
|---|---|
| Maximum sustainable events/sec | No fixed-rate load generator was run |
| Scaling with CPU count | Single host, no comparative run |
| CPU/memory at 1k / 5k events/sec | No such test occurred |
| Production traffic validation | Lab host only |
| Zero packet loss on this host | Two loss/failure counters are nonzero here |

## How to answer in an interview

> "I publish what the runtime actually reported, not a synthetic ceiling. On the lab host at a
> snapshot taken in November 2026, the daemon had processed about 12.3 million events with 12.3
> million forensic records, zero queue drops, and a measured p95 of about 16 microseconds for the
> forensic append. It also showed 1.34 million minifilter ring drops and 7,028 failed alert writes,
> so I describe those as open limitations rather than claiming zero loss. The separate release soak
> measured zero loss over 36.5 hours. If a role needs a hard throughput ceiling, I would run a
> fixed-rate harness and report the environment and bottleneck, not just the peak number."

*See also: [Test results](../testing/RESULTS.md) · [Failure matrix](../OPERATIONAL_FAILURE_MATRIX.md)*
