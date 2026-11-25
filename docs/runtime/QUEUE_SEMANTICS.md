# Queue semantics — drop, backpressure, and what the counters actually mean

> Scope: production observe-only runtime at build source `4dd3393`.
> This is a **mapping document** for AEGIS-PLAN-007. It does not change a queue,
> add a blocking producer, or claim a new host measurement.
> Source of truth: `src/control/state_machine.zig`, `docs/runtime/RUNTIME_CONTRACT.md`,
> `docs/runtime/HEALTH_MODEL.md`, and ADR-0010 / ADR-0012 / ADR-0014.

## 1. Behavior as implemented

The pipeline queue is **bounded and lossy**, not blocking. When the queue is
full the producer sheds and increments a counter; it does **not** block the
host telemetry source and wait for the consumer. This is a deliberate design
decision recorded in ADR-0010 (fairness between host sensors) and ADR-0012
(FIM ingress volume). No silent loss is permitted: every shed is visible in
the health snapshot.

| Observable | Where it is emitted | Meaning |
|---|---|---|
| `data_integrity.queue_dropped_total` | `src/control/state_machine.zig:468-469` | Total pipeline queue drops since process start |
| `data_integrity.shed_overload` | `:480-481` | Explicit overload shedding; proof that shedding is counted rather than hidden |
| `data_integrity.loss_budget` | `:480` | Configured/observed loss budget envelope |
| `data_integrity.minifilter_ring_dropped` | `:478` | Kernel ring loss before the pipeline |
| `data_integrity.minifilter_pipeline_dropped` | `:479` | Minifilter-to-pipeline loss |
| `data_integrity.nose_frames_rejected` | `:470` | Rejected frames (malformed/shape/capacity) |
| `data_integrity.nose_frames_dropped{,_framing,_midframe,_shape,_capacity}` | `:470-475` | Total plus diagnostic subsets; subsets are never summed by the soak gate (`:460-462`) |
| `counters.dropped` | `RUNTIME_CONTRACT.md:166-167` | Health soft/hard failure rule input |
| `queue.stats` depth and reserve boundary | operator snapshot | Queue depth against configured reserve |

## 2. Drop vs backpressure — the distinction that matters

- **Drop / shed:** implemented and counted. Bounded queue; the producer sheds
  and the counter grows. This is the current production behavior.
- **Blocking-producer backpressure:** **not implemented.** There is no path
  where a full downstream queue blocks the kernel-ring reader or the Nose pipe
  reader and propagates a stop signal upstream. Any document that calls the
  current behavior "backpressure" means *counted shedding*, not flow control.
- **Silent loss:** forbidden. A drop with no counter increment is a stop-the-line
  condition under `AGENTS.md` and must be filed as an issue, not worked around.

## 3. Why the design is lossy (recorded decisions)

1. ADR-0010 proved one host sensor cannot be allowed to blind another under a
   storm; fairness is preferred to a single blocking lane.
2. ADR-0012 measured the FIM ingress lane and rejected coalescing at E5 — the
   lane was not duplicate delivery, so "compress it" was the wrong lever.
3. ADR-0014 isolated the ETW `NameDelete` lane at ingress after a census showed
   it dominated the queue. The fix was admission filtering, not blocking.
4. The 4 MiB kernel ring change is recorded in `EVIDENCE_INDEX.json`: after it,
   a 180 s elevated window drained 178,499 rows with ring drops 0, pipeline
   drops 0, and queue drops 0. That is a **historical window**, not a guarantee
   at `4dd3393`.

## 4. Evidence level

| Claim | Level at `4dd3393` |
|---|---|
| Counters exist and are emitted in health JSON | E1 (source mapping), E2 via `tests/runtime/test_health.py` |
| Queue is bounded and sheds rather than blocks | E1 (source + ADR record) |
| Zero-loss behavior over a specified interval | **Not measured at `4dd3393`**; historical soak at release identity only |
| Blocking-producer backpressure | **Not implemented** |

## 5. Open work / owner actions

- Run the owner-run soak in
  `analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md` and record
  ring/queue/drop counters with the exact source commit and interval.
- If blocking backpressure is ever wanted, it is a new source slice with ABI,
  authority, and state impact; it must not be introduced by editing this page.

---

See also: [`HEALTH_MODEL.md`](HEALTH_MODEL.md),
[`COMPONENT_MATRIX.md`](COMPONENT_MATRIX.md),
[`../adr/0010-host-telemetry-admission.md`](../adr/0010-host-telemetry-admission.md),
[`../adr/0012-fim-ingress-volume.md`](../adr/0012-fim-ingress-volume.md),
[`../adr/0014-q-loss-ingress-isolation.md`](../adr/0014-q-loss-ingress-isolation.md).
