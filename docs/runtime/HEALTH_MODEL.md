# Runtime health model — actual fields, vocabulary mapping, and gaps

> Scope: production observe-only runtime at build source `c01e809`
> (prior `7822f4c` and `43a8bcc` scopes are HISTORICAL).
> This is a **mapping document**, not a source change. It does not rename states,
> add fields, or claim that an unimplemented field exists. Source of truth for the
> response schema is [`RUNTIME_CONTRACT.md`](RUNTIME_CONTRACT.md) §2 and §4;
> the emitted payload is built in `src/control/state_machine.zig`.

## 1. Vocabulary mapping (no code rename)

| Requested vocabulary | Production value that corresponds to it | Meaning |
|---|---|---|
| `HEALTHY` | `RUNNING` | Processing events and reporting healthy on every probe (`RUNTIME_CONTRACT.md:41`) |
| `DEGRADED` | `DEGRADED` | Alive, health check failed for at least one cycle, non-fatal (`:42`) |
| `FAILED` | `FAILED` | Exited unexpectedly or exceeded hard failure threshold (`:43`) |
| `UNKNOWN` | **No value in the production vocabulary** | A probe with no response is a soft failure (`:175`); `STARTING`/`READY` are transient, not `UNKNOWN` |

The daemon state machine also carries `STOPPED`, `STARTING`, `READY`, `RECOVERING`
and `STOPPING` (`src/control/state_machine.zig:6`). `RUNTIME_CONTRACT.md:33-43`
says "five-state lifecycle" but lists six values and does not list `RECOVERING`
or `STOPPING`. That inconsistency is a **documentation gap**, recorded here and not
silently resolved by changing either file in this slice.

## 2. Fields that actually exist in the health payload

Core schema (`RUNTIME_CONTRACT.md:130-152`):

| Field | Notes |
|---|---|
| `component` | Component name |
| `state` | One of the production lifecycle values in §1 |
| `pid`, `uptime_ms` | Process identity and uptime |
| `last_event_ms` | Time since last event; stale value is a soft failure (`:164-165`) |
| `defcon_level`, `defcon_label` | Single DEFCON authority, additive for old readers (`:157-163`) |
| `counters.in_events`, `out_events`, `errors`, `dropped` | `dropped` growth is a soft/hard failure rule (`:166-167`) |
| `deps[].name`, `deps[].state` | Component's own view of dependencies (`:168-169`) |

Additional keys emitted by `src/control/state_machine.zig`:

| Field | Source | What it proves |
|---|---|---|
| `data_integrity.queue_dropped_total` | `:468-469` | Total queue drops |
| `data_integrity.nose_frames_rejected` | `:468,470` | Rejected frames (not silent loss) |
| `data_integrity.nose_frames_dropped{,_framing,_midframe,_shape,_capacity}` | `:468-475` | Total plus diagnostic subsets; subsets are never summed by the soak gate (`:460-462`) |
| `data_integrity.nose_pipe_errors`, `pipeline_processing_errors` | `:468,476-477` | Pipe and processing error counters |
| `data_integrity.minifilter_ring_dropped`, `minifilter_pipeline_dropped` | `:468,478-479` | Host telemetry loss |
| `data_integrity.loss_budget`, `shed_overload` | `:468,480-481` | Observable shedding; **not** blocking-producer backpressure |
| `data_integrity.process_generation_ms` | `:468,482` | Process generation token, **not** an OS reboot id (`:464-466`) |
| `detector_degradation.{correlator,anomaly_detector,threat_tracker}_errors` | `:487-490` | Detection degradation, deliberately outside `data_loss_observed` (`:484-486`) |
| `resources` | `:495-498` | Sampled resource telemetry |
| `subsystems[].state` | `:501-504` | Bridge and pipeline view (`RUNNING`/`DEGRADED`) |
| `workers.{pipeline,sensor,nose,etw,fim,registry}_ready` | `:510-516` | Per-worker readiness |
| `workers.failed`, `failure_reason`, `failure_mask` | `:517-519` | Worker failure and reason |
| `last_transition_ms` | additive AEGIS-003 key | Epoch-ms of the last daemon `SystemState` change; not an OS reboot id |
| `reason` | additive AEGIS-003 key | First observable cause from the existing readiness/bridge/loss facts |
| `impact` | additive AEGIS-003 key | Diagnostic scope of the degraded state; not a host effect |
| `recovery_state` | additive AEGIS-003 key | `RECOVERING` or `NOT_RECOVERING` from the existing state machine |

## 3. Requested fields — implemented or not

| Requested field | Status | Nearest actual field | Gap |
|---|---|---|---|
| `reason` | **Additive E2 implemented** | root `reason` token | Component-level first-cause token derived from existing readiness/bridge/loss facts; worker token retained when `workers.failed` |
| `last_transition` | **Additive E2 implemented** | root `last_transition_ms` | Last daemon `SystemState` change, stamped by `transition`, `recomputeHealth` and `reconcileLifecycle` |
| `impact` | **Additive E2 implemented** | root `impact` token | Diagnostic scope (`none`, `event_pipeline`, `bridge_telemetry`, `data_integrity`, `subsystem_health`), not a host effect |
| `recovery_state` | **Additive E2 implemented** | root `recovery_state` token | Projects existing `RECOVERING` as `RECOVERING`, otherwise `NOT_RECOVERING`; no field previously existed |
| `UNKNOWN` value | **Not implemented** | Probe timeout = soft failure (`RUNTIME_CONTRACT.md:175`) | No explicit `UNKNOWN` state; adding one would be an owner-level contract revision and is explicitly out of scope |

The four additive keys are a source slice, not a documentation-only change.
They advance the build source and are proven at E2 only; fresh E3/E4/E5 proof
is still required before a DONE claim. Exact pre-slice line locations,
the no-ABI additive JSON skeleton and the state-vocabulary boundary are recorded
in [`HEALTH-KERNEL-E1-AUDIT`](../../analysis/current-head/HEALTH-KERNEL-E1-AUDIT-AA3B7B0-20261128.md);
the applied transaction is recorded in
[`AEGIS-003-HEALTH-ADDITIVE-E2`](../../analysis/current-head/AEGIS-003-HEALTH-ADDITIVE-E2-20261128.md).

## 4. Component families

| Family | Where it is visible today |
|---|---|
| Process | `state`, `pid`, `uptime_ms`, `process_generation_ms` |
| Sensor | `workers.nose_ready`, `etw_ready`, `fim_ready`, `registry_ready`; `deps[].state` |
| Queue | `data_integrity.queue_dropped_total`, `shed_overload` |
| Worker | `workers.failed`, `failure_reason`, `failure_mask`, `detector_degradation.*` |
| Evidence | Hash-chain verification via `forensic verify` CLI; not a health state field |
| Persistence | `minifilter_ring_dropped`, `minifilter_pipeline_dropped`, `alert_file` counters in operator snapshots |

## 5. DEGRADED display rule

A `DEGRADED` operator screenshot is a real state and must not be retouched. The README
snapshot at `README.md:20-23` is explicitly explained: `runtime=DEGRADED` with all
subsystems `RUNNING` is the control API echoing daemon health, not an independent root
cause. Any new screenshot must carry its commit and timestamp.

---

See also: [`docs/runtime/RUNTIME_CONTRACT.md`](RUNTIME_CONTRACT.md),
[`docs/OPERATIONAL_FAILURE_MATRIX.md`](../OPERATIONAL_FAILURE_MATRIX.md).
