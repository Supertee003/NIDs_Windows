# OBSERVABILITY-001 — honest observability closure (Slice 4)

**PATCH-ID:** OBSERVABILITY-001
**FLOW-ID:** HEALTH-INTEGRITY, NET-INGRESS, DETECTION-METRICS, SOAK-VERDICT
**TARGET HEAD:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40` (detached worktree)
**BUILD SOURCE BEFORE PATCH:** `f4cde3c503fd8b696183751a608b999768caa769`
**STATUS:** code + E2 COMPLETE. Not E5. All changes additive control-plane JSON
or read-only counters. No host effect, no wire/event change, no enforcement.

---

## Declaration

- **TARGET FILES**
  - `src/control/state_machine.zig` — health `data_integrity` gains
    `shed_overload` and `process_generation_ms`.
  - `src/pipeline/runtime_state.zig` — `g_process_generation_ms`,
    `g_nose_pace_waits`, bounded `g_rule_fire_*` + `recordRuleFire()`.
  - `src/daemon.zig` — pin the process generation once at startup.
  - `src/capture/nose_pipe_reader.zig` — bounded Nose backpressure
    (`noseShouldPace` + `paceBeforeSubmit`) and unit test.
  - `src/pipeline/event_processor.zig` — `recordRuleFire` at the 4
    rule-driven detection sites.
  - `src/control/handler_registry.zig` — queue.stats gains `nose_pace_waits`
    and `rule_fire` (bounded top-10 + collisions).
  - `tools/aegisctl/api/control_api.py` — CLI projection whitelist gains the
    two new health keys.
  - `tools/host_soak_check.py` — process-generation invalidation check.
  - Tests: `tests/security/test_soak_verdict.py`,
    `tests/runtime/test_health.py`, `tests/tools/test_aegisctl_queue.py`.
- **IN-SCOPE:** additive health/queue fields; bounded Nose pacing; bounded
  per-rule fire telemetry; explicit counter-reset identity.
- **OUT-OF-SCOPE:** CPU/RAM native sampling (new linkage + off-hot-path sampler
  + E5, would reopen ADR-0013 latency risk); fabricated FP counter; latency
  bucket/clock changes; any enforcement or host effect.
- **CONTRACT IMPACT:** none (`CanonicalEvent`/wire unchanged; health and
  queue.stats are control-plane JSON, older readers ignore new keys).
- **ABI IMPACT:** none.
- **AUTHORITY IMPACT:** none. All new data is observational.
- **STATE IMPACT:** process generation pinned once at startup; atomics reset at
  process start (documented, not changed).
- **TEST IMPACT:** +2 Zig tests, +3 Python soak tests, +1 health, +1 queue.
- **EVIDENCE IMPACT:** one E2 entry; item 4 recorded STALE in
  `LATENCY-STALE-20261119.md`.

---

## Item-by-item disposition

| Plan item | Decision | Evidence / rationale |
|---|---|---|
| 1. `shed_overload` in `data_integrity` | **DONE** | `state_machine.zig` now emits it alongside the six loss counters; deliberately NOT in `data_loss_observed` — a shed-only storm (`dropped=0`) is a budgeted policy outcome scored by `--shed-budget`, not DEGRADED. CLI whitelist updated. |
| 2. True Nose backpressure | **DONE** | Bounded pause (≤5 ms, stop-signal checked) keyed on the Npcap share before `pushDecodedFrame`, mirroring PACE-MF-001. The Go pipe is the upstream buffer; after the hard bound the existing counted-drop path applies. `g_nose_pace_waits` on queue.stats. Pure `noseShouldPace` gate unit-tested. |
| 3. Boot-id / reset semantics | **DONE (honest name)** | `process_generation_ms` pinned once at daemon startup and published in health. Soak baseline/delta now invalidate on a generation change even when counters did not go backwards. Called a PROCESS token, not an OS boot id — no durable boot source exists in-tree and conflating the two would cause false invalidations. |
| 4. 6/10 latency stages at 1 ns | **STALE — no change** | All 10 stages already have `markStage` observe sites; the 1 ns is the log2 bucket floor, and the coarse-clock bug was fixed at `02b4e5d` (ADR-0013). See `LATENCY-STALE-20261119.md`. Changing bucket math would invalidate all latency evidence. |
| 5a. Resource metrics (CPU/RAM/disk/ring) | **PARTIAL: ring only** | Ring counters (`written`/`overwritten`/`capacity`, already in queue.stats) are the disk/ring telemetry — verified, no new code. CPU/RAM need Windows API linkage and an off-hot-path sampler plus E5 proof; deferred with an owner decision rather than added riskily. |
| 5b. TP/FP + per-rule fire rate | **PARTIAL: per-rule fire + TP proxy** | Bounded 256-slot direct-mapped per-rule counter, collisions counted (never merged), fed at the 4 rule-driven Zig detection sites, exposed as a top-10 in queue.stats. Confirmed counts are the available TP proxy. No FP counter is fabricated: `false_positive` is an operator incident label with no runtime transition, so an always-zero FP gauge would be a production mock (STOP-THE-LINE). |

A "gap" that is stale or needs unsafe/new-native work is closed by an honest
decision, not by shipping a mock or rewriting a proven subsystem.

---

## Result

PATCH-ID: OBSERVABILITY-001
FLOW-ID: HEALTH-INTEGRITY, NET-INGRESS, DETECTION-METRICS, SOAK-VERDICT
TARGET HEAD: `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40`
FINAL HEAD: unchanged (worktree, uncommitted)

OLD FLOW:
```
health.data_integrity: 7 keys, no shed/generation -> soak cannot see shed,
cannot detect a restart that rebuilt counters past baseline
Nose: full share -> immediate counted drop (no pause)
detection metrics: total count only; no per-rule attribution
```

NEW FLOW:
```
health.data_integrity: +shed_overload +process_generation_ms
  -> soak scores shed separately and invalidates on generation change
Nose: near-full Npcap share -> bounded <=5ms pause (stop-checked)
  -> pipe drains; after bound, existing counted drop still applies
detection: recordRuleFire(rule_id) at AC/L4/anomaly/correlation sites
  -> bounded 256-slot sample -> queue.stats.rule_fire top-10 + collisions
```

INVARIANT: no observed metric may become an enforcement input; no new telemetry
may add a host effect or a wire change; never fabricate a counter that no
producer feeds.

BUILD RESULT: `zig build` exit 0; `zig fmt` exit 0 on all touched Zig files.

TEST RESULT (2026-11-19):
```
zig build test --summary all -> 2116 passed / 11 skipped / 0 failed (2127)
pytest soak + health + queue + control_retry -> 74 passed
```

WINDOWS RESULT: not E5; no host access, no egress, no service change.

EVIDENCE LEVEL: E2 (unit + pure-function verdict tests) + E1 (static/STALE).

EVIDENCE ARTIFACTS:
- `analysis/current-head/OBSERVABILITY-001-PATCH.md`
- `analysis/current-head/LATENCY-STALE-20261119.md`

ROLLBACK: revert the listed files. No state, config, host or authority change.

REMAINING RISK:
- CPU/RAM gauges deferred — an operator wanting them needs an owner decision,
  native linkage, an off-hot-path sampler and E5 proof.
- Per-rule fire counts are a bounded sample: a slot collision is counted, not
  attributed, so exact per-rule rates need the offline analyzer for >256 rules.
- Nose pacing adds at most 5 ms to a near-full-share frame; it is strictly
  bounded and stop-checked, so it cannot hang the reader.

OPEN BLOCKERS: owner authorisation to commit source (truth rebaseline gated);
fresh soak for the final candidate after all four slices.

COMPLETION GATE: Slice 4 COMPLETE at E2 with no new authority and no host effect.
Board remains 5/6; no tag/publish.

TRUTH STATE: TRUTH_INVALID in this worktree is expected while source is uncommitted.
