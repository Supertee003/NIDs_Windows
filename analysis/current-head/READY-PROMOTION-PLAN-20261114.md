# READY-PROMOTION-001 — patch plan for DEFECT-READY-001 (not applied)

**Created:** 2026-11-14
**Status:** SOURCE APPLIED (`7c604d5`, E2) — installed runtime NOT updated; elevation required.
**Unblocked:** the soak window failed at 16.95 h on `shed_overload` (`SOAK-SHED-001`), so there was nothing left to protect and the patch landed. The fresh window starts after the reinstall below.

This document is the patch transaction, written now so the window's end is a
one-shot job rather than a fresh investigation.

---

## PATCH declaration

```
PATCH-ID        READY-PROMOTION-001
FLOW-ID         CTL-001 (status/health/readiness), HEALTH-001 (subsystem lifecycle)
TARGET HEAD     28380f9 (records) — build source 1fa877c
TARGET FILES    src/control/state_machine.zig
                src/daemon.zig
                tests/unit/state_machine_promotion.zig (new) OR existing test block
TARGET SYMBOLS  RuntimeState.recomputeHealth, RuntimeState.transition,
                SystemState.canTransitionTo, runDaemon's startup transition
IN-SCOPE        one promotion path: DEGRADED -> RECOVERING -> RUNNING, driven by
                live facts, with hysteresis
OUT-OF-SCOPE    enforcement, PEP, WFP, forensic ring, CLI (already named the cause
                in CLI-STATE-001), installer
CONTRACT IMPACT none: no wire field added or removed. `runtime_state` already
                exists and keeps its meaning; only its value becomes truthful.
ABI IMPACT      none
AUTHORITY IMPACT none
STATE IMPACT    system_state may now leave DEGRADED without a restart
TEST IMPACT     new unit tests + remove the xfail in
                tests/integration/test_e4_live_pipeline.py
EVIDENCE IMPACT one E3 entry + an E4 rerun of the E4-FLOW-001 gate
```

## The defect, restated

`src/daemon.zig:854-860` samples `bridge_init.allActive()` **once**, immediately
after `bridge_init.initAll()`, and moves the lifecycle to `.degraded` if any
bridge is not yet attested. Nothing re-evaluates it afterwards:

* `recomputeHealth()` maps `failed → degraded` and `degraded → recovering`, and
  is not called on any timer;
* even if it were, `recovering → running` has no caller;
* the health contract (`healthJson`) is computed from live facts, so it says
  `RUNNING` / `degraded: false` while `statusJson` says `DEGRADED`.

Observed on the live host for the whole run, not for a startup instant.

## Proposed change

1. **One promotion rule, in one place.** Extend `RuntimeState` with
   `reconcileLifecycle(facts) !void` that takes the same booleans `healthJson`
   already uses (`workers.pipeline`, `core_pipeline_failed`, `bridge_ready`,
   `data_loss_observed`) plus `all_subsystems_healthy`, and applies:

   | current | facts | next |
   |---|---|---|
   | RUNNING | any fact false | DEGRADED |
   | DEGRADED | all facts true, N consecutive samples | RECOVERING |
   | RECOVERING | all facts true, N consecutive samples | RUNNING |
   | RECOVERING | any fact false | DEGRADED |

2. **Hysteresis, not a weathervane.** `N = 3` consecutive samples, minimum 5 s
   apart. A single healthy sample must not clear a genuine degradation (that is
   how a flapping bridge would hide).

3. **Callers.** Invoke `reconcileLifecycle` from the control pipe's `health`
   handler (it already computes every fact) and from the main loop's existing
   tick, so an operator polling health is not required to make the state
   truthful. No new thread.

4. **Startup stays.** The initial transition remains; it is simply no longer
   final. The startup sample should also be replaced by "wait for the readiness
   barrier, then reconcile", which is what the barrier was for.

5. **Transition table.** `SystemState.canTransitionTo` already permits
   `degraded → recovering` and `recovering → running`; `running → degraded` is
   permitted. **Verify** before relying on it (`src/control/state_machine.zig:56-63`)
   and extend only if a required edge is missing.

## Tests the patch must carry

1. Unit: degraded + healthy facts → recovering after N samples, running after
   2N samples.
2. Unit: a healthy sample followed by an unhealthy one inside the hysteresis
   window leaves the state DEGRADED (no flapping).
3. Unit: `data_loss_observed` above budget keeps the runtime DEGRADED even with
   every worker ready — the RC-CLOSEOUT envelope must not be promoted past.
4. Mutation: disable the promotion branch → tests 1 and 3 fail.
5. Live: remove the `xfail` from `test_every_surface_agrees_about_health` and
   confirm `status`, `health` and `readiness` agree on the reinstalled build.

## Risks

1. **Flapping.** Mitigated by N-sample hysteresis; if it still flaps, the
   underlying bridge is genuinely unstable and the state is telling the truth.
2. **Soak invalidation.** The whole reason this is a plan: applying it before
   `2026-11-15T22:20:15` destroys the running window.
3. **Installed-build mismatch.** After the commit the installed binary is older
   than source — `Build/runtime mismatch` is a STOP-THE-LINE trigger here, so the
   patch and the elevated reinstall + `clean_host_e5` rerun must land together.
4. **Promotion past real degradation.** Guarded by test 3 and by requiring the
   same facts `healthJson` uses; a fact that is missing from that set cannot be
   promoted past, which is why rule 1 lives inside `RuntimeState` rather than in
   a caller.

## Rollback

`git revert` of the single patch restores the one-shot transition; the runtime
returns to reporting DEGRADED permanently, which is the current behaviour and is
fail-closed, so rollback is safe at any point.

## Completion gate

`PASS` requires: the four unit tests, `zig build` clean, `truth.py verify` valid
after a `--stamp` rebuild, the elevated reinstall, `clean_host_e5` PASS, the E4
gate green with the xfail removed, and the soak window restarted from the new
build.
