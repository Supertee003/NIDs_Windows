# Runtime health and kernel lifecycle — E1 source audit

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged — records-only)  
**RECORDS TIP WHEN WRITTEN:** `61be9bc51ba95ce8499a67a6eb7bf373e887062d`  
**SCOPE:** AEGIS-003 + AEGIS-009. Read-only inspection; no build, host, driver,
service or finalizer action. This is a **finding map, not new proof**.

## 1. Runtime health (AEGIS-003)

The health payload is emitted by `src/control/state_machine.zig:393-555` through
`src/control/handler_registry.zig:441-470`; the mapping document
`docs/runtime/HEALTH_MODEL.md:56-68` already records the same gaps.

| Requested field | Current source | Boundary |
|---|---|---|
| `reason` | **partial** — worker-scoped `workers.failure_reason` at `state_machine.zig:539-548`, controlled tokens at `src/pipeline/runtime_state.zig:195-205`; subsystem `error` at `state_machine.zig:127-151` | no component-level `reason` |
| `last_transition` | **not implemented** — `RuntimeState` has `started_at_ms`, `uptime_ms`, `promote_streak`, `last_sample_ms` (`:161-174`) but no transition timestamp | state changes at `:255-263`, `:265-280`, `:311-355` |
| `impact` | **not implemented** — absent from `healthJson()`; nearest source is prose (`HEALTH_MODEL.md:60-63`) | not a health JSON key |
| `recovery_state` | **not implemented as a field** — `RECOVERING` is an internal state (`:25-45`, promotion `:339-352`) that can appear inside `runtime_state` (`:457-458`) | no dedicated key |
| `UNKNOWN` | **not implemented** — closed state set at `:25-45`; fixtures `tests/runtime/conftest.py:38` and `tests/contracts/test_contract_fixtures.py:27` also use a closed tuple | adding it is an owner-level contract revision, not a quiet patch |

**Contract impact:** additive JSON keys would be compatible with the existing
"older readers ignore unknown keys" pattern (`RUNTIME_CONTRACT.md:160-163`,
`state_machine.zig:439-441`, `:450-455`, `:487-495`); no canonical event ABI or
IOCTL struct changes. Adding `UNKNOWN` to `state`/`runtime_state` would violate
`RUNTIME_CONTRACT.md:31-43` and is explicitly out of scope for the safe slice.

A coordinated additive slice would touch `RUNTIME_CONTRACT.md:130-169`,
`HEALTH_MODEL.md:56-68`, `tests/runtime/test_health.py:75-114`,
`tests/contracts/test_contract_fixtures.py:27,129-135,181-186`, and fixtures
`contracts/fixtures/control/runtime_health_response.json`,
`contracts/fixtures/health/degraded_core.json`. Zig unit patterns exist at
`state_machine.zig:650-678`, `:680-710`, `:750-810`. E2 would prove serialization
only, not the E3/E4/E5 proof required before a DONE claim.

## 2. Kernel lifecycle (AEGIS-009)

`docs/runtime/KERNEL_LIFECYCLE.md:3-6` is explicitly HISTORICAL (`4dd3393` scope);
its current-source status at `:49-56` is contract E1 PASS but load/unload/cleanup,
signed driver and full kernel IDS qualification **NOT_PROVEN**. Required proof
fields are at `:21-36`; the owner-only boundary is at `:64-68`.

User-mode WFP bridge (`src/windows/aegis_wfp.c:1-8`) is lifecycle-only: open/close
and provider/sublayer at `:31-58`, direct mutation removed at `:60-68`, install/
uninstall map to open/close at `:70-77`. IOCTL codes/structs are pinned at
`src/windows/wfp_ioctl.c:22-27`, `:34-76`; user-side validation at `:163-245`.

Kernel WFP compiles only `aegis_wfp.c` + `aegis_wfp_callout.c`
(`scripts/wdk_build_production.ps1:173-181`); quarantined stale dispatch is
excluded (`drivers/wfp_callout/quarantined/aegis_wfp_comm.c:1-13`). Lifecycle
source is present: `DriverEntry` allocation/rollback at `aegis_wfp.c:679-802`,
unload cleanup at `:809-860`, callout registration at `aegis_wfp_callout.c:596-883`,
unregister drain at `:886-1078`. Classify is intentionally fail-open (`:14`,
`:485-489`) with `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` at `:682-685`,
`:746`, `:804`, `:859`. IOCTL dispatch refuses `BLOCK` with
`STATUS_NOT_SUPPORTED` (`aegis_wfp.c:923-932`) and reads whole records only
(`:953-1032`); buffer/identity validation at `:1219-1527`.

**Persistent-filter conflict remains in source:** provider is persistent
(`aegis_wfp.c:288-315`), startup enumerates provider-owned filters (`:317-424`),
disabled proof filters are deleted but enabled `FWP_ACTION_BLOCK` filters are
**re-adopted** (`:426-459`), and the unreachable legacy
`AegisWfpBlockFlow()` still constructs a persistent block filter (`:1035-1174`).
Issue #47/#50 are frozen under STOP-THE-LINE (`docs/START-HERE.md:26-28,43-47`;
`DEEP-TECHNICAL-AUDIT-AA3B7B0-20261127.md:21,52-58,161-164,203-218`).

Minifilter: `DriverEntry` registers filter and process notify before comm-port
creation (comm failure non-fatal) at `drivers/minifilter/aegis_minifilter.c:72-124`;
unload disconnects comm, removes notify, unregisters and destroys ring at `:126-143`.
Ring guard checks at `aegis_minifilter_comm.c:82-100`, `:118-137` and
`aegis_minifilter_proc.c:18`; port teardown calls `FltCloseCommunicationPort()`
at `aegis_minifilter_comm.c:265-275`.

**E2 cannot close this item.** Load/unload, filter/service state, driver
signature, BFE cleanup, process-notify teardown under live callbacks, installer
restore and host restoration require an owner-run elevated window
(`KERNEL_LIFECYCLE.md:21-36,64-68`). No such proof exists at `aa3b7b0`.

## 3. Patch-transaction skeletons — NOT APPLIED

```
PATCH-ID:      AEGIS-003-HEALTH-ADDITIVE-01
FLOW-ID:       health fact -> state machine -> JSON -> operator display
TARGET HEAD:   aa3b7b0161e425e54155d5767737bffcde7939b5
TARGET FILES:  src/control/state_machine.zig, src/pipeline/runtime_state.zig,
               docs/runtime/{RUNTIME_CONTRACT,HEALTH_MODEL}.md, contract fixtures,
               tests/runtime/test_health.py, tests/contracts/test_contract_fixtures.py
TARGET SYMBOLS:healthJson, RuntimeState, failure_reason
IN SCOPE:      additive reason/last_transition_ms/impact/recovery_state keys;
               deterministic tokens from already-observable facts
OUT OF SCOPE:  state/runtime_state vocabulary change, UNKNOWN, host action, soak
CONTRACT IMPACT: additive JSON keys only (RUNTIME_CONTRACT.md:160-163)
ABI IMPACT:      none (no canonical wire/IOCTL struct change)
AUTHORITY IMPACT:none
STATE IMPACT:    in-memory transition timestamp only
TEST IMPACT:     zig unit + contract fixture tests at E2
EVIDENCE IMPACT: E2 only; E3/E4/E5 still required before a DONE claim
```

```
PATCH-ID:      AEGIS-009-KERNEL-LIFECYCLE-01
FLOW-ID:       driver load -> telemetry -> unload -> cleanup verification
TARGET HEAD:   aa3b7b0161e425e54155d5767737bffcde7939b5
TARGET FILES:  drivers/wfp_callout/*, drivers/minifilter/* (frozen #47/#50 scope)
IN SCOPE:      only after explicit owner rebaseline disposition of #47/#50
OUT OF SCOPE:  any claim of driver-load, signature or cleanup PASS from E2 alone
CONTRACT IMPACT: to be declared per slice
ABI IMPACT:      to be declared per slice
AUTHORITY IMPACT:none — no host effect authority may be added
STATE IMPACT:    driver/device/filter state on an owner-run lab host
TEST IMPACT:     E2 static checks + mandatory owner-run E5
EVIDENCE IMPACT: NOT_PROVEN until a real host transcript exists
```

**Why not applied:** `src`, `drivers` and `shared` are `SOURCE_PATHS` entries
(`tools/truth.py:44-66`); any source commit moves the build source and regresses
`release_signature`. #47/#50 are STOP-THE-LINE frozen (`AGENTS.md:123-145`).
See [`docs/SOURCE-SLICE-DECISIONS.md`](../../docs/SOURCE-SLICE-DECISIONS.md).

## 4. Recorded boundary

No health field, state value, driver source, test skip, xfail, gate or verdict
was changed. `DEGRADED` remains a real state with a worker-scoped reason;
`docs/runtime/HEALTH_MODEL.md` remains the honest vocabulary map.
