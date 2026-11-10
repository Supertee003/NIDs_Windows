# READINESS-CAUSE-001 — a gate that refuses now names a cause

**Created:** 2026-11-10
**Build source commit:** unchanged (`cf041b8`); this patch touches `tools/aegisctl.py`
only — no Zig/Go/Rust/C source, no wire change
**Finding:** `SYSTEM-SURVEY-001` §S1-05 residual ("`readiness` refuses without
naming a cause")
**Evidence level:** E2 (unit) + E1 live reading of the gate on the deployed host.

---

## 1. What was wrong

`aegisctl.py readiness` is the machine-facing gate: automation branches on its
exit code and `tools/host_soak_check.py` reads the same health payload. On this
host it answered:

```
{"ready": false, "overall_gate": false, "degraded": true,
 "degraded_components": [], "failure_reasons": [], "missing": []}
```

Every worker flag was true, rules were loaded (23), and nothing named why the
gate was shut. `degraded` is a boolean the control API aggregates from several
sources — lifecycle, data-loss counters, subsystem states — so a `true` with
`degraded_components: []` carried no information the operator could act on. That
is the same class as S1-02 (a digest gate that cannot fail): a gate whose answer
cannot be checked.

## 2. What changed

`tools/aegisctl.py`:

- the body of `cmd_readiness` became a pure function `build_readiness(payload)`
  so the decision is testable without a daemon;
- the reason list is now built from the same conditions the gate tests, instead
  of only `workers.failure_reasons` plus rules plus subsystems:
  - `state_<state>` when the state is not `RUNNING` (including `state_unknown`
    when the payload has none);
  - `worker_failed` when the aggregate worker flag is set;
  - `worker_<flag>_not_ready` for each of the six required worker flags;
  - `rules_not_loaded`;
  - `<component>_<error-or-state>` for each non-running subsystem;
  - `degraded_without_named_component` when `degraded` is true and nothing above
    explained it — the exact shape the host produced;
  - `gate_closed_without_named_cause` as a construction guard, so a future gate
    condition added without a reason cannot return a silent refusal.
- `state` is normalised to upper case with `unknown` as the empty value, so a
  payload without state does not print `state_none`.

Gate **semantics did not change**: the same four conditions decide
`overall_gate`. This patch changes what the gate *says*, not when it opens.

## 3. Verification

```
python -m pytest -q tests/tools/test_readiness_cause.py   -> 19 passed
mutation: disable the degraded_without_named_component branch
        -> 1 failed (test_degraded_with_no_attributable_component_is_still_named)
python tools/aegisctl.py readiness                        -> live reading below
```

Live reading on this host, against the **deployed** daemon (the CLI is the only
changed file, so this is a real observation of the shipped gate):

```
{"ready": false, "state": "DEGRADED", "degraded": true,
 "worker_gate": true, "rules_loaded": 23, "policies_loaded": 6, "missing": [],
 "degraded_components": [],
 "failure_reasons": ["degraded_without_named_component", "state_degraded"]}
```

Two things follow from that reading, and both matter for R-08:

1. the previously silent refusal now names itself;
2. **the daemon's degradation has no attributable worker or subsystem.** All six
   worker flags are true and no subsystem reports DEGRADED/FAILED/STOPPED, so the
   `degraded: true` must come from the aggregate data-loss/lifecycle path. That
   is a pointer for the host window, not a closure of it.

## 4. Limitations and open question (stated, not hidden)

1. **E2 + E1, not E5.** No host behaviour changed; the test proves the decision
   function, and the live reading proves the CLI on the installed daemon.
2. **The gate is worker-flag based.** A STOPPED subsystem that is not one of the
   six required workers is *reported* (`degraded_components`, `<name>_stopped` in
   `failure_reasons`) but does not close the gate. Whether, for example, a
   stopped `rust_pep` should block readiness in detection-only mode is a product
   decision — which subsystems are required — and this patch deliberately did not
   make it. The test pins the reporting side only.
3. **`degraded_without_named_component` is a diagnosis, not a fix.** It says the
   aggregate is closed by something the payload does not itemise. Itemising that
   aggregate inside the daemon (`state_machine.zig` / `control_api.py`) is
   separate work, and it is what would let an operator see *which* condition
   closed the gate on a degraded host.
4. **`tools/aegisctl.py` is not the only readiness surface.** `health --strict`,
   `web_dashboard/app.py:985` and `host_soak_check.py:161` each re-derive health
   from the same payload; they were not changed here.
