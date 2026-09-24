# Named Pipe Real Runtime Result — 2026-09-22 22:51

## Authoritative result

`PIPE_REAL_PIPELINE_OBSERVE_ONLY_PASS`.

The Host runtime was healthy, the Nose/pipe worker was ready, and three benign canonical events were sent successfully through `\\.\pipe\aegis_sensor_pipe`.

## Evidence

- Runtime state: `RUNNING`
- Degraded: `false`
- Nose worker: `nose_ready=true`
- Pipeline: ready
- Forensic subsystem: running
- Pipe transport sends: `3 sent, 0 failed`
- Events processed delta: `7`
- Forensic records delta: `7`
- Blocks delta: `0`
- Errors delta: `0`
- Forensic chain: verified
- Host effect: `none`
- Prevention gate: `closed`
- WFP block called: `false`
- PEP called: `false`

## Interpretation

This proves benign named-pipe ingress and pipeline processing:

```text
\\.\pipe\aegis_sensor_pipe -> Zig pipe reader -> pipeline -> forensic record
```

The processed count can exceed the three requested events because other runtime events may arrive during the measurement interval. The pipe transport itself reported all three sends successful.

This does not claim a named-pipe Rule-22 match. No Cobalt Strike, PsExec, anonymous suspicious pipe, Meterpreter, or ATExec behavior was executed. A rule-specific claim requires canonical evidence with `matched_rule_id` and pipe provenance.

## Promotion state

```text
Named pipe real sensor pipeline = PASS
Named pipe configured rule match = PENDING
ETW real sensor pipeline         = PASS
FIM real sensor pipeline         = PASS
L4 host-only transport           = PASS
Rules-22 synthetic               = PASS 22/22
prevention_gate                  = CLOSED
```
