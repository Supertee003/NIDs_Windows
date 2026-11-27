# Operator commands and the fail-closed preflight

> Moved out of `README.md` so the top-level document stays an overview.
> Scope: [`docs/SCOPE.md`](../SCOPE.md) — detection-only / observe-only.
> Status always comes from [`release/release-status.json`](../../release/release-status.json);
> this page records commands, not a current gate result.
> No command below opens host enforcement or creates a host effect.

## 1. Fail-closed preflight before a lab probe

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\project2_runtime_gate.ps1
```

The gate writes health, readiness, snapshot, enforcement-status and a result
receipt under `admin-evidence`. It passes only when the daemon is `RUNNING`,
`degraded=false`, all 23 rules are active, forensic verification is true, the
Go Nose worker is connected, and enforcement remains `detection-only` with
`prevention_gate=closed`. If it fails, do not start the Kali probes. This is a
lab preflight, not a substitute for a current-source soak or a gate PASS.

## 2. Operator surfaces (one authority)

Run these from the repository root. All surfaces consume the daemon-owned
snapshot; none creates a second runtime authority.

```powershell
python tools\aegisctl.py snapshot
python scripts\aegis_console_pro.py --role operator
python -m tools.aegisctl.web_dashboard.app   # http://127.0.0.1:5000/
python scripts\aegis_console.py --mode dashboard
```

Process scans are diagnostic-only and are never promoted to runtime truth when
the control daemon is available. Local logs provide forensic detail but do not
override the authoritative control response.

## 3. Status and CLI verification

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
python tools\aegisctl.py status --json
python tools\aegisctl.py health --json
python tools\aegisctl.py metrics
python tools\aegisctl.py rules list
python tools\aegisctl.py rules validate
python tools\aegisctl.py events count
python tools\aegisctl.py events tail
python tools\aegisctl.py incidents
```

A healthy observe-only system reports `prevention_gate=closed`,
`tier3_enforcing=false`, `host_effect_capable=false` and `receipt_required=true`.
`provider_ready=true` never means traffic was blocked; only a validated receipt
supports a host-effect claim.

## 4. Reading the state correctly

- A historical lab qualification `BLOCK` is an intended policy decision, not a
  confirmed host block. A real effect needs a receipt-backed postcondition with
  `status=ENFORCED` and `host_effect_confirmed=true`. The shipped production
  path cannot reach that state (`prevention_gate=closed`, `host_effect_capable=false`).
- `DEGRADED` is a real health state with a named reason, not a cosmetic badge;
  see [`docs/runtime/HEALTH_MODEL.md`](../runtime/HEALTH_MODEL.md) and
  [`docs/OPERATIONAL_FAILURE_MATRIX.md`](../OPERATIONAL_FAILURE_MATRIX.md).
- Do not display a stale snapshot as live telemetry when a sensor disconnects.
