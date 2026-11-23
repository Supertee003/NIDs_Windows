# Operational Failure Matrix

> What AEGIS does when a dependency fails. "Fail-closed" here means **no authority escalation and no
> false success** — it does **not** mean the host traffic is automatically blocked.
> Production is detection-only: the prevention gate is closed and no host mutation is authorized.

Sources: `README.md` ("The system reports degraded"), live `health --json` / `/api/snapshot`
observations, `docs/architecture/FAILURE_MODEL.md`, `FLOW_MAP.json`,
`EVIDENCE_INDEX.json`.

| Failure | Expected observable behavior | Where it is reported |
|---|---|---|
| WFP driver / adapter unavailable | Detection capability reported accurately; subsystem state not silently `READY`; no host effect claimed | `health --json` deps/subsystems, `endpoint_ownership`, `wfp` state |
| Go Nose pipe disconnect | `nose_connected=false`, ingestion counters stop; no false "event processed" | `health.data_plane`, queue counters |
| Sensor produces no frames | Explicit `DEGRADED` / warning; capture preflight fails instead of interpreting silence as "no attack" | `capture_select.py --verify`, dashboard warning banner |
| Queue pressure / overflow | Bounded queue that drops/sheds when full (no producer blocking); `dropped_total`, `shed_overload`, `queue_dropped_total` increase and are visible | `health.counters`, `health.data_integrity`, `aegisctl metrics` |
| Duplicate / non-monotonic events | Counters expose the anomaly; no silent promotion to truth | `exactly_once` counters |
| Detection engine unavailable | Worker failure state and reason mask set; runtime reports degraded | `health.workers.failed`, `failure_reasons` |
| Forensic storage / integrity failure | `forensic verify` fails; integrity status not `OK`; system remains observe-only | `aegisctl forensic verify`, dashboard Forensic Integrity |
| Control pipe responder degraded | State `DEGRADED` with all subsystems still `RUNNING`; local logs remain diagnostic only | `aegisctl diagnose`, `endpoint_ownership` |
| Control daemon unavailable | No unauthorized fallback authority; CLI/dashboard do not invent runtime state | README "Unified Command Control Center" |
| Rust PEP unavailable | PEP state reported (`READY`/error), `host_effect_capable=false` regardless; no block | `health.rust_pep`, `enforce status` |
| Invalid / malformed event | Rejected at the validation/codec boundary; contract tests cover decoder behavior | codecs, `tests/contracts` |
| Invalid control request | Rejected without an enforcement receipt or any host mutation | control-plane fail-closed probe (`scripts/run_control_receipt_probe.py`) |
| Policy action = `BLOCK` | Recorded as **intent** with `status=observed`, `host_effect_confirmed=false`; no receipt claiming ENFORCED can be produced | evidence log, `enforce status`, `AUTHORITY_MAP.json` |
| Release verification mismatch | Release gate fails; no artifact is published from an unverified tree | `final_audit.py --release-check`, `release_engineering.py --verify` |

## Clarifying "fail-closed"

For this detection-only product, fail-closed means:

1. The prevention gate stays closed; nothing opens it on failure.
2. No component may escalate its authority because another component is down.
3. A failed/partial detection is never reported as a passed detection.
4. A requested host effect is never reported as successful.
5. The operator always sees an explicit degraded/unavailable state, not silence interpreted as safety.

It does **not** mean "block all traffic when the detector fails." That would be a host effect and is
outside the product scope.

## Known current host observation (2026-11-23)

The lab host reported `state=DEGRADED` while all seven subsystems (`zig`, `go`, `cpp`,
`rust_pep`, `tier3`, `control`, `forensic`) reported `RUNNING`. The control-pipe diagnostic line
`responder state DEGRADED` is built by `diagnose_endpoint_ownership()` from `system.health.state`
(`tools/aegisctl/api/control_api.py:974-980`); it renders the daemon's health state rather than
causing it. This is a real, observable state and is shown unchanged in the portfolio dashboard
screenshot. It demonstrates the matrix above: a degraded state is reported, not hidden, and
enforcement remains closed. The specific counter that triggered demotion in this snapshot was not
preserved in the cited evidence; do not infer one.
