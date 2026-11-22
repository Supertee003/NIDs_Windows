# ALERT-FILE-001 — Patch Record (E2)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | ALERT-FILE-001 |
| FLOW-ID | DET-001 (detection → local alert evidence) |
| TARGET HEAD | `f3a5200` |
| FINAL HEAD | `183e095` |
| TARGET FILES | `src/forensic/alert_log.zig` (new), `src/pipeline/event_processor.zig`, `src/pipeline/runtime_state.zig`, `src/control/handler_registry.zig`, `src/daemon.zig`, `src/all_tests.zig`, `tools/aegisctl/web_dashboard/app.py`, `tests/tools/test_web_dashboard.py`, docs (3 files) |
| TARGET SYMBOLS | `Alert`, `formatAlertLine`, `append`, `appendTo`, `alertAppend`, `g_alerts_written`, `g_alerts_write_failed`, `metricsSnapshot`, `_read_alert_feed`, `renderAlerts` |
| IN-SCOPE | one local NDJSON line per detection, fixed path, honest written/failed counters, loopback read-only panel |
| OUT-OF-SCOPE | SIEM transports/egress, env endpoints, payload bytes, external notification, host effects, E5 |
| CONTRACT IMPACT | additive `metrics.snapshot.alert_file` and `snapshot.alerts`; no CanonicalEvent wire change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | observe-only; alerts are advisory detection labels (status `observed`), never enforcement claims |
| STATE IMPACT | two process-lifetime atomics, one append mutex; no detection state |
| TEST IMPACT | 4 Zig tests + 1 metrics JSON-parse test + 5 dashboard/static tests |
| EVIDENCE IMPACT | E2 only; EVIDENCE_INDEX entry `ALERT-FILE-001-E2-20261119` |

## Old flow → New flow

`detection → forensic ring + optional evidence log (AEGIS_EVIDENCE_LOG) + opt-in SIEM (default off) → no reliable local alert file`
→
`detection → alertAppend → fixed logs/alerts.ndjson append (always on, no egress) → counters in metrics.snapshot → loopback dashboard Alerts panel (read-only, honest count)`

## Invariant

Exactly one production writer owns `logs/alerts.ndjson`; no env/endpoint/transport/socket path exists in the module. `g_alerts_written` increments only after a complete escaped line + newline; failures increment `g_alerts_write_failed`. No payload/secret bytes. Marking an alert never changes detection, policy, or enforcement.

## Verification

- `zig build` PASS; `zig build test --summary all` PASS (2128/2139)
- `python -m pytest tests/tools/test_web_dashboard.py tests/tools/test_aegisctl_alerts.py tests/security/test_siem_contract.py tests/tools/test_operator_honesty.py tests/tools/test_notifier_retired.py -q` 43 passed
- Full pytest 1417 passed / 35 skipped / 1 xfailed / 1 xpassed (ratchet/doc failures from the new files were closed by this records patch)

## Evidence level

E2. No E5 claim on the installed soak candidate; no egress proof beyond static no-network-API assertions and unit tests.

## Rollback

Revert `183e095`; remove `src/forensic/alert_log.zig`, the `alertAppend` call site, the two atomics, the metrics block, the dashboard panel and the doc rows.

## Remaining risk / blockers

- Live on-host one-line-per-detection attribution needs a fresh signed candidate and owner-approved soak.
- The file is producer-owned and untracked; operators must rotate/archive it themselves (no auto-purge in this slice).

## Completion gate

Zig + targeted Python suites PASS, static no-egress PASS, no host effect, no wire change — **PASS (E2)**.
