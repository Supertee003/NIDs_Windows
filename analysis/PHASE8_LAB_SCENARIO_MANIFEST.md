# Phase 8 — Controlled Attack Lab Scenario Manifest

> Inert markers only. Nothing in this manifest is transmitted, executed,
> written, spawned, or handed to the enforcement path. The global
> prevention gate is **closed**.

- Scenarios: **7**
- Execution mode: `synthetic_observe_only`
- Topology: `wsl2_hostonly_lab` (isolation: `host_only_network`)
- Bounds: max 8 events/scenario, 2 events/sec, 7 scenarios

## Expected decision matrix

| Scenario | Kind | Rule | Layer | Severity | Config action | Canonical action | PEP | WFP | Cleanup |
|---|---|---|---|---|---|---|---|---|---|
| `LAB-SQL-001` | `sql_marker` | `R0056` | `L7` | `Critical` | `Drop` | `block` | `REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `lab_http_session_close` |
| `LAB-CMD-001` | `command_marker` | `R9064` | `L7` | `Critical` | `Drop` | `block` | `REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `lab_http_session_close` |
| `LAB-XSS-001` | `xss_marker` | `R9059` | `L7` | `High` | `Alert` | `alert` | `NOT_REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `lab_http_session_close` |
| `LAB-TRAV-001` | `traversal_marker` | `R0088` | `L7` | `Critical` | `Block` | `block` | `REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `lab_http_session_close` |
| `LAB-RECON-001` | `bounded_recon` | `R9006` | `L4` | `Medium` | `Alert` | `alert` | `NOT_REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `lab_recon_state_release` |
| `LAB-FILE-001` | `file_canary` | `R1005` | `KERNEL_FILE` | `High` | `Block` | `block` | `REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `canary_file_restore` |
| `LAB-PROC-001` | `process_canary` | `R3003` | `L2_PIPE` | `Medium` | `Alert` | `alert` | `NOT_REQUIRED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `canary_pipe_release` |

## Forbidden categories

The lab must never contain: `real_malware`, `credential_theft`, `ransomware`, `uncontrolled_flood`, `exploit_execution`, `data_exfiltration`, `privilege_escalation`.

## Acceptance

Each scenario must produce a matched rule, its severity and action, deterministic
event/request identifiers, a PEP decision (or an explicit unavailable), a forensic
record, and a cleanup/rollback result. `WFP_RESULT` is `UNAVAILABLE_UNTIL_HOST_VERIFIED`
until a test-signed host with the AEGIS WFP driver proves the host effect; the lab never
claims a block it did not observe.

