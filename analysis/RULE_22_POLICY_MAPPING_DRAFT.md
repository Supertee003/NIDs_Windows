# Rules 22 Rule-to-Policy Mapping Draft

> **Inactive draft:** this file is qualification metadata only. It is not loaded by the daemon and cannot authorize WFP enforcement.

| Rule | Config action | Canonical action | Layer | Sensor | Mode | Block allowed | Status |
|---|---|---|---|---|---|---|---|
| `R0056` | `Drop` | `BLOCK` | `L7` | `payload_sensor_pending` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R9064` | `Drop` | `BLOCK` | `L7` | `payload_sensor_pending` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R9059` | `Alert` | `ALERT` | `L7` | `payload_sensor_pending` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R0088` | `Block` | `BLOCK` | `L7` | `payload_sensor_pending` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R9002` | `Drop` | `BLOCK` | `L4` | `wfp_kernel_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R9006` | `Alert` | `ALERT` | `L4` | `wfp_kernel_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R9007` | `Alert` | `ALERT` | `L4` | `wfp_kernel_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R1001` | `Block` | `BLOCK` | `KERNEL_FILE` | `fim_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R1002` | `Drop` | `BLOCK` | `KERNEL_FILE` | `fim_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R1003` | `Block` | `BLOCK` | `KERNEL_FILE` | `fim_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R1004` | `Drop` | `BLOCK` | `KERNEL_FILE` | `fim_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R1005` | `Block` | `BLOCK` | `KERNEL_FILE` | `fim_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R2001` | `Drop` | `BLOCK` | `KERNEL_PROCESS` | `etw_process_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R2002` | `Drop` | `BLOCK` | `KERNEL_PROCESS` | `etw_process_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R2003` | `Block` | `BLOCK` | `KERNEL_PROCESS` | `etw_process_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R2004` | `Block` | `BLOCK` | `KERNEL_PROCESS` | `etw_process_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R2005` | `Drop` | `BLOCK` | `KERNEL_PROCESS` | `etw_process_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R3001` | `Drop` | `BLOCK` | `L2_PIPE` | `pipe_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R3002` | `Block` | `BLOCK` | `L2_PIPE` | `pipe_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R3003` | `Alert` | `ALERT` | `L2_PIPE` | `pipe_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R3004` | `Drop` | `BLOCK` | `L2_PIPE` | `pipe_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |
| `R3005` | `Block` | `BLOCK` | `L2_PIPE` | `pipe_telemetry` | `DETECT_ONLY` | `false` | `DRAFT_NOT_LOADED` |

## Activation rule

A mapping may become active only after assignment of a stable policy ID, signed policy-envelope verification, cross-language action conversion tests, a detection fixture, a complete EnforcementReceipt v1, host postcondition proof, exact cleanup proof, and a stale-filter scan.

Until then every row remains `DETECT_ONLY` and `block_allowed=false`.
