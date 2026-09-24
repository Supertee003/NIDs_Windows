# Rules 22 Detection Fixture Manifest

> Synthetic observe-only fixtures only. These markers are not attack execution and are not sent to the network, filesystem, process launcher, or enforcement path.

- Fixtures: **22**
- Execution mode: `synthetic_observe_only`
- Global prevention gate: **closed**

| Fixture | Rule | Layer | Synthetic source | Marker | Expected action | Expected host effect | Status |
|---|---|---|---|---|---|---|---|
| `FX-01-R0056` | `R0056` | `L7` | `synthetic_payload_event` | `SQLI_BYPASS` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-02-R9064` | `R9064` | `L7` | `synthetic_payload_event` | `OSI_SEMI` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-03-R9059` | `R9059` | `L7` | `synthetic_payload_event` | `XSS_BASIC` | `Alert` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-04-R0088` | `R0088` | `L7` | `synthetic_payload_event` | `PATH_TRAV` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-05-R9002` | `R9002` | `L4` | `synthetic_wfp_network_event` | `ICMP_FLOOD` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-06-R9006` | `R9006` | `L4` | `synthetic_wfp_network_event` | `SYN_STEALTH` | `Alert` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-07-R9007` | `R9007` | `L4` | `synthetic_wfp_network_event` | `FPU` | `Alert` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-08-R1001` | `R1001` | `KERNEL_FILE` | `synthetic_fim_event` | `SYS32_WRITE` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-09-R1002` | `R1002` | `KERNEL_FILE` | `synthetic_fim_event` | `RANSOM_RENAME` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-10-R1003` | `R1003` | `KERNEL_FILE` | `synthetic_fim_event` | `STARTUP_MOD` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-11-R1004` | `R1004` | `KERNEL_FILE` | `synthetic_fim_event` | `DLL_DROP` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-12-R1005` | `R1005` | `KERNEL_FILE` | `synthetic_fim_event` | `HOSTS_MOD` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-13-R2001` | `R2001` | `KERNEL_PROCESS` | `synthetic_etw_process_event` | `MIMIKATZ` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-14-R2002` | `R2002` | `KERNEL_PROCESS` | `synthetic_etw_process_event` | `SVCHOST_HOLLOW` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-15-R2003` | `R2003` | `KERNEL_PROCESS` | `synthetic_etw_process_event` | `PS_CRADLE` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-16-R2004` | `R2004` | `KERNEL_PROCESS` | `synthetic_etw_process_event` | `CERTUTIL certutil -urlcache` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-17-R2005` | `R2005` | `KERNEL_PROCESS` | `synthetic_etw_process_event` | `PROCDUMP` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-18-R3001` | `R3001` | `L2_PIPE` | `synthetic_pipe_event` | `CS_PIPE` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-19-R3002` | `R3002` | `L2_PIPE` | `synthetic_pipe_event` | `PSEXEC_PIPE` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-20-R3003` | `R3003` | `L2_PIPE` | `synthetic_pipe_event` | `ANON_PIPE` | `Alert` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-21-R3004` | `R3004` | `L2_PIPE` | `synthetic_pipe_event` | `METER_PIPE` | `Drop` | `none` | `READY_FOR_SENSOR_ADAPTER` |
| `FX-22-R3005` | `R3005` | `L2_PIPE` | `synthetic_pipe_event` | `ATEXEC_PIPE` | `Block` | `none` | `READY_FOR_SENSOR_ADAPTER` |

## Per-fixture acceptance

Each adapter must emit a canonical event with the expected Rule key, preserve severity and provenance, create a forensic record, and produce no WFP filter, EnforcementReceipt, filesystem mutation, process creation, or real network transmission.

The manifest does not claim that a sensor adapter is implemented. `READY_FOR_SENSOR_ADAPTER` means the fixture definition is ready for the relevant test harness.
