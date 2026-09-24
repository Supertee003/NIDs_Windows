# AEGIS Rules 22 Qualification Matrix

> This matrix is a baseline for controlled qualification. A configured `Block` or `Drop` action is an intent, not evidence that host enforcement is production-approved.

- Rules in `configs/Rules.json`: **22**
- Generic policies in `configs/policies.json`: **6**
- Global prevention gate: **closed**
- Initial rule statuses: `DETECT_ONLY` for Alert; `BLOCK_CANDIDATE_PENDING_PROOF` for Block/Drop

## Matrix

| Rule | Layer | Severity | Config action | Initial qualification | Sensor assessment | Blocker |
|---|---|---:|---|---|---|---|
| `R0056` SQL Injection (Auth Bypass) | `L7` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | current WFP callout exports 5-tuple only; payload match needs an application/proxy sensor | `L7_SENSOR_MAPPING` |
| `R9064` OS Command Injection (Semicolon) | `L7` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | current WFP callout exports 5-tuple only; payload match needs an application/proxy sensor | `L7_SENSOR_MAPPING` |
| `R9059` Cross-Site Scripting (Basic) | `L7` | High | `Alert` | `DETECT_ONLY` | current WFP callout exports 5-tuple only; payload match needs an application/proxy sensor | `L7_SENSOR_MAPPING` |
| `R0088` Path Traversal (Sensitive) | `L7` | Critical | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | current WFP callout exports 5-tuple only; payload match needs an application/proxy sensor | `L7_SENSOR_MAPPING` |
| `R9002` ICMP Flood (DoS) | `L4` | High | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | kernel network 5-tuple telemetry is implemented; end-to-end proof pending | `KERNEL_WFP_E2E` |
| `R9006` TCP SYN Stealth Scan | `L4` | Medium | `Alert` | `DETECT_ONLY` | kernel network 5-tuple telemetry is implemented; end-to-end proof pending | `KERNEL_WFP_E2E` |
| `R9007` TCP XMAS Scan | `L4` | Medium | `Alert` | `DETECT_ONLY` | kernel network 5-tuple telemetry is implemented; end-to-end proof pending | `KERNEL_WFP_E2E` |
| `R1001` System32 Write Attempt | `KERNEL_FILE` | Critical | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | FIM worker exists; per-rule trigger and block postcondition require proof | `FILE_RULE_PROOF` |
| `R1002` Ransomware Rename Pattern | `KERNEL_FILE` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | FIM worker exists; per-rule trigger and block postcondition require proof | `FILE_RULE_PROOF` |
| `R1003` Startup Folder Modification | `KERNEL_FILE` | High | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | FIM worker exists; per-rule trigger and block postcondition require proof | `FILE_RULE_PROOF` |
| `R1004` DLL Drop in System32 | `KERNEL_FILE` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | FIM worker exists; per-rule trigger and block postcondition require proof | `FILE_RULE_PROOF` |
| `R1005` hosts File Modification | `KERNEL_FILE` | High | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | FIM worker exists; per-rule trigger and block postcondition require proof | `FILE_RULE_PROOF` |
| `R2001` Mimikatz Execution | `KERNEL_PROCESS` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | ETW worker readiness exists; hids_process_monitor implementation is not complete | `PROCESS_SENSOR_PROOF` |
| `R2002` svchost Process Hollowing | `KERNEL_PROCESS` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | ETW worker readiness exists; hids_process_monitor implementation is not complete | `PROCESS_SENSOR_PROOF` |
| `R2003` PowerShell Cradle Download | `KERNEL_PROCESS` | Critical | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | ETW worker readiness exists; hids_process_monitor implementation is not complete | `PROCESS_SENSOR_PROOF` |
| `R2004` certutil Download Abuse | `KERNEL_PROCESS` | High | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | ETW worker readiness exists; hids_process_monitor implementation is not complete | `PROCESS_SENSOR_PROOF` |
| `R2005` procdump Credential Harvest | `KERNEL_PROCESS` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | ETW worker readiness exists; hids_process_monitor implementation is not complete | `PROCESS_SENSOR_PROOF` |
| `R3001` Cobalt Strike Named Pipe | `L2_PIPE` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | pipe sensor path exists; per-rule event production and block semantics require proof | `PIPE_RULE_PROOF` |
| `R3002` PsExec Remote Execution | `L2_PIPE` | High | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | pipe sensor path exists; per-rule event production and block semantics require proof | `PIPE_RULE_PROOF` |
| `R3003` Anonymous Pipe Suspicious | `L2_PIPE` | Medium | `Alert` | `DETECT_ONLY` | pipe sensor path exists; per-rule event production and block semantics require proof | `PIPE_RULE_PROOF` |
| `R3004` Meterpreter Named Pipe | `L2_PIPE` | Critical | `Drop` | `BLOCK_CANDIDATE_PENDING_PROOF` | pipe sensor path exists; per-rule event production and block semantics require proof | `PIPE_RULE_PROOF` |
| `R3005` atexec Scheduled Task Pipe | `L2_PIPE` | High | `Block` | `BLOCK_CANDIDATE_PENDING_PROOF` | pipe sensor path exists; per-rule event production and block semantics require proof | `PIPE_RULE_PROOF` |

## Required evidence per rule

Every rule must first produce a matched canonical event, the expected rule ID, a verified forensic record, and a false-positive result without unintended host effect.

A rule may move from `BLOCK_CANDIDATE_PENDING_PROOF` to `BLOCK_PROVEN` only after policy authorization, a complete `EnforcementReceipt v1`, host postcondition confirmation, exact filter cleanup, and a stale-filter scan pass.

## Immediate blockers

1. `configs/policies.json` contains six generic policies but no direct 22-rule mapping.
2. TypeScript, Zig, and Rust action ordinals must be frozen to one shared contract.
3. L7 rules require a payload-aware sensor; the current WFP callout exports a network 5-tuple, not HTTP payload content.
4. Process-layer rules require real event production proof; `hids_process_monitor.zig` is not a complete event source.
5. No rule is promoted to blocking until the controlled WFP proof is completed on an isolated Windows test target.
