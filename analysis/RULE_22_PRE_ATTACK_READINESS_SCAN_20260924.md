# AEGIS Pre-Attack Readiness Scan

**Status:** `PASS`

This scan is deterministic and observe-only. It validates qualification artifacts; it does not create processes, files, pipes, network traffic, or enforcement requests.

## Baseline

- Matrix rules: `22` (declared `22`)
- Fixture rules: `22` (declared `22`)
- Global gate: `closed`
- Fixture mode: `synthetic_observe_only`; active=`False`

## Coverage by layer

| Layer | Rules |
|---|---:|
| `KERNEL_FILE` | 5 |
| `KERNEL_PROCESS` | 5 |
| `L2_PIPE` | 5 |
| `L4` | 3 |
| `L7` | 4 |

## Qualification blockers

| Blocker | Rules |
|---|---:|
| `FILE_RULE_PROOF` | 5 |
| `KERNEL_WFP_E2E` | 3 |
| `L7_SENSOR_MAPPING` | 4 |
| `PIPE_RULE_PROOF` | 5 |
| `PROCESS_SENSOR_PROOF` | 5 |

## Initial qualification

| State | Rules |
|---|---:|
| `BLOCK_CANDIDATE_PENDING_PROOF` | 18 |
| `DETECT_ONLY` | 4 |

## Findings

- No artifact or safety-contract errors detected.

## Gate decision

The global prevention gate remains closed. Synthetic fixture readiness is not evidence of host detection or enforcement, and no attack simulation should begin until the relevant sensor-specific proof gate is opened through a separate reviewed step.

