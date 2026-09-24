# Phase 8 — Controlled Attack Lab Results

- Run: `phase8-lab-20260924-121122`
- Scenarios: **7** (passed 7, failed 0)
- Execution mode: `synthetic_observe_only`
- Prevention gate: **closed**
- Host effect count: **0**
- Qualification: `SYNTHETIC_LAB_MARKER_NOT_HOST_PROOF`

| Scenario | Rule | Severity | Action | Detection | Bounded window | PEP | WFP | Cleanup |
|---|---|---|---|---|---|---|---|---|
| `LAB-SQL-001` | `R0056` | `Critical` | `block` | `MATCHED` | 1.5s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-CMD-001` | `R9064` | `Critical` | `block` | `MATCHED` | 1.5s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-XSS-001` | `R9059` | `High` | `alert` | `MATCHED` | 1.5s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-TRAV-001` | `R0088` | `Critical` | `block` | `MATCHED` | 1.5s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-RECON-001` | `R9006` | `Medium` | `alert` | `MATCHED` | 7.0s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-FILE-001` | `R1005` | `High` | `block` | `MATCHED` | 1.0s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |
| `LAB-PROC-001` | `R3003` | `Medium` | `alert` | `MATCHED` | 1.0s | `UNEXERCISED` | `UNAVAILABLE_UNTIL_HOST_VERIFIED` | `CONFIRMED` |

## What this proves

Each scenario's inert marker really matches its shipped rule, the derived numeric
rule id matches `rule_loader.hashRuleId`, the scenario is rate/scope bounded, and
cleanup is confirmed with no residue.

## What this does not prove

Sensor delivery, PEP authorization, WFP host effect, and forensic persistence are
**not exercised** here; the prevention gate is closed. `WFP_RESULT` stays
`UNAVAILABLE_UNTIL_HOST_VERIFIED` until a test-signed host with the AEGIS WFP driver
proves the host effect. No block is claimed.

