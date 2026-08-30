# 07 - Error Policy

## Error Classes

| Class | Description | Handling |
|-------|-------------|----------|
| BUILD | Build system failure | Fix build config, retry |
| COMPILE | Compilation error | Fix code, retry |
| RUNTIME | Runtime crash | Restart subsystem, log |
| CONCURRENCY | Race/deadlock | Stop-the-line, investigate |
| ABI | Cross-language mismatch | Stop-the-line, fix contract |
| SECURITY | Policy bypass/unauthorized enforcement | Stop-the-line, security review |
| SEMANTIC | Logic error | Fix logic, add test |

## Stop-the-Line Conditions

- Memory corruption
- ABI mismatch
- Event loss (fabric failure)
- Race/deadlock
- Policy bypass
- Unauthorized enforcement
- Forensic inconsistency (hash chain broken)

## Error Handling Procedure

```
ERROR -> CLASSIFY -> LOCALIZE -> MINIMAL FIX -> TARGETED TEST -> REGRESSION -> CONTINUE
```

## Fail-Soft Model

| Subsystem Down | System Continues? | Fallback |
|----------------|-------------------|----------|
| Brain | YES | insufficient_data advice |
| PEP | YES | deferred/no-op result |
| Detection | YES | empty evidence |
| RAG | YES | empty context |
| Threat Intel | YES | null match |
| Correlation | YES | empty alerts |
| Forensic | NO | stop-the-line |
| Audit | NO | stop-the-line |
| Event Fabric | NO | stop-the-line |

## RPO/RTO

- RPO: 5 minutes (max data loss)
- RTO: 30 seconds (max recovery time)
- No snapshot: RPO always violated
