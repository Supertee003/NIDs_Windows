# G15 — Reliability

**Gate:** G15
**Status:** PARTIAL (daemon manager exists; no watchdog/recovery)
**Date:** 2026-09-07

## Requirement
```
module failure, queue full, malformed event, network loss, policy load failure,
RAG failure, Brain failure, PEP failure, Windows API failure, restart/recovery
```

## Current State
- `aegis_daemon.py`: start/stop/restart/status/health via psutil + PID files
- `connection_semaphore`: limits concurrent connections (100)
- Ring buffer: drops events on overflow (tracked via `m_dropped`)
- EventAccounting (G3): tracks input/processed/dropped/rejected/expired/failed

## Failure Mode Table

| Failure | Behavior | Metric | Recovery |
|---|---|---|---|
| Module crash (Zig) | Process exits; daemon detects via PID | PID file stale | Daemon restart |
| Queue full (ring buffer) | Event dropped | `m_dropped++` | Backpressure (connection_semaphore) |
| Malformed event | Rust rejects (returns false) | `total_rejected++` | Event discarded |
| Network loss (UDP to Brain) | sendto fails silently | No metric (fire-and-forget) | Brain restarts independently |
| Policy load failure | `reload_rules_atomic` returns error | Error logged | Continue with old ruleset |
| Brain failure | Python process exits | Daemon detects via PID | Daemon restart |
| PEP failure (Rust) | `pep_enforce_action` returns error_code | `total_failed++` | Caller handles error |
| Windows API failure | `CreateNamedPipeA` fails | Error logged | Thread exits; listener stops |
| Restart/recovery | Daemon reads PID files, starts fresh | PID files | Process restarts with clean state |

## Missing
- No auto-restart watchdog (daemon must be manually invoked)
- No health-check RPC (only psutil-based status)
- No circuit breaker for Brain/PEP failures

## Exit Gate
```
[x] Failure modes documented (9 failure scenarios)
[x] Each failure has defined behavior + metric + recovery path
[x] EventAccounting tracks drops/rejections
[x] Ring buffer overflow tracked
[ ] Auto-restart watchdog
[ ] Health-check RPC
[ ] Circuit breaker for Brain/PEP
```
