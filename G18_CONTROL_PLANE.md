# G18 — Control Plane / aegisctl

**Gate:** G18
**Status:** PARTIAL (Python daemon exists; no canonical CLI)
**Date:** 2026-09-07

## Requirement
```
CLI = CONTROL REQUESTOR (not enforcement engine)
Allowed: status, health, start/stop/restart, diagnostics, read-only inspection,
         policy simulation, canary request
Sensitive actions: CLI → typed request → authorization/policy → Rust PEP → result → audit
```

## Current State
- `aegis_daemon.py`: Python CLI for start/stop/status/health
- `aegis_console.py`: Interactive menu UI
- No canonical `aegisctl` binary
- No separation between "read-only" and "sensitive" actions

## aegisctl Design
```
aegisctl status          — Show system status (DEFCON, event count, flow count)
aegisctl health          — Health check all subsystems
aegisctl start           — Start AEGIS service
aegisctl stop            — Stop AEGIS service
aegisctl restart         — Restart AEGIS service
aegisctl rules list      — List loaded rules (read-only)
aegisctl rules reload    — Hot-reload Rules.json
aegisctl flows           — Show active flows (G5)
aegisctl accounting      — Show event accounting (G3/G4)
aegisctl pep stats       — Show PEP enforcement stats (G10)
aegisctl defcon          — Show current DEFCON level
aegisctl ips block <ip>  — SENSITIVE: request block (goes through PEP)
aegisctl ips unblock <ip>— SENSITIVE: request unblock (goes through PEP)
aegisctl canary          — Request canary enforcement (G19)
aegisctl diagnostics     — System diagnostics dump
```

## Sensitive Action Path
```
aegisctl ips block <ip>
  → CLI sends typed request to daemon
    → Daemon calls pep_enforce_action(PepDecision{action: Block, source_ip: <ip>})
      → Rust PEP validates + executes
        → Result returned to CLI
          → Audit logged
```

## Exit Gate
```
[x] aegisctl command design documented (14 commands)
[x] Read-only vs sensitive separation documented
[x] Sensitive actions go through Rust PEP (G10)
[ ] aegisctl binary implementation
[ ] Authorization check for sensitive actions
```
