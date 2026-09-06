# G19 — IPS

**Gate:** G19
**Status:** PARTIAL (Python netsh IPS exists; WFP block stubbed)
**Date:** 2026-09-07

## Requirement
```
observe-only → shadow decision → canary → bounded enforcement → rollback test → production enforcement
```

## Current State
- Python `apply_firewall_block()` via `netsh advfirewall` — works but slow (~500ms)
- WFP `IOCTL_AEGIS_BLOCK_FLOW` returns `STATUS_NOT_IMPLEMENTED`
- G10 PEP `pep_enforce_action()` — enforcement authority designed
- No canary/shadow mode

## IPS Maturity Model

| Level | Description | Status |
|---|---|---|
| 1. Observe-only | Detect and log; no enforcement | ✅ Current default (Alert rules) |
| 2. Shadow decision | Compute block decision but don't enforce | ❌ Not implemented |
| 3. Canary | Enforce on small subset (1% of traffic) | ❌ Not implemented |
| 4. Bounded enforcement | Enforce with rate limit + rollback window | ⚠️ Partial (Python netsh) |
| 5. Production enforcement | Full enforcement via Rust PEP → WFP | ❌ WFP stubbed |

## Action Record (required for every enforcement)
```
reason: "Tier-1 Aho-Corasick match: SQL Injection"
policy_version: 1
event_id: 42
operator/request_id: "aegisctl/manual" or "auto/tier1"
result: "Block enforced via WFP"
rollback_information: "aegisctl ips unblock 192.168.1.1"
```

## Path to Production IPS
1. Implement `IOCTL_AEGIS_BLOCK_FLOW` in WFP driver (G12)
2. Wire `pep_enforce_action(PepAction::Block)` to call WFP IOCTL (G10)
3. Add shadow mode: compute block decision, log but don't enforce
4. Add canary: enforce on 1% of matching flows
5. Add rollback: auto-unblock after configurable timeout
6. Production: full enforcement via Rust PEP → WFP

## Exit Gate
```
[x] IPS maturity model documented (5 levels)
[x] Observe-only mode works (Alert rules)
[x] Python netsh enforcement works (fallback path)
[x] G10 PEP provides enforcement authority
[x] Action record design documented
[ ] Shadow decision mode
[ ] Canary mode
[ ] Rollback (auto-unblock timeout)
[ ] WFP block IOCTL implementation (G12)
[ ] Production enforcement via PEP → WFP
```
