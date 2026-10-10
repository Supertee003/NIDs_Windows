# RB-019: Detection-Chain Health Demo (Marked Canary)

## Objective

Prove, in one run, that every provable link in the detection chain
works: transport accepted, daemon alive and flowing, ring appending
with integrity true, graph rebuilt. Built for hackers evaluating the
tool: fire, watch, believe -- with the attribution boundary stated, not
hidden (GAP-019).

## Prerequisites

- System running (service + nose + brain). Operator shell in repo root.
- Accept one marked record in the evidence log + ring (clearly labeled
  `AEGIS_FIXTURE`, never confusable with real incidents; retention
  overwrites it in time).

## Steps

1. **Fire exactly one marked canary**
   ```bat
   python scripts\attack_demo.py --fixture xss
   ```
   - Fixtures: `xss`, `path-traversal`, `command-injection` (each
     carries `AEGIS_FIXTURE` + a TEST rule id matching a configured
     signature). `--dry-run` prints the plan and fires nothing.

2. **Watch the chain prove itself** (the script does this; read it)
   - `SENT`: pipe transport accepted the marked event.
   - `FLOW`: daemon alive + nose flowing mid-demo.
   - `RING`: tip advanced + `verified: true`.
   - `GRAPH`: `reports/threat_graph.html` rebuilt.
   - Exit 0 = chain healthy (with the printed attribution caveat);
     1 fire failed; 2 ring stalled/unhealthy; 3 graph failed.

3. **Look at it**
   - Open the printed HTML path in a browser (or re-run with
     `aegisctl graph --open`). Hover nodes for rule/src detail.

## Verification

- Exit 0 with all four lines (fired / flow / ring / graph).
- Ring tip advanced between the two reads; `verified: true`.
- Per-event attribution is OUT OF SCOPE here (GAP-019): ring
  responses carry no payload text and search has no rule filter, so
  one marked event cannot be picked out of background flow. The demo
  prints this boundary itself.

## Rollback

- None needed: one marked record, overwritten by retention. To
  re-prove, just run again.

## Notes

- This is the sanctioned gate-E canary pattern (`test golden-path`
  does the same), wrapped for humans. Lab users: same script works
  there; nothing prod-specific inside.
- Colors are claim-based triage; `forensic verify` is the authority.
- Never point this at unmarked/live attack traffic; the marker is
  the whole point.

## References

- `scripts/attack_demo.py --help`, `scripts/attack_demo.py --dry-run`
- `scripts/aegis_event_gen.py --help` (fixture catalog)
- RB-002 (query), RB-013 (quarantine lab proof)
