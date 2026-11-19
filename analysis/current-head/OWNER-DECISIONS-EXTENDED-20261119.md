# Owner decisions — extended closure (2026-11-19, post commit `aff6f86`)

**DATE:** 2026-11-19
**OWNER INTENT:** "ทำให้เป็นจริงทั้งหมด" — make every remaining capability REAL, not a mock.
**RULE SCOPE:** must cover all 23 existing rules; rules add/edit/delete already REAL (owner acknowledged).
**NOT DONE:** no host install/restart/topology/load change; no sign; no soak; no push/tag/publish.

## Owner's three explicit choices (this session)

| # | Question | Owner choice | What it means concretely |
|---|---|---|---|
| 1 | Meaning of `policy enable/disable/reload` in a detection-only product | **ควบคุม evidence verdict (แนะนำ)** | enable/disable turns the policy-evaluation evidence label ON/OFF; reload re-reads `configs/policies.json`. It must NOT gate detection and must NOT cause a host effect. Detection stays pure/deterministic. |
| 2 | Alert delivery channel | **File-based local alert (แนะนำ)** | Enable a real local writer to `logs/alerts.ndjson` + show it in the loopback read-only dashboard. No egress, no secrets, no external transport. |
| 3 | FP counter producer | **Operator mark-fp CLI (แนะนำ)** | Operator marks a detection as false positive via aegisctl; feedback stored in producer-owned `logs/`; FP count read from that feedback. Human-in-the-loop, no auto-label, no fabricated zero counter. |

## Policy-stateful clarification (owner asked; answered with evidence)

The owner asked whether statefulness is even needed when rules are already manageable. Answer given:

- **Do NOT make detection stateful-by-policy** (DEFCON/state-machine gating a match). That was a legacy trap (`policy_contract.zig`, replaced by `policy_engine.zig`, not in production). It destroys determinism and reproducibility.
- **Do keep/extend stateful CONTEXT that enriches detection** (rate windows, flow, correlation, threat incidents) — this is the statefulness a kernel IDS genuinely needs.
- **Rules vs policy are different axes**: rules = what to detect (editable ✅); policy = what to do about a detection (read-only + advisory today). Editable rules do not replace manageable policy.
- Conclusion: the product stays detection-only/pure-match; the "make real" work is on the response/evidence/observability side, not on gating detection.

## Remaining authority blocker (NOT authorised, NOT touched)

- **signed-IR promotion** — requires owner trust anchor and a STOP-THE-LINE authority review. No code change.

## Planned slices (system flow contract)

```
SLICE 5 POLICY-MUTATE-001:
  control verb -> privileged postcondition -> atomic evidence-verdict gate
  -> event_processor policy evaluate (gated) -> health/forensics evidence label -> CLI
INVARIANT: detection match itself is never gated; no host effect; no wire change.

SLICE 6 ALERT-FILE-001:
  detection -> alert writer -> logs/alerts.ndjson (append-only)
  -> loopback read-only dashboard panel -> honest alert count
INVARIANT: local file only; no egress; no secret; no config that sends externally.

SLICE 7 FP-FEEDBACK-001:
  operator CLI mark-fp -> producer-owned feedback file -> FP count
  -> health / queue.stats / dashboard -> audit trail
INVARIANT: advisory only; feedback never suppresses or changes detection.

SLICE 8 RESOURCE-TELEMETRY-001:
  off-hot-path sample (Win32) -> resources block in health -> CLI whitelist -> dashboard
INVARIANT: no per-event sampling; no ADR-0013 latency regression; E2 only until host proof.
```

## Evidence level discipline

All new slices target **E2** (unit + pure-function tests) with E1 static records. No E5 claim without a host. Machine maps stay `TRUTH_INVALID` until each source commit is rebaselined; rebaseline only after owner-authorized commit.

## Isolation

No install/restart/service change, no topology switch, no load injection, no edit to `release/T20-final/b597e71`, no egress, no tag/push/publish. Running soak candidate untouched.
