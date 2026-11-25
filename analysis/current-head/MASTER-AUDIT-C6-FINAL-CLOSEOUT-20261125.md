# MASTER AUDIT — final current-source closeout at build source `7822f4c` (2026-11-25)

**BUILD SOURCE:** `7822f4c162f7867555754b7f3677ade33c9548dd` (C6 capture visibility /
shutdown / monotonic source slice)
**RECORDS HEAD AT CLOSEOUT:** `f13bbbefe5bc9c62dc7e2961bc17b497e7b17a66`
**STATUS:** PASS for the narrow current-source proof set (E2 + narrow E3 + narrow E4/E5).
Full current-head Windows E5 / kernel IDS qualification and detection efficacy remain
**OPEN / NOT_PROVEN**. This is a records-only consolidation; it runs no new test and adds
no new capability or authority.

## PATCH DECLARATION

```
PATCH-ID:             C6-FINAL-CLOSEOUT-7822F4C
FLOW-ID:              consolidated current-source proof inventory + honest blocker register
TARGET FILES:         records/docs only; no src/nose/build.zig change
IN-SCOPE:             consolidate E2/E3/E4-E5 already executed at this source, reconcile
                      point-in-time records with supersede-in-part pointers, restate the
                      live status without exceeding evidence
OUT-OF-SCOPE:         detection-rule matrix, soak, loss rate, install, signing, new release,
                      tag, signature or key, E6/E7, host-effect activation, wire/golden-vector/
                      rule/authority change, full Windows E5 / kernel IDS qualification
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none
TEST IMPACT:          none (no new run; prior results recorded at their own commits)
EVIDENCE IMPACT:      no new evidence entry; pointers to the three existing current-source
                      entries (E2, E3, narrow E4/E5) and their audit records
```

## Current-source proof inventory

| Level | What was actually run | Records commit | Scope verdict |
|---|---|---|---|
| E2 | `go test ./...` PASS; Zig decoder tests; `zig build test --summary all` 8/8 steps, 2142 passed / 10 skipped | `7822f4c` (source) + `47e4cf5`/`1e2a8fd`/`7fe84f3` (records) | PASS for the C6 source slice's unit/component behavior |
| E3 | Harness recompiled from unmodified source; `-inject -pipe aegis_nose_i44f -seconds 2`; three exact deltas; exit 0 | `126f49c` | PASS_E3, private pipe only; canonical pipe and live service untouched |
| E4/E5 | Owner-run elevated script on `\\.\pipe\aegis_nose`; pre-state capture, disable failure actions, stop AegisNids/Nose, `-inject -seconds 2`, restore in `finally` | `f13bbbe` | PASS_E4_E5, narrow canonical-pipe lifecycle only, verified restore |

Harness SHA256 is `3CAB8A36C289AE18319071600D8D8412DD97CF299F980914D252F9CAE6F88C67`
for both the E3 and the E4/E5 run at this source. Prior harness SHAs (`09EAEAB7…02E9`
at `43a8bcc`, `3027F320…A431E` at `a26c573`) are historical.

Exact deltas asserted by the harness at both levels:

```
close-before-payload -> +1 midframe, +1 pipe error
absurd-length       -> +1 framing,   +1 pipe error
drain-then-valid    -> +1 framing,   +1 submitted, no pipe error
reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
fabric pending=0 accepted=0 rejected=0 dropped=0
```

`waitForDelta` returns `error.CounterDeltaTimeout` on a missing delta and `main` returns 1
when `frames_submitted == 0`; all three cases printed `OK` and exit was 0, so these are
gated assertions rather than descriptive output. The elevated run ended with `DONE
inject_exit=0`; failure actions, service RUNNING state, Nose command line and the single
canonical pipe matched the captured pre-state on an independent read-only re-check.

## Gate results recorded at this source

- `python scripts/check_summary.py` → `SUMMARY_VALID`
- `python scripts/doc_checker.py` → 0 FAIL / 0 WARN, 23 total
- `python tools/truth.py verify` → `TRUTH_VALID @ 7822f4c` (source is an ancestor of HEAD;
  source history and worktree clean)
- `python tools/release_engineering.py --verify` → 674/674 artifacts match recorded digests
- selected pytest (`tests/docs`, `tests/release`, scope ratchet, evidence-index integrity)
  → 273 passed
- `git diff --check` clean; worktree clean; `origin/main` at `f13bbbe`

The 674 figure means artifact hashes verified against **one** Ed25519 signature over
`SHA256SUMS` — not 674 signatures and not per-artifact security validation.

## Boundaries — never claimed by this closeout

- No WFP mutation, host effect, enforcement or policy authority change. Production is
  observe-only: `prevention_gate=closed`, `host_effect_capable=false`.
- No Signed-IR promotion, EV/HLK/Microsoft attestation, re-key, new release/tag/signature,
  `v2.1.0` label or "production-ready" wording. Release identity remains `v1.1` /
  `466a226` / `a53eda8`, 6/6 gates PASS.
- No `CanonicalEvent` wire layout, golden-vector, rule, match-pattern or authority change.
- No MITRE mapping, benchmark ceiling, replay re-execution, "zero loss ever", active IPC
  nonce/replay enforcement, synthetic host evidence, or relabeled/cleaned transcript.
- No fake or promoted E5, E6/E7, soak or loss-rate result. The 36.52 h soak is HISTORICAL
  at `a53eda8`; historical `43a8bcc` E3/E4/E5 records stay at their own source.

## Open blockers — deliberately still open

1. Full current-head Windows E5 / kernel IDS qualification: **NOT_PROVEN**. The narrow
   `#44` pipe lifecycle proof is not a kernel IDS qualification.
2. Detection efficacy / 23-rule matrix at `7822f4c`: **NOT RE-MEASURED**. The matrix's
   E5/E6 rows were last measured at `f4cde3c`; R2003 has no host proof (FN-1).
3. C6 visibility path host measurement: VLAN/QinQ BPF admission and the bounded IPv6
   extension walk are E2-only; no Npcap host measurement exists at this source.
4. Active IPC nonce/replay and cross-process monotonic identity remain later source work;
   `monotonic_ns` is documented as in-process ordering only.
5. Zig-vs-TypeScript policy-hash byte-stream question remains open.
6. Soak, loss-rate, install, signing, production simulation, E6/E7: no current-source run.

None of these are closed by this records patch, and none may be inferred from the narrow
E3/E4/E5 PASS results.

## Completion gate

**PASS** for the narrow current-source proof inventory (E2 + narrow E3 + narrow E4/E5 at
`7822f4c`). **OPEN / NOT_PROVEN** for full current-head Windows E5 / kernel IDS
qualification, detection efficacy and every item in the open-blocker register above.
