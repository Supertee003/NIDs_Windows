# RULE-LAYER-FAILCLOSED-001 — 2026-11-19 (ported to current v1.1 source)

**Patch:** `RULE-LAYER-FAILCLOSED-001`
**Flow:** `DET-001` — detection identity and source-to-rule-layer selection
**Target HEAD:** `446ff97` (records), build source before patch `4169839`
**Final build source:** `f4cde3c503fd8b696183751a608b999768caa769`
**Origin:** unmerged Manus worktree `closeout/rule-layer-failclosed-001` (`3aafce0`)
**Evidence level:** E2 (source-level proof + full build/test). No E5 runtime claim here.

## Why this is in v1.1 now

The owner chose to land every outstanding handoff before release so the rebuild,
re-sign, RB-024 revalidation and 24 h soak happen **once**. The original patch
was written against the older one-argument `ruleLayerIndexForSource(source)`;
current source has `ruleLayerIndexForSource(source, kind)` from PROC-LAYER-001.
It was therefore ported, not cherry-picked.

## Patch declaration

- **Target files:** `src/pipeline/event_processor.zig`, `src/pipeline/runtime_state.zig`,
  `src/pipeline/rule_loader.zig`, `src/control/handler_registry.zig`.
- **Target symbols:** `resolveRuleAutomaton`, `processEvent`,
  `g_layered_rules_active`, `g_ac_skipped_unavailable_layer`,
  `reloadRules`, `metricsSnapshot`.
- **In scope:** once the first layered ruleset is atomically installed, a
  configured layer whose automaton is unavailable returns no automaton and
  increments an operator-visible payload counter; no other layer's catalog is
  borrowed. The legacy single-AC fallback stays valid only before that swap.
- **Out of scope:** host install/restart, driver signing, E5 revalidation,
  QLOSS ingress work, the 24 h soak, policy/enforcement changes.
- **Contract impact:** additive `metrics.snapshot` field
  `rule_layer_unavailable_events`; no event-wire or cross-language contract change.
- **ABI impact:** none. **Authority impact:** none (Zig detection only).
- **State impact:** one mutex-guarded lifecycle bit, one atomic lifetime counter.
- **Test impact:** five RULE-LAYER pins including PROC-LAYER kind precedence,
  empty-layer no-match, no-payload accounting and pre-layered legacy fallback.

## Behavior and invariant

**Old flow:** `active_ac = g_layer_ac[li] orelse g_active_ac` — a failed layer
automaton silently inherited the network catalog.
**New flow:** selection is layer-local after the layered swap. Missing configured
layer = no match + counted debt; intentionally empty layer = clean no-match;
unknown source keeps its existing `g_ac_skipped_unknown_source` debt.
**Invariant:** after layered activation, bytes from one event source are never
evaluated by an unrelated rule-layer automaton.

## Verification (actual, this tree)

- `zig fmt --check` on all four files — PASS.
- `zig test src/all_tests.zig --test-filter RULE-LAYER` — **5/5 passed**.
- `cargo build --release` — PASS (`aegis_pep` rebuilt after cache cleanup).
- `zig build` — PASS. `zig-out/bin/aegis_nids.exe`: 5,265,408 bytes,
  SHA-256 `0CB573EC6CF3B77BE5CBB477BA7803F4C63361F325AB22A561343092A4C0DF1F`.
- `zig build test --summary all` — **8/8 steps, 3339/3349 passed, 10 skipped, 0 failed**
  (with `build/Release` on PATH; that helper-DLL search-path defect is recorded
  separately and is not introduced by this patch).

## Soak disposition

The soak opened at `2026-11-19T00:20:11` on the pre-change installed image. It is
**VOIDED BY SUPERSEDED BUILD before any PASS**, not counted as a failure or as a
gate. A fresh RB-024 install/rollback drill and a new 24 h window are required
against `f4cde3c`.

## Result

**Build:** PASS. **Test:** PASS. **Windows result:** compile/test host only;
no install, restart or live stimulus yet. **Evidence level:** E2.
**Rollback:** revert source commit `f4cde3c` and rebaseline maps/candidate.
**Remaining risk:** no deterministic fault injection forces a production loader
AC-build failure; the seam and counter semantics are pinned by unit tests.
**Completion gate:** PASS for this E2 source slice. Release closure stays OPEN
until RB-024 and the new 24 h soak PASS on this build source.
