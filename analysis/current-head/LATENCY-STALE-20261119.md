# Latency "6/10 stages stuck at 1 ns" — STALE, no code change

**DATE:** 2026-11-19
**PATCH-ID:** OBSERVABILITY-001 (Slice 4, item 4)
**EVIDENCE LEVEL:** E1 (current-source inspection + commit/evidence cross-check)

The gap-plan item "fix 6/10 latency stages stuck at the 1 ns floor" does not
match current source. No timing code was changed.

## What current source actually shows

- `src/reliability/latency_histogram.zig:77-91` declares all 10 stages
  (`capture_to_decode` … `receipt_issue`).
- `src/pipeline/event_processor.zig` has an observe call for every stage via
  the `markStage` helper (`:109-116`): marks at `:308`, `:439`, `:542`, `:561`,
  `:610`, `:673`, `:675-677`, and `:1212-1214`. No stage is unobserved.
- `src/control/handler_registry.zig:776-782` renders all declared stages from
  `@typeInfo(Stage).Enum.fields.len`.
- The "1 ns" value is the histogram's **bucket floor**, not a stalled clock:
  log2 buckets start at 1 ns (`latency_histogram.zig:25-32`) and `percentile`
  returns `1 << i` (`:54`). A zero/sub-ns sample is represented as 1 ns by
  design.
- The real coarse-clock bug was already fixed at commit `02b4e5d` by switching
  stage timing to the monotonic QueryPerformanceCounter clock
  (`src/reliability/monotonic_clock.zig`, ADR-0013). Evidence records
  post-swap `forensic_append p50 16.4 us / p95 32.8 us` and
  `capture_to_decode p50 16.4 us / p95 65.5 us` — no zero/tick mass.

## Decision

Treat the item as HISTORICAL/STALE. Do **not** rewrite bucket math or the
percentile contract: that would invalidate every latency claim in
`EVIDENCE_INDEX.json` and reopen the 571 us tick-straddle bug ADR-0013 fixed.
If a fresh `queue.stats` ever shows a stage with `count>0` and `p50_ns==1` over
a real load window, revisit with an owner decision and an EVIDENCE_INDEX
refresh. Until then this is a document-only closure, not a code change.
