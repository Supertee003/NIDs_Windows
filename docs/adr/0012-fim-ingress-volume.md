# ADR-0012 — FIM ingress volume: reduce it at the sensor, never silently

**Status:** Proposed — candidate duplicate volume was measured at E5 on the
Windows host on 2026-11-08, but the producer-identity gate **NOT PASSED** (see
*Measurement result*). No suppressing coalescer may deploy until distinct opens
are proven retained; implementation and post-change loss-reduction proof remain
open
**Date:** 2026-11-07
**Measurement:** 2026-11-08, evidence `ADR-0012-DUP-RATIO-E5-20261108`
**Supersedes:** —
**Superseded by:** —
**Owner:** AEGIS Core Team
**Amends open work item 1 of:** ADR-0010 (Host telemetry admission under storm)
**Related:** FLOW QLOSS-HEALTH-001, GitHub issue #29, evidence
`QLOSS-FIM-STORM-20261106`, `QLOSS-QUEUE-BURST-20261106`,
`QLOSS-FAIRSHARE-001-E5-20261107`, `QLOSS-CRITICAL-001-E5-20261107`,
`QLOSS-CONSUMER-001-E5-20261107`, `QLOSS-ISOLATION-002-E2-20261107`

---

## Context

ADR-0010 closed the *fairness* question (one host sensor cannot blind another)
and the *capacity* question (36x the queue, ~950 MB, is not the answer). It left
one lever explicitly open: **the sensor emits more file events than the host
consumer can drain during a burst, and no queue or admission change can remove a
source's own excess.** Every measurement since has pointed at the same place.

Measured facts on this host, all from deployed E5 windows:

| Fact | Value | Source |
|---|---|---|
| Consumer capacity (ReleaseSafe, 60k-file churn) | 2,930 rows/s, 439 drops (0.12%) | `QLOSS-CONSUMER-001-E5-20261107` |
| FIM demand, 20k-file churn over 180 s | 309,723 pushed + 271,887 dropped = 581,610 (~3,231/s) | `QLOSS-CRITICAL-001-E5-20261107` |
| ETW demand, same window | 245,343 pushed + 42,456 dropped = 287,799 (~1,599/s) | `QLOSS-CRITICAL-001-E5-20261107` |
| Combined demand, same window | ~869,409 rows (~4,830/s) vs 2,930/s capacity | same |
| Organic (non-synthetic) burst | 10,408 queue drops (FIM 9,553, ETW 855), ring 0 | `QLOSS-QUEUE-BURST-20261106` |

Two conclusions follow directly:

1. **The deficit is now marginal, not 10:1.** ReleaseSafe narrowed the gap. FIM
   alone is ~10% over capacity; FIM+ETW together are ~65% over. A 10–40%
   ingress reduction at the sensor is in the range where it matters, unlike the
   old Debug-era numbers where it could not have helped.
2. **The loss is attributed, not silent.** Every refused row is already counted
   (`source_quota_shed`, `reserved_tail_shed`, `ring_dropped`,
   `pipeline_dropped`). Any new mechanism must meet that bar: a *different*
   loss is acceptable only if it is *visible* loss.

## What FIM currently emits

`src/pipeline/telemetry_threads.zig::fimThread` polls every 500 ms, parses every
`ReadDirectoryChangesW` record in the batch, and pushes one `fim_change`
`IpcEvent` per record with the path as payload. There is no coalescing, no
debounce, and no per-path state. A churn that touches the same file repeatedly
therefore produces one queued event per touch.

FIM events are `capture_fim` host telemetry and are **advisory evidence only**
under ADR-0009: they never enter threat scoring, policy, PEP, DEFCON, or any
host effect. Their consumers are forensic recording and the host-telemetry
stores, which is what bounds the risk of changing their granularity.

## Decision (accepted in principle; minifilter implementation blocked)

**Reduce volume only where the source contract proves two rows represent the
same observation.** Keep the first row and count every suppressed row in an
always-reported `fim_coalesced_total`. The previously proposed minifilter key
`(path, kind, pid)` preserves cross-process attribution but does not distinguish
separate successful opens by the same process; it is not approved for
deployment. Minifilter identity must include enough producer data to preserve
distinct callbacks. The native poll source has no PID and may use `(path, kind)`
within its 500 ms poll batch, subject to its own contract tests.

Rationale for choosing this over the alternatives:

- It needs **no wire or ABI change**: one event still carries one path, and the
  batch boundary already exists (the 500 ms poll). No `EVENT_VERSION` bump and no
  six-codec vector sync is required for the first step.
- It can preserve **evidence per path and actor** only when the identity key
  distinguishes distinct source events. The prior minifilter proposal failed
  this bar and remains blocked. For native poll records, the first
  `(path, kind)` observation in a batch is retained; the repeat count is lost,
  not the fact that the path changed.
- A valid source-specific key makes the work **structurally bounded** within
  each batch. Until event identity is proven, the minifilter source keeps every
  row and receives no suppression benefit from this proposal.
- It meets ADR-0010's bar that loss must be visible: `fim_coalesced_total` makes
  the reduction a counted decision, never a silent one.
- Hashes are only an index. The coalescer compares the full path bytes and key
  fields before suppressing a row, so a hash collision cannot merge distinct
  files. If its bounded table or path store fills, it fails open for the rest
  of that batch, increments the visible overflow counter, and submits events.

## Alternatives considered

**Extend `IpcEvent` with a `repeat_count` field.** Rejected for the first step.
The event is a fixed 96-byte `extern struct` with a compile-time size assertion;
adding a field means an `EVENT_VERSION` bump, six codecs (Zig/Go/C++/Python x2
plus the golden tuple map) and shared `event_v*` vectors in the same patch. That
is a legitimate second step *if* repeat counts turn out to be load-bearing, and
it is recorded here rather than pre-emptively paid for.

**Per-poll sampling (keep k of N, count the rest).** Rejected. Sampling drops
*distinct* paths as well as repeats, so a single write to an interesting path can
be the row that is dropped, and the drop is not reconstructible from the record.

**Second loss point: token bucket at the FIM thread.** Rejected as a first step
because the queue already implements exactly this at admission, with attribution
(`source_quota_shed`). Adding another bucket above it would make two places
responsible for the same decision.

**Raise consumer throughput further (batched forensic append).** Not rejected —
it is the semantics-neutral lever (ADR-0010 open work item 2) and remains the
preferred companion. But it does not bound burst amplitude, and the measured
per-row cost is dominated by the 4 KiB zero/hash/CRC passes, which is separately
tracked.

**Shrink the watched surface (fewer trees, exclusions).** Rejected. It creates
blind spots, which is a detection-coverage decision, not a volume fix.

## Measurement result and implementation gate

**Candidate duplicate volume measured at E5 on 2026-11-08; identity gate is
NOT PASSED.** The six-worker, 20,000-file host measurement in
`ADR-0012-DUP-RATIO-E5-20261108` reported repeats under the coarse per-PID key
of 48.177% for create-once, 49.391% for rewrite, and 56.992% for recreate,
with zero probe-table overflow. Source review then showed that same-key rows can
be distinct successful opens. These ratios are therefore not valid estimates
of safely coalescible rows and do not pass the implementation gate. Detailed
local-only evidence is retained under
`admin-evidence/adr0012-dup-ratio-20261108/` and indexed in
`EVIDENCE_INDEX.json`.

The measurement is not proof that coalescing reduces queue loss: no coalescer
was active during the measurement. The final queue snapshot also counted
575,935 minifilter records with a repeated timestamp; that count does not prove
duplicate callback delivery. A source review found that each successful
`IRP_MJ_CREATE` is recorded with a fresh `KeQuerySystemTime` value, so the
measured per-PID key can conflate distinct opens. The current implementation
WIP is uncommitted and **must not be deployed** until its minifilter event
identity preserves distinct callbacks and the corrected duplicate ratio is
measured. See
`analysis/current-head/issue-29-minifilter-event-identity-stop-line-20261108.md`.

After implementation, repeat the same host churn and require
`fim_coalesced_total > 0`, FIM pipeline drops strictly below the comparable
baseline, ETW unchanged or better, kernel ring drops at 0, and no readiness-gate
relaxation. If drops do not fall, retain the counted coalescing behavior only
if its evidence value is accepted and continue with the consumer-throughput
lever; do not claim issue #29 closed.

## Consequences

- Forensic FIM row count may fall only for identities proven to be duplicates.
  Until the minifilter identity contract is resolved, its coalescing WIP must
  not be deployed. Repeats are visible only in `fim_coalesced_total` and source
  counters, not as per-row repeat counts.
- Detection rules that would depend on *how often* a path changed in a window
  cannot use FIM repeats at this granularity. No such rule exists today (FIM
  events carry `rule_id = 0` and are advisory), but this must be re-checked if
  one is ever added — the event path would then need the `repeat_count` ABI step.
- The guarantee is per-source and local: coalescing reduces FIM's own demand. It
  does not change network admission, the reserves, or the critical-path bypass
  from ADR-0010/`QLOSS-CRITICAL-001`.
- Ordering within a batch is preserved for first occurrences; a path touched
  again in a later batch produces a new event, so temporal spread is still
  visible at 500 ms resolution.

## Open items

1. Resolve the minifilter event-identity stop-line; prove distinct opens are
   retained before implementing any suppressing coalescer. Native polling can
   be considered separately under its own producer contract.
2. Re-run the corrected E5 duplicate-ratio probe, then comparable E5 churn to
   measure actual FIM queue-drop reduction, ring loss,
   ETW impact, and readiness without relaxing gates.
3. Decide whether the `repeat_count` ABI step is warranted from post-change
   operator needs; consumer throughput (batched append) remains open per ADR-0010.
