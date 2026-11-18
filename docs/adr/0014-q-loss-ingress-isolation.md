# ADR-0014 — Q-LOSS ingress isolation: filter the ETW `NameDelete` lane, never silently

**Status:** **PROPOSED — owner decision required.** No code is written against
this ADR. The three options below change different things (which rows exist,
how fast they are written, or what the release promises), so the choice is a
product decision, not an implementation detail.
**Date:** 2026-11-17
**Measurement:** `QLOSS-CRITICAL-001-E5-20261107`, `QLOSS-CONSUMER-001-E5-20261107`,
`QLOSS-FAIRSHARE-001-E5-20261107`, ADR-0012 census (2026-11-17)
**Amends open work item 1 of:** ADR-0010 (Host telemetry admission under storm)
**Related:** FLOW `QLOSS-HEALTH-001`, GitHub issue #29, gap
`GAP-QLOSS-ISOLATION-002`, ADR-0012 (FIM lane — coalescer rejected at E5)

---

## Context

The known-gap record says: *FIM/ETW ingress volume from the storming source is
not reduced.* Fair-share arithmetic was already fixed at E2 (`QLOSS-FAIRSHARE-001`),
so one storming sensor can no longer blind another; what remains is a sensor
producing more rows than the host consumer can drain, which no admission policy
can remove.

Measured facts, all from deployed E5 windows on this host:

| Fact | Value | Source |
|---|---|---|
| Consumer capacity (ReleaseSafe, 60k-file churn) | 2,930 rows/s, 439 drops (0.12%) | `QLOSS-CONSUMER-001-E5-20261107` |
| ETW demand in the 20k-churn window | 245,343 pushed + 42,456 dropped (287,799, ~1,599/s) | `QLOSS-CRITICAL-001-E5-20261107` |
| Combined FIM+ETW demand, same window | ~869,409 rows (~4,830/s) vs 2,930/s capacity | same |
| Largest single ingress lane | ETW Kernel-File `NameDelete`: **18,151,604 rows** | ADR-0012 census |
| FIM coalescing as a lever | **rejected** at E5 — the lane does not duplicate | ADR-0012, `ADR-0012-SINGLE-HOST-E5-20261117` |

Two facts bound the design space:

1. **The lane is not duplicate delivery.** ADR-0012 proved a create-once,
   one-open-per-path churn produces one record per open. Any volume reduction
   here is therefore a *semantic* decision — which deletes deserve a row — and
   must be visible, counted, and reversible. `AGENTS.md` forbids silent event
   loss.
2. **Deletes are not inert.** The kernel-file rules match path text, so a delete
   of `C:\Windows\System32\x.dll` matches `R1001`/`R1004` today, and a
   mass-delete of `*.locked` files is exactly the ransomware signal `R1002`
   exists for. A filter must not remove rows that would have carried a rule id.

## Options

### A. Producer-side filter: drop only deletes that match no rule path, aggregate the rest

At the ETW consumer, a `NameDelete` whose path matches **no** kernel-file
pattern is not enqueued as its own event. Matching deletes keep flowing
unchanged. The dropped volume is reported as a per-window aggregate plus a
visible counter (`etw_delete_filtered_total`, `etw_delete_aggregate_events`), and
the aggregate row carries the window's delete count, the top-N path prefixes and
one sample path — so a mass delete still appears as one high-count event instead
of millions of rows.

- Removes ~18.1 M of the largest lane while leaving the *match set* identical.
- Every removed row was one that carried `rule_id = 0`; nothing that could have
  raised a rule disappears.
- Cost: producer change in C++ (ETW adapter) + Zig consumer counter + tests
  (~2 days), then a new build, signature and 24 h soak.
- Risk: a future rule that keys on volume of *unmatched* deletes would need the
  aggregate, not the raw lane. The aggregate exists for that reason.

### B. Batched forensic append (consumer throughput)

Keep every row, reduce the per-row cost: the append currently pays a 4 KiB
zero/hash/CRC pass per record; batching amortises it.

- Semantics-neutral, which makes it the safest change to detection.
- Does not bound the burst amplitude, only raises the ceiling by an unknown
  amount until measured.
- Cost: forensic writer change + a new measurement run (~2–3 days) + soak.
- Companion, not a substitute: A and B address different halves of the same
  equation.

### C. Accepted envelope (documented budget + owner sign-off)

Ship with the current lane, publish the loss envelope, and record an explicit
owner acceptance for `source_quota_shed`/`reserved_tail_shed` during storms.

- Zero code, zero new soak; cheapest by far.
- Leaves the gap open by definition: the platform still produces rows it cannot
  drain, and the acceptance has to be restated for every release.
- Requires a named owner sign-off; this ADR cannot supply it.

## Recommendation

**A, with B as a follow-up in the same v1.1 batch if the measurement shows B is
still needed after A lands.** Reasons:

- A is the only option that reduces volume *without* touching what detection can
  see: the row set that carries a rule id is unchanged by construction, and the
  removed rows are exactly the ones already recorded as `rule_id = 0`.
- It keeps ransomware visibility through the aggregate, so the security property
  that justified the lane is preserved rather than traded away.
- It is bounded and cheap to verify: post-change, `etw_delete_filtered_total > 0`,
  kernel-file match count unchanged for the same stimulus, `shed_overload` under
  the 4,000 budget, ring drops 0.
- C is not rejected on merit but on repeatability: it re-opens every release.

## Acceptance criteria (for whichever option is chosen)

1. Same stimulus, same window length: total queue drops and `shed_overload`
   strictly below the `QLOSS-CRITICAL-001` baseline.
2. Kernel-file detection unchanged: a `canary.locked` rename/delete still yields
   `R1002`; `R1001`/`R1004` still fire for matching paths.
3. Any suppressed row is counted in a counter that appears in `status`/`metrics`,
   and the aggregate is emitted for mass deletes.
4. A 24 h soak on the new build with the same budgets (`--loss-budget 3500`,
   `--shed-budget 20000`) passes with no restart.

## Consequences

- If A is chosen, the forensic record for a delete storm becomes one aggregate
  row plus the matching deletes, not millions of rows; the raw lane is no longer
  replayable for unmatched deletes. That is a real loss of forensic granularity
  and is the price of the change — it must be stated in the release notes.
- Either way the work lands in the single v1.1 batch with the 6.0.0 label, so it
  costs one build, one signature and one soak instead of two.
- The gap stays **open** until the chosen option is implemented, measured, and
  soaked. This document does not close it.
